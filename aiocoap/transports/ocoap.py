# SPDX-FileCopyrightText: Martine S. Lenders
#
# SPDX-License-Identifier: MIT

from collections import namedtuple
from functools import wraps

from .. import credentials, interfaces, hpke, message, ocoap
from ..numbers import UNAUTHORIZED, MAX_REGULAR_BLOCK_SIZE_EXP


def _requires_ua(f):
    @wraps(f)
    def wrapper(self):
        if self.underlying_address is None:
            raise ValueError(
                "No underlying address populated that could be used to derive a hostinfo"
            )
        return f(self)

    return wrapper


class OCoAPAddress(
    namedtuple(
        "_OCoAPAddress",
        ["hpke_key_config", "hpke_suite", "underlying_address", "ocoap"],
    ),
    interfaces.EndpointAddress,
):
    """Remote address type for :class:`TransportOCoAP`."""

    def __repr__(self):
        return "<%s in context (%r,%r,%r) to %r>" % (
            type(self).__name__,
            self.hpke_key_config,
            self.hpke_suite,
            self.ocoap,
            self.underlying_address,
        )

    @property
    @_requires_ua
    def hostinfo(self):
        return self.underlying_address.hostinfo

    @property
    @_requires_ua
    def hostinfo_local(self):
        return self.underlying_address.hostinfo_local

    @property
    @_requires_ua
    def uri_base(self):
        return self.underlying_address.uri_base

    @property
    @_requires_ua
    def uri_base_local(self):
        return self.underlying_address.uri_base_local

    @property
    @_requires_ua
    def scheme(self):
        return self.underlying_address.scheme

    @property
    def authenticated_claims(self):
        return self.underlying_address.scheme

    is_multicast = False
    is_multicast_locally = False

    maximum_payload_size = 1024
    maximum_block_size_exp = MAX_REGULAR_BLOCK_SIZE_EXP

    @property
    def blockwise_key(self):
        detail = None
        if self.ocoap:
            detail = self.ocoap.id_ctx
        return (self.underlying_address.blockwise_key, detail)


class TransportOCoAP(interfaces.RequestInterface):
    def __init__(self, context, forward_context):
        self._context = context
        self._wire = forward_context

        if self._context.loop is not self._wire.loop:
            # TransportOSCORE is not designed to bridge loops -- would probably
            # be possible, but incur confusion that is most likely well avoidable
            raise ValueError("Wire and context need to share an asyncio loop")

        self.loop = self._context.loop
        self.log = self._context.log

        # Keep current requests. This is not needed for shutdown purposes (see
        # .shutdown), but because Python 3.6.4 (but not 3.6.5, and not at least
        # some 3.5) would otherwise cancel OCoAP tasks mid-observation. This
        # manifested itself as <https://github.com/chrysn/aiocoap/issues/111>.
        self._tasks = set()

    #
    # implement RequestInterface
    #

    async def recognize_remote(self, message):
        # There is just one of those
        return isinstance(message.remote, OCoAPAddress)

    async def determine_remote(self, message):
        if message.opt.ocoap is not None:
            # double ocoap is not specified; using this fact to make `._wire
            # is ._context` an option
            return None

        creds = self._context.client_credentials.credentials_from_request(message)

        if isinstance(creds, credentials.HPKEKeyConfig):
            hpke_key_configs = creds.key_config
            self.log.debug(
                "Selecting OCoAP transport based on context %r for new request %r",
                hpke_key_configs,
                message,
            )
            for key_id, kem_id, kdf_id, aead_id in hpke_key_configs.iter_supported():
                hpke_key_config = hpke_key_configs[key_id, kem_id, kdf_id, aead_id]
                hpke_suite = hpke_key_config.suites[kem_id, kdf_id, aead_id]
                break
            return OCoAPAddress(hpke_key_config, hpke_suite, message.remote, creds.ocoap)
        else:
            return None

    def request(self, request):
        t = self.loop.create_task(
            self._request(request),
            name="OCoAP request %r" % request,
        )
        self._tasks.add(t)

        def done(t, _tasks=self._tasks, _request=request):
            _tasks.remove(t)
            try:
                t.result()
            except Exception as e:
                _request.add_exception(e)

        t.add_done_callback(done)

    async def _request(self, request) -> None:
        """Process a request including any pre-flights or retries

        Retries by this coroutine are limited to actionable authenticated
        errors, i.e. those where it is ensured that even though the request is
        encrypted twice, it is still only processed once.

        This coroutine sets the result of request.request on completion;
        otherwise it raises and relies on its done callback to propagate the
        error.
        """
        msg = request.request

        hpke_key_config = msg.remote.hpke_key_config
        hpke_suite = msg.remote.hpke_suite

        ocoap_ctx, sealed_request = ocoap.OCoAP.seal_request(
            hpke_key_config, hpke_suite, msg
        )
        sealed_request.remote = msg.remote.underlying_address
        creds = self._context.client_credentials.credentials_from_request(msg)
        creds.ocoap = ocoap_ctx

        wire_request = self._wire.request(sealed_request)

        def _check(more, unprotected_response):
            if more and not unprotected_response.code.is_successful():
                self.log.warning(
                    "OCoAP sealed contained observe, but unsealed code is unsuccessful. Ignoring the observation."
                )
                return False
            return more

        try:
            sealed_response = await wire_request.response

            if sealed_response.opt.ocoap is None:
                # return error messages
                request.add_response(sealed_response)
                return
            unsealed_response = ocoap_ctx.open(sealed_response, sealed_request)
            unsealed_response.remote = OCoAPAddress(
                msg.remote.hpke_key_config,
                msg.remote.hpke_suite,
                sealed_response.remote,
                ocoap_ctx,
            )
            self.log.debug(
                "Successfully unsealed %r into %r",
                sealed_response,
                unsealed_response,
            )

            more = sealed_response.opt.observe is not None
            more = _check(more, unsealed_response)
            request.add_response(unsealed_response, is_last=not more)

            if not more:
                return

            async for sealed_response in wire_request.observation:
                unsealed_response = ocoap_ctx.open(sealed_response, sealed_request)

                more = sealed_response.opt.observe is not None
                more = _check(more, unsealed_response)

                unsealed_response.remote = OCoAPAddress(
                    msg.remote.hpke_key_config,
                    msg.remote.hpke_suite,
                    sealed_response.remote,
                    ocoap_ctx,
                )
                self.log.debug(
                    "Successfully unsealed %r into %r",
                    sealed_response,
                    unsealed_response,
                )
                # FIXME: discover is_last from the underlying response
                request.add_response(unsealed_response, is_last=not more)

                if not more:
                    return
            request.add_exception(
                NotImplementedError(
                    "end of observation"
                    " should have been indicated in is_last, see above lines"
                )
            )
        finally:
            # FIXME: no way yet to cancel observations exists yet, let alone
            # one that can be used in a finally clause (ie. won't raise
            # something else if the observation terminated server-side)
            creds.ocoap = None
            # if wire_request.observation is not None:
            #    wire_request.observation.cancel()

    async def shutdown(self):
        # Nothing to do here yet; the individual requests will be shut down by
        # their underlying transports
        pass
