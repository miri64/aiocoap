# SPDX-FileCopyrightText: Martine S. Lenders
#
# SPDX-License-Identifier: MIT

"""This module TBD"""

import logging

from aiocoap import error
from aiocoap import interfaces
import aiocoap.pipe
from aiocoap import numbers
from aiocoap import ocoap

from aiocoap.transports.ocoap import OCoAPAddress


class OCoAPSiteWrapper(interfaces.Resource):
    def __init__(self, inner_site, hpke_configs):
        self.log = logging.getLogger("coap-server.ocoap-site")

        self._inner_site = inner_site
        self.hpke_configs = hpke_configs

    def get_resources_as_linkheader(self):
        # Not applying any limits while WKCResource does not either
        return self._inner_site.get_resources_as_linkheader()

    async def render(self, request):
        raise RuntimeError(
            "OCoAPSiteWrapper can only be used through the render_to_pipe interface"
        )

    async def needs_blockwise_assembly(self, request):
        raise RuntimeError(
            "OCoAPscoreSiteWrapper can only be used through the render_to_pipe interface"
        )

    async def render_to_pipe(self, pipe):
        request = pipe.request

        if request.opt.ocoap is None:
            await self._inner_site.render_to_pipe(pipe)
            return

        if request.code not in (numbers.FETCH, numbers.POST):
            raise error.MethodNotAllowed

        try:
            ocoap_ctx, unsealed = ocoap.OCoAP.open_request(self.hpke_configs, request)
        except ocoap.OpenError as exc:
            raise error.BadRequest from exc
        except ocoap.NotAProtectedMessage:
            # ie. if no object_seccurity present
            await self._inner_site.render_to_pipe(pipe)
            return

        hpke_config = self.hpke_configs[
            ocoap_ctx.key_id,
            ocoap_ctx.suite.kem_id,
            ocoap_ctx.suite.kdf_id,
            ocoap_ctx.suite.aead_id,
        ]
        unsealed.remote = OCoAPAddress(
            hpke_config, ocoap_ctx.suite, request.remote, ocoap_ctx
        )

        self.log.debug("Request %r was unsealed into %r", request, unsealed)

        # ==============================================================================
        # this is just copied from oscore_sitewrapper.OscoreSiteWrapper.render_to_pipe()
        inner_pipe = aiocoap.pipe.IterablePipe(unsealed)
        pr_that_can_take_errors = aiocoap.pipe.error_to_message(inner_pipe, self.log)
        # FIXME: do not create a task but run this in here (can this become a
        # feature of the aiterable PR?)
        aiocoap.pipe.run_driving_pipe(
            pr_that_can_take_errors,
            self._inner_site.render_to_pipe(inner_pipe),
            name="OCoAP response rendering for %r" % unsealed,
        )

        async for event in inner_pipe:
            if event.exception is not None:
                # These are expected to be rare in handlers
                #
                # FIXME should we try to render them? (See also
                # run_driving_pipe). Just raising them
                # would definitely be bad, as they might be renderable and
                # then would hit the outer message.
                self.log.warn(
                    "Turning error raised from renderer into nondescript protected error %r",
                    event.exception,
                )
                message = aiocoap.Message(code=aiocoap.INTERNAL_SERVER_ERROR)
                is_last = True
            else:
                message = event.message
                is_last = event.is_last

            # FIXME: Around several places in the use of pipe (and
            # now even here), non-final events are hard-coded as observations.
            # This should shift toward the source telling, or the stream being
            # annotated as "eventually consistent resource states".
            if not is_last:
                message.opt.observe = 0

            try:
                sealed_response = ocoap_ctx.seal(message, request)
            except ocoap.SealError as exc:
                raise error.InternalServerError from exc
            if message.opt.observe is not None:
                sealed_response.opt.observe = ocoap_ctx.server_counter & 0xFFFFF
            self.log.debug(
                "Response %r was encrypted into %r", message, sealed_response
            )

            pipe.add_response(sealed_response, is_last=is_last)
            if event.is_last:
                break
        # The created task gets cancelled here because the __aiter__ result is
        # dropped and thus all interest in the inner_pipe goes away
        # ==============================================================================
