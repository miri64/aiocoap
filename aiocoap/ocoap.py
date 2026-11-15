# SPDX-FileCopyrightText: Martine S. Lenders
#
# SPDX-License-Identifier: MIT

"""This module TBD"""

import logging
import math
import secrets
import struct
from typing import Optional

from aiocoap import error
from aiocoap import hpke
from aiocoap import message
from aiocoap import numbers
from .numbers import codes
from .numbers.optionnumbers import OptionNumber
from aiocoap import options

_ocoap_log = logging.getLogger("aiocoap.ocoap")


class NotAProtectedMessage(error.Error, ValueError):
    """Raised when decryption is attempted on a non-Oblivious-CoAP message"""

    def __init__(self, message, plain_message):
        super().__init__(message)
        self.plain_message = plain_message


class DecodeError(error.Error, ValueError):
    """Raised when verification of an OCoAP message fails because payload or OCoAP option was erroneous"""


class ReplayError(error.Error, ValueError):
    """Raised when verification of an OCoAP message fails because payload or OCoAP option was erroneous"""


def _more(msg):
    return (
        msg.code.is_response()
        and (
            msg.opt.observe
            or (msg.opt.block1 and msg.code == codes.CONTINUE)
            or (msg.opt.block2 and msg.opt.block2.more)
        )
    ) or (
        msg.code.is_request()
        and (
            (msg.opt.observe and msg.code == codes.GET and msg.opt.observe != 1)
            or (msg.opt.block1 and msg.opt.block1.more)
            or (msg.opt.block2)
        )
    )
    return False


class OCoAP:
    OCOAP_OPTION_FLAGS_COUNT_MASK = 0x3
    OCOAP_OPTION_FLAGS_ID_CTX = 0x4
    PAYLOAD_HDR_FORMAT = struct.Struct("!BHHH")
    CONTEXTS = {}
    ENC_WINDOW = 20
    PREVIOUS_ENCS = []

    def __init__(
        self, key_id: int, suite: hpke.HPKESuite, ctx: hpke.HPKEContext, enc: bytes
    ):
        self.key_id = key_id
        self.suite = suite
        self.ctx = ctx
        self.enc = enc
        self.aead_key = None
        self.aead_base_iv = None
        self.client_counter = None
        self.server_counter = None
        self._id_ctx = None

    def __repr__(self):
        return (
            f"<{type(self).__name__} for (0x{self.key_id:02x}, 0x{self.suite.kem_id:04x}, "
            f"0x{self.suite.kdf_id:04x}, 0x{self.suite.aead_id:04x}), "
            f'id_ctx: "{self._id_ctx.hex() if self._id_ctx else self._id_ctx}"'
        )

    def __del__(self):
        if self.id_ctx is not None:
            del self.id_ctx

    @property
    def id_ctx(self):
        return self._id_ctx

    @id_ctx.setter
    def id_ctx(self, value):
        self._id_ctx = value
        if value is not None:
            self.CONTEXTS[value] = self

    @id_ctx.deleter
    def id_ctx(self):
        if self._id_ctx is not None:
            del self.CONTEXTS[self._id_ctx]
        self._id_ctx = None

    def generate_id_ctx(self):
        if self.id_ctx is not None:
            return
        for i in range(1, 247):
            id_ctx = secrets.token_bytes(i)
            if id_ctx not in self.CONTEXTS:
                self.id_ctx = id_ctx
                break

    def _construct_ocoap_option(self, is_response: bool):
        if is_response:
            counter = self.server_counter
        else:
            counter = self.client_counter

        if counter == 0 and not is_response:
            return OptionNumber.OCOAP.create_option(value=b"")

        if counter > 0:
            count_len = int(math.log2(counter) / 8 + 1)
        else:
            count_len = 1
        res = counter.to_bytes(count_len, "big")
        flags = 0
        flags |= (count_len - 1) & self.OCOAP_OPTION_FLAGS_COUNT_MASK

        if (counter == 0 or not is_response) and self.id_ctx:
            res += self.id_ctx
            flags |= self.OCOAP_OPTION_FLAGS_ID_CTX
        res = bytes([flags]) + res
        return OptionNumber.OCOAP.create_option(value=res)

    @classmethod
    def _parse_ocoap_option(cls, option_data: bytes):
        if option_data == b"":
            return 0, None
        elif len(option_data) < 2:
            raise DecodeError("OCoAP option too short")
        flags = option_data[0]
        n = flags & cls.OCOAP_OPTION_FLAGS_COUNT_MASK

        count = int.from_bytes(option_data[1 : n + 2], "big")
        id_ctx = None

        if flags & cls.OCOAP_OPTION_FLAGS_ID_CTX:
            id_ctx = option_data[n + 2 :]

        return count, id_ctx

    @classmethod
    def open_request(
        cls, hpke_configs: hpke.HPKEKeyConfigDB, sealed_request: message.Message
    ) -> (OCoAP, message.Message):
        _ocoap_log.debug("Opening sealed message %s ")

        if sealed_request.opt.ocoap is None:
            raise NotAProtectedMessage("No OCoAP Option present", message)

        is_response = sealed_request.code.is_response()

        count, id_ctx = cls._parse_ocoap_option(sealed_request.opt.ocoap)

        if is_response:
            raise ValueError("Responses are not supported by this function")

        if count > 0 and id_ctx is not None:
            try:
                ocoap = cls.CONTEXTS[id_ctx]
            except KeyError:
                raise error.BadRequest
        elif count == 0 and id_ctx is None:
            try:
                key_id, kem_id, kdf_id, aead_id = cls.PAYLOAD_HDR_FORMAT.unpack_from(
                    sealed_request.payload
                )
            except struct.error as exc:
                raise error.BadRequest from exc

            try:
                hpke_config = hpke_configs[key_id, kem_id, kdf_id, aead_id]
                private_key = hpke_configs.get_private_key(key_id, kem_id)
            except KeyError as exc:
                raise error.BadRequest from exc

            n_enc = hpke.KEM(kem_id).n_enc
            enc = sealed_request.payload[cls.PAYLOAD_HDR_FORMAT.size :][:n_enc]
            if len(enc) < n_enc:
                raise error.BadRequest
            if enc in cls.PREVIOUS_ENCS:
                raise ReplayError("Duplicate KEM shared-secret detected")
            cls.PREVIOUS_ENCS.append(enc)
            while len(cls.PREVIOUS_ENCS) > cls.ENC_WINDOW:
                cls.PREVIOUS_ENCS.pop()
            payload_hdr = sealed_request.payload[: cls.PAYLOAD_HDR_FORMAT.size]
            hpke_suite = hpke_config.suites[kem_id, kdf_id, aead_id]
            # just take key_id, kem_id, kdf_id, aead_id concatenation from payload
            info = b"ocoap_request\x00" + payload_hdr
            rctxt = hpke_suite.setup_base_r(enc, private_key, info)
            ocoap = cls(key_id, hpke_suite, rctxt, enc)
            ocoap.server_counter = 0
            ocoap.generate_id_ctx()
        else:
            raise error.BadOption
        return ocoap, ocoap.open(sealed_request)

    @classmethod
    def seal_request(
        cls,
        hpke_config: hpke.HPKEKeyConfig,
        hpke_suite: hpke.HPKESuite,
        unsealed_request: message.Message,
    ) -> (OCoAP, message.Message):
        _ocoap_log.debug("Opening sealed message %s ")

        assert hpke_suite.kem_id == hpke_config.kem_id

        if unsealed_request.remote.ocoap:
            ocoap = unsealed_request.remote.ocoap
            return ocoap, ocoap.seal(unsealed_request)
        else:
            is_response = unsealed_request.code.is_response()

            if is_response:
                raise ValueError("Responses are not supported by this function")

            payload_hdr = cls.PAYLOAD_HDR_FORMAT.pack(
                hpke_config.key_id,
                hpke_suite.kem_id,
                hpke_suite.kdf_id,
                hpke_suite.aead_id,
            )
            info = b"ocoap_request\x00" + payload_hdr
            enc, sctxt = hpke_suite.setup_base_s(hpke_config.public_key, info)

            ocoap = cls(hpke_config.key_id, hpke_suite, sctxt, enc)
            ocoap.client_counter = 0
        return ocoap, ocoap.seal(unsealed_request, payload_hdr=payload_hdr)

    @staticmethod
    def _class_i_options(options: options.Options):
        return message.Message(
            request_hash=options.request_hash,
            ocoap=options.ocoap,
        ).opt.encode()

    def _response_aad(self, request_ocoap_opt, response_opts):
        return (
            len(request_ocoap_opt).to_bytes(1)
            + request_ocoap_opt
            + self._class_i_options(response_opts)
        )

    def _request_aad(self, outer_options, payload_hdr):
        return payload_hdr + self._class_i_options(outer_options)

    def _export_response_secret(self):
        secret_length = max(self.suite.aead.n_n, self.suite.aead.n_k)
        secret = self.ctx.export(b"ocoap_response", secret_length)
        return secret, secret_length

    def _extract_response_prk(self, response_nonce, secret, sealed_request):
        assert sealed_request is not None
        return self.suite.kdf.extract(
            salt=self.enc + sealed_request.payload + response_nonce,
            ikm=secret,
        )

    def _expand_aead_details(self, prk):
        self.aead_key = self.suite.kdf.expand(
            prk=prk,
            info=b"key",
            length=self.suite.aead.n_k,
        )
        self.aead_base_iv = self.suite.kdf.expand(
            prk=prk,
            info=b"base_iv",
            length=self.suite.aead.n_n,
        )

    def _compute_response_aead_nonce(self, count):
        nonce_counter = count.to_bytes(len(self.aead_base_iv), "big")
        aead_nonce = bytes([a ^ b for a, b in zip(self.aead_base_iv, nonce_counter)])
        assert len(aead_nonce) == self.suite.aead.n_n
        return aead_nonce

    def open(
        self,
        sealed_message: message.Message,
        sealed_request: Optional[message.Message] = None,
    ):
        payload_hdr = self.PAYLOAD_HDR_FORMAT.pack(
            self.key_id,
            self.suite.kem_id,
            self.suite.kdf_id,
            self.suite.aead_id,
        )
        is_response = sealed_message.code.is_response()
        if is_response:
            count, id_ctx = self._parse_ocoap_option(sealed_message.opt.ocoap)

            if count == 0:
                if self.server_counter is not None and self.server_counter > 0:
                    raise hpke.OpenError("Count mismatch")
                secret, nonce_length = self._export_response_secret()
                response_nonce = sealed_message.payload[:nonce_length]
                ciphertext = sealed_message.payload[nonce_length:]
                if id_ctx is not None:
                    self.id_ctx = id_ctx
                prk = self._extract_response_prk(response_nonce, secret, sealed_request)
                self._expand_aead_details(prk)
                self.server_counter = count
            else:
                if (
                    self.server_counter is None
                    or self.server_counter >= count
                    or self.id_ctx is None
                    or (id_ctx is not None and self.id_ctx != id_ctx)
                ):
                    raise hpke.OpenError("Count mismatch")
                ciphertext = sealed_message.payload
                self.server_counter = count
            outer_options = sealed_message.opt
            aad = self._response_aad(sealed_request.opt.ocoap, outer_options)
            aead_nonce = self._compute_response_aead_nonce(count)
            try:
                plaintext = self.suite.aead.open(
                    self.aead_key,
                    aead_nonce,
                    aad,
                    ciphertext,
                )
            except ValueError as exc:
                raise hpke.OpenError(exc) from exc
        else:
            count, id_ctx = self._parse_ocoap_option(sealed_message.opt.ocoap)

            if count == 0 and id_ctx is None:
                n_enc = self.suite.kem.n_enc
                # just take key_id, kem_id, kdf_id, aead_id concatenation from payload
                payload_hdr = sealed_message.payload[: self.PAYLOAD_HDR_FORMAT.size]
                ciphertext = sealed_message.payload[
                    self.PAYLOAD_HDR_FORMAT.size + n_enc :
                ]
            else:
                payload_hdr = self.PAYLOAD_HDR_FORMAT.pack(
                    self.key_id,
                    self.suite.kem_id,
                    self.suite.kdf_id,
                    self.suite.aead_id,
                )
                ciphertext = sealed_message.payload
            outer_options = sealed_message.opt
            aad = self._request_aad(outer_options, payload_hdr)
            plaintext = self.ctx.open(ciphertext, aad=aad)

        try:
            unsealed_message = message.Message(code=plaintext[0])
            for opt in outer_options.option_list():
                unsealed_message.opt.add_option(opt)
            unsealed_message.payload = unsealed_message.opt.decode(plaintext[1:])
            unsealed_message.direction = message.Direction.INCOMING
        except error.UnparsableMessage as exc:
            if is_response:
                raise
            raise error.BadRequest from exc

        if unsealed_message.code.is_request():
            if outer_options.observe != 0:
                unsealed_message.opt.observe = None
        if not _more(unsealed_message):
            if is_response or unsealed_message.opt.observe:
                # for requests: only delete on Observe unsubscribe
                # (as checked in _more)
                del self.id_ctx
        return unsealed_message

    def _split_message(self, msg: message.Message, request: message.Message = None):
        """Given a protected message, return the outer message that contains
        all Class I and Class U options (but without payload or Object-Security
        option), and the encoded inner message that contains all Class E
        options and the payload.

        Copied from aiocoap.oscore._split_message, TODO: maybe consolidate

        This leaves the messages' remotes unset."""

        if msg.code.is_request():
            outer_host = msg.opt.uri_host
            proxy_uri = msg.opt.proxy_uri

            inner_message = msg.copy(
                uri_host=None,
                uri_port=None,
                proxy_uri=None,
                proxy_scheme=None,
                ocoap=None,
            )
            inner_message.remote = None

            if proxy_uri is not None:
                # Use set_request_uri to split up the proxy URI into its
                # components; extract, preserve and clear them.
                inner_message.set_request_uri(proxy_uri, set_uri_host=False)
                if inner_message.opt.proxy_uri is not None:
                    raise ValueError("Can not split Proxy-URI into options")
                outer_uri = inner_message.remote.uri_base
                inner_message.remote = None
                inner_message.opt.proxy_scheme = None

            if msg.opt.observe is None:
                outer_code = numbers.POST
            else:
                outer_code = numbers.FETCH
        else:
            assert request is not None
            outer_host = None
            proxy_uri = None

            inner_message = msg.copy()

            outer_code = (
                numbers.CONTENT if request.code == numbers.FETCH else numbers.CHANGED
            )

        # no max-age because these are always successful responses
        outer_message = message.Message(
            code=outer_code,
            uri_host=outer_host,
            ocoap=msg.opt.ocoap,
            observe=msg.opt.observe if msg.code.is_request() else None,
        )
        if proxy_uri is not None:
            outer_message.set_request_uri(outer_uri)

        plaintext = bytes([inner_message.code]) + inner_message.opt.encode()
        if inner_message.payload:
            plaintext += bytes([0xFF])
            plaintext += inner_message.payload

        return outer_message, plaintext

    def seal(
        self,
        unsealed_message: message.Message,
        sealed_request: Optional[message.Message] = None,
        payload_hdr: bytes = None,
    ) -> message.Message:
        is_response = unsealed_message.code.is_response()

        if is_response:
            assert sealed_request is not None
            if self.server_counter < 0:
                raise RuntimeError()
            elif self.server_counter == 0:
                secret, secret_length = self._export_response_secret()
                response_nonce = secrets.token_bytes(secret_length)

                prk = self._extract_response_prk(response_nonce, secret, sealed_request)
                self._expand_aead_details(prk)

            ocoap_opt = self._construct_ocoap_option(is_response)
            # replace potentially existing OCoAP option
            # (e.g. when reusing previous response)
            unsealed_message.opt.delete_option(OptionNumber.OCOAP)
            unsealed_message.opt.add_option(ocoap_opt)
            aad = self._response_aad(sealed_request.opt.ocoap, unsealed_message.opt)
            aead_nonce = self._compute_response_aead_nonce(self.server_counter)
            outer_message, plaintext = self._split_message(
                unsealed_message, sealed_request
            )
            try:
                ciphertext = self.suite.aead.seal(
                    self.aead_key,
                    aead_nonce,
                    aad,
                    plaintext,
                )
            except ValueError as exc:
                raise hpke.SealError(exc) from exc
            if self.server_counter == 0:
                outer_message.payload = response_nonce + ciphertext
            else:
                outer_message.payload = ciphertext
            self.server_counter += 1
        else:
            if (
                not unsealed_message.opt.proxy_uri
                and not unsealed_message.opt.proxy_scheme
            ):
                _ocoap_log.warning(
                    "Not sending request through proxy will still expose "
                    "the identity of your client"
                )
            if payload_hdr is None:
                payload_hdr = self.PAYLOAD_HDR_FORMAT.pack(
                    self.key_id,
                    self.suite.kem_id,
                    self.suite.kdf_id,
                    self.suite.aead_id,
                )
            ocoap_opt = self._construct_ocoap_option(False)
            # replace potentially existing OCoAP option
            # (e.g. when reusing previous request)
            unsealed_message.opt.delete_option(OptionNumber.OCOAP)
            unsealed_message.opt.add_option(ocoap_opt)
            aad = self._request_aad(unsealed_message.opt, payload_hdr)
            outer_message, plaintext = self._split_message(unsealed_message)
            try:
                ciphertext = self.ctx.seal(plaintext, aad)
            except Exception as exc:
                raise hpke.SealError(exc) from exc
            if self.client_counter == 0:
                outer_message.payload = payload_hdr + self.enc + ciphertext
            else:
                outer_message.payload = ciphertext
            self.client_counter += 1
        if not _more(unsealed_message):
            if is_response or not (
                unsealed_message.opt.observe or unsealed_message.opt.block1
            ):
                # only delete id_ctx if response or if not an unsubscription
                # or block1 request (we still need the context for the response
                # in those cases)
                del self.id_ctx
        return outer_message
