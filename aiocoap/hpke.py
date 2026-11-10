# SPDX-FileCopyrightText: Martine S. Lenders
#
# SPDX-License-Identifier: MIT

"""This module TBD"""

import enum
import io
from pathlib import Path
import struct
from typing import Any, BinaryIO, Optional, Union

import cbor_diag
import cbor2
import cryptography.exceptions

import pyhpke
import pyhpke.kem

from . import error
from . import credentials


class SealError(error.Error, ValueError):
    """Raised when verification of an OCoAP message fails because payload or OCoAP option was erroneous"""


class OpenError(error.Error, ValueError):
    """Raised when verification of an OCoAP message fails because payload or OCoAP option was erroneous"""


HPKE_VERSION = b"HPKE-v1"


class KEM_ID(enum.IntEnum):
    DHKEM_P256_HKDF_SHA256 = pyhpke.KEMId.DHKEM_P256_HKDF_SHA256.value
    DHKEM_P384_HKDF_SHA384 = pyhpke.KEMId.DHKEM_P384_HKDF_SHA384.value
    DHKEM_P521_HKDF_SHA512 = pyhpke.KEMId.DHKEM_P521_HKDF_SHA512.value
    DHKEM_X25519_HKDF_SHA256 = pyhpke.KEMId.DHKEM_X25519_HKDF_SHA256.value
    DHKEM_X448_HKDF_SHA512 = pyhpke.KEMId.DHKEM_X448_HKDF_SHA512.value

    def __int__(self):
        return self.value


class KDF_ID(enum.IntEnum):
    HKDF_SHA256 = pyhpke.KDFId.HKDF_SHA256.value
    HKDF_SHA384 = pyhpke.KDFId.HKDF_SHA384.value
    HKDF_SHA512 = pyhpke.KDFId.HKDF_SHA512.value

    def __int__(self):
        return self.value


class AEAD_ID(enum.IntEnum):
    AES128_GCM = pyhpke.AEADId.AES128_GCM.value
    AES256_GCM = pyhpke.AEADId.AES256_GCM.value
    CHACHA20_POLY1305 = pyhpke.AEADId.CHACHA20_POLY1305.value
    EXPORT_ONLY = pyhpke.AEADId.EXPORT_ONLY.value

    def __int__(self):
        return self.value


class KEM:
    # See https://www.iana.org/assignments/hpke
    N_PK = {
        KEM_ID.DHKEM_P256_HKDF_SHA256: 65,
        KEM_ID.DHKEM_P384_HKDF_SHA384: 97,
        KEM_ID.DHKEM_P521_HKDF_SHA512: 133,
        KEM_ID.DHKEM_X25519_HKDF_SHA256: 32,
        KEM_ID.DHKEM_X448_HKDF_SHA512: 56,
    }
    N_SK = {
        KEM_ID.DHKEM_P256_HKDF_SHA256: 32,
        KEM_ID.DHKEM_P384_HKDF_SHA384: 48,
        KEM_ID.DHKEM_P521_HKDF_SHA512: 66,
        KEM_ID.DHKEM_X25519_HKDF_SHA256: 32,
        KEM_ID.DHKEM_X448_HKDF_SHA512: 56,
    }
    N_ENC = {
        KEM_ID.DHKEM_P256_HKDF_SHA256: 65,
        KEM_ID.DHKEM_P384_HKDF_SHA384: 97,
        KEM_ID.DHKEM_P521_HKDF_SHA512: 133,
        KEM_ID.DHKEM_X25519_HKDF_SHA256: 32,
        KEM_ID.DHKEM_X448_HKDF_SHA512: 56,
    }

    class Key:
        def __init__(self, internal: Any):
            self._internal = internal

        def __eq__(self, other):
            return self.serialize() == other.serialize()

        @property
        def internal(self):
            return self._internal  # pragma: no cover

        def serialize(self) -> bytes:
            raise NotImplementedError  # pragma: no cover

    class PublicKey(Key):
        def serialize(self) -> bytes:
            return self._internal.to_public_bytes()

    class PrivateKey(Key):
        def serialize(self) -> bytes:
            return self._internal.to_private_bytes()

    def __init__(self, kem_id: Union[KEM_ID, int], kem: Optional[Any] = None):
        try:
            self._kem_id = KEM_ID(kem_id)
        except ValueError as exc:
            raise ValueError(f"KEM ID = 0x{kem_id:04X} is not supported.") from exc
        if kem is not None:
            self._kem = kem
        else:
            self._kem = pyhpke.kem.KEM(pyhpke.KEMId(int(self._kem_id)))

    @classmethod
    def n_pk_from_kem_id(cls, kem_id: Union[KEM_ID, int]):
        try:
            kem_id = KEM_ID(kem_id)
        except ValueError as exc:
            raise ValueError(f"KEM ID = 0x{kem_id:04X} is not supported.") from exc
        return cls.N_PK[kem_id]

    @property
    def kem_id(self) -> KEM_ID:
        return self._kem_id

    @property
    def n_pk(self) -> int:
        return self.N_PK[self._kem_id]

    @property
    def n_sk(self) -> int:
        return self.N_SK[self._kem_id]

    @property
    def n_enc(self) -> int:
        return self.N_ENC[self._kem_id]

    def generate_key_pair(self) -> tuple[KEM.PrivateKey, KEM.PublicKey]:
        key_pair = self._kem._prim.generate_key_pair()
        return (
            KEM.PrivateKey(key_pair.private_key),
            KEM.PublicKey(key_pair.public_key),
        )

    def deserialize_public_key(self, data: bytes) -> KEM.PublicKey:
        return self.PublicKey(self._kem.deserialize_public_key(data))

    def deserialize_private_key(self, data: bytes) -> KEM.PrivateKey:
        return self.PrivateKey(self._kem.deserialize_private_key(data))


class KDF:
    N_H = {
        KDF_ID.HKDF_SHA256: 32,
        KDF_ID.HKDF_SHA384: 48,
        KDF_ID.HKDF_SHA512: 64,
    }

    def __init__(self, kdf_id: Union[KDF_ID, int], kdf: Optional[Any] = None):
        try:
            self._kdf_id = KDF_ID(kdf_id)
        except ValueError as exc:
            raise ValueError(f"KDF ID = 0x{kdf_id:04X} is not supported.") from exc
        self._kdf = kdf

    @property
    def kdf_id(self) -> KDF_ID:
        return self._kdf_id

    @property
    def n_h(self) -> int:
        return self.N_H[self._kdf_id]

    def expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        if not self._kdf:
            raise RuntimeError("Unable to run KDF.expand(): uninitialized")
        return self._kdf.expand(prk, info, length)

    def extract(self, salt: bytes, ikm: bytes) -> bytes:
        if not self._kdf:
            raise RuntimeError("Unable to run KDF.extract(): uninitialized")
        return self._kdf.extract(salt, ikm)


class AEAD:
    N_K = {
        AEAD_ID.AES128_GCM: 16,
        AEAD_ID.AES256_GCM: 32,
        AEAD_ID.CHACHA20_POLY1305: 32,
        AEAD_ID.EXPORT_ONLY: 0,
    }
    N_N = {
        AEAD_ID.AES128_GCM: 12,
        AEAD_ID.AES256_GCM: 12,
        AEAD_ID.CHACHA20_POLY1305: 12,
        AEAD_ID.EXPORT_ONLY: 0,
    }

    def __init__(self, aead_id: Union[AEAD_ID, int], aead: Optional[Any] = None):
        try:
            self._aead_id = AEAD_ID(aead_id)
        except ValueError as exc:
            raise ValueError(f"AEAD ID = 0x{aead_id:04X} is not supported.") from exc
        if aead is not None:
            self._aead = aead
        else:
            self._aead = pyhpke.aead.AEAD(pyhpke.AEADId(int(self._aead_id)))

    @property
    def aead_id(self) -> AEAD_ID:
        return self._aead_id

    @property
    def n_k(self) -> int:
        return self.N_K[self._aead_id]

    @property
    def n_n(self) -> int:
        return self.N_N[self._aead_id]

    def seal(self, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        try:
            return self._aead.import_key(key).seal(plaintext, nonce, aad)
        except (ValueError, pyhpke.SealError) as exc:
            raise ValueError(exc) from exc

    def open(self, key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        try:
            return self._aead.import_key(key).open(ciphertext, nonce, aad)
        except (
            ValueError,
            pyhpke.OpenError,
            cryptography.exceptions.InvalidTag,
        ) as exc:
            raise ValueError(exc) from exc


class HPKEContext:
    def __init__(self, internal):
        self._internal = internal

    def seal(self, plaintext: bytes, aad: bytes = None) -> bytes:
        try:
            return self._internal.seal(plaintext, aad or b"")
        except pyhpke.SealError as exc:
            raise SealError(exc) from exc

    def open(self, ciphertext: bytes, aad: bytes = None) -> bytes:
        try:
            return self._internal.open(ciphertext, aad or b"")
        except (pyhpke.OpenError, cryptography.exceptions.InvalidTag) as exc:
            raise OpenError(exc) from exc

    def export(self, exporter_context: bytes, length: int) -> bytes:
        return self._internal.export(exporter_context, length)


class HPKESuite:
    def __init__(
        self,
        kem_id: Union[KEM_ID, int],
        kdf_id: Union[KDF_ID, int],
        aead_id: Union[AEAD_ID, int],
    ):
        self._suite = pyhpke.CipherSuite.new(
            pyhpke.KEMId(int(kem_id)),
            pyhpke.KDFId(int(kdf_id)),
            pyhpke.AEADId(int(aead_id)),
        )

    @property
    def kem(self) -> KEM:
        return KEM(self._suite.kem.id.value, self._suite.kem)

    @property
    def kdf(self) -> KDF:
        return KDF(self._suite.kdf.id.value, self._suite.kdf)

    @property
    def aead(self) -> AEAD:
        return AEAD(self._suite.aead.id.value, self._suite.aead)

    @property
    def kem_id(self) -> KEM_ID:
        return KEM_ID(int(self.kem.kem_id))

    @property
    def kdf_id(self) -> KDF_ID:
        return KDF_ID(self._suite.kdf.id.value)

    @property
    def aead_id(self) -> AEAD_ID:
        return AEAD_ID(self._suite.aead.id.value)

    def setup_base_s(
        self,
        pk_r: KEM.PublicKey,
        info: Optional[bytes] = None,
        _ephemeral_keys: Optional[tuple[KEM.PrivateKey, KEM.PublicKey]] = None,
    ) -> tuple[bytes, HPKEContext]:
        if _ephemeral_keys is not None:  # pragma: no branch
            _ephemeral_keys = pyhpke.KEMKeyPair(
                _ephemeral_keys[0].internal,
                _ephemeral_keys[1].internal,
            )
        enc, ctx = self._suite.create_sender_context(
            pk_r.internal,
            info or b"",
            eks=_ephemeral_keys,
        )
        return bytes(enc), HPKEContext(ctx)

    def setup_base_r(
        self, enc: bytes, sk_r: KEM.PrivateKey, info: Optional[bytes] = None
    ) -> HPKEContext:
        return HPKEContext(
            self._suite.create_recipient_context(
                enc,
                sk_r.internal,
                info or b"",
            ),
        )


class HPKEKeyConfig:
    CBOR_KEY_ID_KEY = 0
    CBOR_KEM_ID_KEY = 1
    CBOR_PUBLIC_KEY_KEY = 2
    CBOR_SYMMETIC_ALGORITHMS_KEY = 3

    def __init__(
        self,
        key_id: int,
        kem_id: int,
        symmetric_algorithms: list[tuple[int, int]],
        public_key: Union[bytes, KEM.PublicKey],
    ):
        self.key_id = key_id
        self.kem_id = kem_id
        self._kem = KEM(kem_id)
        if isinstance(public_key, bytes):
            self.public_key = self._kem.deserialize_public_key(public_key)
        else:
            self.public_key = public_key
        self.symmetric_algorithm_ids = symmetric_algorithms
        self.suites = dict()
        self._init_suites()

    def _init_suites(self):
        for kdf_id, aead_id in self.symmetric_algorithm_ids:
            self.suites[self.kem_id, kdf_id, aead_id] = HPKESuite(
                self.kem_id, kdf_id, aead_id
            )

    @staticmethod
    def _list_to_pairs(lst):
        return zip(lst[::2], lst[1::2])

    @staticmethod
    def generate_key_pair(
        key_id: int,
        kem_id: int,
        symmetric_algorithms: list[tuple[int, int]],
    ) -> (HPKEKeyConfig, KEM.PrivateKey):
        kem = KEM(kem_id)
        private_key, public_key = kem.generate_key_pair()
        config = HPKEKeyConfig(
            key_id=key_id,
            kem_id=kem_id,
            symmetric_algorithms=symmetric_algorithms,
            public_key=public_key,
        )
        return config, private_key

    @classmethod
    def load_ocoap_keys_cbor(cls, fp: BinaryIO) -> HPKEKeyConfig:
        key_config = cbor2.load(fp)
        return cls.cbor_dict_to_key_config(key_config)

    def dump_ocoap_key_cbor(self, fp: BinaryIO):
        cbor2.dump(
            {
                self.CBOR_KEY_ID_KEY: self.key_id,
                self.CBOR_KEM_ID_KEY: self.kem_id,
                self.CBOR_PUBLIC_KEY_KEY: self.public_key.serialize(),
                self.CBOR_SYMMETIC_ALGORITHMS_KEY: [
                    id for pair in self.symmetric_algorithm_ids for id in pair
                ],
            },
            fp,
        )

    def dumps_ocoap_key_cbor(self):
        with io.BytesIO() as fp:
            self.dump_ocoap_key_cbor(fp)
            return fp.getvalue()

    @classmethod
    def cbor_dict_to_key_config(cls, key_config_dict: dict) -> HPKEKeyConfig:
        if (
            any(
                key not in key_config_dict
                for key in (
                    cls.CBOR_KEY_ID_KEY,
                    cls.CBOR_KEM_ID_KEY,
                    cls.CBOR_PUBLIC_KEY_KEY,
                    cls.CBOR_SYMMETIC_ALGORITHMS_KEY,
                )
            )
            or any(
                not isinstance(key_config_dict[int_key], int)
                for int_key in (
                    cls.CBOR_KEY_ID_KEY,
                    cls.CBOR_KEM_ID_KEY,
                )
            )
            or any(
                byte_key in key_config_dict
                and not isinstance(key_config_dict[byte_key], bytes)
                for byte_key in (cls.CBOR_PUBLIC_KEY_KEY,)
            )
            or (
                len(key_config_dict[cls.CBOR_PUBLIC_KEY_KEY])
                != KEM.n_pk_from_kem_id(key_config_dict[cls.CBOR_KEM_ID_KEY])
            )
            or not isinstance(key_config_dict[cls.CBOR_SYMMETIC_ALGORITHMS_KEY], list)
            or len(key_config_dict[cls.CBOR_SYMMETIC_ALGORITHMS_KEY]) == 0
            or len(key_config_dict[cls.CBOR_SYMMETIC_ALGORITHMS_KEY]) % 2
            or any(
                len(pair) != 2
                or not isinstance(pair[0], int)
                or not isinstance(pair[1], int)
                for pair in cls._list_to_pairs(
                    key_config_dict[cls.CBOR_SYMMETIC_ALGORITHMS_KEY]
                )
            )
        ):
            raise ValueError("Not a recognizable CBOR-encoded HPKE key configuration.")
        return HPKEKeyConfig(
            key_id=key_config_dict[cls.CBOR_KEY_ID_KEY],
            kem_id=key_config_dict[cls.CBOR_KEM_ID_KEY],
            public_key=key_config_dict[cls.CBOR_PUBLIC_KEY_KEY],
            symmetric_algorithms=list(
                cls._list_to_pairs(key_config_dict[cls.CBOR_SYMMETIC_ALGORITHMS_KEY])
            ),
        )

    @staticmethod
    def load_ohttp_key(fp: BinaryIO) -> HPKEKeyConfig:
        key_id, kem_id = struct.unpack("!BH", fp.read(3))

        n_pk = KEM.n_pk_from_kem_id(kem_id)
        public_key = fp.read(n_pk)
        if len(public_key) != n_pk:
            raise IOError("Not a recognizable key config collection")

        (symmetric_algorithms_len,) = struct.unpack("!H", fp.read(2))
        if symmetric_algorithms_len == 0 or symmetric_algorithms_len % 4:
            raise IOError("Not a recognizable key config collection")

        symmetric_algorithms = []
        while symmetric_algorithms_len > 0:
            kdf_id, aead_id = struct.unpack("!HH", fp.read(4))
            symmetric_algorithms_len -= 4
            symmetric_algorithms.append((kdf_id, aead_id))

        return HPKEKeyConfig(
            key_id=key_id,
            kem_id=kem_id,
            public_key=public_key,
            symmetric_algorithms=symmetric_algorithms,
        )

    def dump_ohttp_key(self, fp: BinaryIO):
        res = fp.write(
            struct.pack(
                "!BH",
                self.key_id,
                self.kem_id,
            )
        )
        if res < struct.calcsize("!BH"):
            raise IOError("Unable to dump full key configuration")
        pub_key = self.public_key.serialize()
        res = fp.write(pub_key)
        if res < len(pub_key):
            raise IOError("Unable to dump full key configuration")

        res = fp.write(
            struct.pack(
                "!H",
                len(self.symmetric_algorithm_ids) * 4,
            )
        )
        if res < struct.calcsize("!H"):
            raise IOError("Unable to dump full key configuration")
        for kdf_id, aead_id in self.symmetric_algorithm_ids:
            res = fp.write(struct.pack("!HH", kdf_id, aead_id))
            if res < struct.calcsize("!HH"):
                raise IOError("Unable to dump full key configuration")


class HPKEKeyConfigFormat(enum.IntEnum):
    OHTTP_KEYS = 1
    OCOAP_CBOR_SEQ = 2


class HPKEKeyConfigDB(dict):
    def __init__(self):
        self._key_ids = {}
        self._private_keys = {}

    def iter_supported(self):
        for key_id, kem_id, kdf_id, aead_id in self:
            # if not supported, the key will not be in this DB
            yield key_id, kem_id, kdf_id, aead_id

    def generate_key_pair(
        self,
        kem_id: int,
        symmetric_algorithms: list[tuple[int, int]],
        key_id: Optional[int] = None,
    ) -> HPKEKeyConfig:
        if key_id is None:
            if kem_id in self._key_ids:
                key_id = self._key_ids[kem_id] + 1
            else:
                key_id = 1
        config, private_key = HPKEKeyConfig.generate_key_pair(
            key_id, kem_id, symmetric_algorithms
        )
        self.add_key_config(config)
        self.add_private_key(key_id, kem_id, private_key)
        return config

    def add_key_config(
        self,
        config: HPKEKeyConfig,
    ) -> None:
        for _, suite in config.suites.items():
            key_id = config.key_id
            kem_id = suite.kem_id
            kdf_id = suite.kdf_id
            aead_id = suite.aead_id
            if (key_id, kem_id, kdf_id, aead_id) in self:
                raise ValueError(
                    f"(key_id, kem_id, kdf_id, aead_id) already in {self!r}"
                )
            self[key_id, kem_id, kdf_id, aead_id] = config
            if self._key_ids.get(kem_id, -1) < key_id:
                self._key_ids[kem_id] = key_id

    def get_key_config(
        self, key_id: int, kem_id: int, kdf_id: int, aead_id: int
    ) -> HPKEKeyConfig:
        return self[key_id, kem_id, kdf_id, aead_id]

    def get_private_key(self, key_id: int, kem_id: int) -> KEM.PrivateKey:
        return self._private_keys[key_id, kem_id]

    def add_private_key(
        self, key_id: int, kem_id: int, private_key: Union[KEM.PrivateKey, bytes]
    ):
        if isinstance(private_key, bytes):
            private_key = KEM(kem_id).deserialize_private_key(private_key)
        self._private_keys[key_id, kem_id] = private_key

    def get_suite(
        self, key_id: int, kem_id: int, kdf_id: int, aead_id: int
    ) -> HPKESuite:
        return self[key_id, kem_id, kdf_id, aead_id].suites[kem_id, kdf_id, aead_id]

    @staticmethod
    def _decode_cbor_sequence(fp):
        decoder = cbor2.CBORDecoder(fp)
        while fp.peek(1):
            yield decoder.decode()

    @classmethod
    def load_ocoap_keys_cbor_seq(cls, fp: BinaryIO) -> HPKEKeyConfigDB:
        key_configs = HPKEKeyConfigDB()
        for key_config in cls._decode_cbor_sequence(fp):
            try:
                key_configs.add_key_config(
                    HPKEKeyConfig.cbor_dict_to_key_config(key_config)
                )
            except ValueError:
                # Do not load unsupported keys
                pass
        if len(key_configs) == 0:
            raise ValueError("Not a recognizable CBOR-encoded HPKE key configuration.")
        return key_configs

    def dump_ocoap_keys_cbor_seq(self, fp: BinaryIO):
        already_dumped = set()
        for key_id, kem_id, kdf_id, aead_id in sorted(self):
            if (key_id, kem_id) in already_dumped:
                continue
            self[key_id, kem_id, kdf_id, aead_id].dump_ocoap_key_cbor(fp)
            already_dumped.add((key_id, kem_id))

    @staticmethod
    def load_ohttp_keys(fp: BinaryIO) -> HPKEKeyConfigDB:
        if not fp.peek(2):
            raise ValueError("Not a recognizable key config collection")
        try:
            (length,) = struct.unpack("!H", fp.read(2))
            if not fp.peek(length):
                raise ValueError("Not a recognizable key config collection")
            key_configs = HPKEKeyConfigDB()
            while fp.tell() - 2 < length:
                try:
                    key_configs.add_key_config(HPKEKeyConfig.load_ohttp_key(fp))
                except ValueError:
                    # Do not load unsupported keys
                    pass
        except (IOError, struct.error) as exc:
            raise ValueError("Not a recognizable key config collection") from exc
        return key_configs

    def dump_ohttp_keys(self, fp: BinaryIO):
        config_keys = sorted(self)
        length = 0
        to_dump = dict()
        for key_id, kem_id, kdf_id, aead_id in sorted(config_keys):
            if (key_id, kem_id) in to_dump:
                continue
            config = self[key_id, kem_id, kdf_id, aead_id]
            length += (
                len(config.public_key.serialize())
                + 5
                + (4 * len(config.symmetric_algorithm_ids))
            )
            to_dump[(key_id, kem_id)] = config
        res = fp.write(struct.pack("!H", length))
        if res < struct.calcsize("!H"):
            raise IOError("Unable to dump full key configuration")
        for key_id, kem_id in sorted(to_dump):
            to_dump[key_id, kem_id].dump_ohttp_key(fp)

    @classmethod
    def load_key_config(cls, fp: BinaryIO) -> HPKEKeyConfigDB:
        try:
            return cls.load_ocoap_keys_cbor_seq(fp)
        except Exception as exc:
            fp.seek(0)
            # Could not decode as CBOR
            return cls.load_ohttp_keys(fp)

    def store(
        self,
        config_file: Union[Path, str],
        key_config_file: Union[Path, str],
        fmt: HPKEKeyConfigFormat,
    ):
        config_file = Path(config_file)
        key_config_file = Path(key_config_file)
        with key_config_file.open("wb") as fp:
            if fmt == HPKEKeyConfigFormat.OHTTP_KEYS:
                self.dump_ohttp_keys(fp)
            elif fmt == HPKEKeyConfigFormat.OCOAP_CBOR_SEQ:
                self.dump_ocoap_keys_cbor_seq(fp)
            else:
                raise ValueError("Unsupported format")
        config_str = cbor_diag.cbor2diag(
            cbor2.dumps(
                {
                    "key_config_file": str(
                        key_config_file.relative_to(config_file.parent)
                    ),
                    "private_keys": {
                        (key_id, kem_id): key.serialize()
                        for (key_id, kem_id), key in self._private_keys.items()
                    },
                }
            )
        )
        with config_file.open("wt", encoding="utf-8") as fp:
            fp.write(config_str)

    @staticmethod
    def load(config_file: Union[Path, str]):
        with Path(config_file).open("rt") as fp:
            cbordiag = fp.read()
            config_dict = cbor2.loads(cbor_diag.diag2cbor(cbordiag))
        with Path(config_dict["key_config_file"]).open("rb") as fp:
            config_db = HPKEKeyConfigDB.load_key_config(fp)
        for (key_id, kem_id), private_key in config_dict.get(
            "private_keys", {}
        ).items():
            config_db.add_private_key(key_id, kem_id, private_key)
        return config_db
