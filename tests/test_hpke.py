# SPDX-FileCopyrightText: Martine S. Lenders
#
# SPDX-License-Identifier: MIT

"""Unittests and integration tests for HPKE"""

import copy
import io
import json
import os.path
import struct
import unittest
import unittest.mock

import pytest

import aiocoap

ocoap_modules = aiocoap.defaults.ocoap_missing_modules()

if not ocoap_modules:
    import cbor2
    import aiocoap.hpke


_skip_unless_ocoap = unittest.skipIf(
    ocoap_modules, "Modules missing for running HPKE tests: %s" % (ocoap_modules,)
)


@_skip_unless_ocoap
class TestKEM(unittest.TestCase):
    def test_n_pk_from_kem_id(self):
        with self.assertRaises(ValueError):
            aiocoap.hpke.KEM.n_pk_from_kem_id(0x0000)
        # See https://www.iana.org/assignments/hpke for test vector basis
        assert aiocoap.hpke.KEM.n_pk_from_kem_id(0x0010) == 65
        assert aiocoap.hpke.KEM.n_pk_from_kem_id(0x0011) == 97
        assert aiocoap.hpke.KEM.n_pk_from_kem_id(0x0012) == 133
        assert aiocoap.hpke.KEM.n_pk_from_kem_id(0x0020) == 32
        assert aiocoap.hpke.KEM.n_pk_from_kem_id(0x0021) == 56

    def test_kem_id(self):
        with self.assertRaises(ValueError):
            aiocoap.hpke.KEM(0x0000)
        assert int(aiocoap.hpke.KEM(0x0010).kem_id) == 0x0010
        assert int(aiocoap.hpke.KEM(0x0011).kem_id) == 0x0011
        assert int(aiocoap.hpke.KEM(0x0012).kem_id) == 0x0012
        assert int(aiocoap.hpke.KEM(0x0020).kem_id) == 0x0020
        assert int(aiocoap.hpke.KEM(0x0021).kem_id) == 0x0021

    def test_n_pk(self):
        # See https://www.iana.org/assignments/hpke for test vector basis
        assert aiocoap.hpke.KEM(0x0010).n_pk == 65
        assert aiocoap.hpke.KEM(0x0011).n_pk == 97
        assert aiocoap.hpke.KEM(0x0012).n_pk == 133
        assert aiocoap.hpke.KEM(0x0020).n_pk == 32
        assert aiocoap.hpke.KEM(0x0021).n_pk == 56

    def test_s_pk(self):
        # See https://www.iana.org/assignments/hpke for test vector basis
        assert aiocoap.hpke.KEM(0x0010).n_sk == 32
        assert aiocoap.hpke.KEM(0x0011).n_sk == 48
        assert aiocoap.hpke.KEM(0x0012).n_sk == 66
        assert aiocoap.hpke.KEM(0x0020).n_sk == 32
        assert aiocoap.hpke.KEM(0x0021).n_sk == 56

    def test_n_enc(self):
        # See https://www.iana.org/assignments/hpke for test vector basis
        assert aiocoap.hpke.KEM(0x0010).n_enc == 65
        assert aiocoap.hpke.KEM(0x0011).n_enc == 97
        assert aiocoap.hpke.KEM(0x0012).n_enc == 133
        assert aiocoap.hpke.KEM(0x0020).n_enc == 32
        assert aiocoap.hpke.KEM(0x0021).n_enc == 56

    def _test_generate_key_pair(self, kem):
        private_key, public_key = kem.generate_key_pair()
        assert isinstance(private_key, aiocoap.hpke.KEM.PrivateKey)
        assert isinstance(public_key, aiocoap.hpke.KEM.PublicKey)
        return private_key, public_key

    def test_generate_key_pair(self):
        for kem_id in aiocoap.hpke.KEM_ID:
            self._test_generate_key_pair(aiocoap.hpke.KEM(kem_id))

    def _test_deserialize_public_key(self, kem):
        _, public_key = self._test_generate_key_pair(kem)
        public_key_bytes = public_key.serialize()
        assert kem.deserialize_public_key(public_key_bytes) == public_key

    def test_deserialize_public_key(self):
        for kem_id in aiocoap.hpke.KEM_ID:
            self._test_deserialize_public_key(aiocoap.hpke.KEM(kem_id))

    def _test_deserialize_private_key(self, kem):
        private_key, _ = self._test_generate_key_pair(kem)
        private_key_bytes = private_key.serialize()
        assert kem.deserialize_private_key(private_key_bytes) == private_key

    def test_deserialize_private_key(self):
        for kem_id in aiocoap.hpke.KEM_ID:
            self._test_deserialize_private_key(aiocoap.hpke.KEM(kem_id))


@_skip_unless_ocoap
class TestKDF(unittest.TestCase):
    def test_kdf_id(self):
        # See https://www.iana.org/assignments/hpke for test vector basis
        with self.assertRaises(ValueError):
            aiocoap.hpke.KDF(0x0000).kdf_id
        assert int(aiocoap.hpke.KDF(0x0001).kdf_id) == 0x0001
        assert int(aiocoap.hpke.KDF(0x0002).kdf_id) == 0x0002
        assert int(aiocoap.hpke.KDF(0x0003).kdf_id) == 0x0003

    def test_n_h(self):
        # See https://www.iana.org/assignments/hpke for test vector basis
        assert int(aiocoap.hpke.KDF(0x0001).n_h) == 32
        assert int(aiocoap.hpke.KDF(0x0002).n_h) == 48
        assert int(aiocoap.hpke.KDF(0x0003).n_h) == 64

    def test_expand(self):
        kdf = aiocoap.hpke.KDF(0x0001)
        with self.assertRaises(RuntimeError):
            kdf.expand(b"some_prk", b"some_info", 5)
        # testing non-failing in TestHPKESuite, as we need the suite for that

    def test_extract(self):
        kdf = aiocoap.hpke.KDF(0x0001)
        with self.assertRaises(RuntimeError):
            kdf.extract(b"some_salt", b"some_ikm")
        # testing non-failing in TestHPKESuite, as we need the suite for that


@_skip_unless_ocoap
class TestAEAD_ID(unittest.TestCase):
    def test_aead_id(self):
        # See https://www.iana.org/assignments/hpke for test vector basis
        with self.assertRaises(ValueError):
            aiocoap.hpke.AEAD(0x0000).aead_id
        internal = aiocoap.hpke.AEAD(0x0001)._aead
        assert int(aiocoap.hpke.AEAD(0x0001, internal).aead_id) == 0x0001
        assert int(aiocoap.hpke.AEAD(0x0002).aead_id) == 0x0002
        assert int(aiocoap.hpke.AEAD(0x0003).aead_id) == 0x0003
        assert int(aiocoap.hpke.AEAD(0xFFFF).aead_id) == 0xFFFF

    def test_n_k(self):
        # See https://www.iana.org/assignments/hpke for test vector basis
        assert int(aiocoap.hpke.AEAD(0x0001).n_k) == 16
        assert int(aiocoap.hpke.AEAD(0x0002).n_k) == 32
        assert int(aiocoap.hpke.AEAD(0x0003).n_k) == 32
        assert int(aiocoap.hpke.AEAD(0xFFFF).n_k) == 0

    def test_n_n(self):
        # See https://www.iana.org/assignments/hpke for test vector basis
        assert int(aiocoap.hpke.AEAD(0x0001).n_n) == 12
        assert int(aiocoap.hpke.AEAD(0x0002).n_n) == 12
        assert int(aiocoap.hpke.AEAD(0x0003).n_n) == 12
        assert int(aiocoap.hpke.AEAD(0xFFFF).n_n) == 0

    def test_seal_open(self):
        aead = aiocoap.hpke.AEAD(0x0001)

        with self.assertRaises(ValueError):
            aead.seal(
                b"too small key",
                b"nonce",
                b"some authenticated data",
                b"The actual plaintext we want to encrypt",
            )

        key = b"A 16-byte key..."
        exp_plaintext = b"The actual plaintext we want to encrypt"
        assert len(key) == aead.n_k
        ciphertext = aead.seal(
            key,
            b"long enough nonce",
            b"some authenticated data",
            exp_plaintext,
        )
        exp_ciphertext = (
            b"U\x14c:\xda\xa0\xc2\x89p\xa3Gk6dm\x90\xa4l\x1dH}P\xfaN\\\xe9\x98 "
            b"q\x16\xecU\xc1\x03\x9f\x05b*\xafV\x88\x16\x01w\x89\x81\xc0\xda\x0bHk|orV"
        )
        assert ciphertext == exp_ciphertext

        with self.assertRaises(ValueError):
            aead.open(
                b"a very wrong key",
                b"long enough nonce",
                b"some authenticated data",
                ciphertext,
            )
        plaintext = aead.open(
            key,
            b"long enough nonce",
            b"some authenticated data",
            ciphertext,
        )
        assert plaintext == exp_plaintext


class TestHPKEContext(unittest.TestCase):
    def test_seal_error(self):
        internal = unittest.mock.MagicMock()
        ctx = aiocoap.hpke.HPKEContext(internal)
        internal.seal.side_effect = aiocoap.hpke.pyhpke.SealError()
        with self.assertRaises(aiocoap.hpke.SealError):
            ctx.seal(b"Some plaintext", "Some aad")
        # testing non-failing in TestHPKESuite, as we need the suite for that

    def test_open_error(self):
        internal = unittest.mock.MagicMock()
        ctx = aiocoap.hpke.HPKEContext(internal)
        internal.open.side_effect = aiocoap.hpke.pyhpke.OpenError()
        with self.assertRaises(aiocoap.hpke.OpenError):
            ctx.open(b"Some ciphertext", "Some aad")
        internal.open.side_effect = aiocoap.hpke.cryptography.exceptions.InvalidTag()
        with self.assertRaises(aiocoap.hpke.OpenError):
            ctx.open(b"Some ciphertext", "Some aad")
        # testing non-failing in TestHPKESuite, as we need the suite for that


@_skip_unless_ocoap
class TestHPKESuite(unittest.TestCase):
    def _test_hpke_suite(self, vector):
        if any(key in vector for key in ["psk", "psk_id", "skSm", "pkSm"]):
            # OCoAP only needs Base HPKE, so skip PSK tests
            return False
        suite = aiocoap.hpke.HPKESuite(
            vector["kem_id"], vector["kdf_id"], vector["aead_id"]
        )

        assert suite.kem_id == aiocoap.hpke.KEM_ID(vector["kem_id"])
        assert suite.kdf_id == aiocoap.hpke.KDF_ID(vector["kdf_id"])
        assert int(suite.kdf.kdf_id) == vector["kdf_id"]
        assert suite.aead_id == aiocoap.hpke.AEAD_ID(vector["aead_id"])
        assert int(suite.aead.aead_id) == vector["aead_id"]

        expanded = suite.kdf.expand(b"abcdef", b"info", suite.aead.n_k)
        assert len(expanded) == suite.aead.n_k

        extracted = suite.kdf.extract(b"Very salty", b"input key material")
        assert len(extracted) == suite.kdf.n_h

        if vector.get("info"):
            info = bytes.fromhex(vector["info"])
        else:
            # info is empty so set it to None to test this behavior
            # of our wrapper
            info = None

        pk_e = suite.kem.deserialize_public_key(bytes.fromhex(vector["pkEm"]))
        sk_e = suite.kem.deserialize_private_key(bytes.fromhex(vector["skEm"]))

        pk_r = suite.kem.deserialize_public_key(bytes.fromhex(vector["pkRm"]))
        sk_r = suite.kem.deserialize_private_key(bytes.fromhex(vector["skRm"]))

        enc, sctxt = suite.setup_base_s(pk_r, info, (sk_e, pk_e))
        assert enc == bytes.fromhex(vector["enc"])
        rctxt = suite.setup_base_r(enc, sk_r, info)

        if vector["aead_id"] != int(aiocoap.hpke.AEAD_ID.EXPORT_ONLY):
            for encryption in vector["encryptions"]:
                plaintext = bytes.fromhex(encryption["pt"])
                if encryption.get("aad"):
                    aad = bytes.fromhex(encryption["aad"])
                else:
                    aad = None
                ciphertext = bytes.fromhex(encryption["ct"])
                sealed_ciphertext = sctxt.seal(plaintext, aad)
                assert ciphertext == sealed_ciphertext
                assert plaintext == rctxt.open(ciphertext, aad)

        for export in vector["exports"]:
            ec = (
                bytes.fromhex(export["exporter_context"])
                if len(export["exporter_context"]) > 0
                else b""
            )
            ev = bytes.fromhex(export["exported_value"])
            exported = sctxt.export(ec, export["L"])
            assert ev == exported
            exported = rctxt.export(ec, export["L"])
            assert ev == exported
        return True

    def test_hpke_suite(self):
        with open(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "test_hpke_test_vectors.json",
            ),
            encoding="utf-8",
        ) as vf:
            # load official test vectors ([TestVectors] from RFC 9180)
            vectors = json.load(vf)
        count = 0
        for vector in vectors:
            if self._test_hpke_suite(vector):
                count += 1
        assert count > 0


@_skip_unless_ocoap
class TestHPKEKeyConfig(unittest.TestCase):
    @unittest.mock.patch("aiocoap.hpke.KEM.deserialize_public_key")
    def test_init(self, deserialize):
        config = aiocoap.hpke.HPKEKeyConfig(
            key_id=0x37,
            kem_id=0x0011,
            public_key=b"public",
            symmetric_algorithms=[(0x0002, 0x0002)],
        )
        assert config.key_id == 0x37
        assert config.kem_id == 0x0011
        assert config.symmetric_algorithm_ids == [(0x0002, 0x0002)]
        assert config.public_key == deserialize.return_value
        assert config.suites[0x0011, 0x0002, 0x0002].kem_id == 0x0011
        assert config.suites[0x0011, 0x0002, 0x0002].kdf_id == 0x0002
        assert config.suites[0x0011, 0x0002, 0x0002].aead_id == 0x0002

        mock_public_key = aiocoap.hpke.KEM.PublicKey(unittest.mock.MagicMock())
        config = aiocoap.hpke.HPKEKeyConfig(
            key_id=0x40,
            kem_id=0x0010,
            public_key=mock_public_key,
            symmetric_algorithms=[(0x0001, 0x0001)],
        )
        assert config.key_id == 0x40
        assert config.kem_id == 0x0010
        assert config.symmetric_algorithm_ids == [(0x0001, 0x0001)]
        assert config.public_key == mock_public_key
        assert config.suites[0x0010, 0x0001, 0x0001].kem_id == 0x0010
        assert config.suites[0x0010, 0x0001, 0x0001].kdf_id == 0x0001
        assert config.suites[0x0010, 0x0001, 0x0001].aead_id == 0x0001

    @unittest.mock.patch("aiocoap.hpke.KEM.deserialize_public_key")
    @unittest.mock.patch(
        "aiocoap.hpke.KEM.generate_key_pair",
        return_value=(b"private", b"doesnt_matter"),
    )
    def test_generate_key_pair(self, generate_key_pair, deserialize_public_key):
        config, private_key = aiocoap.hpke.HPKEKeyConfig.generate_key_pair(
            0x37, 0x0010, [(0x0001, 0x0001)]
        )
        assert config.key_id == 0x37
        assert config.kem_id == 0x0010
        assert config.symmetric_algorithm_ids == [(0x0001, 0x0001)]
        assert config.public_key == deserialize_public_key.return_value
        assert private_key == b"private"
        assert len(config.suites) == 1
        assert config.suites[0x0010, 0x0001, 0x0001].kem_id == 0x0010
        assert config.suites[0x0010, 0x0001, 0x0001].kdf_id == 0x0001
        assert config.suites[0x0010, 0x0001, 0x0001].aead_id == 0x0001

    def _test_load_dump_cbor(self):
        exp_cbor_bin = cbor2.dumps(
            {
                0: 0x01,
                1: 0x0020,
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
                ),
                3: [0x0001, 0x0001, 0x0002, 0x0001],
            }
        )
        with io.BytesIO(exp_cbor_bin) as fp:
            config = aiocoap.hpke.HPKEKeyConfig.load_ocoap_keys_cbor(fp)
        assert config.key_id == 0x01
        assert config.kem_id == 0x0020
        assert config.public_key.serialize().hex() == (
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
        )
        assert config.symmetric_algorithm_ids == [
            (0x0001, 0x0001),
            (0x0002, 0x0001),
        ]
        assert exp_cbor_bin == config.dumps_ocoap_key_cbor()
        return config

    def test_load_dump_cbor(self):
        self._test_load_dump_cbor()

    def _test_load_dump_error(self, cbor_bin):
        with io.BytesIO(cbor_bin) as fp:
            with self.assertRaises(ValueError):
                aiocoap.hpke.HPKEKeyConfig.load_ocoap_keys_cbor(fp)

    def test_load_dump_error(self):
        objs = [
            # Key ID missing
            {
                1: 0x0020,
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
                ),
                3: [0x0001, 0x0001, 0x0002, 0x0001],
            },
            # KEM ID missing
            {
                0: 0x01,
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
                ),
                3: [0x0001, 0x0001, 0x0002, 0x0001],
            },
            # public key missing
            {
                0: 0x01,
                1: 0x0020,
                3: [0x0001, 0x0001, 0x0002, 0x0001],
            },
            # symmetric algorithms missing
            {
                0: 0x01,
                1: 0x0020,
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
                ),
            },
            # Key ID not int
            {
                0: "0x01",
                1: 0x0020,
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
                ),
                3: [0x0001, 0x0001, 0x0002, 0x0001],
            },
            # KEM ID not int
            {
                0: 0x01,
                1: "0x0020",
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
                ),
                3: [0x0001, 0x0001, 0x0002, 0x0001],
            },
            # public key not bytes
            {
                0: 0x01,
                1: 0x0020,
                2: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
                3: [0x0001, 0x0001, 0x0002, 0x0001],
            },
            # public key wrong length
            {
                0: 0x01,
                1: "0x0020",
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca"
                ),
                3: [0x0001, 0x0001, 0x0002, 0x0001],
            },
            # symmetric algorithms not array
            {
                0: 0x01,
                1: "0x0020",
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca"
                ),
                3: {0x0001: 0x0001, 0x0002: 0x0001},
            },
            # symmetric algorithms empty
            {
                0: 0x01,
                1: "0x0020",
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca"
                ),
                3: [],
            },
            # symmetric algorithms invalid length
            {
                0: 0x01,
                1: "0x0020",
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca"
                ),
                3: [0x0001, 0x0001, 0x0002],
            },
            # symmetric algorithms not int values
            {
                0: 0x01,
                1: "0x0020",
                2: bytes.fromhex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca"
                ),
                3: [0x0001, "0x0001", 0x0002, 0x0001],
            },
        ]
        for obj in objs:
            self._test_load_dump_error(cbor2.dumps(obj))

    def test_dump_ohttp_key_erros(self):
        config = self._test_load_dump_cbor()
        fp = unittest.mock.MagicMock()

        # mock partial key_id + kem_id write
        fp.write.return_value = 2
        with self.assertRaises(IOError):
            config.dump_ohttp_key(fp)
        fp.reset_mock()

        # mock partial public key write
        fp.write.side_effect = [3, 4]
        with self.assertRaises(IOError):
            config.dump_ohttp_key(fp)
        fp.reset_mock()

        # mock partial symmetric algorithms length write
        fp.write.side_effect = [3, aiocoap.hpke.KEM(config.kem_id).n_pk, 1]
        with self.assertRaises(IOError):
            config.dump_ohttp_key(fp)

        # mock partial kdf_id + aead_id write
        fp.write.side_effect = [3, aiocoap.hpke.KEM(config.kem_id).n_pk, 2, 4, 1]
        with self.assertRaises(IOError):
            config.dump_ohttp_key(fp)


@_skip_unless_ocoap
class TestHPKEKeyConfigDB(unittest.TestCase):
    # taken from test_hpke_test_vectors.json for kem_id = 32 (0x20)
    TEST_PUBKEY_20 = bytes.fromhex(
        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
    )
    TEST_PRIVKEY_20 = bytes.fromhex(
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"
    )
    # taken from test_hpke_test_vectors.json for kem_id = 33 (0x21)
    TEST_PUBKEY_21 = bytes.fromhex(
        "145d083ea7a6379dbb32dcbd8aff4c206ea5d069b75e96c6dd2a3e38f441471ac97adc"
        "a641fdad66685a96f32b7c3e064635fab3cc89234e"
    )
    TEST_PRIVKEY_21 = bytes.fromhex(
        "27a4354608f3bdd38f1f5af305f3e0682efe4e25808249d8fcb55927f6a9f446b8dc1d0a2c3b8cb133a5673b59a6d55ce754ec0c9a555401"
    )
    TEST_OHTTP_KEYS = (
        (22 + len(TEST_PUBKEY_20) + len(TEST_PUBKEY_21)).to_bytes(2, "big")  # length
        + (0x01).to_bytes(1, "big")  # key_id
        + (0x0020).to_bytes(2, "big")  # kem_id
        + TEST_PUBKEY_20
        + (8).to_bytes(2, "big")  # asymmetric algorithms length
        + (0x0001).to_bytes(2, "big")  # kdf_id
        + (0x0001).to_bytes(2, "big")  # aead_id
        + (0x0002).to_bytes(2, "big")  # kdf_id
        + (0x0001).to_bytes(2, "big")  # aead_id
        # ===============
        + (0x02).to_bytes(1, "big")  # key_id
        + (0x0021).to_bytes(2, "big")  # kem_id
        + TEST_PUBKEY_21
        + (4).to_bytes(2, "big")  # asymmetric algorithms length
        + (0x0001).to_bytes(2, "big")  # kdf_id
        + (0x0001).to_bytes(2, "big")  # aead_id
    )
    TEST_CONFIG_FILE_TEMPLATE = f"""
{{{{
    "key_config_file": "{{key_config_file}}",
    "private_keys": {{{{
        [{0x01}, {0x0020}]: h'{TEST_PRIVKEY_20.hex()}',
        [{0x02}, {0x0021}]: h'{TEST_PRIVKEY_21.hex()}',
    }}}}
}}}}
"""

    @property
    def cbor_seq_for_testing(self):
        # class test vector provided as property method because `cbor2` is only loaded
        # when it is installed.
        return cbor2.dumps(
            {
                0: 0x01,
                1: 0x0020,
                2: self.TEST_PUBKEY_20,
                3: [0x0001, 0x0001, 0x0002, 0x0001],
            }
        ) + cbor2.dumps(
            {
                0: 0x02,
                1: 0x0021,
                # taken from test_hpke_test_vectors.json for kem_id = 33
                2: self.TEST_PUBKEY_21,
                3: [0x0001, 0x0001],
            }
        )

    @unittest.mock.patch("aiocoap.hpke.KEM.deserialize_private_key")
    @unittest.mock.patch("aiocoap.hpke.KEM.deserialize_public_key")
    @unittest.mock.patch("aiocoap.hpke.KEM.generate_key_pair", return_value=(b"", b""))
    def test_get_key_config(self, gen_key_pair, des_pub_key, des_priv_key):
        configs = aiocoap.hpke.HPKEKeyConfigDB()
        with self.assertRaises(KeyError):
            configs.get_key_config(0x01, 0x0010, 0x0001, 0x0001)
        config = configs.generate_key_pair(0x0010, [(0x0001, 0x0001)], key_id=0x01)
        configs.get_key_config(0x01, 0x0010, 0x0001, 0x0001) == config

    def _test_load_ocoap_keys_cbor_seq(self):
        fp = io.BufferedReader(io.BytesIO(b""))
        with self.assertRaises(ValueError):
            aiocoap.hpke.HPKEKeyConfigDB.load_ocoap_keys_cbor_seq(fp)
        fp = io.BufferedReader(io.BytesIO(self.cbor_seq_for_testing))
        configs = aiocoap.hpke.HPKEKeyConfigDB.load_ocoap_keys_cbor_seq(fp)
        # 2 for the first element (has two symmetric algorithms)
        # + for the second element in the sequence
        assert len(configs) == 3
        assert (
            configs[0x01, 0x0020, 0x0001, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_20
        )
        assert (
            configs[0x01, 0x0020, 0x0002, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_20
        )
        assert (
            configs[0x02, 0x0021, 0x0001, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_21
        )
        return configs

    def test_load_ocoap_keys_cbor_seq(self):
        self._test_load_ocoap_keys_cbor_seq()

    def test_dump_ocoap_keys_cbor_seq(self):
        configs = self._test_load_ocoap_keys_cbor_seq()
        fp = io.BytesIO()
        configs.dump_ocoap_keys_cbor_seq(fp)
        assert fp.getvalue() == self.cbor_seq_for_testing

    def _test_load_ohttp_keys(self):
        fp = io.BufferedReader(io.BytesIO(b""))
        with self.assertRaises(ValueError):
            aiocoap.hpke.HPKEKeyConfigDB.load_ohttp_keys(fp)
        # only provide a length of 2 and nothing else
        fp = io.BufferedReader(io.BytesIO((2).to_bytes(2, "big")))
        with self.assertRaises(ValueError):
            aiocoap.hpke.HPKEKeyConfigDB.load_ohttp_keys(fp)
        # taken from test_hpke_test_vectors.json for kem_id = 32 (0x20)
        self.TEST_PUBKEY_20 = bytes.fromhex(
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
        )
        # taken from test_hpke_test_vectors.json for kem_id = 33 (0x21)
        # only provide too short public key
        fp = io.BufferedReader(
            io.BytesIO(
                (3 + len(self.TEST_PUBKEY_20[:-4])).to_bytes(2, "big")  # length
                + (0x01).to_bytes(1, "big")  # key_id
                + (0x0020).to_bytes(2, "big")  # kem_id
                + self.TEST_PUBKEY_20[:-4]
            )
        )
        with self.assertRaises(ValueError):
            aiocoap.hpke.HPKEKeyConfigDB.load_ohttp_keys(fp)

        # only provide a 0-length asymmetric algorithms list
        fp = io.BufferedReader(
            io.BytesIO(
                (5 + len(self.TEST_PUBKEY_20)).to_bytes(2, "big")  # length
                + (0x01).to_bytes(1, "big")  # key_id
                + (0x0020).to_bytes(2, "big")  # kem_id
                + self.TEST_PUBKEY_20
                + (0).to_bytes(2, "big")  # asymmetric algorithms length
            )
        )
        with self.assertRaises(ValueError):
            aiocoap.hpke.HPKEKeyConfigDB.load_ohttp_keys(fp)

        # only provide asymmetric algorithms list length that is not divisible by 4
        fp = io.BufferedReader(
            io.BytesIO(
                (9 + len(self.TEST_PUBKEY_20)).to_bytes(2, "big")  # length
                + (0x01).to_bytes(1, "big")  # key_id
                + (0x0020).to_bytes(2, "big")  # kem_id
                + self.TEST_PUBKEY_20
                + (3).to_bytes(2, "big")  # asymmetric algorithms length
                + (0x0001).to_bytes(2, "big")  # kdf_id
                + (0x0001).to_bytes(2, "big")  # aead_id
            )
        )
        with self.assertRaises(ValueError):
            aiocoap.hpke.HPKEKeyConfigDB.load_ohttp_keys(fp)

        fp = io.BufferedReader(io.BytesIO(self.TEST_OHTTP_KEYS))
        configs = aiocoap.hpke.HPKEKeyConfigDB.load_ohttp_keys(fp)
        # 2 for the first element (has two symmetric algorithms)
        # + for the second element in the sequence
        assert len(configs) == 3
        assert (
            configs[0x01, 0x0020, 0x0001, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_20
        )
        assert (
            configs[0x01, 0x0020, 0x0002, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_20
        )
        assert (
            configs[0x02, 0x0021, 0x0001, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_21
        )
        return configs

    def test_load_ohttp_keys(self):
        self._test_load_ohttp_keys()

    def test_dump_ohttp_keys(self):
        configs = self._test_load_ohttp_keys()
        fp = io.BytesIO()
        configs.dump_ohttp_keys(fp)
        assert fp.getvalue() == self.TEST_OHTTP_KEYS

    def test_load_with_cbor(self):
        fp = io.BufferedReader(io.BytesIO(self.cbor_seq_for_testing))
        configs = aiocoap.hpke.HPKEKeyConfigDB.load_key_config(fp)
        # 2 for the first element (has two symmetric algorithms)
        # + for the second element in the sequence
        assert len(configs) == 3
        assert (
            configs[0x01, 0x0020, 0x0001, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_20
        )
        assert (
            configs[0x01, 0x0020, 0x0002, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_20
        )
        assert (
            configs[0x02, 0x0021, 0x0001, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_21
        )

    def _test_load_with_ohttp_keys(self):
        fp = io.BufferedReader(io.BytesIO(self.TEST_OHTTP_KEYS))
        configs = aiocoap.hpke.HPKEKeyConfigDB.load_key_config(fp)
        # 2 for the first element (has two symmetric algorithms)
        # + for the second element in the sequence
        assert len(configs) == 3
        assert (
            configs[0x01, 0x0020, 0x0001, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_20
        )
        assert (
            configs[0x01, 0x0020, 0x0002, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_20
        )
        assert (
            configs[0x02, 0x0021, 0x0001, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_21
        )
        return configs

    def test_load_with_ohttp_keys(self):
        self._test_load_with_ohttp_keys()

    def test_iter_supported(self):
        configs = self._test_load_with_ohttp_keys()
        exp_pub_keys = [
            self.TEST_PUBKEY_20,
            self.TEST_PUBKEY_20,
            self.TEST_PUBKEY_21,
        ]

        for i, (key_id, kem_id, kdf_id, aead_id) in enumerate(configs.iter_supported()):
            # all key configurations should be supported, unsupported
            # key configurations are not loaded in the first place.
            assert (
                configs[key_id, kem_id, kdf_id, aead_id].public_key.serialize()
                == exp_pub_keys[i]
            )

    @unittest.mock.patch("aiocoap.hpke.KEM.deserialize_private_key")
    @unittest.mock.patch("aiocoap.hpke.KEM.deserialize_public_key")
    @unittest.mock.patch("aiocoap.hpke.KEM.generate_key_pair", return_value=(b"", b""))
    def test_generate_key_pair(self, _, des_pub_key, des_priv_key):
        des_pub_key.return_value = b"public1"
        des_priv_key.return_value = b"private1"
        configs = aiocoap.hpke.HPKEKeyConfigDB()
        config1 = configs.generate_key_pair(0x0010, [(0x0001, 0x0001)])
        assert config1.key_id == 0x01
        assert config1.kem_id == 0x0010
        assert config1.symmetric_algorithm_ids == [(0x0001, 0x0001)]
        assert config1.public_key == b"public1"
        assert len(config1.suites) == 1
        assert len(configs) == 1
        assert config1.suites[0x0010, 0x0001, 0x0001].kem_id == 0x0010
        assert config1.suites[0x0010, 0x0001, 0x0001].kdf_id == 0x0001
        assert config1.suites[0x0010, 0x0001, 0x0001].aead_id == 0x0001
        assert configs[0x01, 0x0010, 0x0001, 0x0001] == config1
        assert configs.get_private_key(0x01, 0x0010) == b"private1"
        assert (
            configs.get_suite(0x01, 0x0010, 0x0001, 0x0001)
            == config1.suites[0x0010, 0x0001, 0x0001]
        )

        des_pub_key.return_value = b"public2"
        des_priv_key.return_value = b"private2"
        config2 = configs.generate_key_pair(0x0011, [(0x0001, 0x0001)], key_id=0x37)
        assert config2.key_id == 0x37
        assert config2.kem_id == 0x0011
        assert config2.symmetric_algorithm_ids == [(0x0001, 0x0001)]
        assert config2.public_key == b"public2"
        assert len(config2.suites) == 1
        assert config2.suites[0x0011, 0x0001, 0x0001].kem_id == 0x0011
        assert config2.suites[0x0011, 0x0001, 0x0001].kdf_id == 0x0001
        assert config2.suites[0x0011, 0x0001, 0x0001].aead_id == 0x0001
        assert len(configs) == 2
        assert configs[0x01, 0x0010, 0x0001, 0x0001] == config1
        assert configs[0x37, 0x0011, 0x0001, 0x0001] == config2
        assert configs.get_private_key(0x01, 0x0010) == b"private1"
        assert configs.get_private_key(0x37, 0x0011) == b"private2"
        assert (
            configs.get_suite(0x01, 0x0010, 0x0001, 0x0001)
            == config1.suites[0x0010, 0x0001, 0x0001]
        )
        assert (
            configs.get_suite(0x37, 0x0011, 0x0001, 0x0001)
            == config2.suites[0x0011, 0x0001, 0x0001]
        )

        des_pub_key.return_value = b"public3"
        des_priv_key.return_value = b"private3"
        config3 = configs.generate_key_pair(0x0011, [(0x0001, 0x0002)])
        assert config3.key_id == 0x38
        assert config3.kem_id == 0x0011
        assert config3.symmetric_algorithm_ids == [(0x0001, 0x0002)]
        assert config3.public_key == b"public3"
        assert len(config3.suites) == 1
        assert config3.suites[0x0011, 0x0001, 0x0002].kem_id == 0x0011
        assert config3.suites[0x0011, 0x0001, 0x0002].kdf_id == 0x0001
        assert config3.suites[0x0011, 0x0001, 0x0002].aead_id == 0x0002
        assert len(configs) == 3
        assert configs[0x01, 0x0010, 0x0001, 0x0001] == config1
        assert configs[0x37, 0x0011, 0x0001, 0x0001] == config2
        assert configs[0x38, 0x0011, 0x0001, 0x0002] == config3
        assert configs.get_private_key(0x01, 0x0010) == b"private1"
        assert configs.get_private_key(0x37, 0x0011) == b"private2"
        assert configs.get_private_key(0x38, 0x0011) == b"private3"
        assert (
            configs.get_suite(0x01, 0x0010, 0x0001, 0x0001)
            == config1.suites[0x0010, 0x0001, 0x0001]
        )
        assert (
            configs.get_suite(0x37, 0x0011, 0x0001, 0x0001)
            == config2.suites[0x0011, 0x0001, 0x0001]
        )
        assert (
            configs.get_suite(0x38, 0x0011, 0x0001, 0x0002)
            == config3.suites[0x0011, 0x0001, 0x0002]
        )

    @unittest.mock.patch("pathlib.Path.open")
    def _test_load(self, path_open):
        def open_mock(*args, **kwargs):
            if path_open.call_count == 1:
                return io.StringIO(
                    self.TEST_CONFIG_FILE_TEMPLATE.format(key_config_file="foobar.test")
                )
            return io.BufferedReader(io.BytesIO(self.cbor_seq_for_testing))

        path_open.side_effect = open_mock
        configs = aiocoap.hpke.HPKEKeyConfigDB.load("test_config_file")
        # 2 for the first element (has two symmetric algorithms)
        # + for the second element in the sequence
        assert len(configs) == 3
        assert (
            configs[0x01, 0x0020, 0x0001, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_20
        )
        assert (
            configs[0x01, 0x0020, 0x0002, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_20
        )
        assert (
            configs[0x02, 0x0021, 0x0001, 0x0001].public_key.serialize()
            == self.TEST_PUBKEY_21
        )
        return configs

    def test_load(self):
        self._test_load()

    @unittest.mock.patch("aiocoap.hpke.HPKEKeyConfigDB.dump_ohttp_keys")
    @unittest.mock.patch("aiocoap.hpke.HPKEKeyConfigDB.dump_ocoap_keys_cbor_seq")
    @unittest.mock.patch("pathlib.Path.open")
    def test_store_cbor(self, open_mock, dump_ocoap, dump_ohttp):
        configs = self._test_load()

        configs.store(
            "test_config_file",
            "foobar.test",
            aiocoap.hpke.HPKEKeyConfigFormat.OCOAP_CBOR_SEQ,
        )
        dump_ocoap.assert_called_once()
        dump_ohttp.assert_not_called()

    @unittest.mock.patch("aiocoap.hpke.HPKEKeyConfigDB.dump_ohttp_keys")
    @unittest.mock.patch("aiocoap.hpke.HPKEKeyConfigDB.dump_ocoap_keys_cbor_seq")
    @unittest.mock.patch("pathlib.Path.open")
    def test_store_ohttp(self, open_mock, dump_ocoap, dump_ohttp):
        configs = self._test_load()

        configs.store(
            "test_config_file",
            "foobar.test",
            aiocoap.hpke.HPKEKeyConfigFormat.OHTTP_KEYS,
        )
        dump_ocoap.assert_not_called()
        dump_ohttp.assert_called_once()

    def test_store_unknown_format(self):
        configs = self._test_load()

        with self.assertRaises(ValueError):
            configs.store(
                "test_config_file",
                "foobar.test",
                aiocoap.hpke.HPKEKeyConfigFormat.OHTTP_KEYS + 0xFFFF,
            )

    def test_add_key_config_duplicate(self):
        configs = self._test_load()

        config = None
        for key in configs.iter_supported():
            config = configs[key]
            break
        assert config is not None
        config = copy.deepcopy(config)
        with self.assertRaises(ValueError):
            configs.add_key_config(config)

    def test_add_private_key(self):
        configs = self._test_load()

        mock_private_key = aiocoap.hpke.KEM.PrivateKey(unittest.mock.MagicMock())
        with self.assertRaises(KeyError):
            assert configs.get_private_key(0xFE, 0x0021)
        configs.add_private_key(0xFE, 0x0021, mock_private_key)
        assert configs.get_private_key(0xFE, 0x0021) == mock_private_key

    def test_dump_ohttp_keys_error_writing_length(self):
        configs = self._test_load()

        fp = unittest.mock.MagicMock()

        # mock partial length write
        fp.write.return_value = 1
        with self.assertRaises(IOError):
            configs.dump_ohttp_keys(fp)
