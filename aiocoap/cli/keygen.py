# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""A tool for creating key pairs for use in credentials

Note that this tool operates on secrets stored in unencrypted files, protectd
by restrictively set file system permissions. While this is common practice
with many tools in the UNIX world, it might be surprising to users coming from
multi-factor environments."""

import aiocoap.meta
import aiocoap.defaults

import argparse
from pathlib import Path


def build_parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--version", action="version", version="%(prog)s " + aiocoap.meta.version
    )

    subparsers = p.add_subparsers(required=True, dest="subcommand")
    generate = subparsers.add_parser(
        "generate",
        help="This generates an"
        " EDHOC key or HPKE key configuration, stores it in a key file that is only readable by the"
        " user, and prints the corresponding public key information in a way"
        " suitable for inclusion in credentials maps.",
    )
    generate.add_argument(
        "keyfile",
        help="File to store the secret key or generated HPKE key configuration in",
        type=Path,
    )
    # TODO: conflict_handler
    edhoc_args = generate.add_argument_group("EDHOC key")
    edhoc_args.add_argument(
        "--kid", help="Hexadecimal EDHOC key identifier", type=bytes.fromhex
    )
    edhoc_args.add_argument("--subject", help="Text placed in the EDHOC CCS", type=str)
    # TODO: conflict_handler
    hpke_args = generate.add_argument_group("HPKE key configuration")
    hpke_args.add_argument(
        "--key-id",
        help="Hexadecimal HPKE key identifier",
        type=lambda v: int(v, base=16),
    )
    hpke_args.add_argument(
        "--kem-id",
        help="Hexadecimal HPKE KEM identifier",
        type=lambda v: int(v, base=16),
    )
    hpke_args.add_argument(
        "--symmetric-algorithm",
        help="Hexadecimal pairs of HPKE KDF and AEAD identifiers",
        type=lambda v: int(v, base=16),
        nargs=2,
        action="append",
        dest="symmetric_algorithms",
        metavar=("KDF_ID", "AEAD_ID"),
    )
    hpke_args.add_argument(
        "--key-config-file",
        help="File to store the HPKE key-config in (default: keys.{cbor,ohttp})",
    )
    hpke_args.add_argument(
        "--key-config-format",
        help="Format for the HPKE key-config (default: cbor)",
        choices=["cbor", "ohttp"],
        default="cbor",
    )

    return p


def main():
    p = build_parser()

    args = p.parse_args()

    if (args.kid or args.subject) is not None and (
        args.kem_id is not None or args.symmetric_algorithms is not None
    ):
        p.error(
            "EDHOC key generation and HPKE key config generation arguments can not be used together."
        )

    if args.kem_id is None and args.symmetric_algorithms is None:
        missmods = aiocoap.defaults.oscore_missing_modules()
        if missmods:
            p.error(
                f'Dependencies missing, consider installing aiocoap as "aiocoap[oscore]" or "aiocoap[all]". Missing modules: {", ".join(missmods)}'
            )

        from aiocoap import edhoc
        import cbor2
        import cbor_diag

        if args.subcommand == "generate":
            try:
                key = edhoc.CoseKeyForEdhoc.generate(args.keyfile)
            except FileExistsError:
                raise p.error("Output file already exists")

            public = key.as_ccs(args.kid, args.subject)
            print(
                cbor_diag.cbor2diag(cbor2.dumps(public, canonical=True), pretty=False)
            )
        else:
            raise RuntimeError(f"Unimplemented subcommand {args.subcommand=}")
    else:
        missmods = aiocoap.defaults.ocoap_missing_modules()
        if missmods:
            p.error(
                f'Dependencies missing, consider installing aiocoap as "aiocoap[ocoap]" or "aiocoap[all]". Missing modules: {", ".join(missmods)}'
            )

        import cbor_diag

        from aiocoap import hpke

        if args.kem_id is None or args.symmetric_algorithms is None:
            p.error("You need one KEM ID and at least one (KDF ID, AEAD ID)-pair.")
        if args.key_id is not None and not (0 < args.key_id <= 0xFF):
            p.error(f"Key ID must be between 0 and {0xff}.")
        if args.key_config_format == "coap":
            key_config_format = hpke.HPKEKeyConfigFormat.OCOAP_CBOR_SEQ
        else:
            key_config_format = hpke.HPKEKeyConfigFormat.OHTTP_KEYS
        if args.key_config_file is None:
            args.key_config_file = f"keys.{args.key_config_format}"
        if args.keyfile.exists():
            configs = hpke.HPKEKeyConfigDB.load(args.keyfile)
        else:
            configs = hpke.HPKEKeyConfigDB()
        try:
            config = configs.generate_key_pair(
                args.kem_id, args.symmetric_algorithms, key_id=args.key_id
            )
        except ValueError as exc:
            raise p.error(f"{exc}")
        configs.store(args.keyfile, args.key_config_file, key_config_format)
        print(cbor_diag.cbor2diag(config.dumps_ocoap_key_cbor(), pretty=True))


if __name__ == "__main__":
    main()
