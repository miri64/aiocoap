# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This helper script can be used to easily inspect aiocoap's environment
autodetection (ie. whether all modules required for particular subsystems are
available, loosely corresponding to its extras (as described in pyproject.toml
or the installation documentation).

Run it as `python3 -m aiocoap.cli.defaults`."""

import socket
import sys
from aiocoap.meta import version
from aiocoap.defaults import (
    has_reuse_port,
    get_default_clienttransports,
    get_default_servertransports,
    missing_module_functions,
)
import argparse
import os


def describe_ai_addrconfig_v6():
    try:
        addrs = socket.getaddrinfo(
            "::1",
            1234,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
            flags=socket.AI_ADDRCONFIG,
        )
        return f"returned {len(addrs)} result(s)"
    except socket.gaierror:
        return "raises gaierror"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    # Allow passing this in as AIOCOAP_DEFAULTS_EXPECT_ALL=1 via the
    # environment, as that's easier to set in tox
    p.add_argument(
        "--expect-all",
        help="Exit with an error unless all subsystems are available",
        action="store_true",
        default=os.environ.get("AIOCOAP_DEFAULTS_EXPECT_ALL") == "1",
    )
    p.add_argument("--version", action="version", version=version)
    args = p.parse_args(sys.argv[1:] if argv is None else argv)

    error = 0

    print("Python version: %s" % sys.version)
    print("aiocoap version: %s" % version)
    print("Modules missing for subsystems:")
    for name, f in missing_module_functions.items():
        missing = f()
        if missing and args.expect_all:
            error = 1
        print(
            "    %s: %s"
            % (
                name,
                "everything there" if not missing else "missing " + ", ".join(missing),
            )
        )
    print("Python platform: %s" % sys.platform)
    print(
        "Default server transports:  %s"
        % ":".join(get_default_servertransports(use_env=False))
    )
    print("Selected server transports: %s" % ":".join(get_default_servertransports()))
    print(
        "Default client transports:  %s"
        % ":".join(get_default_clienttransports(use_env=False))
    )
    print("Selected client transports: %s" % ":".join(get_default_clienttransports()))
    print(
        "SO_REUSEPORT available (default, selected): %s, %s"
        % (has_reuse_port(use_env=False), has_reuse_port())
    )
    print(
        "Behavior of real getaddrinfo('::1', …, AI_ADDRCONFIG) is:",
        describe_ai_addrconfig_v6(),
    )

    if error:
        print(
            "Exiting unsuccessfully because --expect-all was set and not all extras are available."
        )
    return error


if __name__ == "__main__":
    sys.exit(main())
