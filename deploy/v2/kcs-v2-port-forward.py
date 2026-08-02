#!/usr/bin/env python3
"""Validate one private bind and exec the fixed KCS V2 port-forward."""

from __future__ import annotations

import ipaddress
import os
import sys

_SUPPORTED = tuple(
    ipaddress.ip_network(raw)
    for raw in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def _allowed_bind(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    value = ipaddress.ip_address(raw)
    if any(
        (
            value.is_global,
            value.is_loopback,
            value.is_unspecified,
            value.is_link_local,
            value.is_multicast,
            value.is_reserved,
        )
    ) or not any(value.version == network.version and value in network for network in _SUPPORTED):
        raise ValueError("bind must be a private or non-global overlay address")
    return value


def main() -> None:
    if len(sys.argv) != 3:
        print("port-forward wrapper requires bind and control addresses", file=sys.stderr)
        raise SystemExit(2)
    try:
        bind = _allowed_bind(sys.argv[1])
        control = _allowed_bind(sys.argv[2])
    except ValueError:
        print("bind must be a private or non-global overlay address", file=sys.stderr)
        raise SystemExit(2) from None
    if bind != control:
        print("bind must equal the declared control address", file=sys.stderr)
        raise SystemExit(2)
    binary = "/usr/local/bin/k3s"
    os.execv(
        binary,
        [
            binary,
            "kubectl",
            "--namespace",
            "researchcosmos-v2",
            "port-forward",
            f"--address={bind}",
            "service/kcs-v2-api",
            "8443:443",
        ],
    )


if __name__ == "__main__":
    main()
