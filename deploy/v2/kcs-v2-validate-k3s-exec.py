#!/usr/bin/env python3
"""Validate the effective k3s systemd argv without exposing it."""

from __future__ import annotations

import shlex
import sys
from collections import defaultdict

_CRITICAL_SINGLETONS = {
    "advertise-address",
    "bind-address",
    "default-runtime",
    "flannel-iface",
    "node-ip",
    "node-name",
    "server",
    "tls-san",
}


def _extract_argv(raw: str) -> list[str]:
    marker = "argv[]="
    if raw.count(marker) != 1:
        raise ValueError
    encoded, separator, _ = raw.partition(marker)[2].partition(" ; ")
    if not separator:
        raise ValueError
    argv = shlex.split(encoded)
    if len(argv) < 2 or argv[0] != "/usr/local/bin/k3s":
        raise ValueError
    return argv


def _options(argv: list[str]) -> dict[str, list[str]]:
    result: defaultdict[str, list[str]] = defaultdict(list)
    index = 2
    while index < len(argv):
        token = argv[index]
        if not token.startswith("--"):
            raise ValueError
        option = token[2:]
        if "=" in option:
            name, value = option.split("=", 1)
        else:
            index += 1
            if index >= len(argv) or argv[index].startswith("--"):
                raise ValueError
            name, value = option, argv[index]
        if not name or not value:
            raise ValueError
        result[name].append(value)
        index += 1
    return dict(result)


def _exact_singletons(options: dict[str, list[str]], expected: dict[str, str]) -> None:
    for name in _CRITICAL_SINGLETONS:
        values = options.get(name, [])
        if name in expected:
            if values != [expected[name]]:
                raise ValueError
        elif values:
            raise ValueError


def _exact_keyed(options: dict[str, list[str]], option: str, key: str, value: str) -> None:
    relevant = [item for item in options.get(option, []) if item.partition("=")[0] == key]
    if relevant != [f"{key}={value}"]:
        raise ValueError


def _validate(raw: str, arguments: list[str]) -> None:
    role = arguments[0]
    argv = _extract_argv(raw)
    if argv[1] != ("server" if role == "control" else "agent"):
        raise ValueError
    options = _options(argv)
    if role == "control" and len(arguments) == 4:
        address, tls_san, interface = arguments[1:]
        _exact_singletons(
            options,
            {
                "advertise-address": address,
                "bind-address": address,
                "flannel-iface": interface,
                "node-ip": address,
                "tls-san": tls_san,
            },
        )
        _exact_keyed(options, "node-label", "researchcosmos.io/role", "control")
        _exact_keyed(options, "kubelet-arg", "address", address)
        return
    if role == "worker" and len(arguments) == 5:
        control_address, worker_address, node_name, interface = arguments[1:]
        _exact_singletons(
            options,
            {
                "default-runtime": "nvidia",
                "flannel-iface": interface,
                "node-ip": worker_address,
                "node-name": node_name,
                "server": f"https://{control_address}:6443",
            },
        )
        _exact_keyed(options, "kubelet-arg", "address", "127.0.0.1")
        return
    raise ValueError


def main() -> None:
    try:
        raw = sys.stdin.read(65537)
        if len(raw) > 65536:
            raise ValueError
        _validate(raw, sys.argv[1:])
    except (ValueError, IndexError):
        print("effective k3s service configuration mismatch", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
