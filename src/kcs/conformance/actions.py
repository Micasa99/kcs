"""Fixed, sanitized P6 conformance observations shared by both fixture roles."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import os
import socket
import ssl
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_SHARED_BYTES = {
    "agent": b"kcs-v2-agent-shared-probe\n",
    "workspace": b"kcs-v2-workspace-shared-probe\n",
}


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS connection whose transport address cannot be DNS-rebound."""

    def __init__(self, hostname: str, address: str, port: int) -> None:
        self._tls_context = ssl.create_default_context()
        super().__init__(hostname, port=port, timeout=10, context=self._tls_context)
        self._pinned_address = address

    def connect(self) -> None:
        transport = socket.create_connection((self._pinned_address, self.port), self.timeout)
        self.sock = self._tls_context.wrap_socket(transport, server_hostname=self.host)


def _unsafe_runtime_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(
        (
            address.is_loopback,
            address.is_unspecified,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
        )
    )


def _runtime_host_header(hostname: str, port: int, scheme: str) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    return host if port == default_port else f"{host}:{port}"


def _head_runtime_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    hostname: str,
    port: int,
    scheme: str,
    path: str,
) -> int:
    connection: http.client.HTTPConnection
    if scheme == "https":
        connection = _PinnedHTTPSConnection(hostname, str(address), port)
    else:
        connection = http.client.HTTPConnection(str(address), port=port, timeout=10)
    try:
        connection.putrequest("HEAD", path, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", _runtime_host_header(hostname, port, scheme))
        connection.putheader("Connection", "close")
        connection.endheaders()
        return connection.getresponse().status
    finally:
        connection.close()


def shared_write(workspace: Path, role: str) -> dict[str, object]:
    """Write one role-owned fixed probe, never caller-selected content or paths."""
    if role not in _SHARED_BYTES:
        return _error("INVALID_REQUEST", "shared_write")
    directory = workspace / ".kcs-conformance"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = directory / f"{role}.probe"
    temporary = directory / f".{role}.probe.tmp"
    payload = _SHARED_BYTES[role]
    temporary.write_bytes(payload)
    os.chmod(temporary, 0o600)
    temporary.replace(target)
    return {
        "event": f"{role}_shared_write",
        "ok": True,
        "protocolVersion": 1,
        "sizeBytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def shared_read(workspace: Path, observer_role: str, source_role: object) -> dict[str, object]:
    """Read only the other fixed role probe and report its digest."""
    if source_role not in _SHARED_BYTES or source_role == observer_role:
        return _error("INVALID_REQUEST", f"{observer_role}_shared_read")
    target = workspace / ".kcs-conformance" / f"{source_role}.probe"
    try:
        payload = target.read_bytes()
    except OSError:
        return _error("SHARED_PROBE_UNAVAILABLE", f"{observer_role}_shared_read")
    return {
        "event": f"{observer_role}_shared_read",
        "ok": True,
        "protocolVersion": 1,
        "sizeBytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "sourceRole": source_role,
    }


def observe_agent_no_gpu() -> dict[str, object]:
    """Report actual device visibility without printing device identifiers."""
    device_count = len(list(Path("/dev").glob("nvidia[0-9]*")))
    visible = os.environ.get("NVIDIA_VISIBLE_DEVICES", "")
    explicitly_visible = visible.casefold() not in {"", "none", "void"}
    ok = device_count == 0 and not explicitly_visible
    result: dict[str, object] = {
        "event": "agent_gpu_observation",
        "gpuDeviceCount": device_count,
        "ok": ok,
        "protocolVersion": 1,
    }
    if not ok:
        result["code"] = "GPU_DEVICE_VISIBLE"
    return result


def observe_workspace_gpu() -> dict[str, object]:
    """Run the one fixed nvidia-smi query and report only count and output digest."""
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=uuid,name", "--format=csv,noheader"],
            capture_output=True,
            check=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return _error("GPU_UNAVAILABLE", "workspace_gpu_observation")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return _error("GPU_UNAVAILABLE", "workspace_gpu_observation")
    return {
        "event": "workspace_gpu_observation",
        "gpuCount": len(lines),
        "nvidiaSmiSha256": hashlib.sha256(result.stdout).hexdigest(),
        "ok": True,
        "protocolVersion": 1,
    }


def probe_runtime_url(raw_url: str | None) -> dict[str, object]:
    """Reach one already-resolved runtime address without DNS re-resolution."""
    if not raw_url:
        return _error("RUNTIME_URL_REQUIRED", "runtime_url_observation")
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        return _error("INVALID_RUNTIME_URL", "runtime_url_observation")
    if parsed.password or parsed.query or parsed.fragment:
        return _error("INVALID_RUNTIME_URL", "runtime_url_observation")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(
                parsed.hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        }
    except (OSError, ValueError):
        return _error("RUNTIME_UNREACHABLE", "runtime_url_observation")
    if any(_unsafe_runtime_address(address) for address in addresses):
        return _error("LOOPBACK_RUNTIME_URL", "runtime_url_observation")
    status = None
    for address in sorted(addresses, key=lambda item: (item.version, int(item))):
        try:
            status = _head_runtime_address(
                address,
                parsed.hostname,
                port,
                parsed.scheme,
                parsed.path or "/",
            )
        except (OSError, ssl.SSLError, http.client.HTTPException):
            continue
        break
    if status is None:
        return _error("RUNTIME_UNREACHABLE", "runtime_url_observation")
    return {
        "event": "runtime_url_observation",
        "ok": True,
        "protocolVersion": 1,
        "scheme": parsed.scheme,
        "statusCode": status,
    }


def run_agent_action(
    workspace: Path, launch: Mapping[str, Any], runtime_url: str | None
) -> dict[str, object]:
    """Execute one already-bounded agent launch through a closed action table."""
    action = validate_agent_action(launch)
    if action == "sharedWrite":
        return shared_write(workspace, "agent")
    if action == "sharedRead":
        return shared_read(workspace, "agent", launch.get("sourceRole"))
    if action == "observeNoGpu":
        return observe_agent_no_gpu()
    return probe_runtime_url(runtime_url)


def validate_agent_action(launch: Mapping[str, Any]) -> str:
    """Validate the closed launch shape without performing its side effect."""
    protocol = launch.get("protocol")
    action = launch.get("action")
    if protocol != "kcs.conformance/1" or not isinstance(action, str):
        raise ValueError("launch bundle is not a fixed KCS conformance action")
    if action == "sharedWrite" and set(launch) == {"protocol", "action"}:
        return action
    if action == "sharedRead" and set(launch) == {"protocol", "action", "sourceRole"}:
        if launch.get("sourceRole") != "workspace":
            raise ValueError("agent sharedRead requires the workspace probe")
        return action
    if action == "observeNoGpu" and set(launch) == {"protocol", "action"}:
        return action
    if action == "probeRuntimeUrl" and set(launch) == {"protocol", "action"}:
        return action
    raise ValueError("launch bundle action is not allowlisted")


def _error(code: str, event: str) -> dict[str, Any]:
    return {"code": code, "event": event, "ok": False, "protocolVersion": 1}
