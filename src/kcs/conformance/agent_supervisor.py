"""Minimal local echo supervisor for conformance, never a production runner."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any


def serve_once(socket_path: Path) -> None:
    """Serve one framed JSON RPC request on a private Unix socket."""
    socket_path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        connection, _ = listener.accept()
        with connection:
            request = _json(connection.recv(65536))
            response = {
                "protocolVersion": 1,
                "generation": request["generation"],
                "agentRunRef": request["agentRunRef"],
                "launchBundleDigest": request["launchBundleDigest"],
                "state": "running",
                "supervisorAlive": True,
                "pid": 1,
            }
            connection.sendall(json.dumps(response, separators=(",", ":")).encode())


def _json(payload: bytes) -> dict[str, Any]:
    value: Any = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("RPC request must be a JSON object")
    for field in ("generation", "agentRunRef", "launchBundleDigest"):
        if field not in value:
            raise ValueError(f"RPC request is missing {field}")
    return value
