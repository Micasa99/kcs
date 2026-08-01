"""Deterministic PID-1-style Unix-socket supervisor fixture for conformance only."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def serve(socket_path: Path, credential_path: Path) -> None:
    """Keep serving local frames; each start consumes a projection and launches one child."""
    socket_path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        completed: dict[str, bytes] = {}
        while True:
            connection, _ = listener.accept()
            with connection:
                request = _json(connection.recv(65536))
                if request.get("action") == "shutdown":
                    connection.sendall(
                        _frame(
                            {
                                "protocolVersion": 1,
                                "generation": 0,
                                "agentRunRef": "",
                                "launchBundleDigest": "",
                                "state": "stopped",
                                "supervisorAlive": False,
                            }
                        )
                    )
                    return
                _validate_start(request)
                identity = _start_identity(request)
                if identity in completed:
                    connection.sendall(completed[identity])
                    continue
                credential = credential_path.read_bytes()
                if hashlib.sha256(credential).hexdigest() != request["credentialSha256"]:
                    raise ValueError("projected credential digest does not match the frame")
                child = subprocess.Popen(["/bin/true"])
                child.wait()
                response = _frame(
                    {
                        "protocolVersion": 1,
                        "generation": request["generation"],
                        "agentRunRef": request["agentRunRef"],
                        "launchBundleDigest": request["launchBundleDigest"],
                        "credentialGrantRef": request["credentialGrantRef"],
                        "audience": request["audience"],
                        "credentialSha256": request["credentialSha256"],
                        "credentialConsumed": True,
                        "state": "exited",
                        "supervisorAlive": True,
                        "pid": child.pid,
                        "exitCode": child.returncode,
                    }
                )
                completed[identity] = response
                connection.sendall(response)


def _frame(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _json(payload: bytes) -> dict[str, Any]:
    value: Any = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("RPC request must be a JSON object")
    return value


def _validate_start(request: Mapping[str, Any]) -> None:
    required = (
        "credentialGrantRef",
        "agentRunRef",
        "launchBundleDigest",
        "audience",
        "credentialSha256",
    )
    if (
        request.get("protocolVersion") != 1
        or not isinstance(request.get("generation"), int)
        or request["generation"] < 1
    ):
        raise ValueError("invalid supervisor protocol or generation")
    if any(not isinstance(request.get(field), str) or not request[field] for field in required):
        raise ValueError("start frame is missing bound credential identity")


def _start_identity(request: Mapping[str, Any]) -> str:
    return json.dumps(request, sort_keys=True, separators=(",", ":"))
