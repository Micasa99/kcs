"""Deterministic PID-1-style Unix-socket supervisor fixture for conformance only."""

from __future__ import annotations

import hashlib
import json
import re
import socket
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_START_FIELDS = frozenset(
    {
        "protocolVersion",
        "generation",
        "agentRunRef",
        "executionEnvelopeRef",
        "executionEnvelopeDigest",
        "launchBundlePath",
        "launchBundleDigest",
        "launchBundleSizeBytes",
        "materialPaths",
        "credentialGrantRef",
        "audience",
        "credentialSha256",
    }
)


class _GenerationSlots:
    """One immutable conformance slot per supervisor generation."""

    def __init__(self, credential_path: Path) -> None:
        self._credential_path = credential_path
        self._completed: dict[int, tuple[str, bytes]] = {}

    def dispatch(self, request: Mapping[str, Any]) -> bytes:
        _validate_start(request)
        generation = request["generation"]
        assert isinstance(generation, int) and not isinstance(generation, bool)
        frame_identity = json.dumps(request, sort_keys=True, separators=(",", ":"))
        retained = self._completed.get(generation)
        if retained is not None:
            retained_identity, response = retained
            if retained_identity != frame_identity:
                raise ValueError("generation is already bound to different start metadata")
            return response

        credential = self._credential_path.read_bytes()
        if hashlib.sha256(credential).hexdigest() != request["credentialSha256"]:
            raise ValueError("projected credential digest does not match the frame")
        child = subprocess.Popen(["/bin/true"])
        child.wait()
        response = _frame(
            {
                "protocolVersion": 1,
                "generation": generation,
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
        self._completed[generation] = (frame_identity, response)
        return response


def serve(socket_path: Path, credential_path: Path) -> None:
    """Keep serving local frames; each start consumes a projection and launches one child."""
    socket_path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        slots = _GenerationSlots(credential_path)
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
                if request.get("action") == "inspect":
                    connection.sendall(
                        _frame(
                            {
                                "protocolVersion": 1,
                                "generation": 0,
                                "agentRunRef": "",
                                "launchBundleDigest": "",
                                "state": "idle",
                                "supervisorAlive": True,
                            }
                        )
                    )
                    continue
                _validate_start(request)
                connection.sendall(slots.dispatch(request))


def _frame(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _json(payload: bytes) -> dict[str, Any]:
    value: Any = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("RPC request must be a JSON object")
    return value


def _validate_start(request: Mapping[str, Any]) -> None:
    if set(request) != _START_FIELDS:
        raise ValueError("start frame fields do not match the protocol")
    protocol = request.get("protocolVersion")
    generation = request.get("generation")
    size = request.get("launchBundleSizeBytes")
    if type(protocol) is not int or protocol != 1 or type(generation) is not int or generation < 1:
        raise ValueError("invalid supervisor protocol or generation")
    if type(size) is not int or not 0 <= size <= 1048576:
        raise ValueError("invalid launch bundle size")
    refs = ("credentialGrantRef", "agentRunRef", "executionEnvelopeRef", "audience")
    if any(not _valid_ref(request.get(field)) for field in refs):
        raise ValueError("start frame is missing bound credential identity")
    if not _valid_ref(request.get("launchBundlePath")):
        raise ValueError("start frame has an invalid launch path")
    digests = ("executionEnvelopeDigest", "launchBundleDigest", "credentialSha256")
    if any(
        not isinstance(request.get(field), str) or not _DIGEST.fullmatch(request[field])
        for field in digests
    ):
        raise ValueError("start frame has an invalid digest")
    material_paths = request.get("materialPaths")
    if not isinstance(material_paths, list) or any(not _valid_ref(path) for path in material_paths):
        raise ValueError("start frame has invalid material paths")


def _valid_ref(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 256
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )
