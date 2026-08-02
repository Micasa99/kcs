"""Deterministic PID-1-style Unix-socket supervisor fixture for conformance only."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from kcs.jobs.policy import validate_safe_relative_path

from .actions import (
    observe_agent_no_gpu,
    probe_runtime_url,
    shared_read,
    shared_write,
    validate_agent_action,
)

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CREDENTIAL_WAIT_SECONDS = 5.0
_CREDENTIAL_POLL_SECONDS = 0.05
_CREDENTIAL_PROJECTION_TIMEOUT = "CREDENTIAL_PROJECTION_TIMEOUT"
_SUPERVISOR_REQUEST_REJECTED = "SUPERVISOR_REQUEST_REJECTED"
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


class _CredentialProjectionTimeoutError(RuntimeError):
    """The optional Secret volume has not exposed the requested grant yet."""


class _GenerationSlots:
    """One immutable conformance slot per supervisor generation."""

    def __init__(self, credential_path: Path, workspace: Path = Path("/workspace")) -> None:
        self._credential_path = credential_path
        self._workspace = workspace.resolve()
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

        self._wait_for_credential(str(request["credentialSha256"]))
        launch_path = self._workspace / validate_safe_relative_path(request["launchBundlePath"])
        try:
            resolved_launch = launch_path.resolve(strict=True)
            resolved_launch.relative_to(self._workspace)
            if not resolved_launch.is_file():
                raise ValueError("launch bundle is not a regular file")
            launch_bytes = resolved_launch.read_bytes()
        except OSError as error:
            raise ValueError("launch bundle is unavailable") from error
        if len(launch_bytes) != request["launchBundleSizeBytes"]:
            raise ValueError("launch bundle size does not match the frame")
        if hashlib.sha256(launch_bytes).hexdigest() != request["launchBundleDigest"]:
            raise ValueError("launch bundle digest does not match the frame")
        launch = _json(launch_bytes)
        # Validate the closed action in the long-lived supervisor before starting a
        # child. The child receives data only through the fixed internal module.
        validate_agent_action(launch)
        child_environment = dict(os.environ)
        child_environment["KCS_WORKSPACE"] = str(self._workspace)
        child = subprocess.Popen(
            [sys.executable, "-m", "kcs.conformance.action_runner"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=child_environment,
        )
        try:
            output, _ = child.communicate(
                json.dumps(launch, sort_keys=True, separators=(",", ":")).encode(), timeout=30
            )
        except subprocess.TimeoutExpired as error:
            child.kill()
            child.wait()
            raise ValueError("conformance runner child timed out") from error
        if len(output) > 65536:
            raise ValueError("conformance runner child output exceeded its bound")
        action_result = _json(output)
        print(json.dumps(action_result, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        exit_code = child.returncode
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
                "exitCode": exit_code,
                "error": None
                if exit_code == 0
                else str(action_result.get("code", "ACTION_FAILED")),
            }
        )
        self._completed[generation] = (frame_identity, response)
        return response

    def _wait_for_credential(self, expected_digest: str) -> None:
        # Kubernetes accepts the Secret before its optional projected volume is
        # refreshed. Keep this shorter than the pod-exec deadline so a timed-out
        # client can never leave this supervisor dispatching a child in the background.
        deadline = time.monotonic() + _CREDENTIAL_WAIT_SECONDS
        while True:
            try:
                credential: bytes | None = self._credential_path.read_bytes()
            except OSError:
                credential = None
            if credential is not None and hmac.compare_digest(
                hashlib.sha256(credential).hexdigest(), expected_digest
            ):
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _CredentialProjectionTimeoutError
            time.sleep(min(_CREDENTIAL_POLL_SECONDS, remaining))


def serve(socket_path: Path, credential_path: Path, workspace: Path = Path("/workspace")) -> None:
    """Keep serving local frames; each start consumes a projection and launches one child."""
    socket_path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(1)
        slots = _GenerationSlots(credential_path, workspace)
        while True:
            connection, _ = listener.accept()
            with connection:
                try:
                    if _serve_connection(connection, slots, workspace):
                        return
                except _CredentialProjectionTimeoutError:
                    _send_rpc_error(connection, _CREDENTIAL_PROJECTION_TIMEOUT)
                except (OSError, ValueError):
                    # One malformed or failed RPC is a connection failure, not a PID-1
                    # failure. The fixed error code intentionally exposes no exception text.
                    _send_rpc_error(connection, _SUPERVISOR_REQUEST_REJECTED)


def _serve_connection(connection: socket.socket, slots: _GenerationSlots, workspace: Path) -> bool:
    request = _json(connection.recv(65536))
    action = request.get("action")
    if action == "sharedWrite" and _direct_action(request, {"protocolVersion", "action"}):
        _send_event(connection, shared_write(workspace, "agent"))
        return False
    if action == "sharedRead" and _direct_action(
        request, {"protocolVersion", "action", "sourceRole"}
    ):
        _send_event(connection, shared_read(workspace, "agent", request.get("sourceRole")))
        return False
    if action == "observeNoGpu" and _direct_action(request, {"protocolVersion", "action"}):
        _send_event(connection, observe_agent_no_gpu())
        return False
    if action == "probeRuntimeUrl" and _direct_action(request, {"protocolVersion", "action"}):
        _send_event(connection, probe_runtime_url(os.environ.get("RC_PUBLIC_RUNTIME_BASE_URL")))
        return False
    if action == "shutdown":
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
        return True
    if action == "inspect":
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
        return False
    _validate_start(request)
    connection.sendall(slots.dispatch(request))
    return False


def _send_rpc_error(connection: socket.socket, code: str) -> None:
    response = {
        "protocolVersion": 1,
        "generation": 0,
        "agentRunRef": "",
        "launchBundleDigest": "",
        "state": "retryable",
        "supervisorAlive": True,
        "credentialConsumed": False,
        "error": code,
    }
    try:
        connection.sendall(_frame(response))
    except OSError:
        return
    print(
        json.dumps(
            {"event": "agent_rpc_retryable_error", "code": code},
            sort_keys=True,
            separators=(",", ":"),
        ),
        file=sys.stderr,
        flush=True,
    )


def _send_event(connection: socket.socket, response: Mapping[str, object]) -> None:
    encoded = _frame(response)
    connection.sendall(encoded)
    print(encoded.decode(), file=sys.stderr, flush=True)


def _direct_action(request: Mapping[str, Any], fields: set[str]) -> bool:
    if request.get("protocolVersion") != 1 or set(request) != fields:
        raise ValueError("conformance RPC action fields do not match the fixed protocol")
    return True


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


def rpc(socket_path: Path) -> None:
    """Run the one fixed stdin/stdout RPC client used by Kubernetes exec."""
    payload = sys.stdin.buffer.read(65537)
    if len(payload) > 65536:
        raise ValueError("agent RPC request exceeded its bound")
    _json(payload)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(str(socket_path))
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        response = connection.recv(65537)
    if len(response) > 65536:
        raise ValueError("agent RPC response exceeded its bound")
    _json(response)
    sys.stdout.buffer.write(response + b"\n")
    sys.stdout.buffer.flush()


def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?", choices=("serve", "rpc"), default="serve")
    arguments = parser.parse_args()
    socket_path = Path(os.environ.get("KCS_AGENT_SOCKET", "/run/kcs/agent.sock"))
    if arguments.command == "rpc":
        rpc(socket_path)
        return
    serve(
        socket_path,
        Path(os.environ.get("KCS_CREDENTIAL_PATH", "/var/run/kcs/credential/credential")),
        Path(os.environ.get("KCS_WORKSPACE", "/workspace")),
    )


if __name__ == "__main__":
    _main()
