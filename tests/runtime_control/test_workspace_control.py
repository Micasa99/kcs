from __future__ import annotations

import hashlib
import json
import socket
import struct
import threading
import uuid
from pathlib import Path

from kcs.conformance.workspace_sidecar import WorkspaceSidecar
from kcs.jobs.canonical import canonical_digest
from kcs.jobs.transport import LocalWorkspaceRpcTransport
from kcs.runtime_control.workspace_sidecar import RuntimeControlSidecar


def _serve_launcher_once(
    socket_path: Path, ready: threading.Event, response_payload: dict[str, object]
) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        ready.set()
        connection, _ = listener.accept()
        with connection:
            size = struct.unpack(">I", _recv_exact(connection, 4))[0]
            request = json.loads(_recv_exact(connection, size))
            response = {
                "schemaVersion": 1,
                "command": request["command"],
                "requestRef": request["requestRef"],
                "requestDigest": request["requestDigest"],
                "jobUid": request["jobUid"],
                "podUid": request["podUid"],
                "generation": request["generation"],
                "state": "completed",
                "replayed": False,
                "observedAt": "2026-08-09T00:00:00Z",
                "errorCode": None,
                "payload": response_payload,
            }
            encoded = json.dumps(response, separators=(",", ":")).encode()
            connection.sendall(struct.pack(">I", len(encoded)) + encoded)


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        value.extend(connection.recv(size - len(value)))
    return bytes(value)


def _finalize_request() -> dict[str, object]:
    payload = {"captureReceiptDigest": "c" * 64}
    return {
        "action": "nativeLauncher",
        "jobUid": "job-uid",
        "podUid": "pod-uid",
        "frame": {
            "command": "finalize",
            "requestRef": "finalize-1",
            "requestDigest": canonical_digest(payload),
            "generation": 1,
            "payload": payload,
        },
    }


def _inspect_request() -> dict[str, object]:
    finalize = _finalize_request()
    frame = finalize["frame"]
    assert isinstance(frame, dict)
    return {
        "action": "inspectNativeFinalize",
        "jobUid": finalize["jobUid"],
        "podUid": finalize["podUid"],
        "finalizeRef": frame["requestRef"],
        "generation": frame["generation"],
        "requestDigest": frame["requestDigest"],
    }


def _without_body_size(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return {key: item for key, item in value.items() if key != "bodySize"}


def test_finalize_receipt_survives_ack_loss_and_control_restart(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    control_state = tmp_path / "control-state"
    launcher_socket = Path("/tmp") / f"kcs-launcher-{uuid.uuid4().hex}.sock"
    monkeypatch.setenv("KCS_NATIVE_LAUNCHER_SOCKET", str(launcher_socket))

    ready = threading.Event()
    launcher = threading.Thread(
        target=_serve_launcher_once,
        args=(launcher_socket, ready, {"finalized": True, "launcherAlive": True}),
        daemon=True,
    )
    launcher.start()
    assert ready.wait(timeout=2)

    control = RuntimeControlSidecar(workspace, control_state)
    transport = LocalWorkspaceRpcTransport(control.dispatch, temp_dir=tmp_path)
    first = _without_body_size(transport.rpc({}, _finalize_request()).header)
    assert first == {
        "ok": True,
        "result": {"finalized": True, "launcherAlive": True},
    }
    launcher.join(timeout=2)
    assert not launcher.is_alive()
    launcher_socket.unlink(missing_ok=True)

    restarted = RuntimeControlSidecar(workspace, control_state)
    replay_transport = LocalWorkspaceRpcTransport(restarted.dispatch, temp_dir=tmp_path)
    inspected = _without_body_size(replay_transport.rpc({}, _inspect_request()).header)
    assert inspected == {
        "ok": True,
        "state": "acknowledged",
        "generation": 1,
        "requestDigest": _inspect_request()["requestDigest"],
        "captureReceiptDigest": "c" * 64,
    }
    assert _without_body_size(replay_transport.rpc({}, _finalize_request()).header) == first

    stopped = _without_body_size(replay_transport.rpc({}, {"action": "shutdown"}).header)
    assert stopped == {"ok": True, "state": "stopped", "supervisorAlive": False}
    assert restarted.shutdown_requested is True


def test_shutdown_requires_durable_finalize_receipt(tmp_path: Path) -> None:
    control = RuntimeControlSidecar(tmp_path / "workspace", tmp_path / "empty-control-state")
    transport = LocalWorkspaceRpcTransport(control.dispatch, temp_dir=tmp_path)
    absent = transport.rpc({}, _inspect_request()).header
    assert absent["state"] == "absent"
    assert absent["generation"] == 1
    assert absent["requestDigest"] == _inspect_request()["requestDigest"]
    assert absent["captureReceiptDigest"] is None

    reply = transport.rpc({}, {"action": "shutdown"})
    assert reply.header["ok"] is False
    assert reply.header["code"] == "PRECONDITION_FAILED"
    assert control.shutdown_requested is False


def test_fixed_probes_exist_only_in_conformance_wrapper(tmp_path: Path) -> None:
    request = {"protocolVersion": 1, "action": "sharedWrite"}
    production = RuntimeControlSidecar(
        tmp_path / "production-workspace", tmp_path / "production-control"
    )
    rejected = LocalWorkspaceRpcTransport(production.dispatch, temp_dir=tmp_path).rpc({}, request)
    assert rejected.header["ok"] is False
    assert rejected.header["code"] == "INVALID_REQUEST"

    conformance = WorkspaceSidecar(tmp_path / "conformance-workspace")
    accepted = LocalWorkspaceRpcTransport(conformance.dispatch, temp_dir=tmp_path).rpc({}, request)
    assert accepted.header["ok"] is True


def test_production_control_owns_transfer_and_pty_transport(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    control = RuntimeControlSidecar(workspace, tmp_path / "control-state")
    transport = LocalWorkspaceRpcTransport(control.dispatch, temp_dir=tmp_path)

    staged_bytes = b"staged input\n"
    staged_body = tmp_path / "staged.bin"
    staged_body.write_bytes(staged_bytes)
    stage = {
        "action": "stage",
        "transferRef": "stage-1",
        "requestDigest": "a" * 64,
        "direction": "stage_input",
        "path": "worktree/input.txt",
        "declaredSizeBytes": len(staged_bytes),
        "authorizedMaxSizeBytes": len(staged_bytes),
        "contentSha256": hashlib.sha256(staged_bytes).hexdigest(),
        "overwritePolicy": "forbid",
    }
    assert transport.rpc({}, stage, staged_body).header["state"] == "completed"
    assert (workspace / "worktree/input.txt").read_bytes() == staged_bytes

    captured_bytes = b"captured output\n"
    output = workspace / "worktree/output.txt"
    output.write_bytes(captured_bytes)
    collect = {
        "action": "collect",
        "transferRef": "collect-1",
        "requestDigest": "b" * 64,
        "direction": "collect_output",
        "path": "worktree/output.txt",
        "declaredSizeBytes": len(captured_bytes),
        "authorizedMaxSizeBytes": len(captured_bytes),
        "contentSha256": hashlib.sha256(captured_bytes).hexdigest(),
        "overwritePolicy": "forbid",
    }
    collected = transport.rpc({}, collect)
    assert collected.header["state"] == "completed"
    assert collected.content_path is not None
    try:
        assert collected.content_path.read_bytes() == captured_bytes
    finally:
        collected.content_path.unlink(missing_ok=True)

    launcher_socket = Path("/tmp") / f"kcs-launcher-{uuid.uuid4().hex}.sock"
    monkeypatch.setenv("KCS_NATIVE_LAUNCHER_SOCKET", str(launcher_socket))
    ready = threading.Event()
    launcher = threading.Thread(
        target=_serve_launcher_once,
        args=(launcher_socket, ready, {"terminalRef": "terminal-1"}),
        daemon=True,
    )
    launcher.start()
    assert ready.wait(timeout=2)
    pty_payload = {"cols": 120, "rows": 40}
    pty = {
        "action": "nativeLauncher",
        "jobUid": "job-uid",
        "podUid": "pod-uid",
        "frame": {
            "command": "createPty",
            "requestRef": "terminal-1",
            "requestDigest": canonical_digest(pty_payload),
            "generation": 1,
            "payload": pty_payload,
        },
    }
    assert transport.rpc({}, pty).header["result"] == {"terminalRef": "terminal-1"}
    launcher.join(timeout=2)
    assert not launcher.is_alive()
    launcher_socket.unlink(missing_ok=True)
