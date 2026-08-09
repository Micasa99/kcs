from __future__ import annotations

import hashlib
import json
import os
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


def _finalize_receipt(
    finalize_request: dict[str, object],
    *,
    state: str,
    commit_request: dict[str, object] | None = None,
) -> dict[str, object]:
    frame = finalize_request["frame"]
    assert isinstance(frame, dict)
    payload = frame["payload"]
    assert isinstance(payload, dict)
    identity = {
        "schemaVersion": 1,
        "requestRef": frame["requestRef"],
        "requestDigest": frame["requestDigest"],
        "captureReceiptDigest": payload["captureReceiptDigest"],
        "jobUid": finalize_request["jobUid"],
        "podUid": finalize_request["podUid"],
        "generation": frame["generation"],
        "acceptedAt": "2026-08-09T00:00:00Z",
    }
    receipt: dict[str, object] = {
        **identity,
        "receiptDigest": hashlib.sha256(
            json.dumps(identity, separators=(",", ":")).encode()
        ).hexdigest(),
        "state": state,
        "commitRequestRef": None,
        "commitRequestDigest": None,
        "committedAt": None,
    }
    if state == "committed":
        assert commit_request is not None
        commit_frame = commit_request["frame"]
        assert isinstance(commit_frame, dict)
        receipt.update(
            {
                "commitRequestRef": commit_frame["requestRef"],
                "commitRequestDigest": commit_frame["requestDigest"],
                "committedAt": "2026-08-09T00:00:01Z",
            }
        )
    return receipt


def _public_receipt(receipt: dict[str, object]) -> dict[str, object]:
    return {
        key: receipt[key]
        for key in (
            "requestRef",
            "requestDigest",
            "captureReceiptDigest",
            "receiptDigest",
            "state",
            "acceptedAt",
            "commitRequestRef",
            "commitRequestDigest",
            "committedAt",
        )
    }


def _read_launcher_request(connection: socket.socket) -> dict[str, object]:
    size = struct.unpack(">I", _recv_exact(connection, 4))[0]
    request = json.loads(_recv_exact(connection, size))
    assert isinstance(request, dict)
    return request


def _write_launcher_ack(
    connection: socket.socket,
    request: dict[str, object],
    response_payload: dict[str, object],
) -> None:
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
        "observedAt": "2026-08-09T00:00:02Z",
        "errorCode": None,
        "payload": response_payload,
    }
    encoded = json.dumps(response, separators=(",", ":")).encode()
    connection.sendall(struct.pack(">I", len(encoded)) + encoded)


def _serve_two_phase_finalize(
    socket_path: Path,
    ready: threading.Event,
    finalize_request: dict[str, object],
    observed: list[dict[str, object]],
    *,
    committed_receipt_path: Path | None = None,
    drop_commit_ack: bool = False,
) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(2)
        ready.set()
        finalize_connection, _ = listener.accept()
        with finalize_connection:
            received_finalize = _read_launcher_request(finalize_connection)
            observed.append(received_finalize)
            assert received_finalize["command"] == "finalize"
            accepted = _finalize_receipt(finalize_request, state="accepted")
            _write_launcher_ack(
                finalize_connection,
                received_finalize,
                {
                    "finalized": True,
                    "launcherAlive": True,
                    "finalizeReceipt": _public_receipt(accepted),
                },
            )

        commit_connection, _ = listener.accept()
        with commit_connection:
            received_commit = _read_launcher_request(commit_connection)
            observed.append(received_commit)
            assert received_commit["command"] == "commitFinalize"
            commit_payload = received_commit["payload"]
            assert isinstance(commit_payload, dict)
            assert commit_payload == {"finalizeReceiptDigest": accepted["receiptDigest"]}
            committed = _finalize_receipt(
                finalize_request,
                state="committed",
                commit_request={
                    "frame": {
                        "requestRef": received_commit["requestRef"],
                        "requestDigest": received_commit["requestDigest"],
                    }
                },
            )
            if committed_receipt_path is not None:
                committed_receipt_path.write_text(
                    json.dumps(committed, separators=(",", ":")), encoding="utf-8"
                )
                committed_receipt_path.chmod(0o600)
            if not drop_commit_ack:
                _write_launcher_ack(
                    commit_connection,
                    received_commit,
                    {
                        "committed": True,
                        "launcherAlive": False,
                        "finalizeReceipt": _public_receipt(committed),
                    },
                )
    socket_path.unlink(missing_ok=True)


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
    observed: list[dict[str, object]] = []
    finalize_request = _finalize_request()
    launcher = threading.Thread(
        target=_serve_two_phase_finalize,
        args=(launcher_socket, ready, finalize_request, observed),
        daemon=True,
    )
    launcher.start()
    assert ready.wait(timeout=2)

    control = RuntimeControlSidecar(workspace, control_state)
    transport = LocalWorkspaceRpcTransport(control.dispatch, temp_dir=tmp_path)
    first = _without_body_size(transport.rpc({}, finalize_request).header)
    accepted = _finalize_receipt(finalize_request, state="accepted")
    assert first == {
        "ok": True,
        "result": {
            "finalized": True,
            "launcherAlive": True,
            "finalizeReceipt": _public_receipt(accepted),
        },
    }

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
    assert _without_body_size(replay_transport.rpc({}, finalize_request).header) == first

    stopped = _without_body_size(replay_transport.rpc({}, {"action": "shutdown"}).header)
    assert stopped == {"ok": True, "state": "stopped", "supervisorAlive": False}
    assert restarted.shutdown_requested is True
    launcher.join(timeout=2)
    assert not launcher.is_alive()
    assert [request["command"] for request in observed] == ["finalize", "commitFinalize"]


def test_shutdown_reconciles_committed_receipt_when_commit_ack_is_lost(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    control_state = tmp_path / "control-state"
    launcher_socket = Path("/tmp") / f"kcs-launcher-{uuid.uuid4().hex}.sock"
    launcher_receipt = tmp_path / "launcher-finalize-receipt.json"
    monkeypatch.setenv("KCS_NATIVE_LAUNCHER_SOCKET", str(launcher_socket))
    monkeypatch.setenv("KCS_NATIVE_FINALIZE_RECEIPT_PATH", str(launcher_receipt))

    ready = threading.Event()
    observed: list[dict[str, object]] = []
    finalize_request = _finalize_request()
    launcher = threading.Thread(
        target=_serve_two_phase_finalize,
        args=(launcher_socket, ready, finalize_request, observed),
        kwargs={
            "committed_receipt_path": launcher_receipt,
            "drop_commit_ack": True,
        },
        daemon=True,
    )
    launcher.start()
    assert ready.wait(timeout=2)

    control = RuntimeControlSidecar(workspace, control_state)
    transport = LocalWorkspaceRpcTransport(control.dispatch, temp_dir=tmp_path)
    assert transport.rpc({}, finalize_request).header["ok"] is True
    stopped = _without_body_size(transport.rpc({}, {"action": "shutdown"}).header)
    assert stopped == {"ok": True, "state": "stopped", "supervisorAlive": False}
    assert control.shutdown_requested is True
    launcher.join(timeout=2)
    assert not launcher.is_alive()
    assert [request["command"] for request in observed] == ["finalize", "commitFinalize"]


def test_shutdown_does_not_infer_commit_from_missing_launcher_socket(
    tmp_path: Path, monkeypatch
) -> None:
    launcher_socket = Path("/tmp") / f"kcs-launcher-{uuid.uuid4().hex}.sock"
    monkeypatch.setenv("KCS_NATIVE_LAUNCHER_SOCKET", str(launcher_socket))
    finalize_request = _finalize_request()
    accepted = _finalize_receipt(finalize_request, state="accepted")
    ready = threading.Event()
    launcher = threading.Thread(
        target=_serve_launcher_once,
        args=(
            launcher_socket,
            ready,
            {
                "finalized": True,
                "launcherAlive": True,
                "finalizeReceipt": _public_receipt(accepted),
            },
        ),
        daemon=True,
    )
    launcher.start()
    assert ready.wait(timeout=2)

    control = RuntimeControlSidecar(tmp_path / "workspace", tmp_path / "control-state")
    transport = LocalWorkspaceRpcTransport(control.dispatch, temp_dir=tmp_path)
    assert transport.rpc({}, finalize_request).header["ok"] is True
    launcher.join(timeout=2)
    launcher_socket.unlink(missing_ok=True)

    stopped = transport.rpc({}, {"action": "shutdown"}).header
    assert stopped["ok"] is False
    assert stopped["code"] == "DEPENDENCY_UNAVAILABLE"
    assert control.shutdown_requested is False


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
    staged_stat = (workspace / "worktree/input.txt").stat()
    if os.geteuid() == 0:
        assert (staged_stat.st_uid, staged_stat.st_gid) == (10001, 10001)
    assert staged_stat.st_mode & 0o777 == 0o660
    parent_stat = (workspace / "worktree").stat()
    if os.geteuid() == 0:
        assert (parent_stat.st_uid, parent_stat.st_gid) == (10001, 10001)
    assert parent_stat.st_mode & 0o2777 == 0o2775

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
