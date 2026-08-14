"""Production workspace control over a private Unix socket.

The control process owns transport, staging, capture, native-launcher forwarding,
PTY forwarding and finalize coordination.  Research or conformance actions are
extensions and are deliberately not part of this module.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import Any, NoReturn
from urllib.parse import urlsplit, urlunsplit

import rfc8785

from kcs.jobs.errors import DependencyUnavailableError
from kcs.jobs.policy import validate_safe_relative_path
from kcs.jobs.transport import (
    decode_workspace_header,
    write_workspace_response,
)

_COPY_CHUNK = 1024 * 1024
_MAX_RPC_HEADER = 4 * 1024 * 1024
_MAX_NATIVE_FRAME = 131072
_MAX_INLINE_OPERATION_RESULT = 64 * 1024
_MAX_OPERATION_RESULT = 256 * 1024 * 1024
_MAX_STAGE_TREE_ENTRIES = 4096
_MAX_CAPTURE_TREE_FILES = 4096
_MAX_CAPTURE_TREE_BYTES = 128 * 1024 * 1024
_MAX_LIVE_SNAPSHOT_ENTRIES = 2000
_MAX_LIVE_SNAPSHOT_BYTES = 16 * 1024 * 1024
_MAX_LIVE_CONTENT_RANGE = 1024 * 1024
_WORKSPACE_TREE_SCHEMA = "cosmos.workspace-tree/1"
_ENTRY_MODE_BITS = {
    "read_only": 0o444,
    "read_write": 0o664,
    "executable": 0o775,
}
_EXPERIMENT_UID = 10001
_EXPERIMENT_GID = 10001
_NATIVE_FINALIZE_RECEIPT_PATH = "/run/rc-control/finalize-receipt.json"
_NATIVE_LAUNCHER_PRECONDITION_ERRORS = frozenset(
    {
        "entrypoint_invalid",
        "launch_invalid",
        "model_route_missing",
        "runner_adapter_invalid",
        "runner_adapter_unsupported",
        "runner_entrypoint_mismatch",
        "runner_protocol_unsupported",
    }
)
_NATIVE_LAUNCHER_DEPENDENCY_ERRORS = frozenset(
    {
        "child_start_failed",
        "credential_unavailable",
        "finalize_pending",
        "trajectory_open_failed",
    }
)


class _RpcRejectedError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def _workspace_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise _RpcRejectedError("INVALID_REQUEST", "workspace path is absent")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise _RpcRejectedError("UNSAFE_PATH", "workspace path is unsafe")
    if path.parts[0] in {".git", ".cosmos"}:
        raise _RpcRejectedError("UNSAFE_PATH", "workspace entry claims a private prefix")
    return str(path)


def _workspace_action_payload(frame: Mapping[str, Any]) -> dict[str, Any]:
    if set(frame) != {
        "protocol",
        "action",
        "operation_id",
        "request_digest",
        "frame_digest",
        "payload",
    }:
        raise _RpcRejectedError("INVALID_REQUEST", "workspace tree frame is not closed")
    payload = frame.get("payload")
    if not isinstance(payload, dict):
        raise _RpcRejectedError("INVALID_REQUEST", "workspace tree payload is absent")
    frame_digest = frame.get("frame_digest")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if frame_digest != hashlib.sha256(encoded.encode()).hexdigest():
        raise _RpcRejectedError("DIGEST_MISMATCH", "workspace tree frame digest differs")
    request_digest = frame.get("request_digest")
    if not isinstance(request_digest, str) or len(request_digest) != 64:
        raise _RpcRejectedError("INVALID_REQUEST", "workspace request digest is invalid")
    return payload


def _workspace_tree_entries(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > _MAX_STAGE_TREE_ENTRIES:
        raise _RpcRejectedError("INVALID_REQUEST", "workspace tree entries are invalid")
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != {"path", "size", "sha256", "mode"}:
            raise _RpcRejectedError("INVALID_REQUEST", "workspace tree entry is invalid")
        relative = _workspace_relative_path(raw.get("path"))
        size = raw.get("size")
        digest = raw.get("sha256")
        mode = raw.get("mode")
        if (
            relative in seen
            or type(size) is not int
            or size < 0
            or not isinstance(digest, str)
            or len(digest) != 64
            or mode not in _ENTRY_MODE_BITS
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "workspace tree entry descriptor is invalid")
        seen.add(relative)
        entries.append({"path": relative, "size": size, "sha256": digest, "mode": mode})
    return entries


def _workspace_tree_digest(entries: list[dict[str, object]]) -> str:
    canonical = [
        {
            "path": entry["path"],
            "blobDigest": entry["sha256"],
            "size": entry["size"],
            "mode": entry["mode"],
        }
        for entry in sorted(entries, key=lambda entry: str(entry["path"]))
    ]
    encoded = json.dumps(
        {"schema": _WORKSPACE_TREE_SCHEMA, "entries": canonical},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode()).hexdigest()


class RuntimeControlSidecar:
    """Production control authority; no network listener is created."""

    def __init__(
        self,
        workspace: Path,
        control_state_dir: Path | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        workspace.mkdir(parents=True, exist_ok=True)
        self.workspace = workspace.resolve(strict=True)
        self._private = _private_directory(self.workspace, ".kcs")
        self._partials = _private_directory(self._private, "partials")
        self._snapshots = _private_directory(self._private, "snapshots")
        self._receipts = _private_directory(self._private, "receipts")
        if control_state_dir is None:
            configured = os.environ.get("KCS_CONTROL_STATE_DIR")
            control_state_dir = (
                Path(configured) if configured else self._private / "runtime-control"
            )
        self._control_state = _secure_directory(control_state_dir)
        self._finalize_receipts = _private_directory(self._control_state, "finalize-receipts")
        self._base_manifests = _private_directory(self._control_state, "base-manifests")
        self._live_snapshots = _private_directory(self._control_state, "live-snapshots")
        self._project_snapshots = _private_directory(self._private, "project-snapshots")
        self._project_import_receipts = _private_directory(
            self._private, "project-import-receipts"
        )
        self._clock = clock or (lambda: datetime.now(UTC))
        self._transfers: dict[str, dict[str, Any]] = {}
        self._operations: dict[str, dict[str, Any]] = {}
        self._operation_claims: dict[str, dict[str, str]] = {}
        self._operation_fences: dict[str, dict[str, str]] = {}
        self._operation_lock = RLock()
        self._finalize_lock = RLock()
        self._live_snapshot_lock = RLock()
        self._project_snapshot_lock = RLock()
        self._stage_installs = 0
        self._operation_side_effects = 0
        self._native_state_generation = 0
        self._native_state_sequence = 0
        self._native_state_digest: str | None = None
        self.shutdown_requested = False
        self._workspace_context = {
            key: value
            for key, value in (
                ("conversationRef", os.environ.get("AICOSMOS_CONVERSATION_REF", "").strip()),
                ("attemptRef", os.environ.get("AICOSMOS_ATTEMPT_REF", "").strip()),
                ("productBase", os.environ.get("AICOSMOS_PRODUCT_BASE", "").strip()),
            )
            if value
        }
        worktree = self.workspace / "worktree"
        if self._workspace_context and (
            "conversationRef" in self._workspace_context or (worktree / ".git").exists()
        ):
            self._publish_workspace_context()

    def dispatch(self, frame: bytes, body: Path | None, response_path: Path) -> None:
        """Handle one framed request and write one framed response atomically."""
        try:
            request = decode_workspace_header(frame)
            declared_body = request.pop("bodySize")
            actual_body = body.stat().st_size if body is not None else 0
            if declared_body != actual_body:
                raise _RpcRejectedError("TRANSFER_BYTES_MISMATCH", "RPC body length mismatch")
            response, response_body = self._handle(request, body)
        except _RpcRejectedError as error:
            response, response_body = (
                {
                    "ok": False,
                    "code": error.code,
                    "message": error.message,
                },
                None,
            )
        except Exception:
            response, response_body = (
                {
                    "ok": False,
                    "code": "INTERNAL_ERROR",
                    "message": "workspace sidecar rejected the request",
                },
                None,
            )
        try:
            write_workspace_response(response_path, response, response_body)
        finally:
            if (
                response_body is not None
                and response_body.parent == self._control_state
                and response_body.name.startswith(".live-range-")
            ):
                response_body.unlink(missing_ok=True)

    def stats(self) -> dict[str, int]:
        return {
            "stageInstalls": self._stage_installs,
            "operationSideEffects": self._operation_side_effects,
        }

    def forget_operations(self) -> None:
        """Model a surviving Pod whose replacement sidecar lost runtime truth."""
        with self._operation_lock:
            self._operations.clear()
            self._operation_claims.clear()
            self._operation_fences.clear()

    def _handle(
        self, request: Mapping[str, Any], body: Path | None
    ) -> tuple[dict[str, object], Path | None]:
        action = request.get("action")
        if action == "validateTransfer":
            self._validate_transfer_path(request)
            return {"ok": True, "state": "validated"}, None
        if action == "stage":
            return self._stage(request, body), None
        if action == "collect":
            return self._collect(request)
        if action == "inspectTransfer":
            return self._inspect_transfer(request), None
        if action == "cancelTransfer":
            return self._cancel_transfer(request), None
        if action == "discardTransfer":
            return self._discard_transfer(request), None
        if action == "invoke":
            return self._invoke(request), None
        if action == "fenceOperation":
            return self._fence_operation(request), None
        if action == "inspectOperation":
            return self._inspect_operation(request), None
        if action in {"cancelOperation", "discardOperation"}:
            return self._end_operation(request, str(action)), None
        if action == "stats":
            return {"ok": True, **self.stats()}, None
        if action == "inspectSupervisor":
            return {"ok": True, "state": "idle", "supervisorAlive": True}, None
        if action == "nativeLauncher":
            return self._native_launcher(request), None
        if action == "inspectNativeFinalize":
            return self._inspect_native_finalize(request), None
        if action == "createLiveWorkspaceSnapshot":
            return self._create_live_workspace_snapshot(request), None
        if action == "inspectLiveWorkspaceSnapshot":
            return self._inspect_live_workspace_snapshot(request), None
        if action == "releaseLiveWorkspaceSnapshot":
            return self._release_live_workspace_snapshot(request), None
        if action == "readLiveWorkspaceContent":
            return self._read_live_workspace_content(request)
        if action == "getLiveWorkspaceDiff":
            return self._get_live_workspace_diff(request), None
        if action == "configureWorkspaceContext":
            return self._configure_workspace_context(request), None
        if action == "createProjectWorkspaceSnapshot":
            return self._create_project_workspace_snapshot(request)
        if action == "readProjectWorkspaceSnapshot":
            return self._read_project_workspace_snapshot(request)
        if action == "importProjectWorkspaceRevision":
            return self._import_project_workspace_revision(request, body), None
        if action == "shutdown":
            retained = self._acknowledged_finalize_receipt()
            self._commit_native_finalize(retained)
            self._wait_for_native_launcher_exit()
            self.shutdown_requested = True
            return {"ok": True, "state": "stopped", "supervisorAlive": False}, None
        return self._handle_extension(request, body)

    def _handle_extension(
        self, request: Mapping[str, Any], body: Path | None
    ) -> tuple[dict[str, object], Path | None]:
        """Reject application-specific actions in the production control."""
        del request, body
        raise _RpcRejectedError("INVALID_REQUEST", "unsupported workspace RPC action")

    @staticmethod
    def _wait_for_native_launcher_exit() -> None:
        socket_path = os.environ.get("KCS_NATIVE_LAUNCHER_SOCKET", "/run/rc-control/launcher.sock")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(0.2)
                    connection.connect(socket_path)
            except OSError:
                return
            time.sleep(0.05)
        raise _RpcRejectedError(
            "DEPENDENCY_UNAVAILABLE", "native launcher did not exit after finalize"
        )

    def _native_launcher(self, request: Mapping[str, Any]) -> dict[str, object]:
        if set(request) != {"action", "jobUid", "podUid", "frame"}:
            raise _RpcRejectedError("INVALID_REQUEST", "native launcher envelope is invalid")
        frame = request.get("frame")
        if (
            not isinstance(frame, dict)
            or set(frame) != {"command", "requestRef", "requestDigest", "generation", "payload"}
            or frame.get("command")
            not in {
                "credentialStatus",
                "start",
                "inspect",
                "stop",
                "finalize",
                "commitFinalize",
                "createPty",
                "writePty",
                "readPty",
                "resizePty",
                "closePty",
            }
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "native launcher command is not allowed")
        command = frame["command"]
        request_ref = frame["requestRef"]
        request_digest = frame["requestDigest"]
        generation = frame["generation"]
        command_payload = frame["payload"]
        if (
            not isinstance(command, str)
            or not isinstance(request_ref, str)
            or not request_ref
            or not isinstance(request_digest, str)
            or len(request_digest) != 64
            or type(generation) is not int
            or generation < 0
            or not isinstance(command_payload, dict)
            or not isinstance(request.get("jobUid"), str)
            or not request["jobUid"]
            or not isinstance(request.get("podUid"), str)
            or not request["podUid"]
            or hashlib.sha256(rfc8785.dumps(command_payload)).hexdigest() != request_digest
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "native launcher identity is invalid")
        if command == "finalize":
            raw_capture_digest = command_payload.get("captureReceiptDigest")
            if set(command_payload) != {"captureReceiptDigest"} or not _is_hex_digest(
                raw_capture_digest
            ):
                raise _RpcRejectedError(
                    "INVALID_REQUEST", "native finalize capture receipt digest is invalid"
                )
            assert isinstance(raw_capture_digest, str)
            capture_digest = raw_capture_digest.lower()
            retained = self._load_finalize_receipt(request_ref)
            if retained is not None:
                self._match_finalize_receipt(
                    retained,
                    job_uid=request["jobUid"],
                    pod_uid=request["podUid"],
                    finalize_ref=request_ref,
                    generation=generation,
                    request_digest=request_digest,
                )
                if retained["captureReceiptDigest"].lower() != capture_digest:
                    raise _RpcRejectedError(
                        "IDENTITY_CONFLICT",
                        "retained native finalize capture digest differs",
                    )
                return {"ok": True, "result": dict(retained["launcherResult"])}
        if command == "commitFinalize":
            finalize_receipt_digest = command_payload.get("finalizeReceiptDigest")
            if set(command_payload) != {"finalizeReceiptDigest"} or not _is_hex_digest(
                finalize_receipt_digest
            ):
                raise _RpcRejectedError(
                    "INVALID_REQUEST", "native finalize commit receipt digest is invalid"
                )
        payload = {
            "schemaVersion": 1,
            "command": command,
            "requestRef": request_ref,
            "requestDigest": request_digest,
            "jobUid": request["jobUid"],
            "podUid": request["podUid"],
            "generation": generation,
            "payload": command_payload,
        }
        encoded = rfc8785.dumps(payload)
        if len(encoded) > _MAX_NATIVE_FRAME:
            raise _RpcRejectedError("INVALID_REQUEST", "native launcher frame exceeds 128 KiB")
        socket_path = Path(
            os.environ.get("KCS_NATIVE_LAUNCHER_SOCKET", "/run/rc-control/launcher.sock")
        )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(30)
                connection.connect(str(socket_path))
                connection.sendall(struct.pack(">I", len(encoded)) + encoded)
                response_size = struct.unpack(">I", _recv_exact(connection, 4))[0]
                if response_size > _MAX_NATIVE_FRAME:
                    raise _RpcRejectedError(
                        "DEPENDENCY_UNAVAILABLE", "native launcher reply is too large"
                    )
                response = _recv_exact(connection, response_size)
        except (OSError, TimeoutError) as error:
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE", "native launcher socket is unavailable"
            ) from error
        try:
            result = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE", "native launcher reply is malformed"
            ) from error
        expected_ack_keys = {
            "schemaVersion",
            "command",
            "requestRef",
            "requestDigest",
            "jobUid",
            "podUid",
            "generation",
            "state",
            "replayed",
            "observedAt",
            "errorCode",
            "payload",
        }
        if (
            not isinstance(result, dict)
            or set(result) != expected_ack_keys
            or result["schemaVersion"] != 1
            or result["command"] != command
            or result["requestRef"] != request_ref
            or result["requestDigest"] != request_digest
            or result["jobUid"] != request["jobUid"]
            or result["podUid"] != request["podUid"]
            or result["generation"] != generation
            or result["state"] not in {"accepted", "completed", "failed"}
            or type(result["replayed"]) is not bool
            or not isinstance(result["payload"], dict)
        ):
            raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", "native launcher reply is invalid")
        if result["state"] == "failed":
            code = result["errorCode"]
            if code == "capacity_insufficient":
                public_code = "PRECONDITION_FAILED"
            elif code in {"identity_conflict", "stale_binding"}:
                public_code = "STATE_CONFLICT"
            elif code in _NATIVE_LAUNCHER_PRECONDITION_ERRORS:
                public_code = "PRECONDITION_FAILED"
            else:
                public_code = "DEPENDENCY_UNAVAILABLE"
            known_errors = (
                _NATIVE_LAUNCHER_PRECONDITION_ERRORS
                | _NATIVE_LAUNCHER_DEPENDENCY_ERRORS
                | {"capacity_insufficient", "identity_conflict", "stale_binding"}
            )
            public_error = (
                code if isinstance(code, str) and code in known_errors else "launcher_failed"
            )
            raise _RpcRejectedError(
                public_code,
                f"native launcher rejected {command}: {public_error}",
            )
        if command in {"start", "inspect", "stop"}:
            result["payload"]["runnerObservation"] = self._read_native_state(
                request["jobUid"], request["podUid"], generation
            )
        if command == "start":
            descriptor = command_payload.get("descriptor")
            if not isinstance(descriptor, Mapping) or not _is_hex_digest(
                descriptor.get("baseManifestDigest")
            ):
                raise _RpcRejectedError(
                    "DEPENDENCY_UNAVAILABLE", "native start descriptor has no base manifest"
                )
            self._bind_latest_base_manifest(str(descriptor["baseManifestDigest"]))
        if command == "finalize":
            if result["state"] != "completed":
                raise _RpcRejectedError(
                    "DEPENDENCY_UNAVAILABLE",
                    "native launcher finalize acknowledgement is invalid",
                )
            finalize_receipt = _validate_finalize_launcher_result(
                result["payload"],
                job_uid=str(request["jobUid"]),
                pod_uid=str(request["podUid"]),
                finalize_ref=request_ref,
                request_digest=request_digest,
                generation=generation,
                capture_receipt_digest=capture_digest,
            )
            self._write_finalize_receipt(
                {
                    "schemaVersion": 1,
                    "state": "acknowledged",
                    "jobUid": request["jobUid"],
                    "podUid": request["podUid"],
                    "finalizeRef": request_ref,
                    "requestDigest": request_digest,
                    "generation": generation,
                    "captureReceiptDigest": capture_digest,
                    "finalizeReceiptDigest": finalize_receipt["receiptDigest"],
                    "launcherResult": result["payload"],
                    "observedAt": result["observedAt"],
                }
            )
        if command == "commitFinalize":
            if result["state"] != "completed":
                raise _RpcRejectedError(
                    "DEPENDENCY_UNAVAILABLE",
                    "native launcher finalize commit acknowledgement is invalid",
                )
            _validate_commit_launcher_result(
                result["payload"],
                job_uid=str(request["jobUid"]),
                pod_uid=str(request["podUid"]),
                generation=generation,
                commit_ref=request_ref,
                commit_digest=request_digest,
                finalize_receipt_digest=str(command_payload["finalizeReceiptDigest"]),
            )
        return {"ok": True, "result": result["payload"]}

    def _inspect_native_finalize(self, request: Mapping[str, Any]) -> dict[str, object]:
        expected = {
            "action",
            "jobUid",
            "podUid",
            "finalizeRef",
            "generation",
            "requestDigest",
        }
        if set(request) != expected:
            raise _RpcRejectedError(
                "INVALID_REQUEST", "native finalize inspection envelope is invalid"
            )
        job_uid = request.get("jobUid")
        pod_uid = request.get("podUid")
        finalize_ref = request.get("finalizeRef")
        generation = request.get("generation")
        request_digest = request.get("requestDigest")
        if (
            not isinstance(job_uid, str)
            or not job_uid
            or not isinstance(pod_uid, str)
            or not pod_uid
            or not isinstance(finalize_ref, str)
            or not finalize_ref
            or type(generation) is not int
            or generation < 0
            or not isinstance(request_digest, str)
            or len(request_digest) != 64
        ):
            raise _RpcRejectedError(
                "INVALID_REQUEST", "native finalize inspection identity is invalid"
            )
        retained = self._load_finalize_receipt(finalize_ref)
        if retained is None:
            return {
                "ok": True,
                "state": "absent",
                "generation": generation,
                "requestDigest": request_digest,
                "captureReceiptDigest": None,
            }
        self._match_finalize_receipt(
            retained,
            job_uid=job_uid,
            pod_uid=pod_uid,
            finalize_ref=finalize_ref,
            generation=generation,
            request_digest=request_digest,
        )
        return {
            "ok": True,
            "state": "acknowledged",
            "generation": retained["generation"],
            "requestDigest": retained["requestDigest"],
            "captureReceiptDigest": retained["captureReceiptDigest"],
        }

    def _finalize_receipt_path(self, finalize_ref: str) -> Path:
        name = hashlib.sha256(finalize_ref.encode()).hexdigest()
        return self._finalize_receipts / f"{name}.json"

    def _load_finalize_receipt(self, finalize_ref: str) -> dict[str, Any] | None:
        path = self._finalize_receipt_path(finalize_ref)
        with self._finalize_lock:
            try:
                return self._read_finalize_receipt_path(path)
            except FileNotFoundError:
                return None

    @staticmethod
    def _read_finalize_receipt_path(path: Path) -> dict[str, Any]:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > 131072
        ):
            raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", "native finalize receipt is unsafe")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            raw = source.read(131073)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE", "native finalize receipt is malformed"
            ) from error
        expected = {
            "schemaVersion",
            "state",
            "jobUid",
            "podUid",
            "finalizeRef",
            "requestDigest",
            "generation",
            "captureReceiptDigest",
            "finalizeReceiptDigest",
            "launcherResult",
            "observedAt",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or value["schemaVersion"] != 1
            or value["state"] != "acknowledged"
            or not isinstance(value["jobUid"], str)
            or not isinstance(value["podUid"], str)
            or not isinstance(value["finalizeRef"], str)
            or not isinstance(value["requestDigest"], str)
            or len(value["requestDigest"]) != 64
            or type(value["generation"]) is not int
            or value["generation"] < 0
            or not _is_hex_digest(value["captureReceiptDigest"])
            or not _is_hex_digest(value["finalizeReceiptDigest"])
            or not isinstance(value["launcherResult"], dict)
            or not isinstance(value["observedAt"], str)
        ):
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE", "native finalize receipt is malformed"
            )
        finalize_receipt = _validate_finalize_launcher_result(
            value["launcherResult"],
            job_uid=value["jobUid"],
            pod_uid=value["podUid"],
            finalize_ref=value["finalizeRef"],
            request_digest=value["requestDigest"],
            generation=value["generation"],
            capture_receipt_digest=value["captureReceiptDigest"],
        )
        if finalize_receipt["receiptDigest"] != value["finalizeReceiptDigest"]:
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE", "native finalize receipt digest differs"
            )
        return value

    @staticmethod
    def _match_finalize_receipt(
        retained: Mapping[str, Any],
        *,
        job_uid: str,
        pod_uid: str,
        finalize_ref: str,
        generation: int,
        request_digest: str,
    ) -> None:
        if (
            retained.get("jobUid") != job_uid
            or retained.get("podUid") != pod_uid
            or retained.get("finalizeRef") != finalize_ref
            or retained.get("generation") != generation
            or retained.get("requestDigest") != request_digest
        ):
            raise _RpcRejectedError(
                "IDENTITY_CONFLICT", "retained native finalize identity differs"
            )

    def _write_finalize_receipt(self, receipt: Mapping[str, Any]) -> None:
        encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        finalize_ref = str(receipt["finalizeRef"])
        with self._finalize_lock:
            retained = self._load_finalize_receipt(finalize_ref)
            if retained is not None:
                self._match_finalize_receipt(
                    retained,
                    job_uid=str(receipt["jobUid"]),
                    pod_uid=str(receipt["podUid"]),
                    finalize_ref=finalize_ref,
                    generation=int(receipt["generation"]),
                    request_digest=str(receipt["requestDigest"]),
                )
                if retained != receipt:
                    raise _RpcRejectedError(
                        "IDENTITY_CONFLICT", "retained native finalize receipt differs"
                    )
                return
            descriptor, raw_partial = tempfile.mkstemp(
                dir=self._finalize_receipts, prefix=".partial-"
            )
            partial = Path(raw_partial)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(partial, self._finalize_receipt_path(finalize_ref))
                _fsync_directory(self._finalize_receipts)
            finally:
                partial.unlink(missing_ok=True)

    def _acknowledged_finalize_receipt(self) -> dict[str, Any]:
        with self._finalize_lock:
            paths = tuple(self._finalize_receipts.glob("*.json"))
            receipts = tuple(self._read_finalize_receipt_path(path) for path in paths)
        if not receipts:
            raise _RpcRejectedError(
                "PRECONDITION_FAILED",
                "native finalize receipt is not durably acknowledged",
            )
        if len(receipts) != 1:
            raise _RpcRejectedError(
                "STATE_CONFLICT",
                "multiple native finalize receipts prevent shutdown",
            )
        return receipts[0]

    def _commit_native_finalize(self, retained: Mapping[str, Any]) -> None:
        finalize_receipt_digest = str(retained["finalizeReceiptDigest"])
        commit_payload = {"finalizeReceiptDigest": finalize_receipt_digest}
        commit_digest = hashlib.sha256(rfc8785.dumps(commit_payload)).hexdigest()
        commit_ref = (
            "commit-"
            + hashlib.sha256(
                rfc8785.dumps(
                    {
                        "finalizeRef": retained["finalizeRef"],
                        "finalizeReceiptDigest": finalize_receipt_digest,
                    }
                )
            ).hexdigest()
        )
        request: dict[str, object] = {
            "action": "nativeLauncher",
            "jobUid": retained["jobUid"],
            "podUid": retained["podUid"],
            "frame": {
                "command": "commitFinalize",
                "requestRef": commit_ref,
                "requestDigest": commit_digest,
                "generation": retained["generation"],
                "payload": commit_payload,
            },
        }
        try:
            response = self._native_launcher(request)
        except _RpcRejectedError as error:
            if error.code != "DEPENDENCY_UNAVAILABLE":
                raise
            committed = self._read_launcher_finalize_receipt()
            self._match_committed_launcher_receipt(
                committed,
                retained=retained,
                commit_ref=commit_ref,
                commit_digest=commit_digest,
            )
            if not self._native_launcher_accepting():
                return
            try:
                response = self._native_launcher(request)
            except _RpcRejectedError as retry_error:
                if retry_error.code != "DEPENDENCY_UNAVAILABLE":
                    raise
                committed = self._read_launcher_finalize_receipt()
                self._match_committed_launcher_receipt(
                    committed,
                    retained=retained,
                    commit_ref=commit_ref,
                    commit_digest=commit_digest,
                )
                if self._native_launcher_accepting():
                    raise
                return
        result = response.get("result")
        if not isinstance(result, dict):
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE",
                "native launcher finalize commit acknowledgement is invalid",
            )
        self._match_committed_public_receipt(
            result,
            retained=retained,
            commit_ref=commit_ref,
            commit_digest=commit_digest,
        )

    @staticmethod
    def _match_committed_public_receipt(
        result: Mapping[str, Any],
        *,
        retained: Mapping[str, Any],
        commit_ref: str,
        commit_digest: str,
    ) -> None:
        finalize_receipt = result.get("finalizeReceipt")
        if (
            not isinstance(finalize_receipt, dict)
            or finalize_receipt.get("requestRef") != retained["finalizeRef"]
            or finalize_receipt.get("requestDigest") != retained["requestDigest"]
            or finalize_receipt.get("captureReceiptDigest") != retained["captureReceiptDigest"]
            or finalize_receipt.get("receiptDigest") != retained["finalizeReceiptDigest"]
            or finalize_receipt.get("commitRequestRef") != commit_ref
            or finalize_receipt.get("commitRequestDigest") != commit_digest
        ):
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE",
                "native launcher committed receipt identity differs",
            )

    @staticmethod
    def _match_committed_launcher_receipt(
        committed: Mapping[str, Any],
        *,
        retained: Mapping[str, Any],
        commit_ref: str,
        commit_digest: str,
    ) -> None:
        if (
            committed.get("state") != "committed"
            or committed.get("requestRef") != retained["finalizeRef"]
            or committed.get("requestDigest") != retained["requestDigest"]
            or committed.get("captureReceiptDigest") != retained["captureReceiptDigest"]
            or committed.get("receiptDigest") != retained["finalizeReceiptDigest"]
            or committed.get("jobUid") != retained["jobUid"]
            or committed.get("podUid") != retained["podUid"]
            or committed.get("generation") != retained["generation"]
            or committed.get("commitRequestRef") != commit_ref
            or committed.get("commitRequestDigest") != commit_digest
        ):
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE",
                "native launcher retained commit identity differs",
            )

    @staticmethod
    def _native_launcher_accepting() -> bool:
        socket_path = os.environ.get("KCS_NATIVE_LAUNCHER_SOCKET", "/run/rc-control/launcher.sock")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(0.2)
                connection.connect(socket_path)
        except OSError:
            return False
        return True

    @staticmethod
    def _read_launcher_finalize_receipt() -> dict[str, Any]:
        path = Path(
            os.environ.get("KCS_NATIVE_FINALIZE_RECEIPT_PATH", _NATIVE_FINALIZE_RECEIPT_PATH)
        )
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_gid != os.getegid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > 131072
            ):
                raise _RpcRejectedError(
                    "DEPENDENCY_UNAVAILABLE",
                    "native launcher finalize receipt is unsafe",
                )
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as source:
                raw = source.read(131073)
            value = json.loads(raw)
        except _RpcRejectedError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE",
                "native launcher finalize receipt is unavailable",
            ) from error
        _validate_launcher_finalize_receipt_file(value)
        assert isinstance(value, dict)
        return value

    def _read_native_state(
        self, job_uid: object, pod_uid: object, generation: int
    ) -> dict[str, object]:
        path = Path(
            os.environ.get("KCS_NATIVE_RUNNER_STATE_PATH", "/run/rc-control/runner-state.json")
        )
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > 65536
            ):
                raise _RpcRejectedError(
                    "DEPENDENCY_UNAVAILABLE", "native runner state file is unsafe"
                )
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as source:
                raw = source.read(65537)
            value = json.loads(raw)
        except _RpcRejectedError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE", "native runner state is unavailable"
            ) from error
        expected = {
            "schemaVersion",
            "jobUid",
            "podUid",
            "generation",
            "sequence",
            "state",
            "stateDigest",
            "childPid",
            "processExit",
            "stopCause",
            "protocolTerminal",
            "childStartedAt",
            "childFinishedAt",
            "observedAt",
        }
        process_exit = value.get("processExit") if isinstance(value, dict) else None
        protocol_terminal = value.get("protocolTerminal") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or value["schemaVersion"] != 1
            or value["jobUid"] != job_uid
            or value["podUid"] != pod_uid
            or value["generation"] != generation
            or type(value["sequence"]) is not int
            or value["sequence"] < 1
            or value["state"] not in {"starting", "running", "exited", "killed"}
            or not isinstance(value["stateDigest"], str)
            or len(value["stateDigest"]) != 64
            or value["childPid"] is not None
            and (type(value["childPid"]) is not int or value["childPid"] < 1)
            or value["stopCause"]
            not in {
                "none",
                "natural_exit",
                "stop_requested",
                "soft_deadline",
                "cancel_requested",
                "oom_killed",
                "hard_deadline",
                "unknown",
            }
            or not isinstance(process_exit, dict)
            or set(process_exit) != {"kind", "exitCode", "signal"}
            or process_exit["kind"] not in {"not_observed", "exited", "signaled"}
            or process_exit["exitCode"] is not None
            and type(process_exit["exitCode"]) is not int
            or process_exit["signal"] is not None
            and type(process_exit["signal"]) is not int
            or not isinstance(protocol_terminal, dict)
            or set(protocol_terminal) != {"observed", "eventKind", "stopReason", "errorCode"}
            or type(protocol_terminal["observed"]) is not bool
            or any(
                item is not None and not isinstance(item, str)
                for item in (
                    protocol_terminal["eventKind"],
                    protocol_terminal["stopReason"],
                    protocol_terminal["errorCode"],
                    value["childStartedAt"],
                    value["childFinishedAt"],
                )
            )
            or not isinstance(value["observedAt"], str)
        ):
            raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", "native runner state is malformed")
        digest_input = dict(value)
        retained_digest = str(digest_input.pop("stateDigest"))
        actual_digest = hashlib.sha256(rfc8785.dumps(digest_input)).hexdigest()
        if not hmac.compare_digest(retained_digest, actual_digest):
            raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", "native runner state digest differs")
        sequence = int(value["sequence"])
        if generation < self._native_state_generation or (
            generation == self._native_state_generation
            and (
                sequence < self._native_state_sequence
                or (
                    sequence == self._native_state_sequence
                    and self._native_state_digest not in {None, retained_digest}
                )
            )
        ):
            raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", "native runner state moved backwards")
        self._native_state_generation = generation
        self._native_state_sequence = sequence
        self._native_state_digest = retained_digest
        return {
            key: value[key]
            for key in (
                "state",
                "sequence",
                "stateDigest",
                "childPid",
                "processExit",
                "stopCause",
                "protocolTerminal",
                "childStartedAt",
                "childFinishedAt",
                "observedAt",
            )
        }

    def _validate_transfer_path(
        self, request: Mapping[str, Any], *, allow_stage_existing: bool = False
    ) -> Path:
        raw_path = request.get("path")
        direction = request.get("direction")
        overwrite = request.get("overwritePolicy")
        if not isinstance(raw_path, str):
            raise _RpcRejectedError("UNSAFE_PATH", "transfer path is absent")
        try:
            validate_safe_relative_path(raw_path)
        except ValueError as error:
            raise _RpcRejectedError("UNSAFE_PATH", "transfer path is unsafe") from error
        if direction not in {"stage_input", "collect_output"}:
            raise _RpcRejectedError("INVALID_REQUEST", "transfer direction is invalid")
        if overwrite not in {"forbid", "replace_authorized"}:
            raise _RpcRejectedError("INVALID_REQUEST", "overwrite policy is invalid")
        parts = PurePosixPath(raw_path).parts
        if unicodedata.normalize("NFC", parts[0]).casefold() == ".kcs":
            raise _RpcRejectedError("UNSAFE_PATH", "workspace path enters KCS private storage")
        parent = self.workspace
        for component in parts[:-1]:
            collisions = self._casefold_entries(parent, component)
            if len(collisions) > 1 or (collisions and collisions[0].name != component):
                raise _RpcRejectedError("UNSAFE_PATH", "workspace path has a casefold collision")
            candidate = parent / component
            if candidate.exists() or candidate.is_symlink():
                mode = candidate.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                    raise _RpcRejectedError("UNSAFE_PATH", "workspace path traverses a symlink")
            parent = candidate
        collisions = self._casefold_entries(parent, parts[-1]) if parent.is_dir() else []
        if len(collisions) > 1 or (collisions and collisions[0].name != parts[-1]):
            raise _RpcRejectedError("UNSAFE_PATH", "workspace target has a casefold collision")
        target = parent / parts[-1]
        if target.is_symlink():
            raise _RpcRejectedError("UNSAFE_PATH", "workspace target is a symlink")
        if (
            direction == "stage_input"
            and target.exists()
            and overwrite == "forbid"
            and not allow_stage_existing
        ):
            raise _RpcRejectedError("OVERWRITE_FORBIDDEN", "workspace target already exists")
        if direction == "collect_output" and not target.exists():
            raise _RpcRejectedError("NOT_FOUND", "workspace output does not exist")
        return target

    def _stage(self, request: Mapping[str, Any], body: Path | None) -> dict[str, object]:
        transfer_ref, digest = _identity(request, "transferRef", "requestDigest")
        size, content_digest = _byte_contract(request)
        if body is None or body.stat().st_size != size:
            raise _RpcRejectedError("TRANSFER_BYTES_MISMATCH", "staged byte count does not match")
        actual_size, actual_digest = _hash_file(body)
        if actual_size != size or actual_digest != content_digest:
            raise _RpcRejectedError("TRANSFER_BYTES_MISMATCH", "staged bytes failed verification")
        retained = self._transfers.get(transfer_ref) or self._load_receipt(transfer_ref)
        if retained is not None:
            _same_digest(retained, digest)
            if retained.get("state") == "completed":
                if retained.get("actualSha256") != actual_digest:
                    raise _RpcRejectedError(
                        "TRANSFER_BYTES_MISMATCH", "transfer replay bytes differ"
                    )
                return _public_transfer(retained)
            if retained.get("state") in {"canceled", "discarded"}:
                raise _RpcRejectedError(
                    "STATE_CONFLICT", "the transfer already reached a terminal state"
                )
            if retained.get("state") == "indeterminate":
                raise _RpcRejectedError(
                    "TRANSFER_INDETERMINATE", "the transfer has indeterminate retained state"
                )

        self._validate_transfer_path(request, allow_stage_existing=True)
        parent_fd, target_name = self._open_parent(str(request["path"]), create=True)
        partial = self._partials / hashlib.sha256(transfer_ref.encode()).hexdigest()
        try:
            intent: dict[str, Any]
            if retained is not None and retained.get("state") == "installing":
                reconciled = self._reconcile_installing(
                    request, retained, parent_fd, target_name, partial
                )
                if reconciled is not None:
                    self._transfers[transfer_ref] = reconciled
                    return _public_transfer(reconciled)
                intent = dict(retained)
            else:
                partial.unlink(missing_ok=True)
                descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as output, body.open("rb") as source:
                    shutil.copyfileobj(source, output, length=_COPY_CHUNK)
                    output.flush()
                    os.fsync(output.fileno())
                verified_size, verified_digest = _hash_file(partial)
                if verified_size != size or verified_digest != content_digest:
                    raise _RpcRejectedError(
                        "TRANSFER_BYTES_MISMATCH", "private staged bytes changed"
                    )
                installed_stat = partial.stat(follow_symlinks=False)
                intent = {
                    **_completed_transfer(transfer_ref, digest, size, content_digest),
                    "state": "installing",
                    "direction": "stage_input",
                    "path": request["path"],
                    "overwritePolicy": request["overwritePolicy"],
                    "installDevice": installed_stat.st_dev,
                    "installInode": installed_stat.st_ino,
                }
                self._write_receipt(intent)
            matches = _casefold_entries_at(parent_fd, target_name)
            if len(matches) > 1 or (matches and matches[0] != target_name):
                raise _RpcRejectedError("UNSAFE_PATH", "workspace target is ambiguous")
            if request.get("overwritePolicy") == "forbid":
                if matches:
                    raise _RpcRejectedError(
                        "OVERWRITE_FORBIDDEN", "workspace target already exists"
                    )
                try:
                    os.link(partial, target_name, dst_dir_fd=parent_fd, follow_symlinks=False)
                except FileExistsError as error:
                    raise _RpcRejectedError(
                        "OVERWRITE_FORBIDDEN", "workspace target already exists"
                    ) from error
                partial.unlink()
            else:
                if matches:
                    existing = _stat_at(parent_fd, target_name)
                    if (
                        existing is None
                        or stat.S_ISLNK(existing.st_mode)
                        or not stat.S_ISREG(existing.st_mode)
                    ):
                        raise _RpcRejectedError(
                            "UNSAFE_PATH", "workspace target is not a regular file"
                        )
                os.replace(partial, target_name, dst_dir_fd=parent_fd)
            read_only = str(request["path"]).split("/", 1)[0] in {
                "inputs",
                "sources",
            }
            self._hand_off_staged_file(
                parent_fd,
                target_name,
                read_only=read_only,
            )
            if read_only:
                self._freeze_readonly_directories(str(request["path"]))
            os.fsync(parent_fd)
            self._stage_installs += 1
            result = {**intent, "ok": True, "state": "completed"}
            self._write_receipt(result)
            self._transfers[transfer_ref] = result
            return _public_transfer(result)
        finally:
            partial.unlink(missing_ok=True)
            os.close(parent_fd)

    @staticmethod
    def _hand_off_staged_file(
        parent_fd: int,
        target_name: str,
        *,
        read_only: bool,
    ) -> None:
        descriptor = os.open(
            target_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            os.fchmod(descriptor, 0o440 if read_only else 0o660)
            if os.geteuid() == 0 and read_only:
                os.fchown(descriptor, 0, _EXPERIMENT_GID)
            elif os.geteuid() == 0:
                os.fchown(descriptor, _EXPERIMENT_UID, _EXPERIMENT_GID)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if read_only:
            os.fchmod(parent_fd, 0o550)
            if os.geteuid() == 0:
                os.fchown(parent_fd, 0, _EXPERIMENT_GID)

    def _freeze_readonly_directories(self, raw_path: str) -> None:
        descriptor = os.open(self.workspace, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in PurePosixPath(raw_path).parts[:-1]:
                child = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
                os.fchmod(descriptor, 0o550)
                if os.geteuid() == 0:
                    os.fchown(descriptor, 0, _EXPERIMENT_GID)
                os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _reconcile_installing(
        self,
        request: Mapping[str, Any],
        retained: Mapping[str, Any],
        parent_fd: int | None,
        target_name: str,
        partial: Path,
        *,
        canceling: bool = False,
    ) -> dict[str, Any] | None:
        if (
            retained.get("direction") != "stage_input"
            or retained.get("path") != request.get("path")
            or retained.get("overwritePolicy") != request.get("overwritePolicy")
            or retained.get("actualSizeBytes") != request.get("declaredSizeBytes")
            or retained.get("actualSha256") != request.get("contentSha256")
            or type(retained.get("installDevice")) is not int
            or type(retained.get("installInode")) is not int
        ):
            raise _RpcRejectedError(
                "TRANSFER_INDETERMINATE", "installing receipt does not match the request"
            )
        if parent_fd is None:
            matches: list[str] = []
        else:
            try:
                matches = _casefold_entries_at(parent_fd, target_name)
            except OSError:
                if canceling:
                    self._reject_installing_indeterminate(
                        retained, "installing target publication cannot be inspected"
                    )
                raise
        if len(matches) > 1 or (matches and matches[0] != target_name):
            if canceling:
                self._reject_installing_indeterminate(
                    retained, "installing target publication is ambiguous"
                )
            raise _RpcRejectedError("UNSAFE_PATH", "workspace target is ambiguous")
        if matches:
            assert parent_fd is not None
            try:
                target_stat, target_size, target_digest = _inspect_at(parent_fd, target_name)
            except (OSError, _RpcRejectedError):
                if canceling:
                    self._reject_installing_indeterminate(
                        retained, "installing target publication is unsafe"
                    )
                raise
            if (
                target_stat.st_dev == retained["installDevice"]
                and target_stat.st_ino == retained["installInode"]
                and target_size == retained["actualSizeBytes"]
                and target_digest == retained["actualSha256"]
            ):
                completed = {**retained, "ok": True, "state": "completed"}
                os.fsync(parent_fd)
                self._write_receipt(completed)
                return completed
            if canceling:
                self._reject_installing_indeterminate(
                    retained, "installing target differs from retained intent"
                )
            code = (
                "OVERWRITE_FORBIDDEN"
                if request.get("overwritePolicy") == "forbid"
                else "TRANSFER_INDETERMINATE"
            )
            raise _RpcRejectedError(code, "workspace target differs from installing intent")
        try:
            partial_stat = partial.stat(follow_symlinks=False)
            partial_size, partial_digest = _hash_nofollow(partial)
        except FileNotFoundError as error:
            if canceling:
                self._reject_installing_indeterminate(
                    retained, "installing private bytes cannot be reconciled"
                )
            raise _RpcRejectedError(
                "TRANSFER_INDETERMINATE", "installing bytes cannot be reconciled"
            ) from error
        except (OSError, _RpcRejectedError):
            if canceling:
                self._reject_installing_indeterminate(
                    retained, "installing private bytes cannot be reconciled"
                )
            raise
        if (
            partial_stat.st_dev != retained["installDevice"]
            or partial_stat.st_ino != retained["installInode"]
            or partial_size != retained["actualSizeBytes"]
            or partial_digest != retained["actualSha256"]
        ):
            if canceling:
                self._reject_installing_indeterminate(
                    retained, "installing private bytes differ from retained intent"
                )
            raise _RpcRejectedError(
                "TRANSFER_INDETERMINATE", "installing bytes differ from retained intent"
            )
        return None

    def _reject_installing_indeterminate(
        self, retained: Mapping[str, Any], message: str
    ) -> NoReturn:
        result = {**retained, "ok": True, "state": "indeterminate"}
        self._write_receipt(result)
        self._transfers[str(retained["transferRef"])] = result
        raise _RpcRejectedError("TRANSFER_INDETERMINATE", message)

    def _collect(self, request: Mapping[str, Any]) -> tuple[dict[str, object], Path | None]:
        transfer_ref, digest = _identity(request, "transferRef", "requestDigest")
        size, content_digest = _byte_contract(request)
        retained = self._transfers.get(transfer_ref) or self._load_receipt(transfer_ref)
        if retained is not None:
            _same_digest(retained, digest)
            snapshot_path = retained.get("snapshotPath")
            if retained.get("state") == "completed" and isinstance(snapshot_path, str):
                path = Path(snapshot_path)
                actual_size, actual_digest = _hash_nofollow(path)
                if actual_size != size or actual_digest != content_digest:
                    raise _RpcRejectedError(
                        "TRANSFER_BYTES_MISMATCH", "snapshot verification failed"
                    )
                return _public_transfer(retained), path
            if retained.get("state") in {"canceled", "discarded"}:
                raise _RpcRejectedError(
                    "STATE_CONFLICT", "the transfer already reached a terminal state"
                )

        self._validate_transfer_path(request)
        parent_fd, target_name = self._open_parent(str(request["path"]), create=False)
        source_fd = os.open(
            target_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        os.close(parent_fd)
        if not stat.S_ISREG(os.fstat(source_fd).st_mode):
            os.close(source_fd)
            raise _RpcRejectedError("UNSAFE_PATH", "workspace output is not a regular file")
        snapshot_ref = (
            "snapshot-"
            + hashlib.sha256(f"{transfer_ref}:{digest}:{content_digest}".encode()).hexdigest()
        )
        snapshot = self._snapshots / hashlib.sha256(snapshot_ref.encode()).hexdigest()
        descriptor, raw_partial = tempfile.mkstemp(dir=self._snapshots, prefix=".partial-")
        partial = Path(raw_partial)
        try:
            os.chmod(partial, 0o600)
            copied_digest = hashlib.sha256()
            copied_size = 0
            with os.fdopen(descriptor, "wb") as output, os.fdopen(source_fd, "rb") as source:
                while chunk := source.read(_COPY_CHUNK):
                    copied_size += len(chunk)
                    if copied_size > size:
                        raise _RpcRejectedError(
                            "TRANSFER_BYTES_MISMATCH", "workspace output exceeded its contract"
                        )
                    copied_digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if copied_size != size or copied_digest.hexdigest() != content_digest:
                raise _RpcRejectedError(
                    "TRANSFER_BYTES_MISMATCH", "workspace output failed verification"
                )
            os.replace(partial, snapshot)
            _fsync_directory(self._snapshots)
        finally:
            partial.unlink(missing_ok=True)
        result = {
            "ok": True,
            "transferRef": transfer_ref,
            "requestDigest": digest,
            "state": "completed",
            "actualSizeBytes": size,
            "actualSha256": content_digest,
            "snapshotRef": snapshot_ref,
            "snapshotName": snapshot.name,
            "snapshotPath": str(snapshot),
        }
        self._write_receipt(result)
        self._transfers[transfer_ref] = result
        return _public_transfer(result), snapshot

    def _inspect_transfer(self, request: Mapping[str, Any]) -> dict[str, object]:
        transfer_ref = request.get("transferRef")
        retained = self._transfers.get(str(transfer_ref)) or self._load_receipt(str(transfer_ref))
        return {"ok": True, "known": retained is not None, **_public_transfer(retained or {})}

    def _cancel_transfer(self, request: Mapping[str, Any]) -> dict[str, object]:
        transfer_ref, digest = _identity(request, "transferRef", "requestDigest")
        retained = self._transfers.get(transfer_ref) or self._load_receipt(transfer_ref)
        if retained is not None:
            _same_digest(retained, digest)
        partial = self._partials / hashlib.sha256(transfer_ref.encode()).hexdigest()
        if retained is not None and retained.get("state") == "installing":
            raw_path = retained.get("path")
            if not isinstance(raw_path, str):
                raise _RpcRejectedError(
                    "TRANSFER_INDETERMINATE", "installing receipt has no workspace path"
                )
            parent_fd: int | None
            try:
                parent_fd, target_name = self._open_parent(raw_path, create=False)
            except _RpcRejectedError as error:
                if error.code != "NOT_FOUND":
                    self._reject_installing_indeterminate(
                        retained, "installing target publication is ambiguous"
                    )
                parent_fd = None
                target_name = PurePosixPath(raw_path).name
            except OSError:
                self._reject_installing_indeterminate(
                    retained, "installing target publication cannot be inspected"
                )
            try:
                reconciled = self._reconcile_installing(
                    {
                        "path": raw_path,
                        "overwritePolicy": retained.get("overwritePolicy"),
                        "declaredSizeBytes": retained.get("actualSizeBytes"),
                        "contentSha256": retained.get("actualSha256"),
                    },
                    retained,
                    parent_fd,
                    target_name,
                    partial,
                    canceling=True,
                )
            finally:
                if parent_fd is not None:
                    os.close(parent_fd)
            if reconciled is not None:
                self._transfers[transfer_ref] = reconciled
                raise _RpcRejectedError("STATE_CONFLICT", "completed transfer cannot be canceled")
        if retained is not None and retained.get("state") == "completed":
            raise _RpcRejectedError("STATE_CONFLICT", "completed transfer cannot be canceled")
        if retained is not None and retained.get("state") == "indeterminate":
            raise _RpcRejectedError(
                "TRANSFER_INDETERMINATE", "the transfer has indeterminate retained state"
            )
        partial.unlink(missing_ok=True)
        _fsync_directory(self._partials)
        result = {
            "ok": True,
            "transferRef": transfer_ref,
            "requestDigest": digest,
            "state": "canceled",
        }
        self._write_receipt(result)
        self._transfers[transfer_ref] = result
        return result

    def _discard_transfer(self, request: Mapping[str, Any]) -> dict[str, object]:
        transfer_ref = request.get("transferRef")
        if not isinstance(transfer_ref, str):
            raise _RpcRejectedError("INVALID_REQUEST", "transferRef is absent")
        retained = self._transfers.get(transfer_ref) or self._load_receipt(transfer_ref) or {}
        request_digest = request.get("requestDigest")
        if retained and isinstance(request_digest, str):
            _same_digest(retained, request_digest)
        snapshot_path = retained.get("snapshotPath")
        if isinstance(snapshot_path, str):
            candidate = Path(snapshot_path)
            if candidate.parent == self._snapshots:
                candidate.unlink(missing_ok=True)
                _fsync_directory(self._snapshots)
        partial = self._partials / hashlib.sha256(transfer_ref.encode()).hexdigest()
        partial.unlink(missing_ok=True)
        result = {**retained, "ok": True, "transferRef": transfer_ref, "state": "discarded"}
        result.pop("snapshotPath", None)
        result.pop("snapshotName", None)
        self._write_receipt(result)
        self._transfers[transfer_ref] = result
        return _public_transfer(result)

    def _receipt_path(self, transfer_ref: str) -> Path:
        return self._receipts / f"{hashlib.sha256(transfer_ref.encode()).hexdigest()}.json"

    def _load_receipt(self, transfer_ref: str) -> dict[str, Any] | None:
        path = self._receipt_path(transfer_ref)
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return None
        try:
            mode = os.fstat(descriptor).st_mode
            if not stat.S_ISREG(mode):
                raise _RpcRejectedError("UNSAFE_PATH", "transfer receipt is unsafe")
            with os.fdopen(descriptor, "rb") as source:
                raw = source.read(65537)
            descriptor = -1
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _RpcRejectedError(
                "TRANSFER_INDETERMINATE", "transfer receipt is invalid"
            ) from error
        if (
            not isinstance(value, dict)
            or value.get("receiptVersion") != 1
            or value.get("transferRef") != transfer_ref
            or not isinstance(value.get("requestDigest"), str)
            or value.get("state")
            not in {"installing", "completed", "canceled", "discarded", "indeterminate"}
        ):
            raise _RpcRejectedError("TRANSFER_INDETERMINATE", "transfer receipt is invalid")
        snapshot_name = value.get("snapshotName")
        if snapshot_name is not None:
            expected = hashlib.sha256(str(value.get("snapshotRef")).encode()).hexdigest()
            if snapshot_name != expected:
                raise _RpcRejectedError(
                    "TRANSFER_INDETERMINATE", "transfer snapshot identity is invalid"
                )
            value["snapshotPath"] = str(self._snapshots / snapshot_name)
        value["ok"] = True
        return value

    def _write_receipt(self, retained: Mapping[str, Any]) -> None:
        value = {key: item for key, item in retained.items() if key not in {"ok", "snapshotPath"}}
        value["receiptVersion"] = 1
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        descriptor, raw_partial = tempfile.mkstemp(dir=self._receipts, prefix=".partial-")
        partial = Path(raw_partial)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(partial, self._receipt_path(str(retained["transferRef"])))
            _fsync_directory(self._receipts)
        finally:
            partial.unlink(missing_ok=True)

    def _invoke(self, request: Mapping[str, Any]) -> dict[str, object]:
        operation_ref, digest = _identity(request, "operationRef", "requestDigest")
        dispatch_token = _dispatch_token(request)
        frame = request.get("frame")
        if not isinstance(frame, dict) or frame.get("protocol") != "cosmos.workspace/1":
            raise _RpcRejectedError("INVALID_REQUEST", "workspace frame is invalid")
        with self._operation_lock:
            retained = self._operations.get(operation_ref)
            if retained is not None:
                _same_digest(retained, digest)
                return dict(retained)
            fence = self._operation_fences.get(operation_ref)
            if fence is not None:
                _same_digest(fence, digest)
                raise _RpcRejectedError(
                    "OPERATION_INDETERMINATE", "workspace operation dispatch was fenced"
                )
            claim = self._operation_claims.get(operation_ref)
            if claim is not None:
                _same_digest(claim, digest)
                if claim.get("dispatchToken") != dispatch_token:
                    raise _RpcRejectedError(
                        "OPERATION_INDETERMINATE", "workspace dispatch token was superseded"
                    )
            else:
                self._operation_claims[operation_ref] = {
                    "requestDigest": digest,
                    "dispatchToken": dispatch_token,
                }
            action_result = self._execute_workspace_action(frame)
            encoded_result = json.dumps(
                action_result,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            self._operation_side_effects += 1
            exit_code = 0 if action_result.get("ok") is True else 1
            inline_result: dict[str, object] | None
            result_transfer_ref: str | None
            if len(encoded_result) <= _MAX_INLINE_OPERATION_RESULT:
                inline_result = action_result
                result_transfer_ref = None
                output = encoded_result.decode() + "\n"
            else:
                if len(encoded_result) > _MAX_OPERATION_RESULT:
                    raise _RpcRejectedError(
                        "PAYLOAD_TOO_LARGE",
                        "workspace operation result exceeds the capture bound",
                    )
                result_transfer_ref = self._publish_operation_result(operation_ref, encoded_result)
                inline_result = None
                output = ""
            print(
                json.dumps(
                    {
                        "ok": action_result.get("ok") is True,
                        "operationRef": operation_ref,
                        "action": frame.get("action"),
                        "resultBytes": len(encoded_result),
                        "resultTransferRef": result_transfer_ref,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                file=sys.stderr,
                flush=True,
            )
            result = {
                "ok": True,
                "operationRef": operation_ref,
                "requestDigest": digest,
                "state": "succeeded" if exit_code == 0 else "failed",
                "exitCode": exit_code,
                "stdout": output,
                "stderr": "",
                "inlineResult": inline_result,
                "resultTransferRef": result_transfer_ref,
            }
            self._operations[operation_ref] = result
            return dict(result)

    def _execute_workspace_action(self, frame: Mapping[str, Any]) -> dict[str, object]:
        """Execute task-agnostic workspace tree staging and capture."""
        action = frame.get("action")
        if action == "stage_tree":
            return self._stage_workspace_tree(frame)
        if action == "capture_tree":
            return self._capture_workspace_tree(frame)
        raise _RpcRejectedError("INVALID_REQUEST", "workspace action is not registered")

    def _stage_workspace_tree(self, frame: Mapping[str, Any]) -> dict[str, object]:
        payload = _workspace_action_payload(frame)
        base = payload.get("base_manifest")
        if not isinstance(base, dict) or set(base) != {
            "manifest_ref",
            "tree_digest",
            "entries",
        }:
            raise _RpcRejectedError("INVALID_REQUEST", "workspace base manifest is invalid")
        entries = _workspace_tree_entries(base.get("entries"))
        declared_tree_digest = base.get("tree_digest")
        if declared_tree_digest != _workspace_tree_digest(entries):
            raise _RpcRejectedError(
                "DIGEST_MISMATCH", "workspace base tree digest does not match its entries"
            )
        bulk_transfer = payload.get("bulk_transfer")
        if not isinstance(bulk_transfer, bool):
            raise _RpcRejectedError("INVALID_REQUEST", "workspace bulk-transfer marker is invalid")
        inline_items = payload.get("inline_contents") or []
        if not isinstance(inline_items, list) or (bulk_transfer and inline_items):
            raise _RpcRejectedError(
                "INVALID_REQUEST", "workspace inline staging declaration is invalid"
            )
        inline: dict[str, bytes] = {}
        if not bulk_transfer:
            for item in inline_items:
                if not isinstance(item, dict) or set(item) != {"path", "content_b64"}:
                    raise _RpcRejectedError("INVALID_REQUEST", "workspace inline entry is invalid")
                relative = _workspace_relative_path(item.get("path"))
                encoded_content = item.get("content_b64")
                if not isinstance(encoded_content, str):
                    raise _RpcRejectedError(
                        "INVALID_REQUEST", "workspace inline entry is not base64"
                    )
                try:
                    inline[relative] = base64.b64decode(encoded_content, validate=True)
                except (TypeError, ValueError) as error:
                    raise _RpcRejectedError(
                        "INVALID_REQUEST", "workspace inline entry is not base64"
                    ) from error
            if set(inline) != {str(item["path"]) for item in entries}:
                raise _RpcRejectedError(
                    "INVALID_REQUEST", "workspace inline entries do not close over the manifest"
                )

        operation_id = frame.get("operation_id")
        if not isinstance(operation_id, str) or not operation_id:
            raise _RpcRejectedError("INVALID_REQUEST", "workspace operation id is absent")
        bulk_stem = hashlib.sha256(operation_id.encode()).hexdigest()[:24]
        observed: list[dict[str, object]] = []
        for item in entries:
            relative = str(item["path"])
            content = (
                self._read_workspace_file(f".cosmos/bulk-staging/job_{bulk_stem}/inputs/{relative}")
                if bulk_transfer
                else inline[relative]
            )
            if (
                len(content) != item["size"]
                or hashlib.sha256(content).hexdigest() != item["sha256"]
            ):
                raise _RpcRejectedError(
                    "DIGEST_MISMATCH",
                    f"workspace base entry {relative!r} failed integrity",
                )
            self._write_workspace_file(
                f"worktree/{relative}", content, _ENTRY_MODE_BITS[str(item["mode"])]
            )
            actual = self._read_workspace_file(f"worktree/{relative}")
            mode = self._workspace_file_mode(f"worktree/{relative}")
            observed.append(
                {
                    "path": relative,
                    "size": len(actual),
                    "sha256": hashlib.sha256(actual).hexdigest(),
                    "mode": mode,
                }
            )
        staged_tree_digest = _workspace_tree_digest(observed)
        self._write_base_manifest(
            {
                "treeDigest": declared_tree_digest,
                "entries": [
                    {
                        "path": str(item["path"]),
                        "sizeBytes": int(item["size"]),
                        "contentSha256": str(item["sha256"]),
                        "mode": _ENTRY_MODE_BITS[str(item["mode"])],
                    }
                    for item in entries
                ],
            }
        )
        identity = hashlib.sha256(operation_id.encode()).hexdigest()[:24]
        branch, base_commit = self._initialize_attempt_git(identity, declared_tree_digest)
        self._publish_workspace_context()
        return {
            "ok": True,
            "resume_handle": f"workspace-stage://stage_{identity}",
            "staged_tree_digest": staged_tree_digest,
            "manifest_tree_digest": declared_tree_digest,
            "entry_count": len(entries),
            "git_enabled": True,
            "git_branch": branch,
            "git_base_commit": base_commit,
            "git_error": None,
            "restaged": False,
            "observations": [],
        }

    def _initialize_attempt_git(self, identity: str, tree_digest: str) -> tuple[str, str]:
        """Create one isolated SCM base only after the staged tree passed its digest gate."""

        worktree = self.workspace / "worktree"
        branch = f"rc/attempt/{identity}"
        git_dir = worktree / ".git"
        if git_dir.exists():
            self._exclude_platform_context_from_git(worktree)
            retained = self._git(worktree, ["rev-parse", "--verify", "HEAD"]).strip()
            recorded = self._git(
                worktree,
                ["config", "--get", "rc.baseTreeDigest"],
                allow_failure=True,
            ).strip()
            if not retained or recorded != tree_digest:
                raise _RpcRejectedError(
                    "IDENTITY_CONFLICT", "Attempt Git base differs from the staged tree"
                )
            return branch, retained
        self._git(worktree, ["init", "--shared=group", "-b", branch])
        self._exclude_platform_context_from_git(worktree)
        self._git(worktree, ["config", "user.name", "ResearchCosmos Platform"])
        self._git(worktree, ["config", "user.email", "platform@researchcosmos.invalid"])
        self._git(worktree, ["config", "rc.baseTreeDigest", tree_digest])
        self._git(worktree, ["add", "--all"])
        self._git(
            worktree,
            ["commit", "--no-gpg-sign", "-m", "Attempt base"],
            env={
                "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
            },
        )
        commit = self._git(worktree, ["rev-parse", "HEAD"]).strip()
        if os.geteuid() == 0:
            # The control container intentionally runs without CAP_FOWNER.  Once a
            # path is chowned to the experiment user, PID 1 can no longer chmod it.
            # Walk bottom-up and apply mode before ownership so the whole repository
            # is handed over atomically enough for the experiment process to use it.
            for root, _directories, files in os.walk(git_dir, topdown=False):
                for name in files:
                    path = Path(root) / name
                    mode = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
                    os.chmod(path, mode | 0o060)
                    os.chown(path, _EXPERIMENT_UID, _EXPERIMENT_GID)
                root_path = Path(root)
                mode = stat.S_IMODE(os.stat(root_path, follow_symlinks=False).st_mode)
                os.chmod(root_path, mode | 0o2070)
                os.chown(root_path, _EXPERIMENT_UID, _EXPERIMENT_GID)
        return branch, commit

    def _create_project_workspace_snapshot(
        self, request: Mapping[str, Any]
    ) -> tuple[dict[str, object], Path | None]:
        expected = {
            "action",
            "workspaceRef",
            "snapshotRef",
            "requestDigest",
            "generation",
            "maximumFiles",
            "maximumBytes",
        }
        if set(request) != expected:
            raise _RpcRejectedError("INVALID_REQUEST", "Project snapshot request is not closed")
        workspace_ref = request.get("workspaceRef")
        snapshot_ref = request.get("snapshotRef")
        request_digest = request.get("requestDigest")
        generation = request.get("generation")
        maximum_files = request.get("maximumFiles")
        maximum_bytes = request.get("maximumBytes")
        if (
            not isinstance(workspace_ref, str)
            or not isinstance(snapshot_ref, str)
            or not _is_hex_digest(request_digest)
            or type(generation) is not int
            or generation < 1
            or type(maximum_files) is not int
            or not 1 <= maximum_files <= _MAX_CAPTURE_TREE_FILES
            or type(maximum_bytes) is not int
            or not 1 <= maximum_bytes <= _MAX_CAPTURE_TREE_BYTES
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "Project snapshot identity is invalid")
        target = self._project_snapshot_path(snapshot_ref)
        receipt_path = self._project_snapshot_receipt_path(snapshot_ref)
        with self._project_snapshot_lock:
            if target.exists() and receipt_path.exists():
                receipt = _read_json(receipt_path, "Project snapshot receipt")
                if receipt.get("requestDigest") != request_digest:
                    raise _RpcRejectedError(
                        "IDENTITY_CONFLICT", "Project snapshot identity was reused"
                    )
                return {"ok": True, "snapshot": receipt["snapshot"]}, target
            payload = {"max_files": maximum_files, "max_total_bytes": maximum_bytes}
            encoded_payload = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
            captured = self._capture_workspace_tree(
                {
                    "protocol": "cosmos.workspace/1",
                    "action": "capture_tree",
                    "operation_id": f"project-snapshot:{snapshot_ref}",
                    "request_digest": str(request_digest),
                    "frame_digest": hashlib.sha256(encoded_payload.encode()).hexdigest(),
                    "payload": payload,
                }
            )
            entries = list(captured["entries"])
            tree_digest = str(captured["captured_tree_digest"])
            commit = self._commit_project_tree(entries, snapshot_ref, "snapshot", None)
            bundle = {
                "schema": "cosmos.project-workspace-bundle/1",
                "workspaceRef": workspace_ref,
                "snapshotRef": snapshot_ref,
                "treeDigest": tree_digest,
                "entries": entries,
            }
            encoded = json.dumps(
                bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
            if len(encoded) > maximum_bytes:
                raise _RpcRejectedError(
                    "PAYLOAD_TOO_LARGE", "Project snapshot bundle exceeds its byte bound"
                )
            bundle_sha = hashlib.sha256(encoded).hexdigest()
            _atomic_bytes(target, encoded)
            snapshot = {
                "snapshotRef": snapshot_ref,
                "requestDigest": request_digest,
                "workspaceRef": workspace_ref,
                "generation": generation,
                "state": "ready",
                "treeDigest": tree_digest,
                "bundleSha256": bundle_sha,
                "bundleSizeBytes": len(encoded),
                "entryCount": len(entries),
                "baseCommit": commit,
                "createdAt": _timestamp(self._live_now()),
            }
            _atomic_json(
                receipt_path, {"requestDigest": request_digest, "snapshot": snapshot}
            )
            return {"ok": True, "snapshot": snapshot}, target

    def _read_project_workspace_snapshot(
        self, request: Mapping[str, Any]
    ) -> tuple[dict[str, object], Path | None]:
        expected = {
            "action",
            "workspaceRef",
            "snapshotRef",
            "requestDigest",
            "generation",
            "authorizedMaxSizeBytes",
        }
        if set(request) != expected:
            raise _RpcRejectedError("INVALID_REQUEST", "Project snapshot read is not closed")
        snapshot_ref = request.get("snapshotRef")
        if not isinstance(snapshot_ref, str):
            raise _RpcRejectedError("INVALID_REQUEST", "Project snapshot ref is invalid")
        target = self._project_snapshot_path(snapshot_ref)
        receipt = _read_json(
            self._project_snapshot_receipt_path(snapshot_ref), "Project snapshot receipt"
        )
        snapshot = receipt.get("snapshot")
        if (
            not isinstance(snapshot, dict)
            or snapshot.get("workspaceRef") != request.get("workspaceRef")
            or snapshot.get("requestDigest") != request.get("requestDigest")
            or snapshot.get("generation") != request.get("generation")
            or not target.is_file()
        ):
            raise _RpcRejectedError("STALE_BINDING", "Project snapshot binding differs")
        maximum = request.get("authorizedMaxSizeBytes")
        if type(maximum) is not int or target.stat().st_size > maximum:
            raise _RpcRejectedError("PAYLOAD_TOO_LARGE", "Project snapshot exceeds read bound")
        return {"ok": True, "snapshot": snapshot}, target

    def _import_project_workspace_revision(
        self, request: Mapping[str, Any], body: Path | None
    ) -> dict[str, object]:
        expected = {
            "action",
            "workspaceRef",
            "importRef",
            "requestDigest",
            "generation",
            "sourceRevisionRef",
            "expectedTreeDigest",
            "contentSha256",
            "declaredSizeBytes",
            "authorizedMaxSizeBytes",
            "baseCommit",
            "target",
            "expectedBaseTreeDigest",
        }
        if set(request) != expected or body is None:
            raise _RpcRejectedError("INVALID_REQUEST", "Project import request is not closed")
        import_ref = request.get("importRef")
        request_digest = request.get("requestDigest")
        expected_tree = request.get("expectedTreeDigest")
        target_kind = request.get("target")
        if (
            not isinstance(import_ref, str)
            or not _is_hex_digest(request_digest)
            or not _is_hex_digest(expected_tree)
            or target_kind not in {"retained", "working"}
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "Project import identity is invalid")
        receipt_path = self._project_import_receipt_path(import_ref)
        with self._project_snapshot_lock:
            if receipt_path.exists():
                retained = _read_json(receipt_path, "Project import receipt")
                if retained.get("requestDigest") != request_digest:
                    raise _RpcRejectedError(
                        "IDENTITY_CONFLICT", "Project import identity was reused"
                    )
                return {"ok": True, "receipt": retained["receipt"]}
            declared = request.get("declaredSizeBytes")
            maximum = request.get("authorizedMaxSizeBytes")
            if (
                type(declared) is not int
                or type(maximum) is not int
                or declared != body.stat().st_size
                or declared > maximum
            ):
                raise _RpcRejectedError(
                    "DIGEST_MISMATCH", "Project import size differs from declaration"
                )
            if _hash_file(body)[1] != request.get("contentSha256"):
                raise _RpcRejectedError(
                    "DIGEST_MISMATCH", "Project import content digest differs"
                )
            try:
                bundle = json.loads(body.read_bytes())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise _RpcRejectedError(
                    "MATERIALIZATION_FAILED", "Project import bundle is invalid"
                ) from error
            if (
                not isinstance(bundle, dict)
                or bundle.get("schema") != "cosmos.project-workspace-bundle/1"
                or not isinstance(bundle.get("entries"), list)
            ):
                raise _RpcRejectedError(
                    "MATERIALIZATION_FAILED", "Project import bundle is invalid"
                )
            entries = self._validate_project_bundle_entries(bundle["entries"])
            tree_digest = _workspace_tree_digest(
                [
                    {key: item[key] for key in ("path", "size", "sha256", "mode")}
                    for item in entries
                ]
            )
            if tree_digest != expected_tree or bundle.get("treeDigest") != expected_tree:
                raise _RpcRejectedError(
                    "DIGEST_MISMATCH", "Project import tree digest differs"
                )
            if target_kind == "working":
                expected_base = request.get("expectedBaseTreeDigest")
                if not _is_hex_digest(expected_base):
                    raise _RpcRejectedError(
                        "INVALID_REQUEST", "Project working import has no exact base"
                    )
                capture_payload = {
                    "max_files": _MAX_CAPTURE_TREE_FILES,
                    "max_total_bytes": _MAX_CAPTURE_TREE_BYTES,
                }
                encoded_capture_payload = json.dumps(
                    capture_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                current = self._capture_workspace_tree(
                    {
                        "protocol": "cosmos.workspace/1",
                        "action": "capture_tree",
                        "operation_id": f"project-working-base:{import_ref}",
                        "request_digest": str(request_digest),
                        "frame_digest": hashlib.sha256(
                            encoded_capture_payload.encode()
                        ).hexdigest(),
                        "payload": capture_payload,
                    }
                )
                if current["captured_tree_digest"] != expected_base:
                    raise _RpcRejectedError(
                        "STALE_BINDING", "Project working copy changed after its snapshot"
                    )
            elif request.get("expectedBaseTreeDigest") is not None:
                raise _RpcRejectedError(
                    "INVALID_REQUEST", "retained import cannot carry an exact working base"
                )
            parent = request.get("baseCommit")
            commit = self._commit_project_tree(
                entries,
                import_ref,
                str(target_kind),
                parent if isinstance(parent, str) and parent else None,
            )
            if target_kind == "working":
                receipt = {
                    "importRef": import_ref,
                    "sourceRevisionRef": request.get("sourceRevisionRef"),
                    "retainedCheckoutRef": "project/worktree",
                    "resultCommit": commit,
                    "materializedTreeDigest": tree_digest,
                }
                _atomic_json(
                    receipt_path, {"requestDigest": request_digest, "receipt": receipt}
                )
                return {"ok": True, "receipt": receipt}
            retained_ref = f"checkout_{hashlib.sha256(import_ref.encode()).hexdigest()[:24]}"
            retained_branch = (
                f"rc/retained/{hashlib.sha256(import_ref.encode()).hexdigest()[:24]}"
            )
            destination = self.workspace / "retained" / retained_ref
            partial = self.workspace / "retained" / f".{retained_ref}.partial"
            if not destination.exists():
                if partial.exists():
                    shutil.rmtree(partial)
                self._git(
                    self.workspace / "worktree",
                    ["worktree", "add", str(partial), retained_branch],
                )
                self._git(
                    self.workspace / "worktree",
                    ["worktree", "move", str(partial), str(destination)],
                )
            receipt = {
                "importRef": import_ref,
                "sourceRevisionRef": request.get("sourceRevisionRef"),
                "retainedCheckoutRef": retained_ref,
                "resultCommit": commit,
                "materializedTreeDigest": tree_digest,
            }
            _atomic_json(
                receipt_path, {"requestDigest": request_digest, "receipt": receipt}
            )
            return {"ok": True, "receipt": receipt}

    def _validate_project_bundle_entries(
        self, raw_entries: list[Any]
    ) -> list[dict[str, object]]:
        if len(raw_entries) > _MAX_CAPTURE_TREE_FILES:
            raise _RpcRejectedError("PAYLOAD_TOO_LARGE", "Project bundle has too many files")
        entries: list[dict[str, object]] = []
        total = 0
        for raw in raw_entries:
            if not isinstance(raw, dict) or set(raw) != {
                "path",
                "size",
                "sha256",
                "mode",
                "content_b64",
            }:
                raise _RpcRejectedError(
                    "MATERIALIZATION_FAILED", "Project bundle entry is invalid"
                )
            descriptor = _workspace_tree_entries(
                [{key: raw.get(key) for key in ("path", "size", "sha256", "mode")}]
            )[0]
            encoded = raw.get("content_b64")
            if not isinstance(encoded, str):
                raise _RpcRejectedError(
                    "MATERIALIZATION_FAILED", "Project bundle bytes are invalid"
                )
            try:
                content = base64.b64decode(encoded, validate=True)
            except ValueError as error:
                raise _RpcRejectedError(
                    "MATERIALIZATION_FAILED", "Project bundle bytes are invalid"
                ) from error
            if (
                len(content) != descriptor["size"]
                or hashlib.sha256(content).hexdigest() != descriptor["sha256"]
            ):
                raise _RpcRejectedError(
                    "DIGEST_MISMATCH", "Project bundle entry digest differs"
                )
            total += len(content)
            if total > _MAX_CAPTURE_TREE_BYTES:
                raise _RpcRejectedError("PAYLOAD_TOO_LARGE", "Project bundle exceeds byte bound")
            entries.append({**descriptor, "content_b64": encoded})
        paths = [str(item["path"]) for item in entries]
        if len(paths) != len(set(paths)):
            raise _RpcRejectedError("MATERIALIZATION_FAILED", "Project bundle repeats a path")
        return entries

    def _commit_project_tree(
        self,
        entries: list[dict[str, object]],
        identity: str,
        kind: str,
        requested_parent: str | None,
    ) -> str:
        worktree = self.workspace / "worktree"
        if not (worktree / ".git").exists():
            self._git(worktree, ["init", "--shared=group", "-b", "rc/project"])
            self._git(worktree, ["config", "user.name", "ResearchCosmos Platform"])
            self._git(worktree, ["config", "user.email", "platform@researchcosmos.invalid"])
        self._exclude_platform_context_from_git(worktree)
        index = self._project_snapshots / f".index-{hashlib.sha256(identity.encode()).hexdigest()}"
        index.unlink(missing_ok=True)
        environment = {"GIT_INDEX_FILE": str(index)}
        try:
            for item in entries:
                content = base64.b64decode(str(item["content_b64"]), validate=True)
                blob = self._git(
                    worktree,
                    ["hash-object", "-w", "--stdin"],
                    input_bytes=content,
                ).strip()
                mode = "100755" if item["mode"] == "executable" else "100644"
                self._git(
                    worktree,
                    [
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        f"{mode},{blob},{item['path']}",
                    ],
                    env=environment,
                )
            tree = self._git(worktree, ["write-tree"], env=environment).strip()
            parent = requested_parent
            if parent is not None:
                verified = self._git(
                    worktree,
                    ["rev-parse", "--verify", f"{parent}^{{commit}}"],
                    allow_failure=True,
                ).strip()
                if verified != parent:
                    raise _RpcRejectedError("STALE_BINDING", "Project base commit is unavailable")
            elif kind in {"snapshot", "working"}:
                parent = self._git(
                    worktree,
                    ["rev-parse", "--verify", "refs/heads/rc/project^{commit}"],
                    allow_failure=True,
                ).strip() or None
            command = ["commit-tree", tree, "-m", f"Project {kind} {identity}"]
            if parent is not None:
                command.extend(["-p", parent])
            commit = self._git(
                worktree,
                command,
                env={
                    **environment,
                    "GIT_AUTHOR_NAME": "ResearchCosmos Platform",
                    "GIT_AUTHOR_EMAIL": "platform@researchcosmos.invalid",
                    "GIT_COMMITTER_NAME": "ResearchCosmos Platform",
                    "GIT_COMMITTER_EMAIL": "platform@researchcosmos.invalid",
                    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
                    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
                },
            ).strip()
            if kind == "snapshot":
                ref = "refs/rc/project/snapshots"
            elif kind == "working":
                ref = "refs/heads/rc/project"
            else:
                ref = f"refs/heads/rc/retained/{hashlib.sha256(identity.encode()).hexdigest()[:24]}"
            self._git(worktree, ["update-ref", ref, commit])
            if kind in {"snapshot", "working"}:
                self._git(worktree, ["update-ref", "refs/heads/rc/project", commit])
                self._git(worktree, ["symbolic-ref", "HEAD", "refs/heads/rc/project"])
                if kind == "working":
                    self._git(worktree, ["reset", "--hard", commit])
                else:
                    self._git(worktree, ["read-tree", commit])
            return commit
        finally:
            index.unlink(missing_ok=True)

    def _git(
        self,
        worktree: Path,
        arguments: list[str],
        *,
        env: Mapping[str, str] | None = None,
        input_bytes: bytes | None = None,
        allow_failure: bool = False,
    ) -> str:
        environment = os.environ.copy()
        if env is not None:
            environment.update(env)
        result = subprocess.run(
            ["git", "-c", f"safe.directory={worktree}", *arguments],
            cwd=worktree,
            env=environment,
            input=input_bytes,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 and not allow_failure:
            raise _RpcRejectedError("MATERIALIZATION_FAILED", "Git workspace operation failed")
        return result.stdout.decode("utf-8", errors="strict")

    @staticmethod
    def _exclude_platform_context_from_git(worktree: Path) -> None:
        exclude = worktree / ".git" / "info" / "exclude"
        retained = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
        if ".kcs/" not in retained.splitlines():
            exclude.parent.mkdir(parents=True, exist_ok=True)
            exclude.write_text(retained.rstrip("\n") + "\n.kcs/\n", encoding="utf-8")

    def _project_snapshot_path(self, snapshot_ref: str) -> Path:
        return self._project_snapshots / (
            f"{hashlib.sha256(snapshot_ref.encode()).hexdigest()}.bundle"
        )

    def _project_snapshot_receipt_path(self, snapshot_ref: str) -> Path:
        return self._project_snapshots / (
            f"{hashlib.sha256(snapshot_ref.encode()).hexdigest()}.json"
        )

    def _project_import_receipt_path(self, import_ref: str) -> Path:
        return self._project_import_receipts / (
            f"{hashlib.sha256(import_ref.encode()).hexdigest()}.json"
        )

    def _capture_workspace_tree(self, frame: Mapping[str, Any]) -> dict[str, object]:
        payload = _workspace_action_payload(frame)
        max_files = payload.get("max_files", _MAX_CAPTURE_TREE_FILES)
        max_total_bytes = payload.get("max_total_bytes", _MAX_CAPTURE_TREE_BYTES)
        if (
            type(max_files) is not int
            or not 1 <= max_files <= _MAX_CAPTURE_TREE_FILES
            or type(max_total_bytes) is not int
            or not 1 <= max_total_bytes <= _MAX_CAPTURE_TREE_BYTES
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "workspace capture bounds are invalid")
        worktree = self.workspace / "worktree"
        entries: list[dict[str, object]] = []
        total = 0
        if worktree.is_dir():
            for root, directories, files in os.walk(worktree, followlinks=False):
                root_path = Path(root)
                relative_root = root_path.relative_to(worktree)
                if relative_root == Path("."):
                    directories[:] = [
                        name
                        for name in directories
                        if name not in {".git", ".cosmos", ".kcs"}
                    ]
                for name in sorted(files):
                    path = root_path / name
                    relative = path.relative_to(worktree).as_posix()
                    if path.is_symlink():
                        raise _RpcRejectedError(
                            "UNSAFE_PATH",
                            f"workspace capture found an unsupported symlink at {relative!r}",
                        )
                    if len(entries) >= max_files:
                        raise _RpcRejectedError(
                            "PAYLOAD_TOO_LARGE", "workspace capture exceeds its file bound"
                        )
                    content = self._read_workspace_file(f"worktree/{relative}")
                    total += len(content)
                    if total > max_total_bytes:
                        raise _RpcRejectedError(
                            "PAYLOAD_TOO_LARGE", "workspace capture exceeds its byte bound"
                        )
                    entries.append(
                        {
                            "path": relative,
                            "size": len(content),
                            "sha256": hashlib.sha256(content).hexdigest(),
                            "mode": self._workspace_file_mode(f"worktree/{relative}"),
                            "content_b64": base64.b64encode(content).decode(),
                        }
                    )
        entries.sort(key=lambda item: str(item["path"]))
        captured_tree_digest = _workspace_tree_digest(
            [{key: item[key] for key in ("path", "size", "sha256", "mode")} for item in entries]
        )
        operation_id = frame.get("operation_id")
        if not isinstance(operation_id, str) or not operation_id:
            raise _RpcRejectedError("INVALID_REQUEST", "workspace operation id is absent")
        identity = hashlib.sha256(operation_id.encode()).hexdigest()[:24]
        return {
            "ok": True,
            "resume_handle": f"workspace-capture://capture_{identity}",
            "entries": entries,
            "entry_count": len(entries),
            "total_bytes": total,
            "captured_tree_digest": captured_tree_digest,
            "git": {
                "enabled": False,
                "status_b64": None,
                "status_truncated": False,
            },
            "observations": [],
        }

    def _write_base_manifest(self, manifest: Mapping[str, Any]) -> None:
        tree_digest = manifest.get("treeDigest")
        if not _is_hex_digest(tree_digest):
            raise _RpcRejectedError("INVALID_REQUEST", "workspace base digest is invalid")
        payload = dict(manifest)
        _atomic_json(self._base_manifest_path(str(tree_digest)), payload)
        _atomic_json(self._base_manifests / "latest.json", payload)

    def _bind_latest_base_manifest(self, base_manifest_digest: str) -> None:
        latest = _read_json(self._base_manifests / "latest.json", "workspace base manifest")
        target = self._base_manifest_path(base_manifest_digest)
        if target.exists():
            retained = _read_json(target, "workspace base manifest")
            if retained != latest:
                raise _RpcRejectedError(
                    "IDENTITY_CONFLICT", "base manifest digest was bound to another tree"
                )
            return
        _atomic_json(target, latest)

    def _base_manifest_path(self, digest: str) -> Path:
        if not _is_hex_digest(digest):
            raise _RpcRejectedError("INVALID_REQUEST", "workspace base digest is invalid")
        return self._base_manifests / f"{digest}.json"

    def _create_live_workspace_snapshot(
        self, request: Mapping[str, Any]
    ) -> dict[str, object]:
        expected = {
            "action",
            "snapshotRef",
            "requestDigest",
            "jobRef",
            "jobUid",
            "podUid",
            "generation",
            "baseManifestDigest",
            "ttlSeconds",
            "maximumEntries",
            "maximumBytes",
        }
        if set(request) != expected:
            raise _RpcRejectedError("INVALID_REQUEST", "live snapshot request is not closed")
        identity = self._live_snapshot_identity(request)
        ttl = request.get("ttlSeconds")
        maximum_entries = request.get("maximumEntries")
        maximum_bytes = request.get("maximumBytes")
        if (
            type(ttl) is not int
            or not 1 <= ttl <= 300
            or type(maximum_entries) is not int
            or not 1 <= maximum_entries <= _MAX_LIVE_SNAPSHOT_ENTRIES
            or type(maximum_bytes) is not int
            or not 1 <= maximum_bytes <= _MAX_LIVE_SNAPSHOT_BYTES
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "live snapshot bounds are invalid")
        base_manifest = _read_json(
            self._base_manifest_path(identity["baseManifestDigest"]),
            "workspace base manifest",
        )
        target = self._live_snapshot_path(identity["snapshotRef"])
        with self._live_snapshot_lock:
            if target.exists():
                retained = self._load_live_snapshot(identity["snapshotRef"])
                self._match_live_snapshot(retained, identity)
                self._require_live_snapshot_readable(retained)
                return {"ok": True, "snapshot": self._public_live_snapshot(retained)}
            sequence = self._next_live_snapshot_sequence()
            created_at = self._live_now()
            expires_at = created_at + timedelta(seconds=ttl)
            partial = Path(
                tempfile.mkdtemp(dir=self._live_snapshots, prefix=".partial-live-")
            )
            os.chmod(partial, 0o700)
            blobs = _private_directory(partial, "blobs")
            try:
                scan = self._freeze_live_tree(
                    blobs,
                    maximum_entries=maximum_entries,
                    maximum_bytes=maximum_bytes,
                )
                public_without_digest = {
                    **identity,
                    "sequence": sequence,
                    "state": "ready",
                    "entries": scan["entries"],
                    "truncated": scan["truncated"],
                    "omissions": scan["omissions"],
                    "createdAt": _timestamp(created_at),
                    "expiresAt": _timestamp(expires_at),
                }
                digest_payload = {
                    key: value
                    for key, value in public_without_digest.items()
                    if key != "state"
                }
                snapshot_digest = hashlib.sha256(rfc8785.dumps(digest_payload)).hexdigest()
                public = {
                    **public_without_digest,
                    "snapshotDigest": snapshot_digest,
                    "observedAt": _timestamp(created_at),
                }
                manifest = {
                    "manifestVersion": 1,
                    "snapshot": public,
                    "observedPaths": scan["observedPaths"],
                    "baseManifest": base_manifest,
                }
                _atomic_json(partial / "manifest.json", manifest)
                os.replace(partial, target)
                _fsync_directory(self._live_snapshots)
            finally:
                if partial.exists():
                    shutil.rmtree(partial)
        return {"ok": True, "snapshot": public}

    def _inspect_live_workspace_snapshot(
        self, request: Mapping[str, Any]
    ) -> dict[str, object]:
        identity = self._live_existing_identity(request, "inspectLiveWorkspaceSnapshot")
        with self._live_snapshot_lock:
            retained = self._load_live_snapshot(identity["snapshotRef"])
            self._match_live_snapshot(retained, identity)
            self._require_live_snapshot_readable(retained)
            return {"ok": True, "snapshot": self._public_live_snapshot(retained)}

    def _release_live_workspace_snapshot(
        self, request: Mapping[str, Any]
    ) -> dict[str, object]:
        identity = self._live_existing_identity(request, "releaseLiveWorkspaceSnapshot")
        with self._live_snapshot_lock:
            retained = self._load_live_snapshot(identity["snapshotRef"])
            self._match_live_snapshot(retained, identity)
            self._require_live_snapshot_readable(retained)
            public = dict(retained["snapshot"])
            public["state"] = "released"
            public["observedAt"] = _timestamp(self._live_now())
            retained["snapshot"] = public
            blobs = self._live_snapshot_path(identity["snapshotRef"]) / "blobs"
            if blobs.exists():
                shutil.rmtree(blobs)
            _atomic_json(
                self._live_snapshot_path(identity["snapshotRef"]) / "manifest.json",
                retained,
            )
            return {"ok": True, "snapshot": public}

    def _read_live_workspace_content(
        self, request: Mapping[str, Any]
    ) -> tuple[dict[str, object], Path | None]:
        expected = {
            "action",
            "snapshotRef",
            "requestDigest",
            "jobRef",
            "jobUid",
            "podUid",
            "generation",
            "baseManifestDigest",
            "path",
            "offset",
            "limitBytes",
        }
        if set(request) != expected:
            raise _RpcRejectedError("INVALID_REQUEST", "live content request is not closed")
        identity = self._live_snapshot_identity(request)
        relative = request.get("path")
        try:
            validate_safe_relative_path(str(relative))
        except (TypeError, ValueError) as error:
            raise _RpcRejectedError("UNSAFE_PATH", "live content path is unsafe") from error
        offset, limit = request.get("offset"), request.get("limitBytes")
        if (
            type(offset) is not int
            or offset < 0
            or type(limit) is not int
            or not 1 <= limit <= _MAX_LIVE_CONTENT_RANGE
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "live content range is invalid")
        with self._live_snapshot_lock:
            retained = self._load_live_snapshot(identity["snapshotRef"])
            self._match_live_snapshot(retained, identity)
            self._require_live_snapshot_readable(retained)
            public = retained["snapshot"]
            entry = next(
                (item for item in public["entries"] if item["path"] == relative), None
            )
            if not isinstance(entry, dict):
                raise _RpcRejectedError("NOT_FOUND", "snapshot entry was not found")
            if entry.get("kind") != "file" or not _is_hex_digest(
                entry.get("contentSha256")
            ):
                raise _RpcRejectedError("UNSAFE_PATH", "snapshot entry is not a file")
            total = int(entry["sizeBytes"])
            if offset > total:
                raise _RpcRejectedError("INVALID_REQUEST", "live content offset exceeds file")
            blob = (
                self._live_snapshot_path(identity["snapshotRef"])
                / "blobs"
                / str(entry["contentSha256"])
            )
            if not blob.is_file() or blob.is_symlink():
                raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", "snapshot blob is unavailable")
            descriptor, raw = tempfile.mkstemp(dir=self._control_state, prefix=".live-range-")
            ranged = Path(raw)
            try:
                os.fchmod(descriptor, 0o600)
                with blob.open("rb") as source, os.fdopen(descriptor, "wb") as output:
                    source.seek(offset)
                    content = source.read(limit)
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                end = offset + len(content)
                return (
                    {
                        "ok": True,
                        "snapshotDigest": public["snapshotDigest"],
                        "contentSha256": entry["contentSha256"],
                        "sequence": public["sequence"],
                        "offset": offset,
                        "endOffset": end,
                        "totalSize": total,
                        "sizeBytes": len(content),
                    },
                    ranged if content else None,
                )
            finally:
                if ranged.exists() and ranged.stat().st_size == 0:
                    ranged.unlink(missing_ok=True)

    def _get_live_workspace_diff(self, request: Mapping[str, Any]) -> dict[str, object]:
        expected = {
            "action",
            "snapshotRef",
            "requestDigest",
            "jobRef",
            "jobUid",
            "podUid",
            "generation",
            "baseManifestDigest",
            "pageToken",
            "pageSize",
        }
        if set(request) != expected:
            raise _RpcRejectedError("INVALID_REQUEST", "live diff request is not closed")
        identity = self._live_snapshot_identity(request)
        page_size = request.get("pageSize")
        if type(page_size) is not int or not 1 <= page_size <= 200:
            raise _RpcRejectedError("INVALID_REQUEST", "live diff page size is invalid")
        with self._live_snapshot_lock:
            retained = self._load_live_snapshot(identity["snapshotRef"])
            self._match_live_snapshot(retained, identity)
            self._require_live_snapshot_readable(retained)
            public = retained["snapshot"]
            items = _live_diff_items(retained)
            offset = _decode_live_page_token(
                request.get("pageToken"), str(public["snapshotDigest"])
            )
            if offset > len(items):
                raise _RpcRejectedError("INVALID_PAGE_TOKEN", "live diff page is invalid")
            selected = items[offset : offset + page_size]
            next_offset = offset + len(selected)
            next_token = (
                _encode_live_page_token(str(public["snapshotDigest"]), next_offset)
                if next_offset < len(items)
                else None
            )
            return {
                "ok": True,
                "page": {
                    "snapshotRef": public["snapshotRef"],
                    "snapshotDigest": public["snapshotDigest"],
                    "sequence": public["sequence"],
                    "items": selected,
                    "nextPageToken": next_token,
                    "observedAt": _timestamp(self._live_now()),
                },
            }

    def _freeze_live_tree(
        self,
        blobs: Path,
        *,
        maximum_entries: int,
        maximum_bytes: int,
    ) -> dict[str, Any]:
        worktree = self.workspace / "worktree"
        entries: list[dict[str, Any]] = []
        omissions: list[dict[str, str]] = []
        observed: list[str] = []
        total = 0
        if not worktree.exists():
            return {
                "entries": entries,
                "omissions": omissions,
                "observedPaths": observed,
                "truncated": False,
            }
        root_fd = os.open(
            worktree,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        stack: list[tuple[str, int]] = [("", root_fd)]
        try:
            while stack:
                prefix, directory_fd = stack.pop()
                try:
                    names = sorted(os.listdir(directory_fd))
                    folded: dict[str, list[str]] = {}
                    for name in names:
                        folded.setdefault(unicodedata.normalize("NFC", name).casefold(), []).append(
                            name
                        )
                    collision = {
                        name for group in folded.values() if len(group) > 1 for name in group
                    }
                    pending_directories: list[tuple[str, int]] = []
                    for name in names:
                        if not prefix and name in {".git", ".cosmos", ".kcs"}:
                            continue
                        relative = f"{prefix}/{name}" if prefix else name
                        try:
                            validate_safe_relative_path(relative)
                        except ValueError as error:
                            raise _RpcRejectedError(
                                "UNSAFE_PATH", "worktree contains an unrepresentable path"
                            ) from error
                        observed.append(relative)
                        if name in collision:
                            _append_live_omission(omissions, relative, "unsafe_path")
                            continue
                        try:
                            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        except OSError:
                            _append_live_omission(omissions, relative, "unreadable")
                            continue
                        if len(entries) >= maximum_entries:
                            _append_live_omission(omissions, relative, "entry_limit")
                            continue
                        mode = stat.S_IMODE(before.st_mode)
                        if stat.S_ISLNK(before.st_mode):
                            try:
                                target = os.readlink(name, dir_fd=directory_fd)
                            except OSError:
                                _append_live_omission(omissions, relative, "unreadable")
                                continue
                            if not target or len(target.encode("utf-8")) > 4096:
                                _append_live_omission(omissions, relative, "unsafe_path")
                                continue
                            entries.append(
                                {
                                    "path": relative,
                                    "kind": "symlink",
                                    "mode": mode,
                                    "sizeBytes": len(target.encode("utf-8")),
                                    "contentSha256": None,
                                    "symlinkTarget": target,
                                }
                            )
                            continue
                        if stat.S_ISDIR(before.st_mode):
                            try:
                                child = os.open(
                                    name,
                                    os.O_RDONLY
                                    | getattr(os, "O_DIRECTORY", 0)
                                    | getattr(os, "O_NOFOLLOW", 0),
                                    dir_fd=directory_fd,
                                )
                            except OSError:
                                _append_live_omission(omissions, relative, "unreadable")
                                continue
                            entries.append(
                                {
                                    "path": relative,
                                    "kind": "directory",
                                    "mode": mode,
                                    "sizeBytes": 0,
                                    "contentSha256": None,
                                    "symlinkTarget": None,
                                }
                            )
                            pending_directories.append((relative, child))
                            continue
                        if not stat.S_ISREG(before.st_mode):
                            _append_live_omission(omissions, relative, "unsafe_path")
                            continue
                        if before.st_size > maximum_bytes - total:
                            _append_live_omission(omissions, relative, "byte_limit")
                            continue
                        descriptor = -1
                        try:
                            descriptor = os.open(
                                name,
                                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=directory_fd,
                            )
                            opened = os.fstat(descriptor)
                            content = bytearray()
                            while chunk := os.read(descriptor, min(_COPY_CHUNK, maximum_bytes + 1)):
                                content.extend(chunk)
                                if len(content) > maximum_bytes - total:
                                    break
                            after = os.fstat(descriptor)
                        except OSError:
                            _append_live_omission(omissions, relative, "unreadable")
                            continue
                        finally:
                            if descriptor >= 0:
                                os.close(descriptor)
                        if len(content) > maximum_bytes - total:
                            _append_live_omission(omissions, relative, "byte_limit")
                            continue
                        if (
                            opened.st_dev,
                            opened.st_ino,
                            opened.st_size,
                            opened.st_mtime_ns,
                        ) != (
                            after.st_dev,
                            after.st_ino,
                            after.st_size,
                            after.st_mtime_ns,
                        ) or len(content) != after.st_size:
                            _append_live_omission(
                                omissions, relative, "changed_during_snapshot"
                            )
                            continue
                        digest = hashlib.sha256(content).hexdigest()
                        blob = blobs / digest
                        if not blob.exists():
                            with blob.open("xb") as output:
                                os.chmod(blob, 0o600, follow_symlinks=False)
                                output.write(content)
                                output.flush()
                                os.fsync(output.fileno())
                        total += len(content)
                        entries.append(
                            {
                                "path": relative,
                                "kind": "file",
                                "mode": mode,
                                "sizeBytes": len(content),
                                "contentSha256": digest,
                                "symlinkTarget": None,
                            }
                        )
                    stack.extend(reversed(pending_directories))
                finally:
                    os.close(directory_fd)
        finally:
            for _prefix, descriptor in stack:
                os.close(descriptor)
        entries.sort(key=lambda item: str(item["path"]))
        omissions.sort(key=lambda item: str(item["path"]))
        return {
            "entries": entries,
            "omissions": omissions,
            "observedPaths": sorted(observed),
            "truncated": bool(omissions),
        }

    def _live_snapshot_identity(self, request: Mapping[str, Any]) -> dict[str, Any]:
        result = {
            key: request.get(key)
            for key in (
                "snapshotRef",
                "requestDigest",
                "jobRef",
                "jobUid",
                "podUid",
                "generation",
                "baseManifestDigest",
            )
        }
        if (
            any(not isinstance(result[key], str) or not result[key] for key in (
                "snapshotRef",
                "jobRef",
                "jobUid",
                "podUid",
            ))
            or not _is_hex_digest(result["requestDigest"])
            or not _is_hex_digest(result["baseManifestDigest"])
            or type(result["generation"]) is not int
            or result["generation"] < 1
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "live snapshot identity is invalid")
        return result

    def _live_existing_identity(
        self, request: Mapping[str, Any], action: str
    ) -> dict[str, Any]:
        expected = {
            "action",
            "snapshotRef",
            "requestDigest",
            "jobRef",
            "jobUid",
            "podUid",
            "generation",
            "baseManifestDigest",
        }
        if set(request) != expected or request.get("action") != action:
            raise _RpcRejectedError("INVALID_REQUEST", "live snapshot request is not closed")
        return self._live_snapshot_identity(request)

    def _live_snapshot_path(self, snapshot_ref: str) -> Path:
        return self._live_snapshots / hashlib.sha256(snapshot_ref.encode()).hexdigest()

    def _load_live_snapshot(self, snapshot_ref: str) -> dict[str, Any]:
        path = self._live_snapshot_path(snapshot_ref) / "manifest.json"
        if not path.is_file() or path.is_symlink():
            raise _RpcRejectedError("NOT_FOUND", "live snapshot was not found")
        value = _read_json(path, "live workspace snapshot")
        if (
            value.get("manifestVersion") != 1
            or not isinstance(value.get("snapshot"), dict)
            or value["snapshot"].get("snapshotRef") != snapshot_ref
            or not isinstance(value.get("observedPaths"), list)
            or not isinstance(value.get("baseManifest"), dict)
        ):
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE", "live snapshot manifest is malformed"
            )
        return value

    @staticmethod
    def _match_live_snapshot(
        retained: Mapping[str, Any], identity: Mapping[str, Any]
    ) -> None:
        snapshot = retained["snapshot"]
        if any(snapshot.get(key) != value for key, value in identity.items()):
            raise _RpcRejectedError("IDENTITY_CONFLICT", "live snapshot identity differs")

    def _require_live_snapshot_readable(self, retained: Mapping[str, Any]) -> None:
        snapshot = retained["snapshot"]
        if snapshot.get("state") == "released":
            raise _RpcRejectedError("STATE_CONFLICT", "live snapshot has been released")
        expires_at = snapshot.get("expiresAt")
        if not isinstance(expires_at, str) or self._live_now() >= _parse_timestamp(expires_at):
            raise _RpcRejectedError("LIVE_SNAPSHOT_EXPIRED", "live snapshot has expired")
        if snapshot.get("state") != "ready":
            raise _RpcRejectedError("STATE_CONFLICT", "live snapshot is not readable")

    def _public_live_snapshot(self, retained: Mapping[str, Any]) -> dict[str, Any]:
        public = dict(retained["snapshot"])
        public["observedAt"] = _timestamp(self._live_now())
        return public

    def _next_live_snapshot_sequence(self) -> int:
        path = self._live_snapshots / "sequence"
        try:
            retained = int(path.read_text(encoding="ascii")) if path.exists() else 0
        except (OSError, ValueError) as error:
            raise _RpcRejectedError(
                "DEPENDENCY_UNAVAILABLE", "live snapshot sequence is invalid"
            ) from error
        sequence = retained + 1
        _atomic_bytes(path, f"{sequence}\n".encode("ascii"))
        return sequence

    def _live_now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", "control clock is naive")
        return value.astimezone(UTC)

    def _read_workspace_file(self, raw_path: str) -> bytes:
        parent_fd, target_name = self._open_parent(raw_path, create=False)
        try:
            descriptor = os.open(
                target_name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
        finally:
            os.close(parent_fd)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise _RpcRejectedError("UNSAFE_PATH", "workspace entry is not a regular file")
            chunks = bytearray()
            while chunk := os.read(descriptor, _COPY_CHUNK):
                chunks.extend(chunk)
            return bytes(chunks)
        finally:
            os.close(descriptor)

    def _write_workspace_file(self, raw_path: str, content: bytes, mode: int) -> None:
        parent_fd, target_name = self._open_parent(raw_path, create=True)
        temporary_name = f".{target_name}.{os.getpid()}.{time.time_ns()}.partial"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=parent_fd,
            )
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fchmod(descriptor, mode)
            if os.geteuid() == 0:
                os.fchown(descriptor, _EXPERIMENT_UID, _EXPERIMENT_GID)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary_name, target_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)

    def _publish_workspace_context(self) -> None:
        """Expose only non-sensitive Product subjects to the IDE extension.

        The file is outside the research manifest: capture/live projections
        explicitly exclude the top-level ``.kcs`` directory.  It is written
        after Attempt Git initialization so it cannot enter the immutable base
        commit, while Project workspaces can receive it at control startup.
        """

        if not self._workspace_context:
            return
        encoded = json.dumps(
            self._workspace_context,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self._write_workspace_file("worktree/.kcs/aicosmos.json", encoded, 0o640)

    def _configure_workspace_context(
        self, request: Mapping[str, Any]
    ) -> dict[str, object]:
        if set(request) != {"action", "conversationRef", "productBase"}:
            raise _RpcRejectedError("INVALID_REQUEST", "workspace context shape is invalid")
        conversation_ref = request.get("conversationRef")
        product_base = request.get("productBase")
        if not isinstance(conversation_ref, str) or not conversation_ref:
            raise _RpcRejectedError("INVALID_REQUEST", "workspace conversation is invalid")
        if not isinstance(product_base, str):
            raise _RpcRejectedError("INVALID_REQUEST", "workspace Product base is invalid")
        parsed = urlsplit(product_base.rstrip("/"))
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "workspace Product base is invalid")
        retained_conversation = self._workspace_context.get("conversationRef")
        if retained_conversation and retained_conversation != conversation_ref:
            raise _RpcRejectedError("STALE_BINDING", "workspace conversation binding changed")
        normalized = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")
        )
        self._workspace_context.update(
            conversationRef=conversation_ref,
            productBase=normalized,
        )
        self._publish_workspace_context()
        return {"ok": True, "configured": True}

    def _workspace_file_mode(self, raw_path: str) -> str:
        parent_fd, target_name = self._open_parent(raw_path, create=False)
        try:
            mode = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False).st_mode
        finally:
            os.close(parent_fd)
        if mode & 0o111:
            return "executable"
        if mode & 0o200:
            return "read_write"
        return "read_only"

    def _publish_operation_result(self, operation_ref: str, content: bytes) -> str:
        operation_digest = hashlib.sha256(operation_ref.encode()).hexdigest()
        path = f".cosmos/kcs-operation-results/{operation_digest}.json"
        self._write_workspace_file(path, content, 0o660)
        content_digest = hashlib.sha256(content).hexdigest()
        return f"rc-result-v1-{operation_digest[:24]}-{len(content)}-{content_digest}"

    def _fence_operation(self, request: Mapping[str, Any]) -> dict[str, object]:
        operation_ref, digest = _identity(request, "operationRef", "requestDigest")
        dispatch_token = _dispatch_token(request)
        with self._operation_lock:
            retained = self._operations.get(operation_ref)
            if retained is not None:
                _same_digest(retained, digest)
                return {"ok": True, "known": True, **retained}
            claim = self._operation_claims.get(operation_ref)
            if claim is not None:
                _same_digest(claim, digest)
                if claim.get("dispatchToken") != dispatch_token:
                    raise _RpcRejectedError("IDENTITY_CONFLICT", "workspace dispatch token differs")
            fence = self._operation_fences.get(operation_ref)
            if fence is not None:
                _same_digest(fence, digest)
            else:
                self._operation_fences[operation_ref] = {
                    "requestDigest": digest,
                    "dispatchToken": dispatch_token,
                }
            return {
                "ok": True,
                "known": False,
                "fenced": True,
                "operationRef": operation_ref,
                "requestDigest": digest,
            }

    def _inspect_operation(self, request: Mapping[str, Any]) -> dict[str, object]:
        operation_ref = request.get("operationRef")
        with self._operation_lock:
            retained = self._operations.get(str(operation_ref))
            return {"ok": True, "known": retained is not None, **(retained or {})}

    def _end_operation(self, request: Mapping[str, Any], action: str) -> dict[str, object]:
        operation_ref = request.get("operationRef")
        with self._operation_lock:
            retained = self._operations.get(str(operation_ref))
            if retained is None:
                return {"ok": True, "known": False}
            if action == "discardOperation":
                self._operations.pop(str(operation_ref), None)
                self._operation_claims.pop(str(operation_ref), None)
            return {"ok": True, "known": True, **retained}

    @staticmethod
    def _casefold_entries(parent: Path, name: str) -> list[Path]:
        if not parent.is_dir():
            return []
        folded = unicodedata.normalize("NFC", name).casefold()
        return [
            child
            for child in parent.iterdir()
            if unicodedata.normalize("NFC", child.name).casefold() == folded
        ]

    def _open_parent(self, raw_path: str, *, create: bool) -> tuple[int, str]:
        """Walk parents by descriptor so a concurrent symlink swap cannot escape."""
        parts = PurePosixPath(raw_path).parts
        descriptor = os.open(self.workspace, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in parts[:-1]:
                folded = unicodedata.normalize("NFC", component).casefold()
                entries = os.listdir(descriptor)
                collisions = [
                    entry
                    for entry in entries
                    if unicodedata.normalize("NFC", entry).casefold() == folded
                ]
                if len(collisions) > 1 or (collisions and collisions[0] != component):
                    raise _RpcRejectedError(
                        "UNSAFE_PATH", "workspace path has a casefold collision"
                    )
                created_directory = not collisions
                if created_directory:
                    if not create:
                        raise _RpcRejectedError("NOT_FOUND", "workspace parent does not exist")
                    os.mkdir(component, 0o2775, dir_fd=descriptor)
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                if created_directory:
                    os.fchmod(next_descriptor, 0o2775)
                    if os.geteuid() == 0:
                        os.fchown(next_descriptor, _EXPERIMENT_UID, _EXPERIMENT_GID)
                os.close(descriptor)
                descriptor = next_descriptor
            target_name = parts[-1]
            folded = unicodedata.normalize("NFC", target_name).casefold()
            collisions = _casefold_entries_at(descriptor, target_name)
            if len(collisions) > 1 or (collisions and collisions[0] != target_name):
                raise _RpcRejectedError("UNSAFE_PATH", "workspace target has a casefold collision")
            return descriptor, target_name
        except Exception:
            os.close(descriptor)
            raise


def serve(
    socket_path: Path,
    workspace: Path,
    sidecar_factory: Callable[[Path], RuntimeControlSidecar] = RuntimeControlSidecar,
) -> None:
    """Run the long-lived production control on a private Unix socket only."""
    socket_path.unlink(missing_ok=True)
    sidecar = sidecar_factory(workspace)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(8)
        while True:
            connection, _ = listener.accept()
            with connection:
                try:
                    _serve_connection(connection, sidecar)
                except (ConnectionError, EOFError, DependencyUnavailableError, OSError):
                    # A dropped Kubernetes exec/WebSocket can connect to the
                    # long-lived socket and disappear before its bounded frame
                    # arrives.  That request has no confirmed outcome, but it
                    # must not terminate the capture/control authority.
                    continue
            if sidecar.shutdown_requested:
                return


def _serve_connection(connection: socket.socket, sidecar: RuntimeControlSidecar) -> None:
    prefix = _recv_exact(connection, 4)
    header_size = struct.unpack(">I", prefix)[0]
    if header_size > _MAX_RPC_HEADER:
        raise DependencyUnavailableError("workspace RPC header exceeded its bound")
    frame = prefix + _recv_exact(connection, header_size)
    header = decode_workspace_header(frame)
    body_size = header["bodySize"]
    body_path: Path | None = None
    response_path = _private_path("kcs-sidecar-response-")
    try:
        try:
            _validate_ingress_body(header)
        except _RpcRejectedError as error:
            write_workspace_response(
                response_path,
                {"ok": False, "code": error.code, "message": error.message},
            )
            with response_path.open("rb") as response:
                while chunk := response.read(_COPY_CHUNK):
                    connection.sendall(chunk)
            return
        if body_size:
            body_path = _private_path("kcs-sidecar-body-")
            with body_path.open("wb") as output:
                remaining = body_size
                while remaining:
                    chunk = connection.recv(min(_COPY_CHUNK, remaining))
                    if not chunk:
                        raise ConnectionError("workspace RPC body was truncated")
                    output.write(chunk)
                    remaining -= len(chunk)
        sidecar.dispatch(frame, body_path, response_path)
        with response_path.open("rb") as emitted:
            prefix = emitted.read(4)
            header_size = struct.unpack(">I", prefix)[0]
            event = json.loads(emitted.read(header_size))
            if isinstance(event, dict) and "event" in event:
                print(json.dumps(event, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        with response_path.open("rb") as response:
            while chunk := response.read(_COPY_CHUNK):
                connection.sendall(chunk)
    finally:
        response_path.unlink(missing_ok=True)
        if body_path is not None:
            body_path.unlink(missing_ok=True)


def rpc(socket_path: Path) -> None:
    """Fixed `/opt/kcs/workspace-sidecar rpc` client over stdin/stdout bytes."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(str(socket_path))
        prefix = sys.stdin.buffer.read(4)
        if len(prefix) != 4:
            raise EOFError("workspace RPC header was truncated")
        header_size = struct.unpack(">I", prefix)[0]
        if header_size > _MAX_RPC_HEADER:
            raise DependencyUnavailableError("workspace RPC header exceeded its bound")
        encoded_header = sys.stdin.buffer.read(header_size)
        if len(encoded_header) != header_size:
            raise EOFError("workspace RPC header was truncated")
        frame = prefix + encoded_header
        header = decode_workspace_header(frame)
        _validate_ingress_body(header)
        connection.sendall(frame)
        remaining = header["bodySize"]
        while remaining:
            chunk = sys.stdin.buffer.read(min(_COPY_CHUNK, remaining))
            if not chunk:
                raise EOFError("workspace RPC body was truncated")
            connection.sendall(chunk)
            remaining -= len(chunk)
        connection.shutdown(socket.SHUT_WR)
        while chunk := connection.recv(_COPY_CHUNK):
            sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()


def _identity(request: Mapping[str, Any], ref_field: str, digest_field: str) -> tuple[str, str]:
    ref, digest = request.get(ref_field), request.get(digest_field)
    if not isinstance(ref, str) or not isinstance(digest, str) or len(digest) != 64:
        raise _RpcRejectedError("INVALID_REQUEST", "RPC identity is invalid")
    return ref, digest


def _same_digest(retained: Mapping[str, Any], digest: str) -> None:
    if retained.get("requestDigest") != digest:
        raise _RpcRejectedError("IDENTITY_CONFLICT", "retained identity digest differs")


def _dispatch_token(request: Mapping[str, Any]) -> str:
    value = request.get("dispatchToken")
    if not isinstance(value, str) or len(value) != 32:
        raise _RpcRejectedError("INVALID_REQUEST", "workspace dispatch token is invalid")
    return value


def _byte_contract(request: Mapping[str, Any]) -> tuple[int, str]:
    size, digest = request.get("declaredSizeBytes"), request.get("contentSha256")
    maximum = request.get("authorizedMaxSizeBytes")
    if (
        type(size) is not int
        or type(maximum) is not int
        or not 0 <= size <= maximum <= 107374182400
        or not isinstance(digest, str)
        or len(digest) != 64
    ):
        raise _RpcRejectedError("INVALID_REQUEST", "transfer byte contract is invalid")
    return size, digest


def _validate_ingress_body(request: Mapping[str, Any]) -> None:
    body_size = request.get("bodySize")
    if type(body_size) is not int or body_size < 0:
        raise _RpcRejectedError("INVALID_REQUEST", "RPC body size is invalid")
    if request.get("action") in {"stage", "importProjectWorkspaceRevision"}:
        declared_size, _ = _byte_contract(request)
        if body_size != declared_size:
            raise _RpcRejectedError(
                "INVALID_REQUEST", "stage body size differs from its authorized contract"
            )
    elif body_size != 0:
        raise _RpcRejectedError("INVALID_REQUEST", "this RPC action does not accept a body")


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(_COPY_CHUNK):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _hash_stream(source: Any) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(_COPY_CHUNK):
        size += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def _stat_at(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _hash_nofollow(path: Path) -> tuple[int, str]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise _RpcRejectedError("UNSAFE_PATH", "transfer snapshot is not a regular file")
    with os.fdopen(descriptor, "rb") as source:
        return _hash_stream(source)


def _inspect_at(parent_fd: int, name: str) -> tuple[os.stat_result, int, str]:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    target_stat = os.fstat(descriptor)
    if not stat.S_ISREG(target_stat.st_mode):
        os.close(descriptor)
        raise _RpcRejectedError("UNSAFE_PATH", "workspace target is not a regular file")
    with os.fdopen(descriptor, "rb") as source:
        size, digest = _hash_stream(source)
    return target_stat, size, digest


def _casefold_entries_at(parent_fd: int, name: str) -> list[str]:
    folded = unicodedata.normalize("NFC", name).casefold()
    return [
        entry
        for entry in os.listdir(parent_fd)
        if unicodedata.normalize("NFC", entry).casefold() == folded
    ]


def _completed_transfer(
    transfer_ref: str, request_digest: str, size: int, content_digest: str
) -> dict[str, object]:
    return {
        "ok": True,
        "transferRef": transfer_ref,
        "requestDigest": request_digest,
        "state": "completed",
        "actualSizeBytes": size,
        "actualSha256": content_digest,
        "snapshotRef": None,
    }


def _public_transfer(value: Mapping[str, Any]) -> dict[str, object]:
    return {
        key: item
        for key, item in value.items()
        if key
        not in {
            "direction",
            "installDevice",
            "installInode",
            "overwritePolicy",
            "path",
            "receiptVersion",
            "snapshotName",
            "snapshotPath",
        }
    }


def _is_hex_digest(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _finalize_receipt_digest(
    *,
    request_ref: str,
    request_digest: str,
    capture_receipt_digest: str,
    job_uid: str,
    pod_uid: str,
    generation: int,
    accepted_at: str,
) -> str:
    identity = {
        "schemaVersion": 1,
        "requestRef": request_ref,
        "requestDigest": request_digest,
        "captureReceiptDigest": capture_receipt_digest,
        "jobUid": job_uid,
        "podUid": pod_uid,
        "generation": generation,
        "acceptedAt": accepted_at,
    }
    # Go's encoding/json uses struct field order and escapes these HTML/line
    # separator code points.  The launcher receipt digest is over those bytes,
    # rather than over JCS.
    encoded = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    encoded = (
        encoded.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    return hashlib.sha256(encoded.encode()).hexdigest()


def _validate_public_finalize_receipt(
    value: object,
    *,
    job_uid: str,
    pod_uid: str,
    generation: int,
    state: str,
) -> dict[str, Any]:
    expected = {
        "requestRef",
        "requestDigest",
        "captureReceiptDigest",
        "receiptDigest",
        "state",
        "acceptedAt",
        "commitRequestRef",
        "commitRequestDigest",
        "committedAt",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or not isinstance(value["requestRef"], str)
        or not value["requestRef"]
        or not _is_hex_digest(value["requestDigest"])
        or not _is_hex_digest(value["captureReceiptDigest"])
        or not _is_hex_digest(value["receiptDigest"])
        or value["state"] != state
        or not isinstance(value["acceptedAt"], str)
        or not value["acceptedAt"]
        or (
            state == "accepted"
            and (
                value["commitRequestRef"] is not None
                or value["commitRequestDigest"] is not None
                or value["committedAt"] is not None
            )
        )
        or (
            state == "committed"
            and (
                not isinstance(value["commitRequestRef"], str)
                or not value["commitRequestRef"]
                or not _is_hex_digest(value["commitRequestDigest"])
                or not isinstance(value["committedAt"], str)
                or not value["committedAt"]
            )
        )
    ):
        raise _RpcRejectedError(
            "DEPENDENCY_UNAVAILABLE", "native launcher finalize receipt is invalid"
        )
    actual = _finalize_receipt_digest(
        request_ref=value["requestRef"],
        request_digest=value["requestDigest"],
        capture_receipt_digest=value["captureReceiptDigest"],
        job_uid=job_uid,
        pod_uid=pod_uid,
        generation=generation,
        accepted_at=value["acceptedAt"],
    )
    if not hmac.compare_digest(value["receiptDigest"].lower(), actual):
        raise _RpcRejectedError(
            "DEPENDENCY_UNAVAILABLE", "native launcher finalize receipt digest differs"
        )
    return value


def _validate_finalize_launcher_result(
    value: object,
    *,
    job_uid: str,
    pod_uid: str,
    finalize_ref: str,
    request_digest: str,
    generation: int,
    capture_receipt_digest: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"finalized", "launcherAlive", "finalizeReceipt"}
        or value["finalized"] is not True
        or value["launcherAlive"] is not True
    ):
        raise _RpcRejectedError(
            "DEPENDENCY_UNAVAILABLE",
            "native launcher finalize acknowledgement is invalid",
        )
    receipt = _validate_public_finalize_receipt(
        value["finalizeReceipt"],
        job_uid=job_uid,
        pod_uid=pod_uid,
        generation=generation,
        state="accepted",
    )
    if (
        receipt["requestRef"] != finalize_ref
        or receipt["requestDigest"] != request_digest
        or receipt["captureReceiptDigest"] != capture_receipt_digest
    ):
        raise _RpcRejectedError(
            "DEPENDENCY_UNAVAILABLE",
            "native launcher finalize acknowledgement identity differs",
        )
    return receipt


def _validate_commit_launcher_result(
    value: object,
    *,
    job_uid: str,
    pod_uid: str,
    generation: int,
    commit_ref: str,
    commit_digest: str,
    finalize_receipt_digest: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"committed", "launcherAlive", "finalizeReceipt"}
        or value["committed"] is not True
        or value["launcherAlive"] is not False
    ):
        raise _RpcRejectedError(
            "DEPENDENCY_UNAVAILABLE",
            "native launcher finalize commit acknowledgement is invalid",
        )
    receipt = _validate_public_finalize_receipt(
        value["finalizeReceipt"],
        job_uid=job_uid,
        pod_uid=pod_uid,
        generation=generation,
        state="committed",
    )
    if (
        receipt["receiptDigest"] != finalize_receipt_digest
        or receipt["commitRequestRef"] != commit_ref
        or receipt["commitRequestDigest"] != commit_digest
    ):
        raise _RpcRejectedError(
            "DEPENDENCY_UNAVAILABLE",
            "native launcher finalize commit acknowledgement identity differs",
        )
    return receipt


def _validate_launcher_finalize_receipt_file(value: object) -> None:
    expected = {
        "schemaVersion",
        "requestRef",
        "requestDigest",
        "captureReceiptDigest",
        "jobUid",
        "podUid",
        "generation",
        "receiptDigest",
        "state",
        "acceptedAt",
        "commitRequestRef",
        "commitRequestDigest",
        "committedAt",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value["schemaVersion"] != 1
        or not isinstance(value["requestRef"], str)
        or not value["requestRef"]
        or not _is_hex_digest(value["requestDigest"])
        or not _is_hex_digest(value["captureReceiptDigest"])
        or not isinstance(value["jobUid"], str)
        or not value["jobUid"]
        or not isinstance(value["podUid"], str)
        or not value["podUid"]
        or type(value["generation"]) is not int
        or value["generation"] < 0
        or not _is_hex_digest(value["receiptDigest"])
        or value["state"] not in {"accepted", "committed"}
        or not isinstance(value["acceptedAt"], str)
        or not value["acceptedAt"]
        or (
            value["state"] == "accepted"
            and (
                value["commitRequestRef"] is not None
                or value["commitRequestDigest"] is not None
                or value["committedAt"] is not None
            )
        )
        or (
            value["state"] == "committed"
            and (
                not isinstance(value["commitRequestRef"], str)
                or not value["commitRequestRef"]
                or not _is_hex_digest(value["commitRequestDigest"])
                or not isinstance(value["committedAt"], str)
                or not value["committedAt"]
            )
        )
    ):
        raise _RpcRejectedError(
            "DEPENDENCY_UNAVAILABLE", "native launcher finalize receipt is malformed"
        )
    actual = _finalize_receipt_digest(
        request_ref=value["requestRef"],
        request_digest=value["requestDigest"],
        capture_receipt_digest=value["captureReceiptDigest"],
        job_uid=value["jobUid"],
        pod_uid=value["podUid"],
        generation=value["generation"],
        accepted_at=value["acceptedAt"],
    )
    if not hmac.compare_digest(value["receiptDigest"].lower(), actual):
        raise _RpcRejectedError(
            "DEPENDENCY_UNAVAILABLE",
            "native launcher finalize receipt digest differs",
        )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_bytes(
        path,
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8"),
    )


def _atomic_bytes(path: Path, content: bytes) -> None:
    descriptor, raw = tempfile.mkstemp(dir=path.parent, prefix=".partial-")
    partial = Path(raw)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(partial, path)
        _fsync_directory(path.parent)
    finally:
        partial.unlink(missing_ok=True)


def _read_json(path: Path, subject: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", f"{subject} is unavailable") from error
    if not isinstance(value, dict):
        raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", f"{subject} is malformed")
    return value


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", "control timestamp is naive")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        result = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", "timestamp is malformed") from error
    if result.tzinfo is None:
        raise _RpcRejectedError("DEPENDENCY_UNAVAILABLE", "timestamp is malformed")
    return result.astimezone(UTC)


def _append_live_omission(
    omissions: list[dict[str, str]], path: str, reason: str
) -> None:
    if len(omissions) < _MAX_LIVE_SNAPSHOT_ENTRIES:
        omissions.append({"path": path, "reason": reason})


def _live_diff_items(retained: Mapping[str, Any]) -> list[dict[str, Any]]:
    snapshot = retained["snapshot"]
    current = {str(item["path"]): item for item in snapshot["entries"]}
    base = {
        str(item["path"]): item
        for item in retained["baseManifest"].get("entries", [])
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    omitted = [
        str(item["path"])
        for item in snapshot["omissions"]
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    ]

    def is_omitted(path: str) -> bool:
        return any(path == prefix or path.startswith(f"{prefix}/") for prefix in omitted)

    result: list[dict[str, Any]] = []
    for path in sorted(set(base) | set(current)):
        before = base.get(path)
        after = current.get(path)
        if before is None and after is not None:
            result.append(
                {
                    "path": path,
                    "change": "added",
                    "baseSha256": None,
                    "snapshotSha256": after.get("contentSha256"),
                    "sizeBytes": int(after["sizeBytes"]),
                }
            )
            continue
        if before is not None and after is None:
            if is_omitted(path):
                continue
            result.append(
                {
                    "path": path,
                    "change": "deleted",
                    "baseSha256": before.get("contentSha256"),
                    "snapshotSha256": None,
                    "sizeBytes": int(before.get("sizeBytes", 0)),
                }
            )
            continue
        assert before is not None and after is not None
        before_digest = before.get("contentSha256")
        after_digest = after.get("contentSha256")
        if after.get("kind") != "file":
            result.append(
                {
                    "path": path,
                    "change": "type_changed",
                    "baseSha256": before_digest,
                    "snapshotSha256": after_digest,
                    "sizeBytes": int(after["sizeBytes"]),
                }
            )
        elif before_digest != after_digest:
            result.append(
                {
                    "path": path,
                    "change": "modified",
                    "baseSha256": before_digest,
                    "snapshotSha256": after_digest,
                    "sizeBytes": int(after["sizeBytes"]),
                }
            )
    return result


def _encode_live_page_token(snapshot_digest: str, offset: int) -> str:
    encoded = json.dumps(
        {"digest": snapshot_digest, "offset": offset},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _decode_live_page_token(value: object, snapshot_digest: str) -> int:
    if value is None:
        return 0
    if not isinstance(value, str) or not value:
        raise _RpcRejectedError("INVALID_PAGE_TOKEN", "live diff page token is invalid")
    try:
        padding = "=" * (-len(value) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(f"{value}{padding}"))
    except (ValueError, json.JSONDecodeError) as error:
        raise _RpcRejectedError(
            "INVALID_PAGE_TOKEN", "live diff page token is invalid"
        ) from error
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"digest", "offset"}
        or decoded["digest"] != snapshot_digest
        or type(decoded["offset"]) is not int
        or decoded["offset"] < 0
    ):
        raise _RpcRejectedError("INVALID_PAGE_TOKEN", "live diff page token is invalid")
    return int(decoded["offset"])


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise ConnectionError("workspace RPC frame was truncated")
        result.extend(chunk)
    return bytes(result)


def _private_path(prefix: str) -> Path:
    descriptor, raw_path = tempfile.mkstemp(prefix=prefix)
    os.close(descriptor)
    os.chmod(raw_path, 0o600)
    return Path(raw_path)


def _private_directory(parent: Path, name: str) -> Path:
    path = parent / name
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ValueError("workspace sidecar private directory is unsafe") from None
    os.chmod(path, 0o700, follow_symlinks=False)
    return path


def _secure_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise ValueError("runtime control state directory is unsafe")
    os.chmod(path, 0o700, follow_symlinks=False)
    return path.resolve(strict=True)


def main(
    sidecar_factory: Callable[[Path], RuntimeControlSidecar] = RuntimeControlSidecar,
) -> None:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command")
    serve_parser = subcommands.add_parser("serve")
    serve_parser.add_argument(
        "--socket",
        type=Path,
        default=Path(os.environ.get("KCS_WORKSPACE_SOCKET", "/run/kcs/workspace.sock")),
    )
    serve_parser.add_argument(
        "--workspace", type=Path, default=Path(os.environ.get("KCS_WORKSPACE", "/workspace"))
    )
    rpc_parser = subcommands.add_parser("rpc")
    rpc_parser.add_argument(
        "--socket",
        type=Path,
        default=Path(os.environ.get("KCS_WORKSPACE_SOCKET", "/run/kcs/workspace.sock")),
    )
    arguments = parser.parse_args()
    if arguments.command in {None, "serve"}:
        serve(
            getattr(
                arguments,
                "socket",
                Path(os.environ.get("KCS_WORKSPACE_SOCKET", "/run/kcs/workspace.sock")),
            ),
            getattr(arguments, "workspace", Path(os.environ.get("KCS_WORKSPACE", "/workspace"))),
            sidecar_factory,
        )
    else:
        rpc(arguments.socket)


def _main() -> None:
    main()


if __name__ == "__main__":
    _main()
