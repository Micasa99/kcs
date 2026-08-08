"""Private Unix-socket workspace sidecar fixture with raw binary transfer framing."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
import socket
import stat
import struct
import sys
import tempfile
import time
import unicodedata
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import Any, NoReturn

import rfc8785

from kcs.conformance.actions import (
    observe_workspace_gpu,
    probe_runtime_url,
    shared_read,
    shared_write,
)
from kcs.jobs.errors import DependencyUnavailableError
from kcs.jobs.policy import validate_safe_relative_path
from kcs.jobs.transport import (
    decode_workspace_header,
    write_workspace_response,
)

_COPY_CHUNK = 1024 * 1024
_MAX_RPC_HEADER = 4 * 1024 * 1024
_MAX_NATIVE_FRAME = 131072


class _RpcRejectedError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class WorkspaceSidecar:
    """Conformance-only workspace authority; no network listener is created."""

    def __init__(self, workspace: Path) -> None:
        workspace.mkdir(parents=True, exist_ok=True)
        self.workspace = workspace.resolve(strict=True)
        self._private = _private_directory(self.workspace, ".kcs")
        self._partials = _private_directory(self._private, "partials")
        self._snapshots = _private_directory(self._private, "snapshots")
        self._receipts = _private_directory(self._private, "receipts")
        self._transfers: dict[str, dict[str, Any]] = {}
        self._operations: dict[str, dict[str, Any]] = {}
        self._operation_claims: dict[str, dict[str, str]] = {}
        self._operation_fences: dict[str, dict[str, str]] = {}
        self._operation_lock = RLock()
        self._stage_installs = 0
        self._operation_side_effects = 0
        self._native_state_generation = 0
        self._native_state_sequence = 0
        self._native_state_digest: str | None = None
        self.shutdown_requested = False

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
        write_workspace_response(response_path, response, response_body)

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
        if (
            request.get("protocolVersion") == 1
            and action == "sharedWrite"
            and set(request) == {"protocolVersion", "action"}
        ):
            return shared_write(self.workspace, "workspace"), None
        if (
            request.get("protocolVersion") == 1
            and action == "sharedRead"
            and set(request) == {"protocolVersion", "action", "sourceRole"}
        ):
            return shared_read(self.workspace, "workspace", request.get("sourceRole")), None
        if (
            request.get("protocolVersion") == 1
            and action == "observeGpu"
            and set(request) == {"protocolVersion", "action"}
        ):
            return observe_workspace_gpu(), None
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
        if action == "shutdown":
            if os.environ.get("KCS_NATIVE_LAUNCHER_SOCKET"):
                self._wait_for_native_launcher_exit()
            self.shutdown_requested = True
            return {"ok": True, "state": "stopped", "supervisorAlive": False}, None
        raise _RpcRejectedError("INVALID_REQUEST", "unsupported workspace RPC action")

    @staticmethod
    def _wait_for_native_launcher_exit() -> None:
        socket_path = os.environ.get(
            "KCS_NATIVE_LAUNCHER_SOCKET", "/run/rc-control/launcher.sock"
        )
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
            or hashlib.sha256(rfc8785.dumps(command_payload)).hexdigest() != request_digest
        ):
            raise _RpcRejectedError("INVALID_REQUEST", "native launcher identity is invalid")
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
            else:
                public_code = "DEPENDENCY_UNAVAILABLE"
            raise _RpcRejectedError(
                public_code,
                "native launcher rejected the request",
            )
        if command in {"start", "inspect", "stop"}:
            result["payload"]["runnerObservation"] = self._read_native_state(
                request["jobUid"], request["podUid"], generation
            )
        return {"ok": True, "result": result["payload"]}

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
            or set(protocol_terminal)
            != {"observed", "eventKind", "stopReason", "errorCode"}
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
            os.fsync(parent_fd)
            self._stage_installs += 1
            result = {**intent, "ok": True, "state": "completed"}
            self._write_receipt(result)
            self._transfers[transfer_ref] = result
            return _public_transfer(result)
        finally:
            partial.unlink(missing_ok=True)
            os.close(parent_fd)

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
        action = frame.get("action")
        allowed_fields = {
            "sharedWrite": {"protocol", "action"},
            "sharedRead": {"protocol", "action", "sourceRole"},
            "observeGpu": {"protocol", "action"},
            "probeRuntimeUrl": {"protocol", "action"},
        }
        if (
            not isinstance(action, str)
            or action not in allowed_fields
            or set(frame) != allowed_fields[action]
        ):
            raise _RpcRejectedError(
                "INVALID_REQUEST", "workspace action is not a fixed conformance action"
            )
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
            if action == "sharedWrite":
                action_result = shared_write(self.workspace, "workspace")
            elif action == "sharedRead":
                action_result = shared_read(self.workspace, "workspace", frame.get("sourceRole"))
            elif action == "observeGpu":
                action_result = observe_workspace_gpu()
            else:
                runtime_url = os.environ.get("RC_PUBLIC_RUNTIME_BASE_URL")
                action_result = probe_runtime_url(runtime_url)
            print(
                json.dumps(action_result, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
                flush=True,
            )
            self._operation_side_effects += 1
            exit_code = 0 if action_result.get("ok") is True else 1
            output = json.dumps(action_result, sort_keys=True, separators=(",", ":")) + "\n"
            result = {
                "ok": True,
                "operationRef": operation_ref,
                "requestDigest": digest,
                "state": "succeeded" if exit_code == 0 else "failed",
                "exitCode": exit_code,
                "stdout": output,
                "stderr": "",
                "inlineResult": action_result,
                "resultTransferRef": None,
            }
            self._operations[operation_ref] = result
            return dict(result)

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
                if not collisions:
                    if not create:
                        raise _RpcRejectedError("NOT_FOUND", "workspace parent does not exist")
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
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


def serve(socket_path: Path, workspace: Path) -> None:
    """Run the long-lived PID-1 fixture on a private Unix socket only."""
    socket_path.unlink(missing_ok=True)
    sidecar = WorkspaceSidecar(workspace)
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


def _serve_connection(connection: socket.socket, sidecar: WorkspaceSidecar) -> None:
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
    if request.get("action") == "stage":
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


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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


def _main() -> None:
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
        )
    else:
        rpc(arguments.socket)


if __name__ == "__main__":
    _main()
