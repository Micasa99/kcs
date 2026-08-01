"""Private Unix-socket workspace sidecar fixture with raw binary transfer framing."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unicodedata
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from kcs.jobs.errors import DependencyUnavailableError
from kcs.jobs.policy import validate_safe_relative_path
from kcs.jobs.transport import (
    decode_workspace_header,
    write_workspace_response,
)

_COPY_CHUNK = 1024 * 1024
_MAX_RPC_HEADER = 4 * 1024 * 1024


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
        self._stage_installs = 0
        self._operation_side_effects = 0

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
        self._operations.clear()

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
        if action == "inspectOperation":
            return self._inspect_operation(request), None
        if action in {"cancelOperation", "discardOperation"}:
            return self._end_operation(request, str(action)), None
        if action == "stats":
            return {"ok": True, **self.stats()}, None
        raise _RpcRejectedError("INVALID_REQUEST", "unsupported workspace RPC action")

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
                return dict(retained)
            if retained.get("state") in {"canceled", "discarded"}:
                raise _RpcRejectedError(
                    "STATE_CONFLICT", "the transfer already reached a terminal state"
                )

        self._validate_transfer_path(request, allow_stage_existing=True)
        parent_fd, target_name = self._open_parent(str(request["path"]), create=True)
        partial = self._partials / hashlib.sha256(transfer_ref.encode()).hexdigest()
        partial.unlink(missing_ok=True)
        try:
            descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output, body.open("rb") as source:
                shutil.copyfileobj(source, output, length=_COPY_CHUNK)
                output.flush()
                os.fsync(output.fileno())
            verified_size, verified_digest = _hash_file(partial)
            if verified_size != size or verified_digest != content_digest:
                raise _RpcRejectedError("TRANSFER_BYTES_MISMATCH", "private staged bytes changed")
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
        finally:
            partial.unlink(missing_ok=True)
            os.close(parent_fd)
        result = _completed_transfer(transfer_ref, digest, size, content_digest)
        self._write_receipt(result)
        self._transfers[transfer_ref] = dict(result)
        self._stage_installs += 1
        return result

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
        if retained is not None and retained.get("state") == "completed":
            raise _RpcRejectedError("STATE_CONFLICT", "completed transfer cannot be canceled")
        partial = self._partials / hashlib.sha256(transfer_ref.encode()).hexdigest()
        partial.unlink(missing_ok=True)
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
            or value.get("state") not in {"completed", "canceled", "discarded"}
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
        frame = request.get("frame")
        if not isinstance(frame, dict) or frame.get("protocol") != "cosmos.workspace/1":
            raise _RpcRejectedError("INVALID_REQUEST", "workspace frame is invalid")
        retained = self._operations.get(operation_ref)
        if retained is not None:
            _same_digest(retained, digest)
            return dict(retained)
        subprocess.run([sys.executable, "-c", "pass"], check=True)
        self._operation_side_effects += 1
        exit_code = frame.get("exitCode", 0)
        if type(exit_code) is not int:
            raise _RpcRejectedError("INVALID_REQUEST", "echo exitCode must be an integer")
        result = {
            "ok": True,
            "operationRef": operation_ref,
            "requestDigest": digest,
            "state": "succeeded" if exit_code == 0 else "failed",
            "exitCode": exit_code,
            "stdout": str(frame.get("stdout", "")),
            "stderr": str(frame.get("stderr", "")),
            "inlineResult": frame.get("result"),
            "resultTransferRef": frame.get("resultTransferRef"),
        }
        self._operations[operation_ref] = result
        return dict(result)

    def _inspect_operation(self, request: Mapping[str, Any]) -> dict[str, object]:
        operation_ref = request.get("operationRef")
        retained = self._operations.get(str(operation_ref))
        return {"ok": True, "known": retained is not None, **(retained or {})}

    def _end_operation(self, request: Mapping[str, Any], action: str) -> dict[str, object]:
        operation_ref = request.get("operationRef")
        retained = self._operations.get(str(operation_ref))
        if retained is None:
            return {"ok": True, "known": False}
        if action == "discardOperation":
            self._operations.pop(str(operation_ref), None)
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
                _serve_connection(connection, sidecar)


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
        if key not in {"receiptVersion", "snapshotName", "snapshotPath"}
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
    serve_parser.add_argument("--socket", type=Path, default=Path("/run/kcs/workspace.sock"))
    serve_parser.add_argument("--workspace", type=Path, default=Path("/workspace"))
    rpc_parser = subcommands.add_parser("rpc")
    rpc_parser.add_argument(
        "--socket",
        type=Path,
        default=Path(os.environ.get("KCS_WORKSPACE_SOCKET", "/run/kcs/workspace.sock")),
    )
    arguments = parser.parse_args()
    if arguments.command in {None, "serve"}:
        serve(
            getattr(arguments, "socket", Path("/run/kcs/workspace.sock")),
            getattr(arguments, "workspace", Path("/workspace")),
        )
    else:
        rpc(arguments.socket)


if __name__ == "__main__":
    _main()
