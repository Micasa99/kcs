"""Durable transfer and workspace-operation orchestration for the V2 provider."""

from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Protocol
from uuid import UUID

from .canonical import canonical_bytes, canonical_digest
from .contracts import (
    ActionSnapshot,
    ActionState,
    BindingIdentity,
    JobBindingSnapshot,
    JobBindingState,
    OperationState,
    TransferCancelRequest,
    TransferDirection,
    TransferRegisterRequest,
    TransferSnapshot,
    TransferState,
    WorkspaceInvokeRequest,
    WorkspaceOperationSnapshot,
)
from .errors import (
    DependencyUnavailableError,
    DigestMismatchError,
    IdentityDigestConflictError,
    JobNotFoundError,
    KcsV2Error,
    OperationIdentityConflictError,
    OperationIndeterminateError,
    OverwriteForbiddenError,
    PayloadTooLargeError,
    StateConflictError,
    TransferBytesMismatchError,
    TransferIdentityConflictError,
    TransferIndeterminateError,
    UnsafePathError,
)
from .transport import WorkspaceRpcReply, WorkspaceRpcTransportProtocol

_COPY_CHUNK = 1024 * 1024
_EMPTY_OBJECT_DIGEST = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


class RuntimeStoreProtocol(Protocol):
    def reserve_runtime(
        self, kind: str, identity: str, job_ref: str, values: Mapping[str, str]
    ) -> tuple[object, bool]: ...

    def read_runtime(self, kind: str, job_ref: str, identity: str) -> object | None: ...

    def list_runtime(self, kind: str, job_ref: str | None = None) -> Sequence[object]: ...

    def update_runtime(
        self, kind: str, job_ref: str, identity: str, values: Mapping[str, str]
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class TransferResult:
    snapshot: TransferSnapshot
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


@dataclass(frozen=True, slots=True)
class VerifiedContent:
    """A private verified file ready for a bounded HTTP streaming response."""

    path: Path
    size: int
    sha256: str
    snapshot_ref: str

    def cleanup(self) -> None:
        self.path.unlink(missing_ok=True)


class WorkspaceRuntime:
    """Own transfer/operation state while the public provider remains a façade."""

    def __init__(
        self,
        store: RuntimeStoreProtocol,
        transport: WorkspaceRpcTransportProtocol | None,
        live_binding: Callable[[str], JobBindingSnapshot],
        assert_accepting: Callable[[str], None],
        clock: Callable[[], datetime],
    ) -> None:
        self._store = store
        self._transport = transport
        self._live_binding = live_binding
        self._assert_accepting = assert_accepting
        self._clock = clock

    def register_transfer(self, job_ref: str, request: TransferRegisterRequest) -> TransferResult:
        binding = self._live_binding(job_ref)
        existing = self._store.read_runtime("transfer", job_ref, request.transfer_ref)
        if existing is not None:
            snapshot = self._transfer_snapshot(existing)
            self._validate_transfer_identity(snapshot, request, binding)
            return TransferResult(snapshot=snapshot, created=False)
        self._assert_binding_accepts_new_work(job_ref, binding)
        self._rpc_checked(binding, self._transfer_header("validateTransfer", request))
        now = self._clock()
        snapshot = TransferSnapshot(
            transfer_ref=request.transfer_ref,
            request_digest=request.request_digest,
            job_ref=job_ref,
            job_uid=binding.job_uid,
            pod_uid=_pod_uid(binding),
            spec=request.spec,
            state=TransferState.REGISTERED,
            actual_size_bytes=None,
            actual_sha256=None,
            verified=False,
            content_available=False,
            snapshot_ref=None,
            created_at=now,
            updated_at=now,
            completed_at=None,
            observed_at=now,
            failure_reason=None,
            cancel_action=_not_requested_action(),
            discard_action=_not_requested_action(),
        )
        try:
            record, created = self._store.reserve_runtime(
                "transfer",
                request.transfer_ref,
                job_ref,
                self._transfer_values(snapshot),
            )
        except IdentityDigestConflictError as error:
            raise TransferIdentityConflictError() from error
        retained = self._transfer_snapshot(record)
        self._validate_transfer_identity(retained, request, binding)
        return TransferResult(snapshot=retained, created=created)

    def stage_transfer_content(
        self,
        job_ref: str,
        transfer_ref: str,
        stream: BinaryIO,
        *,
        content_length: int | None = None,
    ) -> TransferSnapshot:
        record = self._transfer_record(job_ref, transfer_ref)
        snapshot = self._transfer_snapshot(record)
        binding = self._binding_for_existing(snapshot, accepting=True)
        if snapshot.spec.direction is not TransferDirection.STAGE_INPUT:
            raise StateConflictError("Only stage_input transfers accept uploaded content")
        if snapshot.state in {TransferState.CANCELED, TransferState.DISCARDED}:
            raise StateConflictError("The transfer no longer accepts content")
        if content_length is not None and (
            content_length != snapshot.spec.declared_size_bytes
            or content_length > snapshot.spec.authorized_max_size_bytes
        ):
            raise TransferBytesMismatchError()
        path, actual_size, actual_digest = _spool_stream(
            stream, snapshot.spec.authorized_max_size_bytes
        )
        try:
            if content_length is not None and content_length != actual_size:
                raise TransferBytesMismatchError()
            if actual_size != snapshot.spec.declared_size_bytes or not hmac.compare_digest(
                actual_digest, snapshot.spec.content_sha256
            ):
                raise TransferBytesMismatchError()
            if snapshot.state is TransferState.COMPLETED:
                if snapshot.actual_size_bytes != actual_size or not hmac.compare_digest(
                    snapshot.actual_sha256 or "", actual_digest
                ):
                    raise TransferBytesMismatchError()
                return snapshot
            staging = snapshot.model_copy(
                update={
                    "state": TransferState.STAGING,
                    "updated_at": self._clock(),
                    "observed_at": self._clock(),
                }
            )
            record = self._write_transfer(record, staging)
            reply = self._rpc_checked(binding, self._transfer_header("stage", snapshot), path)
            return self._complete_transfer(record, staging, reply, snapshot_ref=None)
        finally:
            path.unlink(missing_ok=True)

    def open_collected_content(self, job_ref: str, transfer_ref: str) -> VerifiedContent:
        record = self._transfer_record(job_ref, transfer_ref)
        snapshot = self._transfer_snapshot(record)
        binding = self._binding_for_existing(snapshot, accepting=True)
        if snapshot.spec.direction is not TransferDirection.COLLECT_OUTPUT:
            raise StateConflictError("Only collect_output transfers expose content")
        if snapshot.state in {
            TransferState.CANCELED,
            TransferState.DISCARDED,
            TransferState.FAILED,
            TransferState.INDETERMINATE,
        }:
            raise StateConflictError("The transfer does not have collectable content")
        if snapshot.state is not TransferState.COMPLETED:
            streaming = snapshot.model_copy(
                update={
                    "state": TransferState.STREAMING,
                    "updated_at": self._clock(),
                    "observed_at": self._clock(),
                }
            )
            record = self._write_transfer(record, streaming)
            snapshot = streaming
        reply = self._rpc_checked(binding, self._transfer_header("collect", snapshot))
        content = reply.content_path
        if content is None:
            raise DependencyUnavailableError("workspace collect returned no raw bytes")
        try:
            size, digest = _hash_file(content)
            snapshot_ref = _required_string(reply.header, "snapshotRef")
            if (
                size != snapshot.spec.declared_size_bytes
                or not hmac.compare_digest(digest, snapshot.spec.content_sha256)
                or reply.header.get("actualSizeBytes") != size
                or reply.header.get("actualSha256") != digest
            ):
                raise TransferBytesMismatchError()
            completed = self._complete_transfer(record, snapshot, reply, snapshot_ref=snapshot_ref)
            if completed.snapshot_ref != snapshot_ref:
                raise TransferBytesMismatchError()
            return VerifiedContent(content, size, digest, snapshot_ref)
        except Exception:
            content.unlink(missing_ok=True)
            raise

    def inspect_transfer(self, job_ref: str, transfer_ref: str) -> TransferSnapshot:
        return self._transfer_snapshot(self._transfer_record(job_ref, transfer_ref))

    def cancel_transfer(
        self, job_ref: str, transfer_ref: str, request: TransferCancelRequest
    ) -> TransferResult:
        record = self._transfer_record(job_ref, transfer_ref)
        before = self._transfer_snapshot(record)
        binding = self._binding_for_existing(before)
        action = before.cancel_action
        if action.state is ActionState.NOT_REQUESTED and before.state not in {
            TransferState.REGISTERED,
            TransferState.STAGING,
            TransferState.STREAMING,
        }:
            if before.state is TransferState.INDETERMINATE:
                raise TransferIndeterminateError()
            raise StateConflictError("The transfer is not cancelable in its retained state")
        if action.state is not ActionState.NOT_REQUESTED:
            if (
                action.action_ref != request.cancel_ref
                or action.request_digest != request.request_digest
            ):
                raise TransferIdentityConflictError()
            if action.state is ActionState.SUCCEEDED:
                return TransferResult(before, created=False)
            accepted = before
            created = False
        else:
            now = self._clock()
            accepted = before.model_copy(
                update={
                    "state": TransferState.CANCELING,
                    "updated_at": now,
                    "observed_at": now,
                    "cancel_action": ActionSnapshot(
                        action_ref=request.cancel_ref,
                        request_digest=request.request_digest,
                        state=ActionState.ACCEPTED,
                        observed_at=now,
                    ),
                }
            )
            record = self._write_transfer(record, accepted)
            created = True
        self._rpc_checked(
            binding,
            {
                "action": "cancelTransfer",
                "transferRef": transfer_ref,
                "requestDigest": before.request_digest,
                "cancelRef": request.cancel_ref,
                "cancelDigest": request.request_digest,
            },
        )
        completed_at = self._clock()
        canceled = accepted.model_copy(
            update={
                "state": TransferState.CANCELED,
                "content_available": False,
                "completed_at": completed_at,
                "updated_at": completed_at,
                "observed_at": completed_at,
                "cancel_action": accepted.cancel_action.model_copy(
                    update={"state": ActionState.SUCCEEDED, "observed_at": completed_at}
                ),
            }
        )
        return TransferResult(
            self._transfer_snapshot(self._write_transfer(record, canceled)), created
        )

    def discard_transfer(
        self,
        job_ref: str,
        transfer_ref: str,
        discard_ref: str,
        request_digest: str,
    ) -> TransferSnapshot:
        if not hmac.compare_digest(request_digest, _EMPTY_OBJECT_DIGEST):
            raise DigestMismatchError()
        record = self._transfer_record(job_ref, transfer_ref)
        before = self._transfer_snapshot(record)
        binding = self._binding_for_existing(before)
        if before.state is TransferState.INDETERMINATE:
            raise TransferIndeterminateError()
        action = before.discard_action
        if action.state is not ActionState.NOT_REQUESTED:
            if action.action_ref != discard_ref or action.request_digest != request_digest:
                raise TransferIdentityConflictError()
            if action.state is ActionState.SUCCEEDED:
                return before
            accepted = before
        else:
            now = self._clock()
            accepted = before.model_copy(
                update={
                    "updated_at": now,
                    "observed_at": now,
                    "discard_action": ActionSnapshot(
                        action_ref=discard_ref,
                        request_digest=request_digest,
                        state=ActionState.ACCEPTED,
                        observed_at=now,
                    ),
                }
            )
            record = self._write_transfer(record, accepted)
        self._rpc_checked(
            binding,
            {
                "action": "discardTransfer",
                "transferRef": transfer_ref,
                "requestDigest": before.request_digest,
            },
        )
        completed_at = self._clock()
        discarded = accepted.model_copy(
            update={
                "state": TransferState.DISCARDED,
                "content_available": False,
                "snapshot_ref": None,
                "completed_at": completed_at,
                "updated_at": completed_at,
                "observed_at": completed_at,
                "discard_action": accepted.discard_action.model_copy(
                    update={"state": ActionState.SUCCEEDED, "observed_at": completed_at}
                ),
            }
        )
        return self._transfer_snapshot(self._write_transfer(record, discarded))

    def invoke_workspace(
        self, job_ref: str, request: WorkspaceInvokeRequest
    ) -> WorkspaceOperationSnapshot:
        binding = self._live_binding(job_ref)
        if str(binding.job_uid) != str(request.job_uid) or str(_pod_uid(binding)) != str(
            request.pod_uid
        ):
            raise StateConflictError("Workspace operation binding headers are stale")
        frame_digest = canonical_digest(request.frame.root)
        existing = self._store.read_runtime("operation", job_ref, request.operation_ref)
        if existing is not None:
            retained = self._operation_snapshot(existing)
            self._validate_operation_identity(retained, request, frame_digest, binding)
            if retained.state in {
                OperationState.SUCCEEDED,
                OperationState.FAILED,
                OperationState.INDETERMINATE,
            }:
                if retained.state is OperationState.INDETERMINATE:
                    raise OperationIndeterminateError()
                return retained
            return self._recover_operation(existing, retained, binding)
        self._assert_binding_accepts_new_work(job_ref, binding)
        now = self._clock()
        accepted = WorkspaceOperationSnapshot(
            job_ref=job_ref,
            operation_ref=request.operation_ref,
            request_digest=request.request_digest,
            stored_frame_digest=frame_digest,
            binding=BindingIdentity(job_uid=binding.job_uid, pod_uid=_pod_uid(binding)),
            state=OperationState.ACCEPTED,
            exit_code=None,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            inline_result_size=None,
            inline_result_digest=None,
            inline_result=None,
            result_transfer_ref=None,
            accepted_at=now,
            started_at=None,
            finished_at=None,
            observed_at=now,
            failure_reason=None,
        )
        values = {
            "identityDigest": request.request_digest,
            "frameDigest": frame_digest,
            "jobUid": str(binding.job_uid),
            "podUid": str(_pod_uid(binding)),
            "payload": accepted.model_dump_json(by_alias=True),
        }
        try:
            record, created = self._store.reserve_runtime(
                "operation", request.operation_ref, job_ref, values
            )
        except IdentityDigestConflictError as error:
            raise OperationIdentityConflictError() from error
        retained = self._operation_snapshot(record)
        self._validate_operation_identity(retained, request, frame_digest, binding)
        if not created:
            return self._recover_operation(record, retained, binding)
        try:
            reply = self._rpc_checked(
                binding,
                {
                    "action": "invoke",
                    "operationRef": request.operation_ref,
                    "requestDigest": request.request_digest,
                    "frame": request.frame.root,
                },
                identity_kind="operation",
            )
        except (StateConflictError, DependencyUnavailableError):
            raise
        except Exception as error:
            raise DependencyUnavailableError(
                "workspace invoke response was not confirmed"
            ) from error
        return self._record_operation_result(record, retained, reply)

    def inspect_operation(self, job_ref: str, operation_ref: str) -> WorkspaceOperationSnapshot:
        record = self._store.read_runtime("operation", job_ref, operation_ref)
        if record is None:
            raise JobNotFoundError()
        return self._operation_snapshot(record)

    def _recover_operation(
        self,
        record: object,
        retained: WorkspaceOperationSnapshot,
        binding: JobBindingSnapshot,
    ) -> WorkspaceOperationSnapshot:
        reply = self._rpc_checked(
            binding,
            {"action": "inspectOperation", "operationRef": retained.operation_ref},
            identity_kind="operation",
        )
        if reply.header.get("known") is True:
            if reply.header.get("requestDigest") != retained.request_digest:
                raise OperationIdentityConflictError()
            return self._record_operation_result(record, retained, reply)
        now = self._clock()
        indeterminate = retained.model_copy(
            update={
                "state": OperationState.INDETERMINATE,
                "finished_at": now,
                "observed_at": now,
                "failure_reason": "the surviving workspace sidecar has no operation truth",
            }
        )
        self._store.update_runtime(
            "operation",
            retained.job_ref,
            retained.operation_ref,
            {**_values(record), "payload": indeterminate.model_dump_json(by_alias=True)},
        )
        raise OperationIndeterminateError()

    def _record_operation_result(
        self,
        record: object,
        before: WorkspaceOperationSnapshot,
        reply: WorkspaceRpcReply,
    ) -> WorkspaceOperationSnapshot:
        header = reply.header
        if header.get("requestDigest") != before.request_digest:
            raise OperationIdentityConflictError()
        stdout, stdout_truncated = _bounded_utf8(header.get("stdout", ""))
        stderr, stderr_truncated = _bounded_utf8(header.get("stderr", ""))
        exit_code = header.get("exitCode")
        if type(exit_code) is not int:
            raise DependencyUnavailableError("workspace result exitCode is invalid")
        state_value = header.get("state")
        if state_value not in {"succeeded", "failed"}:
            raise DependencyUnavailableError("workspace result state is invalid")
        inline = header.get("inlineResult")
        result_transfer = header.get("resultTransferRef")
        if inline is not None and not isinstance(inline, dict):
            raise DependencyUnavailableError("workspace inline result must be an object")
        if inline is not None and result_transfer is not None:
            raise DependencyUnavailableError("workspace result locations are ambiguous")
        encoded = canonical_bytes(inline) if inline is not None else None
        if encoded is not None and len(encoded) > 65536:
            raise PayloadTooLargeError("Workspace inline result exceeds 64 KiB")
        now = self._clock()
        result = before.model_copy(
            update={
                "state": OperationState(str(state_value)),
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "inline_result_size": len(encoded) if encoded is not None else None,
                "inline_result_digest": hashlib.sha256(encoded).hexdigest()
                if encoded is not None
                else None,
                "inline_result": inline,
                "result_transfer_ref": result_transfer,
                "started_at": before.started_at or now,
                "finished_at": now,
                "observed_at": now,
                "failure_reason": None
                if state_value == "succeeded"
                else "workspace exit was nonzero",
            }
        )
        written = self._store.update_runtime(
            "operation",
            before.job_ref,
            before.operation_ref,
            {**_values(record), "payload": result.model_dump_json(by_alias=True)},
        )
        return self._operation_snapshot(written)

    def _complete_transfer(
        self,
        record: object,
        before: TransferSnapshot,
        reply: WorkspaceRpcReply,
        *,
        snapshot_ref: str | None,
    ) -> TransferSnapshot:
        if (
            reply.header.get("actualSizeBytes") != before.spec.declared_size_bytes
            or reply.header.get("actualSha256") != before.spec.content_sha256
        ):
            raise TransferBytesMismatchError()
        now = self._clock()
        completed = before.model_copy(
            update={
                "state": TransferState.COMPLETED,
                "actual_size_bytes": before.spec.declared_size_bytes,
                "actual_sha256": before.spec.content_sha256,
                "verified": True,
                "content_available": True,
                "snapshot_ref": snapshot_ref,
                "updated_at": now,
                "completed_at": now,
                "observed_at": now,
                "failure_reason": None,
            }
        )
        return self._transfer_snapshot(self._write_transfer(record, completed))

    def _rpc_checked(
        self,
        binding: JobBindingSnapshot,
        header: Mapping[str, object],
        body: Path | None = None,
        *,
        identity_kind: str = "transfer",
    ) -> WorkspaceRpcReply:
        if self._transport is None:
            raise DependencyUnavailableError("workspace RPC transport is not configured")
        try:
            reply = self._transport.rpc(
                {
                    "jobRef": binding.job_ref,
                    "jobUid": str(binding.job_uid),
                    "podUid": str(_pod_uid(binding)),
                },
                header,
                body,
            )
        except KcsV2Error:
            raise
        except Exception as error:
            raise DependencyUnavailableError(
                "workspace sidecar response was not confirmed"
            ) from error
        if reply.header.get("ok") is not True:
            if reply.content_path is not None:
                reply.content_path.unlink(missing_ok=True)
            _raise_sidecar_error(
                str(reply.header.get("code", "DEPENDENCY_UNAVAILABLE")), identity_kind
            )
        return reply

    def _binding_for_new_work(self, job_ref: str) -> JobBindingSnapshot:
        binding = self._live_binding(job_ref)
        self._assert_binding_accepts_new_work(job_ref, binding)
        return binding

    def _assert_binding_accepts_new_work(self, job_ref: str, binding: JobBindingSnapshot) -> None:
        if binding.binding_state is not JobBindingState.RUNNING:
            raise StateConflictError("The Job is not running and cannot accept workspace work")
        self._assert_accepting(job_ref)

    def _binding_for_existing(
        self, snapshot: TransferSnapshot, *, accepting: bool = False
    ) -> JobBindingSnapshot:
        binding = self._live_binding(snapshot.job_ref)
        if str(binding.job_uid) != str(snapshot.job_uid) or str(_pod_uid(binding)) != str(
            snapshot.pod_uid
        ):
            raise StateConflictError("Transfer binding no longer matches the live Pod")
        if accepting:
            self._assert_binding_accepts_new_work(snapshot.job_ref, binding)
        return binding

    def _transfer_record(self, job_ref: str, transfer_ref: str) -> object:
        record = self._store.read_runtime("transfer", job_ref, transfer_ref)
        if record is None:
            raise JobNotFoundError()
        return record

    def _write_transfer(self, record: object, snapshot: TransferSnapshot) -> object:
        return self._store.update_runtime(
            "transfer",
            snapshot.job_ref,
            snapshot.transfer_ref,
            {**_values(record), "payload": snapshot.model_dump_json(by_alias=True)},
        )

    @staticmethod
    def _transfer_snapshot(record: object) -> TransferSnapshot:
        try:
            return TransferSnapshot.model_validate_json(_values(record)["payload"])
        except (KeyError, ValueError) as error:
            raise DependencyUnavailableError("retained transfer payload is invalid") from error

    @staticmethod
    def _operation_snapshot(record: object) -> WorkspaceOperationSnapshot:
        try:
            return WorkspaceOperationSnapshot.model_validate_json(_values(record)["payload"])
        except (KeyError, ValueError) as error:
            raise DependencyUnavailableError("retained operation payload is invalid") from error

    @staticmethod
    def _transfer_values(snapshot: TransferSnapshot) -> dict[str, str]:
        return {
            "identityDigest": snapshot.request_digest,
            "jobUid": str(snapshot.job_uid),
            "podUid": str(snapshot.pod_uid),
            "payload": snapshot.model_dump_json(by_alias=True),
        }

    @staticmethod
    def _transfer_header(
        action: str, value: TransferRegisterRequest | TransferSnapshot
    ) -> dict[str, object]:
        spec = value.spec
        return {
            "action": action,
            "transferRef": value.transfer_ref,
            "requestDigest": value.request_digest,
            "direction": spec.direction.value,
            "path": spec.path,
            "declaredSizeBytes": spec.declared_size_bytes,
            "authorizedMaxSizeBytes": spec.authorized_max_size_bytes,
            "contentSha256": spec.content_sha256,
            "overwritePolicy": spec.overwrite_policy,
        }

    @staticmethod
    def _validate_transfer_identity(
        retained: TransferSnapshot,
        request: TransferRegisterRequest,
        binding: JobBindingSnapshot,
    ) -> None:
        if (
            retained.request_digest != request.request_digest
            or retained.spec != request.spec
            or str(retained.job_uid) != str(binding.job_uid)
            or str(retained.pod_uid) != str(_pod_uid(binding))
        ):
            raise TransferIdentityConflictError()

    @staticmethod
    def _validate_operation_identity(
        retained: WorkspaceOperationSnapshot,
        request: WorkspaceInvokeRequest,
        frame_digest: str,
        binding: JobBindingSnapshot,
    ) -> None:
        if (
            retained.request_digest != request.request_digest
            or retained.stored_frame_digest != frame_digest
            or str(retained.binding.job_uid) != str(binding.job_uid)
            or str(retained.binding.pod_uid) != str(_pod_uid(binding))
        ):
            raise OperationIdentityConflictError()


def _spool_stream(stream: BinaryIO, maximum: int) -> tuple[Path, int, str]:
    descriptor, raw_path = tempfile.mkstemp(prefix="kcs-transfer-upload-")
    path = Path(raw_path)
    digest = hashlib.sha256()
    size = 0
    try:
        os.chmod(path, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            while chunk := stream.read(_COPY_CHUNK):
                if not isinstance(chunk, bytes):
                    raise TypeError("transfer stream must yield bytes")
                size += len(chunk)
                if size > maximum:
                    raise PayloadTooLargeError()
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        return path, size, digest.hexdigest()
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise


def _hash_file(path: Path) -> tuple[int, str]:
    size = 0
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_COPY_CHUNK):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _bounded_utf8(value: object) -> tuple[str, bool]:
    if not isinstance(value, str):
        raise DependencyUnavailableError("workspace output is not UTF-8 text")
    encoded = value.encode("utf-8")
    if len(encoded) <= 65536:
        return value, False
    return encoded[:65536].decode("utf-8", "ignore"), True


def _values(record: object) -> dict[str, str]:
    values = (
        record.get("values") if isinstance(record, Mapping) else getattr(record, "values", None)
    )
    if not isinstance(values, Mapping):
        raise DependencyUnavailableError("runtime record values are invalid")
    return {str(key): str(value) for key, value in values.items()}


def _pod_uid(binding: JobBindingSnapshot) -> UUID:
    if binding.pod_uid is None:
        raise StateConflictError("The Job has no immutable Pod binding")
    return binding.pod_uid


def _required_string(value: Mapping[str, Any], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise DependencyUnavailableError(f"workspace RPC result is missing {field}")
    return item


def _not_requested_action() -> ActionSnapshot:
    return ActionSnapshot(
        action_ref=None,
        request_digest=None,
        state=ActionState.NOT_REQUESTED,
        observed_at=None,
    )


def _raise_sidecar_error(code: str, identity_kind: str) -> None:
    if code == "TRANSFER_BYTES_MISMATCH":
        raise TransferBytesMismatchError()
    if code == "OVERWRITE_FORBIDDEN":
        raise OverwriteForbiddenError()
    if code == "UNSAFE_PATH":
        raise UnsafePathError()
    if code == "IDENTITY_CONFLICT":
        if identity_kind == "operation":
            raise OperationIdentityConflictError()
        raise TransferIdentityConflictError()
    if code == "TRANSFER_INDETERMINATE":
        raise TransferIndeterminateError()
    if code == "STATE_CONFLICT":
        raise StateConflictError()
    if code == "NOT_FOUND":
        raise JobNotFoundError()
    raise DependencyUnavailableError("workspace sidecar rejected the fixed RPC")
