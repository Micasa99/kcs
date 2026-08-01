"""Durable transfer and workspace-operation orchestration for the V2 provider."""

from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, BinaryIO, Protocol
from uuid import UUID, uuid4

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

    def compare_and_swap_runtime(
        self,
        kind: str,
        job_ref: str,
        identity: str,
        values: Mapping[str, str],
        *,
        expected_resource_version: str,
    ) -> object | None: ...


@dataclass(frozen=True, slots=True)
class TransferResult:
    snapshot: TransferSnapshot
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


@dataclass(frozen=True, slots=True)
class WorkspaceOperationResult:
    snapshot: WorkspaceOperationSnapshot
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
    confirm_delivery: Callable[[], None] | None = None

    def confirm(self) -> None:
        if self.confirm_delivery is not None:
            self.confirm_delivery()

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
        self._runtime_id = uuid4().hex
        self._active_dispatch_tokens: set[str] = set()
        self._active_dispatch_lock = Lock()

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
            record, retained_staging, changed = self._cas_transfer(record, staging)
            if not changed:
                if retained_staging.state is TransferState.COMPLETED:
                    if (
                        retained_staging.actual_size_bytes != actual_size
                        or retained_staging.actual_sha256 != actual_digest
                    ):
                        raise TransferBytesMismatchError()
                    return retained_staging
                if retained_staging.state is not TransferState.STAGING:
                    raise StateConflictError("The transfer changed while content was staged")
                raise DependencyUnavailableError("transfer staging is already in flight")
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
            record, snapshot, changed = self._cas_transfer(record, streaming)
            if not changed and snapshot.state not in {
                TransferState.STREAMING,
                TransferState.COMPLETED,
            }:
                raise StateConflictError("The transfer changed before collection")
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

            def confirm_delivery() -> None:
                self.confirm_collect_delivery(job_ref, transfer_ref, snapshot_ref)

            return VerifiedContent(
                content,
                size,
                digest,
                snapshot_ref,
                confirm_delivery,
            )
        except Exception:
            content.unlink(missing_ok=True)
            raise

    def inspect_transfer(self, job_ref: str, transfer_ref: str) -> TransferSnapshot:
        return self._transfer_snapshot(self._transfer_record(job_ref, transfer_ref))

    def confirm_collect_delivery(
        self, job_ref: str, transfer_ref: str, snapshot_ref: str
    ) -> TransferSnapshot:
        """Record that the verified direct response body finished leaving KCS."""
        record = self._transfer_record(job_ref, transfer_ref)
        snapshot = self._transfer_snapshot(record)
        if (
            snapshot.spec.direction is not TransferDirection.COLLECT_OUTPUT
            or snapshot.state is not TransferState.COMPLETED
            or snapshot.snapshot_ref != snapshot_ref
        ):
            raise StateConflictError("collect delivery confirmation does not match the snapshot")
        values = _values(record)
        retained = values.get("deliveryConfirmedSnapshotRef")
        if retained is not None and retained != snapshot_ref:
            raise TransferIdentityConflictError()
        if retained == snapshot_ref:
            return snapshot
        self._store.update_runtime(
            "transfer",
            job_ref,
            transfer_ref,
            {
                **values,
                "deliveryConfirmedSnapshotRef": snapshot_ref,
                "deliveryConfirmedAt": self._clock().isoformat(),
            },
        )
        return snapshot

    def drain_pre_authorized_collect(self, job_ref: str, transfer_ref: str) -> TransferSnapshot:
        """Prove a named collect was delivered before cancel closed normal admission."""
        record = self._transfer_record(job_ref, transfer_ref)
        snapshot = self._transfer_snapshot(record)
        if snapshot.spec.direction is not TransferDirection.COLLECT_OUTPUT:
            raise StateConflictError("cancel may drain only pre-authorized collect transfers")
        if snapshot.state not in {
            TransferState.COMPLETED,
            TransferState.INDETERMINATE,
        }:
            snapshot = self.reconcile_transfer(job_ref, transfer_ref)
            record = self._transfer_record(job_ref, transfer_ref)
        values = _values(record)
        delivered = values.get("deliveryConfirmedSnapshotRef")
        if (
            snapshot.state is TransferState.COMPLETED
            and snapshot.snapshot_ref is not None
            and delivered == snapshot.snapshot_ref
        ):
            return snapshot
        now = self._clock()
        indeterminate = snapshot.model_copy(
            update={
                "state": TransferState.INDETERMINATE,
                "content_available": False,
                "updated_at": now,
                "completed_at": snapshot.completed_at or now,
                "observed_at": now,
                "failure_reason": "cancel could not prove collect delivery before supervisor stop",
            }
        )
        self._store.update_runtime(
            "transfer",
            job_ref,
            transfer_ref,
            {**values, "payload": indeterminate.model_dump_json(by_alias=True)},
        )
        raise TransferIndeterminateError()

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
            record, retained, created = self._cas_transfer(record, accepted)
            if not created:
                current_action = retained.cancel_action
                if (
                    current_action.action_ref != request.cancel_ref
                    or current_action.request_digest != request.request_digest
                ):
                    raise TransferIdentityConflictError()
                if current_action.state is ActionState.SUCCEEDED:
                    return TransferResult(retained, created=False)
                if current_action.state is not ActionState.ACCEPTED:
                    raise StateConflictError("The transfer changed before cancellation")
                accepted = retained
        try:
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
        except TransferIndeterminateError:
            observed_at = self._clock()
            indeterminate = accepted.model_copy(
                update={
                    "state": TransferState.INDETERMINATE,
                    "content_available": False,
                    "completed_at": observed_at,
                    "updated_at": observed_at,
                    "observed_at": observed_at,
                    "failure_reason": "workspace transfer cancellation is indeterminate",
                    "cancel_action": accepted.cancel_action.model_copy(
                        update={
                            "state": ActionState.INDETERMINATE,
                            "observed_at": observed_at,
                        }
                    ),
                }
            )
            self._cas_transfer(record, indeterminate)
            raise
        except StateConflictError as error:
            truth = self._rpc_checked(
                binding,
                {"action": "inspectTransfer", "transferRef": transfer_ref},
            )
            if (
                truth.header.get("known") is True
                and truth.header.get("state") == "completed"
                and truth.header.get("requestDigest") == before.request_digest
            ):
                if (
                    truth.header.get("actualSizeBytes") != before.spec.declared_size_bytes
                    or truth.header.get("actualSha256") != before.spec.content_sha256
                ):
                    raise TransferBytesMismatchError() from error
                observed_at = self._clock()
                completed = accepted.model_copy(
                    update={
                        "state": TransferState.COMPLETED,
                        "actual_size_bytes": before.spec.declared_size_bytes,
                        "actual_sha256": before.spec.content_sha256,
                        "verified": True,
                        "content_available": True,
                        "completed_at": observed_at,
                        "updated_at": observed_at,
                        "observed_at": observed_at,
                        "failure_reason": None,
                        "cancel_action": accepted.cancel_action.model_copy(
                            update={"state": ActionState.FAILED, "observed_at": observed_at}
                        ),
                    }
                )
                self._cas_transfer(record, completed)
            raise
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
        _, retained, _ = self._cas_transfer(record, canceled)
        if retained.cancel_action.state is not ActionState.SUCCEEDED:
            raise DependencyUnavailableError("transfer cancellation changed concurrently")
        return TransferResult(retained, created)

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
            record, retained, changed = self._cas_transfer(record, accepted)
            if not changed:
                current_action = retained.discard_action
                if (
                    current_action.action_ref != discard_ref
                    or current_action.request_digest != request_digest
                ):
                    raise TransferIdentityConflictError()
                if current_action.state is ActionState.SUCCEEDED:
                    return retained
                if current_action.state is not ActionState.ACCEPTED:
                    raise StateConflictError("The transfer changed before discard")
                accepted = retained
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
        _, retained, _ = self._cas_transfer(record, discarded)
        if retained.discard_action.state is not ActionState.SUCCEEDED:
            raise DependencyUnavailableError("transfer discard changed concurrently")
        return retained

    def invoke_workspace(
        self, job_ref: str, request: WorkspaceInvokeRequest
    ) -> WorkspaceOperationResult:
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
                return WorkspaceOperationResult(retained, created=False)
            return WorkspaceOperationResult(
                self._recover_operation(existing, retained, binding), created=False
            )
        self._assert_binding_accepts_new_work(job_ref, binding)
        now = self._clock()
        dispatch_token = uuid4().hex
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
            "dispatchRuntime": self._runtime_id,
            "dispatchToken": dispatch_token,
            "dispatchPhase": "reserved",
            "payload": accepted.model_dump_json(by_alias=True),
        }
        record: object | None = None
        created = False
        self._activate_dispatch(dispatch_token)
        try:
            try:
                record, created = self._store.reserve_runtime(
                    "operation", request.operation_ref, job_ref, values
                )
            except IdentityDigestConflictError as error:
                raise OperationIdentityConflictError() from error
            retained = self._operation_snapshot(record)
            self._validate_operation_identity(retained, request, frame_digest, binding)
            if not created:
                return WorkspaceOperationResult(
                    self._recover_operation(record, retained, binding), created=False
                )
            record = self._claim_operation_dispatch(record, retained, dispatch_token)
            record, retained = self._prove_operation_dispatch_owner(record, dispatch_token)
            try:
                reply = self._rpc_checked(
                    binding,
                    {
                        "action": "invoke",
                        "operationRef": request.operation_ref,
                        "requestDigest": request.request_digest,
                        "dispatchToken": dispatch_token,
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
            return WorkspaceOperationResult(
                self._record_operation_result(record, retained, reply), created=True
            )
        finally:
            self._deactivate_dispatch(dispatch_token)
            if created and record is not None:
                self._relinquish_operation_dispatch(record, dispatch_token)

    def _claim_operation_dispatch(
        self,
        record: object,
        retained: WorkspaceOperationSnapshot,
        dispatch_token: str,
    ) -> object:
        values = _values(record)
        if (
            values.get("dispatchRuntime") != self._runtime_id
            or values.get("dispatchToken") != dispatch_token
            or values.get("dispatchPhase") != "reserved"
            or not self._dispatch_is_active(dispatch_token)
        ):
            raise OperationIndeterminateError()
        written = self._store.compare_and_swap_runtime(
            "operation",
            retained.job_ref,
            retained.operation_ref,
            {**values, "dispatchPhase": "dispatching"},
            expected_resource_version=_resource_version(record),
        )
        if written is not None:
            return written
        current = self._store.read_runtime("operation", retained.job_ref, retained.operation_ref)
        if current is None:
            raise JobNotFoundError()
        current_snapshot = self._operation_snapshot(current)
        if current_snapshot.state is OperationState.INDETERMINATE:
            raise OperationIndeterminateError()
        raise DependencyUnavailableError("workspace dispatch ownership changed")

    def _prove_operation_dispatch_owner(
        self, record: object, dispatch_token: str
    ) -> tuple[object, WorkspaceOperationSnapshot]:
        retained = self._operation_snapshot(record)
        current = self._store.read_runtime("operation", retained.job_ref, retained.operation_ref)
        if current is None:
            raise JobNotFoundError()
        current_snapshot = self._operation_snapshot(current)
        values = _values(current)
        if (
            values.get("dispatchRuntime") == self._runtime_id
            and values.get("dispatchToken") == dispatch_token
            and values.get("dispatchPhase") == "dispatching"
            and current_snapshot.state is OperationState.ACCEPTED
            and self._dispatch_is_active(dispatch_token)
        ):
            return current, current_snapshot
        if current_snapshot.state is OperationState.INDETERMINATE:
            raise OperationIndeterminateError()
        raise DependencyUnavailableError("workspace dispatch ownership was superseded")

    def _activate_dispatch(self, dispatch_token: str) -> None:
        with self._active_dispatch_lock:
            self._active_dispatch_tokens.add(dispatch_token)

    def _deactivate_dispatch(self, dispatch_token: str) -> None:
        with self._active_dispatch_lock:
            self._active_dispatch_tokens.discard(dispatch_token)

    def _dispatch_is_active(self, dispatch_token: str) -> bool:
        with self._active_dispatch_lock:
            return dispatch_token in self._active_dispatch_tokens

    def _relinquish_operation_dispatch(self, record: object, dispatch_token: str) -> None:
        claimed = self._operation_snapshot(record)
        current = self._store.read_runtime(
            "operation",
            claimed.job_ref,
            claimed.operation_ref,
        )
        if current is None:
            return
        retained = self._operation_snapshot(current)
        values = _values(current)
        if (
            retained.state is not OperationState.ACCEPTED
            or values.get("dispatchToken") != dispatch_token
            or values.get("dispatchPhase") not in {"reserved", "dispatching"}
        ):
            return
        self._store.compare_and_swap_runtime(
            "operation",
            retained.job_ref,
            retained.operation_ref,
            {**values, "dispatchPhase": "relinquished"},
            expected_resource_version=_resource_version(current),
        )

    def inspect_operation(self, job_ref: str, operation_ref: str) -> WorkspaceOperationSnapshot:
        record = self._store.read_runtime("operation", job_ref, operation_ref)
        if record is None:
            raise JobNotFoundError()
        return self._operation_snapshot(record)

    def reconcile_operation(self, job_ref: str, operation_ref: str) -> WorkspaceOperationSnapshot:
        record = self._store.read_runtime("operation", job_ref, operation_ref)
        if record is None:
            raise JobNotFoundError()
        retained = self._operation_snapshot(record)
        binding = self._live_binding(job_ref)
        if str(retained.binding.job_uid) != str(binding.job_uid) or str(
            retained.binding.pod_uid
        ) != str(_pod_uid(binding)):
            raise StateConflictError("Workspace operation binding is stale")
        if retained.state in {
            OperationState.SUCCEEDED,
            OperationState.FAILED,
            OperationState.INDETERMINATE,
        }:
            return retained
        return self._recover_operation(record, retained, binding)

    def reconcile_transfer(self, job_ref: str, transfer_ref: str) -> TransferSnapshot:
        record = self._transfer_record(job_ref, transfer_ref)
        retained = self._transfer_snapshot(record)
        binding = self._binding_for_existing(retained)
        pending_action = (
            retained.cancel_action.state is ActionState.ACCEPTED
            or retained.discard_action.state is ActionState.ACCEPTED
        )
        if retained.state in {
            TransferState.CANCELED,
            TransferState.DISCARDED,
            TransferState.FAILED,
            TransferState.INDETERMINATE,
        } or (retained.state is TransferState.COMPLETED and not pending_action):
            return retained
        for attempt in range(20):
            reply = self._rpc_checked(
                binding,
                {"action": "inspectTransfer", "transferRef": transfer_ref},
            )
            if reply.header.get("known") is True:
                if reply.header.get("requestDigest") != retained.request_digest:
                    raise TransferIdentityConflictError()
                return self._record_transfer_truth(record, retained, reply)
            if retained.state is TransferState.REGISTERED:
                return retained
            if attempt < 19:
                time.sleep(0.005)
                refreshed = self._transfer_record(job_ref, transfer_ref)
                refreshed_snapshot = self._transfer_snapshot(refreshed)
                if refreshed_snapshot != retained:
                    record, retained = refreshed, refreshed_snapshot
                    pending_action = (
                        retained.cancel_action.state is ActionState.ACCEPTED
                        or retained.discard_action.state is ActionState.ACCEPTED
                    )
                    if retained.state in {
                        TransferState.CANCELED,
                        TransferState.DISCARDED,
                        TransferState.FAILED,
                        TransferState.INDETERMINATE,
                    } or (retained.state is TransferState.COMPLETED and not pending_action):
                        return retained
                continue
            now = self._clock()
            indeterminate = TransferSnapshot.model_validate(
                {
                    **retained.model_dump(by_alias=False),
                    "state": TransferState.INDETERMINATE,
                    "content_available": False,
                    "snapshot_ref": None,
                    "updated_at": now,
                    "completed_at": now,
                    "observed_at": now,
                    "failure_reason": "the surviving workspace sidecar has no transfer truth",
                    "cancel_action": retained.cancel_action.model_copy(
                        update={"state": ActionState.INDETERMINATE, "observed_at": now}
                    )
                    if retained.cancel_action.state is ActionState.ACCEPTED
                    else retained.cancel_action,
                    "discard_action": retained.discard_action.model_copy(
                        update={"state": ActionState.INDETERMINATE, "observed_at": now}
                    )
                    if retained.discard_action.state is ActionState.ACCEPTED
                    else retained.discard_action,
                }
            )
            _, current, _ = self._cas_transfer(record, indeterminate)
            return current
        raise DependencyUnavailableError("workspace transfer recovery did not converge")

    def _record_transfer_truth(
        self,
        record: object,
        before: TransferSnapshot,
        reply: WorkspaceRpcReply,
    ) -> TransferSnapshot:
        state = reply.header.get("state")
        now = self._clock()
        if state == "completed":
            snapshot_ref = reply.header.get("snapshotRef")
            if before.spec.direction is TransferDirection.COLLECT_OUTPUT:
                snapshot_ref = _required_string(reply.header, "snapshotRef")
            elif snapshot_ref is not None:
                raise TransferBytesMismatchError()
            return self._complete_transfer(record, before, reply, snapshot_ref=snapshot_ref)
        updates: dict[str, object] = {
            "content_available": False,
            "updated_at": now,
            "completed_at": now,
            "observed_at": now,
            "failure_reason": None,
        }
        if state == "canceled" and before.cancel_action.state is ActionState.ACCEPTED:
            updates.update(
                {
                    "state": TransferState.CANCELED,
                    "cancel_action": before.cancel_action.model_copy(
                        update={"state": ActionState.SUCCEEDED, "observed_at": now}
                    ),
                }
            )
        elif state == "discarded" and before.discard_action.state is ActionState.ACCEPTED:
            updates.update(
                {
                    "state": TransferState.DISCARDED,
                    "snapshot_ref": None,
                    "discard_action": before.discard_action.model_copy(
                        update={"state": ActionState.SUCCEEDED, "observed_at": now}
                    ),
                }
            )
        else:
            raise TransferIndeterminateError()
        terminal = TransferSnapshot.model_validate({**before.model_dump(by_alias=False), **updates})
        _, retained, _ = self._cas_transfer(record, terminal)
        return retained

    def _recover_operation(
        self,
        record: object,
        retained: WorkspaceOperationSnapshot,
        binding: JobBindingSnapshot,
    ) -> WorkspaceOperationSnapshot:
        current = self._operation_snapshot(record)
        if current.state in {
            OperationState.SUCCEEDED,
            OperationState.FAILED,
            OperationState.INDETERMINATE,
        }:
            if current.state is OperationState.INDETERMINATE:
                raise OperationIndeterminateError()
            return current
        values = _values(record)
        dispatch_token = values.get("dispatchToken")
        dispatch_runtime = values.get("dispatchRuntime")
        if not isinstance(dispatch_token, str) or len(dispatch_token) != 32:
            raise DependencyUnavailableError("retained workspace dispatch token is invalid")
        if (
            dispatch_runtime == self._runtime_id
            and values.get("dispatchPhase") in {"reserved", "dispatching"}
            and self._dispatch_is_active(dispatch_token)
        ):
            return current
        if values.get("dispatchPhase") not in {
            "reserved",
            "dispatching",
            "relinquished",
        }:
            raise DependencyUnavailableError("retained workspace dispatch phase is invalid")
        reply = self._rpc_checked(
            binding,
            {
                "action": "fenceOperation",
                "operationRef": current.operation_ref,
                "requestDigest": current.request_digest,
                "dispatchToken": dispatch_token,
            },
            identity_kind="operation",
        )
        if reply.header.get("known") is True:
            if reply.header.get("requestDigest") != current.request_digest:
                raise OperationIdentityConflictError()
            return self._record_operation_result(record, current, reply)
        if (
            reply.header.get("known") is not False
            or reply.header.get("fenced") is not True
            or reply.header.get("requestDigest") != current.request_digest
        ):
            raise DependencyUnavailableError("workspace operation fence was not confirmed")
        now = self._clock()
        indeterminate = WorkspaceOperationSnapshot.model_validate(
            {
                **current.model_dump(by_alias=False),
                "state": OperationState.INDETERMINATE,
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "inline_result_size": None,
                "inline_result_digest": None,
                "inline_result": None,
                "result_transfer_ref": None,
                "finished_at": now,
                "observed_at": now,
                "failure_reason": "the surviving workspace sidecar has no operation truth",
            }
        )
        written = self._store.compare_and_swap_runtime(
            "operation",
            current.job_ref,
            current.operation_ref,
            {
                **values,
                "dispatchPhase": "indeterminate",
                "payload": indeterminate.model_dump_json(by_alias=True),
            },
            expected_resource_version=_resource_version(record),
        )
        if written is None:
            refreshed = self._store.read_runtime(
                "operation", current.job_ref, current.operation_ref
            )
            if refreshed is None:
                raise JobNotFoundError()
            refreshed_snapshot = self._operation_snapshot(refreshed)
            if refreshed_snapshot.state is not OperationState.INDETERMINATE:
                return refreshed_snapshot
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
        try:
            stdout, stdout_truncated = _bounded_utf8(header.get("stdout", ""))
            stderr, stderr_truncated = _bounded_utf8(header.get("stderr", ""))
            exit_code = header.get("exitCode")
            if type(exit_code) is not int:
                raise ValueError("workspace result exitCode is invalid")
            state_value = header.get("state")
            if state_value not in {"succeeded", "failed"}:
                raise ValueError("workspace result state is invalid")
            inline = header.get("inlineResult")
            result_transfer = header.get("resultTransferRef")
            if inline is not None and not isinstance(inline, dict):
                raise ValueError("workspace inline result must be an object")
            if inline is not None and result_transfer is not None:
                raise ValueError("workspace result locations are ambiguous")
            encoded = canonical_bytes(inline) if inline is not None else None
            if encoded is not None and len(encoded) > 65536:
                raise PayloadTooLargeError("Workspace inline result exceeds 64 KiB")
            now = self._clock()
            result = WorkspaceOperationSnapshot.model_validate(
                {
                    **before.model_dump(by_alias=False),
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
        except (KcsV2Error, TypeError, ValueError) as error:
            now = self._clock()
            indeterminate = WorkspaceOperationSnapshot.model_validate(
                {
                    **before.model_dump(by_alias=False),
                    "state": OperationState.INDETERMINATE,
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "",
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                    "inline_result_size": None,
                    "inline_result_digest": None,
                    "inline_result": None,
                    "result_transfer_ref": None,
                    "started_at": before.started_at or now,
                    "finished_at": now,
                    "observed_at": now,
                    "failure_reason": "workspace returned an invalid terminal result",
                }
            )
            retained = self._cas_operation(record, indeterminate, dispatch_phase="indeterminate")
            if retained.state is not OperationState.INDETERMINATE:
                return retained
            raise DependencyUnavailableError(
                "workspace returned an invalid terminal result"
            ) from error
        retained = self._cas_operation(record, result, dispatch_phase=result.state.value)
        if retained.state is OperationState.INDETERMINATE:
            raise OperationIndeterminateError()
        return retained

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
        _, retained, changed = self._cas_transfer(record, completed)
        if changed:
            return retained
        if retained.state is TransferState.COMPLETED:
            if (
                retained.actual_size_bytes != before.spec.declared_size_bytes
                or retained.actual_sha256 != before.spec.content_sha256
                or retained.snapshot_ref != snapshot_ref
            ):
                raise TransferBytesMismatchError()
            return retained
        raise StateConflictError("The transfer reached a conflicting terminal state")

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

    def _cas_transfer(
        self, record: object, snapshot: TransferSnapshot
    ) -> tuple[object, TransferSnapshot, bool]:
        written = self._store.compare_and_swap_runtime(
            "transfer",
            snapshot.job_ref,
            snapshot.transfer_ref,
            {**_values(record), "payload": snapshot.model_dump_json(by_alias=True)},
            expected_resource_version=_resource_version(record),
        )
        if written is not None:
            return written, self._transfer_snapshot(written), True
        current = self._store.read_runtime("transfer", snapshot.job_ref, snapshot.transfer_ref)
        if current is None:
            raise JobNotFoundError()
        return current, self._transfer_snapshot(current), False

    def _cas_operation(
        self,
        record: object,
        snapshot: WorkspaceOperationSnapshot,
        *,
        dispatch_phase: str,
    ) -> WorkspaceOperationSnapshot:
        resource_version = _resource_version(record)
        written = self._store.compare_and_swap_runtime(
            "operation",
            snapshot.job_ref,
            snapshot.operation_ref,
            {
                **_values(record),
                "dispatchPhase": dispatch_phase,
                "payload": snapshot.model_dump_json(by_alias=True),
            },
            expected_resource_version=resource_version,
        )
        if written is not None:
            return self._operation_snapshot(written)
        current = self._store.read_runtime("operation", snapshot.job_ref, snapshot.operation_ref)
        if current is None:
            raise JobNotFoundError()
        retained = self._operation_snapshot(current)
        if retained.state in {
            OperationState.SUCCEEDED,
            OperationState.FAILED,
            OperationState.INDETERMINATE,
        }:
            return retained
        raise DependencyUnavailableError("workspace operation changed concurrently")

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


def _resource_version(record: object) -> str:
    value = (
        record.get("resource_version")
        if isinstance(record, Mapping)
        else getattr(record, "resource_version", None)
    )
    if not isinstance(value, str) or not value:
        raise DependencyUnavailableError("runtime record resourceVersion is absent")
    return value


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
    if code == "OPERATION_INDETERMINATE":
        raise OperationIndeterminateError()
    if code == "STATE_CONFLICT":
        raise StateConflictError()
    if code == "NOT_FOUND":
        raise JobNotFoundError()
    raise DependencyUnavailableError("workspace sidecar rejected the fixed RPC")
