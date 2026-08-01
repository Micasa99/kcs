"""Provider orchestration for the first executable KCS V2 Job journey.

The provider is deliberately limited to physical Kubernetes facts.  It reserves a
stable create identity before dispatch, reconciles a possibly lost create response,
and treats the first observed Pod UID as immutable binding reality.
"""
# ruff: noqa: E501

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, overload
from uuid import UUID

from .canonical import canonical_digest
from .contracts import (
    ActionSnapshot,
    ActionState,
    AgentObservedResources,
    AgentRequestedResources,
    AgentRoleSnapshot,
    AgentStartRequest,
    CancelJobRequest,
    CancelSpec,
    CleanupObservation,
    CleanupState,
    CreateJobRequest,
    CredentialGrantMetadata,
    CredentialGrantSnapshot,
    CredentialObservation,
    CredentialState,
    FinalizeJobRequest,
    FinalizeSpec,
    GenerationSnapshot,
    JobBindingSnapshot,
    JobBindingSnapshotList,
    JobBindingState,
    JobTombstone,
    LogContainer,
    OperationState,
    ProviderTerminalState,
    RoleLogs,
    RoleState,
    RunnerState,
    TransferCancelRequest,
    TransferObservation,
    TransferRegisterRequest,
    TransferSnapshot,
    TransferState,
    WorkspaceInvokeRequest,
    WorkspaceObservedResources,
    WorkspaceOperationSnapshot,
    WorkspaceRequestedResources,
    WorkspaceRoleSnapshot,
)
from .errors import (
    CredentialActiveError,
    CredentialDestroyFailedError,
    CredentialExpiredError,
    DependencyTimeoutError,
    DependencyUnavailableError,
    DigestMismatchError,
    GrantIdentityConflictError,
    IdentityDigestConflict,
    IllegalGenerationError,
    InvalidCursorError,
    InvalidPageTokenError,
    InvalidRequestError,
    JobNotFoundError,
    KcsV2Error,
    OperationIndeterminateError,
    PayloadTooLargeError,
    ReplacementPodError,
    StaleBindingError,
    StaleCursorError,
    StalePageTokenError,
    StateConflictError,
    TombstonedError,
    TransferIndeterminateError,
)
from .lifecycle import (
    LifecycleClaim,
    LifecycleGate,
    ReconcileReport,
    action_snapshot,
    phase_payload,
    read_phase,
)
from .renderer import credential_secret_name
from .transport import (
    AgentRpcResponse,
    AgentRpcTransportProtocol,
    WorkspaceRpcTransportProtocol,
)
from .workspace_runtime import (
    TransferResult,
    VerifiedContent,
    WorkspaceOperationResult,
    WorkspaceRuntime,
)

EMPTY_OBJECT_DIGEST = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
DEFAULT_LOG_LIMIT_BYTES = 65536
MAX_LOG_LIMIT_BYTES = 1048576
DEFAULT_TOMBSTONE_TTL_SECONDS = 604800
DEFAULT_DELETE_POLL_ATTEMPTS = 20
DEFAULT_DELETE_POLL_INTERVAL_SECONDS = 0.25
_MISSING = object()
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CLEANUP_TARGETS = frozenset(
    {CredentialState.DESTROYED, CredentialState.REVOKED, CredentialState.EXPIRED}
)
_OPERATION_ACTIVE_STATES = frozenset({"accepted", "running"})
_OPERATION_TERMINAL_STATES = frozenset({"succeeded", "failed", "indeterminate"})
_TRANSFER_TERMINAL_STATES = frozenset(
    {"completed", "canceled", "discarded", "failed", "indeterminate"}
)


class V2JobRendererProtocol(Protocol):
    """The pure renderer seam used by orchestration."""

    def job_ref(self, request: CreateJobRequest) -> str: ...

    def render(self, request: CreateJobRequest) -> object: ...


class V2KubeAdapterProtocol(Protocol):
    """Namespace-bound Kubernetes operations used by this provider."""

    def create_job(self, job: object) -> object: ...

    def read_job(self, job_ref: str) -> object | None: ...

    def delete_job(self, job_ref: str) -> None: ...

    def list_job_pods(self, job_ref: str, job_uid: str | None = None) -> Sequence[object]: ...

    def read_role_logs(
        self,
        job_ref: str,
        pod_uid: str,
        container: str,
        cursor: str | None,
        limit_bytes: int,
    ) -> object: ...

    def create_secret(self, body: object) -> object: ...

    def read_secret(self, name: str) -> object | None: ...

    def delete_secret(self, name: str) -> bool: ...


class V2JobStoreProtocol(Protocol):
    """Durable create/tombstone record operations used by this provider."""

    def reserve_create(
        self,
        provider_request_id: str,
        spec_digest: str,
        job_ref: str,
        spec_payload: Mapping[str, object],
    ) -> object: ...

    def read_create(self, provider_request_id: str) -> object | None: ...

    def read_by_job_ref(self, job_ref: str) -> object | None: ...

    def mark_created(self, provider_request_id: str, job_uid: str) -> object: ...

    def bind_first_pod(self, provider_request_id: str, pod_uid: str) -> object: ...

    def mark_indeterminate(self, provider_request_id: str, reason: str) -> object: ...

    def mark_deleted(self, provider_request_id: str, **values: object) -> object: ...

    def list_create(self) -> Sequence[object]: ...

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

    def delete_runtime_records(self, job_ref: str) -> int: ...

    def has_runtime_records(self, job_ref: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class CreateResult:
    """A create snapshot plus the status distinction needed by the HTTP route."""

    snapshot: JobBindingSnapshot
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


@dataclass(frozen=True, slots=True)
class FinalizeResult:
    """A finalize snapshot plus the atomic slot reservation outcome."""

    snapshot: JobBindingSnapshot
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


@dataclass(frozen=True, slots=True)
class CancelResult:
    """A cancel snapshot plus the durable slot reservation outcome."""

    snapshot: JobBindingSnapshot
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


@dataclass(frozen=True, slots=True)
class CredentialGrantResult:
    snapshot: CredentialGrantSnapshot
    created: bool


@dataclass(frozen=True, slots=True)
class JobListQuery:
    page_token: str | None = None
    page_size: int = DEFAULT_PAGE_SIZE
    provider_request_id: str | None = None
    subject_ref: str | None = None
    states: tuple[JobBindingState, ...] = ()
    created_after: datetime | None = None
    include_deleted: bool = False


class V2JobProvider:
    """Coordinate durable identities with Kubernetes Job/Pod reality."""

    def __init__(
        self,
        kube: V2KubeAdapterProtocol,
        store: V2JobStoreProtocol,
        renderer: V2JobRendererProtocol,
        *,
        namespace: str | None = None,
        clock: Callable[[], datetime] | None = None,
        tombstone_ttl_seconds: int = DEFAULT_TOMBSTONE_TTL_SECONDS,
        delete_poll_attempts: int = DEFAULT_DELETE_POLL_ATTEMPTS,
        delete_poll_interval_seconds: float = DEFAULT_DELETE_POLL_INTERVAL_SECONDS,
        sleeper: Callable[[float], None] | None = None,
        transport: AgentRpcTransportProtocol | None = None,
        workspace_transport: WorkspaceRpcTransportProtocol | None = None,
    ) -> None:
        if delete_poll_attempts < 1:
            raise ValueError("delete_poll_attempts must be positive")
        if delete_poll_interval_seconds < 0:
            raise ValueError("delete_poll_interval_seconds cannot be negative")
        self._kube = kube
        self._store = store
        self._renderer = renderer
        resolved_namespace = namespace or getattr(kube, "namespace", None)
        if not resolved_namespace:
            raise ValueError("provider requires the V2 Kubernetes namespace")
        self._namespace = str(resolved_namespace)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._tombstone_ttl = timedelta(seconds=tombstone_ttl_seconds)
        self._delete_poll_attempts = delete_poll_attempts
        self._delete_poll_interval_seconds = delete_poll_interval_seconds
        self._sleeper = sleeper or time.sleep
        self._transport = transport
        self._workspace_transport = workspace_transport
        self._lifecycle = LifecycleGate(store)
        self._startup_reconcile = False
        self._workspace_runtime = WorkspaceRuntime(
            store,
            workspace_transport,
            self._live_binding,
            self._assert_accepting_workspace_work,
            self._now,
        )
        self.reconcile_credentials()

    def reconcile_credentials(self) -> int:
        """Reconcile retained grant intent against namespace-bound Secret reality."""
        method = getattr(self._store, "list_runtime", None)
        if not callable(method):
            return 0
        try:
            records = method("credential", None)
        except TypeError:
            return 1
        indeterminate = 0
        for record in records:
            try:
                grant = self._grant_snapshot(record)
                read_secret = getattr(self._kube, "read_secret", None)
                if callable(read_secret):
                    present = read_secret(credential_secret_name(grant.job_ref)) is not None
                    if grant.secret_present is True and not present:
                        target = self._cleanup_target(record)
                        if target is None:
                            self._update_grant(
                                record,
                                state=CredentialState.INDETERMINATE,
                                secret_present=False,
                                reason="Secret disappeared without a retained destruction phase",
                            )
                            continue
                    elif grant.secret_present is False and present:
                        updated = self._update_grant(
                            record,
                            state=CredentialState.INDETERMINATE,
                            secret_present=True,
                            reason="Secret remains after retained absence observation",
                        )
                        updated_record = self._store.read_runtime(
                            "credential", updated.job_ref, updated.credential_grant_ref
                        )
                        if updated_record is not None:
                            self._destroy_grant(updated_record, CredentialState.REVOKED)
                        continue
                self._expire_grant_if_needed(grant)
            except Exception:
                indeterminate += 1
        return indeterminate

    def reconcile_all(self) -> ReconcileReport:
        """Repeatably recover bindings and lifecycle actions from provider reality."""
        report = ReconcileReport()
        self._startup_reconcile = True
        try:
            report.indeterminate += self.reconcile_credentials()
            for record in self._store.list_create():
                report.scanned += 1
                job_ref = str(_field(record, "job_ref"))
                try:
                    lifecycle = self._lifecycle.inspect(job_ref)
                    if lifecycle is not None and lifecycle["activeClaims"]:

                        def terminal_truth(
                            intent: Mapping[str, object], retained_job_ref: str = job_ref
                        ) -> bool:
                            return self._lifecycle_intent_has_terminal_truth(
                                retained_job_ref, intent
                            )

                        remaining = self._lifecycle.release_proven_claims(
                            job_ref,
                            terminal_truth,
                        )
                        lifecycle = self._lifecycle.inspect(job_ref)
                        if remaining:
                            report.indeterminate += 1
                            continue
                    close = lifecycle.get("close") if lifecycle is not None else None
                    close_kind = close.get("kind") if isinstance(close, Mapping) else None
                    if (
                        lifecycle is not None
                        and lifecycle["gate"] == "closing"
                        and close_kind in {"cancel", "finalize"}
                        and not self._runtime_records(str(close_kind), job_ref)
                    ):
                        if not isinstance(close, Mapping):
                            raise DependencyUnavailableError(
                                "lifecycle close identity is unavailable"
                            )
                        self._resume_lifecycle_close(job_ref, close)
                        report.reconciled += 1
                        continue
                    self._reconcile_record(record, report)
                except Exception:
                    report.indeterminate += 1
        finally:
            self._startup_reconcile = False
            consume_errors = getattr(self._store, "consume_scan_errors", None)
            if callable(consume_errors):
                report.indeterminate += int(consume_errors())
        return report

    def _reconcile_record(self, record: object, report: ReconcileReport) -> None:
        job_ref = str(_field(record, "job_ref"))
        if _is_deleted(record) or str(_field(record, "state", "")) == "deleting":
            if str(_field(record, "cleanup_state", "pending")) != "complete":
                self.delete(
                    job_ref,
                    str(_field(record, "delete_ref")),
                    str(_field(record, "delete_request_digest")),
                )
                report.deleted += 1
            return
        if _field(record, "job_uid", None) is None:
            spec_payload = _field(record, "spec_payload", None)
            if not isinstance(spec_payload, Mapping):
                raise DependencyUnavailableError(
                    "reserved create has no replayable retained specification"
                )
            self.create(
                CreateJobRequest.model_validate(
                    {
                        "providerRequestId": str(_field(record, "provider_request_id")),
                        "specDigest": str(_field(record, "spec_digest")),
                        "spec": dict(spec_payload),
                    }
                )
            )
            report.reconciled += 1
            return
        binding = self.inspect(job_ref)
        self._validate_job_annotations(record)
        cancellations = self._runtime_records("cancel", job_ref)
        if cancellations:
            values = _runtime_values(cancellations[-1])
            cancel_spec = CancelSpec.model_validate_json(values["requestSpec"])
            self.cancel(
                job_ref,
                CancelJobRequest(
                    cancel_ref=values["cancelRef"],
                    request_digest=values["identityDigest"],
                    spec=cancel_spec,
                ),
            )
            report.reconciled += 1
            return
        finalizations = self._runtime_records("finalize", job_ref)
        lifecycle = self._lifecycle.inspect(job_ref)
        close = lifecycle.get("close") if lifecycle is not None else None
        finalize_close_incomplete = (
            isinstance(close, Mapping)
            and close.get("kind") == "finalize"
            and lifecycle is not None
            and lifecycle.get("gate") != "closed"
        )
        if finalizations and (
            _finalize_phase(finalizations[-1]) != "succeeded" or finalize_close_incomplete
        ):
            values = _runtime_values(finalizations[-1])
            finalize_spec = FinalizeSpec.model_validate_json(values["requestSpec"])
            self.finalize(
                job_ref,
                FinalizeJobRequest(
                    finalize_ref=values["finalizeRef"],
                    request_digest=values["identityDigest"],
                    spec=finalize_spec,
                ),
            )
            report.reconciled += 1
            return
        for operation in self._store.list_runtime("operation", job_ref):
            operation_state = self._workspace_runtime.inspect_operation(
                job_ref, str(_field(operation, "identity"))
            ).state
            if operation_state in {OperationState.ACCEPTED, OperationState.RUNNING}:
                operation_ref = str(_field(operation, "identity"))
                claim = self._claim_mutation(binding, "operation-reconcile", operation_ref)
                try:
                    self._workspace_runtime.reconcile_operation(job_ref, operation_ref)
                finally:
                    claim.release()
                report.reconciled += 1
        for transfer in self._store.list_runtime("transfer", job_ref):
            transfer_state = self._workspace_runtime.inspect_transfer(
                job_ref, str(_field(transfer, "identity"))
            ).state
            if transfer_state not in {
                TransferState.COMPLETED,
                TransferState.CANCELED,
                TransferState.DISCARDED,
                TransferState.FAILED,
                TransferState.INDETERMINATE,
            }:
                transfer_ref = str(_field(transfer, "identity"))
                claim = self._claim_mutation(binding, "transfer-reconcile", transfer_ref)
                try:
                    self._workspace_runtime.reconcile_transfer(job_ref, transfer_ref)
                finally:
                    claim.release()
                report.reconciled += 1

    def create(self, request: CreateJobRequest) -> CreateResult:
        """Reserve before create and reconcile a response lost after API acceptance."""

        spec_payload = request.spec.digest_payload()
        if not hmac.compare_digest(request.spec_digest, canonical_digest(spec_payload)):
            raise DigestMismatchError

        rendered_job = self._renderer.render(request)
        job_ref = self._renderer.job_ref(request)
        reservation = self._reserve_create(request, job_ref, spec_payload)
        record = _field(reservation, "record", reservation)
        created = bool(_field(reservation, "created", False))
        self._raise_if_record_conflicts(record, request.provider_request_id, request.spec_digest)
        if _is_deleted(record):
            raise TombstonedError(_tombstone_payload(record))
        if str(_field(record, "state", "")) == "deleting":
            return CreateResult(snapshot=self.inspect(job_ref), created=False)
        if _optional_text(record, "indeterminate_reason") is not None:
            return CreateResult(snapshot=self.inspect(job_ref), created=False)

        job = self._read_job(job_ref)
        if job is None:
            if _field(record, "job_uid", None) is not None:
                reason = "the retained Job is no longer observable"
                record = self._mark_indeterminate(record, reason)
                return CreateResult(snapshot=self._missing_job_snapshot(record), created=False)
            job = self._create_or_reconcile_job(rendered_job, job_ref)
        job_uid = _required_text(job, "metadata", "uid")
        self._store.mark_created(request.provider_request_id, job_uid)
        snapshot = self.inspect(job_ref)
        return CreateResult(snapshot=snapshot, created=created)

    def inspect(self, job_ref: str) -> JobBindingSnapshot:
        """Rebuild a binding solely from its durable record and current Job/Pods."""

        record = self._store.read_by_job_ref(job_ref)
        if record is None:
            raise JobNotFoundError
        if _is_deleted(record):
            raise TombstonedError(_tombstone_payload(record))
        deleting = str(_field(record, "state", "")) == "deleting"

        job = self._read_job(job_ref)
        if job is None:
            if _field(record, "job_uid", None) is None:
                raise DependencyUnavailableError(
                    "The create identity is reserved but no Job UID is observable"
                )
            if deleting:
                return self._deleting_snapshot(self._missing_job_snapshot(record), record)
            record = self._mark_indeterminate(record, "the retained Job is no longer observable")
            return self._missing_job_snapshot(record)

        actual_job_uid = _required_text(job, "metadata", "uid")
        retained_job_uid = _field(record, "job_uid", None)
        if deleting:
            pods = tuple(self._list_job_pods(job_ref, actual_job_uid))
            pod_uids = tuple(_required_text(pod, "metadata", "uid") for pod in pods)
            unique_pod_uids = set(pod_uids)
            retained_pod_uid = _field(record, "pod_uid", None)
            replacement_reason: str | None = None
            if retained_job_uid is not None and str(retained_job_uid) != actual_job_uid:
                replacement_reason = "Job UID changed"
            elif len(pods) > 1 or len(unique_pod_uids) > 1:
                replacement_reason = "multiple Pod identities observed for one Job"
            elif retained_pod_uid is not None and pod_uids and str(retained_pod_uid) != pod_uids[0]:
                replacement_reason = "replacement Pod UID differs from the immutable binding"
            elif retained_pod_uid is not None and not pods:
                replacement_reason = "the immutable Pod is no longer observable"
            snapshot = self._snapshot(record, job, pods, replacement_reason=replacement_reason)
            return self._deleting_snapshot(snapshot, record)
        if retained_job_uid is not None and str(retained_job_uid) != actual_job_uid:
            reason = "Job UID changed"
            record = self._mark_indeterminate(record, reason)
            return self._snapshot(record, job, (), replacement_reason=reason)
        if retained_job_uid is None:
            record = self._store.mark_created(
                str(_field(record, "provider_request_id")), actual_job_uid
            )

        pods = tuple(self._list_job_pods(job_ref, actual_job_uid))
        retained_pod_uid = _field(record, "pod_uid", None)
        pod_uids = tuple(_required_text(pod, "metadata", "uid") for pod in pods)
        unique_pod_uids = set(pod_uids)
        replacement_reason = _optional_text(record, "indeterminate_reason")
        if replacement_reason is not None:
            pass
        elif len(pods) > 1 or len(unique_pod_uids) > 1:
            replacement_reason = "multiple Pod identities observed for one Job"
        elif retained_pod_uid is not None and pod_uids and str(retained_pod_uid) != pod_uids[0]:
            replacement_reason = "replacement Pod UID differs from the immutable binding"
        elif retained_pod_uid is not None and not pods:
            replacement_reason = "the immutable Pod is no longer observable"
        elif retained_pod_uid is None and len(pods) == 1:
            try:
                record = self._store.bind_first_pod(
                    str(_field(record, "provider_request_id")), pod_uids[0]
                )
            except ReplacementPodError:
                replacement_reason = "Pod binding changed during reconciliation"

        if replacement_reason is not None:
            record = self._mark_indeterminate(record, replacement_reason)

        snapshot = self._snapshot(record, job, pods, replacement_reason=replacement_reason)
        return self._deleting_snapshot(snapshot, record) if deleting else snapshot

    def list_jobs(self, query: JobListQuery | None = None) -> JobBindingSnapshotList:
        """Return one stable-key-merge page over live bindings and tombstones."""

        query = query or JobListQuery()
        if not 1 <= query.page_size <= MAX_PAGE_SIZE:
            raise InvalidRequestError("pageSize must be between 1 and 200")
        query_digest = self._list_query_digest(query)
        offset = self._page_offset(query.page_token, query_digest)

        records = list(self._store.list_create())
        entries: list[tuple[datetime, str, JobBindingSnapshot | JobTombstone]] = []
        for record in records:
            if (
                query.provider_request_id is not None
                and str(_field(record, "provider_request_id")) != query.provider_request_id
            ):
                continue
            spec_payload = _field(record, "spec_payload", {})
            if (
                query.subject_ref is not None
                and _field(spec_payload, "subjectRef", None) != query.subject_ref
            ):
                continue
            created_at = _as_datetime(_field(record, "created_at"), self._now())
            if query.created_after is not None and created_at <= query.created_after:
                continue
            job_ref = str(_field(record, "job_ref"))
            if _is_deleted(record):
                if not query.include_deleted:
                    continue
                value: JobBindingSnapshot | JobTombstone = _as_tombstone(record)
                state = JobBindingState.DELETED
            else:
                if _field(record, "job_uid", None) is None:
                    job = self._read_job(job_ref)
                    if job is None:
                        continue
                    record = self._store.mark_created(
                        str(_field(record, "provider_request_id")),
                        _required_text(job, "metadata", "uid"),
                    )
                value = self.inspect(job_ref)
                state = value.binding_state
            if query.states and state not in query.states:
                continue
            entries.append((created_at, job_ref, value))

        entries.sort(key=lambda entry: (entry[0], entry[1]))
        page = entries[offset : offset + query.page_size]
        next_offset = offset + len(page)
        next_token = None
        if next_offset < len(entries):
            next_token = _encode_token(
                {
                    "kind": "page",
                    "namespace": self._namespace,
                    "query": query_digest,
                    "offset": next_offset,
                }
            )
        return JobBindingSnapshotList(
            items=[value for _, _, value in page if isinstance(value, JobBindingSnapshot)],
            tombstones=[value for _, _, value in page if isinstance(value, JobTombstone)],
            next_page_token=next_token,
            observed_at=self._now(),
        )

    def logs(
        self,
        job_ref: str,
        role: LogContainer | str,
        cursor: str | None = None,
        limit_bytes: int = DEFAULT_LOG_LIMIT_BYTES,
    ) -> RoleLogs:
        """Read a bounded page from one explicit role on the immutable Pod."""

        try:
            container = role if isinstance(role, LogContainer) else LogContainer(role)
        except ValueError as error:
            raise InvalidRequestError("container must be 'agent' or 'workspace'") from error
        if not 1 <= limit_bytes <= MAX_LOG_LIMIT_BYTES:
            raise InvalidRequestError("limitBytes must be between 1 and 1048576")

        snapshot = self.inspect(job_ref)
        if snapshot.pod_uid is None:
            raise StateConflictError("The Job does not yet have an immutable Pod binding")

        page = self._read_role_logs(
            job_ref,
            str(snapshot.pod_uid),
            container.value,
            cursor,
            limit_bytes,
        )
        role_snapshot = snapshot.agent if container is LogContainer.AGENT else snapshot.workspace
        return RoleLogs(
            job_ref=job_ref,
            job_uid=snapshot.job_uid,
            pod_uid=snapshot.pod_uid,
            container=container,
            input_cursor=cursor,
            start_cursor=str(_field(page, "start_cursor")),
            next_cursor=_optional_text(page, "next_cursor"),
            content=str(_field(page, "content", "")),
            truncated=bool(_field(page, "truncated", False)),
            terminal=bool(
                _field(
                    page,
                    "terminal",
                    snapshot.binding_state
                    in {
                        JobBindingState.SUCCEEDED,
                        JobBindingState.FAILED,
                        JobBindingState.CANCELED,
                    },
                )
            ),
            container_id=_optional_text(page, "container_id")
            or (role_snapshot.container_id if role_snapshot is not None else None),
            observed_at=self._now(),
        )

    def grant_credential(
        self, job_ref: str, metadata: CredentialGrantMetadata, raw_bytes: bytes
    ) -> CredentialGrantSnapshot:
        return self.grant_credential_result(job_ref, metadata, raw_bytes).snapshot

    def grant_credential_result(
        self, job_ref: str, metadata: CredentialGrantMetadata, raw_bytes: bytes
    ) -> CredentialGrantResult:
        """Persist a non-secret grant then create the fixed agent-only Secret."""
        self.reconcile_credentials()
        self._assert_accepting_workspace_work(job_ref)
        if len(raw_bytes) > 65536:
            raise PayloadTooLargeError()
        if not hmac.compare_digest(
            hashlib.sha256(raw_bytes).hexdigest(), metadata.credential_sha256
        ):
            raise DigestMismatchError()
        if not hmac.compare_digest(
            canonical_digest(metadata.digest_payload()), metadata.grant_metadata_digest
        ):
            raise DigestMismatchError()
        binding = self._live_binding(job_ref)
        if str(binding.job_uid) != str(metadata.job_uid) or str(binding.pod_uid) != str(
            metadata.pod_uid
        ):
            raise StaleBindingError()
        identity_digest = hashlib.sha256(
            f"{metadata.grant_metadata_digest}:{metadata.credential_sha256}".encode()
        ).hexdigest()
        existing = self._store.read_runtime("credential", job_ref, metadata.credential_grant_ref)
        if existing is not None:
            if _runtime_values(existing).get("identityDigest") != identity_digest:
                raise GrantIdentityConflictError()
            grant = self._grant_snapshot(existing)
            self._expire_grant_if_needed(grant)
            if grant.state is not CredentialState.ACCEPTED:
                return CredentialGrantResult(
                    self.inspect_credential_grant(job_ref, metadata.credential_grant_ref), False
                )
            record = existing
            created = False
        else:
            active = [
                self._grant_snapshot(item)
                for item in self._store.list_runtime("credential", job_ref)
            ]
            if any(item.secret_present is not False for item in active):
                raise CredentialActiveError()
            values = self._grant_values(
                job_ref,
                metadata,
                state=CredentialState.ACCEPTED,
                identity_digest=identity_digest,
            )
            record, created = self._store.reserve_runtime(
                "credential", metadata.credential_grant_ref, job_ref, values
            )
            if not created:
                retained = self._grant_snapshot(record)
                if retained.state is not CredentialState.ACCEPTED:
                    return CredentialGrantResult(retained, False)
        if not created and self._lifecycle.intent_active(
            job_ref, "credential-grant", metadata.credential_grant_ref
        ):
            return CredentialGrantResult(self._grant_snapshot(record), False)
        claim = self._claim_mutation(binding, "credential-grant", metadata.credential_grant_ref)
        try:
            current = self._store.read_runtime("credential", job_ref, metadata.credential_grant_ref)
            if current is None:
                raise DependencyUnavailableError("credential reservation disappeared")
            record = current
            try:
                self._kube.create_secret(self._credential_secret(job_ref, metadata, raw_bytes))
            except Exception as error:
                raise DependencyUnavailableError(
                    "Kubernetes did not accept the credential projection"
                ) from error
            return CredentialGrantResult(
                self._update_grant(record, state=CredentialState.AVAILABLE, secret_present=True),
                created,
            )
        finally:
            claim.release()

    def register_transfer(self, job_ref: str, request: TransferRegisterRequest) -> TransferResult:
        if self._store.read_runtime("transfer", job_ref, request.transfer_ref) is not None:
            return self._workspace_runtime.register_transfer(job_ref, request)
        binding = self._live_binding(job_ref)
        claim = self._claim_mutation(binding, "transfer-register", request.transfer_ref)
        try:
            return self._workspace_runtime.register_transfer(job_ref, request)
        finally:
            claim.release()

    def stage_transfer_content(
        self,
        job_ref: str,
        transfer_ref: str,
        stream: Any,
        *,
        content_length: int | None = None,
    ) -> TransferSnapshot:
        binding = self._live_binding(job_ref)
        claim = self._claim_mutation(binding, "transfer-stage", transfer_ref)
        try:
            return self._workspace_runtime.stage_transfer_content(
                job_ref,
                transfer_ref,
                stream,
                content_length=content_length,
            )
        finally:
            claim.release()

    def open_collected_content(self, job_ref: str, transfer_ref: str) -> VerifiedContent:
        binding = self._live_binding(job_ref)
        claim = self._claim_mutation(binding, "transfer-collect", transfer_ref)
        try:
            content = self._workspace_runtime.open_collected_content(job_ref, transfer_ref)
            return replace(content, release_claim=claim.release)
        except Exception:
            claim.release()
            raise

    def inspect_transfer(self, job_ref: str, transfer_ref: str) -> TransferSnapshot:
        return self._workspace_runtime.inspect_transfer(job_ref, transfer_ref)

    def cancel_transfer(
        self, job_ref: str, transfer_ref: str, request: TransferCancelRequest
    ) -> TransferResult:
        existing = self._store.read_runtime("transfer", job_ref, transfer_ref)
        if existing is not None:
            snapshot = self._workspace_runtime.inspect_transfer(job_ref, transfer_ref)
            if snapshot.cancel_action.state is ActionState.SUCCEEDED:
                return self._workspace_runtime.cancel_transfer(job_ref, transfer_ref, request)
        binding = self._live_binding(job_ref)
        claim = self._claim_mutation(binding, "transfer-cancel", transfer_ref)
        try:
            return self._workspace_runtime.cancel_transfer(job_ref, transfer_ref, request)
        finally:
            claim.release()

    def discard_transfer(
        self,
        job_ref: str,
        transfer_ref: str,
        discard_ref: str,
        request_digest: str,
    ) -> TransferSnapshot:
        existing = self._store.read_runtime("transfer", job_ref, transfer_ref)
        if existing is not None:
            snapshot = self._workspace_runtime.inspect_transfer(job_ref, transfer_ref)
            if snapshot.discard_action.state is ActionState.SUCCEEDED:
                return self._workspace_runtime.discard_transfer(
                    job_ref, transfer_ref, discard_ref, request_digest
                )
        binding = self._live_binding(job_ref)
        claim = self._claim_mutation(binding, "transfer-discard", transfer_ref)
        try:
            return self._workspace_runtime.discard_transfer(
                job_ref, transfer_ref, discard_ref, request_digest
            )
        finally:
            claim.release()

    def invoke_workspace(
        self, job_ref: str, request: WorkspaceInvokeRequest
    ) -> WorkspaceOperationResult:
        existing = self._store.read_runtime("operation", job_ref, request.operation_ref)
        if existing is not None:
            snapshot = self._workspace_runtime.inspect_operation(job_ref, request.operation_ref)
            if snapshot.state in {
                OperationState.SUCCEEDED,
                OperationState.FAILED,
                OperationState.INDETERMINATE,
            }:
                return self._workspace_runtime.invoke_workspace(job_ref, request)
        binding = self._live_binding(job_ref)
        claim = self._claim_mutation(binding, "workspace-invoke", request.operation_ref)
        try:
            return self._workspace_runtime.invoke_workspace(job_ref, request)
        finally:
            claim.release()

    def inspect_operation(self, job_ref: str, operation_ref: str) -> WorkspaceOperationSnapshot:
        return self._workspace_runtime.inspect_operation(job_ref, operation_ref)

    def inspect_credential_grant(
        self, job_ref: str, credential_grant_ref: str
    ) -> CredentialGrantSnapshot:
        record = self._store.read_runtime("credential", job_ref, credential_grant_ref)
        if record is None or str(_field(record, "job_ref")) != job_ref:
            raise JobNotFoundError()
        snapshot = self._grant_snapshot(record)
        self._expire_grant_if_needed(snapshot)
        record = self._store.read_runtime("credential", job_ref, credential_grant_ref)
        if record is None:
            raise DependencyUnavailableError()
        return self._grant_snapshot(record)

    def start_agent(self, job_ref: str, request: AgentStartRequest) -> GenerationSnapshot:
        binding = self._live_binding(job_ref)
        existing = self._store.read_runtime("generation", job_ref, str(request.generation))
        if existing is not None:
            retained = self._generation_snapshot(existing, replayed=False)
            if retained.runner_state is not RunnerState.ACCEPTED:
                self._validate_retained_generation(retained, request, binding)
                return retained.model_copy(update={"replayed": True})
        self._assert_accepting_workspace_work(job_ref)
        claim = self._claim_mutation(binding, "agent-start", str(request.generation))
        try:
            return self._start_agent_claimed(job_ref, request)
        finally:
            claim.release()

    def _start_agent_claimed(self, job_ref: str, request: AgentStartRequest) -> GenerationSnapshot:
        """Dispatch exactly one legal generation to the bound live supervisor."""
        binding = self._live_binding(job_ref)
        self._assert_accepting_workspace_work(job_ref)
        digest = canonical_digest(request.digest_payload())
        existing = self._store.read_runtime("generation", job_ref, str(request.generation))
        if existing is not None:
            if _runtime_values(existing).get("identityDigest") != digest:
                raise IdentityDigestConflict()
            retained = self._generation_snapshot(existing, replayed=False)
            self._validate_retained_generation(retained, request, binding)
            if retained.runner_state is not RunnerState.ACCEPTED:
                return retained.model_copy(update={"replayed": True})
            record = existing
        else:
            previous = self._latest_generation(job_ref)
            expected = 1 if previous is None else previous.generation + 1
            if request.generation != expected or (
                previous is not None
                and (
                    previous.runner_state is not RunnerState.EXITED or not previous.supervisor_alive
                )
            ):
                raise IllegalGenerationError()
            grant = self.inspect_credential_grant(job_ref, request.credential_grant_ref)
            if grant.state is not CredentialState.AVAILABLE or self._now() >= grant.expires_at:
                self._expire_grant_if_needed(grant)
                raise CredentialExpiredError()
            self._validate_generation_grant(grant, request, binding)
            values = self._generation_values(job_ref, request, digest, binding, grant)
            record, _ = self._store.reserve_runtime(
                "generation", str(request.generation), job_ref, values
            )
            if _runtime_values(record).get("identityDigest") != digest:
                raise IdentityDigestConflict()
            retained = self._generation_snapshot(record, replayed=False)
            self._validate_retained_generation(retained, request, binding)
            if retained.runner_state is not RunnerState.ACCEPTED:
                return retained.model_copy(update={"replayed": True})
        if self._transport is None:
            raise DependencyUnavailableError("agent RPC transport is not configured")
        grant_record = self._store.read_runtime(
            "credential", job_ref, retained.credential_grant_ref
        )
        if grant_record is None:
            raise DependencyUnavailableError("retained generation grant is unavailable")
        grant = self._grant_snapshot(grant_record)
        self._validate_generation_grant(grant, request, binding)
        record_values = _runtime_values(record)
        audience = record_values.get("grantAudience", grant.audience)
        credential_sha = record_values.get("credentialSha256", grant.credential_sha256)
        if audience != grant.audience or credential_sha != grant.credential_sha256:
            raise DependencyUnavailableError("retained generation grant metadata is inconsistent")
        retained_request = self._request_from_generation(retained)
        try:
            self._assert_accepting_workspace_work(job_ref)
            rpc = self._agent_rpc(binding, retained_request, audience, credential_sha)
        except KcsV2Error:
            raise
        except Exception as error:
            raise DependencyUnavailableError("agent supervisor RPC did not complete") from error
        self._validate_agent_ack(rpc, retained_request, audience, credential_sha)
        now = self._now()
        grant = self._acknowledge_grant(grant_record, retained_request, now)
        state = RunnerState.EXITED if rpc.state == "exited" else RunnerState.RUNNING
        generation = retained.model_copy(
            update={
                "runner_state": state,
                "supervisor_alive": rpc.supervisor_alive,
                "pid": rpc.pid,
                "exit_code": rpc.exit_code,
                "started_at": now,
                "finished_at": now if state is RunnerState.EXITED else None,
                "observed_at": now,
                "credential_acknowledged_at": now,
                "credential_destroyed_at": grant.destroyed_at,
            }
        )
        self._store.update_runtime(
            "generation",
            job_ref,
            str(_field(record, "identity")),
            _runtime_values_with(record, {"payload": generation.model_dump_json(by_alias=True)}),
        )
        return generation

    def finalize(self, job_ref: str, request: FinalizeJobRequest) -> FinalizeResult:
        """Quiesce supervisors and revoke credentials without deleting Job/Pod/log reality."""
        self.reconcile_credentials()
        self._assert_no_cancel(job_ref)
        if not hmac.compare_digest(canonical_digest(request.spec), request.request_digest):
            raise DigestMismatchError()
        binding = self._live_binding(job_ref)
        request_spec = request.spec.model_dump_json(by_alias=True)
        close = self._lifecycle.begin_close(
            job_ref,
            str(binding.job_uid),
            str(binding.pod_uid),
            "finalize",
            request.finalize_ref,
            request.request_digest,
            request_spec,
        )
        values = {
            "identityDigest": request.request_digest,
            "finalizeRef": request.finalize_ref,
            "jobUid": str(binding.job_uid),
            "podUid": str(binding.pod_uid),
            "requestSpec": request_spec,
            "payload": json.dumps({"state": "accepted", "observedAt": self._now().isoformat()}),
        }
        record, created = self._reserve_finalize(job_ref, request, binding, values)
        if not created and (
            _runtime_values(record).get("identityDigest") != request.request_digest
            or _runtime_values(record).get("finalizeRef") != request.finalize_ref
        ):
            raise IdentityDigestConflict()
        phase = _finalize_phase(record)
        if phase == "indeterminate":
            phase = _finalize_resume_from(record)
        if phase == "succeeded":
            close.phase("succeeded", closed=True)
            return FinalizeResult(snapshot=self.inspect(job_ref), created=False)
        identity = {
            "jobRef": job_ref,
            "jobUid": str(binding.job_uid),
            "podUid": str(binding.pod_uid),
        }
        try:
            if phase == "accepted":
                self._drain_finalize_records(job_ref, request.spec, binding)
                for grant_record in self._store.list_runtime("credential", job_ref):
                    grant = self._grant_snapshot(grant_record)
                    if grant.secret_present is not False:
                        self._revoke_grant(grant)
                record = self._set_finalize_phase(record, "credentials_revoked")
                close.phase("credentials_revoked")
                phase = "credentials_revoked"
            if phase == "credentials_revoked":
                self._stop_or_recover(job_ref, identity, "agent")
                record = self._set_finalize_phase(record, "agent_stopped")
                close.phase("agent_stopped")
                phase = "agent_stopped"
            if phase == "agent_stopped":
                self._stop_or_recover(job_ref, identity, "workspace")
                record = self._set_finalize_phase(record, "workspace_stopped")
                close.phase("workspace_stopped")
                phase = "workspace_stopped"
            if phase == "workspace_stopped":
                if not self._roles_are_terminal(job_ref):
                    raise DependencyTimeoutError(
                        "Kubernetes has not confirmed both finalized containers terminated"
                    )
                record = self._set_finalize_phase(record, "succeeded")
                close.phase("succeeded", closed=True)
                phase = "succeeded"
        except KcsV2Error as error:
            self._set_finalize_indeterminate(record, phase, type(error).__name__)
            close.phase("indeterminate")
            raise
        except Exception as error:
            self._set_finalize_indeterminate(record, phase, type(error).__name__)
            close.phase("indeterminate")
            raise DependencyUnavailableError("supervisor quiesce did not complete") from error
        if phase != "succeeded":
            raise DependencyUnavailableError("retained finalize phase is indeterminate")
        return FinalizeResult(snapshot=self.inspect(job_ref), created=created)

    def cancel(self, job_ref: str, request: CancelJobRequest) -> CancelResult:
        """Interrupt one binding from a durable slot without inventing output manifests."""
        if not hmac.compare_digest(canonical_digest(request.spec), request.request_digest):
            raise DigestMismatchError()
        self._assert_not_finalizing(job_ref)
        binding = self._live_binding(job_ref)
        request_spec = request.spec.model_dump_json(by_alias=True)
        close = self._lifecycle.begin_close(
            job_ref,
            str(binding.job_uid),
            str(binding.pod_uid),
            "cancel",
            request.cancel_ref,
            request.request_digest,
            request_spec,
        )
        values = {
            "identityDigest": request.request_digest,
            "cancelRef": request.cancel_ref,
            "jobUid": str(binding.job_uid),
            "podUid": str(binding.pod_uid),
            "requestSpec": request_spec,
            # Interrupt acceptance closes admission immediately. Until every requested collect
            # has been reconciled and its delivery proven, loss must be reported conservatively.
            "payload": phase_payload("accepted", self._now(), output_loss_possible=True),
        }
        record, created = self._reserve_cancel(job_ref, request, values)
        retained = _runtime_values(record)
        if (
            retained.get("identityDigest") != request.request_digest
            or retained.get("cancelRef") != request.cancel_ref
        ):
            raise IdentityDigestConflict()
        state, output_loss, resume_from = read_phase(record)
        if state == "succeeded":
            close.phase("succeeded", closed=True)
            return CancelResult(snapshot=self.inspect(job_ref), created=False)
        if state == "indeterminate" and resume_from is None:
            return CancelResult(snapshot=self.inspect(job_ref), created=False)
        phase = resume_from or state
        try:
            if phase == "accepted":
                self._reconcile_active_operations_before_cancel(job_ref)
                collect_indeterminate = self._drain_cancel_collects(job_ref, request.spec)
                output_loss = (
                    output_loss or self._cancel_output_loss(job_ref) or collect_indeterminate
                )
                record = self._set_cancel_phase(
                    record,
                    "collections_drained",
                    output_loss_possible=output_loss,
                    collect_indeterminate=collect_indeterminate,
                )
                close.phase("collections_drained")
                phase = "collections_drained"
            if phase == "collections_drained":
                for grant_record in self._store.list_runtime("credential", job_ref):
                    grant = self._grant_snapshot(grant_record)
                    if grant.secret_present is not False:
                        self._revoke_grant(grant)
                record = self._set_cancel_phase(
                    record, "credentials_revoked", output_loss_possible=output_loss
                )
                close.phase("credentials_revoked")
                phase = "credentials_revoked"
            identity = {
                "jobRef": job_ref,
                "jobUid": str(binding.job_uid),
                "podUid": str(binding.pod_uid),
            }
            if phase == "credentials_revoked":
                self._stop_or_recover(job_ref, identity, "agent")
                record = self._set_cancel_phase(
                    record, "agent_stopped", output_loss_possible=output_loss
                )
                close.phase("agent_stopped")
                phase = "agent_stopped"
            if phase == "agent_stopped":
                self._stop_or_recover(job_ref, identity, "workspace")
                record = self._set_cancel_phase(
                    record, "workspace_stopped", output_loss_possible=output_loss
                )
                close.phase("workspace_stopped")
                phase = "workspace_stopped"
            if phase == "workspace_stopped":
                if not self._roles_are_terminal(job_ref):
                    raise DependencyTimeoutError(
                        "Kubernetes has not confirmed both canceled containers terminated"
                    )
                self._mark_active_operations_indeterminate(job_ref)
                output_loss = self._cancel_output_loss(job_ref) or output_loss
                final_state = "succeeded"
                record = self._set_cancel_phase(
                    record, final_state, output_loss_possible=output_loss
                )
                close.phase(final_state, closed=True)
                phase = final_state
        except KcsV2Error as error:
            self._set_cancel_indeterminate(record, phase, output_loss, type(error).__name__)
            close.phase("indeterminate")
            raise
        except Exception as error:
            self._set_cancel_indeterminate(record, phase, output_loss, type(error).__name__)
            close.phase("indeterminate")
            raise DependencyUnavailableError("cancel lifecycle did not complete") from error
        if phase not in {"succeeded", "indeterminate"}:
            raise DependencyUnavailableError("retained cancel phase is indeterminate")
        return CancelResult(snapshot=self.inspect(job_ref), created=created)

    cancel_job = cancel

    def delete(self, job_ref: str, delete_ref: str, request_digest: str) -> JobTombstone:
        """Persist an ownerless tombstone, then prove foreground cleanup in phases."""
        if not hmac.compare_digest(request_digest, EMPTY_OBJECT_DIGEST):
            raise DigestMismatchError
        record = self._store.read_by_job_ref(job_ref)
        if record is None:
            raise JobNotFoundError
        if _is_deleted(record):
            self._raise_if_delete_conflicts(record, delete_ref, request_digest)
            if _field(record, "cleanup_state", "complete") == "complete":
                return _as_tombstone(record)
            final_state = _provider_terminal_state(_field(record, "final_state", "indeterminate"))
            credential_observations, transfer_observations = _stored_tombstone_observations(record)
        elif str(_field(record, "state", "")) == "deleting":
            self._raise_if_delete_conflicts(record, delete_ref, request_digest)
            final_state = _provider_terminal_state(_field(record, "final_state", "indeterminate"))
            credential_observations, transfer_observations = _stored_tombstone_observations(record)
        else:
            snapshot = self.inspect(job_ref)
            final_state = _terminal_state_for_binding(snapshot.binding_state)
            credential_observations = [
                item.model_dump(mode="json", by_alias=True)
                for item in snapshot.credential_observations
            ]
            transfer_observations = [
                item.model_dump(mode="json", by_alias=True)
                for item in snapshot.transfer_observations
            ]

        deleted_at = self._now()
        expires_at = deleted_at + self._tombstone_ttl
        record = self._mark_deleted(
            record,
            delete_ref=delete_ref,
            request_digest=request_digest,
            final_state=final_state,
            deleted_at=deleted_at,
            expires_at=expires_at,
            cleanup_state=CleanupState.PENDING,
            cleanup_phase=_later_delete_phase(record, "tombstone_persisted"),
            gpu_release_state=(
                CleanupState.COMPLETE
                if _workspace_gpu(record) > 0 and final_state is ProviderTerminalState.CANCELED
                else CleanupState.PENDING
                if _workspace_gpu(record) > 0
                else CleanupState.NOT_REQUIRED
            ),
            credential_observations=credential_observations,
            transfer_observations=transfer_observations,
        )
        if _delete_phase_reached(record, "workload_absent"):
            self._prove_secret_absent(job_ref)
            if self._read_job(job_ref) is not None or self._list_job_pods(
                job_ref, str(_field(record, "job_uid"))
            ):
                raise DependencyTimeoutError("Kubernetes workload absence must be re-proven")
            self._store.delete_runtime_records(job_ref)
            if self._store.has_runtime_records(job_ref):
                raise DependencyTimeoutError(
                    "Kubernetes owner runtime records remain after deletion"
                )
            completion_at = self._now()
            gpu_requested = _workspace_gpu(record) > 0
            record = self._mark_deleted(
                record,
                delete_ref=delete_ref,
                request_digest=request_digest,
                final_state=final_state,
                deleted_at=completion_at,
                expires_at=completion_at + self._tombstone_ttl,
                cleanup_state=CleanupState.PENDING,
                cleanup_phase="owner_records_deleted",
                gpu_release_state=(
                    CleanupState.COMPLETE if gpu_requested else CleanupState.NOT_REQUIRED
                ),
                credential_observations=credential_observations,
                transfer_observations=transfer_observations,
            )
            record = self._mark_deleted(
                record,
                delete_ref=delete_ref,
                request_digest=request_digest,
                final_state=final_state,
                deleted_at=completion_at,
                expires_at=completion_at + self._tombstone_ttl,
                cleanup_state=CleanupState.COMPLETE,
                cleanup_phase="complete",
                gpu_release_state=(
                    CleanupState.COMPLETE if gpu_requested else CleanupState.NOT_REQUIRED
                ),
                credential_observations=credential_observations,
                transfer_observations=transfer_observations,
            )
            return _as_tombstone(record)
        try:
            close = self._lifecycle.begin_close(
                job_ref,
                str(_field(record, "job_uid")),
                str(_field(record, "pod_uid")),
                "delete",
                delete_ref,
                request_digest,
                "{}",
            )
        except StateConflictError as error:
            raise DependencyUnavailableError(
                "delete intent is retained while a lifecycle mutation finishes"
            ) from error
        close.phase("delete_intent_persisted")

        for grant_record in self._store.list_runtime("credential", job_ref):
            grant = self._grant_snapshot(grant_record)
            if grant.secret_present is not False:
                self._revoke_grant(grant)
        self._prove_secret_absent(job_ref)
        observed_credentials, observed_transfers = self._deletion_observations(job_ref)
        credential_observations = observed_credentials or credential_observations
        transfer_observations = observed_transfers or transfer_observations
        record = self._mark_deleted(
            record,
            delete_ref=delete_ref,
            request_digest=request_digest,
            final_state=final_state,
            deleted_at=deleted_at,
            expires_at=expires_at,
            cleanup_state=CleanupState.PENDING,
            cleanup_phase=_later_delete_phase(record, "credentials_destroyed"),
            gpu_release_state=_cleanup_state(record, "gpu_release_state", CleanupState.PENDING),
            credential_observations=credential_observations,
            transfer_observations=transfer_observations,
        )
        close.phase("credentials_destroyed")

        self._delete_job(job_ref)
        record = self._mark_deleted(
            record,
            delete_ref=delete_ref,
            request_digest=request_digest,
            final_state=final_state,
            deleted_at=deleted_at,
            expires_at=expires_at,
            cleanup_state=CleanupState.PENDING,
            cleanup_phase=_later_delete_phase(record, "job_delete_requested"),
            gpu_release_state=_cleanup_state(record, "gpu_release_state", CleanupState.PENDING),
            credential_observations=credential_observations,
            transfer_observations=transfer_observations,
        )
        close.phase("job_delete_requested")
        if not self._wait_for_job_absence(job_ref):
            raise DependencyTimeoutError("Kubernetes has not yet confirmed Job deletion")
        if self._list_job_pods(job_ref, str(_field(record, "job_uid"))):
            raise DependencyTimeoutError("Kubernetes has not confirmed Pod deletion")
        gpu_requested = _workspace_gpu(record) > 0
        record = self._mark_deleted(
            record,
            delete_ref=delete_ref,
            request_digest=request_digest,
            final_state=final_state,
            deleted_at=deleted_at,
            expires_at=expires_at,
            cleanup_state=CleanupState.PENDING,
            cleanup_phase=_later_delete_phase(record, "workload_absent"),
            gpu_release_state=CleanupState.COMPLETE if gpu_requested else CleanupState.NOT_REQUIRED,
            credential_observations=credential_observations,
            transfer_observations=transfer_observations,
        )
        close.phase("workload_absent")
        close.phase("cleanup_proven", closed=True)
        self._store.delete_runtime_records(job_ref)
        if self._store.has_runtime_records(job_ref):
            raise DependencyTimeoutError("Kubernetes owner runtime records remain after deletion")
        completion_at = self._now()
        record = self._mark_deleted(
            record,
            delete_ref=delete_ref,
            request_digest=request_digest,
            final_state=final_state,
            deleted_at=completion_at,
            expires_at=completion_at + self._tombstone_ttl,
            cleanup_state=CleanupState.PENDING,
            cleanup_phase=_later_delete_phase(record, "owner_records_deleted"),
            gpu_release_state=CleanupState.COMPLETE if gpu_requested else CleanupState.NOT_REQUIRED,
            credential_observations=credential_observations,
            transfer_observations=transfer_observations,
        )
        record = self._mark_deleted(
            record,
            delete_ref=delete_ref,
            request_digest=request_digest,
            final_state=final_state,
            deleted_at=completion_at,
            expires_at=completion_at + self._tombstone_ttl,
            cleanup_state=CleanupState.COMPLETE,
            cleanup_phase="complete",
            gpu_release_state=CleanupState.COMPLETE if gpu_requested else CleanupState.NOT_REQUIRED,
            credential_observations=credential_observations,
            transfer_observations=transfer_observations,
        )
        return _as_tombstone(record)

    delete_job = delete

    def _reserve_create(
        self,
        request: CreateJobRequest,
        job_ref: str,
        spec_payload: Mapping[str, object],
    ) -> object:
        try:
            return self._store.reserve_create(
                request.provider_request_id,
                request.spec_digest,
                job_ref,
                spec_payload,
            )
        except KcsV2Error:
            raise
        except Exception as error:
            raise DependencyUnavailableError from error

    def _live_binding(self, job_ref: str) -> JobBindingSnapshot:
        binding = self.inspect(job_ref)
        if binding.binding_state is JobBindingState.DELETING:
            raise StateConflictError("The Job has a retained deletion intent")
        if binding.pod_uid is None or binding.binding_state is JobBindingState.INDETERMINATE:
            raise ReplacementPodError()
        return binding

    def _resume_lifecycle_close(self, job_ref: str, close: Mapping[str, object]) -> None:
        kind = str(close.get("kind", ""))
        ref = str(close.get("ref", ""))
        digest = str(close.get("digest", ""))
        request_spec = str(close.get("requestSpec", ""))
        if kind == "cancel":
            self.cancel(
                job_ref,
                CancelJobRequest(
                    cancel_ref=ref,
                    request_digest=digest,
                    spec=CancelSpec.model_validate_json(request_spec),
                ),
            )
            return
        if kind == "finalize":
            self.finalize(
                job_ref,
                FinalizeJobRequest(
                    finalize_ref=ref,
                    request_digest=digest,
                    spec=FinalizeSpec.model_validate_json(request_spec),
                ),
            )
            return
        raise DependencyUnavailableError("lifecycle close has no replayable action kind")

    def _lifecycle_intent_has_terminal_truth(
        self, job_ref: str, intent: Mapping[str, object]
    ) -> bool:
        kind = str(intent.get("kind", ""))
        ref = str(intent.get("ref", ""))
        if not kind or not ref:
            return False
        if kind == "credential-grant":
            record = self._store.read_runtime("credential", job_ref, ref)
            return record is not None and self._grant_snapshot(record).state in {
                CredentialState.AVAILABLE,
                CredentialState.ACKNOWLEDGED,
                CredentialState.CONSUMED,
                CredentialState.DESTROYED,
                CredentialState.EXPIRED,
                CredentialState.REVOKED,
            }
        if kind == "agent-start":
            record = self._store.read_runtime("generation", job_ref, ref)
            return record is not None and self._generation_snapshot(
                record, replayed=False
            ).runner_state in {
                RunnerState.RUNNING,
                RunnerState.EXITED,
            }
        if kind.startswith("transfer-"):
            record = self._store.read_runtime("transfer", job_ref, ref)
            if record is None:
                return False
            snapshot = self._workspace_runtime.inspect_transfer(job_ref, ref)
            if kind == "transfer-register":
                return True
            if kind == "transfer-cancel":
                return snapshot.cancel_action.state is ActionState.SUCCEEDED
            if kind == "transfer-discard":
                return snapshot.discard_action.state is ActionState.SUCCEEDED
            if kind == "transfer-collect":
                # COMPLETED precedes HTTP BackgroundTask cleanup; it is not holder-death proof.
                return False
            if kind in {"transfer-stage", "transfer-reconcile"}:
                return snapshot.state is TransferState.COMPLETED
            return False
        if kind in {"workspace-invoke", "operation-reconcile"}:
            record = self._store.read_runtime("operation", job_ref, ref)
            return record is not None and self._workspace_runtime.inspect_operation(
                job_ref, ref
            ).state in {
                OperationState.SUCCEEDED,
                OperationState.FAILED,
            }
        return False

    def _validate_job_annotations(self, record: object) -> None:
        job_ref = str(_field(record, "job_ref"))
        job = self._read_job(job_ref)
        if job is None:
            raise DependencyUnavailableError("retained Job is absent during reconciliation")
        annotations = _path(job, "metadata", "annotations")
        if not isinstance(annotations, Mapping) or not annotations:
            return
        spec = _field(record, "spec_payload", {})
        expected = {
            "researchcosmos.io/provider-request-id": str(_field(record, "provider_request_id")),
            "researchcosmos.io/subject-ref": str(_field(spec, "subjectRef")),
            "researchcosmos.io/runtime-plan-digest": str(_field(spec, "runtimePlanDigest")),
            "researchcosmos.io/spec-digest": str(_field(record, "spec_digest")),
        }
        if any(annotations.get(key) != value for key, value in expected.items()):
            self._mark_indeterminate(record, "Job annotations differ from the create reservation")
            raise StateConflictError("Job annotations differ from the create reservation")

    def _assert_not_finalizing(self, job_ref: str) -> None:
        if self._runtime_records("finalize", job_ref):
            raise StateConflictError("The provider is already quiescing this Job")

    def _assert_no_cancel(self, job_ref: str) -> None:
        if self._runtime_records("cancel", job_ref):
            raise StateConflictError("The provider is already canceling this Job")

    def _assert_accepting_workspace_work(self, job_ref: str) -> None:
        self._assert_not_finalizing(job_ref)
        self._assert_no_cancel(job_ref)

    def _claim_mutation(self, binding: JobBindingSnapshot, kind: str, ref: str) -> LifecycleClaim:
        return self._lifecycle.claim(
            binding.job_ref,
            str(binding.job_uid),
            str(binding.pod_uid),
            kind,
            ref,
        )

    def _reserve_cancel(
        self,
        job_ref: str,
        request: CancelJobRequest,
        values: Mapping[str, str],
    ) -> tuple[object, bool]:
        slot = self._store.read_runtime("cancel", job_ref, "slot")
        if slot is not None:
            return slot, False
        return self._store.reserve_runtime("cancel", "slot", job_ref, values)

    def _drain_cancel_collects(self, job_ref: str, spec: CancelSpec) -> bool:
        output_loss = False
        for transfer_ref in spec.finish_collect_transfer_refs:
            try:
                self._workspace_runtime.drain_pre_authorized_collect(job_ref, transfer_ref)
            except Exception:
                output_loss = True
        return output_loss

    def _cancel_output_loss(self, job_ref: str) -> bool:
        for record in self._store.list_runtime("transfer", job_ref):
            snapshot = self._workspace_runtime.inspect_transfer(
                job_ref, str(_field(record, "identity"))
            )
            if snapshot.spec.direction.value != "collect_output":
                continue
            if snapshot.spec.direction.value == "collect_output":
                return True
        return False

    def _reconcile_active_operations_before_cancel(self, job_ref: str) -> None:
        for record in self._store.list_runtime("operation", job_ref):
            snapshot = self._workspace_runtime.inspect_operation(
                job_ref, str(_field(record, "identity"))
            )
            if snapshot.state in {OperationState.ACCEPTED, OperationState.RUNNING}:
                try:
                    self._workspace_runtime.reconcile_operation(job_ref, snapshot.operation_ref)
                except Exception:
                    self._mark_operation_indeterminate(
                        record,
                        snapshot,
                        "operation terminal truth could not be proven before workspace shutdown",
                    )

    def _mark_active_operations_indeterminate(self, job_ref: str) -> None:
        for record in self._store.list_runtime("operation", job_ref):
            snapshot = self._workspace_runtime.inspect_operation(
                job_ref, str(_field(record, "identity"))
            )
            if snapshot.state not in {OperationState.ACCEPTED, OperationState.RUNNING}:
                continue
            self._mark_operation_indeterminate(
                record,
                snapshot,
                "workspace stopped before operation terminal truth was proven",
            )

    def _mark_operation_indeterminate(
        self, record: object, snapshot: WorkspaceOperationSnapshot, reason: str
    ) -> None:
        now = self._now()
        retained = snapshot.model_copy(
            update={
                "state": OperationState.INDETERMINATE,
                "finished_at": now,
                "observed_at": now,
                "failure_reason": reason,
            }
        )
        self._store.update_runtime(
            "operation",
            snapshot.job_ref,
            snapshot.operation_ref,
            _runtime_values_with(record, {"payload": retained.model_dump_json(by_alias=True)}),
        )

    def _set_cancel_phase(
        self,
        record: object,
        phase: str,
        *,
        output_loss_possible: bool,
        collect_indeterminate: bool | None = None,
    ) -> object:
        changes = {
            "payload": phase_payload(phase, self._now(), output_loss_possible=output_loss_possible)
        }
        if collect_indeterminate is not None:
            changes["collectIndeterminate"] = "true" if collect_indeterminate else "false"
        return self._cas_runtime_update(record, changes)

    def _set_cancel_indeterminate(
        self,
        record: object,
        resume_from: str,
        output_loss_possible: bool,
        reason: str,
    ) -> object:
        return self._cas_runtime_update(
            record,
            {
                "payload": phase_payload(
                    "indeterminate",
                    self._now(),
                    output_loss_possible=output_loss_possible,
                    resume_from=resume_from,
                    reason=reason,
                )
            },
        )

    def _roles_are_terminal(self, job_ref: str) -> bool:
        snapshot = self.inspect(job_ref)
        roles_terminal = (
            snapshot.agent is not None
            and snapshot.workspace is not None
            and snapshot.agent.state is RoleState.TERMINATED
            and snapshot.workspace.state is RoleState.TERMINATED
        )
        job = self._read_job(job_ref)
        return (
            roles_terminal
            and job is not None
            and (
                _job_condition_true(job, "Complete")
                or _job_condition_true(job, "Failed")
                or int(_path(job, "status", "succeeded") or 0) > 0
                or int(_path(job, "status", "failed") or 0) > 0
            )
        )

    def _reserve_finalize(
        self,
        job_ref: str,
        request: FinalizeJobRequest,
        binding: JobBindingSnapshot,
        values: Mapping[str, str],
    ) -> tuple[object, bool]:
        slot = self._store.read_runtime("finalize", job_ref, "slot")
        if slot is not None:
            return slot, False
        legacy = [
            record
            for record in self._store.list_runtime("finalize", job_ref)
            if str(_field(record, "identity")) != "slot"
        ]
        if len(legacy) > 1:
            raise DependencyUnavailableError("multiple legacy finalize identities are retained")
        if legacy:
            retained = legacy[0]
            retained_values = _runtime_values(retained)
            legacy_ref = retained_values.get("finalizeRef") or str(_field(retained, "identity"))
            if (
                legacy_ref != request.finalize_ref
                or retained_values.get("identityDigest") != request.request_digest
            ):
                raise IdentityDigestConflict()
            migrated = dict(retained_values)
            migrated.update(
                {
                    "finalizeRef": legacy_ref,
                    "jobUid": str(binding.job_uid),
                    "podUid": str(binding.pod_uid),
                    "requestSpec": request.spec.model_dump_json(by_alias=True),
                }
            )
            record, _ = self._store.reserve_runtime("finalize", "slot", job_ref, migrated)
            return record, False
        return self._store.reserve_runtime("finalize", "slot", job_ref, values)

    def _drain_finalize_records(
        self, job_ref: str, spec: FinalizeSpec, binding: JobBindingSnapshot
    ) -> None:
        deadline = self._now() + timedelta(seconds=spec.drain_timeout_seconds)
        monotonic_deadline = time.monotonic() + spec.drain_timeout_seconds
        while True:
            pending = False
            for ref in spec.operation_refs:
                state = self._requested_runtime_state("operation", job_ref, ref, binding)
                if state == "indeterminate":
                    raise OperationIndeterminateError()
                if state == "failed":
                    raise StateConflictError(f"requested operation {state} before finalize")
                pending = pending or state not in _OPERATION_TERMINAL_STATES
            for ref in spec.transfer_refs:
                state = self._requested_runtime_state("transfer", job_ref, ref, binding)
                if state == "indeterminate":
                    raise TransferIndeterminateError()
                if state == "failed":
                    raise StateConflictError(f"requested transfer {state} before finalize")
                pending = pending or state not in _TRANSFER_TERMINAL_STATES
            if not pending:
                return
            if self._startup_reconcile:
                raise DependencyTimeoutError(
                    "startup reconciliation observed pending finalize work"
                )
            if self._now() >= deadline or time.monotonic() >= monotonic_deadline:
                raise DependencyTimeoutError(
                    "requested operations or transfers did not drain before finalize"
                )
            self._sleeper(0.01)

    def _requested_runtime_state(
        self,
        kind: str,
        job_ref: str,
        identity: str,
        binding: JobBindingSnapshot,
    ) -> str:
        record = self._store.read_runtime(kind, job_ref, identity)
        if record is None:
            raise StateConflictError(f"finalize {kind} reference is not registered")
        _validate_runtime_binding(record, str(binding.job_uid), str(binding.pod_uid))
        values = _runtime_values(record)
        if kind == "operation" and "frameDigest" in values:
            return self._workspace_runtime.reconcile_operation(job_ref, identity).state.value
        if kind == "transfer":
            try:
                workspace_managed = "transferRef" in json.loads(values["payload"])
            except (KeyError, TypeError, json.JSONDecodeError):
                workspace_managed = False
            if workspace_managed:
                transfer = self._workspace_runtime.reconcile_transfer(job_ref, identity)
                if transfer.state is TransferState.INDETERMINATE:
                    return "indeterminate"
                if (
                    transfer.cancel_action.state is ActionState.ACCEPTED
                    or transfer.discard_action.state is ActionState.ACCEPTED
                ):
                    return "active_action"
                return transfer.state.value
        state, _ = _validated_runtime_state(record, kind)
        return state

    def _stop_or_recover(
        self, job_ref: str, identity: Mapping[str, str], role: Literal["agent", "workspace"]
    ) -> None:
        snapshot = self.inspect(job_ref)
        role_snapshot = snapshot.agent if role == "agent" else snapshot.workspace
        if role_snapshot is not None and role_snapshot.state is RoleState.TERMINATED:
            return
        if role == "workspace":
            if self._workspace_transport is None:
                if self._transport is None:
                    raise DependencyUnavailableError(
                        "workspace sidecar RPC transport is not configured"
                    )
                self._validate_stop_ack(self._transport.stop_supervisor(identity, role))
                return
            inspection = self._workspace_transport.rpc(
                identity, {"action": "inspectSupervisor"}
            ).header
            alive = inspection.get("supervisorAlive")
            if type(alive) is not bool:
                raise StateConflictError("workspace supervisor inspection is invalid")
            if alive:
                stopped = self._workspace_transport.rpc(identity, {"action": "shutdown"}).header
                if (
                    stopped.get("ok") is not True
                    or stopped.get("state") != "stopped"
                    or stopped.get("supervisorAlive") is not False
                ):
                    raise StateConflictError("workspace shutdown acknowledgement is invalid")
            return
        if self._transport is None:
            raise DependencyUnavailableError("supervisor RPC transport is not configured")
        inspect_supervisor = getattr(self._transport, "inspect_supervisor", None)
        if callable(inspect_supervisor):
            observed = inspect_supervisor(identity, role)
            if type(observed.supervisor_alive) is not bool:
                raise StateConflictError("agent supervisor inspection is invalid")
            if not observed.supervisor_alive:
                return
        self._validate_stop_ack(self._transport.stop_supervisor(identity, role))

    def _set_finalize_phase(self, record: object, phase: str) -> object:
        return self._cas_runtime_update(
            record,
            {"payload": json.dumps({"state": phase, "observedAt": self._now().isoformat()})},
        )

    def _set_finalize_indeterminate(self, record: object, resume_from: str, reason: str) -> object:
        return self._cas_runtime_update(
            record,
            {
                "payload": json.dumps(
                    {
                        "state": "indeterminate",
                        "resumeFrom": resume_from,
                        "reason": reason,
                        "observedAt": self._now().isoformat(),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            },
        )

    def _cas_runtime_update(self, record: object, changes: Mapping[str, str]) -> object:
        expected = _field(record, "resource_version", None)
        if not isinstance(expected, str) or not expected:
            raise DependencyUnavailableError("runtime phase has no resourceVersion")
        written = self._store.compare_and_swap_runtime(
            str(_field(record, "kind")),
            str(_field(record, "job_ref")),
            str(_field(record, "identity")),
            _runtime_values_with(record, changes),
            expected_resource_version=expected,
        )
        if written is None:
            raise DependencyUnavailableError("runtime phase changed concurrently")
        return written

    @staticmethod
    def _validate_stop_ack(response: AgentRpcResponse) -> None:
        if (
            type(response.protocol_version) is not int
            or response.protocol_version != 1
            or response.state != "stopped"
            or type(response.supervisor_alive) is not bool
            or response.supervisor_alive
        ):
            raise StateConflictError("supervisor shutdown acknowledgement is invalid")

    def _grant_values(
        self,
        job_ref: str,
        metadata: CredentialGrantMetadata,
        *,
        state: CredentialState,
        identity_digest: str,
    ) -> dict[str, str]:
        now = self._now()
        snapshot = CredentialGrantSnapshot(
            credential_grant_ref=metadata.credential_grant_ref,
            credential_sha256=metadata.credential_sha256,
            grant_metadata_digest=metadata.grant_metadata_digest,
            agent_run_ref=metadata.agent_run_ref,
            generation=metadata.generation,
            launch_bundle_digest=metadata.launch_bundle_digest,
            audience=metadata.audience,
            ttl_seconds=metadata.ttl_seconds,
            job_ref=job_ref,
            job_uid=metadata.job_uid,
            pod_uid=metadata.pod_uid,
            state=state,
            accepted_at=now,
            available_at=None,
            acknowledged_at=None,
            ack_agent_run_ref=None,
            ack_generation=None,
            consumed_at=None,
            destroyed_at=None,
            expires_at=now + timedelta(seconds=metadata.ttl_seconds),
            tombstone_expires_at=now + self._tombstone_ttl,
            secret_present=None,
            destroy_failure_reason=None,
            observed_at=now,
        )
        return {
            "identityDigest": identity_digest,
            "jobUid": str(metadata.job_uid),
            "podUid": str(metadata.pod_uid),
            "payload": snapshot.model_dump_json(by_alias=True),
        }

    @staticmethod
    def _grant_snapshot(record: object) -> CredentialGrantSnapshot:
        return CredentialGrantSnapshot.model_validate_json(_runtime_values(record)["payload"])

    def _update_grant(
        self,
        record: object,
        *,
        state: CredentialState,
        secret_present: bool | None,
        reason: str | None = None,
        acknowledged_at: datetime | None = None,
        ack_agent_run_ref: str | None = None,
        ack_generation: int | None = None,
        consumed_at: datetime | None = None,
        destroyed_at: datetime | None = None,
    ) -> CredentialGrantSnapshot:
        before = self._grant_snapshot(record)
        now = self._now()
        after = before.model_copy(
            update={
                "state": state,
                "available_at": now if state is CredentialState.AVAILABLE else before.available_at,
                "acknowledged_at": acknowledged_at
                if acknowledged_at is not None
                else before.acknowledged_at,
                "ack_agent_run_ref": ack_agent_run_ref
                if ack_agent_run_ref is not None
                else before.ack_agent_run_ref,
                "ack_generation": ack_generation
                if ack_generation is not None
                else before.ack_generation,
                "consumed_at": consumed_at if consumed_at is not None else before.consumed_at,
                "destroyed_at": destroyed_at if destroyed_at is not None else before.destroyed_at,
                "secret_present": secret_present,
                "destroy_failure_reason": reason,
                "observed_at": now,
            }
        )
        written = self._store.update_runtime(
            "credential",
            before.job_ref,
            str(_field(record, "identity")),
            _runtime_values_with(record, {"payload": after.model_dump_json(by_alias=True)}),
        )
        return self._grant_snapshot(written)

    def _expire_grant_if_needed(self, grant: CredentialGrantSnapshot) -> None:
        if grant.secret_present is False and grant.state in _CLEANUP_TARGETS:
            return
        record = self._store.read_runtime("credential", grant.job_ref, grant.credential_grant_ref)
        if record is None:
            return
        target = self._cleanup_target(record)
        if target is None:
            return
        self._destroy_grant(record, target)

    def _destroy_grant(self, record: object, state: CredentialState) -> CredentialGrantSnapshot:
        if state not in _CLEANUP_TARGETS:
            raise DependencyUnavailableError("credential cleanup target is invalid")
        retained_values = _runtime_values(record)
        retained_target = self._cleanup_target(record)
        target = retained_target or state
        if "cleanupTarget" not in retained_values:
            record = self._store.update_runtime(
                "credential",
                str(_field(record, "job_ref")),
                str(_field(record, "identity")),
                _runtime_values_with(record, {"cleanupTarget": target.value}),
            )
        grant = self._grant_snapshot(record)
        if grant.secret_present is False:
            if grant.state is target:
                return grant
            return self._update_grant(
                record,
                state=target,
                secret_present=False,
                destroyed_at=grant.destroyed_at or self._now(),
            )
        try:
            deletion = self._kube.delete_secret(credential_secret_name(grant.job_ref))
            if deletion is not True:
                raise DependencyUnavailableError("Kubernetes Secret absence was not confirmed")
            read_secret = getattr(self._kube, "read_secret", None)
            if (
                callable(read_secret)
                and read_secret(credential_secret_name(grant.job_ref)) is not None
            ):
                raise DependencyUnavailableError("Kubernetes Secret remains observable")
        except Exception:
            return self._update_grant(
                record,
                state=CredentialState.DESTROY_FAILED,
                secret_present=True,
                reason="Kubernetes Secret delete failed",
            )
        return self._update_grant(
            record,
            state=target,
            secret_present=False,
            destroyed_at=self._now(),
        )

    def _acknowledge_grant(
        self, record: object, request: AgentStartRequest, now: datetime
    ) -> CredentialGrantSnapshot:
        grant = self._grant_snapshot(record)
        if (
            grant.ack_agent_run_ref is not None and grant.ack_agent_run_ref != request.agent_run_ref
        ) or (grant.ack_generation is not None and grant.ack_generation != request.generation):
            raise StateConflictError("retained credential acknowledgement is inconsistent")
        target = self._cleanup_target(record) or CredentialState.DESTROYED
        if (
            grant.secret_present is False
            and grant.state is target
            and grant.ack_agent_run_ref == request.agent_run_ref
            and grant.ack_generation == request.generation
            and grant.consumed_at is not None
        ):
            return grant
        next_state = grant.state if grant.secret_present is False else CredentialState.CONSUMED
        consumed = self._update_grant(
            record,
            state=next_state,
            secret_present=grant.secret_present,
            acknowledged_at=now,
            ack_agent_run_ref=request.agent_run_ref,
            ack_generation=request.generation,
            consumed_at=grant.consumed_at or now,
        )
        record = self._store.read_runtime(
            "credential", consumed.job_ref, consumed.credential_grant_ref
        )
        if record is None:
            raise DependencyUnavailableError()
        destroyed = self._destroy_grant(record, target)
        if destroyed.state is CredentialState.DESTROY_FAILED:
            raise CredentialDestroyFailedError()
        return destroyed

    def _revoke_grant(self, grant: CredentialGrantSnapshot) -> None:
        record = self._store.read_runtime("credential", grant.job_ref, grant.credential_grant_ref)
        if record is None:
            return
        destroyed = self._destroy_grant(record, CredentialState.REVOKED)
        if destroyed.state is CredentialState.DESTROY_FAILED:
            raise CredentialDestroyFailedError()

    def _prove_secret_absent(self, job_ref: str) -> None:
        name = credential_secret_name(job_ref)
        try:
            deleted = self._kube.delete_secret(name)
            read_secret = getattr(self._kube, "read_secret", None)
            present = callable(read_secret) and read_secret(name) is not None
        except Exception as error:
            raise CredentialDestroyFailedError() from error
        if deleted is not True or present:
            raise CredentialDestroyFailedError()

    def _deletion_observations(
        self, job_ref: str
    ) -> tuple[list[Mapping[str, object]], list[Mapping[str, object]]]:
        credentials: list[Mapping[str, object]] = [
            CredentialObservation(
                credential_grant_ref=grant.credential_grant_ref,
                state=grant.state,
                secret_present=grant.secret_present,
                observed_at=grant.observed_at,
            ).model_dump(mode="json", by_alias=True)
            for grant in (
                self._grant_snapshot(record)
                for record in self._store.list_runtime("credential", job_ref)
            )
        ]
        transfers: list[Mapping[str, object]] = [
            TransferObservation(
                transfer_ref=snapshot.transfer_ref,
                state=snapshot.state,
                observed_at=snapshot.observed_at,
            ).model_dump(mode="json", by_alias=True)
            for snapshot in (
                self._workspace_runtime.inspect_transfer(job_ref, str(_field(record, "identity")))
                for record in self._store.list_runtime("transfer", job_ref)
            )
        ]
        return credentials, transfers

    def _cleanup_target(self, record: object) -> CredentialState | None:
        values = _runtime_values(record)
        retained = values.get("cleanupTarget")
        if retained is not None:
            try:
                target = CredentialState(retained)
            except ValueError as error:
                raise DependencyUnavailableError("credential cleanup target is invalid") from error
            if target not in _CLEANUP_TARGETS:
                raise DependencyUnavailableError("credential cleanup target is invalid")
            return target
        grant = self._grant_snapshot(record)
        if grant.state is CredentialState.EXPIRED:
            return CredentialState.EXPIRED
        if grant.ack_agent_run_ref is not None or grant.consumed_at is not None:
            return CredentialState.DESTROYED
        if self._now() >= grant.expires_at:
            return CredentialState.EXPIRED
        if grant.state in {CredentialState.DESTROY_FAILED, CredentialState.INDETERMINATE}:
            return CredentialState.REVOKED
        return None

    def _credential_secret(
        self, job_ref: str, metadata: CredentialGrantMetadata, raw_bytes: bytes
    ) -> dict[str, object]:
        return {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": credential_secret_name(job_ref),
                "labels": {"researchcosmos.io/managed-by": "v2-attempt-runtime"},
                "ownerReferences": [
                    {
                        "apiVersion": "batch/v1",
                        "kind": "Job",
                        "name": job_ref,
                        "uid": str(metadata.job_uid),
                        "controller": False,
                        "blockOwnerDeletion": False,
                    }
                ],
                "annotations": {
                    "researchcosmos.io/job-uid": str(metadata.job_uid),
                    "researchcosmos.io/pod-uid": str(metadata.pod_uid),
                    "researchcosmos.io/grant-ref": metadata.credential_grant_ref,
                },
            },
            "type": "Opaque",
            "data": {"credential": base64.b64encode(raw_bytes).decode("ascii")},
        }

    def _generation_values(
        self,
        job_ref: str,
        request: AgentStartRequest,
        digest: str,
        binding: JobBindingSnapshot,
        grant: CredentialGrantSnapshot,
    ) -> dict[str, str]:
        now = self._now()
        snapshot = GenerationSnapshot(
            job_ref=job_ref,
            generation=request.generation,
            agent_run_ref=request.agent_run_ref,
            execution_envelope_ref=request.execution_envelope_ref,
            execution_envelope_digest=request.execution_envelope_digest,
            launch_bundle_path=request.launch_bundle_path,
            launch_bundle_digest=request.launch_bundle_digest,
            launch_bundle_size_bytes=request.launch_bundle_size_bytes,
            material_paths=request.material_paths,
            credential_grant_ref=request.credential_grant_ref,
            start_metadata_digest=digest,
            runner_state=RunnerState.ACCEPTED,
            supervisor_alive=True,
            pid=None,
            exit_code=None,
            started_at=None,
            finished_at=None,
            observed_at=now,
            replayed=False,
            credential_acknowledged_at=None,
            credential_destroyed_at=None,
        )
        return {
            "identityDigest": digest,
            "jobUid": str(binding.job_uid),
            "podUid": str(binding.pod_uid),
            "grantAudience": grant.audience,
            "credentialSha256": grant.credential_sha256,
            "payload": snapshot.model_dump_json(by_alias=True),
        }

    @staticmethod
    def _generation_snapshot(record: object, *, replayed: bool) -> GenerationSnapshot:
        result = GenerationSnapshot.model_validate_json(_runtime_values(record)["payload"])
        return result.model_copy(update={"replayed": replayed})

    @staticmethod
    def _request_from_generation(generation: GenerationSnapshot) -> AgentStartRequest:
        return AgentStartRequest(
            execution_envelope_ref=generation.execution_envelope_ref,
            execution_envelope_digest=generation.execution_envelope_digest,
            agent_run_ref=generation.agent_run_ref,
            generation=generation.generation,
            launch_bundle_path=generation.launch_bundle_path,
            launch_bundle_digest=generation.launch_bundle_digest,
            launch_bundle_size_bytes=generation.launch_bundle_size_bytes,
            material_paths=generation.material_paths,
            credential_grant_ref=generation.credential_grant_ref,
        )

    @staticmethod
    def _validate_retained_generation(
        retained: GenerationSnapshot,
        request: AgentStartRequest,
        binding: JobBindingSnapshot,
    ) -> None:
        if (
            retained.job_ref != binding.job_ref
            or V2JobProvider._request_from_generation(retained) != request
        ):
            raise IdentityDigestConflict()
        if not hmac.compare_digest(
            retained.start_metadata_digest, canonical_digest(request.digest_payload())
        ):
            raise DependencyUnavailableError("retained generation metadata is inconsistent")

    @staticmethod
    def _validate_generation_grant(
        grant: CredentialGrantSnapshot,
        request: AgentStartRequest,
        binding: JobBindingSnapshot,
    ) -> None:
        if (
            grant.credential_grant_ref != request.credential_grant_ref
            or grant.agent_run_ref != request.agent_run_ref
            or grant.generation != request.generation
            or grant.launch_bundle_digest != request.launch_bundle_digest
            or str(grant.job_uid) != str(binding.job_uid)
            or str(grant.pod_uid) != str(binding.pod_uid)
            or grant.job_ref != binding.job_ref
        ):
            raise StateConflictError("The credential grant is not bound to this start request")

    @staticmethod
    def _validate_agent_ack(
        rpc: AgentRpcResponse,
        request: AgentStartRequest,
        audience: str,
        credential_sha: str,
    ) -> None:
        if (
            type(rpc.protocol_version) is not int
            or rpc.protocol_version != 1
            or type(rpc.generation) is not int
            or rpc.generation != request.generation
            or rpc.agent_run_ref != request.agent_run_ref
            or rpc.launch_bundle_digest != request.launch_bundle_digest
            or not _SHA256.fullmatch(rpc.launch_bundle_digest)
            or rpc.credential_grant_ref != request.credential_grant_ref
            or rpc.audience != audience
            or rpc.credential_sha256 != credential_sha
            or not _SHA256.fullmatch(credential_sha)
            or type(rpc.credential_consumed) is not bool
            or not rpc.credential_consumed
            or type(rpc.supervisor_alive) is not bool
            or not rpc.supervisor_alive
            or not isinstance(rpc.state, str)
            or rpc.state not in {"running", "exited"}
            or rpc.error is not None
            or (rpc.exit_code is not None and type(rpc.exit_code) is not int)
            or (rpc.pid is not None and type(rpc.pid) is not int)
            or (rpc.pid is not None and rpc.pid < 1)
            or (rpc.state == "exited" and type(rpc.exit_code) is not int)
        ):
            raise StateConflictError(
                "The supervisor acknowledgement does not match the start request"
            )

    def _latest_generation(self, job_ref: str) -> GenerationSnapshot | None:
        generations = [
            self._generation_snapshot(item, replayed=False)
            for item in self._store.list_runtime("generation", job_ref)
        ]
        return max(generations, key=lambda item: item.generation) if generations else None

    def _agent_rpc(
        self,
        binding: JobBindingSnapshot,
        request: AgentStartRequest,
        audience: str,
        credential_sha: str,
    ) -> AgentRpcResponse:
        if self._transport is None or binding.pod_uid is None:
            raise DependencyUnavailableError()
        return self._transport.agent_rpc(
            {
                "jobRef": binding.job_ref,
                "jobUid": str(binding.job_uid),
                "podUid": str(binding.pod_uid),
            },
            {
                "protocolVersion": 1,
                "generation": request.generation,
                "agentRunRef": request.agent_run_ref,
                "executionEnvelopeRef": request.execution_envelope_ref,
                "executionEnvelopeDigest": request.execution_envelope_digest,
                "launchBundlePath": request.launch_bundle_path,
                "launchBundleDigest": request.launch_bundle_digest,
                "launchBundleSizeBytes": request.launch_bundle_size_bytes,
                "materialPaths": request.material_paths,
                "credentialGrantRef": request.credential_grant_ref,
                "audience": audience,
                "credentialSha256": credential_sha,
            },
        )

    def _runtime_records(self, kind: str, job_ref: str) -> Sequence[object]:
        method = getattr(self._store, "list_runtime", None)
        records = tuple(method(kind, job_ref)) if callable(method) else ()
        if kind in {"finalize", "cancel"}:
            slot = tuple(record for record in records if str(_field(record, "identity")) == "slot")
            return slot or records
        return records

    def _create_or_reconcile_job(self, rendered_job: object, job_ref: str) -> object:
        try:
            job = self._kube.create_job(rendered_job)
        except Exception as error:
            # A conflict or a dropped create response is reconciled by deterministic name.
            job = self._read_job(job_ref)
            if job is None:
                raise DependencyUnavailableError from error
        if job is None:
            job = self._read_job(job_ref)
        if job is None:
            raise DependencyUnavailableError("Kubernetes did not return the created Job")
        return job

    def _read_job(self, job_ref: str) -> object | None:
        try:
            return self._kube.read_job(job_ref)
        except Exception as error:
            if _api_status(error) == 404:
                return None
            raise DependencyUnavailableError from error

    def _list_job_pods(self, job_ref: str, job_uid: str) -> Sequence[object]:
        try:
            return self._kube.list_job_pods(job_ref, job_uid)
        except Exception as error:
            raise DependencyUnavailableError from error

    def _read_role_logs(
        self,
        job_ref: str,
        pod_uid: str,
        container: str,
        cursor: str | None,
        limit_bytes: int,
    ) -> object:
        try:
            return self._kube.read_role_logs(
                job_ref,
                pod_uid,
                container,
                cursor,
                limit_bytes,
            )
        except (InvalidCursorError, StaleCursorError):
            raise
        except Exception as error:
            raise DependencyUnavailableError from error

    def _delete_job(self, job_ref: str) -> None:
        try:
            self._kube.delete_job(job_ref)
        except Exception as error:
            if _api_status(error) != 404:
                raise DependencyUnavailableError from error

    def _wait_for_job_absence(self, job_ref: str) -> bool:
        for attempt in range(self._delete_poll_attempts):
            if self._read_job(job_ref) is None:
                return True
            if attempt + 1 < self._delete_poll_attempts:
                self._sleeper(self._delete_poll_interval_seconds)
        return False

    def _snapshot(
        self,
        record: object,
        job: object,
        pods: Sequence[object],
        *,
        replacement_reason: str | None,
    ) -> JobBindingSnapshot:
        observed_at = self._now()
        pod = pods[0] if len(pods) == 1 else None
        binding_state, binding_reason = _binding_state(job, pod, replacement_reason)
        workload_terminal = binding_state in {
            JobBindingState.SUCCEEDED,
            JobBindingState.FAILED,
        }
        spec_payload = _field(record, "spec_payload", {})
        agent = _role_snapshot(spec_payload, pod, "agent") if pod is not None else None
        workspace = _role_snapshot(spec_payload, pod, "workspace") if pod is not None else None
        job_uid = str(_field(record, "job_uid", None) or _required_text(job, "metadata", "uid"))
        pod_uid = _field(record, "pod_uid", None)
        if pod_uid is None and pod is not None and replacement_reason is None:
            pod_uid = _required_text(pod, "metadata", "uid")
        created_at = _as_datetime(
            _field(record, "created_at", None),
            _as_datetime(_path(job, "metadata", "creation_timestamp"), observed_at),
        )
        updated_at = _as_datetime(_field(record, "updated_at", None), observed_at)
        started_at = _as_optional_datetime(_path(pod, "status", "start_time")) if pod else None
        finished_at = _job_finished_at(job)
        cleanup = CleanupObservation(
            state=CleanupState.PENDING,
            reason=None,
            observed_at=observed_at,
        )
        gpu_release_state = (
            CleanupState.PENDING if _workspace_gpu(record) > 0 else CleanupState.NOT_REQUIRED
        )
        grants = [
            self._grant_snapshot(item)
            for item in self._runtime_records("credential", str(_field(record, "job_ref")))
        ]
        generations = [
            self._generation_snapshot(item, replayed=False)
            for item in self._runtime_records("generation", str(_field(record, "job_ref")))
        ]
        runtime_job_ref = str(_field(record, "job_ref"))
        operations = [
            (
                str(_field(item, "identity")),
                _validated_runtime_state(
                    _validate_runtime_binding(item, job_uid, str(pod_uid)), "operation"
                )[0],
            )
            for item in self._runtime_records("operation", runtime_job_ref)
        ]
        transfers = [
            (
                str(_field(item, "identity")),
                *_validated_runtime_state(
                    _validate_runtime_binding(item, job_uid, str(pod_uid)), "transfer"
                ),
            )
            for item in self._runtime_records("transfer", runtime_job_ref)
        ]
        finalizations = self._runtime_records("finalize", runtime_job_ref)
        cancellations = self._runtime_records("cancel", runtime_job_ref)
        latest = max(generations, key=lambda item: item.generation) if generations else None
        finalize_action = _finalize_action(finalizations)
        if finalizations and binding_state not in {
            JobBindingState.SUCCEEDED,
            JobBindingState.FAILED,
        }:
            binding_state = JobBindingState.FINALIZING
        cancel_action = action_snapshot(cancellations, "cancelRef")
        output_loss_possible = False
        if cancellations:
            cancel_state, output_loss_possible, resume_from = read_phase(cancellations[-1])
            if cancel_state == "succeeded":
                binding_state = JobBindingState.CANCELED
                binding_reason = "provider cancellation completed"
                cleanup = CleanupObservation(
                    state=CleanupState.COMPLETE,
                    reason=None,
                    observed_at=observed_at,
                )
            elif cancel_state == "indeterminate" and resume_from is None:
                binding_state = JobBindingState.INDETERMINATE
                binding_reason = "provider cancellation is indeterminate"
                cleanup = CleanupObservation(
                    state=CleanupState.INDETERMINATE,
                    reason=binding_reason,
                    observed_at=observed_at,
                )
            else:
                binding_state = JobBindingState.CANCELING
                binding_reason = "provider cancellation is in progress"
        if (
            workload_terminal
            and agent is not None
            and workspace is not None
            and agent.state is RoleState.TERMINATED
            and workspace.state is RoleState.TERMINATED
        ):
            gpu_release_state = (
                CleanupState.COMPLETE if _workspace_gpu(record) > 0 else CleanupState.NOT_REQUIRED
            )
        return JobBindingSnapshot(
            job_ref=str(_field(record, "job_ref")),
            provider_handle=str(_field(record, "job_ref")),
            provider_request_id=str(_field(record, "provider_request_id")),
            subject_ref=str(_field(spec_payload, "subjectRef")),
            runtime_plan_digest=str(_field(spec_payload, "runtimePlanDigest")),
            spec_digest=str(_field(record, "spec_digest")),
            job_uid=UUID(job_uid),
            pod_uid=pod_uid,
            resource_version=_optional_path_text(job, "metadata", "resource_version"),
            node_name=_optional_path_text(pod, "spec", "node_name") if pod else None,
            binding_state=binding_state,
            binding_reason=binding_reason,
            observed_pod_count=len(pods),
            created_at=created_at,
            updated_at=updated_at,
            started_at=started_at,
            finished_at=finished_at,
            observed_at=observed_at,
            agent=agent,
            workspace=workspace,
            latest_agent_generation=latest,
            active_operation_refs=sorted(
                ref for ref, state in operations if state in _OPERATION_ACTIVE_STATES
            ),
            terminal_operation_refs=sorted(
                ref for ref, state in operations if state in _OPERATION_TERMINAL_STATES
            ),
            credential_observations=[
                CredentialObservation(
                    credential_grant_ref=item.credential_grant_ref,
                    state=item.state,
                    secret_present=item.secret_present,
                    observed_at=item.observed_at,
                )
                for item in grants
            ],
            transfer_observations=[
                TransferObservation(
                    transfer_ref=ref,
                    state=TransferState(state),
                    observed_at=observed,
                )
                for ref, state, observed in sorted(transfers)
            ],
            finalize_action=finalize_action,
            cancel_action=cancel_action,
            delete_action=_not_requested_action(),
            output_loss_possible=output_loss_possible,
            cleanup=cleanup,
            gpu_release=CleanupObservation(
                state=gpu_release_state,
                reason=None,
                observed_at=observed_at,
            ),
        )

    def _missing_job_snapshot(self, record: object) -> JobBindingSnapshot:
        observed_at = self._now()
        spec_payload = _field(record, "spec_payload", {})
        created_at = _as_datetime(_field(record, "created_at"), observed_at)
        cancellations = self._runtime_records("cancel", str(_field(record, "job_ref")))
        cancel_action = action_snapshot(cancellations, "cancelRef")
        output_loss = read_phase(cancellations[-1])[1] if cancellations else False
        return JobBindingSnapshot(
            job_ref=str(_field(record, "job_ref")),
            provider_handle=str(_field(record, "job_ref")),
            provider_request_id=str(_field(record, "provider_request_id")),
            subject_ref=str(_field(spec_payload, "subjectRef")),
            runtime_plan_digest=str(_field(spec_payload, "runtimePlanDigest")),
            spec_digest=str(_field(record, "spec_digest")),
            job_uid=UUID(str(_field(record, "job_uid"))),
            pod_uid=_field(record, "pod_uid", None),
            resource_version=_optional_text(record, "resource_version"),
            node_name=None,
            binding_state=JobBindingState.INDETERMINATE,
            binding_reason=_optional_text(record, "indeterminate_reason")
            or "the retained Job is no longer observable",
            observed_pod_count=0,
            created_at=created_at,
            updated_at=_as_datetime(_field(record, "updated_at", None), observed_at),
            started_at=None,
            finished_at=None,
            observed_at=observed_at,
            agent=None,
            workspace=None,
            latest_agent_generation=None,
            active_operation_refs=[],
            terminal_operation_refs=[],
            credential_observations=[],
            transfer_observations=[],
            finalize_action=_finalize_action(
                self._runtime_records("finalize", str(_field(record, "job_ref")))
            ),
            cancel_action=cancel_action,
            delete_action=_not_requested_action(),
            output_loss_possible=output_loss,
            cleanup=CleanupObservation(
                state=CleanupState.INDETERMINATE,
                reason="Job absence is not a confirmed delete",
                observed_at=observed_at,
            ),
            gpu_release=CleanupObservation(
                state=CleanupState.INDETERMINATE,
                reason="Job absence does not prove resource release",
                observed_at=observed_at,
            ),
        )

    def _deleting_snapshot(
        self, snapshot: JobBindingSnapshot, record: object
    ) -> JobBindingSnapshot:
        observed_at = self._now()
        cleanup_state = _cleanup_state(record, "cleanup_state", CleanupState.PENDING)
        gpu_state = _cleanup_state(record, "gpu_release_state", CleanupState.PENDING)
        return snapshot.model_copy(
            update={
                "binding_state": JobBindingState.DELETING,
                "binding_reason": "provider deletion is in progress",
                "delete_action": ActionSnapshot(
                    action_ref=str(_field(record, "delete_ref")),
                    request_digest=str(_field(record, "delete_request_digest")),
                    state=ActionState.ACCEPTED,
                    observed_at=_as_datetime(_field(record, "updated_at"), observed_at),
                ),
                "cleanup": CleanupObservation(
                    state=cleanup_state,
                    reason=_optional_text(record, "cleanup_reason"),
                    observed_at=observed_at,
                ),
                "gpu_release": CleanupObservation(
                    state=gpu_state,
                    reason=_optional_text(record, "gpu_release_reason"),
                    observed_at=observed_at,
                ),
            }
        )

    def _mark_deleted(
        self,
        record: object,
        *,
        delete_ref: str,
        request_digest: str,
        final_state: ProviderTerminalState,
        deleted_at: datetime,
        expires_at: datetime,
        cleanup_state: CleanupState,
        cleanup_phase: str,
        gpu_release_state: CleanupState = CleanupState.PENDING,
        credential_observations: Sequence[Mapping[str, object]] = (),
        transfer_observations: Sequence[Mapping[str, object]] = (),
    ) -> object:
        try:
            return self._store.mark_deleted(
                str(_field(record, "provider_request_id")),
                deleted_at=deleted_at,
                expires_at=expires_at,
                delete_ref=delete_ref,
                delete_request_digest=request_digest,
                final_state=final_state.value,
                cleanup_state=cleanup_state.value,
                cleanup_phase=cleanup_phase,
                gpu_release_state=gpu_release_state.value,
                credential_observations=list(credential_observations),
                transfer_observations=list(transfer_observations),
            )
        except KcsV2Error:
            raise
        except Exception as error:
            raise DependencyUnavailableError from error

    def _mark_indeterminate(self, record: object, reason: str) -> object:
        try:
            return self._store.mark_indeterminate(
                str(_field(record, "provider_request_id")), reason
            )
        except KcsV2Error:
            raise
        except Exception as error:
            raise DependencyUnavailableError from error

    def _raise_if_record_conflicts(
        self,
        record: object,
        provider_request_id: str,
        spec_digest: str,
    ) -> None:
        if str(
            _field(record, "provider_request_id")
        ) != provider_request_id or not hmac.compare_digest(
            str(_field(record, "spec_digest")), spec_digest
        ):
            raise IdentityDigestConflict

    @staticmethod
    def _raise_if_delete_conflicts(
        record: object,
        delete_ref: str,
        request_digest: str,
    ) -> None:
        if str(_field(record, "delete_ref", "")) != delete_ref or not hmac.compare_digest(
            str(_field(record, "delete_request_digest", "")), request_digest
        ):
            raise IdentityDigestConflict

    def _list_query_digest(self, query: JobListQuery) -> str:
        payload = {
            "namespace": self._namespace,
            "providerRequestId": query.provider_request_id,
            "subjectRef": query.subject_ref,
            "states": sorted(state.value for state in query.states),
            "createdAfter": query.created_after.isoformat() if query.created_after else None,
            "includeDeleted": query.include_deleted,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _page_offset(self, token: str | None, query_digest: str) -> int:
        if token is None:
            return 0
        payload = _decode_token(token, InvalidPageTokenError)
        if payload.get("kind") != "page" or not isinstance(payload.get("offset"), int):
            raise InvalidPageTokenError
        if payload.get("namespace") != self._namespace or payload.get("query") != query_digest:
            raise StalePageTokenError
        offset_value = payload.get("offset")
        if not isinstance(offset_value, int):
            raise InvalidPageTokenError
        offset = offset_value
        if offset < 0:
            raise InvalidPageTokenError
        return offset

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise RuntimeError("provider clock must return an aware datetime")
        return value.astimezone(UTC)


def _field(value: object, name: str, default: object = _MISSING) -> Any:
    if isinstance(value, Mapping):
        if name in value:
            return value[name]
    elif hasattr(value, name):
        return getattr(value, name)
    if default is _MISSING:
        raise DependencyUnavailableError(f"Provider record is missing required field {name}")
    return default


def _runtime_values(record: object) -> Mapping[str, str]:
    values = _field(record, "values", {})
    if not isinstance(values, Mapping):
        raise DependencyUnavailableError("runtime record values are invalid")
    return {str(key): str(value) for key, value in values.items()}


def _runtime_values_with(record: object, changes: Mapping[str, str]) -> dict[str, str]:
    values = dict(_runtime_values(record))
    values.update(changes)
    return values


def _runtime_state_observation(record: object) -> tuple[str, datetime]:
    values = _runtime_values(record)
    try:
        payload: object = json.loads(values["payload"])
    except (KeyError, json.JSONDecodeError) as error:
        raise DependencyUnavailableError("runtime observation payload is invalid") from error
    if not isinstance(payload, Mapping):
        raise DependencyUnavailableError("runtime observation payload is invalid")
    state = payload.get("state")
    if not isinstance(state, str) or not state:
        raise DependencyUnavailableError("runtime observation state is invalid")
    observed_value = payload.get("observedAt")
    if observed_value is None:
        raise DependencyUnavailableError("runtime observation timestamp is absent")
    try:
        observed = _as_datetime(observed_value, datetime.now(UTC))
    except (TypeError, ValueError) as error:
        raise DependencyUnavailableError("runtime observation timestamp is invalid") from error
    return state, observed


def _validated_runtime_state(record: object, kind: str) -> tuple[str, datetime]:
    state, observed = _runtime_state_observation(record)
    allowed = (
        _OPERATION_ACTIVE_STATES | _OPERATION_TERMINAL_STATES
        if kind == "operation"
        else {item.value for item in TransferState}
    )
    if state not in allowed:
        raise DependencyUnavailableError(f"retained {kind} state is invalid")
    return state, observed


def _validate_runtime_binding(record: object, job_uid: str, pod_uid: str) -> object:
    values = _runtime_values(record)
    if values.get("jobUid") != job_uid or values.get("podUid") != pod_uid:
        raise DependencyUnavailableError("runtime observation binding is inconsistent")
    return record


def _finalize_action(records: Sequence[object]) -> ActionSnapshot:
    if not records:
        return _not_requested_action()
    record = records[-1]
    values = _runtime_values(record)
    try:
        payload = json.loads(values["payload"])
        observed_at = _as_datetime(payload["observedAt"], datetime.now(UTC))
        state = {
            "succeeded": ActionState.SUCCEEDED,
            "indeterminate": ActionState.INDETERMINATE,
        }.get(payload.get("state"), ActionState.ACCEPTED)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        state = ActionState.INDETERMINATE
        observed_at = datetime.now(UTC)
    return ActionSnapshot(
        action_ref=values.get("finalizeRef") or str(_field(record, "identity")),
        request_digest=values.get("identityDigest"),
        state=state,
        observed_at=observed_at,
    )


def _finalize_phase(record: object) -> str:
    try:
        value = json.loads(_runtime_values(record)["payload"])
        phase = value.get("state")
    except (KeyError, TypeError, json.JSONDecodeError):
        return "indeterminate"
    return str(phase) if phase else "indeterminate"


def _finalize_resume_from(record: object) -> str:
    try:
        value = json.loads(_runtime_values(record)["payload"])
        resume = value.get("resumeFrom")
    except (KeyError, TypeError, json.JSONDecodeError):
        return "indeterminate"
    return str(resume) if resume else "indeterminate"


def _path(value: object, *names: str) -> Any:
    current = value
    for name in names:
        current = _field(current, name, None)
        if current is None:
            return None
    return current


def _required_text(value: object, *path: str) -> str:
    result = _path(value, *path)
    if result is None or str(result) == "":
        raise DependencyUnavailableError(f"Kubernetes object is missing {'.'.join(path)}")
    return str(result)


def _optional_text(value: object, name: str) -> str | None:
    result = _field(value, name, None)
    return str(result) if result is not None else None


def _optional_path_text(value: object, *path: str) -> str | None:
    result = _path(value, *path)
    return str(result) if result is not None else None


def _api_status(error: Exception) -> int | None:
    status = getattr(error, "status", None)
    return status if isinstance(status, int) else None


def _as_datetime(value: object, fallback: datetime) -> datetime:
    parsed = _as_optional_datetime(value)
    return parsed or fallback


def _as_optional_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(UTC)
    raise DependencyUnavailableError("Provider observation contains an invalid timestamp")


def _not_requested_action() -> ActionSnapshot:
    return ActionSnapshot(
        action_ref=None,
        request_digest=None,
        state=ActionState.NOT_REQUESTED,
        observed_at=None,
    )


def _is_deleted(record: object) -> bool:
    return str(_field(record, "state", "")) == "deleted"


def _workspace_gpu(record: object) -> int:
    spec = _field(record, "spec_payload", {})
    workspace = _field(spec, "workspace", {})
    resources = _field(workspace, "resources", {})
    return int(_field(resources, "gpu", 0))


def _binding_state(
    job: object,
    pod: object | None,
    replacement_reason: str | None,
) -> tuple[JobBindingState, str | None]:
    if replacement_reason is not None:
        return JobBindingState.INDETERMINATE, replacement_reason
    if _job_condition_true(job, "Failed") or int(_path(job, "status", "failed") or 0) > 0:
        return JobBindingState.FAILED, _job_condition_reason(job, "Failed")
    if _job_condition_true(job, "Complete") or int(_path(job, "status", "succeeded") or 0) > 0:
        return JobBindingState.SUCCEEDED, None
    if pod is None:
        return JobBindingState.PROVISIONING, None
    statuses = tuple(_path(pod, "status", "container_statuses") or ())
    statuses_by_name = {
        str(_field(status, "name", "")): status
        for status in statuses
        if _field(status, "name", None) in {"agent", "workspace"}
    }
    if set(statuses_by_name) == {"agent", "workspace"} and all(
        bool(_field(status, "ready", False)) for status in statuses_by_name.values()
    ):
        return JobBindingState.RUNNING, None
    return JobBindingState.BOUND, None


def _job_condition_true(job: object, condition_type: str) -> bool:
    for condition in _path(job, "status", "conditions") or ():
        if (
            _field(condition, "type", None) == condition_type
            and str(_field(condition, "status", "")).lower() == "true"
        ):
            return True
    return False


def _job_condition_reason(job: object, condition_type: str) -> str | None:
    for condition in _path(job, "status", "conditions") or ():
        if _field(condition, "type", None) == condition_type:
            return _optional_text(condition, "reason")
    return None


def _job_finished_at(job: object) -> datetime | None:
    for condition in _path(job, "status", "conditions") or ():
        if (
            _field(condition, "type", None) in {"Complete", "Failed"}
            and str(_field(condition, "status", "")).lower() == "true"
        ):
            return _as_optional_datetime(_field(condition, "last_transition_time", None))
    return None


@overload
def _role_snapshot(
    spec_payload: object,
    pod: object,
    role: Literal["agent"],
) -> AgentRoleSnapshot | None: ...


@overload
def _role_snapshot(
    spec_payload: object,
    pod: object,
    role: Literal["workspace"],
) -> WorkspaceRoleSnapshot | None: ...


def _role_snapshot(
    spec_payload: object,
    pod: object,
    role: Literal["agent", "workspace"],
) -> AgentRoleSnapshot | WorkspaceRoleSnapshot | None:
    status = next(
        (
            item
            for item in (_path(pod, "status", "container_statuses") or ())
            if _field(item, "name", None) == role
        ),
        None,
    )
    if status is None:
        return None

    spec = _field(spec_payload, role, {})
    resources = _field(spec, "resources", {})
    storage_gib = int(_field(_field(spec_payload, "sharedWorkspace", {}), "sizeLimitGiB", 20))
    state, reason, exit_code, started_at, finished_at = _container_state(status)
    container_id = _optional_text(status, "container_id")
    image_id = _optional_text(status, "image_id")
    ready = bool(_field(status, "ready", False))
    restart_count = int(_field(status, "restart_count", 0))
    if role == "agent":
        return AgentRoleSnapshot(
            container_id=container_id,
            image_id=image_id,
            state=state,
            ready=ready,
            restart_count=restart_count,
            exit_code=exit_code,
            reason=reason,
            started_at=started_at,
            finished_at=finished_at,
            requested=AgentRequestedResources(
                cpu_millis=int(_field(resources, "cpuMillis", 1000)),
                memory_mib=int(_field(resources, "memoryMiB", 2048)),
                gpu=0,
                storage_gib=storage_gib,
            ),
            observed=AgentObservedResources(
                cpu_millis=None,
                memory_mib=None,
                gpu=None,
                storage_gib=None,
            ),
        )
    return WorkspaceRoleSnapshot(
        container_id=container_id,
        image_id=image_id,
        state=state,
        ready=ready,
        restart_count=restart_count,
        exit_code=exit_code,
        reason=reason,
        started_at=started_at,
        finished_at=finished_at,
        requested=WorkspaceRequestedResources(
            cpu_millis=int(_field(resources, "cpuMillis", 2000)),
            memory_mib=int(_field(resources, "memoryMiB", 8192)),
            gpu=int(_field(resources, "gpu", 0)),
            storage_gib=storage_gib,
        ),
        observed=WorkspaceObservedResources(
            cpu_millis=None,
            memory_mib=None,
            gpu=None,
            storage_gib=None,
        ),
    )


def _container_state(
    status: object,
) -> tuple[RoleState, str | None, int | None, datetime | None, datetime | None]:
    state = _field(status, "state", None)
    running = _field(state, "running", None) if state is not None else None
    if running is not None:
        return (
            RoleState.RUNNING,
            None,
            None,
            _as_optional_datetime(_field(running, "started_at", None)),
            None,
        )
    terminated = _field(state, "terminated", None) if state is not None else None
    if terminated is not None:
        return (
            RoleState.TERMINATED,
            _optional_text(terminated, "reason"),
            int(_field(terminated, "exit_code", 0)),
            _as_optional_datetime(_field(terminated, "started_at", None)),
            _as_optional_datetime(_field(terminated, "finished_at", None)),
        )
    waiting = _field(state, "waiting", None) if state is not None else None
    if waiting is not None:
        return (
            RoleState.WAITING,
            _optional_text(waiting, "reason"),
            None,
            None,
            None,
        )
    return RoleState.UNKNOWN, None, None, None, None


def _terminal_state_for_binding(state: JobBindingState) -> ProviderTerminalState:
    return {
        JobBindingState.SUCCEEDED: ProviderTerminalState.SUCCEEDED,
        JobBindingState.FAILED: ProviderTerminalState.FAILED,
        JobBindingState.CANCELED: ProviderTerminalState.CANCELED,
    }.get(state, ProviderTerminalState.INDETERMINATE)


def _provider_terminal_state(value: object) -> ProviderTerminalState:
    try:
        return ProviderTerminalState(str(value))
    except ValueError:
        return ProviderTerminalState.INDETERMINATE


def _tombstone_payload(record: object) -> dict[str, object]:
    return _as_tombstone(record).model_dump(mode="json", by_alias=True)


def _as_tombstone(record: object) -> JobTombstone:
    deleted_at = _as_datetime(_field(record, "deleted_at"), datetime.now(UTC))
    cleanup_state = CleanupState(str(_field(record, "cleanup_state", "complete")))
    gpu_release_state = CleanupState(str(_field(record, "gpu_release_state", "not_required")))
    credential_values, transfer_values = _stored_tombstone_observations(record)
    return JobTombstone(
        provider_request_id=str(_field(record, "provider_request_id")),
        spec_digest=str(_field(record, "spec_digest")),
        job_ref=str(_field(record, "job_ref")),
        job_uid=UUID(str(_field(record, "job_uid"))),
        pod_uid=_field(record, "pod_uid", None),
        state="deleted",
        final_state=_provider_terminal_state(_field(record, "final_state", "indeterminate")),
        delete_ref=str(_field(record, "delete_ref")),
        delete_request_digest=str(_field(record, "delete_request_digest")),
        created_at=_as_datetime(_field(record, "created_at"), deleted_at),
        cleanup=CleanupObservation(
            state=cleanup_state,
            reason=_optional_text(record, "cleanup_reason"),
            observed_at=deleted_at,
        ),
        gpu_release=CleanupObservation(
            state=gpu_release_state,
            reason=_optional_text(record, "gpu_release_reason"),
            observed_at=deleted_at,
        ),
        credential_observations=[
            CredentialObservation.model_validate(item) for item in credential_values
        ],
        transfer_observations=[
            TransferObservation.model_validate(item) for item in transfer_values
        ],
        deleted_at=deleted_at,
        expires_at=_as_datetime(_field(record, "expires_at"), deleted_at),
    )


def _stored_tombstone_observations(
    record: object,
) -> tuple[list[Mapping[str, object]], list[Mapping[str, object]]]:
    def load(name: str) -> list[Mapping[str, object]]:
        raw = _field(record, name, None)
        try:
            value: object = json.loads(str(raw)) if raw is not None else []
        except json.JSONDecodeError as error:
            raise DependencyUnavailableError(
                "retained tombstone observations are invalid"
            ) from error
        if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
            raise DependencyUnavailableError("retained tombstone observations are invalid")
        return [dict(item) for item in value]

    return load("credential_observations_json"), load("transfer_observations_json")


def _cleanup_state(record: object, field_name: str, fallback: CleanupState) -> CleanupState:
    try:
        return CleanupState(str(_field(record, field_name, fallback.value)))
    except ValueError as error:
        raise DependencyUnavailableError("retained cleanup state is invalid") from error


def _later_delete_phase(record: object, desired: str) -> str:
    order = {
        None: 0,
        "tombstone_persisted": 1,
        "credentials_destroyed": 2,
        "job_delete_requested": 3,
        "workload_absent": 4,
        "owner_records_deleted": 5,
        "complete": 6,
    }
    retained = _field(record, "cleanup_phase", None)
    if retained not in order or desired not in order:
        raise DependencyUnavailableError("retained deletion phase is invalid")
    return str(retained) if order[retained] >= order[desired] else desired


def _delete_phase_reached(record: object, desired: str) -> bool:
    order = {
        None: 0,
        "tombstone_persisted": 1,
        "credentials_destroyed": 2,
        "job_delete_requested": 3,
        "workload_absent": 4,
        "owner_records_deleted": 5,
        "complete": 6,
    }
    retained = _field(record, "cleanup_phase", None)
    if retained not in order or desired not in order:
        raise DependencyUnavailableError("retained deletion phase is invalid")
    return order[retained] >= order[desired]


def _encode_token(payload: Mapping[str, object]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_token(
    token: str,
    error_type: type[InvalidPageTokenError],
) -> dict[str, object]:
    try:
        padding = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + padding)
        if base64.urlsafe_b64encode(raw).decode().rstrip("=") != token:
            raise ValueError
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise error_type from error
    return value
