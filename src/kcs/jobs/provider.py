"""Provider orchestration for the first executable KCS V2 Job journey.

The provider is deliberately limited to physical Kubernetes facts.  It reserves a
stable create identity before dispatch, reconciles a possibly lost create response,
and treats the first observed Pod UID as immutable binding reality.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
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
    CleanupObservation,
    CleanupState,
    CreateJobRequest,
    JobBindingSnapshot,
    JobBindingSnapshotList,
    JobBindingState,
    JobTombstone,
    LogContainer,
    ProviderTerminalState,
    RoleLogs,
    RoleState,
    WorkspaceObservedResources,
    WorkspaceRequestedResources,
    WorkspaceRoleSnapshot,
)
from .errors import (
    DependencyTimeoutError,
    DependencyUnavailableError,
    DigestMismatchError,
    IdentityDigestConflict,
    InvalidCursorError,
    InvalidPageTokenError,
    InvalidRequestError,
    JobNotFoundError,
    KcsV2Error,
    ReplacementPodError,
    StaleCursorError,
    StalePageTokenError,
    StateConflictError,
    TombstonedError,
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


@dataclass(frozen=True, slots=True)
class CreateResult:
    """A create snapshot plus the status distinction needed by the HTTP route."""

    snapshot: JobBindingSnapshot
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


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

        job = self._read_job(job_ref)
        if job is None:
            if _field(record, "job_uid", None) is None:
                raise DependencyUnavailableError(
                    "The create identity is reserved but no Job UID is observable"
                )
            record = self._mark_indeterminate(record, "the retained Job is no longer observable")
            return self._missing_job_snapshot(record)

        actual_job_uid = _required_text(job, "metadata", "uid")
        retained_job_uid = _field(record, "job_uid", None)
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

        return self._snapshot(record, job, pods, replacement_reason=replacement_reason)

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

    def delete(self, job_ref: str, delete_ref: str, request_digest: str) -> JobTombstone:
        """Persist deletion identity before removing workload reality."""

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
        else:
            final_state = _terminal_state_for_binding(self.inspect(job_ref).binding_state)

        deleted_at = _as_datetime(_field(record, "deleted_at", None), self._now())
        expires_at = _as_datetime(
            _field(record, "expires_at", None), deleted_at + self._tombstone_ttl
        )
        record = self._mark_deleted(
            record,
            delete_ref=delete_ref,
            request_digest=request_digest,
            final_state=final_state,
            deleted_at=deleted_at,
            expires_at=expires_at,
            cleanup_state=CleanupState.PENDING,
        )

        self._delete_job(job_ref)
        if not self._wait_for_job_absence(job_ref):
            raise DependencyTimeoutError("Kubernetes has not yet confirmed Job deletion")
        gpu_requested = _workspace_gpu(record) > 0
        record = self._mark_deleted(
            record,
            delete_ref=delete_ref,
            request_digest=request_digest,
            final_state=final_state,
            deleted_at=deleted_at,
            expires_at=expires_at,
            cleanup_state=CleanupState.COMPLETE,
            gpu_release_state=CleanupState.COMPLETE if gpu_requested else CleanupState.NOT_REQUIRED,
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
            latest_agent_generation=None,
            active_operation_refs=[],
            terminal_operation_refs=[],
            credential_observations=[],
            transfer_observations=[],
            finalize_action=_not_requested_action(),
            cancel_action=_not_requested_action(),
            delete_action=_not_requested_action(),
            output_loss_possible=False,
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
            finalize_action=_not_requested_action(),
            cancel_action=_not_requested_action(),
            delete_action=_not_requested_action(),
            output_loss_possible=False,
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
        gpu_release_state: CleanupState = CleanupState.PENDING,
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
                gpu_release_state=gpu_release_state.value,
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
        credential_observations=[],
        transfer_observations=[],
        deleted_at=deleted_at,
        expires_at=_as_datetime(_field(record, "expires_at"), deleted_at),
    )


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
