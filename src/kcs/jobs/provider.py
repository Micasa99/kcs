"""Provider orchestration for the first executable KCS V2 Job journey.

The provider is deliberately limited to physical Kubernetes facts.  It reserves a
stable create identity before dispatch, reconciles a possibly lost create response,
and keeps every Pod incarnation under the immutable Job UID.
"""
# ruff: noqa: E501

from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol, overload
from uuid import UUID

from kubernetes.utils.quantity import parse_quantity  # type: ignore[import-untyped]

from .canonical import canonical_bytes, canonical_digest
from .cluster_feed import ClusterFeed
from .contracts import (
    ActionSnapshot,
    ActionState,
    AgentObservedResources,
    AgentRequestedResources,
    AgentRoleSnapshot,
    AgentStartRequest,
    CancelJobRequest,
    CancelSpec,
    CapacitySnapshot,
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
    NetworkPolicyObservation,
    NodeTelemetryList,
    NvidiaDeviceTelemetry,
    NvidiaTelemetrySnapshot,
    ObservabilityHealth,
    OperationState,
    PodIncarnationSnapshot,
    PodIncarnationState,
    ProviderTerminalState,
    QueueSnapshot,
    RoleLogs,
    RoleState,
    RunnerState,
    RuntimeEventPage,
    TerminalCreateRequest,
    TerminalSessionSnapshot,
    TerminalState,
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
from .dev_session import DevSessionMutation, DevSessionRelayTarget, DevSessionService
from .errors import (
    CredentialActiveError,
    CredentialDestroyFailedError,
    CredentialExpiredError,
    CursorGapError,
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
    PreconditionFailedError,
    ReplacementPodError,
    RuntimeRecipeForbiddenError,
    StaleBindingError,
    StaleCursorError,
    StalePageTokenError,
    StateConflictError,
    TerminalBusyError,
    TerminalCredentialError,
    TombstonedError,
    TransferIndeterminateError,
)
from .lifecycle import (
    LifecycleClaim,
    LifecycleClose,
    LifecycleGate,
    ReconcileReport,
    action_snapshot,
    phase_payload,
    read_phase,
)
from .live_workspace import (
    LiveContentRange,
    LiveSnapshotResult,
    LiveWorkspaceRuntime,
)
from .m2_contracts import (
    CapabilityActivationPlan,
    LiveWorkspaceDiffPage,
    LiveWorkspaceSnapshot,
    LiveWorkspaceSnapshotRequest,
    ResolvedRuntimeAssembly,
    RuntimeAssemblyResolutionRequest,
)
from .native_contracts import (
    AnyJobBindingSnapshotList,
    DevSessionCreateRequest,
    DevSessionRenewRequest,
    DevSessionSnapshot,
    NativeCreateJobRequest,
    NativeFinalizeJobRequest,
    NativeJobBindingSnapshot,
    NativeRoleLogs,
    NativeRunnerGenerationSnapshot,
    NativeTerminalSessionSnapshot,
    ResolvedRuntimeRecipe,
    RunnerCredentialGrantSnapshot,
    RunnerStartRequest,
    RunnerStopRequest,
)
from .native_runtime import (
    NativeMutationResult,
    NativeRuntimeController,
    RunnerCredentialGrantMetadata,
)
from .project_workspace import (
    CreateProjectSnapshotRequest,
    EnsureProjectWorkspaceRequest,
    ProjectDevSessionCreateRequest,
    ProjectDevSessionMutation,
    ProjectDevSessionRenewRequest,
    ProjectDevSessionSnapshot,
    ProjectImportSnapshot,
    ProjectRelayTarget,
    ProjectSnapshotContent,
    ProjectTreeSnapshot,
    ProjectWorkspaceMutation,
    ProjectWorkspaceService,
    ProjectWorkspaceSnapshot,
    RegisterProjectImportRequest,
)
from .recipe_registry import runtime_recipe_digest
from .renderer import (
    PLATFORM_CA_MOUNT_PATH,
    activation_volume_name,
    credential_secret_name,
    network_policy_ref,
    network_policy_spec_digest,
    runner_credential_secret_name,
)
from .runtime_assembly import RuntimeAssemblyResolver, capability_activation_receipt
from .transport import (
    AgentRpcResponse,
    AgentRpcTransportProtocol,
    WorkspaceRpcTransportProtocol,
)
from .workspace_runtime import (
    StartMaterialBinding,
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
TERMINAL_WRITER_KIND = "terminal-writer"
TERMINAL_WRITER_ID = "workspace"
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
_START_MATERIAL_BINDINGS_KEY = "startMaterialBindings"
_START_MATERIAL_BINDINGS_DIGEST_KEY = "startMaterialBindingsDigest"


class V2JobRendererProtocol(Protocol):
    """The pure renderer seam used by orchestration."""

    @property
    def platform_ca_mount_enabled(self) -> bool: ...

    def job_ref(self, request: CreateJobRequest | NativeCreateJobRequest) -> str: ...

    def render(
        self,
        request: CreateJobRequest | NativeCreateJobRequest,
        *,
        native_recipe: ResolvedRuntimeRecipe | None = None,
        activation_plan: CapabilityActivationPlan | None = None,
    ) -> object: ...

    def render_network_policy(
        self, request: CreateJobRequest | NativeCreateJobRequest
    ) -> object: ...

    def resolve_recipe(
        self, runner_ref: str, environment_profile_ref: str
    ) -> ResolvedRuntimeRecipe: ...


class V2ObservabilityProtocol(Protocol):
    """Additive cluster-observation service kept outside scheduling authority."""

    def telemetry_nodes(self) -> NodeTelemetryList: ...

    def events(self, cursor: str | None, limit: int) -> RuntimeEventPage: ...

    def healthz(self) -> ObservabilityHealth: ...

    def collect(self) -> int: ...


class V2KubeAdapterProtocol(Protocol):
    """Namespace-bound Kubernetes operations used by this provider."""

    def create_job(self, job: object) -> object: ...

    def create_network_policy(self, policy: object) -> object: ...

    def read_network_policy(self, name: str) -> object | None: ...

    def delete_network_policy(self, name: str, policy_uid: str) -> None: ...

    def read_job(self, job_ref: str) -> object | None: ...

    def delete_job(self, job_ref: str, job_uid: str) -> None: ...

    def list_job_pods(self, job_ref: str, job_uid: str | None = None) -> Sequence[object]: ...

    def list_nodes(self) -> Sequence[object]: ...

    def list_managed_jobs(self) -> Sequence[object]: ...

    def list_managed_pods(self) -> Sequence[object]: ...

    def read_pod_usage(self, pod_name: str) -> Mapping[str, Mapping[str, int]]: ...

    def read_role_logs(
        self,
        job_ref: str,
        pod_uid: str,
        container: str,
        cursor: str | None,
        limit_bytes: int,
    ) -> object: ...

    def exec_workspace_readonly(
        self,
        binding: Mapping[str, str],
        command: tuple[str, ...],
        *,
        timeout_seconds: float = 15.0,
        output_limit_bytes: int = 65536,
    ) -> object: ...

    def create_secret(self, body: object) -> object: ...

    def read_secret(self, name: str) -> object | None: ...

    def delete_secret(self, name: str, secret_uid: str) -> bool: ...

    def upsert_secret(self, name: str, body: object) -> object: ...

    def pod_relay_endpoint(self, job_ref: str, pod_uid: str) -> tuple[str, int]: ...

    def pod_container_image_id(
        self, job_ref: str, pod_uid: str, container: str
    ) -> tuple[str | None, bool]: ...

    def open_workspace_terminal(
        self,
        binding: Mapping[str, str],
        terminal_ref: str,
        *,
        rows: int = 24,
        columns: int = 80,
    ) -> None: ...

    def write_workspace_terminal(
        self, binding: Mapping[str, str], terminal_ref: str, content: bytes
    ) -> None: ...

    def read_workspace_terminal(
        self,
        binding: Mapping[str, str],
        terminal_ref: str,
        cursor: int,
        limit_bytes: int,
    ) -> tuple[bytes, int, bool]: ...

    def resize_workspace_terminal(
        self,
        binding: Mapping[str, str],
        terminal_ref: str,
        *,
        rows: int,
        columns: int,
    ) -> None: ...

    def close_workspace_terminal(self, binding: Mapping[str, str], terminal_ref: str) -> bool: ...

    def terminal_is_open(self, binding: Mapping[str, str], terminal_ref: str) -> bool: ...


class V2JobStoreProtocol(Protocol):
    """Durable create/tombstone record operations used by this provider."""

    def reserve_create(
        self,
        provider_request_id: str,
        spec_digest: str,
        job_ref: str,
        spec_payload: Mapping[str, object],
        *,
        native_recipe_snapshot: Mapping[str, object] | None = None,
    ) -> object: ...

    def read_create(self, provider_request_id: str) -> object | None: ...

    def read_by_job_ref(self, job_ref: str) -> object | None: ...

    def mark_created(self, provider_request_id: str, job_uid: str) -> object: ...

    def bind_pod_incarnation(
        self,
        provider_request_id: str,
        pod_uid: str,
        incarnation_json: str | None = None,
    ) -> object: ...

    def mark_indeterminate(self, provider_request_id: str, reason: str) -> object: ...

    def mark_deleted(self, provider_request_id: str, **values: object) -> object: ...

    def list_create(self) -> Sequence[object]: ...

    def reserve_runtime(
        self, kind: str, identity: str, job_ref: str, values: Mapping[str, str]
    ) -> tuple[object, bool]: ...

    def reserve_catalog(
        self,
        kind: str,
        identity: str,
        digest: str,
        payload: Mapping[str, Any],
    ) -> tuple[object, bool]: ...

    def read_catalog(self, kind: str, identity: str) -> object | None: ...

    def read_runtime(self, kind: str, job_ref: str, identity: str) -> object | None: ...

    def list_runtime(
        self,
        kind: str,
        job_ref: str | None = None,
        *,
        strict: bool = False,
    ) -> Sequence[object]: ...

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

    snapshot: JobBindingSnapshot | NativeJobBindingSnapshot
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


@dataclass(frozen=True, slots=True)
class FinalizeResult:
    """A finalize snapshot plus the atomic slot reservation outcome."""

    snapshot: JobBindingSnapshot | NativeJobBindingSnapshot
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


@dataclass(frozen=True, slots=True)
class CancelResult:
    """A cancel snapshot plus the durable slot reservation outcome."""

    snapshot: JobBindingSnapshot | NativeJobBindingSnapshot
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


@dataclass(frozen=True, slots=True)
class CredentialGrantResult:
    snapshot: CredentialGrantSnapshot
    created: bool


@dataclass(frozen=True, slots=True)
class TerminalCreateResult:
    """Public descriptor plus a private header credential for this response."""

    snapshot: TerminalSessionSnapshot | NativeTerminalSessionSnapshot
    credential: str
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
        observability: V2ObservabilityProtocol | None = None,
        hosted_admission: bool = True,
        openvscode_image_ref: str | None = None,
        runtime_assembly_resolver: RuntimeAssemblyResolver | None = None,
        project_workspaces: ProjectWorkspaceService | None = None,
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
        self._observability = observability
        self._hosted_admission = hosted_admission
        self._runtime_assembly_resolver = runtime_assembly_resolver
        self._project_workspaces = project_workspaces
        self._cluster_feed = ClusterFeed(kube, clock=self._clock)
        self._lifecycle = LifecycleGate(store)
        self._startup_reconcile = False
        self._workspace_runtime = WorkspaceRuntime(
            store,
            workspace_transport,
            self._live_binding,
            self._assert_accepting_workspace_work,
            self._now,
        )
        self._live_workspace = LiveWorkspaceRuntime(
            store,
            workspace_transport,
            self._native_live_binding,
            clock=self._clock,
        )
        self._native = NativeRuntimeController(
            store,
            kube,
            workspace_transport,
            clock=self._clock,
        )
        self._dev_sessions = DevSessionService(
            store,
            kube,
            openvscode_image_ref=openvscode_image_ref,
            binding_resolver=self._native_live_binding,
            clock=self._clock,
        )
        self._native_metrics_lock = threading.Lock()
        self._native_recipe_forbidden_total = 0
        self._m2_metrics: collections.Counter[str] = collections.Counter()
        self._terminal_lifecycle_lock = threading.RLock()
        self.reconcile_credentials()
        self.reconcile_terminals()
        self._dev_sessions.reconcile()

    def ensure_project_workspace(
        self, request: EnsureProjectWorkspaceRequest
    ) -> ProjectWorkspaceMutation:
        return self._project_workspace_service().ensure(request)

    def inspect_project_workspace(self, workspace_ref: str) -> ProjectWorkspaceSnapshot:
        return self._project_workspace_service().inspect(workspace_ref)

    def create_project_dev_session(
        self, workspace_ref: str, request: ProjectDevSessionCreateRequest
    ) -> ProjectDevSessionMutation:
        return self._project_workspace_service().create_dev_session(workspace_ref, request)

    def inspect_project_dev_session(
        self, workspace_ref: str, session_ref: str, credential: str
    ) -> ProjectDevSessionSnapshot:
        return self._project_workspace_service().inspect_dev_session(
            workspace_ref, session_ref, credential
        )

    def renew_project_dev_session(
        self,
        workspace_ref: str,
        session_ref: str,
        credential: str,
        request: ProjectDevSessionRenewRequest,
    ) -> ProjectDevSessionMutation:
        return self._project_workspace_service().renew_dev_session(
            workspace_ref, session_ref, credential, request
        )

    def revoke_project_dev_session(
        self, workspace_ref: str, session_ref: str, credential: str
    ) -> ProjectDevSessionSnapshot:
        return self._project_workspace_service().revoke_dev_session(
            workspace_ref, session_ref, credential
        )

    def project_dev_session_relay_target(
        self, workspace_ref: str, session_ref: str, credential: str, path: str
    ) -> ProjectRelayTarget:
        return self._project_workspace_service().relay_target(
            workspace_ref, session_ref, credential, path
        )

    def observe_project_dev_session_relay_ready(
        self, workspace_ref: str, session_ref: str, credential: str
    ) -> ProjectDevSessionSnapshot:
        return self._project_workspace_service().observe_relay_ready(
            workspace_ref, session_ref, credential
        )

    def create_project_snapshot(
        self, workspace_ref: str, request: CreateProjectSnapshotRequest
    ) -> tuple[ProjectTreeSnapshot, bool]:
        return self._project_workspace_service().create_snapshot(workspace_ref, request)

    def open_project_snapshot_content(
        self, workspace_ref: str, snapshot_ref: str
    ) -> ProjectSnapshotContent:
        return self._project_workspace_service().open_snapshot_content(
            workspace_ref, snapshot_ref
        )

    def register_project_import(
        self, workspace_ref: str, request: RegisterProjectImportRequest
    ) -> tuple[ProjectImportSnapshot, bool]:
        return self._project_workspace_service().register_import(workspace_ref, request)

    def put_project_import(
        self, workspace_ref: str, import_ref: str, content: Path
    ) -> ProjectImportSnapshot:
        return self._project_workspace_service().put_import(workspace_ref, import_ref, content)

    def _project_workspace_service(self) -> ProjectWorkspaceService:
        if self._project_workspaces is None:
            raise DependencyUnavailableError("Project Workspace service is not configured")
        return self._project_workspaces

    def create_dev_session(
        self, job_ref: str, request: DevSessionCreateRequest
    ) -> DevSessionMutation:
        binding = self._native_live_binding(job_ref)
        self._assert_accepting_workspace_work(job_ref)
        return self._dev_sessions.create(job_ref, request, binding)

    def inspect_dev_session(
        self, job_ref: str, dev_session_ref: str, credential: str
    ) -> DevSessionSnapshot:
        return self._dev_sessions.inspect(job_ref, dev_session_ref, credential)

    def renew_dev_session(
        self,
        job_ref: str,
        dev_session_ref: str,
        credential: str,
        request: DevSessionRenewRequest,
    ) -> DevSessionMutation:
        self._assert_accepting_workspace_work(job_ref)
        return self._dev_sessions.renew(job_ref, dev_session_ref, credential, request)

    def revoke_dev_session(
        self, job_ref: str, dev_session_ref: str, credential: str
    ) -> DevSessionSnapshot:
        return self._dev_sessions.revoke(job_ref, dev_session_ref, credential)

    def dev_session_relay_target(
        self, job_ref: str, dev_session_ref: str, credential: str, path: str
    ) -> DevSessionRelayTarget:
        try:
            return self._dev_sessions.relay_target(job_ref, dev_session_ref, credential, path)
        except KcsV2Error as error:
            if error.code == "DEV_SESSION_RELAY_DOWN":
                self._record_m2_metric("dev_session_relay_down_total")
            raise

    def observe_dev_session_relay_ready(
        self, job_ref: str, dev_session_ref: str, credential: str
    ) -> DevSessionSnapshot:
        return self._dev_sessions.observe_relay_ready(
            job_ref, dev_session_ref, credential
        )

    def capacity(self) -> CapacitySnapshot:
        """Return a fresh, read-only projection of Kubernetes Node capacity."""
        return self._cluster_feed.capacity()

    def queue(self) -> QueueSnapshot:
        """Return managed Jobs that Kubernetes has not made ready."""
        return self._cluster_feed.queue()

    def telemetry_nodes(self) -> NodeTelemetryList:
        """Return cluster telemetry without promoting observations to scheduler facts."""

        if self._observability is None:
            raise DependencyUnavailableError("KCS observability is not configured")
        return self._observability.telemetry_nodes()

    def runtime_events(self, cursor: str | None, limit: int) -> RuntimeEventPage:
        """Read the durable, cursor-addressed event ring."""

        if self._observability is None:
            raise DependencyUnavailableError("KCS runtime events are not configured")
        return self._observability.events(cursor, limit)

    def observability_health(self) -> ObservabilityHealth:
        """Self-report observability dependencies; this surface never raises for outage."""

        if self._observability is None:
            return ObservabilityHealth(
                prometheus="down",
                dcgm="down",
                kube_state_metrics="down",
                oldest_scrape_age_seconds=None,
            )
        return self._observability.healthz()

    def prometheus_metrics(self) -> str:
        """Expose bounded aggregate native lifecycle facts without job identities."""

        jobs: collections.Counter[str] = collections.Counter()
        runners: collections.Counter[str] = collections.Counter()
        stops: collections.Counter[str] = collections.Counter()
        activations: collections.Counter[tuple[str, str]] = collections.Counter()
        credentials: collections.Counter[str] = collections.Counter()
        hard_deadlines = 0
        output_loss = 0
        collection_errors = 0
        with self._native_metrics_lock:
            recipe_forbidden_total = self._native_recipe_forbidden_total
            m2_metrics = getattr(self, "_m2_metrics", collections.Counter()).copy()
        list_runtime = getattr(self._store, "list_runtime", None)
        active_terminals = 0
        active_dev_sessions = 0
        if callable(list_runtime):
            active_terminals = sum(
                _runtime_values(record).get("state") in {"opening", "ready"}
                for record in list_runtime("terminal")
            )
            active_dev_sessions = sum(
                _runtime_values(record).get("state") in {"opening", "ready"}
                for record in list_runtime("dev-session")
            )
        for record in self._store.list_create():
            if not _is_native_record(record) or _is_deleted(record):
                continue
            try:
                snapshot = self.inspect(str(_field(record, "job_ref")))
                if not isinstance(snapshot, NativeJobBindingSnapshot):
                    continue
                values = snapshot.root
                jobs[str(values["bindingState"])] += 1
                generation = values.get("latestRunnerGeneration")
                if isinstance(generation, Mapping):
                    observation = generation.get("runnerObservation")
                    if isinstance(observation, Mapping):
                        runners[str(observation["state"])] += 1
                stop_action = values.get("runnerStopAction")
                if isinstance(stop_action, Mapping):
                    stops[str(stop_action["state"])] += 1
                activation = values.get("recipeActivation")
                if isinstance(activation, Mapping):
                    activations[(str(activation["state"]), str(activation["deliveryFailure"]))] += 1
                capability_activation = values.get("capabilityActivation")
                if isinstance(capability_activation, Mapping):
                    m2_metrics[f"capability_activation_state_{capability_activation['state']}"] += 1
                for credential in values.get("credentialObservations", []):
                    if isinstance(credential, Mapping):
                        credentials[str(credential["state"])] += 1
                deadline = values.get("deadline")
                if isinstance(deadline, Mapping) and deadline.get("hardDeadlineTriggeredAt"):
                    hard_deadlines += 1
                output_loss += int(bool(values.get("outputLossPossible")))
            except Exception:
                collection_errors += 1

        lines = [
            "# HELP kcs_native_jobs Current native jobs by binding state.",
            "# TYPE kcs_native_jobs gauge",
            *_prometheus_counter_lines("kcs_native_jobs", "binding_state", jobs),
            "# HELP kcs_native_runner_generations Current runner generations by launcher state.",
            "# TYPE kcs_native_runner_generations gauge",
            *_prometheus_counter_lines("kcs_native_runner_generations", "runner_state", runners),
            "# HELP kcs_native_runner_stop_actions Current stopRunner actions by state.",
            "# TYPE kcs_native_runner_stop_actions gauge",
            *_prometheus_counter_lines("kcs_native_runner_stop_actions", "state", stops),
            "# HELP kcs_native_recipe_activations Current recipe delivery observations.",
            "# TYPE kcs_native_recipe_activations gauge",
            *(
                f'kcs_native_recipe_activations{{state="{state}",delivery_failure="{failure}"}} {count}'
                for (state, failure), count in sorted(activations.items())
            ),
            "# HELP kcs_native_credentials Current projected runner credentials by state.",
            "# TYPE kcs_native_credentials gauge",
            *_prometheus_counter_lines("kcs_native_credentials", "state", credentials),
            "# HELP kcs_native_hard_deadline_triggered Current jobs killed by hard deadline.",
            "# TYPE kcs_native_hard_deadline_triggered gauge",
            f"kcs_native_hard_deadline_triggered {hard_deadlines}",
            "# HELP kcs_native_output_loss_possible Current jobs with possible output loss.",
            "# TYPE kcs_native_output_loss_possible gauge",
            f"kcs_native_output_loss_possible {output_loss}",
            "# HELP kcs_native_metrics_collection_errors Native bindings not readable during scrape.",
            "# TYPE kcs_native_metrics_collection_errors gauge",
            f"kcs_native_metrics_collection_errors {collection_errors}",
            "# HELP kcs_native_recipe_forbidden_total Rejected unregistered runtime recipe resolutions.",
            "# TYPE kcs_native_recipe_forbidden_total counter",
            f"kcs_native_recipe_forbidden_total {recipe_forbidden_total}",
            "# HELP kcs_m2_active_terminals Current attachable terminal sessions.",
            "# TYPE kcs_m2_active_terminals gauge",
            f"kcs_m2_active_terminals {active_terminals}",
            "# HELP kcs_m2_active_dev_sessions Current attachable developer sessions.",
            "# TYPE kcs_m2_active_dev_sessions gauge",
            f"kcs_m2_active_dev_sessions {active_dev_sessions}",
            "# HELP kcs_m2_live_operations_total Bounded live-workspace operations.",
            "# TYPE kcs_m2_live_operations_total counter",
            f"kcs_m2_live_operations_total {m2_metrics['live_operations_total']}",
            "# HELP kcs_m2_live_latency_seconds_sum Live-workspace operation latency.",
            "# TYPE kcs_m2_live_latency_seconds_sum counter",
            f"kcs_m2_live_latency_seconds_sum {m2_metrics['live_latency_seconds_sum']}",
            "# HELP kcs_m2_live_bytes_total Live-workspace bytes returned.",
            "# TYPE kcs_m2_live_bytes_total counter",
            f"kcs_m2_live_bytes_total {m2_metrics['live_bytes_total']}",
            "# HELP kcs_m2_cursor_gap_total Terminal reads outside retention.",
            "# TYPE kcs_m2_cursor_gap_total counter",
            f"kcs_m2_cursor_gap_total {m2_metrics['cursor_gap_total']}",
            "# HELP kcs_m2_dev_session_relay_down_total Relay dependency failures.",
            "# TYPE kcs_m2_dev_session_relay_down_total counter",
            f"kcs_m2_dev_session_relay_down_total {m2_metrics['dev_session_relay_down_total']}",
            "# HELP kcs_m2_capability_activation_failures_total Rejected exact activation resolutions.",
            "# TYPE kcs_m2_capability_activation_failures_total counter",
            f"kcs_m2_capability_activation_failures_total {m2_metrics['capability_activation_failures_total']}",
            "# HELP kcs_m2_capability_activations Current activation receipts by state.",
            "# TYPE kcs_m2_capability_activations gauge",
            *(
                f'kcs_m2_capability_activations{{state="{state}"}} {m2_metrics[f"capability_activation_state_{state}"]}'
                for state in ("ready", "failed", "indeterminate")
            ),
        ]
        return "\n".join(lines) + "\n"

    def collect_runtime_events(self) -> int:
        """Capture managed Kubernetes transitions into the persistent event ring."""

        if self._observability is None:
            return 0
        emitted = self._observability.collect()
        record_runner_phase = getattr(self._observability, "record_runner_phase", None)
        if not callable(record_runner_phase):
            return emitted
        for record in self._store.list_create():
            if not _is_native_record(record) or _is_deleted(record):
                continue
            job_ref = str(_field(record, "job_ref"))
            try:
                binding = self.inspect(job_ref)
                if not isinstance(binding, NativeJobBindingSnapshot):
                    continue
                generation = binding.root["latestRunnerGeneration"]
                if not isinstance(generation, Mapping):
                    continue
                node_name = binding.root["nodeName"]
                compute_node = (
                    self._cluster_feed.display_compute_node(str(node_name))
                    if node_name is not None
                    else None
                )
                emitted += int(
                    record_runner_phase(
                        job_ref,
                        compute_node,
                        int(generation["generation"]),
                        generation["runnerObservation"],
                    )
                )
            except Exception:
                # Kubernetes and the launcher may disappear between the ordinary
                # event sweep and this observation. The binding remains the
                # authority; the next sweep retries without inventing a phase.
                continue
        return emitted

    def nvidia_telemetry(self, job_ref: str) -> NvidiaTelemetrySnapshot:
        """Read NVIDIA driver observations from the exact bound Workspace Pod.

        This fixed probe is observation-only.  It neither accepts caller argv
        nor feeds scheduling decisions, and missing driver data fails typed
        instead of being rewritten as zero utilization.
        """

        binding = self._live_binding(job_ref)
        if isinstance(binding, NativeJobBindingSnapshot):
            root = binding.root
            pod_uid = root["podUid"]
            node_name = root["nodeName"]
            record = self._store.read_by_job_ref(job_ref)
            native_spec = _field(_field(record, "spec_payload", {}), "native", {})
            accelerator = _field(_field(native_spec, "resources", {}), "accelerator", {})
            gpu_count = int(_field(accelerator, "count", 0))
            job_uid = root["jobUid"]
            runtime_lane = "native"
        else:
            pod_uid = binding.pod_uid
            node_name = binding.node_name
            gpu_count = binding.workspace.requested.gpu if binding.workspace is not None else 0
            job_uid = binding.job_uid
            runtime_lane = "hosted"
        if pod_uid is None or node_name is None:
            raise StateConflictError("The Job has no running compute placement")
        if gpu_count < 1:
            raise StateConflictError("The bound runtime has no NVIDIA GPU allocation")
        probe = self._kube.exec_workspace_readonly(
            {
                "jobRef": job_ref,
                "jobUid": str(job_uid),
                "podUid": str(pod_uid),
                "runtimeLane": runtime_lane,
            },
            (
                "nvidia-smi",
                "--query-gpu=uuid,utilization.gpu,memory.used,memory.total,temperature.gpu",
                "--format=csv,noheader,nounits",
            ),
        )
        if int(_field(probe, "exit_code", -1)) != 0:
            raise DependencyUnavailableError("NVIDIA telemetry probe did not succeed")
        rows = str(_field(probe, "stdout", "")).splitlines()
        devices: list[NvidiaDeviceTelemetry] = []
        try:
            for row in rows:
                fields = [item.strip() for item in row.split(",")]
                if len(fields) != 5 or any(not item or item == "N/A" for item in fields):
                    raise ValueError
                devices.append(
                    NvidiaDeviceTelemetry(
                        device_id=fields[0],
                        utilization_percent=int(float(fields[1])),
                        memory_used_mib=int(float(fields[2])),
                        memory_total_mib=int(float(fields[3])),
                        temperature_celsius=int(float(fields[4])),
                    )
                )
        except (TypeError, ValueError) as error:
            raise DependencyUnavailableError("NVIDIA telemetry output was malformed") from error
        if not devices:
            raise DependencyUnavailableError("NVIDIA telemetry returned no allocated device")
        return NvidiaTelemetrySnapshot(
            job_ref=job_ref,
            job_uid=job_uid,
            pod_uid=pod_uid,
            compute_node=self._cluster_feed.display_compute_node(node_name),
            observed_at=self._now(),
            devices=devices,
        )

    def create_terminal(
        self,
        job_ref: str,
        request: TerminalCreateRequest,
    ) -> TerminalCreateResult:
        """Acquire the single Workspace writer and open an exact Pod PTY."""

        with self._terminal_lifecycle_lock:
            return self._create_terminal(job_ref, request)

    def _create_terminal(
        self,
        job_ref: str,
        request: TerminalCreateRequest,
    ) -> TerminalCreateResult:
        self.reconcile_terminals()
        binding = self._live_binding(job_ref)
        spec = request.spec
        if (
            binding.subject_ref != spec.subject_ref
            or str(binding.job_uid) != str(spec.job_uid)
            or str(binding.pod_uid) != str(spec.pod_uid)
        ):
            raise StaleBindingError()
        if isinstance(binding, NativeJobBindingSnapshot):
            self._assert_accepting_workspace_work(job_ref)
            claim = self._lifecycle.claim(
                job_ref,
                str(binding.job_uid),
                str(binding.pod_uid),
                "native-terminal-create",
                request.terminal_ref,
            )
            try:
                return self._create_native_terminal(job_ref, request, binding)
            finally:
                claim.release()
        if self._transport is None:
            raise DependencyUnavailableError("Agent pause transport is unavailable")
        now = self._now()
        expires = now + timedelta(seconds=spec.ttl_seconds)
        credential = secrets.token_urlsafe(32)
        credential_sha = hashlib.sha256(credential.encode("utf-8")).hexdigest()
        values = {
            "identityDigest": request.request_digest,
            "requestDigest": request.request_digest,
            "subjectRef": spec.subject_ref,
            "jobUid": str(spec.job_uid),
            "podUid": str(spec.pod_uid),
            "state": "opening",
            "createdAt": now.isoformat(),
            "expiresAt": expires.isoformat(),
            "observedAt": now.isoformat(),
            "credentialSha256": credential_sha,
            "agentPaused": "false",
        }
        record, created = self._store.reserve_runtime(
            "terminal", request.terminal_ref, job_ref, values
        )
        retained = _runtime_values(record)
        if retained.get("identityDigest") != request.request_digest:
            raise IdentityDigestConflict()
        if not created:
            values = dict(retained)
            expires = _as_datetime(values.get("expiresAt"), now)
            if expires <= now or values.get("state") in {"closed", "expired", "lost"}:
                raise StateConflictError("The retained terminal session is no longer attachable")
            values["credentialSha256"] = credential_sha
            values["observedAt"] = now.isoformat()

        exact = {
            "jobRef": job_ref,
            "jobUid": str(binding.job_uid),
            "podUid": str(binding.pod_uid),
        }
        claimed = False
        try:
            self._claim_terminal_writer(exact, request.terminal_ref)
            claimed = True
            paused = self._transport.pause_agent(exact)
            if paused.state not in {"paused", "idle", "exited"}:
                raise StateConflictError("The Agent writer did not enter a paused state")
            self._kube.open_workspace_terminal(exact, request.terminal_ref)
        except Exception:
            if claimed:
                try:
                    self._kube.close_workspace_terminal(exact, request.terminal_ref)
                except Exception:
                    pass
                try:
                    self._transport.resume_agent(exact)
                except Exception:
                    pass
            values.update(
                {
                    "state": "lost",
                    "agentPaused": "false",
                    "observedAt": self._now().isoformat(),
                }
            )
            try:
                self._store.update_runtime("terminal", job_ref, request.terminal_ref, values)
            except Exception:
                pass
            if claimed:
                self._release_terminal_writer(exact, request.terminal_ref)
            raise
        values.update(
            {
                "state": "open",
                "agentPaused": "true",
                "observedAt": self._now().isoformat(),
            }
        )
        record = self._store.update_runtime("terminal", job_ref, request.terminal_ref, values)
        return TerminalCreateResult(
            snapshot=self._terminal_snapshot(record),
            credential=credential,
            created=created,
        )

    def _create_native_terminal(
        self,
        job_ref: str,
        request: TerminalCreateRequest,
        binding: NativeJobBindingSnapshot,
    ) -> TerminalCreateResult:
        spec = request.spec
        now = self._now()
        expires = now + timedelta(seconds=spec.ttl_seconds)
        credential = secrets.token_urlsafe(32)
        credential_sha = hashlib.sha256(credential.encode("utf-8")).hexdigest()
        values = {
            "identityDigest": request.request_digest,
            "requestDigest": request.request_digest,
            "subjectRef": spec.subject_ref,
            "jobUid": str(spec.job_uid),
            "podUid": str(spec.pod_uid),
            "state": "opening",
            "createdAt": now.isoformat(),
            "expiresAt": expires.isoformat(),
            "observedAt": now.isoformat(),
            "credentialSha256": credential_sha,
            "agentPaused": "true",
            "runtimeLane": "native",
            "ptyRef": request.terminal_ref,
        }
        record, created = self._store.reserve_runtime(
            "terminal", request.terminal_ref, job_ref, values
        )
        retained = _runtime_values(record)
        if retained.get("identityDigest") != request.request_digest:
            raise IdentityDigestConflict()
        if not created:
            if retained.get("state") in {"closed", "expired", "lost"}:
                raise StateConflictError("The retained terminal session is no longer attachable")
            values = dict(retained)
            values["credentialSha256"] = credential_sha
            values["observedAt"] = now.isoformat()
        exact = {
            "runtimeLane": "native",
            "jobRef": job_ref,
            "jobUid": str(binding.job_uid),
            "podUid": str(binding.pod_uid),
        }
        claimed = False
        try:
            self._claim_terminal_writer(exact, request.terminal_ref)
            claimed = True
            opened = self._native.launcher_rpc(
                exact,
                {
                    "command": "createPty",
                    "requestRef": request.terminal_ref,
                    "generation": _native_generation(binding),
                    "ptyRef": request.terminal_ref,
                    "ttlSeconds": spec.ttl_seconds,
                },
            )
            if opened.get("open") is not True or opened.get("runnerPaused") is not True:
                raise DependencyUnavailableError("native terminal did not open")
        except Exception:
            if claimed:
                self._release_terminal_writer(exact, request.terminal_ref)
            values.update(state="lost", agentPaused="false", observedAt=self._now().isoformat())
            self._store.update_runtime("terminal", job_ref, request.terminal_ref, values)
            raise
        values.update(state="open", agentPaused="true", observedAt=self._now().isoformat())
        record = self._store.update_runtime("terminal", job_ref, request.terminal_ref, values)
        return TerminalCreateResult(
            snapshot=self._terminal_snapshot(record),
            credential=credential,
            created=created,
        )

    def inspect_terminal(
        self,
        job_ref: str,
        terminal_ref: str,
        *,
        subject_ref: str,
        credential: str,
    ) -> TerminalSessionSnapshot | NativeTerminalSessionSnapshot:
        self.reconcile_terminals()
        record = self._store.read_runtime("terminal", job_ref, terminal_ref)
        if record is None:
            raise JobNotFoundError()
        values = _runtime_values(record)
        expected = values.get("credentialSha256", "")
        supplied = hashlib.sha256(credential.encode("utf-8")).hexdigest()
        if (
            values.get("subjectRef") != subject_ref
            or not expected
            or not hmac.compare_digest(expected, supplied)
        ):
            raise TerminalCredentialError()
        if _as_datetime(values.get("expiresAt"), self._now()) <= self._now():
            raise TerminalCredentialError()
        return self._terminal_snapshot(record)

    def write_terminal(
        self,
        job_ref: str,
        terminal_ref: str,
        content: bytes,
        *,
        subject_ref: str,
        credential: str,
    ) -> TerminalSessionSnapshot | NativeTerminalSessionSnapshot:
        record, binding = self._terminal_access(
            job_ref, terminal_ref, subject_ref=subject_ref, credential=credential
        )
        if _runtime_values(record).get("runtimeLane") == "native":
            self._assert_accepting_workspace_work(job_ref)
            request_ref = f"terminal-write-{terminal_ref}-{secrets.token_hex(8)}"
            claim = self._lifecycle.claim(
                job_ref,
                binding["jobUid"],
                binding["podUid"],
                "native-terminal-write",
                request_ref,
            )
            try:
                self._native.launcher_rpc(
                    binding,
                    {
                        "command": "writePty",
                        "requestRef": request_ref,
                        "generation": _native_generation_from_values(self.inspect(job_ref).root),
                        "ptyRef": terminal_ref,
                        "contentBase64": base64.b64encode(content).decode("ascii"),
                    },
                )
            finally:
                claim.release()
        else:
            self._kube.write_workspace_terminal(binding, terminal_ref, content)
        return self._touch_terminal(record)

    def read_terminal(
        self,
        job_ref: str,
        terminal_ref: str,
        *,
        cursor: int,
        limit_bytes: int,
        subject_ref: str,
        credential: str,
    ) -> tuple[
        bytes,
        int,
        bool,
        TerminalSessionSnapshot | NativeTerminalSessionSnapshot,
    ]:
        record, binding = self._terminal_access(
            job_ref, terminal_ref, subject_ref=subject_ref, credential=credential
        )
        if _runtime_values(record).get("runtimeLane") == "native":
            result = self._native.launcher_rpc(
                binding,
                {
                    "command": "readPty",
                    "requestRef": f"terminal-read-{terminal_ref}-{cursor}",
                    "generation": _native_generation_from_values(self.inspect(job_ref).root),
                    "ptyRef": terminal_ref,
                    "cursor": cursor,
                    "limitBytes": limit_bytes,
                },
            )
            gap = result.get("cursorGap")
            if isinstance(gap, Mapping):
                try:
                    self._record_m2_metric("cursor_gap_total")
                    raise CursorGapError(
                        int(gap["requestedCursor"]),
                        int(gap["earliestRetainedCursor"]),
                    )
                except (KeyError, TypeError, ValueError) as error:
                    raise DependencyUnavailableError(
                        "native terminal returned an invalid cursor gap"
                    ) from error
            try:
                content = base64.b64decode(str(result["contentBase64"]), validate=True)
                next_cursor = int(result["nextCursor"])
                open_state = bool(result["open"])
            except (KeyError, TypeError, ValueError) as error:
                raise DependencyUnavailableError(
                    "native terminal returned an invalid output frame"
                ) from error
        else:
            content, next_cursor, open_state = self._kube.read_workspace_terminal(
                binding, terminal_ref, cursor, limit_bytes
            )
        return content, next_cursor, open_state, self._touch_terminal(record)

    def resize_terminal(
        self,
        job_ref: str,
        terminal_ref: str,
        *,
        rows: int,
        columns: int,
        subject_ref: str,
        credential: str,
    ) -> TerminalSessionSnapshot | NativeTerminalSessionSnapshot:
        record, binding = self._terminal_access(
            job_ref, terminal_ref, subject_ref=subject_ref, credential=credential
        )
        if _runtime_values(record).get("runtimeLane") == "native":
            self._assert_accepting_workspace_work(job_ref)
            request_ref = f"terminal-resize-{terminal_ref}-{secrets.token_hex(8)}"
            claim = self._lifecycle.claim(
                job_ref,
                binding["jobUid"],
                binding["podUid"],
                "native-terminal-resize",
                request_ref,
            )
            try:
                self._native.launcher_rpc(
                    binding,
                    {
                        "command": "resizePty",
                        "requestRef": request_ref,
                        "generation": _native_generation_from_values(self.inspect(job_ref).root),
                        "ptyRef": terminal_ref,
                        "rows": rows,
                        "columns": columns,
                    },
                )
            finally:
                claim.release()
        else:
            self._kube.resize_workspace_terminal(binding, terminal_ref, rows=rows, columns=columns)
        return self._touch_terminal(record)

    def close_terminal(
        self,
        job_ref: str,
        terminal_ref: str,
        *,
        subject_ref: str,
        credential: str,
    ) -> TerminalSessionSnapshot | NativeTerminalSessionSnapshot:
        record, binding = self._terminal_access(
            job_ref,
            terminal_ref,
            subject_ref=subject_ref,
            credential=credential,
            allow_closed=True,
        )
        values = dict(_runtime_values(record))
        if values.get("state") == "closed":
            return self._terminal_snapshot(record)
        native = values.get("runtimeLane") == "native"
        try:
            if native:
                self._native.launcher_rpc(
                    binding,
                    {
                        "command": "closePty",
                        "requestRef": f"terminal-close-{terminal_ref}",
                        "generation": _native_generation_from_values(self.inspect(job_ref).root),
                        "ptyRef": terminal_ref,
                        "reason": "terminal_closed",
                    },
                )
            else:
                self._kube.close_workspace_terminal(binding, terminal_ref)
        finally:
            if not native and self._transport is not None:
                self._transport.resume_agent(binding)
        values.update(
            {
                "state": "closed",
                "agentPaused": "false",
                "observedAt": self._now().isoformat(),
            }
        )
        updated = self._store.update_runtime("terminal", job_ref, terminal_ref, values)
        self._release_terminal_writer(binding, terminal_ref)
        return self._terminal_snapshot(updated)

    def reconcile_terminals(self) -> int:
        """Release Agent pause after expiry, API restart, or lost PTY state."""

        with self._terminal_lifecycle_lock:
            return self._reconcile_terminals()

    def _reconcile_terminals(self) -> int:
        indeterminate = 0
        for record in self._store.list_runtime("terminal", None):
            values = dict(_runtime_values(record))
            if values.get("state") not in {"opening", "open"}:
                continue
            job_ref = str(_field(record, "job_ref"))
            binding = {
                "jobRef": job_ref,
                "jobUid": values.get("jobUid", ""),
                "podUid": values.get("podUid", ""),
            }
            native = values.get("runtimeLane") == "native"
            if native:
                binding["runtimeLane"] = "native"
            binding_check_failed = False
            current: JobBindingSnapshot | NativeJobBindingSnapshot | None = None
            try:
                current = self._live_binding(job_ref)
                stale_binding = (
                    str(current.job_uid) != binding["jobUid"]
                    or str(current.pod_uid) != binding["podUid"]
                )
            except (JobNotFoundError, StateConflictError, TombstonedError):
                stale_binding = True
            except Exception:
                stale_binding = False
                binding_check_failed = True
            expired = _as_datetime(values.get("expiresAt"), self._now()) <= self._now()
            alive = (
                True
                if native
                else self._kube.terminal_is_open(binding, str(_field(record, "identity")))
            )
            if binding_check_failed and not expired:
                indeterminate += 1
                continue
            if not expired and alive and not stale_binding:
                continue
            terminal_ref = str(_field(record, "identity"))
            cleanup_failed = False
            try:
                if native:
                    self._native.launcher_rpc(
                        binding,
                        {
                            "command": "closePty",
                            "requestRef": f"terminal-expire-{terminal_ref}",
                            "generation": _native_generation_from_values(
                                current.root
                                if isinstance(current, NativeJobBindingSnapshot)
                                else {}
                            ),
                            "ptyRef": terminal_ref,
                            "reason": "terminal_expired" if expired else "terminal_binding_lost",
                        },
                    )
                else:
                    self._kube.close_workspace_terminal(binding, terminal_ref)
            except Exception:
                cleanup_failed = True
            try:
                if not native and self._transport is not None:
                    self._transport.resume_agent(binding)
            except Exception:
                cleanup_failed = True
            exact_pod_exists = False
            try:
                exact_pod_exists = any(
                    _required_text(pod, "metadata", "uid") == binding["podUid"]
                    for pod in self._list_job_pods(job_ref, binding["jobUid"])
                )
            except Exception:
                if cleanup_failed:
                    indeterminate += 1
                    continue
            if cleanup_failed and exact_pod_exists:
                indeterminate += 1
                continue
            values.update(
                {
                    "state": "expired" if expired else "lost",
                    "agentPaused": "false",
                    "observedAt": self._now().isoformat(),
                }
            )
            self._store.update_runtime("terminal", job_ref, terminal_ref, values)
            self._release_terminal_writer(binding, terminal_ref)
        return indeterminate

    def _claim_terminal_writer(self, binding: Mapping[str, str], terminal_ref: str) -> None:
        identity_digest = canonical_digest({"jobRef": binding["jobRef"], "writer": "workspace"})
        desired = {
            "identityDigest": identity_digest,
            "jobUid": binding["jobUid"],
            "podUid": binding["podUid"],
            "terminalRef": terminal_ref,
            "state": "held",
            "observedAt": self._now().isoformat(),
        }
        record, created = self._store.reserve_runtime(
            TERMINAL_WRITER_KIND,
            TERMINAL_WRITER_ID,
            binding["jobRef"],
            desired,
        )
        if created:
            return
        for _ in range(8):
            values = _runtime_values(record)
            if values.get("state") == "held":
                if (
                    values.get("terminalRef") == terminal_ref
                    and values.get("jobUid") == binding["jobUid"]
                    and values.get("podUid") == binding["podUid"]
                ):
                    return
                raise TerminalBusyError()
            resource_version = _field(record, "resource_version", None)
            if not isinstance(resource_version, str) or not resource_version:
                raise DependencyUnavailableError(
                    "terminal writer reservation has no resource version"
                )
            claimed = self._store.compare_and_swap_runtime(
                TERMINAL_WRITER_KIND,
                binding["jobRef"],
                TERMINAL_WRITER_ID,
                desired,
                expected_resource_version=resource_version,
            )
            if claimed is not None:
                return
            record = self._store.read_runtime(
                TERMINAL_WRITER_KIND, binding["jobRef"], TERMINAL_WRITER_ID
            )
            if record is None:
                raise DependencyUnavailableError(
                    "terminal writer reservation disappeared during claim"
                )
        raise DependencyUnavailableError("terminal writer reservation changed concurrently")

    def _release_terminal_writer(self, binding: Mapping[str, str], terminal_ref: str) -> None:
        for _ in range(8):
            record = self._store.read_runtime(
                TERMINAL_WRITER_KIND, binding["jobRef"], TERMINAL_WRITER_ID
            )
            if record is None:
                return
            values = dict(_runtime_values(record))
            if values.get("terminalRef") != terminal_ref or values.get("state") != "held":
                return
            resource_version = _field(record, "resource_version", None)
            if not isinstance(resource_version, str) or not resource_version:
                raise DependencyUnavailableError(
                    "terminal writer reservation has no resource version"
                )
            values.update({"state": "released", "observedAt": self._now().isoformat()})
            released = self._store.compare_and_swap_runtime(
                TERMINAL_WRITER_KIND,
                binding["jobRef"],
                TERMINAL_WRITER_ID,
                values,
                expected_resource_version=resource_version,
            )
            if released is not None:
                return
        raise DependencyUnavailableError("terminal writer release changed concurrently")

    def _terminal_access(
        self,
        job_ref: str,
        terminal_ref: str,
        *,
        subject_ref: str,
        credential: str,
        allow_closed: bool = False,
    ) -> tuple[object, dict[str, str]]:
        record = self._store.read_runtime("terminal", job_ref, terminal_ref)
        if record is None:
            raise JobNotFoundError()
        values = _runtime_values(record)
        expected = values.get("credentialSha256", "")
        supplied = hashlib.sha256(credential.encode("utf-8")).hexdigest()
        if (
            values.get("subjectRef") != subject_ref
            or not expected
            or not hmac.compare_digest(expected, supplied)
        ):
            raise TerminalCredentialError()
        if _as_datetime(values.get("expiresAt"), self._now()) <= self._now():
            raise TerminalCredentialError()
        state = values.get("state")
        if state != "open" and not (allow_closed and state == "closed"):
            raise StateConflictError("The terminal session is not open")
        if allow_closed and state == "closed":
            retained_binding = {
                "jobRef": job_ref,
                "jobUid": values["jobUid"],
                "podUid": values["podUid"],
            }
            if values.get("runtimeLane") == "native":
                retained_binding["runtimeLane"] = "native"
            return record, retained_binding
        current = self._live_binding(job_ref)
        if (
            current.subject_ref != subject_ref
            or str(current.job_uid) != values.get("jobUid")
            or str(current.pod_uid) != values.get("podUid")
        ):
            raise StaleBindingError()
        binding = {
            "jobRef": job_ref,
            "jobUid": str(current.job_uid),
            "podUid": str(current.pod_uid),
        }
        native = values.get("runtimeLane") == "native"
        if native:
            binding["runtimeLane"] = "native"
        if (
            state == "open"
            and not native
            and not self._kube.terminal_is_open(binding, terminal_ref)
        ):
            raise StateConflictError("The retained terminal PTY is no longer attached")
        return record, binding

    def _touch_terminal(
        self, record: object
    ) -> TerminalSessionSnapshot | NativeTerminalSessionSnapshot:
        values = dict(_runtime_values(record))
        values["observedAt"] = self._now().isoformat()
        updated = self._store.update_runtime(
            "terminal",
            str(_field(record, "job_ref")),
            str(_field(record, "identity")),
            values,
        )
        return self._terminal_snapshot(updated)

    def _terminal_snapshot(
        self, record: object
    ) -> TerminalSessionSnapshot | NativeTerminalSessionSnapshot:
        values = _runtime_values(record)
        if values.get("runtimeLane") == "native":
            return NativeTerminalSessionSnapshot.model_validate(
                {
                    "terminalRef": str(_field(record, "identity")),
                    "ptyRef": values.get("ptyRef", str(_field(record, "identity"))),
                    "requestDigest": values["requestDigest"],
                    "subjectRef": values["subjectRef"],
                    "jobRef": str(_field(record, "job_ref")),
                    "jobUid": values["jobUid"],
                    "podUid": values["podUid"],
                    "container": "runner",
                    "state": values["state"],
                    "createdAt": values["createdAt"],
                    "expiresAt": values["expiresAt"],
                    "observedAt": values["observedAt"],
                    "writable": True,
                    "runnerPaused": True,
                    "launcherMediated": True,
                    "shellCommand": ["/bin/sh"],
                    "effectiveUid": 10002,
                    "effectiveGid": 10001,
                    "effectiveCapabilities": [],
                    "noNewPrivileges": True,
                    "umask": "0002",
                    "cwd": "/workspace/worktree",
                    "home": "/run/rc-terminal/home",
                    "tmpdir": "/run/rc-terminal/tmp",
                }
            )
        return TerminalSessionSnapshot(
            terminal_ref=str(_field(record, "identity")),
            request_digest=values["requestDigest"],
            subject_ref=values["subjectRef"],
            job_ref=str(_field(record, "job_ref")),
            job_uid=UUID(values["jobUid"]),
            pod_uid=UUID(values["podUid"]),
            container="workspace",
            state=TerminalState(values["state"]),
            created_at=_as_datetime(values.get("createdAt"), self._now()),
            expires_at=_as_datetime(values.get("expiresAt"), self._now()),
            observed_at=_as_datetime(values.get("observedAt"), self._now()),
            writable=True,
            agent_paused=values.get("agentPaused") == "true",
        )

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
                    secret = read_secret(credential_secret_name(grant.job_ref))
                    present = secret is not None and self._secret_matches_grant_binding(
                        secret,
                        grant.job_ref,
                        str(grant.job_uid),
                        grant.credential_grant_ref,
                        str(grant.pod_uid),
                    )
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
            report.indeterminate += self.reconcile_terminals()
            report.indeterminate += self._dev_sessions.reconcile()
            if self._project_workspaces is not None:
                try:
                    workspace_report = self._project_workspaces.reconcile()
                    report.reconciled += workspace_report["hibernated"]
                    report.deleted += workspace_report["orphans"]
                except Exception:
                    report.indeterminate += 1
            for record in self._store.list_create():
                report.scanned += 1
                job_ref = str(_field(record, "job_ref"))
                try:
                    if self._requires_ownerless_delete_recovery(record):
                        self.delete(
                            job_ref,
                            str(_field(record, "delete_ref")),
                            str(_field(record, "delete_request_digest")),
                        )
                        report.deleted += 1
                        continue
                    lifecycle = self._lifecycle.inspect(job_ref)
                    if lifecycle is not None and lifecycle["activeClaims"]:
                        for active_claim in lifecycle["activeClaims"]:
                            intent = active_claim.get("intent")
                            if isinstance(intent, Mapping):
                                self._resume_active_lifecycle_claim(job_ref, intent)

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
                        and close_kind
                        in {"cancel", "native-cancel", "finalize", "native-finalize", "delete"}
                        and not self._runtime_records(str(close_kind), job_ref)
                    ):
                        if not isinstance(close, Mapping):
                            raise DependencyUnavailableError(
                                "lifecycle close identity is unavailable"
                            )
                        self._resume_lifecycle_close(job_ref, close)
                        if close_kind == "delete":
                            report.deleted += 1
                            continue
                        report.reconciled += 1
                        if str(_field(record, "state", "")) != "deleting":
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
                if not self._requires_ownerless_delete_recovery(record):
                    lifecycle = self._lifecycle.inspect(job_ref)
                    close = lifecycle.get("close") if lifecycle is not None else None
                    if (
                        lifecycle is not None
                        and lifecycle.get("gate") == "closing"
                        and isinstance(close, Mapping)
                        and close.get("kind")
                        in {"cancel", "native-cancel", "finalize", "native-finalize"}
                    ):
                        self._resume_lifecycle_close(job_ref, close)
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
            replay_payload = {
                "providerRequestId": str(_field(record, "provider_request_id")),
                "specDigest": str(_field(record, "spec_digest")),
                "spec": dict(spec_payload),
            }
            replay_request = (
                NativeCreateJobRequest.model_validate(replay_payload)
                if _is_native_record(record)
                else CreateJobRequest.model_validate(replay_payload)
            )
            self.create(replay_request)
            report.reconciled += 1
            return
        binding = self.inspect(job_ref)
        self._validate_job_annotations(record)
        if isinstance(binding, NativeJobBindingSnapshot):
            self._reconcile_native_runner_deadline(job_ref, binding)
            native_finalizations = self._runtime_records("native-finalize", job_ref)
            if native_finalizations:
                values = _runtime_values(native_finalizations[-1])
                payload = values.get("requestSpec")
                if payload:
                    self.finalize(
                        job_ref,
                        NativeFinalizeJobRequest.model_validate_json(payload),
                    )
                    report.reconciled += 1
                    return
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

    def _reconcile_native_runner_deadline(
        self, job_ref: str, binding: NativeJobBindingSnapshot
    ) -> None:
        root = binding.root
        generation = root["latestRunnerGeneration"]
        if not isinstance(generation, Mapping):
            return
        observation = generation["runnerObservation"]
        if observation["state"] not in {"starting", "running"}:
            return
        if self._now() < _as_datetime(generation["softDeadlineAt"], self._now()):
            return
        spec = {
            "jobUid": root["jobUid"],
            "podUid": root["podUid"],
            "generation": generation["generation"],
            "reason": "soft_deadline",
        }
        request = RunnerStopRequest.model_validate(
            {
                "stopRef": f"runner-soft-{canonical_digest(spec)[:24]}",
                "requestDigest": canonical_digest(spec),
                "spec": spec,
            }
        )
        self.stop_runner(job_ref, request)

    def create(self, request: CreateJobRequest | NativeCreateJobRequest) -> CreateResult:
        """Reserve before create and reconcile a response lost after API acceptance."""

        if not isinstance(request, NativeCreateJobRequest) and not self._hosted_admission:
            raise RuntimeRecipeForbiddenError(
                "hosted Job admission is retired; submit an exact native runtime recipe"
            )

        spec_payload = (
            request.spec
            if isinstance(request, NativeCreateJobRequest)
            else request.spec.digest_payload()
        )
        if not hmac.compare_digest(request.spec_digest, canonical_digest(spec_payload)):
            raise DigestMismatchError

        job_ref = self._renderer.job_ref(request)
        recipe_snapshot: Mapping[str, object] | None = None
        rendered_job: object | None = None
        if isinstance(request, NativeCreateJobRequest):
            existing = self._store.read_create(request.provider_request_id)
            if existing is None:
                native_spec = request.spec["native"]
                selection = native_spec.get("capabilityActivation")
                if isinstance(selection, Mapping):
                    assembly = self.runtime_assembly_by_digest(str(native_spec["assemblyDigest"]))
                    assembly_root = assembly.root
                    assembly_recipe = assembly_root["recipe"]
                    assembly_plan = assembly_root["capabilityActivation"]
                    if (
                        assembly_recipe["runnerRef"] != native_spec["runnerRef"]
                        or assembly_recipe["environmentProfileRef"]
                        != native_spec["environmentProfileRef"]
                        or assembly_root["selectedModelProtocol"]
                        != native_spec["selectedModelProtocol"]
                        or assembly_plan["planRef"] != selection["planRef"]
                        or assembly_plan["planDigest"] != selection["planDigest"]
                    ):
                        raise StateConflictError(
                            "native create differs from the resolved runtime assembly"
                        )
                    recipe_snapshot = dict(assembly_recipe)
                else:
                    try:
                        recipe_snapshot = self._renderer.resolve_recipe(
                            str(native_spec["runnerRef"]),
                            str(native_spec["environmentProfileRef"]),
                        ).wire()
                    except RuntimeRecipeForbiddenError:
                        self._record_native_recipe_forbidden()
                        raise
        else:
            rendered_job = self._renderer.render(request)
        reservation = self._reserve_create(
            request,
            job_ref,
            spec_payload,
            native_recipe_snapshot=recipe_snapshot,
        )
        record = _field(reservation, "record", reservation)
        created = bool(_field(reservation, "created", False))
        self._raise_if_record_conflicts(record, request.provider_request_id, request.spec_digest)
        if _is_deleted(record):
            raise TombstonedError(_tombstone_payload(record))
        native_recipe = (
            self._frozen_native_recipe(record)
            if isinstance(request, NativeCreateJobRequest)
            else None
        )
        activation_plan = (
            self._native_activation_plan(record)
            if isinstance(request, NativeCreateJobRequest)
            else None
        )
        if str(_field(record, "state", "")) == "deleting":
            return CreateResult(snapshot=self.inspect(job_ref), created=False)
        if _optional_text(record, "indeterminate_reason") is not None:
            return CreateResult(snapshot=self.inspect(job_ref), created=False)

        job = self._read_job(job_ref)
        if job is None:
            if _field(record, "job_uid", None) is not None:
                reason = "the retained Job is no longer observable"
                record = self._mark_indeterminate(record, reason)
                missing = (
                    self._native_missing_job_snapshot(record)
                    if _is_native_record(record)
                    else self._missing_job_snapshot(record)
                )
                return CreateResult(snapshot=missing, created=False)
            expected_policy = self._renderer.render_network_policy(request)
            self._create_or_reconcile_network_policy(expected_policy, record)
            if rendered_job is None:
                if isinstance(request, NativeCreateJobRequest):
                    self._dev_sessions.ensure_relay_credential(job_ref)
                rendered_job = self._renderer.render(
                    request,
                    native_recipe=native_recipe,
                    activation_plan=activation_plan,
                )
            job = self._create_or_reconcile_job(rendered_job, job_ref)
        job_uid = _required_text(job, "metadata", "uid")
        self._store.mark_created(request.provider_request_id, job_uid)
        snapshot = self.inspect(job_ref)
        return CreateResult(snapshot=snapshot, created=created)

    def inspect(self, job_ref: str) -> JobBindingSnapshot | NativeJobBindingSnapshot:
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
                if _is_native_record(record):
                    return self._native_missing_job_snapshot(record)
                return self._deleting_snapshot(self._missing_job_snapshot(record), record)
            record = self._mark_indeterminate(record, "the retained Job is no longer observable")
            if _is_native_record(record):
                return self._native_missing_job_snapshot(record)
            return self._missing_job_snapshot(record)

        _, policy_reason = self._network_policy_observation(record, self._now())
        if policy_reason is not None and not deleting:
            record = self._mark_indeterminate(record, policy_reason)

        actual_job_uid = _required_text(job, "metadata", "uid")
        retained_job_uid = _field(record, "job_uid", None)
        if deleting:
            pods = tuple(self._list_job_pods(job_ref, actual_job_uid))
            replacement_reason: str | None = None
            if retained_job_uid is not None and str(retained_job_uid) != actual_job_uid:
                replacement_reason = "Job UID changed"
            elif _current_pod(pods)[1] is not None:
                replacement_reason = _current_pod(pods)[1]
            if _is_native_record(record):
                return self._native_snapshot(
                    record,
                    job,
                    pods,
                    replacement_reason=replacement_reason,
                )
            snapshot = self._snapshot(record, job, pods, replacement_reason=replacement_reason)
            return self._deleting_snapshot(snapshot, record)
        if retained_job_uid is not None and str(retained_job_uid) != actual_job_uid:
            reason = "Job UID changed"
            record = self._mark_indeterminate(record, reason)
            if _is_native_record(record):
                return self._native_snapshot(record, job, (), replacement_reason=reason)
            return self._snapshot(record, job, (), replacement_reason=reason)
        if retained_job_uid is None:
            record = self._store.mark_created(
                str(_field(record, "provider_request_id")), actual_job_uid
            )

        pods = tuple(self._list_job_pods(job_ref, actual_job_uid))
        current_pod, selection_reason = _current_pod(pods)
        replacement_reason = _optional_text(record, "indeterminate_reason")
        if replacement_reason is not None:
            pass
        elif selection_reason is not None:
            replacement_reason = selection_reason
        elif current_pod is not None:
            current_uid = _required_text(current_pod, "metadata", "uid")
            try:
                observed_at = self._now()
                incarnation = _pod_incarnation(current_pod, observed_at)
                record = self._store.bind_pod_incarnation(
                    str(_field(record, "provider_request_id")),
                    current_uid,
                    incarnation.model_dump_json(by_alias=True),
                )
            except ReplacementPodError:
                replacement_reason = "Pod binding changed during reconciliation"

        if replacement_reason is not None:
            record = self._mark_indeterminate(record, replacement_reason)

        if _is_native_record(record):
            binding = self._native_binding_identity(record, job, current_pod)
            if current_pod is not None and replacement_reason is None:
                self._native.refresh_generation(job_ref, binding)
            return self._native_snapshot(
                record,
                job,
                pods,
                replacement_reason=replacement_reason,
            )

        snapshot = self._snapshot(record, job, pods, replacement_reason=replacement_reason)
        if replacement_reason is None and self._refresh_running_generation(snapshot):
            snapshot = self._snapshot(
                record,
                job,
                pods,
                replacement_reason=replacement_reason,
            )
        return self._deleting_snapshot(snapshot, record) if deleting else snapshot

    def _refresh_running_generation(self, binding: JobBindingSnapshot) -> bool:
        """Persist a terminal child observation exposed by the live supervisor.

        A Kubernetes Job stays alive because both long-lived supervisors are
        PID 1, so Pod phase cannot reveal that the hosted Work Agent child has
        exited.  Refresh only the retained running generation and only through
        the fixed, read-only supervisor inspection RPC.  This also reaps a
        completed child instead of leaving it as a zombie under PID 1.
        """

        retained = binding.latest_agent_generation
        inspect_supervisor = (
            getattr(self._transport, "inspect_supervisor", None)
            if self._transport is not None
            else None
        )
        if (
            retained is None
            or retained.runner_state is not RunnerState.RUNNING
            or binding.pod_uid is None
            or not callable(inspect_supervisor)
        ):
            return False
        observed = inspect_supervisor(
            {
                "jobRef": binding.job_ref,
                "jobUid": str(binding.job_uid),
                "podUid": str(binding.pod_uid),
            },
            "agent",
        )
        if (
            observed.protocol_version != 1
            or observed.generation != retained.generation
            or observed.agent_run_ref != retained.agent_run_ref
            or observed.launch_bundle_digest != retained.launch_bundle_digest
            or observed.supervisor_alive is not True
            or observed.state not in {"running", "exited"}
        ):
            raise StateConflictError(
                "The supervisor inspection differs from the retained generation"
            )
        if observed.state == "running":
            return False
        if type(observed.exit_code) is not int:
            raise StateConflictError("The terminal supervisor inspection has no integer exit code")
        record = self._store.read_runtime(
            "generation",
            binding.job_ref,
            str(retained.generation),
        )
        if record is None:
            raise DependencyUnavailableError(
                "The retained generation disappeared during inspection"
            )
        current = self._generation_snapshot(record, replayed=False)
        if current.runner_state is RunnerState.EXITED:
            return False
        if current.runner_state is not RunnerState.RUNNING:
            raise StateConflictError("The retained generation changed during supervisor inspection")
        now = self._now()
        terminal = current.model_copy(
            update={
                "runner_state": RunnerState.EXITED,
                "supervisor_alive": True,
                "pid": observed.pid,
                "exit_code": observed.exit_code,
                "finished_at": now,
                "observed_at": now,
            }
        )
        try:
            self._cas_runtime_update(
                record,
                {"payload": terminal.model_dump_json(by_alias=True)},
            )
        except DependencyUnavailableError:
            raced = self._store.read_runtime(
                "generation",
                binding.job_ref,
                str(retained.generation),
            )
            if (
                raced is not None
                and self._generation_snapshot(
                    raced,
                    replayed=False,
                ).runner_state
                is RunnerState.EXITED
            ):
                return True
            raise
        return True

    def list_jobs(
        self, query: JobListQuery | None = None
    ) -> JobBindingSnapshotList | AnyJobBindingSnapshotList:
        """Return one stable-key-merge page over live bindings and tombstones."""

        query = query or JobListQuery()
        if not 1 <= query.page_size <= MAX_PAGE_SIZE:
            raise InvalidRequestError("pageSize must be between 1 and 200")
        query_digest = self._list_query_digest(query)
        offset = self._page_offset(query.page_token, query_digest)

        records = list(self._store.list_create())
        entries: list[
            tuple[datetime, str, JobBindingSnapshot | NativeJobBindingSnapshot | JobTombstone]
        ] = []
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
                value: JobBindingSnapshot | NativeJobBindingSnapshot | JobTombstone = _as_tombstone(
                    record
                )
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
        native_present = any(isinstance(value, NativeJobBindingSnapshot) for _, _, value in page)
        if native_present:
            return AnyJobBindingSnapshotList.model_validate(
                {
                    "items": [
                        value.model_dump(mode="json", by_alias=True)
                        for _, _, value in page
                        if isinstance(value, (JobBindingSnapshot, NativeJobBindingSnapshot))
                    ],
                    "tombstones": [
                        value.model_dump(mode="json", by_alias=True)
                        for _, _, value in page
                        if isinstance(value, JobTombstone)
                    ],
                    "nextPageToken": next_token,
                    "observedAt": self._now().isoformat(),
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
    ) -> RoleLogs | NativeRoleLogs:
        """Read a bounded page from one explicit role on the immutable Pod."""

        snapshot = self.inspect(job_ref)
        if isinstance(snapshot, NativeJobBindingSnapshot):
            container = str(role)
            if container not in {"runner", "control"}:
                raise InvalidRequestError("native container must be 'runner' or 'control'")
            if not 1 <= limit_bytes <= MAX_LOG_LIMIT_BYTES:
                raise InvalidRequestError("limitBytes must be between 1 and 1048576")
            root = snapshot.root
            if root["podUid"] is None:
                raise StateConflictError("The Job does not yet have an immutable Pod binding")
            page = self._read_role_logs(
                job_ref, str(root["podUid"]), container, cursor, limit_bytes
            )
            role_snapshot = root[container]
            return NativeRoleLogs.model_validate(
                {
                    "jobRef": job_ref,
                    "jobUid": root["jobUid"],
                    "podUid": root["podUid"],
                    "container": container,
                    "inputCursor": cursor,
                    "startCursor": str(_field(page, "start_cursor")),
                    "nextCursor": _optional_text(page, "next_cursor"),
                    "content": str(_field(page, "content", "")),
                    "truncated": bool(_field(page, "truncated", False)),
                    "terminal": bool(_field(page, "terminal", False)),
                    "containerId": (
                        role_snapshot.get("containerId")
                        if isinstance(role_snapshot, Mapping)
                        else None
                    ),
                    "observedAt": self._now().isoformat(),
                }
            )

        try:
            container = role if isinstance(role, LogContainer) else LogContainer(role)
        except ValueError as error:
            raise InvalidRequestError("container must be 'agent' or 'workspace'") from error
        if not 1 <= limit_bytes <= MAX_LOG_LIMIT_BYTES:
            raise InvalidRequestError("limitBytes must be between 1 and 1048576")

        snapshot = self.inspect(job_ref)
        if not isinstance(snapshot, JobBindingSnapshot):
            raise StateConflictError("hosted role logs require a hosted binding")
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

    def resolve_runtime_recipe(
        self, runner_ref: str, environment_profile_ref: str
    ) -> ResolvedRuntimeRecipe:
        try:
            return self._renderer.resolve_recipe(runner_ref, environment_profile_ref)
        except RuntimeRecipeForbiddenError:
            self._record_native_recipe_forbidden()
            raise

    def resolve_runtime_assembly(
        self,
        request: RuntimeAssemblyResolutionRequest | Mapping[str, Any],
    ) -> ResolvedRuntimeAssembly:
        """Resolve exact catalog pins; RC cannot submit image or command fields."""

        if self._runtime_assembly_resolver is None:
            raise DependencyUnavailableError("runtime assembly registry is not configured")
        try:
            resolved = self._runtime_assembly_resolver.resolve(request)
        except KcsV2Error as error:
            if error.code == "CAPABILITY_ACTIVATION_INCOMPATIBLE":
                self._record_m2_metric("capability_activation_failures_total")
            raise
        wire = resolved.wire()
        plan = CapabilityActivationPlan.model_validate(wire["capabilityActivation"])
        plan_wire = plan.wire()
        self._store.reserve_catalog(
            "activation-plan",
            str(plan_wire["planRef"]),
            str(plan_wire["planDigest"]),
            plan_wire,
        )
        stable = _stable_runtime_assembly(wire)
        self._store.reserve_catalog(
            "runtime-assembly",
            str(wire["assemblyDigest"]),
            str(wire["assemblyDigest"]),
            stable,
        )
        return self.runtime_assembly_by_digest(str(wire["assemblyDigest"]))

    def runtime_assembly_by_digest(self, assembly_digest: str) -> ResolvedRuntimeAssembly:
        """Read restart-durable exact assembly bytes for create/renderer verification."""

        record = self._store.read_catalog("runtime-assembly", assembly_digest)
        if record is None:
            raise JobNotFoundError("The resolved runtime assembly was not found")
        if _field(record, "digest", None) != assembly_digest:
            raise IdentityDigestConflict()
        try:
            payload = json.loads(str(_field(record, "payload")))
        except (TypeError, json.JSONDecodeError) as error:
            raise DependencyUnavailableError("retained runtime assembly is invalid") from error
        if not isinstance(payload, dict) or payload.get("assemblyDigest") != assembly_digest:
            raise DependencyUnavailableError("retained runtime assembly identity differs")
        observed_at = self._now().isoformat()
        recipe = payload.get("recipe")
        if not isinstance(recipe, dict):
            raise DependencyUnavailableError("retained runtime assembly recipe is invalid")
        recipe["observedAt"] = observed_at
        payload["observedAt"] = observed_at
        try:
            return ResolvedRuntimeAssembly.model_validate(payload)
        except ValueError as error:
            raise DependencyUnavailableError("retained runtime assembly is invalid") from error

    def capability_activation_plan(
        self, plan_ref: str, plan_digest: str
    ) -> CapabilityActivationPlan:
        """Return one exact restart-durable plan for native Job rendering."""

        record = self._store.read_catalog("activation-plan", plan_ref)
        if record is None:
            raise JobNotFoundError("The capability activation plan was not found")
        if _field(record, "digest", None) != plan_digest:
            raise IdentityDigestConflict()
        try:
            plan = CapabilityActivationPlan.model_validate_json(str(_field(record, "payload")))
        except (TypeError, ValueError) as error:
            raise DependencyUnavailableError(
                "retained capability activation plan is invalid"
            ) from error
        if plan.root["planRef"] != plan_ref or plan.root["planDigest"] != plan_digest:
            raise IdentityDigestConflict()
        return plan

    def create_live_workspace_snapshot(
        self,
        job_ref: str,
        request: LiveWorkspaceSnapshotRequest | Mapping[str, Any],
    ) -> LiveSnapshotResult:
        started = time.monotonic()
        try:
            return self._live_workspace.create(job_ref, request)
        finally:
            self._record_live_operation(started)

    def inspect_live_workspace_snapshot(
        self, job_ref: str, snapshot_ref: str
    ) -> LiveWorkspaceSnapshot:
        started = time.monotonic()
        try:
            return self._live_workspace.inspect(job_ref, snapshot_ref)
        finally:
            self._record_live_operation(started)

    def release_live_workspace_snapshot(
        self, job_ref: str, snapshot_ref: str
    ) -> LiveWorkspaceSnapshot:
        started = time.monotonic()
        try:
            return self._live_workspace.release(job_ref, snapshot_ref)
        finally:
            self._record_live_operation(started)

    def read_live_workspace_content(
        self,
        job_ref: str,
        snapshot_ref: str,
        path: str,
        *,
        offset: int = 0,
        limit_bytes: int = 1048576,
    ) -> LiveContentRange:
        started = time.monotonic()
        try:
            result = self._live_workspace.read_content(
                job_ref,
                snapshot_ref,
                path,
                offset=offset,
                limit_bytes=limit_bytes,
            )
            self._record_m2_metric("live_bytes_total", len(result.content))
            return result
        finally:
            self._record_live_operation(started)

    def get_live_workspace_diff(
        self,
        job_ref: str,
        snapshot_ref: str,
        *,
        page_token: str | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> LiveWorkspaceDiffPage:
        started = time.monotonic()
        try:
            return self._live_workspace.diff(
                job_ref,
                snapshot_ref,
                page_token=page_token,
                page_size=page_size,
            )
        finally:
            self._record_live_operation(started)

    def _record_live_operation(self, started: float) -> None:
        self._record_m2_metric("live_operations_total")
        self._record_m2_metric("live_latency_seconds_sum", max(0.0, time.monotonic() - started))

    def _record_m2_metric(self, name: str, value: float | int = 1) -> None:
        with self._native_metrics_lock:
            self._m2_metrics[name] += value

    def _record_native_recipe_forbidden(self) -> None:
        with self._native_metrics_lock:
            self._native_recipe_forbidden_total += 1

    def grant_runner_credential_result(
        self,
        job_ref: str,
        metadata: RunnerCredentialGrantMetadata,
        raw_bytes: bytes,
    ) -> NativeMutationResult:
        snapshot, binding = self._native_binding(job_ref)
        del snapshot
        self._assert_accepting_workspace_work(job_ref)
        claim = self._lifecycle.claim(
            job_ref,
            str(binding["jobUid"]),
            str(binding["podUid"]),
            "native-runner-credential",
            metadata.credential_grant_ref,
        )
        try:
            return self._native.grant(job_ref, binding, metadata, raw_bytes)
        finally:
            claim.release()

    def inspect_runner_credential_grant(
        self, job_ref: str, credential_grant_ref: str
    ) -> RunnerCredentialGrantSnapshot:
        self._native_binding(job_ref)
        return self._native.inspect_grant(job_ref, credential_grant_ref)

    def start_runner(
        self, job_ref: str, request: RunnerStartRequest
    ) -> NativeRunnerGenerationSnapshot:
        snapshot, binding = self._native_binding(job_ref)
        self._assert_accepting_workspace_work(job_ref)
        claim = self._lifecycle.claim(
            job_ref,
            str(binding["jobUid"]),
            str(binding["podUid"]),
            "native-runner-start",
            str(request.root["generation"]),
        )
        try:
            return self._start_runner_unclaimed(job_ref, request, snapshot, binding)
        finally:
            claim.release()

    def _start_runner_unclaimed(
        self,
        job_ref: str,
        request: RunnerStartRequest,
        snapshot: NativeJobBindingSnapshot,
        binding: Mapping[str, Any],
    ) -> NativeRunnerGenerationSnapshot:
        root = snapshot.root
        record = self._store.read_by_job_ref(job_ref)
        if record is None:
            raise JobNotFoundError()
        native_spec = _field(_field(record, "spec_payload", {}), "native", {})
        recipe = self._frozen_native_recipe(record)

        def transfer_ready(ref: str) -> bool:
            try:
                return (
                    self._workspace_runtime.inspect_transfer(job_ref, ref).state
                    is TransferState.COMPLETED
                )
            except KcsV2Error:
                return False

        if root["recipeActivation"] is None or root["recipeActivation"]["state"] != "active":
            raise PreconditionFailedError("native runtime recipe is not active")
        return self._native.start(
            job_ref,
            binding,
            native_spec,
            recipe.root,
            request,
            transfer_ready,
        )

    def stop_runner(self, job_ref: str, request: RunnerStopRequest) -> NativeMutationResult:
        _snapshot, binding = self._native_binding(job_ref)
        return self._native.stop(job_ref, binding, request)

    def _native_binding(self, job_ref: str) -> tuple[NativeJobBindingSnapshot, dict[str, Any]]:
        snapshot = self.inspect(job_ref)
        if not isinstance(snapshot, NativeJobBindingSnapshot):
            raise StateConflictError("native runner operation requires a native binding")
        root = snapshot.root
        if root["podUid"] is None or root["bindingState"] == "indeterminate":
            raise ReplacementPodError()
        return snapshot, {
            "runtimeLane": "native",
            "jobRef": job_ref,
            "jobUid": root["jobUid"],
            "podUid": root["podUid"],
        }

    def _native_live_binding(self, job_ref: str) -> NativeJobBindingSnapshot:
        """Return the exact live native binding used by workspace snapshots."""

        snapshot, _binding = self._native_binding(job_ref)
        return snapshot

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
            retained_bindings = self._retained_start_material_bindings(existing)
            self._workspace_runtime.validate_start_material_bindings(
                job_ref,
                binding,
                request.launch_bundle_path,
                request.launch_bundle_size_bytes,
                request.launch_bundle_digest,
                request.material_paths,
                retained_bindings,
            )
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
            material_bindings = self._workspace_runtime.resolve_start_material_bindings(
                job_ref,
                binding,
                request.launch_bundle_path,
                request.launch_bundle_size_bytes,
                request.launch_bundle_digest,
                request.material_paths,
            )
            grant = self.inspect_credential_grant(job_ref, request.credential_grant_ref)
            if grant.state is not CredentialState.AVAILABLE or self._now() >= grant.expires_at:
                self._expire_grant_if_needed(grant)
                raise CredentialExpiredError()
            self._validate_generation_grant(grant, request, binding)
            values = self._generation_values(
                job_ref,
                request,
                digest,
                binding,
                grant,
                material_bindings,
            )
            record, _ = self._store.reserve_runtime(
                "generation", str(request.generation), job_ref, values
            )
            if _runtime_values(record).get("identityDigest") != digest:
                raise IdentityDigestConflict()
            retained = self._generation_snapshot(record, replayed=False)
            self._validate_retained_generation(retained, request, binding)
            if self._retained_start_material_bindings(record) != material_bindings:
                raise PreconditionFailedError()
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

    def finalize(
        self, job_ref: str, request: FinalizeJobRequest | NativeFinalizeJobRequest
    ) -> FinalizeResult:
        """Quiesce supervisors and revoke credentials without deleting Job/Pod/log reality."""
        if isinstance(request, NativeFinalizeJobRequest):
            if not hmac.compare_digest(
                canonical_digest(request.root["spec"]), request.root["requestDigest"]
            ):
                raise DigestMismatchError()
            _snapshot, binding = self._native_binding(job_ref)
            close = self._lifecycle.begin_close(
                job_ref,
                str(binding["jobUid"]),
                str(binding["podUid"]),
                "native-finalize",
                request.root["finalizeRef"],
                request.root["requestDigest"],
                request.model_dump_json(by_alias=True),
            )

            def transfers_terminal(refs: list[str]) -> bool:
                for ref in refs:
                    try:
                        state = self._workspace_runtime.inspect_transfer(job_ref, ref).state
                    except KcsV2Error:
                        return False
                    if state not in {
                        TransferState.COMPLETED,
                        TransferState.CANCELED,
                        TransferState.DISCARDED,
                        TransferState.FAILED,
                        TransferState.INDETERMINATE,
                    }:
                        return False
                return True

            try:
                self._dev_sessions.revoke_for_job(job_ref, "native_finalize")
                result = self._native.finalize(
                    job_ref,
                    binding,
                    request,
                    transfers_terminal,
                    lambda: self._native_control_shutdown_observed(job_ref, binding),
                )
                close.phase("succeeded", closed=True)
            except KcsV2Error:
                close.phase("indeterminate")
                raise
            except Exception as error:
                close.phase("indeterminate")
                raise DependencyUnavailableError("native finalize did not complete") from error
            return FinalizeResult(snapshot=self.inspect(job_ref), created=result.created)
        self.reconcile_credentials()
        self._assert_no_cancel(job_ref)
        if not hmac.compare_digest(canonical_digest(request.spec), request.request_digest):
            raise DigestMismatchError()
        binding = self._binding_for_close(
            job_ref, "finalize", request.finalize_ref, request.request_digest
        )
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
                if not self._roles_are_terminal(
                    job_ref, str(binding.job_uid), str(binding.pod_uid)
                ):
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
        current = self.inspect(job_ref)
        if isinstance(current, NativeJobBindingSnapshot):
            return self._cancel_native(job_ref, request, current)
        if not hmac.compare_digest(canonical_digest(request.spec), request.request_digest):
            raise DigestMismatchError()
        self._assert_not_finalizing(job_ref)
        binding = self._binding_for_close(
            job_ref, "cancel", request.cancel_ref, request.request_digest
        )
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
                if not self._roles_are_terminal(
                    job_ref, str(binding.job_uid), str(binding.pod_uid)
                ):
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

    def _cancel_native(
        self,
        job_ref: str,
        request: CancelJobRequest,
        snapshot: NativeJobBindingSnapshot,
    ) -> CancelResult:
        if not hmac.compare_digest(canonical_digest(request.spec), request.request_digest):
            raise DigestMismatchError()
        root = snapshot.root
        cancel_action = root["cancelAction"]
        same_cancel_action = (
            isinstance(cancel_action, Mapping)
            and isinstance(cancel_action.get("actionRef"), str)
            and isinstance(cancel_action.get("requestDigest"), str)
            and hmac.compare_digest(cancel_action["actionRef"], request.cancel_ref)
            and hmac.compare_digest(cancel_action["requestDigest"], request.request_digest)
        )
        prestart_evidence = (
            root["podUid"] is None
            and root["observedPodCount"] == 0
            and root["latestRunnerGeneration"] is None
            and not root["credentialObservations"]
        )
        prestart = prestart_evidence and (
            root["bindingState"] in {"provisioning", "bound"}
            or (
                root["bindingState"] in {"canceling", "canceled", "indeterminate"}
                and same_cancel_action
            )
        )
        if (
            (root["podUid"] is None and not prestart)
            or (root["bindingState"] == "indeterminate" and not prestart)
        ):
            raise ReplacementPodError()
        self._assert_not_finalizing(job_ref)
        request_spec = request.spec.model_dump_json(by_alias=True)
        pod_uid = "" if prestart else str(root["podUid"])
        close = self._lifecycle.begin_close(
            job_ref,
            str(root["jobUid"]),
            pod_uid,
            "native-cancel",
            request.cancel_ref,
            request.request_digest,
            request_spec,
        )
        values = {
            "identityDigest": request.request_digest,
            "cancelRef": request.cancel_ref,
            "jobUid": str(root["jobUid"]),
            "podUid": pod_uid,
            "requestSpec": request_spec,
            # Native cancellation keeps control alive for capture.  Until all
            # pre-authorized collects have terminal truth, possible output
            # loss is the only honest initial observation.
            "payload": phase_payload("accepted", self._now(), output_loss_possible=True),
        }
        record, created = self._store.reserve_runtime("cancel", request.cancel_ref, job_ref, values)
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
        binding = {
            "runtimeLane": "native",
            "jobRef": job_ref,
            "jobUid": root["jobUid"],
            "podUid": root["podUid"],
        }
        try:
            if prestart:
                # The retained Job never observed a Pod, runner generation, or
                # credential.  Its exact Job UID remains the lifecycle identity;
                # an empty pod UID records that no incarnation was ever bound.
                record = self._set_cancel_phase(
                    record, "succeeded", output_loss_possible=False
                )
                close.phase("succeeded", closed=True)
                phase = "succeeded"
            if phase == "accepted":
                self._dev_sessions.revoke_for_job(job_ref, "native_cancel")
                self._native.revoke_all(job_ref)
                record = self._set_cancel_phase(
                    record, "credentials_revoked", output_loss_possible=True
                )
                close.phase("credentials_revoked")
                phase = "credentials_revoked"
            if phase == "credentials_revoked":
                generation = self._native.refresh_generation(job_ref, binding)
                if generation is not None and generation.root["runnerObservation"]["state"] not in {
                    "exited",
                    "killed",
                }:
                    stop_spec = {
                        "jobUid": root["jobUid"],
                        "podUid": root["podUid"],
                        "generation": generation.root["generation"],
                        "reason": "cancel_requested",
                    }
                    stop_request = RunnerStopRequest.model_validate(
                        {
                            "stopRef": f"runner-cancel-{request.request_digest[:24]}",
                            "requestDigest": canonical_digest(stop_spec),
                            "spec": stop_spec,
                        }
                    )
                    self._native.stop(job_ref, binding, stop_request)
                record = self._set_cancel_phase(record, "runner_stopped", output_loss_possible=True)
                close.phase("runner_stopped")
                phase = "runner_stopped"
            if phase == "runner_stopped":
                collect_indeterminate = self._drain_cancel_collects(job_ref, request.spec)
                output_loss = collect_indeterminate or self._native_cancel_output_loss(
                    job_ref, request.spec.finish_collect_transfer_refs
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
                record = self._set_cancel_phase(
                    record, "succeeded", output_loss_possible=output_loss
                )
                close.phase("succeeded", closed=True)
                phase = "succeeded"
        except KcsV2Error as error:
            self._set_cancel_indeterminate(record, phase, True, type(error).__name__)
            close.phase("indeterminate")
            raise
        except Exception as error:
            self._set_cancel_indeterminate(record, phase, True, type(error).__name__)
            close.phase("indeterminate")
            raise DependencyUnavailableError("native cancel lifecycle did not complete") from error
        if phase != "succeeded":
            raise DependencyUnavailableError("retained native cancel phase is indeterminate")
        return CancelResult(snapshot=self.inspect(job_ref), created=created)

    cancel_job = cancel

    def delete(self, job_ref: str, delete_ref: str, request_digest: str) -> JobTombstone:
        """Fence close, persist ownerless delete intent, then prove foreground cleanup."""
        if not hmac.compare_digest(request_digest, EMPTY_OBJECT_DIGEST):
            raise DigestMismatchError
        record = self._store.read_by_job_ref(job_ref)
        if record is None:
            raise JobNotFoundError
        state = str(_field(record, "state", ""))
        if (
            state not in {"deleting", "deleted"}
            and _field(record, "job_uid", None) is not None
            and self._read_job(job_ref) is None
        ):
            self._mark_indeterminate(record, "the retained Job is no longer observable")
            raise DependencyUnavailableError(
                "delete cannot acquire a lifecycle fence after the retained Job disappeared"
            )
        ownerless_recovery = self._requires_ownerless_delete_recovery(record)
        if _is_deleted(record):
            self._raise_if_delete_conflicts(record, delete_ref, request_digest)
            if _field(record, "cleanup_state", "complete") == "complete":
                return _as_tombstone(record)
            final_state = _provider_terminal_state(_field(record, "final_state", "indeterminate"))
            credential_observations, transfer_observations = _stored_tombstone_observations(record)
        elif str(_field(record, "state", "")) == "deleting":
            self._raise_if_delete_conflicts(record, delete_ref, request_digest)
            if not ownerless_recovery:
                lifecycle = self._lifecycle.inspect(job_ref)
                retained_close = lifecycle.get("close") if lifecycle is not None else None
                if (
                    lifecycle is not None
                    and lifecycle.get("gate") == "closing"
                    and isinstance(retained_close, Mapping)
                    and retained_close.get("kind")
                    in {"cancel", "native-cancel", "finalize", "native-finalize"}
                ):
                    self._resume_lifecycle_close(job_ref, retained_close)
            final_state = _provider_terminal_state(_field(record, "final_state", "indeterminate"))
            credential_observations, transfer_observations = _stored_tombstone_observations(record)
        else:
            snapshot = self.inspect(job_ref)
            final_state = _terminal_state_for_binding(snapshot.binding_state)
            if isinstance(snapshot, NativeJobBindingSnapshot):
                credential_observations = [
                    dict(item) for item in snapshot.root["credentialObservations"]
                ]
                transfer_observations = [
                    dict(item) for item in snapshot.root["transferObservations"]
                ]
            else:
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
        close: LifecycleClose | None = None
        if not ownerless_recovery:
            close = self._lifecycle.begin_close(
                job_ref,
                str(_field(record, "job_uid")),
                str(_field(record, "pod_uid")),
                "delete",
                delete_ref,
                request_digest,
                "{}",
            )
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
        if close is not None:
            close.phase("delete_intent_persisted")

        if _is_native_record(record):
            self._dev_sessions.revoke_for_job(job_ref, "job_delete")
            if not self._dev_sessions.delete_relay_credential(job_ref):
                raise CredentialDestroyFailedError()
            self._native.revoke_all(job_ref)
            self._prove_native_secret_absent(job_ref, str(_field(record, "job_uid")))
        else:
            for grant_record in self._store.list_runtime("credential", job_ref):
                grant = self._grant_snapshot(grant_record)
                if grant.secret_present is not False:
                    self._revoke_grant(grant)
            self._prove_secret_absent(job_ref, str(_field(record, "job_uid")))
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
        if close is not None:
            close.phase("credentials_destroyed")

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
        if close is not None:
            close.phase("job_delete_requested")
        return self._finish_ownerless_delete(
            record,
            delete_ref,
            request_digest,
            final_state,
            credential_observations,
            transfer_observations,
        )

    def _finish_ownerless_delete(
        self,
        record: object,
        delete_ref: str,
        request_digest: str,
        final_state: ProviderTerminalState,
        credential_observations: Sequence[Mapping[str, object]],
        transfer_observations: Sequence[Mapping[str, object]],
    ) -> JobTombstone:
        """Finish deletion using only the ownerless deleting record after Job delete intent."""
        job_ref = str(_field(record, "job_ref"))
        observed_at = self._now()
        self._delete_job(job_ref, str(_field(record, "job_uid")))
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
            deleted_at=observed_at,
            expires_at=observed_at + self._tombstone_ttl,
            cleanup_state=CleanupState.PENDING,
            cleanup_phase=_later_delete_phase(record, "workload_absent"),
            gpu_release_state=CleanupState.COMPLETE if gpu_requested else CleanupState.NOT_REQUIRED,
            credential_observations=credential_observations,
            transfer_observations=transfer_observations,
        )
        self._delete_network_policy(record)
        record = self._mark_deleted(
            record,
            delete_ref=delete_ref,
            request_digest=request_digest,
            final_state=final_state,
            deleted_at=observed_at,
            expires_at=observed_at + self._tombstone_ttl,
            cleanup_state=CleanupState.PENDING,
            cleanup_phase=_later_delete_phase(record, "network_policy_absent"),
            gpu_release_state=CleanupState.COMPLETE if gpu_requested else CleanupState.NOT_REQUIRED,
            credential_observations=credential_observations,
            transfer_observations=transfer_observations,
        )
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

    def _requires_ownerless_delete_recovery(self, record: object) -> bool:
        if str(_field(record, "state", "")) != "deleting":
            return False
        return (
            _delete_phase_reached(record, "job_delete_requested")
            or self._read_job(str(_field(record, "job_ref"))) is None
        )

    delete_job = delete

    def _reserve_create(
        self,
        request: CreateJobRequest | NativeCreateJobRequest,
        job_ref: str,
        spec_payload: Mapping[str, object],
        *,
        native_recipe_snapshot: Mapping[str, object] | None = None,
    ) -> object:
        try:
            return self._store.reserve_create(
                request.provider_request_id,
                request.spec_digest,
                job_ref,
                spec_payload,
                native_recipe_snapshot=native_recipe_snapshot,
            )
        except KcsV2Error:
            raise
        except Exception as error:
            raise DependencyUnavailableError from error

    def _frozen_native_recipe(self, record: object) -> ResolvedRuntimeRecipe:
        raw = _field(record, "native_recipe_snapshot_json", None)
        if not isinstance(raw, str) or not raw:
            raise DependencyUnavailableError(
                "native create reservation has no frozen runtime recipe"
            )
        try:
            recipe = ResolvedRuntimeRecipe.model_validate_json(raw)
        except (TypeError, ValueError) as error:
            raise DependencyUnavailableError(
                "native create reservation has an invalid runtime recipe"
            ) from error
        supplied_digest = str(recipe.root["recipeDigest"])
        if not hmac.compare_digest(supplied_digest, runtime_recipe_digest(recipe)):
            raise StateConflictError("frozen native runtime recipe digest differs")
        spec = _field(record, "spec_payload", {})
        native_spec = _field(spec, "native", {})
        if recipe.runner_ref != str(
            _field(native_spec, "runnerRef", "")
        ) or recipe.environment_profile_ref != str(
            _field(native_spec, "environmentProfileRef", "")
        ):
            raise StateConflictError("frozen native runtime recipe pair differs")
        return recipe

    def _native_activation_plan(self, record: object) -> CapabilityActivationPlan | None:
        spec = _field(record, "spec_payload", {})
        native_spec = _field(spec, "native", {})
        selection = _field(native_spec, "capabilityActivation", None)
        if not isinstance(selection, Mapping):
            return None
        return self.capability_activation_plan(
            str(selection["planRef"]), str(selection["planDigest"])
        )

    def _live_binding(self, job_ref: str) -> JobBindingSnapshot | NativeJobBindingSnapshot:
        binding = self.inspect(job_ref)
        if binding.binding_state is JobBindingState.DELETING:
            raise StateConflictError("The Job has a retained deletion intent")
        if binding.pod_uid is None or binding.binding_state is JobBindingState.INDETERMINATE:
            raise ReplacementPodError()
        return binding

    def _native_live_binding(self, job_ref: str) -> NativeJobBindingSnapshot:
        binding = self._live_binding(job_ref)
        if not isinstance(binding, NativeJobBindingSnapshot):
            raise StateConflictError("The operation requires a Native Job")
        return binding

    def _binding_for_close(
        self, job_ref: str, kind: str, ref: str, digest: str
    ) -> JobBindingSnapshot:
        binding = self.inspect(job_ref)
        if binding.binding_state is not JobBindingState.DELETING:
            if binding.pod_uid is None or binding.binding_state is JobBindingState.INDETERMINATE:
                raise ReplacementPodError()
            return binding
        lifecycle = self._lifecycle.inspect(job_ref)
        close = lifecycle.get("close") if lifecycle is not None else None
        if (
            lifecycle is None
            or lifecycle.get("gate") not in {"closing", "closed"}
            or not isinstance(close, Mapping)
            or close.get("kind") != kind
            or close.get("ref") != ref
            or close.get("digest") != digest
            or binding.pod_uid is None
        ):
            raise StateConflictError("The deleting Job has no matching retained close authority")
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
        if kind == "native-finalize":
            self.finalize(
                job_ref,
                NativeFinalizeJobRequest.model_validate_json(request_spec),
            )
            return
        if kind == "native-cancel":
            self.cancel(
                job_ref,
                CancelJobRequest(
                    cancel_ref=ref,
                    request_digest=digest,
                    spec=CancelSpec.model_validate_json(request_spec),
                ),
            )
            return
        if kind == "delete":
            self.delete(job_ref, ref, digest)
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
        if kind == "native-runner-credential":
            record = self._store.read_runtime("runner-credential", job_ref, ref)
            if record is None:
                # The credential controller reserves this record before
                # creating its Secret, so absence proves no side effect.
                return True
            RunnerCredentialGrantSnapshot.model_validate_json(_runtime_values(record)["payload"])
            return True
        if kind == "native-runner-start":
            intent = self._store.read_runtime("runner-start", job_ref, ref)
            generation = self._store.read_runtime("runner-generation", job_ref, ref)
            if intent is None:
                # runner-start is retained before launcher RPC.
                return True
            return _runtime_values(intent).get("state") == "succeeded" and generation is not None
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
                if snapshot.state is TransferState.COMPLETED:
                    return True
                if (
                    kind == "transfer-reconcile"
                    and self._startup_reconcile
                    and snapshot.state is TransferState.REGISTERED
                    and snapshot.actual_size_bytes is None
                    and snapshot.actual_sha256 is None
                    and not snapshot.verified
                    and not snapshot.content_available
                    and snapshot.snapshot_ref is None
                ):
                    owner = self.inspect(job_ref)
                    cleanup_state = (
                        str(owner.root["cleanup"]["state"])
                        if isinstance(owner, NativeJobBindingSnapshot)
                        else owner.cleanup.state.value
                    )
                    return (
                        owner.binding_state
                        in {JobBindingState.SUCCEEDED, JobBindingState.FAILED}
                        and cleanup_state == CleanupState.COMPLETE.value
                    )
                return False
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

    def _resume_active_lifecycle_claim(self, job_ref: str, intent: Mapping[str, object]) -> None:
        if intent.get("kind") != "native-runner-start":
            return
        generation_ref = str(intent.get("ref", ""))
        if not generation_ref:
            return
        record = self._store.read_runtime("runner-start", job_ref, generation_ref)
        if record is None or _runtime_values(record).get("state") == "succeeded":
            return
        request_spec = _runtime_values(record).get("requestSpec")
        if not request_spec:
            raise DependencyUnavailableError("native runner start intent is not replayable")
        request = RunnerStartRequest.model_validate_json(request_spec)
        snapshot, binding = self._native_binding(job_ref)
        self._start_runner_unclaimed(job_ref, request, snapshot, binding)

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
        lifecycle = self._lifecycle.inspect(job_ref)
        close = lifecycle.get("close") if lifecycle is not None else None
        if (
            self._runtime_records("finalize", job_ref)
            or self._runtime_records("native-finalize", job_ref)
            or (
                lifecycle is not None
                and lifecycle.get("gate") in {"closing", "closed"}
                and isinstance(close, Mapping)
                and close.get("kind") in {"finalize", "native-finalize"}
            )
        ):
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

    def _native_cancel_output_loss(self, job_ref: str, expected_refs: list[str]) -> bool:
        """Return false only when every requested collect has proven complete."""

        for transfer_ref in expected_refs:
            try:
                snapshot = self._workspace_runtime.inspect_transfer(job_ref, transfer_ref)
            except Exception:
                return True
            if snapshot.state is not TransferState.COMPLETED:
                return True
        return False

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
        current = self._store.read_runtime(
            "cancel", str(_field(record, "job_ref")), str(_field(record, "identity"))
        )
        if current is not None and read_phase(current)[0] == "succeeded":
            return current
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

    def _roles_are_terminal(self, job_ref: str, job_uid: str, pod_uid: str) -> bool:
        pods = self._list_job_pods(job_ref, job_uid)
        pod, selection_reason = _current_pod(pods)
        if (
            pod is None
            or selection_reason is not None
            or _required_text(pod, "metadata", "uid") != pod_uid
        ):
            return False
        job = self._read_job(job_ref)
        if job is None or _required_text(job, "metadata", "uid") != job_uid:
            return False
        role_statuses = [
            status
            for status in (_path(pod, "status", "container_statuses") or ())
            if _field(status, "name", None) in {"agent", "workspace"}
        ]
        roles_terminal = (
            len(role_statuses) == 2
            and {str(_field(status, "name")) for status in role_statuses} == {"agent", "workspace"}
            and all(_path(status, "state", "terminated") is not None for status in role_statuses)
        )
        return roles_terminal and (
            _job_condition_true(job, "Complete")
            or _job_condition_true(job, "Failed")
            or int(_path(job, "status", "succeeded") or 0) > 0
            or int(_path(job, "status", "failed") or 0) > 0
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
        current = self._store.read_runtime(
            "finalize", str(_field(record, "job_ref")), str(_field(record, "identity"))
        )
        if current is not None and _finalize_phase(current) == "succeeded":
            return current
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
            deletion = self._delete_bound_secret(
                grant.job_ref,
                str(grant.job_uid),
                grant_binding=(grant.credential_grant_ref, str(grant.pod_uid)),
            )
            if deletion is not True:
                raise DependencyUnavailableError("Kubernetes Secret absence was not confirmed")
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

    def _bound_secret_annotations(
        self, secret: object, job_ref: str, job_uid: str
    ) -> Mapping[str, object]:
        metadata = _field(secret, "metadata", {})
        labels = _field(metadata, "labels", {})
        annotations = _field(metadata, "annotations", {})
        owner_references = _field(metadata, "owner_references", None)
        if owner_references is None:
            owner_references = _field(metadata, "ownerReferences", ())
        job_owners = [owner for owner in owner_references if _field(owner, "kind", None) == "Job"]
        if (
            not isinstance(labels, Mapping)
            or labels.get("researchcosmos.io/managed-by") != "v2-attempt-runtime"
            or not isinstance(annotations, Mapping)
            or annotations.get("researchcosmos.io/job-uid") != job_uid
            or len(job_owners) != 1
            or _field(job_owners[0], "name", None) != job_ref
            or str(_field(job_owners[0], "uid", "")) != job_uid
        ):
            raise StateConflictError("The credential Secret is not bound to the retained Job UID")
        return annotations

    def _secret_matches_grant_binding(
        self,
        secret: object,
        job_ref: str,
        job_uid: str,
        credential_grant_ref: str,
        pod_uid: str,
    ) -> bool:
        annotations = self._bound_secret_annotations(secret, job_ref, job_uid)
        secret_grant_ref = annotations.get("researchcosmos.io/grant-ref")
        secret_pod_uid = annotations.get("researchcosmos.io/pod-uid")
        if (
            not isinstance(secret_grant_ref, str)
            or not secret_grant_ref
            or not isinstance(secret_pod_uid, str)
            or not secret_pod_uid
        ):
            raise StateConflictError("The credential Secret has no retained grant binding")
        if secret_pod_uid != pod_uid:
            raise StateConflictError("The credential Secret is not bound to the retained Pod UID")
        return secret_grant_ref == credential_grant_ref

    def _delete_bound_secret(
        self,
        job_ref: str,
        job_uid: str,
        *,
        grant_binding: tuple[str, str] | None = None,
    ) -> bool:
        name = credential_secret_name(job_ref)
        secret = self._kube.read_secret(name)
        if secret is None:
            return True
        if grant_binding is None:
            self._bound_secret_annotations(secret, job_ref, job_uid)
        elif not self._secret_matches_grant_binding(
            secret, job_ref, job_uid, grant_binding[0], grant_binding[1]
        ):
            return True
        secret_uid = _required_text(secret, "metadata", "uid")
        if self._kube.delete_secret(name, secret_uid) is not True:
            return False
        return self._kube.read_secret(name) is None

    def _prove_secret_absent(self, job_ref: str, job_uid: str) -> None:
        try:
            deleted = self._delete_bound_secret(job_ref, job_uid)
        except Exception as error:
            raise CredentialDestroyFailedError() from error
        if deleted is not True:
            raise CredentialDestroyFailedError()

    def _prove_native_secret_absent(self, job_ref: str, job_uid: str) -> None:
        name = runner_credential_secret_name(job_ref)
        try:
            secret = self._kube.read_secret(name)
            if secret is None:
                return
            annotations = _path(secret, "metadata", "annotations") or {}
            if (
                _field(annotations, "researchcosmos.io/job-uid", None) != job_uid
                or _field(annotations, "researchcosmos.io/runtime-lane", "native") != "native"
            ):
                raise CredentialDestroyFailedError()
            uid = _required_text(secret, "metadata", "uid")
            if self._kube.delete_secret(name, uid) is not True:
                raise CredentialDestroyFailedError()
            if self._kube.read_secret(name) is not None:
                raise CredentialDestroyFailedError()
        except CredentialDestroyFailedError:
            raise
        except Exception as error:
            raise CredentialDestroyFailedError() from error

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
        credentials.extend(
            {
                "credentialGrantRef": snapshot.root["credentialGrantRef"],
                "state": snapshot.root["state"],
                "secretPresent": snapshot.root["secretPresent"],
                "observedAt": snapshot.root["observedAt"],
            }
            for snapshot in (
                RunnerCredentialGrantSnapshot.model_validate_json(
                    _runtime_values(record)["payload"]
                )
                for record in self._store.list_runtime("runner-credential", job_ref)
            )
        )
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
        material_bindings: Sequence[StartMaterialBinding],
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
        bindings_payload: dict[str, object] = {
            "version": 1,
            "bindings": [item.digest_payload() for item in material_bindings],
        }
        encoded_bindings = canonical_bytes(bindings_payload).decode("utf-8")
        return {
            "identityDigest": digest,
            "jobUid": str(binding.job_uid),
            "podUid": str(binding.pod_uid),
            "grantAudience": grant.audience,
            "credentialSha256": grant.credential_sha256,
            _START_MATERIAL_BINDINGS_KEY: encoded_bindings,
            _START_MATERIAL_BINDINGS_DIGEST_KEY: canonical_digest(bindings_payload),
            "payload": snapshot.model_dump_json(by_alias=True),
        }

    @staticmethod
    def _retained_start_material_bindings(record: object) -> tuple[StartMaterialBinding, ...]:
        values = _runtime_values(record)
        encoded = values.get(_START_MATERIAL_BINDINGS_KEY)
        retained_digest = values.get(_START_MATERIAL_BINDINGS_DIGEST_KEY)
        if not isinstance(encoded, str) or not isinstance(retained_digest, str):
            raise PreconditionFailedError()
        try:
            payload = json.loads(encoded)
            if (
                not isinstance(payload, dict)
                or set(payload) != {"version", "bindings"}
                or type(payload.get("version")) is not int
                or payload.get("version") != 1
                or not isinstance(payload.get("bindings"), list)
                or canonical_bytes(payload).decode("utf-8") != encoded
                or not hmac.compare_digest(canonical_digest(payload), retained_digest)
            ):
                raise PreconditionFailedError()
            bindings: list[StartMaterialBinding] = []
            for item in payload["bindings"]:
                if (
                    not isinstance(item, dict)
                    or set(item)
                    != {
                        "path",
                        "transferRef",
                        "requestDigest",
                        "actualSizeBytes",
                        "actualSha256",
                    }
                    or not isinstance(item.get("path"), str)
                    or not isinstance(item.get("transferRef"), str)
                    or not isinstance(item.get("requestDigest"), str)
                    or type(item.get("actualSizeBytes")) is not int
                    or not isinstance(item.get("actualSha256"), str)
                ):
                    raise PreconditionFailedError()
                bindings.append(
                    StartMaterialBinding(
                        path=item["path"],
                        transfer_ref=item["transferRef"],
                        request_digest=item["requestDigest"],
                        actual_size_bytes=item["actualSizeBytes"],
                        actual_sha256=item["actualSha256"],
                    )
                )
            return tuple(bindings)
        except PreconditionFailedError:
            raise
        except (TypeError, ValueError) as error:
            raise PreconditionFailedError() from error

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

    def _create_or_reconcile_network_policy(
        self, expected: object, record: object
    ) -> object:
        policy_ref = network_policy_ref(str(_field(record, "job_ref")))
        create_error: Exception | None = None
        try:
            self._kube.create_network_policy(expected)
        except Exception as error:
            create_error = error
        policy = self._read_network_policy(policy_ref)
        if policy is None:
            if create_error is not None:
                raise DependencyUnavailableError from create_error
            raise DependencyUnavailableError("Kubernetes did not return the NetworkPolicy")
        _required_text(policy, "metadata", "uid")
        _required_text(policy, "metadata", "resource_version")
        reason = self._network_policy_drift(expected, policy)
        if reason is not None:
            self._mark_indeterminate(record, reason)
            raise DependencyUnavailableError(reason)
        return policy

    def _network_policy_observation(
        self, record: object, observed_at: datetime
    ) -> tuple[NetworkPolicyObservation | None, str | None]:
        spec = _field(record, "spec_payload", {})
        requested_class = _field(spec, "networkClass", None)
        if requested_class is None:
            return None, None
        request_payload = {
            "providerRequestId": str(_field(record, "provider_request_id")),
            "specDigest": str(_field(record, "spec_digest")),
            "spec": dict(spec),
        }
        try:
            request: CreateJobRequest | NativeCreateJobRequest = (
                NativeCreateJobRequest.model_validate(request_payload)
                if _is_native_record(record)
                else CreateJobRequest.model_validate(request_payload)
            )
            expected = self._renderer.render_network_policy(request)
        except (TypeError, ValueError) as error:
            raise DependencyUnavailableError(
                "retained network policy request is invalid"
            ) from error
        policy_ref = network_policy_ref(str(_field(record, "job_ref")))
        policy = self._read_network_policy(policy_ref)
        if policy is None:
            return None, "the retained NetworkPolicy is no longer observable"
        reason = self._network_policy_drift(expected, policy)
        if reason is not None:
            return None, reason
        return (
            NetworkPolicyObservation(
                requested_class=str(requested_class),
                policy_ref=policy_ref,
                policy_uid=UUID(_required_text(policy, "metadata", "uid")),
                resource_version=_required_text(policy, "metadata", "resource_version"),
                spec_digest=network_policy_spec_digest(policy),
                observed_at=observed_at,
            ),
            None,
        )

    @staticmethod
    def _network_policy_drift(expected: object, actual: object) -> str | None:
        expected_name = _required_text(expected, "metadata", "name")
        if _required_text(actual, "metadata", "name") != expected_name:
            return "NetworkPolicy identity changed"
        if _required_text(actual, "metadata", "namespace") != _required_text(
            expected, "metadata", "namespace"
        ):
            return "NetworkPolicy namespace changed"
        for field_name in ("labels", "annotations"):
            expected_values = _path(expected, "metadata", field_name)
            actual_values = _path(actual, "metadata", field_name)
            if not isinstance(expected_values, Mapping) or not isinstance(
                actual_values, Mapping
            ):
                return f"NetworkPolicy {field_name} are not observable"
            if any(actual_values.get(key) != value for key, value in expected_values.items()):
                return f"NetworkPolicy {field_name} changed"
        if not hmac.compare_digest(
            network_policy_spec_digest(expected), network_policy_spec_digest(actual)
        ):
            return "NetworkPolicy spec changed"
        return None

    def _read_network_policy(self, policy_ref: str) -> object | None:
        try:
            return self._kube.read_network_policy(policy_ref)
        except Exception as error:
            if _api_status(error) == 404:
                return None
            raise DependencyUnavailableError from error

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

    def _pod_usage(self, pod: object) -> Mapping[str, Mapping[str, int]]:
        """Best-effort Metrics Server observation for the exact current Pod."""

        reader = getattr(self._kube, "read_pod_usage", None)
        if not callable(reader):
            return {}
        pod_name = _required_text(pod, "metadata", "name")
        try:
            value = reader(pod_name)
        except Exception:
            # Metrics are observational and can legitimately be absent while
            # the Pod or Metrics Server warms up.  Keep nullable fields rather
            # than turning a healthy Job inspection into a 503.
            return {}
        return value if isinstance(value, Mapping) else {}

    def _native_binding_identity(
        self, record: object, job: object, pod: object | None
    ) -> dict[str, Any]:
        pod_uid = _field(record, "pod_uid", None)
        if pod_uid is None and pod is not None:
            pod_uid = _required_text(pod, "metadata", "uid")
        return {
            "runtimeLane": "native",
            "jobRef": str(_field(record, "job_ref")),
            "jobUid": str(
                _field(record, "job_uid", None) or _required_text(job, "metadata", "uid")
            ),
            "podUid": str(pod_uid) if pod_uid is not None else "",
        }

    def _native_control_shutdown_observed(
        self, job_ref: str, binding: Mapping[str, Any]
    ) -> bool:
        """Prove a lost shutdown reply from the exact native Pod incarnation."""

        job = self._read_job(job_ref)
        if job is None or _required_text(job, "metadata", "uid") != str(binding["jobUid"]):
            return False
        matches = [
            pod
            for pod in self._list_job_pods(job_ref, str(binding["jobUid"]))
            if _required_text(pod, "metadata", "uid") == str(binding["podUid"])
        ]
        if len(matches) != 1:
            return False
        status = _named_container_status(matches[0], "control")
        if status is None:
            return False
        state, reason, exit_code, _started, _finished = _container_state(status)
        return (
            state is RoleState.TERMINATED
            and exit_code == 0
            and reason == "Completed"
        )

    def _native_snapshot(
        self,
        record: object,
        job: object,
        pods: Sequence[object],
        *,
        replacement_reason: str | None,
    ) -> NativeJobBindingSnapshot:
        observed_at = self._now()
        network_policy, policy_reason = self._network_policy_observation(record, observed_at)
        if replacement_reason is None:
            replacement_reason = policy_reason
        pod = _current_pod(pods)[0] if replacement_reason is None else None
        spec_payload = _field(record, "spec_payload", {})
        native_spec = _field(spec_payload, "native", {})
        job_ref = str(_field(record, "job_ref"))
        job_uid = str(_field(record, "job_uid", None) or _required_text(job, "metadata", "uid"))
        pod_uid_value = _field(record, "pod_uid", None)
        if pod_uid_value is None and pod is not None:
            pod_uid_value = _required_text(pod, "metadata", "uid")
        pod_uid = str(pod_uid_value) if pod_uid_value is not None else None
        recipe = self._frozen_native_recipe(record)
        recipe_drift = self._native_recipe_drift(job, pod, native_spec, recipe)
        if replacement_reason is None and recipe_drift is not None:
            replacement_reason = recipe_drift
        binding_state, binding_reason = _binding_state(job, pod, replacement_reason)
        if replacement_reason is None and pod is not None:
            statuses = {
                str(_field(item, "name", "")): item
                for item in (_path(pod, "status", "container_statuses") or ())
            }
            if set(statuses).issuperset({"runner", "control"}) and all(
                bool(_field(statuses[name], "ready", False)) for name in ("runner", "control")
            ):
                binding_state = JobBindingState.RUNNING
        generation_records = list(self._store.list_runtime("runner-generation", job_ref))
        latest = (
            max(
                (
                    NativeRunnerGenerationSnapshot.model_validate_json(
                        _runtime_values(item)["payload"]
                    )
                    for item in generation_records
                ),
                key=lambda item: int(item.root["generation"]),
            )
            if generation_records
            else None
        )
        finalize_records = list(self._store.list_runtime("native-finalize", job_ref))
        cancel_records = list(self._store.list_runtime("cancel", job_ref))
        stop_records = list(self._store.list_runtime("runner-stop", job_ref))
        if finalize_records and binding_state not in {
            JobBindingState.SUCCEEDED,
            JobBindingState.FAILED,
        }:
            binding_state = JobBindingState.FINALIZING
            binding_reason = "native capture barrier accepted; platform finalizing"
        usage = self._pod_usage(pod) if pod is not None else {}
        runner = self._native_runner_role(native_spec, pod, latest, usage.get("runner"))
        control = self._native_control_role(pod)
        activation = self._native_activation(
            record,
            pod,
            runner,
            control,
            recipe,
            observed_at,
        )
        capability_activation = self._native_capability_activation(
            record,
            pod,
            latest,
            observed_at,
        )
        post_ack_delivery_loss = _native_post_ack_delivery_loss(activation, latest)
        if post_ack_delivery_loss is not None:
            # A delivery failure before start ACK is deterministic.  The same
            # failure after ACK can destroy live outputs before capture, so a
            # failed Job alone cannot prove a complete terminal observation.
            binding_state = JobBindingState.INDETERMINATE
            binding_reason = (
                "native runtime delivery failed after runner start acknowledgment: "
                f"{post_ack_delivery_loss}"
            )
        post_ack_runtime_loss = _native_post_ack_runtime_loss(
            binding_state,
            binding_reason,
            latest,
        )
        if post_ack_runtime_loss is not None:
            # A native Job must remain alive after the child exits so RC can
            # capture the workspace before finalize.  Therefore a failed Job
            # after start ACK, with no capture barrier, is loss of the runtime
            # substrate rather than an ordinary runner exit.  Preserve that
            # uncertainty instead of leaving the durable generation "running"
            # forever or reporting a deterministic failure.
            binding_state = JobBindingState.INDETERMINATE
            binding_reason = (
                "native runtime disappeared after runner start acknowledgment: "
                f"{post_ack_runtime_loss}"
            )
        cancel_action = action_snapshot(cancel_records, "cancelRef")
        cancel_output_loss_possible = False
        if cancel_records:
            cancel_state, cancel_output_loss_possible, resume_from = read_phase(
                cancel_records[-1]
            )
            if cancel_state == "succeeded":
                binding_state = JobBindingState.CANCELED
                binding_reason = "provider cancellation completed"
            elif cancel_state == "indeterminate" and resume_from is None:
                binding_state = JobBindingState.INDETERMINATE
                binding_reason = "provider cancellation is indeterminate"
            else:
                binding_state = JobBindingState.CANCELING
                binding_reason = "provider cancellation is in progress"
        created_at = _as_datetime(_field(record, "created_at", None), observed_at)
        hard_seconds = int(
            _optional_path_text(
                job, "metadata", "annotations", "researchcosmos.io/hard-deadline-seconds"
            )
            or int(_path(job, "spec", "active_deadline_seconds") or 1)
        )
        deadline_payload = {
            "runnerDeadlineSeconds": int(_field(native_spec, "runnerDeadlineSeconds")),
            "softTimerStartedAt": latest.root["softTimerStartedAt"] if latest else None,
            "softDeadlineAt": latest.root["softDeadlineAt"] if latest else None,
            "hardDeadlineSeconds": hard_seconds,
            "hardDeadlineAt": (created_at + timedelta(seconds=hard_seconds)).isoformat(),
            "hardDeadlineTriggeredAt": (
                _job_finished_at(job).isoformat()
                if _job_condition_reason(job, "Failed") == "DeadlineExceeded"
                and _job_finished_at(job) is not None
                else None
            ),
            "policyDigest": canonical_digest(
                {
                    "runnerDeadlineSeconds": int(_field(native_spec, "runnerDeadlineSeconds")),
                    "hardDeadlineSeconds": hard_seconds,
                }
            ),
        }
        operation_states = [
            (
                str(_field(item, "identity")),
                _validated_runtime_state(item, "operation")[0],
            )
            for item in self._store.list_runtime("operation", job_ref)
        ]
        transfer_states = [
            (
                str(_field(item, "identity")),
                *_validated_runtime_state(item, "transfer"),
            )
            for item in self._store.list_runtime("transfer", job_ref)
        ]
        grants = [
            RunnerCredentialGrantSnapshot.model_validate_json(_runtime_values(item)["payload"])
            for item in self._store.list_runtime("runner-credential", job_ref)
        ]
        cleanup = {
            "state": "complete"
            if binding_state
            in {
                JobBindingState.SUCCEEDED,
                JobBindingState.FAILED,
                JobBindingState.CANCELED,
            }
            else (
                "indeterminate"
                if cancel_records and binding_state is JobBindingState.INDETERMINATE
                else "pending"
            ),
            "reason": (
                binding_reason
                if cancel_records and binding_state is JobBindingState.INDETERMINATE
                else None
            ),
            "observedAt": observed_at.isoformat(),
        }
        accelerator = _field(_field(native_spec, "resources", {}), "accelerator", {})
        gpu_count = int(_field(accelerator, "count", 0))
        payload = {
            "runtimeLane": "native",
            "jobRef": job_ref,
            "providerHandle": job_ref,
            "providerRequestId": str(_field(record, "provider_request_id")),
            "subjectRef": str(_field(spec_payload, "subjectRef")),
            "runtimePlanDigest": str(_field(spec_payload, "runtimePlanDigest")),
            "specDigest": str(_field(record, "spec_digest")),
            "jobUid": job_uid,
            "podUid": pod_uid,
            "resourceVersion": _optional_path_text(job, "metadata", "resource_version"),
            "nodeName": _optional_path_text(pod, "spec", "node_name") if pod else None,
            "bindingState": binding_state.value,
            "bindingReason": binding_reason,
            "observedPodCount": min(len(pods), 1),
            "podIncarnations": [
                item.model_dump(mode="json", by_alias=True)
                for item in _pod_incarnations(record, pods, observed_at)[-1:]
            ],
            "createdAt": created_at.isoformat(),
            "updatedAt": _as_datetime(_field(record, "updated_at", None), observed_at).isoformat(),
            "startedAt": (
                _as_optional_datetime(_path(pod, "status", "start_time")).isoformat()
                if pod is not None and _as_optional_datetime(_path(pod, "status", "start_time"))
                else None
            ),
            "finishedAt": _job_finished_at(job).isoformat() if _job_finished_at(job) else None,
            "observedAt": observed_at.isoformat(),
            "networkPolicy": (
                network_policy.model_dump(mode="json", by_alias=True)
                if network_policy is not None
                else None
            ),
            "runner": runner,
            "control": control,
            "latestRunnerGeneration": latest.root if latest else None,
            "recipeActivation": activation,
            "capabilityActivation": capability_activation,
            "deadline": deadline_payload,
            "activeOperationRefs": sorted(
                ref for ref, state in operation_states if state in _OPERATION_ACTIVE_STATES
            ),
            "terminalOperationRefs": sorted(
                ref for ref, state in operation_states if state in _OPERATION_TERMINAL_STATES
            ),
            "credentialObservations": [
                {
                    "credentialGrantRef": item.root["credentialGrantRef"],
                    "state": item.root["state"],
                    "secretPresent": item.root["secretPresent"],
                    "observedAt": item.root["observedAt"],
                }
                for item in grants
            ],
            "transferObservations": [
                {"transferRef": ref, "state": state, "observedAt": timestamp.isoformat()}
                for ref, state, timestamp in sorted(transfer_states)
            ],
            "runnerStopAction": action_snapshot(stop_records, "stopRef").model_dump(
                mode="json", by_alias=True
            ),
            "finalizeAction": action_snapshot(finalize_records, "finalizeRef").model_dump(
                mode="json", by_alias=True
            ),
            "cancelAction": cancel_action.model_dump(mode="json", by_alias=True),
            "deleteAction": _not_requested_action().model_dump(mode="json", by_alias=True),
            "outputLossPossible": post_ack_delivery_loss is not None
            or post_ack_runtime_loss is not None
            or replacement_reason is not None
            or deadline_payload["hardDeadlineTriggeredAt"] is not None
            or cancel_output_loss_possible,
            "cleanup": cleanup,
            "gpuRelease": {
                "state": "complete"
                if gpu_count
                and binding_state in {JobBindingState.SUCCEEDED, JobBindingState.FAILED}
                else ("pending" if gpu_count else "not_required"),
                "reason": None,
                "observedAt": observed_at.isoformat(),
            },
        }
        return NativeJobBindingSnapshot.model_validate(payload)

    def _native_runner_role(
        self,
        native_spec: Mapping[str, Any],
        pod: object | None,
        latest: NativeRunnerGenerationSnapshot | None,
        observed: Mapping[str, int] | None,
    ) -> dict[str, Any] | None:
        status = _named_container_status(pod, "runner") if pod is not None else None
        if status is None:
            return None
        state, reason, _exit, started, finished = _container_state(status)
        observation = (
            latest.root["runnerObservation"] if latest else _initial_runner_observation(self._now())
        )
        resources = _field(native_spec, "resources", {})
        return {
            "containerId": _optional_text(status, "container_id"),
            "imageId": _optional_text(status, "image_id"),
            "state": state.value,
            "ready": bool(_field(status, "ready", False)),
            "restartCount": int(_field(status, "restart_count", 0)),
            "reason": reason,
            "startedAt": started.isoformat() if started else None,
            "finishedAt": finished.isoformat() if finished else None,
            "requested": dict(resources),
            "observed": {
                "cpuMillis": None if observed is None else observed.get("cpuMillis"),
                "memoryMiB": None if observed is None else observed.get("memoryMiB"),
                "peakEphemeralStorageMiB": None,
                # The Pod request proves neither assignment nor utilization.
                # Device facts stay not_reported until a device-scoped source
                # is joined to this exact Pod UID.
                "acceleratorKind": None,
                "acceleratorCount": None,
            },
            "observation": observation,
        }

    @staticmethod
    def _native_control_role(pod: object | None) -> dict[str, Any] | None:
        status = _named_container_status(pod, "control") if pod is not None else None
        if status is None:
            return None
        state, reason, _exit, started, finished = _container_state(status)
        return {
            "containerId": _optional_text(status, "container_id"),
            "imageId": _optional_text(status, "image_id"),
            "state": state.value,
            "ready": bool(_field(status, "ready", False)),
            "restartCount": int(_field(status, "restart_count", 0)),
            "reason": reason,
            "startedAt": started.isoformat() if started else None,
            "finishedAt": finished.isoformat() if finished else None,
        }

    def _native_activation(
        self,
        record: object,
        pod: object | None,
        runner: Mapping[str, Any] | None,
        control: Mapping[str, Any] | None,
        recipe: ResolvedRuntimeRecipe,
        observed_at: datetime,
    ) -> dict[str, Any] | None:
        if pod is None:
            return None
        node_name = _optional_path_text(pod, "spec", "node_name")
        if node_name is None:
            # The Pod exists but the scheduler has not assigned it yet.  The
            # binding itself exposes nodeName=null; no activation receipt
            # exists until KCS can bind it to a concrete node.
            return None
        spec_payload = _field(record, "spec_payload", {})
        native_spec = _field(spec_payload, "native", {})
        resources = dict(_field(native_spec, "resources", {}))
        delivery = recipe.root["delivery"]
        # Activation is a retained delivery fact, not a live readiness gauge.
        # Once both runtime roles have started, a normal runner exit/finalize
        # must not make the exact recipe receipt regress from ``active`` back
        # to ``pending``. Delivery failures still take precedence below.
        active = bool(
            runner
            and control
            and runner.get("startedAt")
            and control.get("startedAt")
        )
        failure = _native_delivery_failure(pod)
        state = "failed" if failure != "none" else ("active" if active else "pending")
        if delivery["mode"] == "assembled":
            delivery_receipt = {
                "mode": "assembled",
                "transport": "imageVolume",
                "environmentImageRef": delivery["environmentImageDigest"],
                "environmentImageId": runner["imageId"] if runner else None,
                "platformImageVolumeRef": delivery["platformImageVolumeDigest"],
                "platformImageVolumeId": None,
                "runnerImageVolumeRef": delivery["runnerImageVolumeDigest"],
                "runnerImageVolumeId": None,
                "controlImageRef": delivery["controlImageDigest"],
                "controlImageId": control["imageId"] if control else None,
            }
        else:
            delivery_receipt = {
                "mode": "prebuilt",
                "prebuiltImageRef": delivery["prebuiltImageDigest"],
                "prebuiltImageId": runner["imageId"] if runner else None,
                "platformImageVolumeRef": delivery["platformImageVolumeDigest"],
                "platformImageVolumeId": None,
                "controlImageRef": delivery["controlImageDigest"],
                "controlImageId": control["imageId"] if control else None,
            }
        return {
            "activationRef": f"activation-{str(_field(record, 'job_ref'))}",
            "assemblyDigest": str(_field(native_spec, "assemblyDigest")),
            "recipeRef": recipe.root["recipeRef"],
            "recipeDigest": recipe.root["recipeDigest"],
            "deliveryReceipt": delivery_receipt,
            "imageFilesystem": recipe.root["imageFilesystem"],
            "state": state,
            "deliveryFailure": failure,
            "replacementPodCreated": False,
            "jobUid": str(_field(record, "job_uid")),
            "podUid": _required_text(pod, "metadata", "uid"),
            "nodeName": node_name,
            "requestedResources": resources,
            "admittedResources": self._native_admitted_resources(pod),
            "observedResources": (
                runner["observed"]
                if runner
                else {
                    "cpuMillis": None,
                    "memoryMiB": None,
                    "peakEphemeralStorageMiB": None,
                    "acceleratorKind": None,
                    "acceleratorCount": None,
                }
            ),
            "activatedAt": (
                runner["startedAt"] if active and runner and runner["startedAt"] else None
            ),
            "observedAt": observed_at.isoformat(),
        }

    @staticmethod
    def _native_admitted_resources(pod: object) -> dict[str, object]:
        containers = tuple(_path(pod, "spec", "containers") or ())

        def total(section: str, resource: str) -> int:
            value = sum(
                (
                    parse_quantity(
                        str(
                            _field(
                                _field(_field(item, "resources", {}), section, {}),
                                resource,
                                "0",
                            )
                        )
                    )
                    for item in containers
                ),
                start=parse_quantity("0"),
            )
            parsed = int(value * 1000) if resource == "cpu" else int(value / (1024 * 1024))
            if parsed < 1:
                raise DependencyUnavailableError(f"native Pod has no admitted {section} {resource}")
            return parsed

        gpu_count = sum(
            int(
                _field(
                    _field(_field(item, "resources", {}), "requests", {}),
                    "nvidia.com/gpu",
                    0,
                )
            )
            for item in containers
        )
        return {
            "cpuRequestMillis": total("requests", "cpu"),
            "cpuLimitMillis": total("limits", "cpu"),
            "memoryRequestMiB": total("requests", "memory"),
            "memoryLimitMiB": total("limits", "memory"),
            "ephemeralStorageRequestMiB": total("requests", "ephemeral-storage"),
            "ephemeralStorageLimitMiB": total("limits", "ephemeral-storage"),
            "accelerator": {
                "kind": "nvidia-gpu" if gpu_count else "none",
                "count": gpu_count,
            },
        }

    def _native_recipe_drift(
        self,
        job: object,
        pod: object | None,
        native_spec: Mapping[str, Any],
        recipe: ResolvedRuntimeRecipe,
    ) -> str | None:
        annotations = _path(job, "metadata", "annotations") or {}
        expected_annotations = {
            "researchcosmos.io/assembly-digest": str(native_spec["assemblyDigest"]),
            "researchcosmos.io/recipe-ref": str(recipe.root["recipeRef"]),
            "researchcosmos.io/recipe-digest": str(recipe.root["recipeDigest"]),
        }
        if not isinstance(annotations, Mapping) or any(
            annotations.get(key) != value for key, value in expected_annotations.items()
        ):
            return "Job annotations differ from the frozen native recipe"
        if pod is None:
            return None
        containers = {
            str(_field(item, "name", "")): item for item in (_path(pod, "spec", "containers") or ())
        }
        if set(containers) != {"runner", "control"}:
            return "Pod container roles differ from the frozen native recipe"
        delivery = recipe.root["delivery"]
        runner_image = (
            delivery["environmentImageDigest"]
            if delivery["mode"] == "assembled"
            else delivery["prebuiltImageDigest"]
        )
        if (
            _field(containers["runner"], "image", None) != runner_image
            or list(_field(containers["runner"], "command", ()) or ())
            != list(recipe.root["launcherCommand"])
            or _field(containers["control"], "image", None) != delivery["controlImageDigest"]
            or list(_field(containers["control"], "command", ()) or ())
            != list(recipe.root["controlCommand"])
        ):
            return "Pod images or commands differ from the frozen native recipe"
        runner_mounts = {
            (str(_field(item, "mount_path", "")), bool(_field(item, "read_only", False)))
            for item in (_field(containers["runner"], "volume_mounts", ()) or ())
        }
        expected_mounts = {
            (str(item["mountPath"]), bool(item["readOnly"])) for item in recipe.root["mounts"]
        }
        if self._renderer.platform_ca_mount_enabled:
            expected_mounts.add((PLATFORM_CA_MOUNT_PATH, True))
        activation_plan = self._native_activation_plan_for_spec(native_spec)
        if activation_plan is not None:
            expected_mounts.update(
                (str(item["targetPath"]), True) for item in activation_plan.root["mounts"]
            )
        if runner_mounts != expected_mounts:
            return "Pod runner mounts differ from the frozen native recipe"
        volumes = {
            str(_field(item, "name", "")): item for item in (_path(pod, "spec", "volumes") or ())
        }
        platform_ref = _path(volumes.get("rc-platform"), "image", "reference")
        runner_ref = _path(volumes.get("rc-runner"), "image", "reference")
        if platform_ref != delivery["platformImageVolumeDigest"] or (
            delivery["mode"] == "assembled" and runner_ref != delivery["runnerImageVolumeDigest"]
        ):
            return "Pod image volumes differ from the frozen native recipe"
        if delivery["mode"] == "prebuilt" and "rc-runner" in volumes:
            return "prebuilt native Pod unexpectedly mounts a runner image volume"
        if activation_plan is not None:
            if (
                annotations.get("researchcosmos.io/capability-plan-ref")
                != activation_plan.root["planRef"]
                or annotations.get("researchcosmos.io/capability-plan-digest")
                != activation_plan.root["planDigest"]
            ):
                return "Job annotations differ from the frozen capability activation plan"
            for mount in activation_plan.root["mounts"]:
                volume = volumes.get(activation_volume_name(mount))
                if _path(volume, "image", "reference") != mount["imageVolumeDigest"]:
                    return "Pod capability ImageVolume differs from the frozen activation plan"
        return None

    def _native_activation_plan_for_spec(
        self, native_spec: Mapping[str, Any]
    ) -> CapabilityActivationPlan | None:
        selection = _field(native_spec, "capabilityActivation", None)
        if not isinstance(selection, Mapping):
            return None
        return self.capability_activation_plan(
            str(selection["planRef"]), str(selection["planDigest"])
        )

    def _native_capability_activation(
        self,
        record: object,
        pod: object | None,
        latest: NativeRunnerGenerationSnapshot | None,
        observed_at: datetime,
    ) -> dict[str, Any] | None:
        native_spec = _field(_field(record, "spec_payload", {}), "native", {})
        plan = self._native_activation_plan_for_spec(native_spec)
        if plan is None or pod is None:
            return None
        volumes = {
            str(_field(item, "name", "")): item for item in (_path(pod, "spec", "volumes") or ())
        }
        runner = next(
            (
                item
                for item in (_path(pod, "spec", "containers") or ())
                if _field(item, "name", "") == "runner"
            ),
            None,
        )
        runner_mounts = {
            str(_field(item, "mount_path", "")): item
            for item in (_field(runner, "volume_mounts", ()) or ())
        }
        observed_mounts: dict[str, dict[str, Any]] = {}
        for expected in plan.root["mounts"]:
            target = str(expected["targetPath"])
            volume = volumes.get(activation_volume_name(expected))
            mount = runner_mounts.get(target)
            reference = _path(volume, "image", "reference")
            observed_mounts[target] = {
                "imageVolumeRef": reference or str(expected["imageVolumeDigest"]),
                # PodStatus has no CRI ID for an ImageVolume. The exact digest
                # remains observable in PodSpec; keep imageVolumeId nullable.
                "imageVolumeId": None,
                "verified": (
                    reference == expected["imageVolumeDigest"]
                    and mount is not None
                    and bool(_field(mount, "read_only", False))
                ),
            }
        generation = int(latest.root["generation"]) if latest is not None else 1
        return capability_activation_receipt(
            plan,
            job_uid=str(_field(record, "job_uid")),
            pod_uid=_required_text(pod, "metadata", "uid"),
            generation=generation,
            observed_mounts=observed_mounts,
            observed_at=observed_at,
        ).wire()

    def _native_missing_job_snapshot(self, record: object) -> NativeJobBindingSnapshot:
        # A native Job that disappeared after UID assignment is intentionally
        # represented as indeterminate with output loss.  Reuse a minimal
        # synthetic Job observation so the canonical snapshot stays complete.
        job = {
            "metadata": {
                "uid": str(_field(record, "job_uid")),
                "resource_version": None,
                "annotations": {"researchcosmos.io/hard-deadline-seconds": "1"},
            },
            "spec": {"active_deadline_seconds": 1},
            "status": {"conditions": []},
        }
        return self._native_snapshot(
            record,
            job,
            (),
            replacement_reason="the retained native Job is no longer observable",
        )

    def _delete_job(self, job_ref: str, job_uid: str) -> None:
        try:
            self._kube.delete_job(job_ref, job_uid)
        except Exception as error:
            if _api_status(error) != 404:
                raise DependencyUnavailableError from error

    def _delete_network_policy(self, record: object) -> None:
        spec = _field(record, "spec_payload", {})
        if _field(spec, "networkClass", None) is None:
            return
        policy_ref = network_policy_ref(str(_field(record, "job_ref")))
        policy = self._read_network_policy(policy_ref)
        if policy is None:
            return
        observation, reason = self._network_policy_observation(record, self._now())
        if reason is not None or observation is None:
            raise DependencyUnavailableError(reason or "NetworkPolicy identity is unavailable")
        try:
            self._kube.delete_network_policy(policy_ref, str(observation.policy_uid))
        except Exception as error:
            if _api_status(error) != 404:
                raise DependencyUnavailableError from error
        for attempt in range(self._delete_poll_attempts):
            if self._read_network_policy(policy_ref) is None:
                return
            if attempt + 1 < self._delete_poll_attempts:
                self._sleeper(self._delete_poll_interval_seconds)
        raise DependencyTimeoutError("Kubernetes has not confirmed NetworkPolicy deletion")

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
        network_policy, policy_reason = self._network_policy_observation(record, observed_at)
        if replacement_reason is None:
            replacement_reason = policy_reason
        pod = _current_pod(pods)[0] if replacement_reason is None else None
        binding_state, binding_reason = _binding_state(job, pod, replacement_reason)
        workload_terminal = binding_state in {
            JobBindingState.SUCCEEDED,
            JobBindingState.FAILED,
        }
        spec_payload = _field(record, "spec_payload", {})
        usage = self._pod_usage(pod) if pod is not None else {}
        agent = (
            _role_snapshot(spec_payload, pod, "agent", usage.get("agent"))
            if pod is not None
            else None
        )
        workspace = (
            _role_snapshot(spec_payload, pod, "workspace", usage.get("workspace"))
            if pod is not None
            else None
        )
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
        current_pod_uid = str(pod_uid) if pod_uid is not None else None
        grants = [
            self._grant_snapshot(item)
            for item in self._runtime_records("credential", str(_field(record, "job_ref")))
            if _runtime_values(item).get("podUid") == current_pod_uid
        ]
        generations = [
            self._generation_snapshot(item, replayed=False)
            for item in self._runtime_records("generation", str(_field(record, "job_ref")))
            if _runtime_values(item).get("podUid") == current_pod_uid
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
            if _runtime_values(item).get("podUid") == current_pod_uid
        ]
        transfers = [
            (
                str(_field(item, "identity")),
                *_validated_runtime_state(
                    _validate_runtime_binding(item, job_uid, str(pod_uid)), "transfer"
                ),
            )
            for item in self._runtime_records("transfer", runtime_job_ref)
            if _runtime_values(item).get("podUid") == current_pod_uid
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
            pod_incarnations=_pod_incarnations(record, pods, observed_at),
            created_at=created_at,
            updated_at=updated_at,
            started_at=started_at,
            finished_at=finished_at,
            observed_at=observed_at,
            network_policy=network_policy,
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
        network_policy, _ = self._network_policy_observation(record, observed_at)
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
            pod_incarnations=_pod_incarnations(record, (), observed_at),
            created_at=created_at,
            updated_at=_as_datetime(_field(record, "updated_at", None), observed_at),
            started_at=None,
            finished_at=None,
            observed_at=observed_at,
            network_policy=network_policy,
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


def _stable_runtime_assembly(value: Mapping[str, Any]) -> dict[str, Any]:
    """Remove observations while retaining the exact digest-bearing assembly."""

    stable = json.loads(json.dumps(value))
    stable.pop("observedAt", None)
    recipe = stable.get("recipe")
    if isinstance(recipe, dict):
        recipe.pop("observedAt", None)
    return stable


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


def _current_pod(pods: Sequence[object]) -> tuple[object | None, str | None]:
    """Select the one writable incarnation while retaining terminal history."""

    active = [
        pod
        for pod in pods
        if str(_path(pod, "status", "phase") or "") not in {"Succeeded", "Failed"}
        and _path(pod, "metadata", "deletion_timestamp") is None
    ]
    if len(active) > 1:
        return None, "multiple active Pod identities observed for one Job"
    if len(active) == 1:
        return active[0], None
    if not pods:
        return None, None

    def order(pod: object) -> tuple[str, str]:
        created = _path(pod, "metadata", "creation_timestamp")
        return (str(created or ""), _required_text(pod, "metadata", "uid"))

    return max(pods, key=order), None


def _pod_incarnation(pod: object, observed_at: datetime) -> PodIncarnationSnapshot:
    phase = str(_path(pod, "status", "phase") or "")
    state = {
        "Pending": PodIncarnationState.PENDING,
        "Running": PodIncarnationState.RUNNING,
        "Succeeded": PodIncarnationState.SUCCEEDED,
        "Failed": PodIncarnationState.FAILED,
    }.get(phase, PodIncarnationState.UNKNOWN)
    reason = _optional_path_text(pod, "status", "reason")
    finished: list[datetime] = []
    for status in _path(pod, "status", "container_statuses") or ():
        value = _path(status, "state", "terminated", "finished_at")
        parsed = _as_optional_datetime(value)
        if parsed is not None:
            finished.append(parsed)
    return PodIncarnationSnapshot(
        pod_name=_required_text(pod, "metadata", "name"),
        pod_uid=UUID(_required_text(pod, "metadata", "uid")),
        node_name=_optional_path_text(pod, "spec", "node_name"),
        state=state,
        reason=reason,
        started_at=_as_optional_datetime(_path(pod, "status", "start_time")),
        finished_at=max(finished) if finished else None,
        observed_at=observed_at,
    )


def _pod_incarnations(
    record: object,
    pods: Sequence[object],
    observed_at: datetime,
) -> list[PodIncarnationSnapshot]:
    retained: dict[str, PodIncarnationSnapshot] = {}
    encoded = _field(record, "pod_incarnations_json", None)
    if isinstance(encoded, str):
        try:
            values = json.loads(encoded)
            if not isinstance(values, list):
                raise ValueError
            for value in values:
                if isinstance(value, dict) and set(value) == {"podUid"}:
                    continue  # legacy/store-only binding; live Pod fills the observation
                snapshot = PodIncarnationSnapshot.model_validate(value)
                retained[str(snapshot.pod_uid)] = snapshot
        except (TypeError, ValueError):
            raise DependencyUnavailableError("Pod incarnation history is malformed") from None
    for pod in pods:
        snapshot = _pod_incarnation(pod, observed_at)
        retained[str(snapshot.pod_uid)] = snapshot
    return sorted(
        retained.values(),
        key=lambda item: (
            item.started_at.isoformat() if item.started_at is not None else "",
            str(item.pod_uid),
        ),
    )


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


def _is_native_record(record: object) -> bool:
    spec = _field(record, "spec_payload", {})
    return isinstance(spec, Mapping) and isinstance(spec.get("native"), Mapping)


def _workspace_gpu(record: object) -> int:
    spec = _field(record, "spec_payload", {})
    native = _field(spec, "native", None)
    if isinstance(native, Mapping):
        resources = _field(native, "resources", {})
        accelerator = _field(resources, "accelerator", {})
        return int(_field(accelerator, "count", 0))
    workspace = _field(spec, "workspace", {})
    resources = _field(workspace, "resources", {})
    return int(_field(resources, "gpu", 0))


def _named_container_status(pod: object | None, name: str) -> object | None:
    if pod is None:
        return None
    return next(
        (
            item
            for item in (_path(pod, "status", "container_statuses") or ())
            if _field(item, "name", None) == name
        ),
        None,
    )


def _initial_runner_observation(observed_at: datetime) -> dict[str, object]:
    payload: dict[str, object] = {
        "state": "starting",
        "sequence": 1,
        "childPid": None,
        "processExit": {"kind": "not_observed", "exitCode": None, "signal": None},
        "stopCause": "none",
        "protocolTerminal": {
            "observed": False,
            "eventKind": None,
            "stopReason": None,
            "errorCode": None,
        },
        "childStartedAt": None,
        "childFinishedAt": None,
        "observedAt": observed_at.isoformat(),
    }
    payload["stateDigest"] = canonical_digest(payload)
    return payload


def _native_generation(binding: NativeJobBindingSnapshot) -> int:
    return _native_generation_from_values(binding.root)


def _native_generation_from_values(values: Mapping[str, Any]) -> int:
    generation = values.get("latestRunnerGeneration")
    if not isinstance(generation, Mapping):
        raise StateConflictError("native runner generation is not active")
    value = generation.get("generation")
    if type(value) is not int or value < 1:
        raise StateConflictError("native runner generation identity is invalid")
    return value


def _native_delivery_failure(pod: object) -> str:
    reason = str(_path(pod, "status", "reason") or "").casefold()
    message = str(_path(pod, "status", "message") or "").casefold()
    combined = f"{reason} {message}"
    if "evict" in combined:
        return "emptydir_evicted"
    if "enospc" in combined or "no space left" in combined:
        return "enospc"
    for status in _path(pod, "status", "container_statuses") or ():
        waiting_reason = str(_path(status, "state", "waiting", "reason") or "")
        if waiting_reason in {"ImagePullBackOff", "ErrImagePull"}:
            return "image_pull"
    return "none"


def _native_post_ack_delivery_loss(
    activation: Mapping[str, Any] | None,
    generation: NativeRunnerGenerationSnapshot | None,
) -> str | None:
    """Classify destructive delivery loss only after runner start ACK."""

    if activation is None or generation is None:
        return None
    failure = str(activation.get("deliveryFailure", "none"))
    if failure not in {"enospc", "emptydir_evicted"}:
        return None
    return failure if generation.root.get("credentialAcknowledgedAt") is not None else None


def _native_post_ack_runtime_loss(
    binding_state: JobBindingState,
    binding_reason: str | None,
    generation: NativeRunnerGenerationSnapshot | None,
) -> str | None:
    """Classify a failed native Job after start ACK as possible output loss."""

    if binding_state is not JobBindingState.FAILED or generation is None:
        return None
    if generation.root.get("credentialAcknowledgedAt") is None:
        return None
    return binding_reason or "job_failed"


def _prometheus_counter_lines(
    metric: str,
    label: str,
    values: Mapping[str, int],
) -> list[str]:
    return [f'{metric}{{{label}="{value}"}} {count}' for value, count in sorted(values.items())]


def _binding_state(
    job: object,
    pod: object | None,
    replacement_reason: str | None,
) -> tuple[JobBindingState, str | None]:
    if replacement_reason is not None:
        return JobBindingState.INDETERMINATE, replacement_reason
    if _job_condition_true(job, "Failed"):
        return JobBindingState.FAILED, _job_condition_reason(job, "Failed")
    if _job_condition_true(job, "Complete") or int(_path(job, "status", "succeeded") or 0) > 0:
        return JobBindingState.SUCCEEDED, None
    if pod is None:
        if int(_path(job, "status", "failed") or 0) > 0:
            return JobBindingState.FAILED, None
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
    if (
        int(_path(job, "status", "failed") or 0) > 0
        and int(_path(job, "status", "active") or 0) == 0
    ):
        return JobBindingState.FAILED, None
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
    observed: Mapping[str, int] | None = None,
) -> AgentRoleSnapshot | None: ...


@overload
def _role_snapshot(
    spec_payload: object,
    pod: object,
    role: Literal["workspace"],
    observed: Mapping[str, int] | None = None,
) -> WorkspaceRoleSnapshot | None: ...


def _role_snapshot(
    spec_payload: object,
    pod: object,
    role: Literal["agent", "workspace"],
    observed: Mapping[str, int] | None = None,
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
                cpu_millis=(None if observed is None else observed.get("cpuMillis")),
                memory_mib=(None if observed is None else observed.get("memoryMiB")),
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
            cpu_millis=(None if observed is None else observed.get("cpuMillis")),
            memory_mib=(None if observed is None else observed.get("memoryMiB")),
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
        "network_policy_absent": 5,
        "owner_records_deleted": 6,
        "complete": 7,
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
        "network_policy_absent": 5,
        "owner_records_deleted": 6,
        "complete": 7,
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
