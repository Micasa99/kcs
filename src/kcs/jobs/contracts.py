"""Strict Pydantic contracts for the first executable KCS V2 Job journey."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from .canonical import validate_request_digest
from .policy import (
    validate_casefold_unique_paths,
    validate_immutable_image,
    validate_opaque_ref,
    validate_runtime_environment,
    validate_safe_relative_path,
)


def _to_camel(value: str) -> str:
    first, *rest = value.split("_")
    alias = first + "".join(part.capitalize() for part in rest)
    return alias.replace("Mib", "MiB").replace("Gib", "GiB")


class ContractModel(BaseModel):
    """Immutable JSON contract with camelCase wire aliases and no extension fields."""

    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )


OpaqueRef = Annotated[
    StrictStr,
    Field(min_length=1, max_length=256, pattern=r"^[^\u0000-\u001f\u007f]+$"),
    AfterValidator(validate_opaque_ref),
]
Sha256 = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
ImmutableImage = Annotated[
    StrictStr,
    Field(pattern=r"^.+@sha256:[0-9a-f]{64}$"),
    AfterValidator(validate_immutable_image),
]
SafeRelativePath = Annotated[
    StrictStr,
    Field(min_length=1),
    AfterValidator(validate_safe_relative_path),
]
Timestamp = AwareDatetime
KubernetesUid = UUID
OpaqueCursor = Annotated[
    StrictStr,
    Field(min_length=1, max_length=4096, pattern=r"^[A-Za-z0-9_-]+$"),
]
OpaquePageToken = OpaqueCursor
RuntimeEnvName = Annotated[
    StrictStr,
    Field(
        max_length=64,
        pattern=r"^(LANG|LC_ALL|TZ|HTTP_PROXY|HTTPS_PROXY|NO_PROXY|RC_PUBLIC_RUNTIME_BASE_URL)$",
    ),
]
RuntimeEnvValue = Annotated[StrictStr, Field(max_length=2048)]
Environment = Annotated[
    dict[RuntimeEnvName, RuntimeEnvValue],
    Field(max_length=32),
    AfterValidator(validate_runtime_environment),
]


class AgentResources(ContractModel):
    cpu_millis: Annotated[StrictInt, Field(ge=1, le=8000)] = 1000
    memory_mib: Annotated[StrictInt, Field(ge=1, le=32768)] = 2048


class WorkspaceResources(ContractModel):
    cpu_millis: Annotated[StrictInt, Field(ge=1, le=64000)] = 2000
    memory_mib: Annotated[StrictInt, Field(ge=1, le=262144)] = 8192
    gpu: Annotated[StrictInt, Field(ge=0, le=8)] = 0


class AgentSpec(ContractModel):
    image: ImmutableImage
    command: tuple[Literal["/opt/kcs/agent-supervisor"]]
    resources: AgentResources = Field(default_factory=AgentResources)
    runtime_env: Environment = Field(default_factory=dict)


class WorkspaceSpec(ContractModel):
    image: ImmutableImage
    command: tuple[Literal["/opt/kcs/workspace-sidecar"]]
    resources: WorkspaceResources = Field(default_factory=WorkspaceResources)
    runtime_env: Environment = Field(default_factory=dict)


class SharedWorkspaceSpec(ContractModel):
    kind: Literal["ephemeral"]
    mount_path: Literal["/workspace"]
    size_limit_gib: Annotated[StrictInt, Field(ge=1, le=100)]


class NodeSelector(ContractModel):
    pool: Literal["gpu"] = Field(alias="researchcosmos.io/pool")

    def as_mapping(self) -> dict[str, str]:
        return {"researchcosmos.io/pool": self.pool}


class JobSpec(ContractModel):
    subject_ref: OpaqueRef
    runtime_plan_digest: Sha256
    agent: AgentSpec
    workspace: WorkspaceSpec
    shared_workspace: SharedWorkspaceSpec
    node_selector: NodeSelector
    active_deadline_seconds: Annotated[StrictInt, Field(ge=1, le=86400)]

    def digest_payload(self) -> dict[str, object]:
        """Return exactly the fields present on the wire, retaining omission semantics."""
        return self.model_dump(mode="json", by_alias=True, exclude_unset=True)


class CreateJobRequest(ContractModel):
    provider_request_id: OpaqueRef
    spec_digest: Sha256
    spec: JobSpec

    @model_validator(mode="after")
    def validate_spec_digest(self) -> CreateJobRequest:
        validate_request_digest(self.provider_request_id, self.spec_digest, self.spec)
        return self


class JobBindingState(StrEnum):
    PROVISIONING = "provisioning"
    BOUND = "bound"
    RUNNING = "running"
    FINALIZING = "finalizing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELING = "canceling"
    CANCELED = "canceled"
    INDETERMINATE = "indeterminate"
    DELETING = "deleting"
    DELETED = "deleted"


BindingState = JobBindingState


class ProviderTerminalState(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"
    INDETERMINATE = "indeterminate"


class RoleState(StrEnum):
    WAITING = "waiting"
    RUNNING = "running"
    TERMINATED = "terminated"
    UNKNOWN = "unknown"
    INDETERMINATE = "indeterminate"


class RunnerState(StrEnum):
    NOT_STARTED = "not_started"
    ACCEPTED = "accepted"
    STARTING = "starting"
    RUNNING = "running"
    EXITED = "exited"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


class CredentialState(StrEnum):
    ACCEPTED = "accepted"
    AVAILABLE = "available"
    ACKNOWLEDGED = "acknowledged"
    CONSUMED = "consumed"
    DESTROYED = "destroyed"
    EXPIRED = "expired"
    REVOKED = "revoked"
    DESTROY_FAILED = "destroy_failed"
    INDETERMINATE = "indeterminate"


class TransferState(StrEnum):
    REGISTERED = "registered"
    STAGING = "staging"
    AVAILABLE = "available"
    STREAMING = "streaming"
    COMPLETED = "completed"
    CANCELING = "canceling"
    CANCELED = "canceled"
    DISCARDED = "discarded"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


class ActionState(StrEnum):
    NOT_REQUESTED = "not_requested"
    ACCEPTED = "accepted"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


class CleanupState(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    COMPLETE = "complete"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


class LogContainer(StrEnum):
    AGENT = "agent"
    WORKSPACE = "workspace"


class AgentRequestedResources(ContractModel):
    cpu_millis: Annotated[StrictInt, Field(ge=1, le=8000)]
    memory_mib: Annotated[StrictInt, Field(ge=1, le=32768)]
    gpu: Literal[0]
    storage_gib: Annotated[StrictInt, Field(ge=1, le=100)]


class WorkspaceRequestedResources(ContractModel):
    cpu_millis: Annotated[StrictInt, Field(ge=1, le=64000)]
    memory_mib: Annotated[StrictInt, Field(ge=1, le=262144)]
    gpu: Annotated[StrictInt, Field(ge=0, le=8)]
    storage_gib: Annotated[StrictInt, Field(ge=1, le=100)]


class AgentObservedResources(ContractModel):
    cpu_millis: Annotated[StrictInt, Field(ge=0, le=8000)] | None
    memory_mib: Annotated[StrictInt, Field(ge=0, le=32768)] | None
    gpu: Literal[0] | None
    storage_gib: Annotated[StrictInt, Field(ge=0, le=100)] | None


class WorkspaceObservedResources(ContractModel):
    cpu_millis: Annotated[StrictInt, Field(ge=0, le=64000)] | None
    memory_mib: Annotated[StrictInt, Field(ge=0, le=262144)] | None
    gpu: Annotated[StrictInt, Field(ge=0, le=8)] | None
    storage_gib: Annotated[StrictInt, Field(ge=0, le=100)] | None


class AgentRoleSnapshot(ContractModel):
    container_id: StrictStr | None
    image_id: StrictStr | None
    state: RoleState
    ready: StrictBool
    restart_count: Annotated[StrictInt, Field(ge=0)]
    exit_code: StrictInt | None
    reason: StrictStr | None
    started_at: Timestamp | None
    finished_at: Timestamp | None
    requested: AgentRequestedResources
    observed: AgentObservedResources


class WorkspaceRoleSnapshot(ContractModel):
    container_id: StrictStr | None
    image_id: StrictStr | None
    state: RoleState
    ready: StrictBool
    restart_count: Annotated[StrictInt, Field(ge=0)]
    exit_code: StrictInt | None
    reason: StrictStr | None
    started_at: Timestamp | None
    finished_at: Timestamp | None
    requested: WorkspaceRequestedResources
    observed: WorkspaceObservedResources


class ActionSnapshot(ContractModel):
    action_ref: OpaqueRef | None
    request_digest: Sha256 | None
    state: ActionState
    observed_at: Timestamp | None

    @model_validator(mode="after")
    def validate_state_fields(self) -> ActionSnapshot:
        values = (self.action_ref, self.request_digest, self.observed_at)
        if self.state is ActionState.NOT_REQUESTED and any(value is not None for value in values):
            raise ValueError("not_requested actions cannot carry request identity")
        if self.state is not ActionState.NOT_REQUESTED and any(value is None for value in values):
            raise ValueError("requested actions require ref, digest, and observedAt")
        return self


class CleanupObservation(ContractModel):
    state: CleanupState
    reason: StrictStr | None
    observed_at: Timestamp | None


class CredentialObservation(ContractModel):
    credential_grant_ref: OpaqueRef
    state: CredentialState
    secret_present: StrictBool | None
    observed_at: Timestamp


class TransferObservation(ContractModel):
    transfer_ref: OpaqueRef
    state: TransferState
    observed_at: Timestamp


class GenerationSnapshot(ContractModel):
    job_ref: OpaqueRef
    generation: Annotated[StrictInt, Field(ge=1)]
    agent_run_ref: OpaqueRef
    execution_envelope_ref: OpaqueRef
    execution_envelope_digest: Sha256
    launch_bundle_path: SafeRelativePath
    launch_bundle_digest: Sha256
    launch_bundle_size_bytes: Annotated[StrictInt, Field(ge=0, le=1048576)]
    material_paths: Annotated[
        list[SafeRelativePath], AfterValidator(validate_casefold_unique_paths)
    ]
    credential_grant_ref: OpaqueRef
    start_metadata_digest: Sha256
    runner_state: RunnerState
    supervisor_alive: StrictBool
    pid: StrictInt | None
    exit_code: StrictInt | None
    started_at: Timestamp | None
    finished_at: Timestamp | None
    observed_at: Timestamp
    replayed: StrictBool
    credential_acknowledged_at: Timestamp | None
    credential_destroyed_at: Timestamp | None

    @model_validator(mode="after")
    def validate_exited_state(self) -> GenerationSnapshot:
        if self.runner_state is RunnerState.EXITED and (
            self.exit_code is None or self.finished_at is None
        ):
            raise ValueError("exited generation requires exitCode and finishedAt")
        return self


class JobBindingSnapshot(ContractModel):
    job_ref: OpaqueRef
    provider_handle: OpaqueRef
    provider_request_id: OpaqueRef
    subject_ref: OpaqueRef
    runtime_plan_digest: Sha256
    spec_digest: Sha256
    job_uid: KubernetesUid
    pod_uid: KubernetesUid | None
    resource_version: StrictStr | None
    node_name: StrictStr | None
    binding_state: JobBindingState
    binding_reason: StrictStr | None
    observed_pod_count: Annotated[StrictInt, Field(ge=0)]
    created_at: Timestamp
    updated_at: Timestamp
    started_at: Timestamp | None
    finished_at: Timestamp | None
    observed_at: Timestamp
    agent: AgentRoleSnapshot | None
    workspace: WorkspaceRoleSnapshot | None
    latest_agent_generation: GenerationSnapshot | None
    active_operation_refs: list[OpaqueRef]
    terminal_operation_refs: list[OpaqueRef]
    credential_observations: list[CredentialObservation]
    transfer_observations: list[TransferObservation]
    finalize_action: ActionSnapshot
    cancel_action: ActionSnapshot
    delete_action: ActionSnapshot
    output_loss_possible: StrictBool
    cleanup: CleanupObservation
    gpu_release: CleanupObservation

    @model_validator(mode="after")
    def validate_binding_coherence(self) -> JobBindingSnapshot:
        if self.binding_state is JobBindingState.RUNNING and (
            self.pod_uid is None or self.observed_pod_count != 1
        ):
            raise ValueError("running binding requires one immutable Pod UID")
        if self.observed_pod_count >= 2 and self.binding_state is not JobBindingState.INDETERMINATE:
            raise ValueError("multiple observed Pods require an indeterminate binding")
        action_by_state = {
            JobBindingState.FINALIZING: self.finalize_action,
            JobBindingState.CANCELING: self.cancel_action,
            JobBindingState.DELETING: self.delete_action,
        }
        action = action_by_state.get(self.binding_state)
        if action is not None and action.state is ActionState.NOT_REQUESTED:
            raise ValueError(f"{self.binding_state.value} binding requires its action")
        return self


class JobTombstone(ContractModel):
    provider_request_id: OpaqueRef
    spec_digest: Sha256
    job_ref: OpaqueRef
    job_uid: KubernetesUid
    pod_uid: KubernetesUid | None
    state: Literal["deleted"]
    final_state: ProviderTerminalState
    delete_ref: OpaqueRef
    delete_request_digest: Sha256
    created_at: Timestamp
    cleanup: CleanupObservation
    gpu_release: CleanupObservation
    credential_observations: list[CredentialObservation]
    transfer_observations: list[TransferObservation]
    deleted_at: Timestamp
    expires_at: Timestamp

    @model_validator(mode="after")
    def validate_time_order(self) -> JobTombstone:
        if not self.created_at <= self.deleted_at <= self.expires_at:
            raise ValueError("tombstone timestamps must be ordered createdAt/deletedAt/expiresAt")
        return self


class JobBindingSnapshotList(ContractModel):
    items: Annotated[list[JobBindingSnapshot], Field(max_length=200)]
    tombstones: Annotated[list[JobTombstone], Field(max_length=200)]
    next_page_token: OpaquePageToken | None
    observed_at: Timestamp

    @model_validator(mode="after")
    def validate_combined_limit(self) -> JobBindingSnapshotList:
        if len(self.items) + len(self.tombstones) > 200:
            raise ValueError("items and tombstones together may contain at most 200 records")
        return self


class RoleLogs(ContractModel):
    job_ref: OpaqueRef
    job_uid: KubernetesUid
    pod_uid: KubernetesUid
    container: LogContainer
    input_cursor: OpaqueCursor | None
    start_cursor: OpaqueCursor
    next_cursor: OpaqueCursor | None
    content: Annotated[StrictStr, Field(max_length=1048576)]
    truncated: StrictBool
    terminal: StrictBool
    container_id: StrictStr | None
    observed_at: Timestamp

    @model_validator(mode="after")
    def validate_content_bytes(self) -> RoleLogs:
        if len(self.content.encode("utf-8")) > 1048576:
            raise ValueError("log content exceeds 1 MiB of UTF-8")
        return self
