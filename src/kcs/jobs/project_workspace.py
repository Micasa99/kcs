"""Durable Project Workspace service, exact snapshots, Git receipts and IDE relay.

This module intentionally stays below ResearchCosmos product semantics.  A Workspace
is one persistent PVC plus a CPU-only service Deployment.  Attempt Jobs never mount
that PVC: exact snapshot bytes cross the boundary and the existing Attempt capture
remains the result authority.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

from kubernetes import client  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonical_digest
from .errors import (
    DependencyUnavailableError,
    DevSessionCredentialError,
    DevSessionExpiredError,
    DevSessionIdentityConflictError,
    DevSessionRelayDownError,
    DevSessionRevokedError,
    DigestMismatchError,
    IdentityDigestConflict,
    InvalidRequestError,
    JobNotFoundError,
    KcsV2Error,
    MaterializationFailedError,
    PayloadTooLargeError,
    StaleBindingError,
)
from .settings import V2RuntimeSettings
from .transport import WorkspaceRpcTransportProtocol

MANAGED_BY = "v2-project-workspace"
WORKSPACE_VOLUME = "project-workspace"
OPENVSCODE_VOLUME = "rc-openvscode"
WORKSPACE_EXTENSION_VOLUME = "rc-workspace-extension"
SESSION_VOLUME = "project-session"
CONTROL_SOCKET_VOLUME = "workspace-control"
WORKLOAD_SERVICE_ACCOUNT = "kcs-v2-workload"
MAX_PROJECT_BUNDLE_BYTES = 128 * 1024 * 1024


class _WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ProjectWorkspaceSpec(_WireModel):
    tenant_ref: str = Field(alias="tenantRef", min_length=1, max_length=256)
    principal_ref: str = Field(alias="principalRef", min_length=1, max_length=256)
    conversation_ref: str = Field(alias="conversationRef", min_length=1, max_length=256)
    storage_gib: int = Field(alias="storageGiB", ge=1, le=1024)


class EnsureProjectWorkspaceRequest(_WireModel):
    workspace_ref: str = Field(alias="workspaceRef", min_length=1, max_length=256)
    request_digest: str = Field(alias="requestDigest", pattern=r"^[0-9a-f]{64}$")
    spec: ProjectWorkspaceSpec

    @model_validator(mode="after")
    def validate_digest(self) -> EnsureProjectWorkspaceRequest:
        if (
            canonical_digest(self.spec.model_dump(mode="json", by_alias=True))
            != self.request_digest
        ):
            raise ValueError("requestDigest does not match Project Workspace spec")
        return self


class WorkspaceStorageObservation(_WireModel):
    requested_gib: int = Field(alias="requestedGiB")
    allocated_gib: int | None = Field(alias="allocatedGiB")
    used_bytes: int | None = Field(alias="usedBytes")
    persistent: Literal[True] = True


class WorkspaceServiceObservation(_WireModel):
    control_ready: bool = Field(alias="controlReady")
    ide_ready: bool = Field(alias="ideReady")
    relay_ready: bool = Field(alias="relayReady")


class ProjectWorkspaceSnapshot(_WireModel):
    workspace_ref: str = Field(alias="workspaceRef")
    request_digest: str = Field(alias="requestDigest")
    tenant_ref: str = Field(alias="tenantRef")
    principal_ref: str = Field(alias="principalRef")
    conversation_ref: str = Field(alias="conversationRef")
    generation: int
    state: Literal["provisioning", "ready", "degraded"]
    storage: WorkspaceStorageObservation
    service: WorkspaceServiceObservation
    created_at: datetime = Field(alias="createdAt")
    observed_at: datetime = Field(alias="observedAt")


class ProjectDevSessionSpec(_WireModel):
    tenant_ref: str = Field(alias="tenantRef")
    principal_ref: str = Field(alias="principalRef")
    conversation_ref: str = Field(alias="conversationRef")
    generation: int = Field(ge=1)
    ttl_seconds: int = Field(alias="ttlSeconds", ge=60, le=3600)


class ProjectDevSessionCreateRequest(_WireModel):
    dev_session_ref: str = Field(alias="devSessionRef")
    request_digest: str = Field(alias="requestDigest", pattern=r"^[0-9a-f]{64}$")
    spec: ProjectDevSessionSpec

    @model_validator(mode="after")
    def validate_digest(self) -> ProjectDevSessionCreateRequest:
        if (
            canonical_digest(self.spec.model_dump(mode="json", by_alias=True))
            != self.request_digest
        ):
            raise ValueError("requestDigest does not match Project dev-session spec")
        return self


class ProjectDevSessionRenewSpec(_WireModel):
    ttl_seconds: int = Field(alias="ttlSeconds", ge=60, le=3600)


class ProjectDevSessionRenewRequest(_WireModel):
    renew_ref: str = Field(alias="renewRef")
    request_digest: str = Field(alias="requestDigest", pattern=r"^[0-9a-f]{64}$")
    spec: ProjectDevSessionRenewSpec

    @model_validator(mode="after")
    def validate_digest(self) -> ProjectDevSessionRenewRequest:
        if (
            canonical_digest(self.spec.model_dump(mode="json", by_alias=True))
            != self.request_digest
        ):
            raise ValueError("requestDigest does not match Project dev-session renew spec")
        return self


class ProjectDevSessionSnapshot(_WireModel):
    dev_session_ref: str = Field(alias="devSessionRef")
    request_digest: str = Field(alias="requestDigest")
    workspace_ref: str = Field(alias="workspaceRef")
    tenant_ref: str = Field(alias="tenantRef")
    principal_ref: str = Field(alias="principalRef")
    conversation_ref: str = Field(alias="conversationRef")
    generation: int
    state: Literal["opening", "ready", "revoked", "expired", "lost"]
    relay_path: str = Field(alias="relayPath")
    writable: Literal[True] = True
    open_vscode_image_ref: str = Field(alias="openVscodeImageRef")
    open_vscode_image_id: str | None = Field(alias="openVscodeImageId")
    workspace_extension_image_ref: str = Field(alias="workspaceExtensionImageRef")
    workspace_extension_sha256: str = Field(alias="workspaceExtensionSha256")
    created_at: datetime = Field(alias="createdAt")
    expires_at: datetime = Field(alias="expiresAt")
    revoked_at: datetime | None = Field(alias="revokedAt")
    observed_at: datetime = Field(alias="observedAt")


class ProjectSnapshotSpec(_WireModel):
    expected_generation: int = Field(alias="expectedGeneration", ge=1)
    maximum_files: int = Field(alias="maximumFiles", ge=1, le=4096)
    maximum_bytes: int = Field(
        alias="maximumBytes", ge=1, le=MAX_PROJECT_BUNDLE_BYTES
    )


class CreateProjectSnapshotRequest(_WireModel):
    snapshot_ref: str = Field(alias="snapshotRef")
    request_digest: str = Field(alias="requestDigest", pattern=r"^[0-9a-f]{64}$")
    spec: ProjectSnapshotSpec

    @model_validator(mode="after")
    def validate_digest(self) -> CreateProjectSnapshotRequest:
        if (
            canonical_digest(self.spec.model_dump(mode="json", by_alias=True))
            != self.request_digest
        ):
            raise ValueError("requestDigest does not match Project snapshot spec")
        return self


class ProjectTreeSnapshot(_WireModel):
    snapshot_ref: str = Field(alias="snapshotRef")
    request_digest: str = Field(alias="requestDigest")
    workspace_ref: str = Field(alias="workspaceRef")
    generation: int
    state: Literal["ready"] = "ready"
    tree_digest: str = Field(alias="treeDigest")
    bundle_sha256: str = Field(alias="bundleSha256")
    bundle_size_bytes: int = Field(alias="bundleSizeBytes")
    entry_count: int = Field(alias="entryCount")
    base_commit: str = Field(alias="baseCommit")
    created_at: datetime = Field(alias="createdAt")


class ProjectImportSpec(_WireModel):
    expected_generation: int = Field(alias="expectedGeneration", ge=1)
    source_revision_ref: str = Field(alias="sourceRevisionRef")
    expected_tree_digest: str = Field(alias="expectedTreeDigest", pattern=r"^[0-9a-f]{64}$")
    content_sha256: str = Field(alias="contentSha256", pattern=r"^[0-9a-f]{64}$")
    declared_size_bytes: int = Field(
        alias="declaredSizeBytes", ge=1, le=MAX_PROJECT_BUNDLE_BYTES
    )
    base_commit: str | None = Field(alias="baseCommit", default=None)


class RegisterProjectImportRequest(_WireModel):
    import_ref: str = Field(alias="importRef")
    request_digest: str = Field(alias="requestDigest", pattern=r"^[0-9a-f]{64}$")
    spec: ProjectImportSpec

    @model_validator(mode="after")
    def validate_digest(self) -> RegisterProjectImportRequest:
        if (
            canonical_digest(
                self.spec.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_unset=True,
                )
            )
            != self.request_digest
        ):
            raise ValueError("requestDigest does not match Project import spec")
        return self


class ProjectImportSnapshot(_WireModel):
    import_ref: str = Field(alias="importRef")
    request_digest: str = Field(alias="requestDigest")
    workspace_ref: str = Field(alias="workspaceRef")
    generation: int
    source_revision_ref: str = Field(alias="sourceRevisionRef")
    state: Literal["registered", "completed", "failed"]
    expected_tree_digest: str = Field(alias="expectedTreeDigest")
    retained_checkout_ref: str | None = Field(alias="retainedCheckoutRef")
    result_commit: str | None = Field(alias="resultCommit")
    materialized_tree_digest: str | None = Field(alias="materializedTreeDigest")
    observed_at: datetime = Field(alias="observedAt")


@dataclass(frozen=True, slots=True)
class ProjectWorkspaceMutation:
    snapshot: ProjectWorkspaceSnapshot
    created: bool


@dataclass(frozen=True, slots=True)
class ProjectDevSessionMutation:
    snapshot: ProjectDevSessionSnapshot
    credential: str | None
    created: bool


@dataclass(frozen=True, slots=True)
class ProjectRelayTarget:
    host: str
    port: int
    path: str


@dataclass(frozen=True, slots=True)
class ProjectSnapshotContent:
    path: Path
    size: int
    sha256: str

    def cleanup(self) -> None:
        self.path.unlink(missing_ok=True)


def _short_hash(value: str, length: int = 20) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def project_deployment_name(workspace_ref: str) -> str:
    return f"kcs-v2-project-{_short_hash(workspace_ref)}"


def project_pvc_name(workspace_ref: str) -> str:
    return f"kcs-v2-project-data-{_short_hash(workspace_ref)}"


def project_session_secret_name(workspace_ref: str) -> str:
    return f"kcs-v2-project-session-{_short_hash(workspace_ref)}"


class ProjectWorkspaceRenderer:
    """Render one exact persistent Workspace Deployment and PVC."""

    def __init__(self, settings: V2RuntimeSettings) -> None:
        self._settings = settings

    def pvc(self, workspace_ref: str, storage_gib: int) -> client.V1PersistentVolumeClaim:
        return client.V1PersistentVolumeClaim(
            api_version="v1",
            kind="PersistentVolumeClaim",
            metadata=client.V1ObjectMeta(
                name=project_pvc_name(workspace_ref),
                namespace=self._settings.namespace,
                labels=self._labels(workspace_ref),
            ),
            spec=client.V1PersistentVolumeClaimSpec(
                access_modes=["ReadWriteOnce"],
                storage_class_name=self._settings.workspace_storage_class,
                resources=client.V1VolumeResourceRequirements(
                    requests={"storage": f"{storage_gib}Gi"}
                ),
            ),
        )

    def deployment(self, workspace_ref: str) -> client.V1Deployment:
        control_image, openvscode, relay, extension_image, extension_sha256 = self._images()
        name = project_deployment_name(workspace_ref)
        labels = self._labels(workspace_ref)
        workspace_mount = client.V1VolumeMount(
            name=WORKSPACE_VOLUME, mount_path="/workspace", read_only=False
        )
        restricted = client.V1SecurityContext(
            run_as_user=10001,
            run_as_group=10001,
            allow_privilege_escalation=False,
            read_only_root_filesystem=True,
            capabilities=client.V1Capabilities(drop=["ALL"]),
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        )
        ide_identity = client.V1SecurityContext(
            run_as_user=10002,
            run_as_group=10001,
            allow_privilege_escalation=False,
            read_only_root_filesystem=True,
            capabilities=client.V1Capabilities(drop=["ALL"]),
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        )
        relay_identity = client.V1SecurityContext(
            run_as_user=0,
            run_as_group=0,
            allow_privilege_escalation=False,
            read_only_root_filesystem=True,
            capabilities=client.V1Capabilities(drop=["ALL"]),
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        )
        pod = client.V1PodSpec(
            service_account_name=WORKLOAD_SERVICE_ACCOUNT,
            automount_service_account_token=False,
            restart_policy="Always",
            node_selector=dict(self._settings.node_selector),
            enable_service_links=False,
            host_network=False,
            host_pid=False,
            host_ipc=False,
            security_context=client.V1PodSecurityContext(
                seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault")
            ),
            init_containers=[
                client.V1Container(
                    name="workspace-init",
                    image=control_image,
                    image_pull_policy="IfNotPresent",
                    command=["/bin/sh", "-ceu"],
                    args=[
                        "install -d -m 2775 -o 10001 -g 10001 /workspace/worktree "
                        "/workspace/retained; install -d -m 0700 -o 10001 -g 10001 "
                        "/workspace/.kcs /workspace/.kcs/tmp; "
                        "install -d -m 0770 -o 10002 -g 10001 "
                        "/workspace/.ide/home /workspace/.ide/tmp; "
                        "install -d -m 0700 -o 10001 -g 10001 /run/rc-control"
                    ],
                    security_context=client.V1SecurityContext(
                        run_as_user=0,
                        run_as_group=0,
                        allow_privilege_escalation=False,
                        capabilities=client.V1Capabilities(
                            drop=["ALL"], add=["CHOWN", "FOWNER", "DAC_OVERRIDE"]
                        ),
                        seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
                    ),
                    volume_mounts=[
                        workspace_mount,
                        client.V1VolumeMount(
                            name=CONTROL_SOCKET_VOLUME,
                            mount_path="/run/rc-control",
                        ),
                    ],
                ),
                client.V1Container(
                    name="ide-bootstrap",
                    image=control_image,
                    image_pull_policy="IfNotPresent",
                    command=["/bin/sh", "-ceu"],
                    args=[
                        "actual=$(sha256sum /opt/rc-workspace-extension/aicosmos-workspace.vsix "
                        "| cut -d' ' -f1); test \"$actual\" = \"$AICOSMOS_WORKSPACE_VSIX_SHA256\"; "
                        "umask 0002; /opt/rc-dev/openvscode/bin/openvscode-server "
                        "--install-extension /opt/rc-workspace-extension/aicosmos-workspace.vsix "
                        "--force --extensions-dir /workspace/.ide/home/.openvscode-extensions"
                    ],
                    env=[
                        client.V1EnvVar(name="HOME", value="/workspace/.ide/home"),
                        client.V1EnvVar(name="TMPDIR", value="/workspace/.ide/tmp"),
                        client.V1EnvVar(
                            name="AICOSMOS_WORKSPACE_VSIX_SHA256",
                            value=extension_sha256,
                        ),
                    ],
                    resources=client.V1ResourceRequirements(
                        requests={"cpu": "50m", "memory": "64Mi"},
                        limits={"cpu": "500m", "memory": "512Mi"},
                    ),
                    security_context=ide_identity,
                    volume_mounts=[
                        workspace_mount,
                        client.V1VolumeMount(
                            name=OPENVSCODE_VOLUME,
                            mount_path="/opt/rc-dev",
                            read_only=True,
                        ),
                        client.V1VolumeMount(
                            name=WORKSPACE_EXTENSION_VOLUME,
                            mount_path="/opt/rc-workspace-extension",
                            read_only=True,
                        ),
                    ],
                )
            ],
            containers=[
                client.V1Container(
                    name="workspace-control",
                    image=control_image,
                    image_pull_policy="IfNotPresent",
                    command=["/bin/sh", "-ceu"],
                    args=["umask 0002; exec /opt/kcs/workspace-sidecar serve"],
                    env=[
                        client.V1EnvVar(name="KCS_WORKSPACE", value="/workspace"),
                        client.V1EnvVar(
                            name="KCS_WORKSPACE_SOCKET", value="/run/rc-control/workspace.sock"
                        ),
                        client.V1EnvVar(
                            name="KCS_CONTROL_STATE_DIR",
                            value="/workspace/.kcs/runtime-control",
                        ),
                        client.V1EnvVar(name="TMPDIR", value="/workspace/.kcs/tmp"),
                    ],
                    resources=client.V1ResourceRequirements(
                        requests={"cpu": "100m", "memory": "128Mi"},
                        limits={"cpu": "1", "memory": "1Gi"},
                    ),
                    security_context=restricted,
                    readiness_probe=client.V1Probe(
                        _exec=client.V1ExecAction(
                            command=["/bin/sh", "-c", "test -S /run/rc-control/workspace.sock"]
                        ),
                        period_seconds=3,
                    ),
                    volume_mounts=[
                        workspace_mount,
                        client.V1VolumeMount(
                            name=CONTROL_SOCKET_VOLUME, mount_path="/run/rc-control"
                        ),
                    ],
                ),
                client.V1Container(
                    name="openvscode",
                    image=control_image,
                    image_pull_policy="IfNotPresent",
                    command=["/bin/sh", "-ceu"],
                    args=[
                        "umask 0002; exec /opt/rc-dev/openvscode/bin/openvscode-server "
                        "--host 127.0.0.1 --port 3000 --without-connection-token "
                        "--accept-server-license-terms --telemetry-level off "
                        "--server-data-dir /workspace/.ide/home/.openvscode-server "
                        "--user-data-dir /workspace/.ide/home/.openvscode-user "
                        "--extensions-dir /workspace/.ide/home/.openvscode-extensions "
                        "/workspace/worktree"
                    ],
                    env=[
                        client.V1EnvVar(name="HOME", value="/workspace/.ide/home"),
                        client.V1EnvVar(name="TMPDIR", value="/workspace/.ide/tmp"),
                    ],
                    ports=[client.V1ContainerPort(name="ide", container_port=3000)],
                    resources=client.V1ResourceRequirements(
                        requests={"cpu": "250m", "memory": "512Mi"},
                        limits={"cpu": "2", "memory": "2Gi"},
                    ),
                    security_context=ide_identity,
                    readiness_probe=client.V1Probe(
                        _exec=client.V1ExecAction(
                            command=[
                                "python",
                                "-c",
                                "import socket; "
                                "socket.create_connection(('127.0.0.1', 3000), 1).close()",
                            ]
                        ),
                        period_seconds=3,
                    ),
                    volume_mounts=[
                        workspace_mount,
                        client.V1VolumeMount(
                            name=OPENVSCODE_VOLUME, mount_path="/opt/rc-dev", read_only=True
                        ),
                    ],
                ),
                client.V1Container(
                    name="relay",
                    image=relay,
                    image_pull_policy="IfNotPresent",
                    env=[
                        client.V1EnvVar(name="LISTEN_ADDR", value=":8080"),
                        client.V1EnvVar(name="UPSTREAM_URL", value="http://127.0.0.1:3000"),
                        client.V1EnvVar(
                            name="DEV_SESSION_CREDENTIAL_FILE",
                            value="/run/dev-session/credential",
                        ),
                        client.V1EnvVar(
                            name="DEV_SESSION_EXPIRES_AT_FILE",
                            value="/run/dev-session/expires-at",
                        ),
                        client.V1EnvVar(
                            name="DEV_SESSION_REVOKED_FILE",
                            value="/run/dev-session/revoked",
                        ),
                    ],
                    ports=[client.V1ContainerPort(name="relay", container_port=8080)],
                    resources=client.V1ResourceRequirements(
                        requests={"cpu": "50m", "memory": "32Mi"},
                        limits={"cpu": "250m", "memory": "128Mi"},
                    ),
                    security_context=relay_identity,
                    readiness_probe=client.V1Probe(
                        tcp_socket=client.V1TCPSocketAction(port=8080), period_seconds=3
                    ),
                    volume_mounts=[
                        client.V1VolumeMount(
                            name=SESSION_VOLUME, mount_path="/run/dev-session", read_only=True
                        )
                    ],
                ),
            ],
            volumes=[
                client.V1Volume(
                    name=WORKSPACE_VOLUME,
                    persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                        claim_name=project_pvc_name(workspace_ref)
                    ),
                ),
                client.V1Volume(
                    name=CONTROL_SOCKET_VOLUME,
                    empty_dir=client.V1EmptyDirVolumeSource(size_limit="64Mi"),
                ),
                client.V1Volume(
                    name=OPENVSCODE_VOLUME,
                    image=client.V1ImageVolumeSource(
                        reference=openvscode, pull_policy="IfNotPresent"
                    ),
                ),
                client.V1Volume(
                    name=WORKSPACE_EXTENSION_VOLUME,
                    image=client.V1ImageVolumeSource(
                        reference=extension_image, pull_policy="IfNotPresent"
                    ),
                ),
                client.V1Volume(
                    name=SESSION_VOLUME,
                    secret=client.V1SecretVolumeSource(
                        secret_name=project_session_secret_name(workspace_ref),
                        optional=False,
                        default_mode=0o400,
                    ),
                ),
            ],
        )
        return client.V1Deployment(
            api_version="apps/v1",
            kind="Deployment",
            metadata=client.V1ObjectMeta(
                name=name, namespace=self._settings.namespace, labels=labels
            ),
            spec=client.V1DeploymentSpec(
                replicas=1,
                strategy=client.V1DeploymentStrategy(type="Recreate"),
                selector=client.V1LabelSelector(match_labels=labels),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(labels=labels), spec=pod
                ),
            ),
        )

    def _images(self) -> tuple[str, str, str, str, str]:
        control = self._settings.project_workspace_control_image
        openvscode = self._settings.native_openvscode_image_volume
        relay = self._settings.native_dev_session_relay_image
        extension = self._settings.project_workspace_vsix_image_volume
        extension_sha256 = self._settings.project_workspace_vsix_sha256
        if (
            control is None
            or openvscode is None
            or relay is None
            or extension is None
            or extension_sha256 is None
        ):
            raise DependencyUnavailableError("Project Workspace images are not configured")
        return control, openvscode, relay, extension, extension_sha256

    @staticmethod
    def _labels(workspace_ref: str) -> dict[str, str]:
        return {
            "researchcosmos.io/managed-by": MANAGED_BY,
            "researchcosmos.io/project-workspace-hash": _short_hash(workspace_ref, 16),
        }


class ProjectWorkspaceService:
    """Coordinate Workspace persistence, exact RPCs and scoped IDE sessions."""

    def __init__(
        self,
        store: Any,
        kube: Any,
        transport: WorkspaceRpcTransportProtocol | None,
        settings: V2RuntimeSettings,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._kube = kube
        self._transport = transport
        self._settings = settings
        self._renderer = ProjectWorkspaceRenderer(settings)
        self._clock = clock or (lambda: datetime.now(UTC))

    def ensure(self, request: EnsureProjectWorkspaceRequest) -> ProjectWorkspaceMutation:
        ref = request.workspace_ref
        now = self._now()
        values = {
            "identityDigest": request.request_digest,
            "requestDigest": request.request_digest,
            "tenantRef": request.spec.tenant_ref,
            "principalRef": request.spec.principal_ref,
            "conversationRef": request.spec.conversation_ref,
            "storageGiB": str(request.spec.storage_gib),
            "generation": "0",
            "podName": "",
            "podUid": "",
            "createdAt": now.isoformat(),
            "observedAt": now.isoformat(),
        }
        record, created = self._store.reserve_runtime(
            "project-workspace", ref, ref, values, owner_job_ref=False
        )
        if record.values.get("identityDigest") != request.request_digest:
            raise IdentityDigestConflict()
        if self._kube.read_persistent_volume_claim(project_pvc_name(ref)) is None:
            try:
                self._kube.create_persistent_volume_claim(
                    self._renderer.pvc(ref, request.spec.storage_gib)
                )
            except Exception as error:
                if getattr(error, "status", None) != 409:
                    raise
        session_secret_name = project_session_secret_name(ref)
        if self._kube.read_secret(session_secret_name) is None:
            self._kube.upsert_secret(
                session_secret_name,
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": session_secret_name,
                        "labels": {
                            "researchcosmos.io/managed-by": MANAGED_BY,
                            "researchcosmos.io/project-workspace-hash": _short_hash(ref, 16),
                        },
                    },
                    "type": "Opaque",
                    "data": {"revoked": ""},
                },
            )
        if self._kube.read_deployment(project_deployment_name(ref)) is None:
            try:
                self._kube.create_deployment(self._renderer.deployment(ref))
            except Exception as error:
                if getattr(error, "status", None) != 409:
                    raise
        return ProjectWorkspaceMutation(self.inspect(ref), created)

    def inspect(self, workspace_ref: str) -> ProjectWorkspaceSnapshot:
        record = self._record(workspace_ref)
        values = dict(record.values)
        pods = self._kube.list_pods(
            f"researchcosmos.io/managed-by={MANAGED_BY},"
            f"researchcosmos.io/project-workspace-hash={_short_hash(workspace_ref, 16)}"
        )
        active = [
            pod
            for pod in pods
            if _field(_field(pod, "metadata", {}), "deletion_timestamp") is None
        ]
        pod = active[-1] if active else None
        pod_name = str(_field(_field(pod, "metadata", {}), "name") or "")
        pod_uid = str(_field(_field(pod, "metadata", {}), "uid") or "")
        generation = int(values.get("generation", "0"))
        if pod_uid and pod_uid != values.get("podUid"):
            generation += 1
            values.update(
                generation=str(generation),
                podName=pod_name,
                podUid=pod_uid,
                observedAt=self._now().isoformat(),
            )
            record = self._store.update_runtime(
                "project-workspace", workspace_ref, workspace_ref, values
            )
        ready: set[str] = set()
        if pod is not None:
            for status in _field(_field(pod, "status", {}), "container_statuses", []) or []:
                if bool(_field(status, "ready")):
                    ready.add(str(_field(status, "name")))
        service = WorkspaceServiceObservation(
            controlReady="workspace-control" in ready,
            ideReady="openvscode" in ready,
            relayReady="relay" in ready,
        )
        all_ready = service.control_ready and service.ide_ready and service.relay_ready
        state = (
            "ready"
            if all_ready
            else "provisioning"
            if pod is None or not ready
            else "degraded"
        )
        pvc = self._kube.read_persistent_volume_claim(project_pvc_name(workspace_ref))
        allocated = int(values["storageGiB"]) if pvc is not None else None
        return ProjectWorkspaceSnapshot(
            workspaceRef=workspace_ref,
            requestDigest=values["requestDigest"],
            tenantRef=values["tenantRef"],
            principalRef=values["principalRef"],
            conversationRef=values["conversationRef"],
            generation=max(1, generation),
            state=state,
            storage=WorkspaceStorageObservation(
                requestedGiB=int(values["storageGiB"]),
                allocatedGiB=allocated,
                usedBytes=None,
                persistent=True,
            ),
            service=service,
            createdAt=values["createdAt"],
            observedAt=self._now(),
        )

    def create_dev_session(
        self, workspace_ref: str, request: ProjectDevSessionCreateRequest
    ) -> ProjectDevSessionMutation:
        binding = self._binding(workspace_ref, request.spec.generation)
        workspace = self.inspect(workspace_ref)
        if (
            request.spec.tenant_ref != workspace.tenant_ref
            or request.spec.principal_ref != workspace.principal_ref
            or request.spec.conversation_ref != workspace.conversation_ref
        ):
            raise StaleBindingError()
        now = self._now()
        expires = now + timedelta(seconds=request.spec.ttl_seconds)
        values = {
            "identityDigest": request.request_digest,
            "requestDigest": request.request_digest,
            "tenantRef": request.spec.tenant_ref,
            "principalRef": request.spec.principal_ref,
            "conversationRef": request.spec.conversation_ref,
            "generation": str(request.spec.generation),
            "podName": binding["podName"],
            "podUid": binding["podUid"],
            "state": "opening",
            "createdAt": now.isoformat(),
            "expiresAt": expires.isoformat(),
            "revokedAt": "",
            "observedAt": now.isoformat(),
        }
        record, created = self._store.reserve_runtime(
            "project-dev-session",
            request.dev_session_ref,
            workspace_ref,
            values,
            owner_job_ref=False,
        )
        if not created:
            retained = dict(record.values)
            if retained.get("identityDigest") != request.request_digest:
                raise DevSessionIdentityConflictError()
            credential = self._secret_credential(workspace_ref)
            if credential is None:
                raise DevSessionRelayDownError()
            return ProjectDevSessionMutation(self._session_snapshot(record), credential, False)
        credential = secrets.token_urlsafe(32)
        values["credentialSha256"] = hashlib.sha256(credential.encode()).hexdigest()
        self._kube.upsert_secret(
            project_session_secret_name(workspace_ref),
            self._session_secret(workspace_ref, credential, expires),
        )
        record = self._store.update_runtime(
            "project-dev-session", workspace_ref, request.dev_session_ref, values
        )
        return ProjectDevSessionMutation(self._session_snapshot(record), credential, True)

    def inspect_dev_session(
        self, workspace_ref: str, session_ref: str, credential: str
    ) -> ProjectDevSessionSnapshot:
        return self._session_snapshot(self._access_session(workspace_ref, session_ref, credential))

    def renew_dev_session(
        self,
        workspace_ref: str,
        session_ref: str,
        credential: str,
        request: ProjectDevSessionRenewRequest,
    ) -> ProjectDevSessionMutation:
        record = self._access_session(workspace_ref, session_ref, credential)
        values = dict(record.values)
        if values.get("renewRef") == request.renew_ref:
            if values.get("renewDigest") != request.request_digest:
                raise DevSessionIdentityConflictError()
            retained = self._secret_credential(workspace_ref)
            if retained is None:
                raise DevSessionRelayDownError()
            return ProjectDevSessionMutation(self._session_snapshot(record), retained, False)
        rotated = secrets.token_urlsafe(32)
        expires = self._now() + timedelta(seconds=request.spec.ttl_seconds)
        self._kube.upsert_secret(
            project_session_secret_name(workspace_ref),
            self._session_secret(workspace_ref, rotated, expires),
        )
        values.update(
            renewRef=request.renew_ref,
            renewDigest=request.request_digest,
            credentialSha256=hashlib.sha256(rotated.encode()).hexdigest(),
            expiresAt=expires.isoformat(),
            state="opening",
            observedAt=self._now().isoformat(),
        )
        record = self._store.update_runtime(
            "project-dev-session", workspace_ref, session_ref, values
        )
        return ProjectDevSessionMutation(self._session_snapshot(record), rotated, True)

    def revoke_dev_session(
        self, workspace_ref: str, session_ref: str, credential: str
    ) -> ProjectDevSessionSnapshot:
        record = self._access_session(workspace_ref, session_ref, credential)
        values = dict(record.values)
        now = self._now()
        values.update(
            state="revoked", revokedAt=now.isoformat(), observedAt=now.isoformat()
        )
        name = project_session_secret_name(workspace_ref)
        self._kube.upsert_secret(
            name,
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": name},
                "data": {"revoked": ""},
            },
        )
        return self._session_snapshot(
            self._store.update_runtime(
                "project-dev-session", workspace_ref, session_ref, values
            )
        )

    def relay_target(
        self, workspace_ref: str, session_ref: str, credential: str, path: str
    ) -> ProjectRelayTarget:
        record = self._access_session(workspace_ref, session_ref, credential)
        values = dict(record.values)
        try:
            host, port = self._kube.project_relay_endpoint(
                values["podName"], values["podUid"]
            )
        except Exception as error:
            raise DevSessionRelayDownError() from error
        return ProjectRelayTarget(host=host, port=port, path=path)

    def observe_relay_ready(
        self, workspace_ref: str, session_ref: str, credential: str
    ) -> ProjectDevSessionSnapshot:
        record = self._access_session(workspace_ref, session_ref, credential)
        values = dict(record.values)
        if values.get("state") == "opening":
            values.update(state="ready", observedAt=self._now().isoformat())
            record = self._store.update_runtime(
                "project-dev-session", workspace_ref, session_ref, values
            )
        return self._session_snapshot(record)

    def create_snapshot(
        self, workspace_ref: str, request: CreateProjectSnapshotRequest
    ) -> tuple[ProjectTreeSnapshot, bool]:
        binding = self._binding(workspace_ref, request.spec.expected_generation)
        retained = self._store.read_runtime("project-snapshot", workspace_ref, request.snapshot_ref)
        if retained is not None:
            if retained.values.get("identityDigest") != request.request_digest:
                raise IdentityDigestConflict()
            return self._tree_snapshot(retained), False
        reply = self._rpc(
            binding,
            {
                "action": "createProjectWorkspaceSnapshot",
                "workspaceRef": workspace_ref,
                "snapshotRef": request.snapshot_ref,
                "requestDigest": request.request_digest,
                "generation": request.spec.expected_generation,
                "maximumFiles": request.spec.maximum_files,
                "maximumBytes": request.spec.maximum_bytes,
            },
        )
        try:
            data = dict(reply.header.get("snapshot") or {})
            values = {
                "identityDigest": request.request_digest,
                "requestDigest": request.request_digest,
                "generation": str(request.spec.expected_generation),
                "treeDigest": str(data["treeDigest"]),
                "bundleSha256": str(data["bundleSha256"]),
                "bundleSizeBytes": str(data["bundleSizeBytes"]),
                "entryCount": str(data["entryCount"]),
                "baseCommit": str(data["baseCommit"]),
                "createdAt": str(data["createdAt"]),
            }
            record, created = self._store.reserve_runtime(
                "project-snapshot",
                request.snapshot_ref,
                workspace_ref,
                values,
                owner_job_ref=False,
            )
            return self._tree_snapshot(record), created
        finally:
            if reply.content_path is not None:
                reply.content_path.unlink(missing_ok=True)

    def open_snapshot_content(
        self, workspace_ref: str, snapshot_ref: str
    ) -> ProjectSnapshotContent:
        record = self._store.read_runtime("project-snapshot", workspace_ref, snapshot_ref)
        if record is None:
            raise JobNotFoundError()
        binding = self._binding(workspace_ref, int(record.values["generation"]))
        reply = self._rpc(
            binding,
            {
                "action": "readProjectWorkspaceSnapshot",
                "workspaceRef": workspace_ref,
                "snapshotRef": snapshot_ref,
                "requestDigest": record.values["requestDigest"],
                "generation": int(record.values["generation"]),
                "authorizedMaxSizeBytes": MAX_PROJECT_BUNDLE_BYTES,
            },
        )
        if reply.content_path is None:
            raise DependencyUnavailableError("Project snapshot content was absent")
        size = reply.content_path.stat().st_size
        digest = _sha256_file(reply.content_path)
        if size != int(record.values["bundleSizeBytes"]) or digest != record.values["bundleSha256"]:
            reply.content_path.unlink(missing_ok=True)
            raise DigestMismatchError()
        return ProjectSnapshotContent(reply.content_path, size, digest)

    def register_import(
        self, workspace_ref: str, request: RegisterProjectImportRequest
    ) -> tuple[ProjectImportSnapshot, bool]:
        self._binding(workspace_ref, request.spec.expected_generation)
        now = self._now()
        values = {
            "identityDigest": request.request_digest,
            "requestDigest": request.request_digest,
            "generation": str(request.spec.expected_generation),
            "sourceRevisionRef": request.spec.source_revision_ref,
            "expectedTreeDigest": request.spec.expected_tree_digest,
            "contentSha256": request.spec.content_sha256,
            "declaredSizeBytes": str(request.spec.declared_size_bytes),
            "baseCommit": request.spec.base_commit or "",
            "state": "registered",
            "retainedCheckoutRef": "",
            "resultCommit": "",
            "materializedTreeDigest": "",
            "observedAt": now.isoformat(),
        }
        record, created = self._store.reserve_runtime(
            "project-import",
            request.import_ref,
            workspace_ref,
            values,
            owner_job_ref=False,
        )
        return self._import_snapshot(record), created

    def put_import(
        self, workspace_ref: str, import_ref: str, content: Path
    ) -> ProjectImportSnapshot:
        record = self._store.read_runtime("project-import", workspace_ref, import_ref)
        if record is None:
            raise JobNotFoundError()
        values = dict(record.values)
        size = content.stat().st_size
        digest = _sha256_file(content)
        if size != int(values["declaredSizeBytes"]) or digest != values["contentSha256"]:
            raise DigestMismatchError()
        if values.get("state") == "completed":
            return self._import_snapshot(record)
        binding = self._binding(workspace_ref, int(values["generation"]))
        reply = self._rpc(
            binding,
            {
                "action": "importProjectWorkspaceRevision",
                "workspaceRef": workspace_ref,
                "importRef": import_ref,
                "requestDigest": values["requestDigest"],
                "generation": int(values["generation"]),
                "sourceRevisionRef": values["sourceRevisionRef"],
                "expectedTreeDigest": values["expectedTreeDigest"],
                "contentSha256": values["contentSha256"],
                "declaredSizeBytes": int(values["declaredSizeBytes"]),
                "authorizedMaxSizeBytes": MAX_PROJECT_BUNDLE_BYTES,
                "baseCommit": values.get("baseCommit") or None,
            },
            content,
        )
        receipt = dict(reply.header.get("receipt") or {})
        values.update(
            state="completed",
            retainedCheckoutRef=str(receipt["retainedCheckoutRef"]),
            resultCommit=str(receipt["resultCommit"]),
            materializedTreeDigest=str(receipt["materializedTreeDigest"]),
            observedAt=self._now().isoformat(),
        )
        return self._import_snapshot(
            self._store.update_runtime("project-import", workspace_ref, import_ref, values)
        )

    def _rpc(
        self,
        binding: Mapping[str, str],
        header: Mapping[str, object],
        body: Path | None = None,
    ):
        if self._transport is None:
            raise DependencyUnavailableError("Project Workspace control transport is unavailable")
        reply = self._transport.rpc(binding, header, body)
        if reply.header.get("ok") is True:
            return reply
        if reply.content_path is not None:
            reply.content_path.unlink(missing_ok=True)
        code = reply.header.get("code")
        errors: dict[object, type[KcsV2Error]] = {
            "INVALID_REQUEST": InvalidRequestError,
            "NOT_FOUND": JobNotFoundError,
            "STALE_BINDING": StaleBindingError,
            "IDENTITY_CONFLICT": IdentityDigestConflict,
            "DIGEST_MISMATCH": DigestMismatchError,
            "PAYLOAD_TOO_LARGE": PayloadTooLargeError,
            "MATERIALIZATION_FAILED": MaterializationFailedError,
            "DEPENDENCY_UNAVAILABLE": DependencyUnavailableError,
        }
        raise errors.get(code, DependencyUnavailableError)()

    def _binding(self, workspace_ref: str, expected_generation: int) -> dict[str, str]:
        snapshot = self.inspect(workspace_ref)
        record = self._record(workspace_ref)
        values = dict(record.values)
        if snapshot.state != "ready" or snapshot.generation != expected_generation:
            raise StaleBindingError()
        if not values.get("podName") or not values.get("podUid"):
            raise StaleBindingError()
        deployment = self._kube.read_deployment(project_deployment_name(workspace_ref))
        deployment_uid = str(_field(_field(deployment, "metadata", {}), "uid") or "")
        return {
            "runtimeLane": "project",
            "jobRef": workspace_ref,
            "jobUid": deployment_uid,
            "podName": values["podName"],
            "podUid": values["podUid"],
            "generation": str(expected_generation),
        }

    def _record(self, workspace_ref: str):
        record = self._store.read_runtime("project-workspace", workspace_ref, workspace_ref)
        if record is None:
            raise JobNotFoundError()
        return record

    def _access_session(self, workspace_ref: str, session_ref: str, credential: str):
        record = self._store.read_runtime("project-dev-session", workspace_ref, session_ref)
        if record is None:
            raise JobNotFoundError()
        values = dict(record.values)
        state = values.get("state")
        if state == "revoked":
            raise DevSessionRevokedError()
        if state == "expired" or _parse_time(values.get("expiresAt")) <= self._now():
            raise DevSessionExpiredError()
        supplied = hashlib.sha256(credential.encode()).hexdigest()
        if not values.get("credentialSha256") or not hmac.compare_digest(
            values["credentialSha256"], supplied
        ):
            raise DevSessionCredentialError()
        self._binding(workspace_ref, int(values["generation"]))
        return record

    def _session_snapshot(self, record: Any) -> ProjectDevSessionSnapshot:
        values = dict(record.values)
        state = values.get("state", "lost")
        if state in {"opening", "ready"} and _parse_time(values.get("expiresAt")) <= self._now():
            state = "expired"
        image_id = None
        if state in {"opening", "ready"}:
            try:
                image_id, ide_ready = self._kube.project_container_image_id(
                    values["podName"], values["podUid"], "openvscode"
                )
                _relay_id, relay_ready = self._kube.project_container_image_id(
                    values["podName"], values["podUid"], "relay"
                )
                if not (ide_ready and relay_ready):
                    state = "opening"
            except Exception:
                state = "lost"
        return ProjectDevSessionSnapshot(
            devSessionRef=record.identity,
            requestDigest=values["requestDigest"],
            workspaceRef=record.job_ref,
            tenantRef=values["tenantRef"],
            principalRef=values["principalRef"],
            conversationRef=values["conversationRef"],
            generation=int(values["generation"]),
            state=state,
            relayPath=(
                f"/api/v2/project-workspaces/{quote(record.job_ref, safe='')}/dev-sessions/"
                f"{quote(record.identity, safe='')}/relay"
            ),
            writable=True,
            openVscodeImageRef=self._settings.native_openvscode_image_volume or "",
            openVscodeImageId=image_id,
            workspaceExtensionImageRef=(
                self._settings.project_workspace_vsix_image_volume or ""
            ),
            workspaceExtensionSha256=self._settings.project_workspace_vsix_sha256 or "",
            createdAt=values["createdAt"],
            expiresAt=values["expiresAt"],
            revokedAt=values.get("revokedAt") or None,
            observedAt=self._now(),
        )

    def _tree_snapshot(self, record: Any) -> ProjectTreeSnapshot:
        values = dict(record.values)
        return ProjectTreeSnapshot(
            snapshotRef=record.identity,
            requestDigest=values["requestDigest"],
            workspaceRef=record.job_ref,
            generation=int(values["generation"]),
            state="ready",
            treeDigest=values["treeDigest"],
            bundleSha256=values["bundleSha256"],
            bundleSizeBytes=int(values["bundleSizeBytes"]),
            entryCount=int(values["entryCount"]),
            baseCommit=values["baseCommit"],
            createdAt=values["createdAt"],
        )

    def _import_snapshot(self, record: Any) -> ProjectImportSnapshot:
        values = dict(record.values)
        return ProjectImportSnapshot(
            importRef=record.identity,
            requestDigest=values["requestDigest"],
            workspaceRef=record.job_ref,
            generation=int(values["generation"]),
            sourceRevisionRef=values["sourceRevisionRef"],
            state=values["state"],
            expectedTreeDigest=values["expectedTreeDigest"],
            retainedCheckoutRef=values.get("retainedCheckoutRef") or None,
            resultCommit=values.get("resultCommit") or None,
            materializedTreeDigest=values.get("materializedTreeDigest") or None,
            observedAt=values["observedAt"],
        )

    def _session_secret(
        self, workspace_ref: str, credential: str, expires: datetime
    ) -> dict[str, object]:
        return {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": project_session_secret_name(workspace_ref),
                "labels": {
                    "researchcosmos.io/managed-by": MANAGED_BY,
                    "researchcosmos.io/project-workspace-hash": _short_hash(workspace_ref, 16),
                },
            },
            "type": "Opaque",
            "data": {
                "credential": base64.b64encode(credential.encode()).decode("ascii"),
                "expires-at": base64.b64encode(
                    str(int(expires.timestamp())).encode("ascii")
                ).decode("ascii"),
                # The fixed Secret slot is patched in place so the long-lived
                # Workspace Pod observes credential rotation without restart.
                # Explicit null removes the revoke marker left by the previous
                # session; omitting it would preserve that map key and every
                # subsequent session would remain permanently revoked.
                "revoked": None,
            },
        }

    def _secret_credential(self, workspace_ref: str) -> str | None:
        secret = self._kube.read_secret(project_session_secret_name(workspace_ref))
        data = _field(secret, "data", {}) if secret is not None else {}
        raw = data.get("credential") if isinstance(data, Mapping) else None
        if not isinstance(raw, str):
            return None
        try:
            return base64.b64decode(raw, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise RuntimeError("Project Workspace clock must be timezone-aware")
        return value.astimezone(UTC)


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=UTC)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "CreateProjectSnapshotRequest",
    "EnsureProjectWorkspaceRequest",
    "ProjectDevSessionCreateRequest",
    "ProjectDevSessionRenewRequest",
    "ProjectDevSessionSnapshot",
    "ProjectImportSnapshot",
    "ProjectSnapshotContent",
    "ProjectTreeSnapshot",
    "ProjectWorkspaceService",
    "ProjectWorkspaceSnapshot",
    "RegisterProjectImportRequest",
]
