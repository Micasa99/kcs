"""Pure renderer for the fixed KCS V2 dual-role Kubernetes Job."""

from __future__ import annotations

import hashlib

from kubernetes import client  # type: ignore[import-untyped]

from .contracts import CreateJobRequest
from .policy import PolicyViolationError
from .settings import V2RuntimeSettings

MANAGED_BY = "v2-attempt-runtime"
WORKSPACE_VOLUME = "workspace"
CREDENTIAL_VOLUME = "agent-credential"
WORKSPACE_MOUNT_PATH = "/workspace"
CREDENTIAL_MOUNT_PATH = "/var/run/kcs/credential"
WORKLOAD_SERVICE_ACCOUNT = "kcs-v2-workload"


def _short_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def job_ref_for_provider_request(provider_request_id: str) -> str:
    """Return the stable Kubernetes Job name without exposing the opaque request ref."""
    return f"kcs-v2-{_short_hash(provider_request_id, 24)}"


def credential_secret_name(job_ref: str) -> str:
    """Return the predeclared deterministic Secret slot for one Job."""
    return f"kcs-v2-credential-{_short_hash(job_ref, 24)}"


class V2JobRenderer:
    def __init__(self, settings: V2RuntimeSettings) -> None:
        self._settings = settings

    def job_ref(self, request: CreateJobRequest) -> str:
        return job_ref_for_provider_request(request.provider_request_id)

    def render(self, request: CreateJobRequest) -> client.V1Job:
        spec = request.spec
        node_selector = spec.node_selector.as_mapping()
        if node_selector != dict(self._settings.node_selector):
            raise PolicyViolationError(
                "request nodeSelector must exactly match the configured selector"
            )

        job_ref = self.job_ref(request)
        labels = {
            "researchcosmos.io/managed-by": MANAGED_BY,
            "researchcosmos.io/provider-request-hash": _short_hash(request.provider_request_id),
            "researchcosmos.io/subject-hash": _short_hash(spec.subject_ref),
        }
        annotations = {
            "researchcosmos.io/provider-request-id": request.provider_request_id,
            "researchcosmos.io/subject-ref": spec.subject_ref,
            "researchcosmos.io/runtime-plan-digest": spec.runtime_plan_digest,
            "researchcosmos.io/spec-digest": request.spec_digest,
        }
        workspace_mount = client.V1VolumeMount(
            name=WORKSPACE_VOLUME,
            mount_path=WORKSPACE_MOUNT_PATH,
            read_only=False,
        )
        credential_mount = client.V1VolumeMount(
            name=CREDENTIAL_VOLUME,
            mount_path=CREDENTIAL_MOUNT_PATH,
            read_only=True,
        )

        containers = [
            client.V1Container(
                name="agent",
                image=spec.agent.image,
                image_pull_policy="IfNotPresent",
                command=list(spec.agent.command),
                env=self._environment(spec.agent.runtime_env),
                resources=self._agent_resources(
                    spec.agent.resources.cpu_millis,
                    spec.agent.resources.memory_mib,
                ),
                security_context=self._security_context(),
                volume_mounts=[workspace_mount, credential_mount],
            ),
            client.V1Container(
                name="workspace",
                image=spec.workspace.image,
                image_pull_policy="IfNotPresent",
                command=list(spec.workspace.command),
                env=self._environment(spec.workspace.runtime_env),
                resources=self._workspace_resources(
                    spec.workspace.resources.cpu_millis,
                    spec.workspace.resources.memory_mib,
                    spec.workspace.resources.gpu,
                ),
                security_context=self._security_context(),
                volume_mounts=[workspace_mount],
            ),
        ]
        volumes = [
            client.V1Volume(
                name=WORKSPACE_VOLUME,
                empty_dir=client.V1EmptyDirVolumeSource(
                    size_limit=f"{spec.shared_workspace.size_limit_gib}Gi"
                ),
            ),
            client.V1Volume(
                name=CREDENTIAL_VOLUME,
                secret=client.V1SecretVolumeSource(
                    secret_name=credential_secret_name(job_ref),
                    optional=True,
                    default_mode=0o400,
                ),
            ),
        ]
        pod_spec = client.V1PodSpec(
            containers=containers,
            volumes=volumes,
            restart_policy="Never",
            automount_service_account_token=False,
            service_account_name=WORKLOAD_SERVICE_ACCOUNT,
            node_selector=node_selector,
            host_network=False,
            host_pid=False,
            host_ipc=False,
            share_process_namespace=False,
            enable_service_links=False,
        )
        template = client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(labels=dict(labels), annotations=dict(annotations)),
            spec=pod_spec,
        )
        return client.V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=client.V1ObjectMeta(
                name=job_ref,
                namespace=self._settings.namespace,
                labels=labels,
                annotations=annotations,
            ),
            spec=client.V1JobSpec(
                template=template,
                completions=1,
                parallelism=1,
                # One replacement Pod remains the same KCS Job / Research
                # Attempt.  The provider records both immutable Pod UIDs and
                # requires explicit reattach before new workspace effects.
                backoff_limit=1,
                active_deadline_seconds=spec.active_deadline_seconds,
            ),
        )

    @staticmethod
    def _environment(environment: dict[str, str]) -> list[client.V1EnvVar]:
        return [
            client.V1EnvVar(name=name, value=value) for name, value in sorted(environment.items())
        ]

    @staticmethod
    def _security_context() -> client.V1SecurityContext:
        return client.V1SecurityContext(
            privileged=False,
            allow_privilege_escalation=False,
            read_only_root_filesystem=False,
        )

    @staticmethod
    def _agent_resources(cpu_millis: int, memory_mib: int) -> client.V1ResourceRequirements:
        resources = {"cpu": f"{cpu_millis}m", "memory": f"{memory_mib}Mi"}
        return client.V1ResourceRequirements(requests=dict(resources), limits=dict(resources))

    @staticmethod
    def _workspace_resources(
        cpu_millis: int,
        memory_mib: int,
        gpu: int,
    ) -> client.V1ResourceRequirements:
        resources = {"cpu": f"{cpu_millis}m", "memory": f"{memory_mib}Mi"}
        if gpu:
            resources["nvidia.com/gpu"] = str(gpu)
        return client.V1ResourceRequirements(requests=dict(resources), limits=dict(resources))
