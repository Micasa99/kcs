"""Pure renderer for the fixed KCS V2 dual-role Kubernetes Job."""

from __future__ import annotations

import hashlib
import json

from kubernetes import client  # type: ignore[import-untyped]

from .contracts import CreateJobRequest
from .native_contracts import NativeCreateJobRequest, ResolvedRuntimeRecipe
from .policy import PolicyViolationError
from .recipe_registry import NativeRecipeRegistry
from .settings import V2RuntimeSettings

MANAGED_BY = "v2-attempt-runtime"
WORKSPACE_VOLUME = "workspace"
CREDENTIAL_VOLUME = "agent-credential"
WORKSPACE_MOUNT_PATH = "/workspace"
CREDENTIAL_MOUNT_PATH = "/var/run/kcs/credential"
MODEL_GATEWAY_CREDENTIAL_VOLUME = "model-gateway-credential"
MODEL_GATEWAY_CREDENTIAL_MOUNT_PATH = "/var/run/rc/model-gateway"
PLATFORM_VOLUME = "rc-platform"
RUNNER_VOLUME = "rc-runner"
CONTROL_VOLUME = "rc-control"
USER_HOME_VOLUME = "rc-user-home"
USER_TMP_VOLUME = "rc-user-tmp"
TERMINAL_HOME_VOLUME = "rc-terminal-home"
TERMINAL_TMP_VOLUME = "rc-terminal-tmp"
WORKLOAD_SERVICE_ACCOUNT = "kcs-v2-workload"


def _short_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def job_ref_for_provider_request(provider_request_id: str) -> str:
    """Return the stable Kubernetes Job name without exposing the opaque request ref."""
    return f"kcs-v2-{_short_hash(provider_request_id, 24)}"


def credential_secret_name(job_ref: str) -> str:
    """Return the predeclared deterministic Secret slot for one Job."""
    return f"kcs-v2-credential-{_short_hash(job_ref, 24)}"


def runner_credential_secret_name(job_ref: str) -> str:
    """Return the independent native model-gateway Secret slot."""
    return f"kcs-v2-runner-credential-{_short_hash(job_ref, 24)}"


class V2JobRenderer:
    def __init__(
        self,
        settings: V2RuntimeSettings,
        recipe_registry: NativeRecipeRegistry | None = None,
    ) -> None:
        self._settings = settings
        self._recipes = recipe_registry or NativeRecipeRegistry(
            settings.native_recipe_registry_path
        )

    def job_ref(self, request: CreateJobRequest | NativeCreateJobRequest) -> str:
        return job_ref_for_provider_request(request.provider_request_id)

    def resolve_recipe(
        self, runner_ref: str, environment_profile_ref: str
    ) -> ResolvedRuntimeRecipe:
        return self._recipes.resolve(runner_ref, environment_profile_ref)

    def render(
        self,
        request: CreateJobRequest | NativeCreateJobRequest,
        *,
        native_recipe: ResolvedRuntimeRecipe | None = None,
    ) -> client.V1Job:
        if isinstance(request, NativeCreateJobRequest):
            return self._render_native(request, native_recipe=native_recipe)
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
                ephemeral=client.V1EphemeralVolumeSource(
                    volume_claim_template=client.V1PersistentVolumeClaimTemplate(
                        metadata=client.V1ObjectMeta(labels=dict(labels)),
                        spec=client.V1PersistentVolumeClaimSpec(
                            access_modes=["ReadWriteOnce"],
                            storage_class_name=(self._settings.workspace_storage_class),
                            resources=client.V1VolumeResourceRequirements(
                                requests={"storage": (f"{spec.shared_workspace.size_limit_gib}Gi")}
                            ),
                        ),
                    )
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

    def _render_native(
        self,
        request: NativeCreateJobRequest,
        *,
        native_recipe: ResolvedRuntimeRecipe | None = None,
    ) -> client.V1Job:
        spec = request.spec
        native = spec["native"]
        recipe = native_recipe or self._recipes.resolve(
            str(native["runnerRef"]), str(native["environmentProfileRef"])
        )
        if (
            recipe.runner_ref != str(native["runnerRef"])
            or recipe.environment_profile_ref != str(native["environmentProfileRef"])
        ):
            raise PolicyViolationError("frozen native recipe differs from the requested pair")
        self._validate_gateway(native["modelEnv"])
        if native["selectedModelProtocol"] not in recipe.root["supportedModelProtocols"]:
            raise PolicyViolationError(
                "selectedModelProtocol is not supported by the resolved runtime recipe"
            )
        delivery = recipe.root["delivery"]
        job_ref = self.job_ref(request)
        labels = {
            "researchcosmos.io/managed-by": MANAGED_BY,
            "researchcosmos.io/runtime-lane": "native",
            "researchcosmos.io/provider-request-hash": _short_hash(request.provider_request_id),
            "researchcosmos.io/subject-hash": _short_hash(str(spec["subjectRef"])),
        }
        hard_deadline = (
            self._settings.native_provision_seconds
            + int(native["runnerDeadlineSeconds"])
            + self._settings.native_capture_seconds
            + self._settings.native_finalize_seconds
        )
        annotations = {
            "researchcosmos.io/provider-request-id": request.provider_request_id,
            "researchcosmos.io/subject-ref": str(spec["subjectRef"]),
            "researchcosmos.io/runtime-plan-digest": str(spec["runtimePlanDigest"]),
            "researchcosmos.io/spec-digest": request.spec_digest,
            "researchcosmos.io/assembly-digest": str(native["assemblyDigest"]),
            "researchcosmos.io/recipe-ref": str(recipe.root["recipeRef"]),
            "researchcosmos.io/recipe-digest": str(recipe.root["recipeDigest"]),
            "researchcosmos.io/hard-deadline-seconds": str(hard_deadline),
        }
        volumes = self._native_volumes(
            job_ref,
            recipe,
            labels,
            workspace_size_gib=int(spec["sharedWorkspace"]["sizeLimitGiB"]),
            ephemeral_storage_mib=int(native["resources"]["ephemeralStorageMiB"]),
        )
        runtime_mounts = [
            client.V1VolumeMount(name=WORKSPACE_VOLUME, mount_path="/workspace"),
            client.V1VolumeMount(
                name=PLATFORM_VOLUME, mount_path="/opt/rc-platform", read_only=True
            ),
            client.V1VolumeMount(name=CONTROL_VOLUME, mount_path="/run/rc-control"),
            client.V1VolumeMount(
                name=MODEL_GATEWAY_CREDENTIAL_VOLUME,
                mount_path=MODEL_GATEWAY_CREDENTIAL_MOUNT_PATH,
                read_only=True,
            ),
            client.V1VolumeMount(name=USER_HOME_VOLUME, mount_path="/run/rc-user/home"),
            client.V1VolumeMount(name=USER_TMP_VOLUME, mount_path="/run/rc-user/tmp"),
            client.V1VolumeMount(name=TERMINAL_HOME_VOLUME, mount_path="/run/rc-terminal/home"),
            client.V1VolumeMount(name=TERMINAL_TMP_VOLUME, mount_path="/run/rc-terminal/tmp"),
        ]
        if delivery["mode"] == "assembled":
            runtime_mounts.append(
                client.V1VolumeMount(
                    name=RUNNER_VOLUME, mount_path="/opt/rc-runner", read_only=True
                )
            )
            runtime_image = delivery["environmentImageDigest"]
        else:
            runtime_image = delivery["prebuiltImageDigest"]
        model_env = dict(native["modelEnv"])
        launcher_env = {
            **model_env,
            "RC_NATIVE_RUNNER_ENTRYPOINT_JSON": json.dumps(
                recipe.root["runnerEntrypoint"], separators=(",", ":")
            ),
            "RC_NATIVE_TASK_PATH": str(native["taskPath"]),
            "RC_NATIVE_SELECTED_MODEL_PROTOCOL": str(native["selectedModelProtocol"]),
            "RC_NATIVE_RUNNER_REF": str(native["runnerRef"]),
            "RC_NATIVE_RUNNER_DEADLINE_SECONDS": str(native["runnerDeadlineSeconds"]),
            "RC_NATIVE_EPHEMERAL_STORAGE_MIB": str(
                native["resources"]["ephemeralStorageMiB"]
            ),
        }
        containers = [
            client.V1Container(
                name="runner",
                image=runtime_image,
                image_pull_policy="IfNotPresent",
                command=list(recipe.root["launcherCommand"]),
                env=self._environment(launcher_env),
                resources=self._native_runtime_resources(native["resources"]),
                security_context=self._native_runtime_security_context(),
                volume_mounts=runtime_mounts,
            ),
            client.V1Container(
                name="control",
                image=delivery["controlImageDigest"],
                image_pull_policy="IfNotPresent",
                command=list(recipe.root["controlCommand"]),
                env=self._environment(
                    {
                        "KCS_WORKSPACE": "/workspace",
                        "KCS_WORKSPACE_SOCKET": "/run/rc-control/workspace.sock",
                        "KCS_NATIVE_LAUNCHER_SOCKET": str(recipe.root["launcherSocketPath"]),
                        "KCS_NATIVE_RUNNER_STATE_PATH": "/run/rc-control/runner-state.json",
                        "TMPDIR": "/run/rc-control",
                    }
                ),
                resources=client.V1ResourceRequirements(
                    requests={"cpu": "250m", "memory": "256Mi", "ephemeral-storage": "256Mi"},
                    limits={"cpu": "1000m", "memory": "1Gi", "ephemeral-storage": "1Gi"},
                ),
                security_context=self._native_control_security_context(),
                volume_mounts=[
                    client.V1VolumeMount(name=WORKSPACE_VOLUME, mount_path="/workspace"),
                    client.V1VolumeMount(name=CONTROL_VOLUME, mount_path="/run/rc-control"),
                ],
            ),
        ]
        pod_spec = client.V1PodSpec(
            containers=containers,
            volumes=volumes,
            restart_policy="Never",
            automount_service_account_token=False,
            service_account_name=WORKLOAD_SERVICE_ACCOUNT,
            node_selector=dict(self._settings.node_selector),
            host_network=False,
            host_pid=False,
            host_ipc=False,
            share_process_namespace=False,
            enable_service_links=False,
            security_context=client.V1PodSecurityContext(
                seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault")
            ),
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
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(labels=dict(labels), annotations=annotations),
                    spec=pod_spec,
                ),
                completions=1,
                parallelism=1,
                backoff_limit=0,
                active_deadline_seconds=hard_deadline,
            ),
        )

    def _native_volumes(
        self,
        job_ref: str,
        recipe: ResolvedRuntimeRecipe,
        labels: dict[str, str],
        *,
        workspace_size_gib: int,
        ephemeral_storage_mib: int,
    ) -> list[client.V1Volume]:
        delivery = recipe.root["delivery"]
        if ephemeral_storage_mib < 512:
            raise PolicyViolationError(
                "native ephemeralStorageMiB must leave room for control and logs"
            )
        private_volume_budget = (ephemeral_storage_mib * 3) // 4
        fixed_private_budget = 192
        user_budget = private_volume_budget - fixed_private_budget
        user_home_mib = user_budget // 2
        user_tmp_mib = user_budget - user_home_mib
        volumes = [
            client.V1Volume(
                name=WORKSPACE_VOLUME,
                ephemeral=client.V1EphemeralVolumeSource(
                    volume_claim_template=client.V1PersistentVolumeClaimTemplate(
                        metadata=client.V1ObjectMeta(labels=dict(labels)),
                        spec=client.V1PersistentVolumeClaimSpec(
                            access_modes=["ReadWriteOnce"],
                            storage_class_name=self._settings.workspace_storage_class,
                            resources=client.V1VolumeResourceRequirements(
                                requests={"storage": f"{workspace_size_gib}Gi"}
                            ),
                        ),
                    )
                ),
            ),
            client.V1Volume(
                name=PLATFORM_VOLUME,
                image=client.V1ImageVolumeSource(
                    reference=delivery["platformImageVolumeDigest"], pull_policy="IfNotPresent"
                ),
            ),
            client.V1Volume(
                name=MODEL_GATEWAY_CREDENTIAL_VOLUME,
                secret=client.V1SecretVolumeSource(
                    secret_name=runner_credential_secret_name(job_ref),
                    optional=True,
                    default_mode=0o400,
                    items=[client.V1KeyToPath(key="token", path="token", mode=0o400)],
                ),
            ),
            client.V1Volume(
                name=CONTROL_VOLUME,
                empty_dir=client.V1EmptyDirVolumeSource(size_limit="64Mi"),
            ),
            client.V1Volume(
                name=USER_HOME_VOLUME,
                empty_dir=client.V1EmptyDirVolumeSource(size_limit=f"{user_home_mib}Mi"),
            ),
            client.V1Volume(
                name=USER_TMP_VOLUME,
                empty_dir=client.V1EmptyDirVolumeSource(size_limit=f"{user_tmp_mib}Mi"),
            ),
            client.V1Volume(
                name=TERMINAL_HOME_VOLUME,
                empty_dir=client.V1EmptyDirVolumeSource(size_limit="64Mi"),
            ),
            client.V1Volume(
                name=TERMINAL_TMP_VOLUME,
                empty_dir=client.V1EmptyDirVolumeSource(size_limit="64Mi"),
            ),
        ]
        if delivery["mode"] == "assembled":
            volumes.append(
                client.V1Volume(
                    name=RUNNER_VOLUME,
                    image=client.V1ImageVolumeSource(
                        reference=delivery["runnerImageVolumeDigest"],
                        pull_policy="IfNotPresent",
                    ),
                )
            )
        return volumes

    def _validate_gateway(self, model_env: dict[str, str]) -> None:
        if (
            self._settings.model_gateway_openai_base_url is None
            or self._settings.model_gateway_anthropic_base_url is None
        ):
            raise PolicyViolationError("native model gateway endpoints are not configured")
        if (
            model_env["OPENAI_BASE_URL"].rstrip("/") != self._settings.model_gateway_openai_base_url
            or model_env["ANTHROPIC_BASE_URL"].rstrip("/")
            != self._settings.model_gateway_anthropic_base_url
        ):
            raise PolicyViolationError("native model gateway endpoints differ from policy")

    @staticmethod
    def _native_runtime_resources(resources: dict[str, object]) -> client.V1ResourceRequirements:
        cpu = int(resources["cpuMillis"])
        memory = int(resources["memoryMiB"])
        ephemeral = int(resources["ephemeralStorageMiB"])
        requests = {
            "cpu": f"{cpu}m",
            "memory": f"{memory}Mi",
            "ephemeral-storage": f"{ephemeral}Mi",
        }
        limits = {
            "cpu": f"{min(cpu * 2, 64000)}m",
            "memory": f"{min(memory * 2, 262144)}Mi",
            "ephemeral-storage": f"{min(ephemeral * 2, 262144)}Mi",
        }
        accelerator = resources["accelerator"]
        if isinstance(accelerator, dict) and accelerator.get("kind") == "nvidia-gpu":
            count = str(accelerator["count"])
            requests["nvidia.com/gpu"] = count
            limits["nvidia.com/gpu"] = count
        return client.V1ResourceRequirements(requests=requests, limits=limits)

    @staticmethod
    def _native_runtime_security_context() -> client.V1SecurityContext:
        return client.V1SecurityContext(
            run_as_user=0,
            run_as_group=0,
            privileged=False,
            allow_privilege_escalation=False,
            read_only_root_filesystem=True,
            # CHOWN is launcher-only: staging and the writable volume roots are
            # created by kubelet/control as uid 0, then handed to the exact
            # experiment identity before exec. The child transition below
            # still clears every group/capability and verifies CapEff=0.
            capabilities=client.V1Capabilities(
                drop=["ALL"], add=["CHOWN", "SETUID", "SETGID", "KILL"]
            ),
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        )

    @staticmethod
    def _native_control_security_context() -> client.V1SecurityContext:
        return client.V1SecurityContext(
            run_as_user=0,
            run_as_group=0,
            privileged=False,
            allow_privilege_escalation=False,
            read_only_root_filesystem=True,
            capabilities=client.V1Capabilities(drop=["ALL"], add=["CHOWN", "DAC_OVERRIDE"]),
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
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
