"""Pure renderer for the fixed KCS V2 dual-role Kubernetes Job."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit, urlunsplit

from kubernetes import client  # type: ignore[import-untyped]

from .canonical import canonical_digest
from .contracts import CreateJobRequest, NetworkClass
from .m2_contracts import CapabilityActivationPlan
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
PLATFORM_CA_VOLUME = "platform-ca"
PLATFORM_CA_MOUNT_PATH = "/var/run/rc-platform-ca/ca.crt"
RUNNER_VOLUME = "rc-runner"
CONTROL_VOLUME = "rc-control"
USER_HOME_VOLUME = "rc-user-home"
USER_TMP_VOLUME = "rc-user-tmp"
TERMINAL_HOME_VOLUME = "rc-terminal-home"
TERMINAL_TMP_VOLUME = "rc-terminal-tmp"
OPENVSCODE_VOLUME = "rc-openvscode"
DEV_SESSION_CREDENTIAL_VOLUME = "rc-dev-session-credential"
PUBLIC_EGRESS_EXCEPT = {
    "0.0.0.0/0": [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ],
    "::/0": ["::/128", "::1/128", "fc00::/7", "fe80::/10"],
}


def _short_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def _product_base_from_gateway(openai_base_url: str) -> str:
    """Recover the same-origin Product base from RC's frozen gateway URL."""

    suffix = "/model-gateway/openai/v1"
    parsed = urlsplit(openai_base_url.rstrip("/"))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    path = parsed.path.rstrip("/")
    if not path.endswith(suffix):
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, path[: -len(suffix)], "", ""))


def _native_control_volume_mib(ephemeral_storage_mib: int) -> int:
    """Reserve a bounded share of the declared budget for raw runner evidence."""

    return max(128, min(8192, ephemeral_storage_mib // 4))


def job_ref_for_provider_request(provider_request_id: str, resource_prefix: str = "kcs-v2") -> str:
    """Return the stable Kubernetes Job name without exposing the opaque request ref."""
    return f"{resource_prefix}-{_short_hash(provider_request_id, 24)}"


def _resource_prefix(job_ref: str) -> str:
    prefix, separator, digest = job_ref.rpartition("-")
    if not separator or len(digest) != 24:
        raise ValueError("Job reference has no resource prefix")
    return prefix


def network_policy_ref(job_ref: str) -> str:
    return f"{_resource_prefix(job_ref)}-network-{_short_hash(job_ref, 24)}"


def network_policy_spec_digest(policy: object) -> str:
    payload = client.ApiClient().sanitize_for_serialization(policy)
    if not isinstance(payload, dict) or not isinstance(payload.get("spec"), dict):
        raise ValueError("NetworkPolicy has no serializable spec")
    return canonical_digest(payload["spec"])


def credential_secret_name(job_ref: str) -> str:
    """Return the predeclared deterministic Secret slot for one Job."""
    return f"{_resource_prefix(job_ref)}-credential-{_short_hash(job_ref, 24)}"


def runner_credential_secret_name(job_ref: str) -> str:
    """Return the independent native model-gateway Secret slot."""
    return f"{_resource_prefix(job_ref)}-runner-credential-{_short_hash(job_ref, 24)}"


def dev_session_secret_name(job_ref: str) -> str:
    """Return the stable internal credential mounted by the relay sidecar."""
    return f"{_resource_prefix(job_ref)}-dev-session-{_short_hash(job_ref, 24)}"


def dev_session_browser_secret_name(job_ref: str) -> str:
    """Return the KCS-only browser-session Secret slot."""
    return f"{_resource_prefix(job_ref)}-dev-browser-{_short_hash(job_ref, 24)}"


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

    @property
    def platform_ca_mount_enabled(self) -> bool:
        return self._settings.platform_ca_secret is not None

    def job_ref(self, request: CreateJobRequest | NativeCreateJobRequest) -> str:
        return job_ref_for_provider_request(
            request.provider_request_id, self._settings.resource_prefix
        )

    def resolve_recipe(
        self, runner_ref: str, environment_profile_ref: str
    ) -> ResolvedRuntimeRecipe:
        return self._recipes.resolve(runner_ref, environment_profile_ref)

    def render_network_policy(
        self, request: CreateJobRequest | NativeCreateJobRequest
    ) -> dict[str, object]:
        job_ref = self.job_ref(request)
        requested_class = (
            str(request.spec["networkClass"])
            if isinstance(request, NativeCreateJobRequest)
            else request.spec.network_class.value
        )
        if requested_class not in {NetworkClass.NONE.value, NetworkClass.RESTRICTED.value}:
            raise PolicyViolationError("networkClass must be none or restricted")
        selector = {
            "researchcosmos.io/managed-by": MANAGED_BY,
            "researchcosmos.io/provider-request-hash": _short_hash(
                request.provider_request_id
            ),
        }
        ingress = []
        if isinstance(request, NativeCreateJobRequest):
            ingress = [
                {
                    "from": [
                        {
                            "podSelector": {
                                "matchLabels": {
                                    "app.kubernetes.io/name": self._settings.api_selector_name
                                }
                            }
                        }
                    ],
                    "ports": [{"protocol": "TCP", "port": 8080}],
                }
            ]
        egress: list[dict[str, object]] = [
            {
                "to": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                        },
                        "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                    }
                ],
                "ports": [
                    {"protocol": "UDP", "port": 53},
                    {"protocol": "TCP", "port": 53},
                ],
            }
        ]
        ip_blocks = []
        for cidr in self._settings.platform_egress_cidrs:
            public_exclusions = PUBLIC_EGRESS_EXCEPT.get(cidr)
            if (
                public_exclusions is not None
                and requested_class != NetworkClass.RESTRICTED.value
            ):
                continue
            block: dict[str, object] = {"cidr": cidr}
            if public_exclusions is not None:
                block["except"] = public_exclusions
            ip_blocks.append({"ipBlock": block})
        if ip_blocks:
            egress.append(
                {
                    "to": ip_blocks,
                    "ports": [{"protocol": "TCP", "port": 443}],
                }
            )
        spec: dict[str, object] = {
            "podSelector": {"matchLabels": selector},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": ingress,
            "egress": egress,
        }
        policy_ref = network_policy_ref(job_ref)
        annotations = {
            "researchcosmos.io/provider-request-id": request.provider_request_id,
            "researchcosmos.io/job-ref": job_ref,
            "researchcosmos.io/job-spec-digest": request.spec_digest,
            "researchcosmos.io/requested-network-class": requested_class,
        }
        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": policy_ref,
                "namespace": self._settings.namespace,
                "labels": selector,
                "annotations": annotations,
            },
            "spec": spec,
        }
        annotations["researchcosmos.io/network-policy-spec-digest"] = (
            network_policy_spec_digest(policy)
        )
        return policy

    def render(
        self,
        request: CreateJobRequest | NativeCreateJobRequest,
        *,
        native_recipe: ResolvedRuntimeRecipe | None = None,
        activation_plan: CapabilityActivationPlan | None = None,
    ) -> client.V1Job:
        if isinstance(request, NativeCreateJobRequest):
            return self._render_native(
                request,
                native_recipe=native_recipe,
                activation_plan=activation_plan,
            )
        spec = request.spec
        if spec.workspace.resources.gpu > self._settings.max_gpu_per_job:
            raise PolicyViolationError("requested GPU count exceeds the configured maximum")
        if spec.active_deadline_seconds > self._settings.max_job_deadline_seconds:
            raise PolicyViolationError("requested deadline exceeds the configured maximum")
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
            "researchcosmos.io/requested-network-class": spec.network_class.value,
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
            service_account_name=self._settings.workload_service_account,
            priority_class_name=self._settings.workload_priority_class,
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
        activation_plan: CapabilityActivationPlan | None = None,
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
        accelerator = native["resources"]["accelerator"]
        gpu_count = (
            int(accelerator["count"])
            if isinstance(accelerator, dict) and accelerator.get("kind") == "nvidia-gpu"
            else 0
        )
        if gpu_count > self._settings.max_gpu_per_job:
            raise PolicyViolationError("requested GPU count exceeds the configured maximum")
        if hard_deadline > self._settings.max_job_deadline_seconds:
            raise PolicyViolationError("requested deadline exceeds the configured maximum")
        annotations = {
            "researchcosmos.io/provider-request-id": request.provider_request_id,
            "researchcosmos.io/subject-ref": str(spec["subjectRef"]),
            "researchcosmos.io/runtime-plan-digest": str(spec["runtimePlanDigest"]),
            "researchcosmos.io/spec-digest": request.spec_digest,
            "researchcosmos.io/requested-network-class": str(spec["networkClass"]),
            "researchcosmos.io/assembly-digest": str(native["assemblyDigest"]),
            "researchcosmos.io/recipe-ref": str(recipe.root["recipeRef"]),
            "researchcosmos.io/recipe-digest": str(recipe.root["recipeDigest"]),
            "researchcosmos.io/hard-deadline-seconds": str(hard_deadline),
        }
        if activation_plan is not None:
            annotations.update(
                {
                    "researchcosmos.io/capability-plan-ref": str(
                        activation_plan.root["planRef"]
                    ),
                    "researchcosmos.io/capability-plan-digest": str(
                        activation_plan.root["planDigest"]
                    ),
                }
            )
        volumes = self._native_volumes(
            job_ref,
            recipe,
            labels,
            workspace_size_gib=int(spec["sharedWorkspace"]["sizeLimitGiB"]),
            ephemeral_storage_mib=int(native["resources"]["ephemeralStorageMiB"]),
            activation_plan=activation_plan,
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
        control_mounts = [
            client.V1VolumeMount(name=WORKSPACE_VOLUME, mount_path="/workspace"),
            client.V1VolumeMount(name=CONTROL_VOLUME, mount_path="/run/rc-control"),
        ]
        platform_ca_env: dict[str, str] = {}
        if self._settings.platform_ca_secret is not None:
            platform_ca_mount = client.V1VolumeMount(
                name=PLATFORM_CA_VOLUME,
                mount_path=PLATFORM_CA_MOUNT_PATH,
                sub_path="ca.crt",
                read_only=True,
            )
            runtime_mounts.append(platform_ca_mount)
            control_mounts.append(platform_ca_mount)
            platform_ca_env = {
                "NODE_EXTRA_CA_CERTS": PLATFORM_CA_MOUNT_PATH,
            }
        if delivery["mode"] == "assembled":
            runtime_mounts.append(
                client.V1VolumeMount(
                    name=RUNNER_VOLUME, mount_path="/opt/rc-runner", read_only=True
                )
            )
            runtime_image = delivery["environmentImageDigest"]
        else:
            runtime_image = delivery["prebuiltImageDigest"]
        activation_mounts = (
            list(activation_plan.root["mounts"]) if activation_plan is not None else []
        )
        for mount in activation_mounts:
            source_path = str(mount["sourcePath"])
            runtime_mounts.append(
                client.V1VolumeMount(
                    name=activation_volume_name(mount),
                    mount_path=str(mount["targetPath"]),
                    read_only=True,
                    sub_path=(source_path.lstrip("/") or None),
                )
            )
        model_env = dict(native["modelEnv"])
        product_base = _product_base_from_gateway(model_env.get("OPENAI_BASE_URL", ""))
        launcher_env = {
            **model_env,
            **platform_ca_env,
            "COSMOS_INPUTS_DIR": "/workspace/inputs",
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
        if activation_plan is not None:
            launcher_env.update(
                {
                    "RC_NATIVE_CAPABILITY_PLAN_DIGEST": str(
                        activation_plan.root["planDigest"]
                    ),
                    "RC_NATIVE_SKILL_DISCOVERY_PATHS_JSON": json.dumps(
                        [
                            str(item["runnerDiscoveryPath"])
                            for item in activation_mounts
                            if item["kind"] == "skill"
                        ],
                        separators=(",", ":"),
                    ),
                    "RC_NATIVE_TOOL_DISCOVERY_PATHS_JSON": json.dumps(
                        [
                            str(item["runnerDiscoveryPath"])
                            for item in activation_mounts
                            if item["kind"] == "tool"
                        ],
                        separators=(",", ":"),
                    ),
                }
            )
        control_volume_mib = _native_control_volume_mib(
            int(native["resources"]["ephemeralStorageMiB"])
        )
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
                        **platform_ca_env,
                        "KCS_WORKSPACE": "/workspace",
                        "KCS_WORKSPACE_SOCKET": "/run/rc-control/workspace.sock",
                        "KCS_NATIVE_LAUNCHER_SOCKET": str(recipe.root["launcherSocketPath"]),
                        "KCS_NATIVE_RUNNER_STATE_PATH": "/run/rc-control/runner-state.json",
                        "TMPDIR": "/run/rc-control",
                        "AICOSMOS_ATTEMPT_REF": str(spec["subjectRef"]),
                        "AICOSMOS_PRODUCT_BASE": product_base,
                    }
                ),
                resources=client.V1ResourceRequirements(
                    requests={
                        "cpu": "250m",
                        "memory": "256Mi",
                        "ephemeral-storage": f"{min(256, control_volume_mib)}Mi",
                    },
                    limits={
                        "cpu": "1000m",
                        "memory": "1Gi",
                        "ephemeral-storage": f"{control_volume_mib}Mi",
                    },
                ),
                security_context=self._native_control_security_context(),
                volume_mounts=control_mounts,
            ),
        ]
        dev_sidecars = (
            self._native_dev_session_sidecars(recipe, runtime_image, job_ref)
            if self._settings.native_openvscode_image_volume is not None
            else []
        )
        pod_spec = client.V1PodSpec(
            containers=containers,
            init_containers=dev_sidecars or None,
            volumes=volumes,
            restart_policy="Never",
            automount_service_account_token=False,
            service_account_name=self._settings.workload_service_account,
            priority_class_name=self._settings.workload_priority_class,
            node_selector=dict(self._settings.node_selector),
            host_network=False,
            host_pid=False,
            host_ipc=False,
            share_process_namespace=False,
            enable_service_links=False,
            security_context=client.V1PodSecurityContext(
                seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
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
        activation_plan: CapabilityActivationPlan | None,
    ) -> list[client.V1Volume]:
        delivery = recipe.root["delivery"]
        if ephemeral_storage_mib < 512:
            raise PolicyViolationError(
                "native ephemeralStorageMiB must leave room for control and logs"
            )
        private_volume_budget = (ephemeral_storage_mib * 3) // 4
        control_volume_mib = _native_control_volume_mib(ephemeral_storage_mib)
        fixed_private_budget = control_volume_mib + 128
        user_budget = private_volume_budget - fixed_private_budget
        if user_budget < 128:
            raise PolicyViolationError(
                "native ephemeralStorageMiB leaves no writable HOME/TMP budget"
            )
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
                # Runner evidence and control state grow with the real session.  A
                # per-volume cap can evict an otherwise healthy Attempt before
                # capture; Pod/container ephemeral-storage remains the authority.
                empty_dir=client.V1EmptyDirVolumeSource(),
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
        if self._settings.platform_ca_secret is not None:
            volumes.append(
                client.V1Volume(
                    name=PLATFORM_CA_VOLUME,
                    secret=client.V1SecretVolumeSource(
                        secret_name=self._settings.platform_ca_secret,
                        optional=False,
                        default_mode=0o444,
                        items=[client.V1KeyToPath(key="ca.crt", path="ca.crt", mode=0o444)],
                    ),
                )
            )
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
        if self._settings.native_openvscode_image_volume is not None:
            volumes.extend(
                [
                    client.V1Volume(
                        name=OPENVSCODE_VOLUME,
                        image=client.V1ImageVolumeSource(
                            reference=self._settings.native_openvscode_image_volume,
                            pull_policy="IfNotPresent",
                        ),
                    ),
                    client.V1Volume(
                        name=DEV_SESSION_CREDENTIAL_VOLUME,
                        secret=client.V1SecretVolumeSource(
                            secret_name=dev_session_secret_name(job_ref),
                            optional=False,
                            default_mode=0o400,
                        ),
                    ),
                ]
            )
        if activation_plan is not None:
            for mount in activation_plan.root["mounts"]:
                volumes.append(
                    client.V1Volume(
                        name=activation_volume_name(mount),
                        image=client.V1ImageVolumeSource(
                            reference=str(mount["imageVolumeDigest"]),
                            pull_policy="IfNotPresent",
                        ),
                    )
                )
        return volumes

    def _native_dev_session_sidecars(
        self, recipe: ResolvedRuntimeRecipe, runtime_image: str, job_ref: str
    ) -> list[client.V1Container]:
        """Add the remotely proven OpenVSCode and credential-gating native sidecars.

        Kubernetes 1.36 terminates ``restartPolicy: Always`` init sidecars after
        runner/control finish, so they cannot keep the Job alive.  Only relay sees
        the dev credential; OpenVSCode owns no platform secret and stays loopback.
        """

        del recipe
        relay_image = self._settings.native_dev_session_relay_image
        if relay_image is None:
            raise PolicyViolationError("native dev-session relay image is not configured")
        terminal_identity = client.V1SecurityContext(
            run_as_user=10002,
            run_as_group=10001,
            privileged=False,
            allow_privilege_escalation=False,
            read_only_root_filesystem=True,
            capabilities=client.V1Capabilities(drop=["ALL"]),
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        )
        # The relay is the sole consumer of the root-owned 0400 session
        # credential.  It has no workspace mount, no service-account token and
        # no capabilities; OpenVSCode remains the unprivileged terminal user.
        relay_identity = client.V1SecurityContext(
            run_as_user=0,
            run_as_group=0,
            privileged=False,
            allow_privilege_escalation=False,
            read_only_root_filesystem=True,
            capabilities=client.V1Capabilities(drop=["ALL"]),
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        )
        return [
            client.V1Container(
                name="openvscode",
                image=runtime_image,
                image_pull_policy="IfNotPresent",
                # OpenVSCode 1.109 has no positional/default-folder CLI
                # contract. Product supplies the standard `?folder=` web
                # query so every browser entry opens the frozen worktree.
                command=[
                    "/opt/rc-dev/openvscode/bin/openvscode-server",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "3000",
                    "--without-connection-token",
                    "--accept-server-license-terms",
                    "--telemetry-level",
                    "off",
                    "--server-data-dir",
                    "/run/rc-terminal/home/.openvscode-server",
                    "--user-data-dir",
                    "/run/rc-terminal/home/.openvscode-user",
                    "--extensions-dir",
                    "/run/rc-terminal/home/.openvscode-extensions",
                ],
                env=self._environment(
                    {
                        "HOME": "/run/rc-terminal/home",
                        "TMPDIR": "/run/rc-terminal/tmp",
                        "RC_OPENVSCODE_BINARY": (
                            "/opt/rc-dev/openvscode/bin/openvscode-server"
                        ),
                    }
                ),
                resources=client.V1ResourceRequirements(
                    requests={"cpu": "250m", "memory": "512Mi", "ephemeral-storage": "512Mi"},
                    limits={"cpu": "2", "memory": "2Gi", "ephemeral-storage": "2Gi"},
                ),
                security_context=terminal_identity,
                restart_policy="Always",
                volume_mounts=[
                    client.V1VolumeMount(name=WORKSPACE_VOLUME, mount_path="/workspace"),
                    client.V1VolumeMount(
                        name=TERMINAL_HOME_VOLUME, mount_path="/run/rc-terminal/home"
                    ),
                    client.V1VolumeMount(
                        name=TERMINAL_TMP_VOLUME, mount_path="/run/rc-terminal/tmp"
                    ),
                    client.V1VolumeMount(
                        name=OPENVSCODE_VOLUME, mount_path="/opt/rc-dev", read_only=True
                    ),
                ],
            ),
            client.V1Container(
                name="relay",
                image=relay_image,
                image_pull_policy="IfNotPresent",
                env=self._environment(
                    {
                        "LISTEN_ADDR": ":8080",
                        "UPSTREAM_URL": "http://127.0.0.1:3000",
                        "DEV_SESSION_CREDENTIAL_FILE": "/run/dev-session/credential",
                    }
                ),
                ports=[client.V1ContainerPort(name="dev-relay", container_port=8080)],
                resources=client.V1ResourceRequirements(
                    requests={"cpu": "50m", "memory": "32Mi", "ephemeral-storage": "32Mi"},
                    limits={"cpu": "250m", "memory": "128Mi", "ephemeral-storage": "128Mi"},
                ),
                security_context=relay_identity,
                restart_policy="Always",
                volume_mounts=[
                    client.V1VolumeMount(
                        name=DEV_SESSION_CREDENTIAL_VOLUME,
                        mount_path="/run/dev-session",
                        read_only=True,
                    )
                ],
            ),
        ]

    def _validate_gateway(self, model_env: dict[str, str]) -> None:
        if (
            not self._settings.model_gateway_openai_base_urls
            or not self._settings.model_gateway_anthropic_base_urls
        ):
            raise PolicyViolationError("native model gateway endpoints are not configured")
        if (
            model_env["OPENAI_BASE_URL"].rstrip("/")
            not in self._settings.model_gateway_openai_base_urls
            or model_env["ANTHROPIC_BASE_URL"].rstrip("/")
            not in self._settings.model_gateway_anthropic_base_urls
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
            "cpu": f"{cpu}m",
            "memory": f"{memory}Mi",
            "ephemeral-storage": f"{ephemeral}Mi",
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


def activation_volume_name(mount: dict[str, object]) -> str:
    identity = ":".join(
        (
            str(mount["kind"]),
            str(mount["capabilityRef"]),
            str(mount["materialDigest"]),
        )
    )
    return f"rc-cap-{_short_hash(identity, 24)}"
