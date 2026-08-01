"""Simplified wrapper over the Kubernetes API.

Translates Docker-like operations into Kubernetes API calls.
"""

from __future__ import annotations

import os
import time

from kubernetes import client, config
from kubernetes.client import ApiException

from kcs.legacy_guard import (
    V2_EXCLUSION_SELECTOR,
    LegacyTargetForbiddenError,
    assert_legacy_target_allowed,
)

"""Status constants."""
STATUS_RUNNING = "running"
STATUS_STOPPED = "stopped"
STATUS_PENDING = "pending"
STATUS_TERMINATING = "terminating"
STATUS_ERROR = "error"
STATUS_UNKNOWN = "unknown"

# ── Labels and naming conventions ────────────────────────────────

MANAGED_BY = "kcs"  # value for app.kubernetes.io/managed-by
LABEL_MANAGED_BY = "app.kubernetes.io/managed-by"
LABEL_APP = "app"

# Naming conventions
DEPLOYMENT_PREFIX = "kcs-"
SERVICE_SUFFIX = "-svc"


def _format_memory(value: str) -> str:
    """Convert Kubernetes memory format to human-readable. e.g. '255639780Ki' → '244Gi'"""
    try:
        if value.endswith("Ki"):
            kib = int(value[:-2])
            if kib >= 1024**2:
                return f"{kib / 1024**2:.0f}Gi"
            elif kib >= 1024:
                return f"{kib / 1024:.0f}Mi"
            else:
                return f"{kib}Ki"
        if value.endswith("Mi"):
            return value
        if value.endswith("Gi"):
            return value
        # Bare number treated as bytes
        b = int(value)
        if b >= 1024**3:
            return f"{b / 1024**3:.0f}Gi"
        if b >= 1024**2:
            return f"{b / 1024**2:.0f}Mi"
        return f"{b / 1024:.0f}Ki"
    except (ValueError, TypeError):
        return value


def _cpu_cores(v: str) -> float:
    """K8s CPU string to float cores. '500m' → 0.5, '2' → 2.0"""
    if not v:
        return 0.0
    v = str(v)
    if v.endswith("m"):
        return float(v[:-1]) / 1000
    return float(v)


def _mem_bytes(v: str) -> int:
    """K8s memory string to bytes."""
    if not v:
        return 0
    v = str(v)
    v = v.strip()
    if v.endswith("Ki"):
        return int(v[:-2]) * 1024
    if v.endswith("Mi"):
        return int(v[:-2]) * 1024 * 1024
    if v.endswith("Gi"):
        return int(v[:-2]) * 1024 * 1024 * 1024
    if v.endswith("Ti"):
        return int(v[:-2]) * 1024 * 1024 * 1024 * 1024
    if v.endswith("m"):
        return int(int(v[:-1]) / 1000)
    # Bare number = bytes (from kubelet)
    try:
        b = int(v)
        if b > 1024**4:  # probably bytes
            return b
    except ValueError:
        pass
    return 0


class KCSClient:
    """Simplified client wrapping the Kubernetes API.

    Usage:
        client = KCSClient()
        client.create("my-nginx", "nginx:latest", ports=[80])
        containers = client.list()
        client.logs("my-nginx")
    """

    def __init__(
        self,
        namespace: str = "default",
        kubeconfig: str | None = None,
        context: str | None = None,
    ):
        self.namespace = namespace

        # Load kubeconfig (in-cluster and out-of-cluster)
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                if kubeconfig:
                    config.load_kube_config(config_file=kubeconfig, context=context)
                else:
                    config.load_kube_config(context=context)
            except config.ConfigException:
                # Try k3s default path
                k3s_cfg = "/etc/rancher/k3s/k3s.yaml"
                if os.path.exists(k3s_cfg):
                    if os.access(k3s_cfg, os.R_OK):
                        config.load_kube_config(config_file=k3s_cfg, context=context)
                    else:
                        raise RuntimeError(
                            f"k3s config file not readable: {k3s_cfg}\n\n"
                            "Fix:\n"
                            f"  sudo chmod 644 {k3s_cfg}\n"
                            "Or:\n"
                            f"  sudo cp {k3s_cfg} ~/.kube/config && sudo chown $USER ~/.kube/config"
                        ) from None
                else:
                    raise RuntimeError(
                        "No k3s/k8s cluster config found.\n\n"
                        "Quick start a local cluster:\n"
                        "  k3d cluster create kcs-dev    # create with k3d (recommended)\n"
                        "  curl -sfL https://get.k3s.io | sh -  # or install k3s directly\n\n"
                        "Install k3d:\n"
                        "  curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/"
                        "install.sh | bash"
                    ) from None

        self.apps_v1 = client.AppsV1Api()
        self.core_v1 = client.CoreV1Api()
        self._kubeconfig = kubeconfig

    # ── Resource naming ───────────────────────────────────────

    @staticmethod
    def deployment_name(name: str) -> str:
        return f"{DEPLOYMENT_PREFIX}{name}"

    @staticmethod
    def service_name(name: str) -> str:
        return f"{DEPLOYMENT_PREFIX}{name}{SERVICE_SUFFIX}"

    @staticmethod
    def labels(name: str) -> dict[str, str]:
        return {LABEL_MANAGED_BY: MANAGED_BY, LABEL_APP: name}

    # ── Container operations ───────────────────────────────────

    def create(
        self,
        name: str,
        image: str,
        ports: list[int] | None = None,
        env: dict[str, str] | None = None,
        volumes: list[dict[str, str]] | None = None,
        replicas: int = 1,
        command: list[str] | None = None,
        args: list[str] | None = None,
        node: str | None = None,
        gpus: int | None = None,
        cpu: str | None = None,
        memory: str | None = None,
    ) -> dict:
        """Create a "container" (backed by a Deployment or StatefulSet + Service).

        PVC volumes ({'path': ...}) automatically use StatefulSet so each Pod has
        independent storage.
        node pins the Pod to a specific node name.
        gpus/cpu/memory set requests=limits for exclusive allocation.
        """
        self._assert_legacy_namespace()
        res_name = self.deployment_name(name)
        labels = self.labels(name)

        # Detect whether to use StatefulSet
        has_pvc = any("path" in v for v in (volumes or []))

        # Build container definition
        # kcs-built images are imported locally under k3s — no pull needed;
        # public images still need IfNotPresent.
        from kcs.config import get_registry as _reg
        from kcs.config import is_built_image as _is_built

        if _is_built(image) and not _reg():
            pull_policy = "Never"
        else:
            pull_policy = "IfNotPresent"
        container = client.V1Container(
            name=name,
            image=image,
            image_pull_policy=pull_policy,
            env=[client.V1EnvVar(name=k, value=v) for k, v in (env or {}).items()],
            ports=[client.V1ContainerPort(container_port=p) for p in (ports or [])],
            command=command,
            args=args,
            resources=self._build_resources(gpus, cpu, memory),
        )

        pod_spec = client.V1PodSpec(containers=[container])
        if node:
            pod_spec.node_selector = {"kubernetes.io/hostname": node}
        volume_mounts = []
        k8s_volumes = []
        pvc_templates = []

        if volumes:
            for i, v in enumerate(volumes):
                vol_name = f"kcs-vol-{i}"
                if "host" in v:
                    k8s_volumes.append(
                        client.V1Volume(
                            name=vol_name,
                            host_path=client.V1HostPathVolumeSource(path=v["host"]),
                        )
                    )
                    volume_mounts.append(
                        client.V1VolumeMount(name=vol_name, mount_path=v["container"])
                    )
                else:
                    container_path = v["path"]
                    if has_pvc:
                        # StatefulSet: volumeClaimTemplate
                        volume_mounts.append(
                            client.V1VolumeMount(name=f"data-{i}", mount_path=container_path)
                        )
                        pvc_templates.append(
                            client.V1PersistentVolumeClaim(
                                metadata=client.V1ObjectMeta(name=f"data-{i}"),
                                spec=client.V1PersistentVolumeClaimSpec(
                                    access_modes=["ReadWriteOnce"],
                                    resources=client.V1VolumeResourceRequirements(
                                        requests={"storage": "1Gi"}
                                    ),
                                ),
                            )
                        )
                    else:
                        # Deployment: shared PVC
                        pvc_name = f"kcs-{name}-pvc-{i}"
                        self._ensure_pvc(pvc_name)
                        k8s_volumes.append(
                            client.V1Volume(
                                name=vol_name,
                                persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                    claim_name=pvc_name
                                ),
                            )
                        )
                        volume_mounts.append(
                            client.V1VolumeMount(name=vol_name, mount_path=container_path)
                        )

        container.volume_mounts = volume_mounts
        pod_spec.volumes = k8s_volumes if k8s_volumes else None

        pod_template = client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(labels=labels),
            spec=pod_spec,
        )

        if has_pvc:
            # StatefulSet
            headless_svc_name = f"{res_name}-headless"
            self._ensure_headless_service(headless_svc_name, labels)
            statefulset = client.V1StatefulSet(
                api_version="apps/v1",
                kind="StatefulSet",
                metadata=client.V1ObjectMeta(name=res_name, labels=labels),
                spec=client.V1StatefulSetSpec(
                    replicas=replicas,
                    selector=client.V1LabelSelector(match_labels=labels),
                    service_name=headless_svc_name,
                    template=pod_template,
                    volume_claim_templates=pvc_templates if pvc_templates else None,
                ),
            )
            self.apps_v1.create_namespaced_stateful_set(namespace=self.namespace, body=statefulset)
        else:
            # Deployment
            deployment = client.V1Deployment(
                api_version="apps/v1",
                kind="Deployment",
                metadata=client.V1ObjectMeta(name=res_name, labels=labels),
                spec=client.V1DeploymentSpec(
                    replicas=replicas,
                    selector=client.V1LabelSelector(match_labels=labels),
                    template=pod_template,
                ),
            )
            self.apps_v1.create_namespaced_deployment(namespace=self.namespace, body=deployment)

        # Create Service (expose ports)
        if ports:
            svc_ports = [
                client.V1ServicePort(name=f"port-{p}", port=p, target_port=p, protocol="TCP")
                for p in ports
            ]
            service = client.V1Service(
                api_version="v1",
                kind="Service",
                metadata=client.V1ObjectMeta(name=self.service_name(name), labels=labels),
                spec=client.V1ServiceSpec(selector=labels, ports=svc_ports, type="LoadBalancer"),
            )
            self.core_v1.create_namespaced_service(namespace=self.namespace, body=service)

        return {
            "name": name,
            "image": image,
            "status": STATUS_PENDING,
            "ports": ports or [],
            "replicas": replicas,
        }

    def list(self, all_namespaces: bool = False) -> list[dict]:
        """List all kcs-managed containers (Deployments + StatefulSets)."""
        if not all_namespaces:
            self._assert_legacy_namespace()
        label_selector = f"{LABEL_MANAGED_BY}={MANAGED_BY},{V2_EXCLUSION_SELECTOR}"
        items = []

        # Collect Deployments
        try:
            if all_namespaces:
                depls = self.apps_v1.list_deployment_for_all_namespaces(
                    label_selector=label_selector
                )
            else:
                depls = self.apps_v1.list_namespaced_deployment(
                    namespace=self.namespace, label_selector=label_selector
                )
            items.extend(depls.items)
        except ApiException:
            pass

        # Collect StatefulSets
        try:
            if all_namespaces:
                sts = self.apps_v1.list_stateful_set_for_all_namespaces(
                    label_selector=label_selector
                )
            else:
                sts = self.apps_v1.list_namespaced_stateful_set(
                    namespace=self.namespace, label_selector=label_selector
                )
            items.extend(sts.items)
        except ApiException:
            pass

        result = []
        for d in items:
            try:
                assert_legacy_target_allowed(d.metadata)
            except LegacyTargetForbiddenError:
                if all_namespaces:
                    continue
                raise
            name = d.metadata.labels.get(LABEL_APP, d.metadata.name)
            container_spec = d.spec.template.spec.containers[0]
            image = container_spec.image

            # Extract resource requests
            resources = {}
            if container_spec.resources and container_spec.resources.requests:
                resources = dict(container_spec.resources.requests)
            ready = d.status.ready_replicas or 0
            desired = d.spec.replicas

            if desired == 0:
                # Still has pods terminating -> show intermediate state
                current = d.status.replicas or 0
                status = STATUS_TERMINATING if current > 0 else STATUS_STOPPED
            elif ready == desired:
                status = STATUS_RUNNING
            elif ready == 0:
                status = STATUS_PENDING
            else:
                status = STATUS_RUNNING

            try:
                svc = self.core_v1.read_namespaced_service(
                    name=self.service_name(name), namespace=d.metadata.namespace
                )
                ports = [f"{p.port}:{p.target_port}/{p.protocol}" for p in (svc.spec.ports or [])]
            except ApiException:
                ports = []

            created = d.metadata.creation_timestamp
            if created:
                delta = int(time.time() - created.timestamp())
                if delta < 60:
                    age = f"{delta}s"
                elif delta < 3600:
                    age = f"{delta // 60}m{delta % 60}s"
                elif delta < 86400:
                    age = f"{delta // 3600}h{(delta % 3600) // 60}m"
                else:
                    age = f"{delta // 86400}d"
            else:
                age = "?"

            result.append(
                {
                    "name": name,
                    "image": image,
                    "status": status,
                    "ports": ports,
                    "replicas": ready,
                    "age": age,
                    "namespace": d.metadata.namespace,
                    "resources": resources,
                }
            )

        return result

    def get(self, name: str) -> dict | None:
        """Get detailed container info (like docker inspect)."""
        self._assert_legacy_namespace()
        depl_name = self.deployment_name(name)

        d = None
        is_statefulset = False

        # Try Deployment first, then StatefulSet
        try:
            d = self.apps_v1.read_namespaced_deployment(name=depl_name, namespace=self.namespace)
        except ApiException as e:
            if e.status != 404:
                raise

        if d is None:
            try:
                d = self.apps_v1.read_namespaced_stateful_set(
                    name=depl_name, namespace=self.namespace
                )
                is_statefulset = True
            except ApiException as e:
                if e.status == 404:
                    return None
                raise

        assert_legacy_target_allowed(d.metadata)
        container = d.spec.template.spec.containers[0]
        ready = d.status.ready_replicas or 0

        if is_statefulset:
            desired = d.spec.replicas or 0
        else:
            desired = d.spec.replicas

        if desired == 0:
            current = d.status.replicas or 0
            status = STATUS_TERMINATING if current > 0 else STATUS_STOPPED
        elif ready == desired:
            status = STATUS_RUNNING
        elif ready == 0:
            status = STATUS_PENDING
        else:
            status = STATUS_RUNNING

        # Get port info with real access addresses
        try:
            svc = self.core_v1.read_namespaced_service(
                name=self.service_name(name), namespace=self.namespace
            )
            cluster_ip = svc.spec.cluster_ip or ""
            # Find the pod's actual node IP, not LB ingress
            pod_node_ip = ""
            try:
                pods = self.list_pods(name)
                if pods:
                    pod_node_ip = pods[0].get("node", "")
            except LegacyTargetForbiddenError:
                raise
            except Exception:
                pass
            ports = [
                {
                    "port": p.port,
                    "target_port": p.target_port,
                    "protocol": p.protocol,
                    "node_port": p.node_port,
                    "cluster_ip": cluster_ip,
                    "node_ip": pod_node_ip,
                }
                for p in (svc.spec.ports or [])
            ]
        except ApiException:
            ports = []

        # Environment variables
        env = {
            e.name: e.value or f"<ref:{e.value_from.field_ref.field_path}>"
            for e in (container.env or [])
        }

        # Volume mounts
        volumes = []
        if container.volume_mounts:
            for vm in container.volume_mounts:
                volumes.append({"mount_path": vm.mount_path, "name": vm.name})

        # Resource declarations
        resources = {}
        if container.resources:
            if container.resources.requests:
                resources["requests"] = container.resources.requests
            if container.resources.limits:
                resources["limits"] = container.resources.limits

        return {
            "name": name,
            "image": container.image,
            "namespace": self.namespace,
            "status": status,
            "replicas": desired,
            "ready_replicas": ready,
            "ports": ports,
            "env": env,
            "volumes": volumes,
            "resources": resources,
            "created_at": str(d.metadata.creation_timestamp),
            "labels": d.metadata.labels or {},
            "node": "",
        }

    def stop(self, name: str) -> bool:
        """Stop a container (set replicas to 0)."""
        return self._scale(name, 0)

    def start(self, name: str) -> bool:
        """Start a stopped container (set replicas to 1)."""
        return self._scale(name, 1)

    def _scale(self, name: str, replicas: int) -> bool:
        """Set replica count (Deployment or StatefulSet)."""
        self._assert_controller_allowed(name)
        res_name = self.deployment_name(name)
        for read, patch in (
            (
                self.apps_v1.read_namespaced_deployment,
                self.apps_v1.patch_namespaced_deployment_scale,
            ),
            (
                self.apps_v1.read_namespaced_stateful_set,
                self.apps_v1.patch_namespaced_stateful_set_scale,
            ),
        ):
            resource = self._read_allowed_resource(read, res_name)
            if resource is None:
                continue
            body = {
                "metadata": {"resourceVersion": resource.metadata.resource_version},
                "spec": {"replicas": replicas},
            }
            try:
                patch(name=res_name, namespace=self.namespace, body=body)
                return True
            except ApiException as error:
                if error.status != 404:
                    raise
        return False

    def scale(self, name: str, replicas: int) -> bool:
        """Scale up or down."""
        return self._scale(name, replicas)

    def remove(self, name: str, force: bool = False) -> bool:
        """Remove a container (Deployment/StatefulSet + Service)."""
        self._assert_remove_allowed(name)
        res_name = self.deployment_name(name)
        svc_name = self.service_name(name)
        deleted = False

        resources = (
            (
                self.apps_v1.read_namespaced_deployment,
                self.apps_v1.delete_namespaced_deployment,
                res_name,
            ),
            (
                self.apps_v1.read_namespaced_stateful_set,
                self.apps_v1.delete_namespaced_stateful_set,
                res_name,
            ),
            (
                self.core_v1.read_namespaced_service,
                self.core_v1.delete_namespaced_service,
                svc_name,
            ),
            (
                self.core_v1.read_namespaced_service,
                self.core_v1.delete_namespaced_service,
                f"{res_name}-headless",
            ),
        )
        for read, delete, resource_name in resources:
            resource = self._read_allowed_resource(read, resource_name)
            if resource is None:
                continue
            uid = resource.metadata.uid
            try:
                delete(
                    name=resource_name,
                    namespace=self.namespace,
                    body={
                        "apiVersion": "v1",
                        "kind": "DeleteOptions",
                        "preconditions": {
                            "uid": uid,
                            "resourceVersion": resource.metadata.resource_version,
                        },
                    },
                )
                deleted = True
            except ApiException as error:
                if error.status != 404:
                    raise

        return deleted

    def logs(self, name: str, follow: bool = False, tail: int = 100, pod: int | None = None) -> str:
        """Get container logs. pod specifies the StatefulSet ordinal."""
        pod_name = self._get_target_pod(name, pod)
        if not pod_name:
            return f"Error: no Pod found for container '{name}'"
        if follow:
            # streaming logs
            return self.core_v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=self.namespace,
                follow=True,
                tail_lines=tail,
                _preload_content=False,
            )
        else:
            return self.core_v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=self.namespace,
                tail_lines=tail,
            )

    def exec(
        self,
        name: str,
        command: list[str],
        tty: bool = False,
        stdin: bool = False,
        pod: int | None = None,
    ) -> str:
        """Execute a command in a container. pod specifies the StatefulSet ordinal."""
        pod_name = self._get_target_pod(name, pod)
        if not pod_name:
            return f"Error: no Pod found for container '{name}'"
        pod_obj = self.core_v1.read_namespaced_pod(name=pod_name, namespace=self.namespace)
        assert_legacy_target_allowed(pod_obj.metadata)
        container_name = pod_obj.spec.containers[0].name

        # Use kubectl
        import subprocess as _sp

        env = {**os.environ}
        if self._kubeconfig:
            env["KUBECONFIG"] = self._kubeconfig
        cmd = ["kubectl", "exec", pod_name, "-n", self.namespace, "-c", container_name]
        if tty and stdin:
            cmd.extend(["-it"])
        cmd.append("--")
        cmd.extend(command)

        try:
            if tty and stdin:
                # Interactive mode: pass through stdin/stdout, don't capture
                result = _sp.run(cmd, env=env, timeout=None)
                return ""
            else:
                result = _sp.run(cmd, capture_output=True, text=True, timeout=30, env=env)
                return (result.stdout + result.stderr).strip() or "(empty)"
        except _sp.TimeoutExpired:
            return "Error: command timed out"
        except FileNotFoundError:
            return (
                "Error: kubectl required (bundled with k3s: "
                "ln -s /usr/local/bin/k3s /usr/local/bin/kubectl)"
            )

    def resolve_volume_path(self, name: str, mount_path: str) -> str | None:
        """Return the host (NFS) path backing a container's volume mount, or None."""
        pod_objs = self._get_pods(name)
        if not pod_objs:
            return None
        pod = pod_objs[0]
        for vm in pod.spec.containers[0].volume_mounts or []:
            if vm.mount_path.rstrip("/") == mount_path.rstrip("/"):
                for vol in pod.spec.volumes or []:
                    if vol.name == vm.name and vol.persistent_volume_claim:
                        pvc_name = vol.persistent_volume_claim.claim_name
                        try:
                            pvc = self.core_v1.read_namespaced_persistent_volume_claim(
                                name=pvc_name, namespace=self.namespace
                            )
                            pv_name = pvc.spec.volume_name
                            if pv_name:
                                pv = self.core_v1.read_persistent_volume(name=pv_name)
                                nfs = pv.spec.nfs
                                if nfs:
                                    return nfs.path
                        except ApiException:
                            pass
        return None

    # ── Utility methods ───────────────────────────────────────

    @staticmethod
    def _build_resources(
        gpus: int | None = None,
        cpu: str | None = None,
        memory: str | None = None,
    ):
        """Build V1ResourceRequirements from user-facing resource specs.
        Sets requests=limits for exclusive allocation.
        """
        requests = {}
        limits = {}
        if gpus:
            requests["nvidia.com/gpu"] = str(gpus)
            limits["nvidia.com/gpu"] = str(gpus)
        if cpu:
            requests["cpu"] = cpu
            limits["cpu"] = cpu
        if memory:
            requests["memory"] = memory
            limits["memory"] = memory
        if not requests:
            return None
        return client.V1ResourceRequirements(requests=requests, limits=limits)

    def _ensure_headless_service(self, name: str, labels: dict) -> None:
        """Create a headless service (required by StatefulSet)."""
        try:
            self.core_v1.read_namespaced_service(name=name, namespace=self.namespace)
        except ApiException as e:
            if e.status == 404:
                svc = client.V1Service(
                    metadata=client.V1ObjectMeta(name=name),
                    spec=client.V1ServiceSpec(
                        cluster_ip="None",
                        selector=labels,
                        ports=[client.V1ServicePort(port=80, target_port=80)],
                    ),
                )
                self.core_v1.create_namespaced_service(namespace=self.namespace, body=svc)

    def _ensure_pvc(self, name: str, size: str = "1Gi") -> None:
        """Auto-create a PVC if it does not exist."""
        try:
            self.core_v1.read_namespaced_persistent_volume_claim(
                name=name, namespace=self.namespace
            )
        except ApiException as e:
            if e.status == 404:
                pvc = client.V1PersistentVolumeClaim(
                    metadata=client.V1ObjectMeta(name=name),
                    spec=client.V1PersistentVolumeClaimSpec(
                        access_modes=["ReadWriteOnce"],
                        resources=client.V1VolumeResourceRequirements(requests={"storage": size}),
                    ),
                )
                self.core_v1.create_namespaced_persistent_volume_claim(
                    namespace=self.namespace, body=pvc
                )

    def _get_target_pod(self, name: str, pod: int | None = None) -> str | None:
        """Return a requested StatefulSet Pod or the first allowed matching Pod."""
        self._assert_legacy_namespace()
        if pod is not None:
            target_name = f"{self.deployment_name(name)}-{pod}"
            try:
                target = self.core_v1.read_namespaced_pod(
                    name=target_name, namespace=self.namespace
                )
                assert_legacy_target_allowed(target.metadata)
                return target_name
            except ApiException:
                return None
        pods = self._get_pods(name)
        return pods[0].metadata.name if pods else None

    def _get_pods(self, name: str):
        """Get the list of Pods belonging to a container."""
        self._assert_legacy_namespace()
        labels = self.labels(name)
        label_selector = ",".join([*(f"{k}={v}" for k, v in labels.items()), V2_EXCLUSION_SELECTOR])
        pods = self.core_v1.list_namespaced_pod(
            namespace=self.namespace, label_selector=label_selector
        )
        for pod in pods.items:
            assert_legacy_target_allowed(pod.metadata)
        return pods.items

    def list_pods(self, name: str) -> list[dict]:
        """Get details for each replica (Pod) of a container."""
        pods = self._get_pods(name)

        # Build node-name → IP mapping
        node_ips: dict[str, str] = {}
        try:
            nodes = self.core_v1.list_node()
            for n in nodes.items:
                for addr in n.status.addresses or []:
                    if addr.type == "InternalIP":
                        node_ips[n.metadata.name] = addr.address
                        break
        except ApiException:
            pass

        result = []
        for p in pods:
            status = STATUS_PENDING
            if p.status.phase == "Running":
                ready = all(c.ready for c in (p.status.container_statuses or []))
                status = STATUS_RUNNING if ready else STATUS_PENDING
            elif p.status.phase in ("Failed", "Error"):
                status = STATUS_ERROR
            elif p.status.phase == "Succeeded":
                status = STATUS_STOPPED

            # Calculate age
            if p.metadata.creation_timestamp:
                delta = int(time.time() - p.metadata.creation_timestamp.timestamp())
                if delta < 60:
                    age = f"{delta}s"
                elif delta < 3600:
                    age = f"{delta // 60}m{delta % 60}s"
                else:
                    age = f"{delta // 3600}h"
            else:
                age = "?"

            result.append(
                {
                    "name": p.metadata.name,
                    "namespace": p.metadata.namespace or self.namespace,
                    "labels": dict(p.metadata.labels or {}),
                    "status": status,
                    "node": node_ips.get(p.spec.node_name, p.spec.node_name or "-"),
                    "ip": p.status.pod_ip or "-",
                    "age": age,
                    "restarts": sum(c.restart_count for c in (p.status.container_statuses or [])),
                }
            )
        return result

    def cluster_info(self) -> dict:
        """Get basic cluster info."""
        try:
            version = client.VersionApi().get_code()
            nodes = self.core_v1.list_node()
            return {
                "version": version.git_version,
                "platform": version.platform,
                "nodes": len(nodes.items),
            }
        except ApiException:
            return {"version": "unknown", "platform": "unknown", "nodes": 0}

    def list_nodes(self) -> list[dict]:
        """Get the status of all nodes."""
        try:
            nodes = self.core_v1.list_node()
        except ApiException:
            return []

        # Build node usage map
        usage = self.get_node_usage()

        result = []
        for n in nodes.items:
            # Get node condition statuses
            conditions = {}
            for c in n.status.conditions or []:
                conditions[c.type] = c.status

            # Get roles
            roles = []
            for label in n.metadata.labels or {}:
                if label.startswith("node-role.kubernetes.io/"):
                    roles.append(label.split("/")[-1])
            if not roles:
                roles.append("worker")

            # Get internal IP
            internal_ip = ""
            for addr in n.status.addresses or []:
                if addr.type == "InternalIP":
                    internal_ip = addr.address
                    break

            # Get capacity and allocatable resources
            capacity = n.status.capacity or {}
            allocatable = n.status.allocatable or {}

            result.append(
                {
                    "name": n.metadata.name,
                    "roles": roles,
                    "status": ("Ready" if conditions.get("Ready") == "True" else "NotReady"),
                    "ip": internal_ip,
                    "capacity": {
                        "cpu": float(_cpu_cores(capacity.get("cpu", "0"))),
                        "memory": _mem_bytes(capacity.get("memory", "0")),
                        "gpu": int(capacity.get("nvidia.com/gpu", 0)),
                        "storage": _mem_bytes(capacity.get("ephemeral-storage", "0")),
                    },
                    "allocatable": {
                        "cpu": float(_cpu_cores(allocatable.get("cpu", "0"))),
                        "memory": _mem_bytes(allocatable.get("memory", "0")),
                        "gpu": int(allocatable.get("nvidia.com/gpu", 0)),
                        "storage": _mem_bytes(allocatable.get("ephemeral-storage", "0")),
                    },
                    "used": usage.get(n.metadata.name, {"cpu": 0, "memory": 0, "gpu": 0}),
                    "disk_pressure": conditions.get("DiskPressure") == "True",
                    "memory_pressure": conditions.get("MemoryPressure") == "True",
                    "pid_pressure": conditions.get("PIDPressure") == "True",
                    "taints": (
                        [
                            (f"{t.key}={t.value}:{t.effect}" if t.value else f"{t.key}:{t.effect}")
                            for t in (n.spec.taints or [])
                        ]
                        if n.spec.taints
                        else []
                    ),
                    "version": (n.status.node_info.kubelet_version if n.status.node_info else "?"),
                }
            )

        return result

    def get_node_usage(self) -> dict:
        """Sum kcs-managed pod resource requests per node.

        Returns: {node_name: {"cpu": float_cores, "memory": int_bytes, "gpu": int}}
        """
        nodes: dict[str, dict] = {}
        try:
            pods = self.core_v1.list_pod_for_all_namespaces(
                label_selector=f"{LABEL_MANAGED_BY}={MANAGED_BY},{V2_EXCLUSION_SELECTOR}"
            )
        except ApiException:
            return nodes

        for p in pods.items:
            try:
                assert_legacy_target_allowed(p.metadata)
            except LegacyTargetForbiddenError:
                continue
            if p.status.phase != "Running":
                continue
            # Skip terminating pods (e.g. during 30s grace period after stop)
            if p.metadata.deletion_timestamp:
                continue
            node = p.spec.node_name
            if not node:
                continue
            if node not in nodes:
                nodes[node] = {"cpu": 0.0, "memory": 0, "gpu": 0}
            for c in p.spec.containers:
                res = c.resources
                if not res or not res.requests:
                    continue
                nodes[node]["cpu"] += _cpu_cores(res.requests.get("cpu", "0"))
                nodes[node]["memory"] += _mem_bytes(res.requests.get("memory", "0"))
                gpu = int(res.requests.get("nvidia.com/gpu", 0))
                nodes[node]["gpu"] += gpu
        return nodes

    def _assert_legacy_namespace(self) -> None:
        assert_legacy_target_allowed({"namespace": self.namespace})

    def _assert_controller_allowed(self, name: str) -> None:
        """Read the V1 controller metadata before any scale/delete mutation."""
        self._assert_legacy_namespace()
        resource_name = self.deployment_name(name)
        for read in (
            self.apps_v1.read_namespaced_deployment,
            self.apps_v1.read_namespaced_stateful_set,
        ):
            self._read_allowed_resource(read, resource_name)

    def _assert_remove_allowed(self, name: str) -> None:
        """Preflight every controller and Service that remove() can mutate."""
        self._assert_controller_allowed(name)
        for service_name in (self.service_name(name), f"{self.deployment_name(name)}-headless"):
            self._read_allowed_resource(self.core_v1.read_namespaced_service, service_name)

    def _read_allowed_resource(self, read, name: str):
        """Read and guard the exact resource immediately before its mutation."""
        try:
            resource = read(name=name, namespace=self.namespace)
        except ApiException as error:
            if error.status == 404:
                return None
            raise
        assert_legacy_target_allowed(resource.metadata)
        return resource
