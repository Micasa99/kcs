"""ClusterService — business logic for cluster management + utility functions."""

from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from kcs.config import get_registry, is_built_image, load, save, set_cluster_registry
from kcs.k8s import KCSClient
from kcs.server.models import ClusterConfig, WorkerNode

if TYPE_CHECKING:
    from kcs.jobs.provider import V2JobProvider
    from kcs.jobs.settings import V2RuntimeSettings

log = logging.getLogger("kcs")


# ══════════════════════════════════════════════════════════════════════════════
# Module-level singleton
# ══════════════════════════════════════════════════════════════════════════════

_service: ClusterService | None = None
_v2_provider: V2JobProvider | None = None


def get_service() -> ClusterService:
    global _service
    if _service is None:
        _service = ClusterService()
    return _service


def set_service_config(config: ClusterConfig) -> None:
    get_service().cluster_config = config


def get_v2_provider(settings: V2RuntimeSettings | None = None) -> V2JobProvider:
    """Build the namespace-bound V2 provider only when V2 mode selects it."""
    global _v2_provider
    if _v2_provider is None:
        from kubernetes import client, config  # type: ignore[import-untyped]

        from kcs.jobs.kube import V2KubeAdapter
        from kcs.jobs.observability import EventStore, PrometheusClient, V2Observability
        from kcs.jobs.project_workspace import ProjectWorkspaceService
        from kcs.jobs.provider import V2JobProvider
        from kcs.jobs.recipe_registry import NativeRecipeRegistry
        from kcs.jobs.renderer import V2JobRenderer
        from kcs.jobs.runtime_assembly import (
            NativeCapabilityRegistry,
            RuntimeAssemblyResolver,
        )
        from kcs.jobs.settings import V2RuntimeSettings
        from kcs.jobs.store import V2JobStore
        from kcs.jobs.transport import ExecRpcTransport, ExecWorkspaceRpcTransport

        settings = settings or V2RuntimeSettings.from_env(os.environ)
        config.load_incluster_config()
        batch_api = client.BatchV1Api(api_client=client.ApiClient())
        core_api = client.CoreV1Api(api_client=client.ApiClient())
        apps_api = client.AppsV1Api(api_client=client.ApiClient())
        kube = V2KubeAdapter(
            settings.namespace,
            batch_api,
            core_api,
            apps_api=apps_api,
            networking_api=client.NetworkingV1Api(api_client=client.ApiClient()),
            metrics_api=client.CustomObjectsApi(api_client=client.ApiClient()),
            # kubernetes.stream.stream temporarily replaces its ApiClient's
            # request transport with a websocket transport.  A fresh client
            # per exec keeps that mutation away from concurrent REST reads
            # and from every other exec call.
            exec_core_api_factory=lambda: client.CoreV1Api(api_client=client.ApiClient()),
        )
        observability = V2Observability(
            kube,
            PrometheusClient(
                settings.prometheus_url,
                timeout_seconds=settings.prometheus_timeout_seconds,
            ),
            EventStore(settings.event_db_path),
        )
        recipes = NativeRecipeRegistry(settings.native_recipe_registry_path)
        renderer = V2JobRenderer(settings, recipes)
        assembly_resolver = RuntimeAssemblyResolver(
            recipes,
            NativeCapabilityRegistry(settings.native_capability_registry_path),
        )
        store = V2JobStore(kube)
        workspace_transport = ExecWorkspaceRpcTransport(kube.exec_workspace_rpc)
        project_workspaces = ProjectWorkspaceService(
            store, kube, workspace_transport, settings
        )
        _v2_provider = V2JobProvider(
            kube,
            store,
            renderer,
            namespace=settings.namespace,
            transport=ExecRpcTransport(kube.exec_supervisor_rpc),
            workspace_transport=workspace_transport,
            observability=observability,
            hosted_admission=False,
            openvscode_image_ref=settings.native_openvscode_image_volume,
            runtime_assembly_resolver=assembly_resolver,
            project_workspaces=project_workspaces,
        )
    return _v2_provider


# ══════════════════════════════════════════════════════════════════════════════
# Utility functions
# ══════════════════════════════════════════════════════════════════════════════


def find_free_port(start: int = 5001) -> int:
    port = start
    while port < 5100:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1
    return start


def resolve_image(image: str) -> str:
    if "/" in image and ":" in image.rsplit("/", 1)[-1]:
        return image
    if is_built_image(image):
        reg = get_registry()
        if reg:
            return f"{reg['host']}:{reg['internal_port']}/{image}"
        return f"registry.kcs-system.svc.cluster.local:5000/{image}"
    return image


def _run_ssh(
    target: str,
    remote_cmd: str,
    *,
    password: str | None = None,
    identity_file: str | None = None,
    need_sudo: bool = False,
    capture: bool = True,
    stdin_text: str | None = None,
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    """Run a command on a remote host via SSH.

    Password is passed through a pipe fd (sshpass -d) — never in environ.
    The pipe is closed before this function returns.
    """
    identity_path: Path | None = None
    if identity_file is not None:
        identity_path = Path(identity_file).expanduser().absolute()
        try:
            identity_stat = identity_path.lstat()
        except OSError:
            raise ValueError("SSH identity file is not a secure regular file") from None
        permissions = stat.S_IMODE(identity_stat.st_mode)
        if (
            not stat.S_ISREG(identity_stat.st_mode)
            or identity_stat.st_uid != os.getuid()
            or permissions & ~0o600
        ):
            raise ValueError("SSH identity file is not a secure regular file")

    sshpass_bin = shutil.which("sshpass")
    use_sshpass = sshpass_bin is not None and password is not None

    if use_sshpass:
        r_fd, w_fd = os.pipe()
        os.write(w_fd, (password + "\n").encode())
        os.close(w_fd)
        cmd = [
            "sshpass",
            "-d",
            str(r_fd),
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
        ]
    else:
        r_fd = None
        cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
        ]
        if need_sudo:
            cmd.append("-t")

    if identity_path is not None:
        cmd.extend(["-i", str(identity_path), "-o", "IdentitiesOnly=yes"])

    cmd.extend([target, remote_cmd])

    kwargs: dict = dict(text=True, timeout=timeout)
    if capture:
        kwargs["capture_output"] = True
    if stdin_text is not None:
        kwargs["input"] = stdin_text
    if use_sshpass:
        kwargs["pass_fds"] = [r_fd]

    try:
        try:
            return subprocess.run(cmd, **kwargs)
        except subprocess.TimeoutExpired as error:
            raise subprocess.TimeoutExpired(
                cmd=["ssh"],
                timeout=error.timeout,
                output=error.output,
                stderr=error.stderr,
            ) from None
    finally:
        if r_fd is not None:
            try:
                os.close(r_fd)
            except OSError:
                pass


def get_server_ip_from_kubeconfig() -> str | None:
    kubeconfig = os.environ.get("KUBECONFIG") or str(Path.home() / ".kcs" / "k3s.yaml")
    if not os.path.exists(kubeconfig):
        kubeconfig = "/etc/rancher/k3s/k3s.yaml"
    try:
        with open(kubeconfig) as f:
            cfg = yaml.safe_load(f)
        for c in cfg.get("clusters", []):
            server_url = c["cluster"]["server"]
            m = re.search(r"https?://([^:]+)", server_url)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def read_k3s_token(sudo_password: str | None = None) -> str | None:
    token_path = "/var/lib/rancher/k3s/server/token"
    if not os.path.exists(token_path):
        return None
    try:
        with open(token_path) as f:
            return f.read().strip()
    except PermissionError:
        pass
    try:
        if sudo_password:
            result = subprocess.run(
                ["sudo", "-S", "-p", "", "cat", token_path],
                input=sudo_password + "\n",
                text=True,
                capture_output=True,
                timeout=10,
            )
        else:
            result = subprocess.run(
                ["sudo", "-n", "cat", token_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def configure_containerd_insecure(registry_ip: str) -> None:
    registries_yaml = f"""mirrors:
  "{registry_ip}:5000":
    endpoint:
      - "http://{registry_ip}:5000"
configs:
  "{registry_ip}:5000":
    tls:
      insecure_skip_verify: true
"""
    registries_path = "/etc/rancher/k3s/registries.yaml"
    try:
        subprocess.run(
            ["sudo", "tee", registries_path],
            input=registries_yaml,
            text=True,
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "systemctl", "restart", "k3s", "k3s-agent"],
            capture_output=True,
            timeout=30,
        )
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# ClusterService
# ══════════════════════════════════════════════════════════════════════════════


class ClusterService:
    """Manages cluster lifecycle: config, repair, NFS, workers."""

    def __init__(self, cluster_config: ClusterConfig | None = None):
        self.cluster_config = cluster_config

    # ── Client ──────────────────────────────────────────────────────────────

    def get_client(self) -> KCSClient:
        return KCSClient(kubeconfig=self.get_kubeconfig_path())

    def get_kubeconfig_path(self) -> str:
        kubeconfig = os.environ.get("KUBECONFIG")
        if kubeconfig:
            return kubeconfig
        k3s_dst = str(Path.home() / ".kcs" / "k3s.yaml")
        if os.path.exists(k3s_dst):
            return k3s_dst
        return "/etc/rancher/k3s/k3s.yaml"

    # ── Config ──────────────────────────────────────────────────────────────

    @staticmethod
    def load_config_file(path: str) -> ClusterConfig:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        suffix = p.suffix.lower()
        if suffix in (".toml", ".tml"):
            import tomllib

            with open(path, "rb") as f:
                raw = tomllib.load(f)
        elif suffix in (".yaml", ".yml"):
            with open(path) as f:
                raw = yaml.safe_load(f)
        else:
            raise ValueError(f"Unsupported config format: {suffix} (use .toml or .yaml)")

        workers = [WorkerNode(**w) for w in raw.get("workers", [])]
        return ClusterConfig(
            backend=raw.get("backend", "k3s"),
            api_key=raw.get("api_key"),
            sudo_password=raw.get("sudo_password"),
            nfs_path=raw.get("nfs_path", "/srv/nfs/k3s"),
            workers=workers,
        )

    # ── Registry ────────────────────────────────────────────────────────────

    def _ensure_registry(self) -> dict | None:
        kubeconfig = self.get_kubeconfig_path()
        check = subprocess.run(
            [
                "kubectl",
                "get",
                "deployment",
                "registry",
                "-n",
                "kcs-system",
                "-o",
                "jsonpath={.status.readyReplicas}",
                "--kubeconfig",
                kubeconfig,
            ],
            capture_output=True,
            text=True,
        )
        if check.stdout.strip() != "1":
            registry_yaml = """apiVersion: v1
kind: Namespace
metadata:
  name: kcs-system
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: registry
  namespace: kcs-system
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 10Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: registry
  namespace: kcs-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: registry
  template:
    metadata:
      labels:
        app: registry
    spec:
      containers:
      - name: registry
        image: registry:2
        ports:
        - containerPort: 5000
        volumeMounts:
        - name: data
          mountPath: /var/lib/registry
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: registry
---
apiVersion: v1
kind: Service
metadata:
  name: registry
  namespace: kcs-system
spec:
  type: NodePort
  ports:
  - port: 5000
    targetPort: 5000
    nodePort: 30500
  selector:
    app: registry
"""
            result = subprocess.run(
                ["kubectl", "apply", "--kubeconfig", kubeconfig, "-f", "-"],
                input=registry_yaml,
                text=True,
                capture_output=True,
            )
            if result.returncode != 0:
                return None
            subprocess.run(
                [
                    "kubectl",
                    "wait",
                    "--for=condition=available",
                    "deployment/registry",
                    "-n",
                    "kcs-system",
                    "--kubeconfig",
                    kubeconfig,
                    "--timeout=60s",
                ],
                capture_output=True,
            )

        ip_result = subprocess.run(
            [
                "kubectl",
                "get",
                "svc",
                "registry",
                "-n",
                "kcs-system",
                "--kubeconfig",
                kubeconfig,
                "-o",
                "jsonpath={.spec.clusterIP}",
            ],
            capture_output=True,
            text=True,
        )
        cluster_ip = ip_result.stdout.strip()
        if not cluster_ip:
            return None

        reg_info = {
            "host": cluster_ip,
            "internal_port": "5000",
            "external_port": "30500",
        }
        set_cluster_registry(**reg_info)
        configure_containerd_insecure(cluster_ip)
        return reg_info

    def _push_to_registry(self, tag: str, reg: dict) -> None:
        kubeconfig = self.get_kubeconfig_path()
        local_port = find_free_port(30500)
        host_tag = f"localhost:{local_port}/{tag}"

        pf = subprocess.Popen(
            [
                "kubectl",
                "port-forward",
                "svc/registry",
                f"{local_port}:5000",
                "-n",
                "kcs-system",
                "--kubeconfig",
                kubeconfig,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(10):
            time.sleep(0.5)
            check = subprocess.run(
                ["curl", "-s", f"http://localhost:{local_port}/v2/"],
                capture_output=True,
            )
            if check.returncode == 0:
                break
        try:
            subprocess.run(["docker", "tag", tag, host_tag], capture_output=True)
            subprocess.run(["docker", "push", host_tag], capture_output=True, timeout=60)
        finally:
            pf.terminate()

    # ── Workers ─────────────────────────────────────────────────────────────

    def _prune_stale_workers(
        self, config: ClusterConfig, configured_hostnames: set[str]
    ) -> list[str]:
        results = []
        try:
            client = self.get_client()
            nodes = client.list_nodes()
        except Exception:
            return results

        for n in nodes:
            if "control-plane" in n["roles"] or "master" in n["roles"]:
                continue
            if n["name"] in configured_hostnames:
                continue
            log.info("Pruning stale worker: %s (%s)", n["name"], n["ip"])
            try:
                client.core_v1.delete_node(name=n["name"])
                results.append(f"Removed stale worker: {n['name']}")
            except Exception as e:
                results.append(f"Failed to remove {n['name']}: {e}")

        return results

    # ── Apply config ────────────────────────────────────────────────────────

    def apply_config(self) -> list[str]:
        """Apply cluster config: ensure backend, join workers, prune stale."""
        config = self.cluster_config
        if not config:
            return ["No config loaded"]

        results = []

        # 1. Ensure backend
        if config.backend == "k3s":
            k3s_src = "/etc/rancher/k3s/k3s.yaml"
            if not os.path.exists(k3s_src):
                log.warning("Host k3s not installed")
                results.append("WARNING: host k3s not installed")
            else:
                k3s_dst = str(Path.home() / ".kcs" / "k3s.yaml")
                if not os.path.exists(k3s_dst):
                    shutil.copy(k3s_src, k3s_dst)
                    log.info("Copied k3s.yaml to %s", k3s_dst)
                cfg = load()
                cfg["current_cluster"] = None
                save(cfg)
                log.info("Backend set to host k3s")
                results.append("Backend: k3s (host)")
        # 2. Join workers
        if not config.workers:
            self._prune_stale_workers(config, set())
            return results

        server_ip = None
        try:
            result = subprocess.run(["hostname", "-I"], capture_output=True, text=True)
            for ip in result.stdout.strip().split():
                if not ip.startswith(("127.", "10.", "172.")):
                    server_ip = ip
                    break
        except Exception:
            pass
        if not server_ip:
            server_ip = get_server_ip_from_kubeconfig()
        if not server_ip:
            log.warning("Cannot detect server IP")
            results.append("WARNING: Cannot detect server IP, worker join will fail")
        else:
            log.info("Server IP: %s", server_ip)

        k3s_token = read_k3s_token(config.sudo_password)
        if not k3s_token:
            log.warning("Cannot read k3s token")
            results.append("WARNING: Cannot read k3s token, worker join will fail")

        if not server_ip or not k3s_token:
            return results

        log.info("sshpass: %s", "found" if shutil.which("sshpass") else "not found")

        configured_hostnames: set[str] = set()

        reg = get_registry()
        registry_cfg = ""
        if reg:
            reg_ip = reg["host"]
            registry_cfg = (
                f"sudo mkdir -p /etc/rancher/k3s && "
                f"cat << 'KCS_REG_EOF' | sudo tee /etc/rancher/k3s/registries.yaml > /dev/null\n"
                f"mirrors:\n"
                f'  "{reg_ip}:5000":\n'
                f"    endpoint:\n"
                f'      - "http://{reg_ip}:5000"\n'
                f"KCS_REG_EOF\n"
            )

        for w in config.workers:
            target = f"{w.user}@{w.host}"
            need_sudo = w.user != "root"
            pw = w.password  # captured once, cleared per-iteration below

            log.info("Checking %s ...", target)
            try:
                hn = _run_ssh(
                    target,
                    "hostname",
                    password=pw,
                    identity_file=w.ssh_key,
                    timeout=15,
                )
                remote_hostname = hn.stdout.strip() if hn.returncode == 0 else w.host
                log.info("Remote hostname: %s", remote_hostname)
            except Exception as e:
                log.warning("Failed to check %s: %s", target, e)
                remote_hostname = w.host

            client = self.get_client()
            try:
                existing = client.core_v1.list_node(
                    field_selector=f"metadata.name={remote_hostname}"
                )
                already_joined = bool(existing.items)
            except Exception:
                already_joined = False

            if already_joined:
                log.info("Node %s already in cluster", remote_hostname)
                if registry_cfg:
                    sync_cmd = (
                        f"sudo -S -p '' sh -c '{registry_cfg}'" if need_sudo else registry_cfg
                    )
                    sudo_pw = (pw + "\n") if need_sudo else None
                    _run_ssh(
                        target,
                        sync_cmd,
                        password=pw,
                        identity_file=w.ssh_key,
                        need_sudo=need_sudo,
                        stdin_text=sudo_pw,
                        timeout=30,
                    )
                    log.info("  registry config synced")

                restart_cmd = (
                    "systemctl restart k3s-agent 2>/dev/null || systemctl restart k3s 2>/dev/null"
                )
                if need_sudo:
                    restart_cmd = f"sudo -S -p '' sh -c '{restart_cmd}'"
                ri = (pw + "\n") if need_sudo else None
                _run_ssh(
                    target,
                    restart_cmd,
                    password=pw,
                    identity_file=w.ssh_key,
                    need_sudo=need_sudo,
                    stdin_text=ri,
                    timeout=30,
                )
                log.info("  k3s-agent restarted")

                results.append(f"Worker {target} ({remote_hostname}): ok")
                configured_hostnames.add(remote_hostname)
                pw = None  # clear
                continue

            # fresh join
            k3s_url = f"https://{server_ip}:6443"
            install_cmd = (
                f"curl -sfL https://get.k3s.io | K3S_URL={k3s_url} K3S_TOKEN={k3s_token} sh -"
            )
            cleanup = (
                "sudo systemctl stop k3s-agent 2>/dev/null; "
                "sudo systemctl disable k3s-agent 2>/dev/null; "
                "sudo /usr/local/bin/k3s-killall.sh 2>/dev/null; "
                "sudo /usr/local/bin/k3s-agent-uninstall.sh 2>/dev/null; "
                "sudo rm -rf /var/lib/rancher/k3s"
            )
            install_cmd = f"{cleanup}; {registry_cfg}{install_cmd}"

            if need_sudo:
                install_cmd = f"sudo -S -p '' sh -c '{install_cmd}'"

            stdin_input = (pw + "\n") if need_sudo else None

            log.info("Joining %s via SSH ...", target)
            try:
                result = _run_ssh(
                    target,
                    install_cmd,
                    password=pw,
                    identity_file=w.ssh_key,
                    need_sudo=need_sudo,
                    stdin_text=stdin_input,
                    timeout=120,
                    capture=True,
                )
            except subprocess.TimeoutExpired:
                log.error("SSH timeout for %s", target)
                results.append(f"Worker {target}: SSH timeout")
                pw = None
                continue

            if result.returncode == 0:
                log.info("Node %s joined successfully", remote_hostname)
                results.append(f"Worker {target} ({remote_hostname}): joined")
            else:
                log.error("Join failed for %s: exit %s", target, result.returncode)
                results.append(f"Worker {target}: failed (exit {result.returncode})")

            configured_hostnames.add(remote_hostname)
            pw = None  # clear after use

        pruned = self._prune_stale_workers(config, configured_hostnames)
        results.extend(pruned)
        return results

    # ── Repair ──────────────────────────────────────────────────────────────

    def repair(self) -> None:
        """Auto-repair: fix broken registry, restart stuck containers."""
        kubeconfig = self.get_kubeconfig_path()

        need_repair = False
        svc = subprocess.run(
            [
                "kubectl",
                "get",
                "svc",
                "registry",
                "-n",
                "kcs-system",
                "--kubeconfig",
                kubeconfig,
            ],
            capture_output=True,
        )
        if svc.returncode != 0:
            need_repair = True
        else:
            ready_check = subprocess.run(
                [
                    "kubectl",
                    "get",
                    "deployment",
                    "registry",
                    "-n",
                    "kcs-system",
                    "-o",
                    "jsonpath={.status.readyReplicas}",
                    "--kubeconfig",
                    kubeconfig,
                ],
                capture_output=True,
                text=True,
            )
            if ready_check.stdout.strip() not in ("1",):
                log.warning("Registry not ready (readyReplicas=%s)", ready_check.stdout.strip())
                need_repair = True

        if need_repair:
            log.info("Repairing registry...")
            subprocess.run(
                [
                    "kubectl",
                    "delete",
                    "deployment",
                    "registry",
                    "-n",
                    "kcs-system",
                    "--ignore-not-found",
                    "--kubeconfig",
                    kubeconfig,
                ],
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                [
                    "kubectl",
                    "delete",
                    "pvc",
                    "registry",
                    "-n",
                    "kcs-system",
                    "--ignore-not-found",
                    "--kubeconfig",
                    kubeconfig,
                ],
                capture_output=True,
                timeout=10,
            )
            time.sleep(2)
            subprocess.run(
                [
                    "kubectl",
                    "delete",
                    "pvc",
                    "registry",
                    "-n",
                    "kcs-system",
                    "--ignore-not-found",
                    "--force",
                    "--kubeconfig",
                    kubeconfig,
                ],
                capture_output=True,
                timeout=10,
            )
            reg_info = self._ensure_registry()
            if not reg_info:
                log.error("Failed to deploy registry")
                sys.exit(1)
            log.info("Registry repaired, ClusterIP: %s", reg_info["host"])

        # ensure images are in registry
        cfg = load()
        built_images = list(cfg.get("built_images", {}).keys())
        if built_images:
            reg = get_registry()
            if reg:
                log.info("Checking images in registry...")
                for tag in built_images:
                    tag_result = subprocess.run(
                        ["docker", "image", "inspect", tag],
                        capture_output=True,
                        timeout=10,
                    )
                    if tag_result.returncode == 0:
                        log.info("Pushing %s to registry", tag)
                        self._push_to_registry(tag, reg)
                    else:
                        log.warning("Local image %s not found, skipping", tag)
                log.info("Images synced to registry")

        # restart stuck containers
        try:
            client = self.get_client()
            containers = client.list()
            for c in containers:
                if c["status"] == "pending" and c["replicas"] == 0:
                    log.info("Restarting stuck container: %s", c["name"])
                    client.start(c["name"])
                    time.sleep(2)
        except Exception as e:
            log.error("Failed to restart containers: %s", e)
            sys.exit(1)

        log.info("Cluster health check: OK")

    # ── NFS ─────────────────────────────────────────────────────────────────

    def setup_nfs(self) -> dict:
        """Auto-configure NFS shared storage across all nodes."""
        cfg = self.cluster_config
        if not cfg:
            return {"message": "No cluster config loaded (use --config)"}
        if not cfg.sudo_password:
            return {"message": "sudo_password not set in config"}
        if not cfg.workers:
            return {"message": "No workers in config"}

        results = []

        server_ip = None
        try:
            result = subprocess.run(["hostname", "-I"], capture_output=True, text=True)
            for ip in result.stdout.strip().split():
                if not ip.startswith(("127.",)):
                    server_ip = ip
                    break
        except Exception:
            pass
        if not server_ip:
            return {"message": "Cannot detect server IP", "results": []}
        log.info("NFS server IP: %s", server_ip)

        # 1. Install NFS server locally
        log.info("Installing nfs-kernel-server locally...")
        step1 = subprocess.run(
            ["sudo", "-S", "-p", "", "apt", "install", "nfs-kernel-server", "-y"],
            input=cfg.sudo_password + "\n",
            text=True,
            capture_output=True,
            timeout=60,
        )
        results.append("nfs-kernel-server: " + ("installed" if step1.returncode == 0 else "FAILED"))

        nfs_path = cfg.nfs_path or "/srv/nfs/k3s"

        # 2. Export NFS path (restricted to known workers, no world-write, root squashed)
        log.info("Setting up NFS export %s...", nfs_path)
        client_hosts = " ".join(f"{w.host}(rw,sync,no_subtree_check)" for w in cfg.workers)
        export_line = f"{nfs_path} {client_hosts}"
        setup_cmds = (
            f"mkdir -p {nfs_path} && "
            f"chmod 755 {nfs_path} && "
            f"grep -q '{nfs_path}' /etc/exports || echo '{export_line}' >> /etc/exports && "
            "exportfs -ra"
        )
        step2 = subprocess.run(
            ["sudo", "-S", "-p", "", "bash", "-c", setup_cmds],
            input=cfg.sudo_password + "\n",
            text=True,
            capture_output=True,
            timeout=30,
        )
        results.append(f"NFS export {nfs_path}: " + ("ok" if step2.returncode == 0 else "FAILED"))

        # 3. Install nfs-common on each worker
        for w in cfg.workers:
            target = f"{w.user}@{w.host}"
            need_sudo = w.user != "root"
            pw = w.password
            log.info("Installing nfs-common on %s ...", target)

            install_cmd = "apt install nfs-common -y"
            if need_sudo:
                install_cmd = f"sudo -S -p '' bash -c '{install_cmd}'"

            sudo_pw = (pw + "\n") if need_sudo else None
            try:
                r = _run_ssh(
                    target,
                    install_cmd,
                    password=pw,
                    identity_file=w.ssh_key,
                    need_sudo=need_sudo,
                    stdin_text=sudo_pw,
                    timeout=60,
                )
                ok = r.returncode == 0
            except subprocess.TimeoutExpired:
                ok = False
            pw = None
            results.append(f"nfs-common on {target}: {'ok' if ok else 'FAILED'}")

        # 4. Deploy NFS provisioner
        log.info("Deploying NFS provisioner...")
        provisioner_yaml = f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: nfs-provisioner
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nfs-provisioner-runner
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "update", "patch"]
  - apiGroups: [""]
    resources: ["endpoints"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: nfs-provisioner
subjects:
  - kind: ServiceAccount
    name: nfs-provisioner
    namespace: default
roleRef:
  kind: ClusterRole
  name: nfs-provisioner-runner
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nfs-provisioner
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nfs-provisioner
  template:
    metadata:
      labels:
        app: nfs-provisioner
    spec:
      serviceAccountName: nfs-provisioner
      containers:
        - name: nfs-provisioner
          image: registry.k8s.io/sig-storage/nfs-subdir-external-provisioner:v4.0.2
          volumeMounts:
            - name: nfs
              mountPath: /persistentvolumes
          env:
            - name: PROVISIONER_NAME
              value: nfs-client
            - name: NFS_SERVER
              value: "{server_ip}"
            - name: NFS_PATH
              value: {nfs_path}
      volumes:
        - name: nfs
          nfs:
            server: {server_ip}
            path: {nfs_path}
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-client
provisioner: nfs-client
"""
        kubeconfig = self.get_kubeconfig_path()
        subprocess.run(
            [
                "kubectl",
                "delete",
                "storageclass",
                "nfs-client",
                "--ignore-not-found",
                "--kubeconfig",
                kubeconfig,
            ],
            capture_output=True,
            timeout=10,
        )
        step4 = subprocess.run(
            ["kubectl", "apply", "--kubeconfig", kubeconfig, "-f", "-"],
            input=provisioner_yaml,
            text=True,
            capture_output=True,
            timeout=30,
        )
        if step4.returncode != 0:
            results.append(f"NFS provisioner: FAILED ({step4.stderr[-200:]})")
        else:
            results.append("NFS provisioner: deployed")

        return {
            "message": "NFS setup complete",
            "server_ip": server_ip,
            "results": results,
        }
