"""Focused simulated Journey for the V2/legacy isolation boundary."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner
from fastapi.testclient import TestClient

V2_NAMESPACE = "researchcosmos-v2"
V2_LABEL = "researchcosmos.io/managed-by"
V2_LABEL_VALUE = "v2-attempt-runtime"
SAFE_DENIAL = "Legacy debug access to V2 managed workloads is forbidden"


def _pod(*, namespace: str = "default", managed: bool = True) -> SimpleNamespace:
    labels = {"app": "formal-attempt"}
    if managed:
        labels[V2_LABEL] = V2_LABEL_VALUE
    metadata = SimpleNamespace(
        name="formal-attempt-pod",
        namespace=namespace,
        labels=labels,
        creation_timestamp=None,
    )
    container = SimpleNamespace(name="agent", volume_mounts=[])
    spec = SimpleNamespace(containers=[container], volumes=[], node_name="worker")
    status = SimpleNamespace(
        phase="Running",
        container_statuses=[SimpleNamespace(ready=True, restart_count=0)],
        pod_ip="10.0.0.2",
    )
    return SimpleNamespace(metadata=metadata, spec=spec, status=status)


def test_task8_legacy_isolation_and_ssh_identity_journey(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """V2 targets stay outside every debug path and configured SSH identity is real."""
    try:
        guard = importlib.import_module("kcs.legacy_guard")
    except ModuleNotFoundError:
        pytest.fail("central legacy/V2 guard is missing")

    from kcs import cli, k8s, shell_proxy
    from kcs.server import services
    from kcs.server.app import create_app
    from kcs.server.models import ClusterConfig, WorkerNode

    events: list[dict[str, object]] = []
    forbidden = guard.LegacyTargetForbiddenError

    class CoreApi:
        def list_namespaced_pod(self, **kwargs: object) -> SimpleNamespace:
            events.append({"event": "pod_selection", "selector": kwargs["label_selector"]})
            return SimpleNamespace(items=[_pod()])

        def read_namespaced_pod(self, **kwargs: object) -> SimpleNamespace:
            events.append({"event": "pod_read"})
            return _pod()

        def read_namespaced_pod_log(self, **kwargs: object) -> str:
            events.append({"event": "DANGEROUS_pod_log"})
            return "formal log"

        def list_node(self) -> SimpleNamespace:
            return SimpleNamespace(items=[])

    legacy_client = k8s.KCSClient.__new__(k8s.KCSClient)
    legacy_client.namespace = "default"
    legacy_client._kubeconfig = None
    legacy_client.core_v1 = CoreApi()
    legacy_client.apps_v1 = SimpleNamespace()

    def kubectl_bomb(*args: object, **kwargs: object) -> None:
        events.append({"event": "DANGEROUS_kubectl_exec"})
        raise AssertionError("kubectl exec must not run")

    monkeypatch.setattr(
        k8s.subprocess if hasattr(k8s, "subprocess") else subprocess,
        "run",
        kubectl_bomb,
    )
    legacy_actions = {
        "generic_selection": lambda: legacy_client._get_target_pod("formal-attempt"),
        "logs": lambda: legacy_client.logs("formal-attempt"),
        "exec": lambda: legacy_client.exec("formal-attempt", ["id"]),
        "volume": lambda: legacy_client.resolve_volume_path("formal-attempt", "/workspace"),
        "pod_list": lambda: legacy_client.list_pods("formal-attempt"),
    }
    for action, call in legacy_actions.items():
        with pytest.raises(forbidden, match="^" + SAFE_DENIAL + "$"):
            call()
        events.append({"event": "legacy_rejected", "surface": action})

    selectors = [str(event["selector"]) for event in events if event["event"] == "pod_selection"]
    assert selectors and all(f"{V2_LABEL}!={V2_LABEL_VALUE}" in value for value in selectors)
    assert not any(str(event["event"]).startswith("DANGEROUS_") for event in events)

    # The constructor must preserve an explicitly selected V1 namespace.
    monkeypatch.setattr(k8s.config, "load_incluster_config", lambda: None)
    monkeypatch.setattr(k8s.client, "AppsV1Api", lambda: SimpleNamespace())
    monkeypatch.setattr(k8s.client, "CoreV1Api", lambda: SimpleNamespace())
    assert k8s.KCSClient(namespace="debug-team").namespace == "debug-team"

    class HttpClient:
        namespace = "default"
        _kubeconfig = None

        def get(self, name: str) -> dict[str, str]:
            return {"name": name}

        def exec(self, *args: object, **kwargs: object) -> None:
            raise forbidden()

        def _get_target_pod(self, *args: object, **kwargs: object) -> None:
            raise forbidden()

        def resolve_volume_path(self, *args: object, **kwargs: object) -> str:
            events.append({"event": "DANGEROUS_nfs_resolution"})
            return str(tmp_path)

    http_service = SimpleNamespace(
        cluster_config=None,
        get_client=lambda: HttpClient(),
        get_kubeconfig_path=lambda: "/unused/kubeconfig",
    )
    monkeypatch.setattr(services, "_service", http_service)

    proxy_pod = {
        "metadata": {
            "name": "formal-attempt-pod",
            "namespace": "default",
            "labels": {V2_LABEL: V2_LABEL_VALUE},
        }
    }

    def proxy_kubectl(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        events.append({"event": "proxy_pod_selection"})
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"items": [proxy_pod]}), "")

    monkeypatch.setattr(shell_proxy, "_get_namespace", lambda kubeconfig=None: "default")
    monkeypatch.setattr(shell_proxy.subprocess, "run", proxy_kubectl)

    def proxy_side_effect_bomb(*args: object, **kwargs: object) -> None:
        events.append({"event": "DANGEROUS_proxy_socket_wrapper_or_session"})
        raise AssertionError("proxy side effect must not run")

    monkeypatch.setattr(shell_proxy, "_socket_path", proxy_side_effect_bomb)
    monkeypatch.setattr(shell_proxy, "_ensure_wrapper", proxy_side_effect_bomb)
    monkeypatch.setattr(shell_proxy, "ShellSession", proxy_side_effect_bomb)

    with TestClient(create_app(api_mode="v1"), raise_server_exceptions=False) as client:
        responses = {
            "http_exec": client.post(
                "/api/v1/containers/formal-attempt/exec", json={"command": ["id"]}
            ),
            "http_upload": client.post(
                "/api/v1/containers/formal-attempt/upload?path=/workspace/result.txt",
                files={"file": ("result.txt", b"must-not-write")},
            ),
            "http_shell": client.post("/api/v1/containers/formal-attempt/shell/sessions"),
            "http_proxy": client.post(
                "/api/v1/shell-proxy/start", json={"container": "formal-attempt"}
            ),
        }
    for surface, response in responses.items():
        assert response.status_code == 403, (surface, response.text)
        assert response.json() == {"detail": SAFE_DENIAL}
        events.append({"event": "http_rejected", "surface": surface, "status": 403})
    with pytest.raises(forbidden, match="^" + SAFE_DENIAL + "$"):
        shell_proxy.run_server("formal-attempt")
    events.append({"event": "proxy_run_server_rejected"})
    assert not any(str(event["event"]).startswith("DANGEROUS_") for event in events)

    # The CLI independently rejects V2 metadata before local kubectl, and pins the
    # allowed debug namespace explicitly instead of inheriting kubectl context.
    exec_calls: list[list[str]] = []
    monkeypatch.setattr(
        cli,
        "_api",
        lambda *args, **kwargs: {
            "pods": [
                {
                    "name": "formal-attempt-pod",
                    "namespace": V2_NAMESPACE,
                    "labels": {V2_LABEL: V2_LABEL_VALUE},
                }
            ]
        },
    )
    monkeypatch.setattr(cli.os, "execvpe", lambda *args: exec_calls.append(list(args[1])))
    rejected_cli = CliRunner().invoke(cli.main, ["ssh", "formal-attempt"])
    assert rejected_cli.exit_code != 0
    assert SAFE_DENIAL in rejected_cli.output
    assert exec_calls == []

    monkeypatch.setattr(
        cli,
        "_api",
        lambda *args, **kwargs: {
            "pods": [{"name": "debug-pod", "namespace": "debug-team", "labels": {}}]
        },
    )
    allowed_cli = CliRunner().invoke(cli.main, ["ssh", "debug"])
    assert allowed_cli.exit_code == 0, allowed_cli.output
    assert exec_calls[0][:7] == [
        "kubectl",
        "exec",
        "-it",
        "debug-pod",
        "-n",
        "debug-team",
        "--",
    ]
    events.extend(
        [
            {"event": "cli_v2_rejected_before_exec"},
            {"event": "cli_debug_namespace_pinned", "namespace": "debug-team"},
        ]
    )

    # Parse the deploy artifacts as Kubernetes objects, not as source-text checks.
    repo = Path(__file__).resolve().parents[1]
    rbac_docs = {
        doc["kind"] + "/" + doc["metadata"]["name"]: doc
        for doc in yaml.safe_load_all((repo / "deploy/v2/rbac.yaml").read_text())
        if doc
    }
    role = rbac_docs["Role/kcs-v2-api"]
    binding = rbac_docs["RoleBinding/kcs-v2-api"]
    workload = rbac_docs["ServiceAccount/kcs-v2-workload"]
    assert role["metadata"]["namespace"] == V2_NAMESPACE
    assert binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "kcs-v2-api", "namespace": V2_NAMESPACE}
    ]
    assert workload["automountServiceAccountToken"] is False
    rules = {
        (tuple(rule["apiGroups"]), tuple(rule["resources"])): set(rule["verbs"])
        for rule in role["rules"]
    }
    assert rules == {
        (("batch",), ("jobs",)): {"create", "get", "patch", "delete"},
        (("",), ("pods",)): {"get", "list", "patch"},
        (("",), ("pods/log",)): {"get"},
        (("",), ("pods/exec",)): {"get", "create"},
        (("",), ("configmaps",)): {"create", "get", "list", "update", "delete"},
        (("",), ("secrets",)): {"create", "get", "delete"},
    }
    policy = yaml.safe_load((repo / "deploy/v2/network-policy.yaml").read_text())
    assert policy["metadata"]["namespace"] == V2_NAMESPACE
    assert policy["spec"] == {
        "podSelector": {"matchLabels": {V2_LABEL: V2_LABEL_VALUE}},
        "policyTypes": ["Ingress"],
        "ingress": [],
    }
    events.append({"event": "deploy_policy_verified", "egress_restricted": False})

    # SSH uses the configured private key and preserves sshpass's fd transport.
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    identity = fake_home / "worker-key"
    identity.write_text("not-a-real-key")
    identity.chmod(0o600)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setattr(services.shutil, "which", lambda name: "/usr/bin/sshpass")
    ssh_observation: dict[str, object] = {}

    def fake_ssh_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        pass_fd = list(kwargs["pass_fds"])[0]  # type: ignore[arg-type]
        ssh_observation["password_pipe_ok"] = os.read(pass_fd, 64) == b"pipe-secret\n"
        ssh_observation["argv"] = cmd
        return subprocess.CompletedProcess(["ssh"], 0, "ok\n", "")

    monkeypatch.setattr(services.subprocess, "run", fake_ssh_run)
    services._run_ssh(
        "worker@example.invalid",
        "hostname",
        password="pipe-secret",
        identity_file="~/worker-key",
    )
    argv = ssh_observation["argv"]
    assert isinstance(argv, list)
    assert argv[argv.index("-i") + 1] == str(identity)
    assert any(
        value == "-o" and argv[index + 1] == "IdentitiesOnly=yes"
        for index, value in enumerate(argv[:-1])
    )
    assert ssh_observation["password_pipe_ok"] is True
    assert str(identity) not in caplog.text

    identity_link = fake_home / "worker-key-link"
    identity_link.symlink_to(identity)
    with pytest.raises(ValueError) as linked_identity:
        services._run_ssh(
            "worker@example.invalid",
            "hostname",
            identity_file="~/worker-key-link",
        )
    assert str(identity_link) not in str(linked_identity.value)

    identity.chmod(0o640)
    with pytest.raises(ValueError) as invalid_identity:
        services._run_ssh(
            "worker@example.invalid",
            "hostname",
            identity_file="~/worker-key",
        )
    assert str(identity) not in str(invalid_identity.value)
    worker = WorkerNode(
        host="example.invalid",
        password="password-sentinel",
        ssh_key="identity-sentinel",
    )
    assert "password-sentinel" not in repr(worker)
    assert "identity-sentinel" not in repr(worker)

    # Exercise the worker orchestration seam with all remote execution replaced by
    # an in-memory observer; this proves WorkerNode.ssh_key is threaded by the service.
    identity.chmod(0o600)
    remote_identities: list[str | None] = []

    def observed_remote(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        remote_identities.append(kwargs.get("identity_file"))  # type: ignore[arg-type]
        stdout = "worker-node\n" if len(args) > 1 and args[1] == "hostname" else ""
        return subprocess.CompletedProcess(["ssh"], 0, stdout, "")

    def local_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        stdout = "192.0.2.10\n" if cmd[:2] == ["hostname", "-I"] else ""
        return subprocess.CompletedProcess(cmd, 0, stdout, "")

    monkeypatch.setattr(services, "_run_ssh", observed_remote)
    monkeypatch.setattr(services.subprocess, "run", local_run)
    monkeypatch.setattr(services, "read_k3s_token", lambda password=None: "token-sentinel")
    monkeypatch.setattr(services, "get_registry", lambda: None)
    monkeypatch.setattr(services.os.path, "exists", lambda path: False)
    cluster = services.ClusterService(
        ClusterConfig(
            backend="k3s",
            sudo_password="sudo-sentinel",
            workers=[worker.model_copy(update={"ssh_key": "~/worker-key"})],
        )
    )
    cluster.get_client = lambda: SimpleNamespace(
        core_v1=SimpleNamespace(list_node=lambda **kwargs: SimpleNamespace(items=[]))
    )
    cluster._prune_stale_workers = lambda config, names: []
    caplog.set_level("INFO", logger="kcs")
    cluster.apply_config()
    cluster.setup_nfs()
    assert remote_identities and set(remote_identities) == {"~/worker-key"}
    assert "token-sentinel" not in caplog.text
    events.append(
        {
            "event": "ssh_identity_verified",
            "identity_argv": True,
            "identities_only": True,
            "password_pipe": True,
            "symlink_rejected": True,
            "insecure_mode_rejected": True,
            "secret_or_path_logged": False,
        }
    )

    print(json.dumps({"journey": "task8-isolation", "events": events}, sort_keys=True))
