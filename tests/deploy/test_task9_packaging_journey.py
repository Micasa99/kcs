"""One focused local Journey for the Task 9 package/deployment boundary."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SHA256 = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")
ZERO_DIGEST_IMAGE = (
    "registry.example.invalid/researchcosmos/kcs-api@sha256:"
    "0000000000000000000000000000000000000000000000000000000000000000"
)
SYNTHETIC_API_IMAGE = (
    "registry.example.invalid/researchcosmos/kcs-api@sha256:"
    "1111111111111111111111111111111111111111111111111111111111111111"
)


def _documents(path: str) -> list[dict[str, object]]:
    return [item for item in yaml.safe_load_all((ROOT / path).read_text()) if item]


def _wait_for_socket(path: Path) -> None:
    deadline = time.monotonic() + 5
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert path.exists(), f"fixture socket was not created: {path}"


def _agent_rpc(environment: dict[str, str], payload: dict[str, object]) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, "-m", "kcs.conformance.agent_supervisor", "rpc"],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env=environment,
        check=True,
    )
    lines = result.stdout.splitlines()
    assert len(lines) == 1
    return json.loads(lines[0])


def _workspace_rpc(environment: dict[str, str], payload: dict[str, object]) -> dict[str, object]:
    header = dict(payload, bodySize=0)
    encoded = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    result = subprocess.run(
        [sys.executable, "-m", "kcs.conformance.workspace_sidecar", "rpc"],
        input=struct.pack(">I", len(encoded)) + encoded,
        capture_output=True,
        env=environment,
        check=True,
    )
    size = struct.unpack(">I", result.stdout[:4])[0]
    return json.loads(result.stdout[4 : 4 + size])


def test_task9_packaging_journey(tmp_path: Path) -> None:
    """Packaged API, fixed fixtures, and deployment checks form one closed journey."""
    events: list[dict[str, object]] = []

    canonical = (ROOT / "openapi/generated/kcs-v2-jobs.openapi.json").read_bytes()
    packaged = (
        importlib.resources.files("kcs.openapi").joinpath("kcs-v2-jobs.openapi.json").read_bytes()
    )
    digest = hashlib.sha256(packaged).hexdigest()
    assert packaged == canonical
    assert digest == "965ec1236bab74d2306ce96c97109abc12f80971f18dc32b3bb7602bc8fed526"
    events.append({"event": "canonical_package_resource", "sha256": digest})

    namespace = _documents("deploy/v2/namespace.yaml")[0]
    assert namespace["kind"] == "Namespace"
    assert namespace["metadata"]["name"] == "researchcosmos-v2"  # type: ignore[index]

    rbac = {
        f"{item['kind']}/{item['metadata']['name']}": item  # type: ignore[index]
        for item in _documents("deploy/v2/rbac.yaml")
    }
    assert set(rbac) == {
        "ServiceAccount/kcs-v2-api",
        "ServiceAccount/kcs-v2-workload",
        "Role/kcs-v2-api",
        "RoleBinding/kcs-v2-api",
        "ClusterRole/kcs-v2-capacity-reader",
        "ClusterRoleBinding/kcs-v2-capacity-reader",
    }
    assert rbac["ServiceAccount/kcs-v2-workload"]["automountServiceAccountToken"] is False
    binding = rbac["RoleBinding/kcs-v2-api"]
    assert binding["subjects"] == [
        {
            "kind": "ServiceAccount",
            "name": "kcs-v2-api",
            "namespace": "researchcosmos-v2",
        }
    ]
    expected_verbs = {
        ("batch", "jobs"): {"create", "get", "list", "patch", "delete"},
        ("", "pods"): {"get", "list", "patch"},
        ("", "pods/log"): {"get"},
        ("", "pods/exec"): {"get", "create"},
        ("", "configmaps"): {"create", "get", "list", "update", "delete"},
        ("", "secrets"): {"create", "get", "delete"},
        ("metrics.k8s.io", "pods"): {"get", "list"},
        ("", "events"): {"get", "list", "watch"},
    }
    actual_verbs = {
        (rule["apiGroups"][0], resource): set(rule["verbs"])
        for rule in rbac["Role/kcs-v2-api"]["rules"]
        for resource in rule["resources"]
    }
    assert actual_verbs == expected_verbs
    assert rbac["ClusterRole/kcs-v2-capacity-reader"]["rules"] == [
        {"apiGroups": [""], "resources": ["nodes"], "verbs": ["list"]}
    ]

    api_docs = _documents("deploy/v2/kcs-api.yaml")
    deployment = next(item for item in api_docs if item["kind"] == "Deployment")
    service = next(item for item in api_docs if item["kind"] == "Service")
    spec = deployment["spec"]
    assert spec["replicas"] == 1 and spec["strategy"] == {"type": "Recreate"}
    pod = spec["template"]["spec"]
    assert pod["serviceAccountName"] == "kcs-v2-api"
    assert pod["nodeSelector"] == {"researchcosmos.io/role": "control"}
    assert pod["automountServiceAccountToken"] is True
    container = pod["containers"][0]
    assert SHA256.fullmatch(container["image"])
    assert container["image"] == ZERO_DIGEST_IMAGE
    assert container["image"] != SYNTHETIC_API_IMAGE
    assert container["env"] and container["volumeMounts"]
    assert container["startupProbe"]["httpGet"]["scheme"] == "HTTPS"
    assert container["readinessProbe"]["httpGet"]["scheme"] == "HTTPS"
    assert container["livenessProbe"]["httpGet"]["scheme"] == "HTTPS"
    assert "ephemeral-storage" in container["resources"]["requests"]
    assert "ephemeral-storage" in container["resources"]["limits"]
    assert {volume["name"] for volume in pod["volumes"]} == {"tls", "tmp", "state"}
    assert service["spec"]["type"] == "ClusterIP"
    assert service["spec"]["ports"] == [{"name": "https", "port": 443, "targetPort": "https"}]
    events.append({"event": "api_manifest_contract", "imageState": "non_runnable_placeholder"})

    plugin = _documents("deploy/v2/nvidia-device-plugin.yaml")
    daemonset = next(item for item in plugin if item["kind"] == "DaemonSet")
    plugin_image = daemonset["spec"]["template"]["spec"]["containers"][0]["image"]
    assert daemonset["spec"]["template"]["spec"]["nodeSelector"] == {
        "researchcosmos.io/pool": "gpu"
    }
    assert plugin_image == (
        "nvcr.io/nvidia/k8s-device-plugin@"
        "sha256:7bf6ab18378be099493c9fe50f9cd2d559e0d81f17742d7ac188365408579d5d"
    )

    for path in (
        "Containerfile",
        "deploy/v2/conformance-agent.Containerfile",
        "deploy/v2/conformance-workspace.Containerfile",
    ):
        text = (ROOT / path).read_text()
        from_lines = [line for line in text.splitlines() if line.startswith("FROM ")]
        assert from_lines and all(
            "linux/amd64" in line and "@sha256:" in line for line in from_lines
        )
        assert "org.opencontainers.image.revision" in text
        assert 'org.opencontainers.image.licenses="MIT"' in text
        assert "setuptools==80.9.0" in text and "wheel==0.45.1" in text
        assert "--no-build-isolation" in text
    requirements = [
        line
        for line in (ROOT / "requirements.lock").read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert requirements and all("==" in line for line in requirements)
    build_system = tomllib.loads((ROOT / "pyproject.toml").read_text())["build-system"]
    assert build_system["requires"] == ["setuptools==80.9.0", "wheel==0.45.1"]
    events.append({"event": "oci_inputs_pinned", "runtime_requirements": len(requirements)})

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    credential = tmp_path / "credential"
    credential.write_bytes(b"synthetic-task9-credential")
    socket_temp = tempfile.TemporaryDirectory(prefix="kcs-task9-")
    agent_socket = Path(socket_temp.name) / "agent.sock"
    workspace_socket = Path(socket_temp.name) / "workspace.sock"
    environment = {
        **os.environ,
        "KCS_AGENT_SOCKET": str(agent_socket),
        "KCS_CREDENTIAL_PATH": str(credential),
        "KCS_WORKSPACE": str(workspace),
        "KCS_WORKSPACE_SOCKET": str(workspace_socket),
        "RC_PUBLIC_RUNTIME_BASE_URL": "http://127.0.0.1:9/forbidden",
    }
    processes = [
        subprocess.Popen(
            [sys.executable, "-m", "kcs.conformance.agent_supervisor"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        ),
        subprocess.Popen(
            [sys.executable, "-m", "kcs.conformance.workspace_sidecar"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        ),
    ]
    try:
        _wait_for_socket(agent_socket)
        _wait_for_socket(workspace_socket)
        agent_write = _agent_rpc(environment, {"protocolVersion": 1, "action": "sharedWrite"})
        workspace_read = _workspace_rpc(
            environment, {"protocolVersion": 1, "action": "sharedRead", "sourceRole": "agent"}
        )
        workspace_write = _workspace_rpc(
            environment, {"protocolVersion": 1, "action": "sharedWrite"}
        )
        agent_read = _agent_rpc(
            environment, {"protocolVersion": 1, "action": "sharedRead", "sourceRole": "workspace"}
        )
        assert agent_write["sha256"] == workspace_read["sha256"]
        assert workspace_write["sha256"] == agent_read["sha256"]
        no_gpu = _agent_rpc(environment, {"protocolVersion": 1, "action": "observeNoGpu"})
        assert no_gpu == {
            "event": "agent_gpu_observation",
            "gpuDeviceCount": 0,
            "ok": True,
            "protocolVersion": 1,
        }
        runtime = _agent_rpc(environment, {"protocolVersion": 1, "action": "probeRuntimeUrl"})
        assert runtime["ok"] is False and runtime["code"] == "LOOPBACK_RUNTIME_URL"
        gpu = _workspace_rpc(environment, {"protocolVersion": 1, "action": "observeGpu"})
        assert gpu["event"] == "workspace_gpu_observation"
        assert gpu["ok"] is False and gpu["code"] == "GPU_UNAVAILABLE"
        events.extend(
            [
                {"event": "shared_agent_to_workspace", "sha256": agent_write["sha256"]},
                {"event": "shared_workspace_to_agent", "sha256": workspace_write["sha256"]},
                no_gpu,
                runtime,
                gpu,
            ]
        )
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=5)
        socket_temp.cleanup()

    token = tmp_path / "service-token"
    token.write_bytes(b"synthetic-task9-service-token")
    join_token = tmp_path / "join-token"
    join_token.write_bytes(b"synthetic-task9-join-token")
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("synthetic-certificate\n")
    key.write_text("synthetic-private-key\n")
    deploy_environment = {
        **os.environ,
        "KCS_CONTROL_SSH_ALIAS": "kcs-control",
        "KCS_WORKER_SSH_ALIAS": "kcs-worker",
        "KCS_CONTROL_PRIVATE_ADDRESS": "10.77.0.10",
        "KCS_WORKER_PRIVATE_ADDRESS": "10.77.0.20",
        "KCS_ALLOWED_PEER_CIDRS": "10.77.0.0/24",
        "KCS_PORT_FORWARD_ADDRESS": "10.77.0.10",
        "KCS_TLS_SAN": "kcs-v2.internal.example",
        "KCS_K3S_VERSION": "v1.33.3+k3s1",
        "KCS_NVIDIA_TOOLKIT_VERSION": "1.17.8-1",
        "KCS_WORKER_WORKSPACE_ROOT": "/scratch/kcs-workspaces",
        "KCS_WORKSPACE_STORAGE_ROOT": "/scratch/kcs-workspaces",
        "KCS_API_IMAGE": SYNTHETIC_API_IMAGE,
        "KCS_KUBE_STATE_METRICS_IMAGE": SYNTHETIC_API_IMAGE,
        "KCS_DCGM_EXPORTER_IMAGE": SYNTHETIC_API_IMAGE,
        "KCS_PROMETHEUS_IMAGE": SYNTHETIC_API_IMAGE,
        "KCS_ALERTMANAGER_IMAGE": SYNTHETIC_API_IMAGE,
        "KCS_TLS_CERT_FILE": str(cert),
        "KCS_TLS_KEY_FILE": str(key),
        "KCS_SERVICE_TOKEN_FILE": str(token),
        "KCS_K3S_TOKEN_FILE": str(join_token),
        "KCS_WORKER_NODE_NAME": "kcs-gpu-worker",
        "KCS_LEGACY_DEBUG_UNITS": "kcs.service",
        "KCS_LEGACY_SERVICE_ACCOUNT": "kcs-debug",
    }
    for script in ("scripts/deploy_v2_control.sh", "scripts/deploy_v2_worker.sh"):
        result = subprocess.run(
            ["bash", str(ROOT / script), "--check"],
            capture_output=True,
            text=True,
            env=deploy_environment,
            check=True,
        )
        check_event = json.loads(result.stdout.strip())
        assert check_event == {"event": "deployment_check", "ok": True, "script": Path(script).stem}
        events.append(check_event)

        unsafe_cidr_environment = {
            **deploy_environment,
            "KCS_ALLOWED_PEER_CIDRS": "10.77.0.0/24,169.254.0.0/16",
        }
        unsafe_cidr = subprocess.run(
            ["bash", str(ROOT / script), "--check"],
            capture_output=True,
            text=True,
            env=unsafe_cidr_environment,
        )
        assert unsafe_cidr.returncode != 0
        assert "nonpublic peer CIDRs" in unsafe_cidr.stderr

        cgnat_environment = {
            **deploy_environment,
            "KCS_CONTROL_PRIVATE_ADDRESS": "100.64.7.10",
            "KCS_WORKER_PRIVATE_ADDRESS": "100.64.7.20",
            "KCS_ALLOWED_PEER_CIDRS": "100.64.7.0/24",
            "KCS_PORT_FORWARD_ADDRESS": "100.64.7.10",
        }
        cgnat = subprocess.run(
            ["bash", str(ROOT / script), "--check"],
            capture_output=True,
            text=True,
            env=cgnat_environment,
            check=True,
        )
        assert json.loads(cgnat.stdout) == {
            "event": "deployment_check",
            "ok": True,
            "script": Path(script).stem,
        }

    zero_digest = subprocess.run(
        ["bash", str(ROOT / "scripts/deploy_v2_control.sh"), "--check"],
        capture_output=True,
        text=True,
        env={**deploy_environment, "KCS_API_IMAGE": ZERO_DIGEST_IMAGE},
    )
    assert zero_digest.returncode == 2
    assert "nonzero digest-pinned image" in zero_digest.stderr

    bind_validator = ROOT / "deploy/v2/kcs-v2-port-forward.py"
    public_bind = subprocess.run(
        [sys.executable, str(bind_validator), "8.8.8.8", "8.8.8.8"],
        capture_output=True,
        text=True,
    )
    assert public_bind.returncode == 2
    assert "private or non-global overlay" in public_bind.stderr

    exec_validator = ROOT / "deploy/v2/kcs-v2-validate-k3s-exec.py"
    effective_exec = (
        "{ path=/usr/local/bin/k3s ; argv[]=/usr/local/bin/k3s server "
        "--bind-address=10.77.0.10 --advertise-address=10.77.0.10 "
        "--node-ip=10.77.0.10 --tls-san=kcs-v2.internal.example "
        "--node-label=researchcosmos.io/role=control --flannel-iface=eth0 "
        "--kubelet-arg=address=10.77.0.10 "
        "--default-local-storage-path=/scratch/kcs-workspaces ; ignore_errors=no ; }"
    )
    subprocess.run(
        [
            sys.executable,
            str(exec_validator),
            "control",
            "10.77.0.10",
            "kcs-v2.internal.example",
            "eth0",
            "/scratch/kcs-workspaces",
        ],
        input=effective_exec,
        text=True,
        check=True,
    )
    conflicting_exec = effective_exec.replace(
        "--bind-address=10.77.0.10", "--bind-address=10.77.0.10 --bind-address=0.0.0.0"
    )
    conflict = subprocess.run(
        [
            sys.executable,
            str(exec_validator),
            "control",
            "10.77.0.10",
            "kcs-v2.internal.example",
            "eth0",
            "/scratch/kcs-workspaces",
        ],
        input=conflicting_exec,
        capture_output=True,
        text=True,
    )
    assert conflict.returncode == 2
    assert conflict.stderr == "effective k3s service configuration mismatch\n"

    assert token.read_bytes() == b"synthetic-task9-service-token"
    assert b"\n" not in token.read_bytes()
    for event in events:
        print(json.dumps(event, sort_keys=True, separators=(",", ":")))
