from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from kcs.jobs.project_workspace import ProjectWorkspaceRenderer
from kcs.jobs.settings import V2RuntimeSettings
from kcs.jobs.transport import LocalWorkspaceRpcTransport
from kcs.runtime_control.workspace_sidecar import (
    RuntimeControlSidecar,
    _workspace_tree_digest,
)


def test_project_workspace_is_persistent_cpu_only_and_installs_exact_extension() -> None:
    digest = "1" * 64
    settings = V2RuntimeSettings(
        namespace="project-workspace-test",
        node_selector={"researchcosmos.io/pool": "gpu"},
        api_mode="v2",
        service_token=None,
        native_openvscode_image_volume=f"registry.example/openvscode@sha256:{'2' * 64}",
        native_dev_session_relay_image=f"registry.example/relay@sha256:{'3' * 64}",
        project_workspace_control_image=f"registry.example/control@sha256:{'4' * 64}",
        project_workspace_vsix_image_volume=f"registry.example/vsix@sha256:{'5' * 64}",
        project_workspace_vsix_sha256=digest,
    )
    renderer = ProjectWorkspaceRenderer(settings)

    pvc = renderer.pvc("workspace-1", 40)
    deployment = renderer.deployment("workspace-1", "conv_project_1")
    pod = deployment.spec.template.spec

    assert pvc.spec.access_modes == ["ReadWriteOnce"]
    assert pvc.spec.resources.requests == {"storage": "40Gi"}
    assert deployment.spec.strategy.type == "Recreate"
    assert pod.automount_service_account_token is False
    assert pod.restart_policy == "Always"
    assert {container.name for container in pod.containers} == {
        "workspace-control",
        "openvscode",
        "relay",
    }
    for container in [*pod.init_containers, *pod.containers]:
        if container.resources is not None:
            assert "nvidia.com/gpu" not in (container.resources.requests or {})
            assert "nvidia.com/gpu" not in (container.resources.limits or {})
    assert not {
        env.name
        for container in [*pod.init_containers, *pod.containers]
        for env in container.env or []
        if "MODEL_GATEWAY" in env.name or "KCS_V2_SERVICE_TOKEN" in env.name
    }
    bootstrap = next(item for item in pod.init_containers if item.name == "ide-bootstrap")
    assert digest in {env.value for env in bootstrap.env}
    assert "--install-extension" in bootstrap.args[0]
    assert "/workspace/.ide/home/.installed-vsix.sha256" in bootstrap.args[0]
    relay = next(item for item in pod.containers if item.name == "relay")
    assert {env.name for env in relay.env} == {
        "LISTEN_ADDR",
        "UPSTREAM_URL",
        "DEV_SESSION_CREDENTIAL_FILE",
    }
    openvscode = next(item for item in pod.containers if item.name == "openvscode")
    assert "/workspace/worktree" in openvscode.args[0]
    control = next(item for item in pod.containers if item.name == "workspace-control")
    control_env = {item.name: item.value for item in control.env}
    assert control_env["AICOSMOS_CONVERSATION_REF"] == "conv_project_1"


def test_snapshot_and_sealed_import_keep_project_and_attempt_git_separate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    worktree = workspace / "worktree"
    worktree.mkdir(parents=True)
    (workspace / "retained").mkdir()
    (worktree / "analysis.py").write_text("print('base')\n")
    monkeypatch.setenv("AICOSMOS_CONVERSATION_REF", "conv_project_1")
    control = RuntimeControlSidecar(workspace, tmp_path / "control-state")
    transport = LocalWorkspaceRpcTransport(control.dispatch, temp_dir=tmp_path)
    configured = transport.rpc(
        {},
        {
            "action": "configureWorkspaceContext",
            "conversationRef": "conv_project_1",
            "productBase": "https://ai-cosmos.example/ai4sci/cosmos/",
        },
    )
    assert configured.header["ok"] is True
    assert configured.header["configured"] is True

    created = transport.rpc(
        {},
        {
            "action": "createProjectWorkspaceSnapshot",
            "workspaceRef": "workspace-1",
            "snapshotRef": "snapshot-1",
            "requestDigest": "a" * 64,
            "generation": 1,
            "maximumFiles": 20,
            "maximumBytes": 1024 * 1024,
        },
    )
    assert created.content_path is not None
    try:
        bundle = json.loads(created.content_path.read_bytes())
    finally:
        created.content_path.unlink(missing_ok=True)
    snapshot = created.header["snapshot"]
    assert _git(worktree, "symbolic-ref", "--short", "HEAD") == "rc/project"
    assert _git(worktree, "status", "--porcelain") == ""
    assert _git(worktree, "rev-parse", "HEAD") == snapshot["baseCommit"]
    private_context = worktree / ".kcs" / "aicosmos.json"
    assert json.loads(private_context.read_text()) == {
        "conversationRef": "conv_project_1",
        "productBase": "https://ai-cosmos.example/ai4sci/cosmos",
    }
    assert all(entry["path"] != ".kcs/aicosmos.json" for entry in bundle["entries"])

    result = b"print('retained result')\n"
    entry = bundle["entries"][0]
    entry.update(
        size=len(result),
        sha256=hashlib.sha256(result).hexdigest(),
        content_b64=base64.b64encode(result).decode(),
    )
    bundle["treeDigest"] = _workspace_tree_digest(
        [{key: entry[key] for key in ("path", "size", "sha256", "mode")}]
    )
    encoded = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
    payload = tmp_path / "sealed-revision.bundle"
    payload.write_bytes(encoded)
    imported = transport.rpc(
        {},
        {
            "action": "importProjectWorkspaceRevision",
            "workspaceRef": "workspace-1",
            "importRef": "import-1",
            "requestDigest": "b" * 64,
            "generation": 1,
            "sourceRevisionRef": "workspace_revision:revision-1",
            "expectedTreeDigest": bundle["treeDigest"],
            "contentSha256": hashlib.sha256(encoded).hexdigest(),
            "declaredSizeBytes": len(encoded),
            "authorizedMaxSizeBytes": 1024 * 1024,
            "baseCommit": snapshot["baseCommit"],
        },
        payload,
    ).header["receipt"]

    retained = workspace / "retained" / imported["retainedCheckoutRef"]
    assert (retained / "analysis.py").read_bytes() == result
    assert _git(retained, "symbolic-ref", "--short", "HEAD").startswith("rc/retained/")
    assert _git(retained, "rev-parse", "HEAD") == imported["resultCommit"]
    assert (worktree / "analysis.py").read_text() == "print('base')\n"
    assert _git(worktree, "rev-parse", "HEAD") == snapshot["baseCommit"]


def _git(worktree: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-c", f"safe.directory={worktree}", *arguments],
        cwd=worktree,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
