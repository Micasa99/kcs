from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from kcs.jobs.canonical import canonical_digest
from kcs.jobs.provider import V2JobProvider
from kcs.jobs.recipe_registry import NativeRecipeRegistry, runtime_recipe_digest
from kcs.jobs.runtime_assembly import NativeCapabilityRegistry, RuntimeAssemblyResolver
from kcs.jobs.transport import LocalWorkspaceRpcTransport
from kcs.runtime_control.workspace_sidecar import RuntimeControlSidecar

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 10, 1, 0, tzinfo=UTC)


class _CatalogStore:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str], SimpleNamespace] = {}

    def reserve_catalog(
        self, kind: str, identity: str, digest: str, payload: dict[str, object]
    ) -> tuple[SimpleNamespace, bool]:
        key = (kind, identity)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        retained = self.records.get(key)
        if retained is not None:
            assert retained.digest == digest
            assert retained.payload == encoded
            return retained, False
        retained = SimpleNamespace(digest=digest, payload=encoded)
        self.records[key] = retained
        return retained, True

    def read_catalog(self, kind: str, identity: str) -> SimpleNamespace | None:
        return self.records.get((kind, identity))


def _assembly_resolver(tmp_path: Path) -> tuple[RuntimeAssemblyResolver, str]:
    recipe = json.loads(
        (ROOT / "openapi/native-fixtures/runtime-recipe-assembled.json").read_text()
    )
    recipe["recipeDigest"] = runtime_recipe_digest(recipe)
    recipes_path = tmp_path / "recipes.json"
    recipes_path.write_text(
        json.dumps(
            {
                "version": 1,
                "recipes": [
                    {
                        "recipe": recipe,
                        "requires": ["linux-amd64", "workspace-rw"],
                        "provides": ["linux-amd64", "workspace-rw", "nvidia-gpu"],
                    }
                ],
            }
        )
    )
    capabilities_path = tmp_path / "capabilities.json"
    capabilities_path.write_text(
        json.dumps(
            {
                "version": 1,
                "capabilities": [
                    {
                        "kind": kind,
                        "capabilityRef": f"{kind}.probe@1.0.0",
                        "materialDigest": digest,
                        "imageVolumeDigest": (
                            f"registry.example/{kind}@sha256:{image_digest}"
                        ),
                        "sourcePath": f"/bundle/{kind}",
                        "targetPath": f"/opt/rc-{kind}s/probe",
                        "runnerDiscoveryPath": f"/opt/rc-{kind}s/probe",
                        "runnerRefs": ["runner-codex"],
                        "environmentProfileRefs": ["env-default"],
                        "modelProtocols": ["openai-responses"],
                    }
                    for kind, digest, image_digest in (
                        ("skill", "a" * 64, "1" * 64),
                        ("tool", "b" * 64, "2" * 64),
                    )
                ],
            }
        )
    )
    return (
        RuntimeAssemblyResolver(
            NativeRecipeRegistry(recipes_path),
            NativeCapabilityRegistry(capabilities_path),
            clock=lambda: NOW,
        ),
        recipe["recipeDigest"],
    )


def test_exact_assembly_survives_provider_restart_with_opaque_owner_lock(
    tmp_path: Path,
) -> None:
    resolver, recipe_digest = _assembly_resolver(tmp_path)
    store = _CatalogStore()
    first = object.__new__(V2JobProvider)
    first._runtime_assembly_resolver = resolver
    first._store = store
    first._clock = lambda: NOW
    request = {
        "runnerRef": "runner-codex",
        "environmentProfileRef": "env-default",
        "recipeDigest": recipe_digest,
        "capabilityLockDigest": "e" * 64,
        "selectedModelProtocol": "openai-responses",
        "skillPins": [
            {"capabilityRef": "skill.probe@1.0.0", "materialDigest": "a" * 64}
        ],
        "toolPins": [
            {"capabilityRef": "tool.probe@1.0.0", "materialDigest": "b" * 64}
        ],
    }

    resolved = first.resolve_runtime_assembly(request)
    plan = resolved.root["capabilityActivation"]
    assert plan["capabilityLockDigest"] == "e" * 64
    assert [mount["kind"] for mount in plan["mounts"]] == ["skill", "tool"]

    restarted = object.__new__(V2JobProvider)
    restarted._store = store
    restarted._clock = lambda: NOW
    restored = restarted.runtime_assembly_by_digest(resolved.root["assemblyDigest"])
    restored_plan = restarted.capability_activation_plan(
        plan["planRef"], plan["planDigest"]
    )
    assert restored.root["assemblyDigest"] == resolved.root["assemblyDigest"]
    assert restored_plan.root == plan


def test_live_snapshot_rpc_is_immutable_bounded_and_releasable(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    control = RuntimeControlSidecar(
        workspace,
        tmp_path / "control-state",
        clock=lambda: NOW,
    )
    transport = LocalWorkspaceRpcTransport(control.dispatch, temp_dir=tmp_path)
    original = b"original\n"
    tree_digest = _stage_single_file(transport, original)
    base_manifest_digest = "a" * 64
    control._bind_latest_base_manifest(base_manifest_digest)

    task = workspace / "worktree/TASK.md"
    during = b"during-attempt\n"
    task.write_bytes(during)
    results = workspace / "worktree/results"
    results.mkdir()
    (results / "metrics.jsonl").write_bytes(b'{"loss":0.2}\n')
    os.symlink("TASK.md", workspace / "worktree/task-link")
    spec = {
        "jobUid": "11111111-1111-4111-8111-111111111111",
        "podUid": "22222222-2222-4222-8222-222222222222",
        "generation": 1,
        "baseManifestDigest": base_manifest_digest,
        "ttlSeconds": 60,
        "maximumEntries": 20,
        "maximumBytes": 4096,
    }
    identity = {
        "snapshotRef": "snapshot-focused-1",
        "requestDigest": canonical_digest(spec),
        "jobRef": "job-focused-1",
        "jobUid": spec["jobUid"],
        "podUid": spec["podUid"],
        "generation": 1,
        "baseManifestDigest": base_manifest_digest,
    }
    created = transport.rpc(
        {},
        {"action": "createLiveWorkspaceSnapshot", **identity, **spec},
    ).header
    assert created["ok"] is True
    snapshot = created["snapshot"]
    assert snapshot["baseManifestDigest"] == base_manifest_digest
    assert {entry["kind"] for entry in snapshot["entries"]} == {
        "file",
        "directory",
        "symlink",
    }
    assert tree_digest != snapshot["snapshotDigest"]

    task.write_bytes(b"after-snapshot\n")
    content = transport.rpc(
        {},
        {
            "action": "readLiveWorkspaceContent",
            **identity,
            "path": "TASK.md",
            "offset": 0,
            "limitBytes": 1048576,
        },
    )
    assert content.content_path is not None
    try:
        assert content.content_path.read_bytes() == during
    finally:
        content.content_path.unlink(missing_ok=True)
    assert content.header["snapshotDigest"] == snapshot["snapshotDigest"]

    diff = transport.rpc(
        {},
        {
            "action": "getLiveWorkspaceDiff",
            **identity,
            "pageToken": None,
            "pageSize": 20,
        },
    ).header["page"]
    changes = {(item["path"], item["change"]) for item in diff["items"]}
    assert ("TASK.md", "modified") in changes
    assert ("results/metrics.jsonl", "added") in changes

    released = transport.rpc(
        {}, {"action": "releaseLiveWorkspaceSnapshot", **identity}
    ).header
    assert released["snapshot"]["state"] == "released"
    inspected = transport.rpc(
        {}, {"action": "inspectLiveWorkspaceSnapshot", **identity}
    ).header
    assert inspected["ok"] is False
    assert inspected["code"] == "STATE_CONFLICT"


def _stage_single_file(transport: LocalWorkspaceRpcTransport, content: bytes) -> str:
    digest = hashlib.sha256(content).hexdigest()
    tree_digest = canonical_digest(
        {
            "schema": "cosmos.workspace-tree/1",
            "entries": [
                {
                    "path": "TASK.md",
                    "blobDigest": digest,
                    "size": len(content),
                    "mode": "read_write",
                }
            ],
        }
    )
    payload = {
        "base_manifest": {
            "manifest_ref": {"kind": "workspace_base_manifest", "id": "base-1"},
            "tree_digest": tree_digest,
            "entries": [
                {
                    "path": "TASK.md",
                    "size": len(content),
                    "sha256": digest,
                    "mode": "read_write",
                }
            ],
        },
        "compute_lease_ref": {"kind": "compute_lease", "id": "lease-1"},
        "bulk_transfer": False,
        "inline_contents": [
            {
                "path": "TASK.md",
                "content_b64": base64.b64encode(content).decode(),
            }
        ],
    }
    frame = {
        "protocol": "cosmos.workspace/1",
        "action": "stage_tree",
        "operation_id": "workspace-stage-tree:live-test",
        "request_digest": "c" * 64,
        "frame_digest": canonical_digest(payload),
        "payload": payload,
    }
    reply = transport.rpc(
        {},
        {
            "action": "invoke",
            "operationRef": "operation-live-stage",
            "requestDigest": "d" * 64,
            "dispatchToken": "e" * 32,
            "frame": frame,
        },
    ).header
    assert reply.get("state") == "succeeded", reply
    return tree_digest
