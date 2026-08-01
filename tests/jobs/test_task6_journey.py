"""Focused trusted-transfer and exactly-once workspace Journey for Task 6."""

from __future__ import annotations

import hashlib
import io
import json
import warnings
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import pytest
from fastapi import FastAPI

from kcs.conformance.workspace_sidecar import WorkspaceSidecar
from kcs.jobs.canonical import canonical_digest
from kcs.jobs.contracts import (
    OperationState,
    TransferCancelRequest,
    TransferCancelSpec,
    TransferDirection,
    TransferRegisterRequest,
    TransferSpec,
    WorkspaceFrame,
    WorkspaceInvokeRequest,
)
from kcs.jobs.errors import (
    DependencyUnavailableError,
    IdentityDigestConflict,
    OperationIndeterminateError,
    OverwriteForbiddenError,
    TransferBytesMismatchError,
    UnsafePathError,
)
from kcs.jobs.provider import V2JobProvider
from kcs.jobs.store import V2JobStore
from kcs.jobs.transport import LocalWorkspaceRpcTransport, WorkspaceRpcReply
from kcs.server.routes.jobs import create_jobs_router

JOB_UID = UUID("00000000-0000-4000-8000-000000000001")
POD_UID = UUID("00000000-0000-4000-8000-000000000002")
DIGEST = "a" * 64
NOW = datetime(2026, 8, 2, tzinfo=UTC)


class _ConflictError(Exception):
    status = 409


class _Kube:
    namespace = "researchcosmos-v2"

    def __init__(self) -> None:
        self.maps: dict[str, dict[str, Any]] = {}

    def create_config_map(self, body: object) -> object:
        value = json.loads(json.dumps(body))
        name = value["metadata"]["name"]
        if name in self.maps:
            raise _ConflictError()
        value["metadata"]["resourceVersion"] = "1"
        self.maps[name] = value
        return value

    def read_config_map(self, name: str) -> object | None:
        return self.maps.get(name)

    def replace_config_map(self, name: str, body: object) -> object:
        value = json.loads(json.dumps(body))
        value["metadata"]["resourceVersion"] = str(
            int(self.maps[name]["metadata"]["resourceVersion"]) + 1
        )
        self.maps[name] = value
        return value

    def list_config_maps(self, selector: str | None = None) -> list[object]:
        if not selector:
            return list(self.maps.values())
        pairs = [item.split("=", 1) for item in selector.split(",")]
        return [
            item
            for item in self.maps.values()
            if all(item["metadata"]["labels"].get(key) == value for key, value in pairs)
        ]

    def read_job(self, job_ref: str) -> object:
        return {"metadata": {"uid": str(JOB_UID), "resourceVersion": "9"}, "status": {}}

    def list_job_pods(self, job_ref: str, job_uid: str | None = None) -> list[object]:
        statuses = [
            {
                "name": role,
                "ready": True,
                "restart_count": 0,
                "state": {"running": {"started_at": NOW}},
            }
            for role in ("agent", "workspace")
        ]
        return [
            {
                "metadata": {"uid": str(POD_UID)},
                "status": {"container_statuses": statuses},
            }
        ]


class _Renderer:
    def job_ref(self, request: object) -> str:
        return "job-1"

    def render(self, request: object) -> object:
        return {}


def _setup(workspace: Path) -> tuple[_Kube, V2JobStore, WorkspaceSidecar, V2JobProvider]:
    kube = _Kube()
    store = V2JobStore(kube, clock=lambda: NOW)  # type: ignore[arg-type]
    store.reserve_create(
        "request-1",
        DIGEST,
        "job-1",
        {"subjectRef": "s", "runtimePlanDigest": DIGEST, "workspace": {}},
    )
    store.mark_created("request-1", str(JOB_UID))
    store.bind_first_pod("request-1", str(POD_UID))
    sidecar = WorkspaceSidecar(workspace)
    provider = V2JobProvider(
        kube,  # type: ignore[arg-type]
        store,
        _Renderer(),
        clock=lambda: NOW,
        workspace_transport=LocalWorkspaceRpcTransport(sidecar.dispatch),
    )
    return kube, store, sidecar, provider


def _transfer(
    ref: str,
    direction: TransferDirection,
    path: str,
    content: bytes,
    *,
    overwrite: Literal["forbid", "replace_authorized"] = "forbid",
) -> TransferRegisterRequest:
    spec = TransferSpec(
        direction=direction,
        path=path,
        declared_size_bytes=len(content),
        authorized_max_size_bytes=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
        mode="direct",
        overwrite_policy=overwrite,
    )
    return TransferRegisterRequest(
        transfer_ref=ref,
        request_digest=canonical_digest(spec),
        spec=spec,
    )


def test_transfer_bytes_are_atomic_replayable_and_discard_only_private_content(
    tmp_path: Path,
) -> None:
    kube, store, sidecar, provider = _setup(tmp_path)
    content = b"\x00trusted\xff\n" * 8192
    request = _transfer("stage-1", TransferDirection.STAGE_INPUT, "inputs/a.bin", content)

    registered = provider.register_transfer("job-1", request)
    assert registered.created is True and registered.snapshot.state == "registered"
    changed = _transfer(
        "stage-1",
        TransferDirection.STAGE_INPUT,
        "inputs/changed.bin",
        content,
    )
    with pytest.raises(IdentityDigestConflict):
        provider.register_transfer("job-1", changed)
    local = LocalWorkspaceRpcTransport(sidecar.dispatch)
    lost = _LostReply(local, "stage")
    interrupted = V2JobProvider(
        kube,  # type: ignore[arg-type]
        store,
        _Renderer(),
        clock=lambda: NOW,
        workspace_transport=lost,
    )
    with pytest.raises(DependencyUnavailableError, match="not confirmed"):
        interrupted.stage_transfer_content(
            "job-1", "stage-1", io.BytesIO(content), content_length=len(content)
        )
    assert interrupted.inspect_transfer("job-1", "stage-1").state == "staging"
    provider = V2JobProvider(
        kube,  # type: ignore[arg-type]
        store,
        _Renderer(),
        clock=lambda: NOW,
        workspace_transport=local,
    )
    completed = provider.stage_transfer_content(
        "job-1", "stage-1", io.BytesIO(content), content_length=len(content)
    )
    raw_stage_request = local.last_request_frame.hex()
    raw_stage_response = local.last_response_frame.hex()
    assert (tmp_path / "inputs/a.bin").read_bytes() == content
    assert completed.actual_sha256 == hashlib.sha256(content).hexdigest()
    assert (
        provider.stage_transfer_content(
            "job-1", "stage-1", io.BytesIO(content), content_length=len(content)
        )
        == completed
    )
    assert sidecar.stats()["stageInstalls"] == 1

    output = b"immutable-output\x00\xff"
    (tmp_path / "outputs").mkdir()
    (tmp_path / "outputs/result.bin").write_bytes(output)
    collect = _transfer("collect-1", TransferDirection.COLLECT_OUTPUT, "outputs/result.bin", output)
    provider.register_transfer("job-1", collect)
    first = provider.open_collected_content("job-1", "collect-1")
    assert first.path.read_bytes() == output
    (tmp_path / "outputs/result.bin").write_bytes(b"changed-after-snapshot")
    second = provider.open_collected_content("job-1", "collect-1")
    assert second.snapshot_ref == first.snapshot_ref
    assert second.path.read_bytes() == output
    first.cleanup()
    second.cleanup()
    provider.discard_transfer("job-1", "collect-1", "discard-1", canonical_digest({}))
    assert (tmp_path / "outputs/result.bin").read_bytes() == b"changed-after-snapshot"
    assert not first.path.exists() and not second.path.exists()
    assert not list(tmp_path.rglob("*.partial"))
    assert not list((tmp_path / ".kcs-transfers/snapshots").iterdir())

    print(
        "JOURNEY transfer",
        json.dumps(
            {
                "stageBytes": len(content),
                "stageSha256": completed.actual_sha256,
                "stageInstalls": sidecar.stats()["stageInstalls"],
                "snapshotRef": first.snapshot_ref,
                "snapshotSha256": hashlib.sha256(output).hexdigest(),
                "rawRequestFrameHex": raw_stage_request,
                "rawResponseFrameHex": raw_stage_response,
                "rawBodyPrefixHex": content[:16].hex(),
            },
            sort_keys=True,
        ),
    )


def test_transfer_policy_mismatch_cancel_and_octet_stream_http(tmp_path: Path) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from starlette.testclient import TestClient

    _, _, _, provider = _setup(tmp_path)
    content = b"http-stream-body" * 4096
    with pytest.raises(ValueError, match="dot-dot"):
        _transfer("traversal", TransferDirection.STAGE_INPUT, "../escape", content)
    (tmp_path / "Straße").mkdir()
    with pytest.raises(UnsafePathError):
        provider.register_transfer(
            "job-1",
            _transfer("casefold", TransferDirection.STAGE_INPUT, "STRASSE/file.bin", content),
        )
    (tmp_path / "e\N{COMBINING ACUTE ACCENT}").mkdir()
    with pytest.raises(UnsafePathError):
        provider.register_transfer(
            "job-1",
            _transfer(
                "unicode",
                TransferDirection.STAGE_INPUT,
                "\N{LATIN SMALL LETTER E WITH ACUTE}/file",
                content,
            ),
        )
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafePathError):
        provider.register_transfer(
            "job-1", _transfer("symlink", TransferDirection.STAGE_INPUT, "link/file", content)
        )
    (tmp_path / "exists.bin").write_bytes(b"existing")
    with pytest.raises(OverwriteForbiddenError):
        provider.register_transfer(
            "job-1",
            _transfer("overwrite", TransferDirection.STAGE_INPUT, "exists.bin", content),
        )
    request = _transfer("stage-http", TransferDirection.STAGE_INPUT, "safe/file.bin", content)
    provider.register_transfer("job-1", request)
    with pytest.raises(TransferBytesMismatchError):
        provider.stage_transfer_content(
            "job-1", "stage-http", io.BytesIO(content[:-1]), content_length=len(content) - 1
        )
    assert not (tmp_path / "safe/file.bin").exists() and not list(tmp_path.rglob("*.partial"))

    cancel_spec = TransferCancelSpec(reason="caller-stop")
    cancel = TransferCancelRequest(
        cancel_ref="cancel-1",
        request_digest=canonical_digest(cancel_spec),
        spec=cancel_spec,
    )
    assert provider.cancel_transfer("job-1", "stage-http", cancel).created is True
    assert provider.cancel_transfer("job-1", "stage-http", cancel).created is False

    app = FastAPI()
    app.include_router(create_jobs_router(provider, "token"))
    client = TestClient(app)
    upload = _transfer("stage-route", TransferDirection.STAGE_INPUT, "http/input.bin", content)
    headers = {"Authorization": "Bearer token", "Content-Type": "application/json"}
    assert (
        client.post(
            "/api/v2/jobs/job-1/transfers",
            headers=headers,
            content=upload.model_dump_json(by_alias=True),
        ).status_code
        == 201
    )
    staged = client.put(
        "/api/v2/jobs/job-1/transfers/stage-route/content",
        headers={
            "Authorization": "Bearer token",
            "Content-Type": "application/octet-stream",
            "KCS-Content-SHA256": hashlib.sha256(content).hexdigest(),
            "Content-Length": str(len(content)),
        },
        content=content,
    )
    assert staged.status_code == 200
    assert (tmp_path / "http/input.bin").read_bytes() == content

    output = b"download\x00\xff"
    (tmp_path / "out.bin").write_bytes(output)
    collect = _transfer("collect-http", TransferDirection.COLLECT_OUTPUT, "out.bin", output)
    response = client.post(
        "/api/v2/jobs/job-1/transfers",
        headers=headers,
        content=collect.model_dump_json(by_alias=True),
    )
    assert response.status_code == 201
    response = client.get(
        "/api/v2/jobs/job-1/transfers/collect-http/content",
        headers={"Authorization": "Bearer token"},
    )
    assert response.content == output
    assert response.headers["content-type"].startswith("application/octet-stream")
    assert response.headers["content-length"] == str(len(output))
    assert response.headers["x-content-sha256"] == hashlib.sha256(output).hexdigest()
    assert response.headers["x-kcs-snapshot-ref"]
    assert response.headers["cache-control"] == "no-store"


class _LostReply:
    def __init__(self, transport: LocalWorkspaceRpcTransport, action: str = "invoke") -> None:
        self.transport = transport
        self.action = action
        self.lost = False

    def rpc(
        self,
        binding: Mapping[str, str],
        header: Mapping[str, object],
        body: Path | None = None,
    ) -> WorkspaceRpcReply:
        reply = self.transport.rpc(binding, header, body)
        if header["action"] == self.action and not self.lost:
            self.lost = True
            raise RuntimeError("simulated response loss")
        return reply


def test_workspace_invoke_recovers_after_restart_without_redispatch(tmp_path: Path) -> None:
    kube, store, sidecar, _ = _setup(tmp_path)
    local = LocalWorkspaceRpcTransport(sidecar.dispatch)
    lost = _LostReply(local)
    provider = V2JobProvider(
        kube,  # type: ignore[arg-type]
        store,
        _Renderer(),
        clock=lambda: NOW,
        workspace_transport=lost,
    )
    frame = WorkspaceFrame.model_validate(
        {
            "protocol": "cosmos.workspace/1",
            "action": "echo",
            "stdout": "x" * 70000,
            "stderr": "\N{SNOWMAN}" * 30000,
            "result": {"value": 7},
            "exitCode": 0,
        }
    )
    request = WorkspaceInvokeRequest(
        operation_ref="operation-1",
        request_digest=canonical_digest(frame.root),
        job_uid=JOB_UID,
        pod_uid=POD_UID,
        frame=frame,
    )
    with pytest.raises(DependencyUnavailableError, match="not confirmed"):
        provider.invoke_workspace("job-1", request)
    assert provider.inspect_operation("job-1", "operation-1").state == "accepted"
    assert sidecar.stats()["operationSideEffects"] == 1

    restarted = V2JobProvider(
        kube,  # type: ignore[arg-type]
        store,
        _Renderer(),
        clock=lambda: NOW,
        workspace_transport=local,
    )
    result = restarted.invoke_workspace("job-1", request)
    assert result.state == "succeeded" and result.exit_code == 0
    assert len(result.stdout.encode()) == 65536 and result.stdout_truncated is True
    assert len(result.stderr.encode()) <= 65536 and result.stderr_truncated is True
    assert result.inline_result == {"value": 7}
    assert result.inline_result_size == len(b'{"value":7}')
    assert result.inline_result_digest == hashlib.sha256(b'{"value":7}').hexdigest()
    assert sidecar.stats()["operationSideEffects"] == 1
    assert restarted.invoke_workspace("job-1", request) == result

    changed = request.model_copy(update={"request_digest": "b" * 64})
    with pytest.raises(IdentityDigestConflict):
        restarted.invoke_workspace("job-1", changed)

    sidecar.forget_operations()
    kube2, store2, _, _ = _setup(tmp_path / "unknown")
    values = dict(store.read_runtime("operation", "job-1", "operation-1").values)  # type: ignore[union-attr]
    values["payload"] = (
        provider.inspect_operation("job-1", "operation-1")
        .model_copy(
            update={"state": OperationState.ACCEPTED, "started_at": None, "finished_at": None}
        )
        .model_dump_json(by_alias=True)
    )
    store2.reserve_runtime("operation", "operation-1", "job-1", values)
    provider2 = V2JobProvider(
        kube2,  # type: ignore[arg-type]
        store2,
        _Renderer(),
        clock=lambda: NOW,
        workspace_transport=local,
    )
    with pytest.raises(OperationIndeterminateError):
        provider2.invoke_workspace("job-1", request)
    assert provider2.inspect_operation("job-1", "operation-1").state == "indeterminate"

    print(
        "JOURNEY operation",
        json.dumps(
            {
                "sideEffects": sidecar.stats()["operationSideEffects"],
                "state": result.state,
                "stdoutBytes": len(result.stdout.encode()),
                "stderrBytes": len(result.stderr.encode()),
                "inlineResultDigest": result.inline_result_digest,
                "stdoutPrefix": result.stdout[:16],
                "stderrPrefix": result.stderr[:4],
                "inlineResult": result.inline_result,
            },
            sort_keys=True,
        ),
    )
