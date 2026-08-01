"""Focused trusted-transfer and exactly-once workspace Journey for Task 6."""

from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import warnings
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any, Literal
from uuid import UUID

import pytest
from fastapi import FastAPI

from kcs.conformance.workspace_sidecar import WorkspaceSidecar, _serve_connection
from kcs.jobs.canonical import canonical_digest
from kcs.jobs.contracts import (
    FinalizeJobRequest,
    FinalizeSpec,
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
from kcs.jobs.transport import (
    AgentRpcResponse,
    LocalWorkspaceRpcTransport,
    WorkspaceRpcReply,
    decode_workspace_header,
)
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
        if value["metadata"].get("resourceVersion") != self.maps[name]["metadata"].get(
            "resourceVersion"
        ):
            raise _ConflictError()
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


class _GuardedSocket:
    def __init__(self, incoming: bytes) -> None:
        self.incoming = bytearray(incoming)
        self.receive_sizes: list[int] = []
        self.sent = bytearray()

    def recv(self, size: int) -> bytes:
        self.receive_sizes.append(size)
        if not self.incoming:
            raise AssertionError("sidecar attempted to read a rejected request body")
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk

    def sendall(self, value: bytes) -> None:
        self.sent.extend(value)


def _provider(
    kube: _Kube,
    store: V2JobStore,
    workspace_transport: object,
    **options: Any,
) -> V2JobProvider:
    return V2JobProvider(
        kube,  # type: ignore[arg-type]
        store,
        _Renderer(),
        clock=lambda: NOW,
        workspace_transport=workspace_transport,  # type: ignore[arg-type]
        **options,
    )


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
    provider = _provider(kube, store, LocalWorkspaceRpcTransport(sidecar.dispatch))
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
    monkeypatch: pytest.MonkeyPatch,
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
    interrupted = _provider(kube, store, lost)
    with pytest.raises(DependencyUnavailableError, match="not confirmed"):
        interrupted.stage_transfer_content(
            "job-1", "stage-1", io.BytesIO(content), content_length=len(content)
        )
    assert interrupted.inspect_transfer("job-1", "stage-1").state == "staging"
    provider = _provider(kube, store, local)
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

    race_content = b"atomic-install"
    race = _transfer("stage-race", TransferDirection.STAGE_INPUT, "inputs/race.bin", race_content)
    provider.register_transfer("job-1", race)
    real_link = os.link

    def concurrent_link(source: object, target: object, **keywords: object) -> None:
        target_fd = keywords.get("dst_dir_fd")
        assert isinstance(target_fd, int)
        descriptor = os.open(
            str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=target_fd
        )
        with os.fdopen(descriptor, "wb") as competitor:
            competitor.write(b"concurrent-winner")
        real_link(source, target, **keywords)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "link", concurrent_link)
    with pytest.raises(OverwriteForbiddenError):
        provider.stage_transfer_content(
            "job-1", "stage-race", io.BytesIO(race_content), content_length=len(race_content)
        )
    monkeypatch.undo()
    assert (tmp_path / "inputs/race.bin").read_bytes() == b"concurrent-winner"

    output = b"immutable-output\x00\xff"
    (tmp_path / "outputs").mkdir()
    (tmp_path / "outputs/result.bin").write_bytes(output)
    collect = _transfer("collect-1", TransferDirection.COLLECT_OUTPUT, "outputs/result.bin", output)
    provider.register_transfer("job-1", collect)
    first = provider.open_collected_content("job-1", "collect-1")
    assert first.path.read_bytes() == output
    (tmp_path / "outputs/result.bin").write_bytes(b"changed-after-snapshot")
    restarted_sidecar = WorkspaceSidecar(tmp_path)
    restarted_provider = _provider(
        kube, store, LocalWorkspaceRpcTransport(restarted_sidecar.dispatch)
    )
    second = restarted_provider.open_collected_content("job-1", "collect-1")
    assert second.snapshot_ref == first.snapshot_ref
    assert second.path.read_bytes() == output
    receipts = list((tmp_path / ".kcs/receipts").glob("*.json"))
    receipt = next(
        item for item in receipts if json.loads(item.read_text())["transferRef"] == "collect-1"
    )
    assert receipt.stat().st_mode & 0o777 == 0o600
    first.cleanup()
    second.cleanup()
    restarted_provider.discard_transfer("job-1", "collect-1", "discard-1", canonical_digest({}))
    assert (tmp_path / "outputs/result.bin").read_bytes() == b"changed-after-snapshot"
    assert not first.path.exists() and not second.path.exists()
    assert not list(tmp_path.rglob("*.partial"))
    assert not list((tmp_path / ".kcs/snapshots").iterdir())
    assert json.loads(receipt.read_text())["state"] == "discarded"

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
    with pytest.raises(UnsafePathError):
        provider.register_transfer(
            "job-1", _transfer("private", TransferDirection.STAGE_INPUT, ".kcs/receipts/x", content)
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

    oversized = _GuardedSocket(struct.pack(">I", 4 * 1024 * 1024 + 1))
    with pytest.raises(DependencyUnavailableError, match="header"):
        _serve_connection(oversized, WorkspaceSidecar(tmp_path / "hostile-header"))  # type: ignore[arg-type]
    assert oversized.receive_sizes == [4]

    hostile_header = json.dumps(
        {
            "action": "stage",
            "transferRef": "hostile-body",
            "requestDigest": "b" * 64,
            "declaredSizeBytes": 1,
            "authorizedMaxSizeBytes": 1,
            "contentSha256": hashlib.sha256(b"x").hexdigest(),
            "bodySize": 2,
        },
        separators=(",", ":"),
    ).encode()
    hostile = _GuardedSocket(struct.pack(">I", len(hostile_header)) + hostile_header)
    _serve_connection(hostile, WorkspaceSidecar(tmp_path / "hostile-body"))  # type: ignore[arg-type]
    assert hostile.receive_sizes == [4, len(hostile_header)]
    reply_size = struct.unpack(">I", hostile.sent[:4])[0]
    reply = decode_workspace_header(bytes(hostile.sent[: reply_size + 4]))
    assert reply["ok"] is False and reply["code"] == "INVALID_REQUEST"


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
            if reply.content_path is not None:
                reply.content_path.unlink(missing_ok=True)
            raise RuntimeError("simulated response loss")
        return reply


class _HeldInvoke:
    def __init__(self, transport: LocalWorkspaceRpcTransport) -> None:
        self.transport = transport
        self.winner_started = Event()
        self.inspected = Event()
        self.release = Event()
        self.invocations = 0

    def rpc(
        self,
        binding: Mapping[str, str],
        header: Mapping[str, object],
        body: Path | None = None,
    ) -> WorkspaceRpcReply:
        if header["action"] == "invoke":
            self.invocations += 1
            self.winner_started.set()
            assert self.release.wait(2)
        elif header["action"] == "inspectOperation":
            self.inspected.set()
        return self.transport.rpc(binding, header, body)


class _InvalidOperationResult:
    def rpc(
        self,
        binding: Mapping[str, str],
        header: Mapping[str, object],
        body: Path | None = None,
    ) -> WorkspaceRpcReply:
        del binding, body
        return WorkspaceRpcReply(
            header={
                "ok": True,
                "operationRef": header["operationRef"],
                "requestDigest": header["requestDigest"],
                "state": "succeeded",
                "exitCode": 7,
                "stdout": "",
                "stderr": "",
                "inlineResult": None,
                "resultTransferRef": 9,
            },
            content_path=None,
        )


class _StopTransport:
    def agent_rpc(
        self, binding: Mapping[str, str], request: Mapping[str, object]
    ) -> AgentRpcResponse:
        raise AssertionError("finalize must not start an agent")

    def stop_supervisor(self, binding: Mapping[str, str], container: str) -> AgentRpcResponse:
        del binding, container
        return AgentRpcResponse(
            protocol_version=1,
            generation=0,
            agent_run_ref="",
            launch_bundle_digest="",
            state="stopped",
            supervisor_alive=False,
        )


def test_workspace_invoke_recovers_after_restart_without_redispatch(tmp_path: Path) -> None:
    kube, store, sidecar, _ = _setup(tmp_path)
    local = LocalWorkspaceRpcTransport(sidecar.dispatch)
    lost = _LostReply(local)
    provider = _provider(kube, store, lost)
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

    restarted = _provider(kube, store, local)
    replay = restarted.invoke_workspace("job-1", request)
    result = replay.snapshot
    assert replay.created is False
    assert result.state == "succeeded" and result.exit_code == 0
    assert len(result.stdout.encode()) == 65536 and result.stdout_truncated is True
    assert len(result.stderr.encode()) <= 65536 and result.stderr_truncated is True
    assert result.inline_result == {"value": 7}
    assert result.inline_result_size == len(b'{"value":7}')
    assert result.inline_result_digest == hashlib.sha256(b'{"value":7}').hexdigest()
    assert sidecar.stats()["operationSideEffects"] == 1
    assert restarted.invoke_workspace("job-1", request).snapshot == result

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
    provider2 = _provider(kube2, store2, local)
    with pytest.raises(OperationIndeterminateError):
        provider2.invoke_workspace("job-1", request)
    assert provider2.inspect_operation("job-1", "operation-1").state == "indeterminate"

    race_sidecar = WorkspaceSidecar(tmp_path / "race")
    race_transport = _HeldInvoke(LocalWorkspaceRpcTransport(race_sidecar.dispatch))
    race_kube, race_store, _, _ = _setup(tmp_path / "race")
    race_provider = _provider(race_kube, race_store, race_transport)
    race_request = request.model_copy(update={"operation_ref": "operation-race"})
    with ThreadPoolExecutor(max_workers=2) as pool:
        winner = pool.submit(race_provider.invoke_workspace, "job-1", race_request)
        assert race_transport.winner_started.wait(1)
        loser = pool.submit(race_provider.invoke_workspace, "job-1", race_request)
        assert race_transport.inspected.wait(1)
        race_transport.release.set()
        outcomes = [winner.result(timeout=2), loser.result(timeout=2)]
    assert sorted(item.created for item in outcomes) == [False, True]
    assert all(item.snapshot.state is OperationState.SUCCEEDED for item in outcomes)
    assert race_transport.invocations == 1

    bad_request = request.model_copy(update={"operation_ref": "operation-invalid"})
    bad_provider = _provider(kube, store, _InvalidOperationResult())
    with pytest.raises(DependencyUnavailableError):
        bad_provider.invoke_workspace("job-1", bad_request)
    invalid = bad_provider.inspect_operation("job-1", "operation-invalid")
    assert invalid.state is OperationState.INDETERMINATE and invalid.failure_reason

    finalize_root = tmp_path / "finalize-recovery"
    finalize_kube, finalize_store, finalize_sidecar, _ = _setup(finalize_root)
    finalize_local = LocalWorkspaceRpcTransport(finalize_sidecar.dispatch)
    finalize_operation = request.model_copy(update={"operation_ref": "operation-finalize"})
    lost_operation = _provider(finalize_kube, finalize_store, _LostReply(finalize_local))
    with pytest.raises(DependencyUnavailableError):
        lost_operation.invoke_workspace("job-1", finalize_operation)

    discarded_bytes = b"finalize-discard"
    (finalize_root / "discard.bin").write_bytes(discarded_bytes)
    discard_request = _transfer(
        "discard-finalize",
        TransferDirection.COLLECT_OUTPUT,
        "discard.bin",
        discarded_bytes,
    )
    lost_operation.register_transfer("job-1", discard_request)
    lost_collect = _provider(finalize_kube, finalize_store, _LostReply(finalize_local, "collect"))
    with pytest.raises(DependencyUnavailableError):
        lost_collect.open_collected_content("job-1", "discard-finalize")
    lost_discard = _provider(
        finalize_kube, finalize_store, _LostReply(finalize_local, "discardTransfer")
    )
    with pytest.raises(DependencyUnavailableError):
        lost_discard.discard_transfer(
            "job-1", "discard-finalize", "discard-finalize-action", canonical_digest({})
        )

    finalizer = _provider(
        finalize_kube,
        finalize_store,
        finalize_local,
        sleeper=lambda _: None,
        transport=_StopTransport(),
    )
    finalize_spec = FinalizeSpec(
        operation_refs=["operation-finalize"],
        transfer_refs=["discard-finalize"],
        drain_timeout_seconds=1,
    )
    finalized = finalizer.finalize(
        "job-1",
        FinalizeJobRequest(
            finalize_ref="finalize-recovery",
            request_digest=canonical_digest(finalize_spec),
            spec=finalize_spec,
        ),
    )
    assert finalized.snapshot.terminal_operation_refs == ["operation-finalize"]
    discarded = finalizer.inspect_transfer("job-1", "discard-finalize")
    assert discarded.state == "discarded" and discarded.discard_action.state == "succeeded"
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
