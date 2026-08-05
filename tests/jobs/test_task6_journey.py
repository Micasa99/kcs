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

import kcs.conformance.workspace_sidecar as workspace_sidecar
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
    StateConflictError,
    TransferBytesMismatchError,
    TransferIndeterminateError,
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
        self.terminated: set[str] = set()

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
        status = {"succeeded": 1} if self.terminated == {"agent", "workspace"} else {}
        return {
            "metadata": {"uid": str(JOB_UID), "resourceVersion": "9"},
            "status": status,
        }

    def list_job_pods(self, job_ref: str, job_uid: str | None = None) -> list[object]:
        statuses = []
        for role in ("agent", "workspace"):
            terminated = role in self.terminated
            statuses.append(
                {
                    "name": role,
                    "ready": not terminated,
                    "restart_count": 0,
                    "state": {"terminated": {"exit_code": 0, "reason": "Completed"}}
                    if terminated
                    else {"running": {"started_at": NOW}},
                }
            )
        return [
            {
                "metadata": {"name": "job-1-pod-1", "uid": str(POD_UID)},
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

    crash_content = b"installed-before-receipt"
    crash_request = _transfer(
        "stage-installing", TransferDirection.STAGE_INPUT, "inputs/installing.bin", crash_content
    )
    provider.register_transfer("job-1", crash_request)
    write_receipt = sidecar._write_receipt
    lost_completed_receipt = False

    def crash_before_completed_receipt(retained: Mapping[str, Any]) -> None:
        nonlocal lost_completed_receipt
        if (
            retained.get("transferRef") == "stage-installing"
            and retained.get("state") == "completed"
            and not lost_completed_receipt
        ):
            lost_completed_receipt = True
            raise RuntimeError("simulated crash before completed receipt")
        write_receipt(retained)

    monkeypatch.setattr(sidecar, "_write_receipt", crash_before_completed_receipt)
    with pytest.raises(DependencyUnavailableError):
        provider.stage_transfer_content(
            "job-1",
            "stage-installing",
            io.BytesIO(crash_content),
            content_length=len(crash_content),
        )
    monkeypatch.undo()
    installed = tmp_path / "inputs/installing.bin"
    installed_inode = installed.stat().st_ino
    installing_receipts = [
        item
        for item in (tmp_path / ".kcs/receipts").glob("*.json")
        if json.loads(item.read_text()).get("transferRef") == "stage-installing"
    ]
    assert len(installing_receipts) == 1
    assert json.loads(installing_receipts[0].read_text())["state"] == "installing"
    recovered_stage = _provider(
        kube, store, LocalWorkspaceRpcTransport(WorkspaceSidecar(tmp_path).dispatch)
    ).stage_transfer_content(
        "job-1",
        "stage-installing",
        io.BytesIO(crash_content),
        content_length=len(crash_content),
    )
    assert recovered_stage.state == "completed" and installed.stat().st_ino == installed_inode
    assert json.loads(installing_receipts[0].read_text())["state"] == "completed"

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
    discard_events: list[str] = []
    fsync_directory = workspace_sidecar._fsync_directory
    write_discard_receipt = restarted_sidecar._write_receipt

    def trace_fsync(path: Path) -> None:
        if path.name == "snapshots":
            discard_events.append("snapshot-fsync")
        fsync_directory(path)

    def trace_discard_receipt(retained: Mapping[str, Any]) -> None:
        if retained.get("state") == "discarded":
            discard_events.append("discard-receipt")
        write_discard_receipt(retained)

    monkeypatch.setattr(workspace_sidecar, "_fsync_directory", trace_fsync)
    monkeypatch.setattr(restarted_sidecar, "_write_receipt", trace_discard_receipt)
    restarted_provider.discard_transfer("job-1", "collect-1", "discard-1", canonical_digest({}))
    monkeypatch.undo()
    assert discard_events[:2] == ["snapshot-fsync", "discard-receipt"]
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


def test_transfer_policy_mismatch_cancel_and_octet_stream_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from starlette.testclient import TestClient

    _, _, sidecar, provider = _setup(tmp_path)
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

    def retain_installing(ref: str, path: str, payload: bytes) -> tuple[Path, Path, Path]:
        transfer = _transfer(ref, TransferDirection.STAGE_INPUT, path, payload)
        provider.register_transfer("job-1", transfer)
        partial = tmp_path / ".kcs/partials" / hashlib.sha256(ref.encode()).hexdigest()
        partial.write_bytes(payload)
        installed_stat = partial.stat()
        sidecar._write_receipt(
            {
                "transferRef": ref,
                "requestDigest": transfer.request_digest,
                "state": "installing",
                "actualSizeBytes": len(payload),
                "actualSha256": hashlib.sha256(payload).hexdigest(),
                "direction": "stage_input",
                "path": path,
                "overwritePolicy": "forbid",
                "installDevice": installed_stat.st_dev,
                "installInode": installed_stat.st_ino,
            }
        )
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        receipt = tmp_path / ".kcs/receipts" / f"{hashlib.sha256(ref.encode()).hexdigest()}.json"
        return partial, target, receipt

    def assert_cancel_indeterminate(ref: str, receipt: Path) -> None:
        with pytest.raises(TransferIndeterminateError) as error:
            provider.cancel_transfer("job-1", ref, cancel.model_copy(update={"cancel_ref": ref}))
        retained = provider.inspect_transfer("job-1", ref)
        assert (
            str(error.value),
            json.loads(receipt.read_text())["state"],
            retained.state,
            retained.cancel_action.state,
        ) == (
            TransferIndeterminateError.default_message,
            "indeterminate",
            "indeterminate",
            "indeterminate",
        )

    installed_partial, installed_target, installed_receipt = retain_installing(
        "cancel-installed", "cancel/installed.bin", b"published-before-cancel"
    )
    os.link(installed_partial, installed_target)
    installed_partial.unlink()
    installed_cancel = cancel.model_copy(update={"cancel_ref": "cancel-installed"})
    with pytest.raises(StateConflictError):
        provider.cancel_transfer("job-1", "cancel-installed", installed_cancel)
    installed = provider.inspect_transfer("job-1", "cancel-installed")
    assert installed.state == "completed" and installed.cancel_action.state == "failed"
    assert json.loads(installed_receipt.read_text())["state"] == "completed"

    absent_partial, absent_target, absent_receipt = retain_installing(
        "cancel-absent", "cancel/absent.bin", b"not-published"
    )
    absent = provider.cancel_transfer(
        "job-1", "cancel-absent", cancel.model_copy(update={"cancel_ref": "cancel-absent"})
    )
    assert absent.snapshot.state == "canceled"
    assert not absent_partial.exists() and not absent_target.exists()
    assert json.loads(absent_receipt.read_text())["state"] == "canceled"

    ambiguous_partial, ambiguous_target, ambiguous_receipt = retain_installing(
        "cancel-ambiguous", "cancel/STRASSE.bin", b"ambiguous-publication"
    )
    (ambiguous_target.parent / "Strasse.bin").write_bytes(b"first")
    (ambiguous_target.parent / "Straße.bin").write_bytes(b"second")
    with pytest.raises(TransferIndeterminateError):
        provider.cancel_transfer(
            "job-1",
            "cancel-ambiguous",
            cancel.model_copy(update={"cancel_ref": "cancel-ambiguous"}),
        )
    ambiguous = provider.inspect_transfer("job-1", "cancel-ambiguous")
    assert ambiguous.state == "indeterminate"
    assert ambiguous.cancel_action.state == "indeterminate"
    assert ambiguous_partial.exists()
    assert json.loads(ambiguous_receipt.read_text())["state"] == "indeterminate"

    _, _, unreadable_parent_receipt = retain_installing(
        "cancel-unreadable-parent",
        "cancel/unreadable-parent.bin",
        b"parent-failure-bytes",
    )

    def deny_parent_open(raw_path: str, *, create: bool) -> tuple[int, str]:
        raise PermissionError(f"private-parent-must-not-escape:{raw_path}:{create}")

    with monkeypatch.context() as parent_failure:
        parent_failure.setattr(sidecar, "_open_parent", deny_parent_open)
        assert_cancel_indeterminate("cancel-unreadable-parent", unreadable_parent_receipt)

    _, _, unreadable_receipt = retain_installing(
        "cancel-unreadable-partial",
        "cancel/unreadable-partial.bin",
        b"unreadable-private-bytes",
    )

    def deny_partial_read(path: Path) -> tuple[int, str]:
        raise PermissionError(f"private-partial-must-not-escape:{path}")

    with monkeypatch.context() as partial_failure:
        partial_failure.setattr(workspace_sidecar, "_hash_nofollow", deny_partial_read)
        assert_cancel_indeterminate("cancel-unreadable-partial", unreadable_receipt)

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
    def __init__(self, kube: _Kube) -> None:
        self.kube = kube

    def agent_rpc(
        self, binding: Mapping[str, str], request: Mapping[str, object]
    ) -> AgentRpcResponse:
        raise AssertionError("finalize must not start an agent")

    def stop_supervisor(self, binding: Mapping[str, str], container: str) -> AgentRpcResponse:
        del binding, container
        self.kube.terminated.update({"agent", "workspace"})
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
            "action": "sharedWrite",
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
    retained_dispatch = store.read_runtime("operation", "job-1", "operation-1")
    invoke_frame = decode_workspace_header(local.last_request_frame)
    assert retained_dispatch.values["dispatchPhase"] == "relinquished"  # type: ignore[union-attr]
    assert invoke_frame["dispatchToken"] == retained_dispatch.values["dispatchToken"]  # type: ignore[union-attr]
    assert sidecar.stats()["operationSideEffects"] == 1

    replay = provider.invoke_workspace("job-1", request)
    result = replay.snapshot
    assert replay.created is False
    assert result.state == "succeeded" and result.exit_code == 0
    assert result.stdout.endswith("\n") and result.stdout_truncated is False
    assert result.stderr == "" and result.stderr_truncated is False
    assert result.inline_result["event"] == "workspace_shared_write"
    expected_inline = json.dumps(
        result.inline_result, sort_keys=True, separators=(",", ":")
    ).encode()
    assert result.inline_result_size == len(expected_inline)
    assert result.inline_result_digest == hashlib.sha256(expected_inline).hexdigest()
    assert decode_workspace_header(local.last_request_frame)["action"] == "fenceOperation"
    assert sidecar.stats()["operationSideEffects"] == 1
    restarted = _provider(kube, store, local)
    assert restarted.invoke_workspace("job-1", request).snapshot == result

    changed = request.model_copy(update={"request_digest": "b" * 64})
    with pytest.raises(IdentityDigestConflict):
        restarted.invoke_workspace("job-1", changed)

    sidecar.forget_operations()
    kube2, store2, _, _ = _setup(tmp_path / "unknown")
    values = dict(store.read_runtime("operation", "job-1", "operation-1").values)  # type: ignore[union-attr]
    values.update({"dispatchRuntime": "retained-runtime", "dispatchPhase": "dispatching"})
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
        replayed = loser.result(timeout=1)
        assert replayed.created is False and replayed.snapshot.state is OperationState.ACCEPTED
        race_transport.release.set()
        created = winner.result(timeout=2)
    assert created.created is True and created.snapshot.state is OperationState.SUCCEEDED
    assert race_transport.invocations == 1

    delayed_kube, delayed_store, delayed_sidecar, _ = _setup(tmp_path / "delayed-owner")
    delayed_local = LocalWorkspaceRpcTransport(delayed_sidecar.dispatch)
    delayed_transport = _HeldInvoke(delayed_local)
    delayed = _provider(delayed_kube, delayed_store, delayed_transport)
    delayed_request = request.model_copy(update={"operation_ref": "operation-delayed"})
    with ThreadPoolExecutor(max_workers=1) as pool:
        old_winner = pool.submit(delayed.invoke_workspace, "job-1", delayed_request)
        assert delayed_transport.winner_started.wait(1)
        retained = delayed_store.read_runtime("operation", "job-1", "operation-delayed")
        assert retained.values["dispatchPhase"] == "dispatching"  # type: ignore[union-attr]
        superseder = _provider(delayed_kube, delayed_store, delayed_local)
        with pytest.raises(OperationIndeterminateError):
            superseder.invoke_workspace("job-1", delayed_request)
        fence = decode_workspace_header(delayed_local.last_request_frame)
        assert fence["action"] == "fenceOperation"
        assert fence["dispatchToken"] == retained.values["dispatchToken"]  # type: ignore[union-attr]
        delayed_transport.release.set()
        with pytest.raises(OperationIndeterminateError):
            old_winner.result(timeout=2)
    assert delayed_sidecar.stats()["operationSideEffects"] == 0

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
        transport=_StopTransport(finalize_kube),
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

    unknown_root = tmp_path / "unknown-transfer-action"
    unknown_kube, unknown_store, unknown_sidecar, unknown_provider = _setup(unknown_root)
    unknown_bytes = b"unknown-transfer"
    unknown_request = _transfer(
        "unknown-action", TransferDirection.STAGE_INPUT, "unknown.bin", unknown_bytes
    )
    unknown_provider.register_transfer("job-1", unknown_request)
    unavailable = _provider(unknown_kube, unknown_store, None)
    with pytest.raises(DependencyUnavailableError):
        unavailable.stage_transfer_content(
            "job-1", "unknown-action", io.BytesIO(unknown_bytes), content_length=len(unknown_bytes)
        )
    with pytest.raises(DependencyUnavailableError):
        unavailable.discard_transfer(
            "job-1", "unknown-action", "unknown-discard", canonical_digest({})
        )
    unknown_finalizer = _provider(
        unknown_kube,
        unknown_store,
        LocalWorkspaceRpcTransport(unknown_sidecar.dispatch),
        sleeper=lambda _: None,
        transport=_StopTransport(unknown_kube),
    )
    unknown_spec = FinalizeSpec(
        operation_refs=[], transfer_refs=["unknown-action"], drain_timeout_seconds=1
    )
    with pytest.raises(TransferIndeterminateError):
        unknown_finalizer.finalize(
            "job-1",
            FinalizeJobRequest(
                finalize_ref="unknown-finalize",
                request_digest=canonical_digest(unknown_spec),
                spec=unknown_spec,
            ),
        )
    unknown = unknown_finalizer.inspect_transfer("job-1", "unknown-action")
    assert unknown.state == "indeterminate" and unknown.discard_action.state == "indeterminate"
    print(
        "JOURNEY operation",
        json.dumps(
            {
                "sideEffects": sidecar.stats()["operationSideEffects"],
                "state": result.state,
                "stdoutBytes": len(result.stdout.encode()),
                "stderrBytes": len(result.stderr.encode()),
                "inlineResultDigest": result.inline_result_digest,
                "stdoutPrefix": result.stdout[:32],
                "stderrPrefix": result.stderr[:4],
                "inlineResult": result.inline_result,
            },
            sort_keys=True,
        ),
    )
