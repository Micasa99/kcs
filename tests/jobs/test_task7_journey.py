"""Compact no-network lifecycle and startup-recovery Journey for Task 7."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kcs.conformance.workspace_sidecar import WorkspaceSidecar
from kcs.jobs.canonical import canonical_digest
from kcs.jobs.contracts import (
    CancelJobRequest,
    CancelSpec,
    CreateJobRequest,
    CredentialGrantMetadata,
    FinalizeSpec,
    TransferDirection,
    TransferRegisterRequest,
    TransferSpec,
    WorkspaceFrame,
    WorkspaceInvokeRequest,
)
from kcs.jobs.errors import (
    CredentialDestroyFailedError,
    DependencyUnavailableError,
    StateConflictError,
)
from kcs.jobs.lifecycle import LifecycleGate
from kcs.jobs.provider import EMPTY_OBJECT_DIGEST, V2JobProvider
from kcs.jobs.store import V2JobStore
from kcs.jobs.transport import AgentRpcResponse, LocalWorkspaceRpcTransport, WorkspaceRpcReply
from kcs.server.routes.jobs import create_jobs_router

JOB_UID = UUID("00000000-0000-4000-8000-000000000071")
POD_UID = UUID("00000000-0000-4000-8000-000000000072")
NOW = datetime(2026, 8, 2, 8, 0, tzinfo=UTC)
FIXTURES = Path(__file__).parents[2] / "openapi" / "examples" / "fixtures"


class _ConflictError(Exception):
    status = 409


class _FakeKube:
    namespace = "researchcosmos-v2"

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.maps: dict[str, dict[str, Any]] = {}
        self.secrets: dict[str, dict[str, Any]] = {}
        self.job: dict[str, Any] | None = None
        self.pods: list[dict[str, Any]] = []
        self.terminated: set[str] = set()
        self.events: list[dict[str, Any]] = []
        self.created_jobs = 0
        self.fail_cancel_phase_once = False
        self.fail_job_delete_once = False
        self.fail_owner_cleanup_phase_once = False
        self.linger_secret_once = False
        self.pause_secret_create = False
        self.secret_create_claimed = Event()
        self.release_secret_create = Event()

    def create_config_map(self, body: object) -> object:
        value = deepcopy(body)
        assert isinstance(value, dict)
        name = value["metadata"]["name"]
        if name in self.maps:
            raise _ConflictError()
        value["metadata"]["resourceVersion"] = "1"
        self.maps[name] = value
        self.events.append({"kind": "ConfigMap", "verb": "create", "name": name})
        return deepcopy(value)

    def read_config_map(self, name: str) -> object | None:
        value = self.maps.get(name)
        return deepcopy(value) if value is not None else None

    def replace_config_map(self, name: str, body: object) -> object:
        value = deepcopy(body)
        assert isinstance(value, dict)
        if value["metadata"].get("resourceVersion") != self.maps[name]["metadata"].get(
            "resourceVersion"
        ):
            raise _ConflictError()
        payload = json.loads(value.get("data", {}).get("payload", "{}"))
        if (
            self.fail_cancel_phase_once
            and value.get("data", {}).get("kind") == "cancel"
            and payload.get("state") == "agent_stopped"
        ):
            self.fail_cancel_phase_once = False
            raise RuntimeError("simulated crash after agent stop")
        if (
            self.fail_owner_cleanup_phase_once
            and value.get("data", {}).get("state") == "deleting"
            and value.get("data", {}).get("cleanupPhase") == "owner_records_deleted"
        ):
            self.fail_owner_cleanup_phase_once = False
            raise RuntimeError("simulated crash after owner runtime cleanup")
        value["metadata"]["resourceVersion"] = str(
            int(self.maps[name]["metadata"]["resourceVersion"]) + 1
        )
        self.maps[name] = value
        self.events.append(
            {
                "kind": "ConfigMap",
                "verb": "replace",
                "name": name,
                "state": value.get("data", {}).get("state") or payload.get("state"),
                "gate": payload.get("gate"),
                "activeClaims": len(payload.get("activeClaims", [])),
                "closePhase": (payload.get("close") or {}).get("phase"),
                "closeKind": (payload.get("close") or {}).get("kind"),
            }
        )
        return deepcopy(value)

    def delete_config_map(self, name: str) -> bool:
        existed = self.maps.pop(name, None) is not None
        self.events.append({"kind": "ConfigMap", "verb": "delete", "name": name})
        return existed

    def list_config_maps(self, label_selector: str | None = None) -> list[object]:
        values = list(self.maps.values())
        if label_selector:
            pairs = [part.split("=", 1) for part in label_selector.split(",")]
            values = [
                item
                for item in values
                if all(item["metadata"]["labels"].get(key) == value for key, value in pairs)
            ]
        return [deepcopy(item) for item in values]

    def create_job(self, body: object) -> object:
        if self.job is not None:
            raise _ConflictError()
        rendered = deepcopy(body)
        assert isinstance(rendered, dict)
        self.created_jobs += 1
        self.job = {
            "metadata": {
                "name": "job-1",
                "uid": str(JOB_UID),
                "resourceVersion": "7",
                "annotations": rendered["metadata"]["annotations"],
            },
            "status": {},
        }
        self.pods = [
            {
                "metadata": {
                    "name": "job-1-pod",
                    "uid": str(POD_UID),
                    "annotations": rendered["metadata"]["annotations"],
                },
                "spec": {"node_name": "gpu-worker"},
                "status": {"start_time": NOW, "container_statuses": self._statuses()},
            }
        ]
        self.events.append({"kind": "Job", "verb": "create", "uid": str(JOB_UID)})
        return deepcopy(self.job)

    def read_job(self, job_ref: str) -> object | None:
        del job_ref
        return deepcopy(self.job)

    def list_job_pods(self, job_ref: str, job_uid: str | None = None) -> list[object]:
        del job_ref, job_uid
        if self.pods:
            self.pods[0]["status"]["container_statuses"] = self._statuses()
        return [deepcopy(item) for item in self.pods]

    def delete_job(self, job_ref: str) -> None:
        del job_ref
        self.events.append({"kind": "Job", "verb": "delete", "propagation": "Foreground"})
        if self.fail_job_delete_once:
            self.fail_job_delete_once = False
            self.job = None
            self.pods = []
            shutil.rmtree(self.workspace, ignore_errors=True)
            raise RuntimeError("simulated response loss after foreground deletion acceptance")
        self.job = None
        self.pods = []
        shutil.rmtree(self.workspace, ignore_errors=True)

    def create_secret(self, body: object) -> object:
        value = deepcopy(body)
        assert isinstance(value, dict)
        name = value["metadata"]["name"]
        if self.pause_secret_create:
            self.secret_create_claimed.set()
            assert self.release_secret_create.wait(timeout=2)
        self.secrets[name] = value
        self.events.append({"kind": "Secret", "verb": "create", "name": name})
        return deepcopy(value)

    def read_secret(self, name: str) -> object | None:
        value = self.secrets.get(name)
        return deepcopy(value) if value is not None else None

    def delete_secret(self, name: str) -> bool:
        self.events.append({"kind": "Secret", "verb": "delete", "name": name})
        if self.linger_secret_once:
            self.linger_secret_once = False
            return False
        self.secrets.pop(name, None)
        return self.read_secret(name) is None

    def read_role_logs(self, *args: object) -> object:
        del args
        return {
            "content": "retained-terminal-log\n",
            "start_cursor": "cursor-0",
            "next_cursor": None,
            "truncated": False,
            "terminal": True,
            "container_id": "container://retained",
        }

    def _statuses(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for role in ("agent", "workspace"):
            if role in self.terminated:
                state = {
                    "terminated": {
                        "exit_code": 0,
                        "reason": "Canceled",
                        "started_at": NOW,
                        "finished_at": NOW,
                    }
                }
                ready = False
            else:
                state = {"running": {"started_at": NOW}}
                ready = True
            result.append(
                {
                    "name": role,
                    "container_id": f"container://{role}",
                    "image_id": f"image://{role}",
                    "ready": ready,
                    "restart_count": 0,
                    "state": state,
                }
            )
        if self.job is not None and self.terminated == {"agent", "workspace"}:
            self.job["status"] = {
                "succeeded": 1,
                "conditions": [
                    {
                        "type": "Complete",
                        "status": "True",
                        "last_transition_time": NOW,
                    }
                ],
            }
        return result


class _Renderer:
    def job_ref(self, request: CreateJobRequest) -> str:
        del request
        return "job-1"

    def render(self, request: CreateJobRequest) -> object:
        return {
            "metadata": {
                "name": "job-1",
                "annotations": {
                    "researchcosmos.io/provider-request-id": request.provider_request_id,
                    "researchcosmos.io/subject-ref": request.spec.subject_ref,
                    "researchcosmos.io/runtime-plan-digest": request.spec.runtime_plan_digest,
                    "researchcosmos.io/spec-digest": request.spec_digest,
                },
            }
        }


class _AgentTransport:
    def __init__(self, kube: _FakeKube) -> None:
        self.kube = kube
        self.stops = 0

    def agent_rpc(
        self, binding: Mapping[str, str], request: Mapping[str, object]
    ) -> AgentRpcResponse:
        del binding, request
        raise AssertionError("Task 7 Journey does not start another generation")

    def inspect_supervisor(self, binding: Mapping[str, str], container: str) -> AgentRpcResponse:
        del binding, container
        alive = "agent" not in self.kube.terminated
        return AgentRpcResponse(1, 0, "", "", "idle" if alive else "stopped", alive)

    def stop_supervisor(self, binding: Mapping[str, str], container: str) -> AgentRpcResponse:
        del binding
        assert container == "agent"
        self.stops += 1
        self.kube.terminated.add("agent")
        self.kube.events.append({"kind": "RPC", "role": "agent", "action": "shutdown"})
        return AgentRpcResponse(1, 0, "", "", "stopped", False)


class _WorkspaceTransport:
    def __init__(self, kube: _FakeKube, sidecar: WorkspaceSidecar) -> None:
        self.kube = kube
        self.local = LocalWorkspaceRpcTransport(sidecar.dispatch)
        self.stops = 0

    def rpc(
        self,
        binding: Mapping[str, str],
        header: Mapping[str, object],
        body: Path | None = None,
    ) -> WorkspaceRpcReply:
        action = header.get("action")
        if action == "inspectSupervisor":
            alive = "workspace" not in self.kube.terminated
            self.kube.events.append({"kind": "RPC", "role": "workspace", "action": action})
            return WorkspaceRpcReply({"ok": True, "supervisorAlive": alive}, None)
        if action == "shutdown":
            self.stops += 1
            self.kube.terminated.add("workspace")
            self.kube.events.append({"kind": "RPC", "role": "workspace", "action": action})
            return WorkspaceRpcReply(
                {"ok": True, "supervisorAlive": False, "state": "stopped"}, None
            )
        if "workspace" in self.kube.terminated:
            raise RuntimeError("terminated workspace sidecar is not reachable")
        return self.local.rpc(binding, header, body)


def _create_request() -> CreateJobRequest:
    body = json.loads((FIXTURES / "create-request.json").read_text())
    body["providerRequestId"] = "request-task-7"
    body["spec"]["workspace"]["resources"]["gpu"] = 1
    body["specDigest"] = canonical_digest(body["spec"])
    return CreateJobRequest.model_validate(body)


def _provider(
    kube: _FakeKube,
    store: V2JobStore,
    agent: _AgentTransport,
    workspace: _WorkspaceTransport,
) -> V2JobProvider:
    return V2JobProvider(
        kube,
        store,
        _Renderer(),
        clock=lambda: NOW,
        sleeper=lambda _: None,
        transport=agent,
        workspace_transport=workspace,
        delete_poll_attempts=2,
    )


def _credential() -> tuple[bytes, CredentialGrantMetadata]:
    raw = b"task-7-short-lived-credential"
    credential_sha256 = hashlib.sha256(raw).hexdigest()
    payload = {
        "agentRunRef": "run-task-7",
        "generation": 1,
        "launchBundleDigest": "a" * 64,
        "audience": "agent",
        "credentialSha256": credential_sha256,
        "ttlSeconds": 300,
        "jobUid": str(JOB_UID),
        "podUid": str(POD_UID),
    }
    return raw, CredentialGrantMetadata(
        credential_grant_ref="grant-task-7",
        credential_sha256=credential_sha256,
        grant_metadata_digest=canonical_digest(payload),
        agent_run_ref="run-task-7",
        generation=1,
        launch_bundle_digest="a" * 64,
        audience="agent",
        ttl_seconds=300,
        job_uid=JOB_UID,
        pod_uid=POD_UID,
    )


def _collect(ref: str, path: str, content: bytes) -> TransferRegisterRequest:
    spec = TransferSpec(
        direction=TransferDirection.COLLECT_OUTPUT,
        path=path,
        declared_size_bytes=len(content),
        authorized_max_size_bytes=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
        mode="direct",
        overwrite_policy="forbid",
    )
    return TransferRegisterRequest(
        transfer_ref=ref, request_digest=canonical_digest(spec), spec=spec
    )


def _cancel(ref: str = "cancel-task-7", *, finish: list[str] | None = None) -> CancelJobRequest:
    spec = CancelSpec(
        finish_collect_transfer_refs=["collect-authorized"] if finish is None else finish,
        reason="caller-interrupt",
    )
    return CancelJobRequest(cancel_ref=ref, request_digest=canonical_digest(spec), spec=spec)


def _setup(
    tmp_path: Path,
) -> tuple[_FakeKube, V2JobStore, _AgentTransport, _WorkspaceTransport, V2JobProvider]:
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    kube = _FakeKube(workspace_path)
    store = V2JobStore(kube, clock=lambda: NOW)  # type: ignore[arg-type]
    agent = _AgentTransport(kube)
    workspace = _WorkspaceTransport(kube, WorkspaceSidecar(workspace_path))
    provider = _provider(kube, store, agent, workspace)
    created = provider.create(_create_request())
    assert created.created is True and created.snapshot.pod_uid == POD_UID
    return kube, store, agent, workspace, provider


def _seed_runtime(tmp_path: Path, store: V2JobStore, provider: V2JobProvider) -> None:
    raw, metadata = _credential()
    provider.grant_credential("job-1", metadata, raw)
    for ref, name, content in (
        ("collect-authorized", "kept.bin", b"authorized-output"),
        ("collect-unrequested", "possibly-lost.bin", b"unrequested-output"),
    ):
        (tmp_path / "workspace" / name).write_bytes(content)
        provider.register_transfer("job-1", _collect(ref, name, content))
    frame = WorkspaceFrame.model_validate(
        {"protocol": "cosmos.workspace/1", "action": "echo", "result": {"answer": 7}}
    )
    operation = WorkspaceInvokeRequest(
        operation_ref="operation-task-7",
        request_digest=canonical_digest(frame.root),
        job_uid=JOB_UID,
        pod_uid=POD_UID,
        frame=frame,
    )
    assert provider.invoke_workspace("job-1", operation).snapshot.state == "succeeded"
    retained = store.read_runtime("operation", "job-1", "operation-task-7")
    assert retained is not None
    accepted = json.loads(retained.values["payload"])
    accepted.update({"state": "accepted", "finishedAt": None})
    store.update_runtime(
        "operation",
        "job-1",
        "operation-task-7",
        {**retained.values, "dispatchPhase": "relinquished", "payload": json.dumps(accepted)},
    )


def test_cancel_delete_tombstone_journey(tmp_path: Path) -> None:
    kube, store, agent, workspace, provider = _setup(tmp_path)
    raw, metadata = _credential()
    kube.pause_secret_create = True
    with ThreadPoolExecutor(max_workers=1) as pool:
        grant = pool.submit(provider.grant_credential_result, "job-1", metadata, raw)
        assert kube.secret_create_claimed.wait(timeout=2)
        try:
            replay = provider.grant_credential_result("job-1", metadata, raw)
            assert replay.created is False and replay.snapshot.state == "accepted"
            with pytest.raises(StateConflictError):
                provider.cancel("job-1", _cancel("cancel-during-grant", finish=[]))
            assert not store.list_runtime("cancel", "job-1")
            lifecycle = store.read_runtime("lifecycle", "job-1", "slot")
            assert lifecycle is not None
            lifecycle_payload = json.loads(lifecycle.values["payload"])
            assert lifecycle_payload["gate"] == "open"
            assert len(lifecycle_payload["activeClaims"]) == 1
            with pytest.raises(StateConflictError):
                LifecycleGate(store).claim(
                    "job-1",
                    str(JOB_UID),
                    str(POD_UID),
                    "credential-grant",
                    "grant-task-7",
                )
        finally:
            kube.release_secret_create.set()
        created_grant = grant.result()
        assert created_grant.created is True and created_grant.snapshot.state == "available"
    LifecycleGate(store).claim(
        "job-1",
        str(JOB_UID),
        str(POD_UID),
        "credential-grant",
        "grant-task-7",
    )
    assert provider.reconcile_all().indeterminate == 0
    reconciled_lifecycle = store.read_runtime("lifecycle", "job-1", "slot")
    assert reconciled_lifecycle is not None
    assert json.loads(reconciled_lifecycle.values["payload"])["activeClaims"] == []
    kube.pause_secret_create = False
    _seed_runtime(tmp_path, store, provider)
    app = FastAPI()
    app.include_router(create_jobs_router(provider, "task-7-token"))
    client = TestClient(app)
    auth = {"Authorization": "Bearer task-7-token", "Content-Type": "application/json"}
    delivered = client.get("/api/v2/jobs/job-1/transfers/collect-authorized/content", headers=auth)
    assert delivered.status_code == 200 and delivered.content == b"authorized-output"

    cancel = _cancel()
    response = client.post(
        "/api/v2/jobs/job-1/cancel", headers=auth, content=cancel.model_dump_json(by_alias=True)
    )
    assert response.status_code == 202, response.text
    canceled = response.json()
    assert canceled["bindingState"] == "canceled"
    assert canceled["cancelAction"]["state"] == "succeeded"
    assert canceled["outputLossPossible"] is True
    assert canceled["gpuRelease"]["state"] == "complete"
    assert {item["transferRef"]: item["state"] for item in canceled["transferObservations"]} == {
        "collect-authorized": "completed",
        "collect-unrequested": "registered",
    }
    assert canceled["terminalOperationRefs"] == ["operation-task-7"]
    assert not kube.secrets and kube.job is not None and len(kube.pods) == 1
    assert provider.logs("job-1", "workspace").content == "retained-terminal-log\n"
    counts = (agent.stops, workspace.stops, workspace.local.last_request_frame)
    lifecycle = store.read_runtime("lifecycle", "job-1", "slot")
    assert lifecycle is not None
    interrupted_close = json.loads(lifecycle.values["payload"])
    interrupted_close["gate"] = "closing"
    interrupted_close["close"]["phase"] = "workspace_stopped"
    store.update_runtime(
        "lifecycle",
        "job-1",
        "slot",
        {**lifecycle.values, "payload": json.dumps(interrupted_close, sort_keys=True)},
    )
    assert (
        client.post(
            "/api/v2/jobs/job-1/cancel", headers=auth, content=cancel.model_dump_json(by_alias=True)
        ).status_code
        == 200
    )
    assert (agent.stops, workspace.stops, workspace.local.last_request_frame) == counts
    repaired_close = store.read_runtime("lifecycle", "job-1", "slot")
    assert repaired_close is not None
    repaired_payload = json.loads(repaired_close.values["payload"])
    assert repaired_payload["gate"] == "closed"
    assert repaired_payload["close"]["phase"] == "succeeded"
    changed = _cancel(finish=["collect-authorized", "collect-unrequested"])
    assert (
        client.post(
            "/api/v2/jobs/job-1/cancel",
            headers=auth,
            content=changed.model_dump_json(by_alias=True),
        ).status_code
        == 409
    )

    delete_headers = {
        **auth,
        "KCS-Delete-Ref": "delete-task-7",
        "KCS-Request-Digest": EMPTY_OBJECT_DIGEST,
    }
    deleted = client.delete("/api/v2/jobs/job-1", headers=delete_headers)
    assert deleted.status_code == 200
    tombstone = deleted.json()
    assert tombstone["state"] == "deleted" and tombstone["finalState"] == "canceled"
    assert tombstone["cleanup"]["state"] == "complete"
    assert tombstone["gpuRelease"]["state"] == "complete"
    assert tombstone["credentialObservations"] == [
        {
            "credentialGrantRef": "grant-task-7",
            "state": "revoked",
            "secretPresent": False,
            "observedAt": NOW.isoformat().replace("+00:00", "Z"),
        }
    ]
    assert {item["transferRef"] for item in tombstone["transferObservations"]} == {
        "collect-authorized",
        "collect-unrequested",
    }
    retained = store.read_create("request-task-7")
    assert retained is not None and retained.is_tombstone
    create_map = next(item for item in kube.maps.values() if item["data"]["state"] == "deleted")
    assert create_map["metadata"]["ownerReferences"] == []
    assert kube.job is None and kube.pods == [] and not (tmp_path / "workspace").exists()
    assert all(item["data"].get("kind") is None for item in kube.maps.values())
    first_tombstone_event = next(
        index
        for index, event in enumerate(kube.events)
        if event["kind"] == "ConfigMap" and event.get("state") == "deleted"
    )
    first_workload_delete = next(
        index
        for index, event in enumerate(kube.events)
        if event["kind"] == "Job" and event["verb"] == "delete"
    )
    delete_intent_event = next(
        index
        for index, event in enumerate(kube.events)
        if event["kind"] == "ConfigMap" and event.get("state") == "deleting"
    )
    assert delete_intent_event < first_workload_delete < first_tombstone_event
    claim_event = next(
        index
        for index, event in enumerate(kube.events)
        if event.get("gate") == "open" and event.get("activeClaims") == 1
    )
    secret_effect = next(
        index
        for index, event in enumerate(kube.events)
        if event["kind"] == "Secret" and event["verb"] == "create"
    )
    release_event = next(
        index
        for index, event in enumerate(kube.events[secret_effect + 1 :], secret_effect + 1)
        if event.get("gate") == "open" and event.get("activeClaims") == 0
    )
    cancel_close = next(
        index
        for index, event in enumerate(kube.events[release_event + 1 :], release_event + 1)
        if event.get("closeKind") == "cancel" and event.get("closePhase") == "accepted"
    )
    delete_close = next(
        index
        for index, event in enumerate(kube.events[cancel_close + 1 :], cancel_close + 1)
        if event.get("closeKind") == "delete" and event.get("closePhase") == "accepted"
    )
    assert claim_event < secret_effect < release_event < cancel_close < delete_close

    assert client.delete("/api/v2/jobs/job-1", headers=delete_headers).json() == tombstone
    assert (
        client.delete(
            "/api/v2/jobs/job-1", headers={**delete_headers, "KCS-Delete-Ref": "changed"}
        ).status_code
        == 409
    )
    assert client.get("/api/v2/jobs/job-1", headers=auth).status_code == 410
    assert (
        client.post(
            "/api/v2/jobs", headers=auth, content=_create_request().model_dump_json(by_alias=True)
        ).status_code
        == 410
    )
    assert kube.created_jobs == 1
    print(
        "JOURNEY task7 lifecycle",
        json.dumps(
            {
                "cancel": canceled,
                "tombstone": tombstone,
                "events": kube.events,
                "sideEffects": {
                    "agentStops": agent.stops,
                    "workspaceStops": workspace.stops,
                    "jobsCreated": kube.created_jobs,
                },
            },
            sort_keys=True,
        ),
    )


def test_startup_reconcile_recovers_cancel_and_delete_crash_points(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        CancelSpec(finish_collect_transfer_refs=["duplicate", "duplicate"])
    with pytest.raises(ValueError):
        FinalizeSpec(
            operation_refs=["duplicate", "duplicate"],
            transfer_refs=[],
            drain_timeout_seconds=1,
        )
    reserved_workspace = tmp_path / "reserved-workspace"
    reserved_workspace.mkdir()
    reserved_kube = _FakeKube(reserved_workspace)
    reserved_store = V2JobStore(reserved_kube, clock=lambda: NOW)  # type: ignore[arg-type]
    reserved_request = _create_request()
    reserved_store.reserve_create(
        reserved_request.provider_request_id,
        reserved_request.spec_digest,
        "job-1",
        reserved_request.spec.digest_payload(),
    )
    reserved_agent = _AgentTransport(reserved_kube)
    reserved_workspace_transport = _WorkspaceTransport(
        reserved_kube, WorkspaceSidecar(reserved_workspace)
    )
    reserved_provider = _provider(
        reserved_kube,
        reserved_store,
        reserved_agent,
        reserved_workspace_transport,
    )
    reserved_report = reserved_provider.reconcile_all()
    assert reserved_report.reconciled == 1
    assert reserved_kube.created_jobs == 1 and reserved_kube.job is not None
    retained_finalize = FinalizeSpec(operation_refs=[], transfer_refs=[], drain_timeout_seconds=1)
    LifecycleGate(reserved_store).begin_close(
        "job-1",
        str(JOB_UID),
        str(POD_UID),
        "finalize",
        "finalize-close-gap",
        canonical_digest(retained_finalize),
        retained_finalize.model_dump_json(by_alias=True),
    )
    close_gap_report = _provider(
        reserved_kube,
        reserved_store,
        reserved_agent,
        reserved_workspace_transport,
    ).reconcile_all()
    assert close_gap_report.reconciled == 1
    recovered_finalize = reserved_store.read_runtime("finalize", "job-1", "slot")
    assert recovered_finalize is not None
    assert json.loads(recovered_finalize.values["payload"])["state"] == "succeeded"
    kube, store, agent, workspace, provider = _setup(tmp_path)
    _seed_runtime(tmp_path, store, provider)
    kube.linger_secret_once = True
    with pytest.raises(CredentialDestroyFailedError):
        provider.cancel("job-1", _cancel())
    assert kube.secrets  # delete acceptance was not treated as absence proof

    kube.fail_cancel_phase_once = True
    restarted = _provider(kube, store, agent, workspace)
    interrupted = restarted.reconcile_all()
    assert interrupted.indeterminate == 1
    assert agent.stops == 1 and "agent" in kube.terminated
    recovered = _provider(kube, store, agent, workspace)
    report = recovered.reconcile_all()
    assert report.indeterminate == 0
    assert recovered.inspect("job-1").binding_state == "canceled"
    assert agent.stops == 1 and workspace.stops == 1 and not kube.secrets

    assert recovered.inspect_operation("job-1", "operation-task-7").state == "succeeded"
    assert recovered.inspect_transfer("job-1", "collect-authorized").state == "completed"
    assert any(
        event.get("action") == "inspectSupervisor" and event.get("role") == "workspace"
        for event in kube.events
    )

    kube.fail_job_delete_once = True
    with pytest.raises(DependencyUnavailableError):
        recovered.delete("job-1", "delete-after-crash", EMPTY_OBJECT_DIGEST)
    pending = store.read_create("request-task-7")
    assert pending is not None and pending.is_deleting and pending.cleanup_state == "pending"
    assert pending.deleted_at is None and pending.expires_at is None
    replayed_create = recovered.create(_create_request())
    assert replayed_create.created is False
    assert replayed_create.snapshot.binding_state == "deleting"
    retained_delete = store.read_create("request-task-7")
    assert retained_delete is not None and retained_delete.is_deleting
    assert retained_delete.delete_ref == "delete-after-crash"
    live_mutations: tuple[Callable[[], object], ...] = (
        lambda: store.mark_created("request-task-7", str(JOB_UID)),
        lambda: store.bind_first_pod("request-task-7", str(POD_UID)),
        lambda: store.mark_indeterminate("request-task-7", "must not replace delete intent"),
    )
    for mutate in live_mutations:
        with pytest.raises(StateConflictError):
            mutate()
    deleting = recovered.inspect("job-1")
    assert deleting.binding_state == "deleting"
    assert deleting.delete_action.action_ref == "delete-after-crash"
    kube.fail_owner_cleanup_phase_once = True
    deletion_gap = _provider(kube, store, agent, workspace)
    interrupted_delete = deletion_gap.reconcile_all()
    assert interrupted_delete.indeterminate == 1
    assert store.read_runtime("lifecycle", "job-1", "slot") is None
    raw, metadata = _credential()
    with pytest.raises(StateConflictError):
        deletion_gap.grant_credential_result("job-1", metadata, raw)
    assert not kube.secrets
    final = _provider(kube, store, agent, workspace).reconcile_all()
    assert final.deleted == 1 and kube.job is None and kube.pods == []
    tombstone = store.read_create("request-task-7")
    assert tombstone is not None and tombstone.cleanup_state == "complete"
    assert all(item["data"].get("kind") is None for item in kube.maps.values())
    print(
        "JOURNEY task7 recovery",
        json.dumps(
            {
                "events": kube.events,
                "report": final.__dict__,
                "tombstone": tombstone.tombstone_payload(),
            },
            sort_keys=True,
        ),
    )
