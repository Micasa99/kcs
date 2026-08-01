"""Focused, no-network recovery Journey for Task 5."""
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import kcs.conformance.agent_supervisor as supervisor
from kcs.jobs.canonical import canonical_digest
from kcs.jobs.contracts import (
    AgentStartRequest,
    CredentialGrantMetadata,
    CredentialGrantSnapshot,
    CredentialState,
    FinalizeJobRequest,
    FinalizeSpec,
    GenerationSnapshot,
    RunnerState,
)
from kcs.jobs.errors import (
    CredentialDestroyFailedError,
    DependencyUnavailableError,
    IdentityDigestConflict,
    StateConflictError,
)
from kcs.jobs.kube import V2KubeAdapter
from kcs.jobs.provider import V2JobProvider
from kcs.jobs.store import V2JobStore
from kcs.jobs.transport import AgentRpcResponse, ExecRpcTransport
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
        self.config_maps: dict[str, dict[str, Any]] = {}
        self.secrets: dict[str, dict[str, Any]] = {}
        self.audit_bytes: list[bytes] = []
        self.secret_creates = 0
        self.secret_deletes = 0
        self.secret_delete_failures = 0
        self.terminated: set[str] = set()
        self.fail_next_finalize_replace = False

    def create_config_map(self, body: object) -> object:
        value = json.loads(json.dumps(body))
        name = value["metadata"]["name"]
        if name in self.config_maps:
            raise _ConflictError()
        value["metadata"]["resourceVersion"] = "1"
        self.config_maps[name] = value
        return value

    def read_config_map(self, name: str) -> object | None:
        return self.config_maps.get(name)

    def replace_config_map(self, name: str, body: object) -> object:
        value = json.loads(json.dumps(body))
        if self.fail_next_finalize_replace and value["data"].get("kind") == "finalize":
            self.fail_next_finalize_replace = False
            raise RuntimeError("simulated retained-phase write loss")
        value["metadata"]["resourceVersion"] = str(
            int(self.config_maps[name]["metadata"]["resourceVersion"]) + 1
        )
        self.config_maps[name] = value
        return value

    def list_config_maps(self, label_selector: str | None = None) -> list[object]:
        if not label_selector:
            return list(self.config_maps.values())
        pairs = [part.split("=", 1) for part in label_selector.split(",")]
        return [
            item
            for item in self.config_maps.values()
            if all(item["metadata"]["labels"].get(key) == value for key, value in pairs)
        ]

    def create_secret(self, body: object) -> object:
        value = json.loads(json.dumps(body))
        self.secret_creates += 1
        value["metadata"]["uid"] = f"00000000-0000-4000-8000-{self.secret_creates + 4:012d}"
        self.secrets[value["metadata"]["name"]] = value
        annotations = value["metadata"]["annotations"]
        self.audit_bytes.append(
            json.dumps(
                {
                    "kind": "Secret",
                    "verb": "create",
                    "name": value["metadata"]["name"],
                    "uid": value["metadata"]["uid"],
                    "jobUid": annotations["researchcosmos.io/job-uid"],
                    "podUid": annotations["researchcosmos.io/pod-uid"],
                    "grantRef": annotations["researchcosmos.io/grant-ref"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
        return value

    def read_secret(self, name: str) -> object | None:
        return self.secrets.get(name)

    def delete_secret(self, name: str, secret_uid: str) -> bool:
        observed = self.secrets.get(name)
        observed_uid = observed["metadata"]["uid"] if observed is not None else None
        observed_grant = (
            observed["metadata"]["annotations"]["researchcosmos.io/grant-ref"]
            if observed is not None
            else None
        )
        event = {
            "kind": "Secret",
            "verb": "delete",
            "name": name,
            "uidPrecondition": secret_uid,
            "observedUid": observed_uid,
            "observedGrantRef": observed_grant,
        }
        if observed_uid is not None and observed_uid != secret_uid:
            event["result"] = "uid-precondition-conflict"
            self.audit_bytes.append(
                json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
            )
            raise _ConflictError()
        self.secret_deletes += 1
        if self.secret_delete_failures:
            self.secret_delete_failures -= 1
            event["result"] = "injected-failure"
            self.audit_bytes.append(
                json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
            )
            raise RuntimeError("simulated Secret delete failure")
        existed = self.secrets.pop(name, None) is not None
        event["result"] = "accepted" if existed else "already-absent"
        self.audit_bytes.append(json.dumps(event, sort_keys=True, separators=(",", ":")).encode())
        return existed

    def read_job(self, job_ref: str) -> object:
        status = {"succeeded": 1} if self.terminated == {"agent", "workspace"} else {}
        return {
            "metadata": {"uid": str(JOB_UID), "resourceVersion": "9"},
            "status": status,
        }

    def list_job_pods(self, job_ref: str, job_uid: str | None = None) -> list[object]:
        statuses = []
        for role in ("agent", "workspace"):
            if role in self.terminated:
                state = {"terminated": {"exitCode": 0, "reason": "Completed"}}
                ready = False
            else:
                state = {"running": {}}
                ready = True
            statuses.append({"name": role, "ready": ready, "restart_count": 0, "state": state})
        return [
            {
                "metadata": {"uid": str(POD_UID)},
                "status": {"container_statuses": statuses},
            }
        ]

    def read_role_logs(self, *args: object) -> object:
        raise AssertionError("not part of this Journey")


class _Renderer:
    def job_ref(self, request: object) -> str:
        return "job-1"

    def render(self, request: object) -> object:
        return {}


class _Transport:
    def __init__(self, kube: _Kube) -> None:
        self.kube = kube
        self.starts = 0
        self.start_frames: list[Mapping[str, object]] = []
        self.stops: list[str] = []
        self.lose_agent_phase = False

    def agent_rpc(
        self, binding: Mapping[str, str], request: Mapping[str, object]
    ) -> AgentRpcResponse:
        self.starts += 1
        self.start_frames.append(dict(request))
        return AgentRpcResponse(
            1,
            cast(int, request["generation"]),
            cast(str, request["agentRunRef"]),
            cast(str, request["launchBundleDigest"]),
            "exited",
            True,
            7,
            0,
            credential_grant_ref=cast(str, request["credentialGrantRef"]),
            audience=cast(str, request["audience"]),
            credential_sha256=cast(str, request["credentialSha256"]),
            credential_consumed=True,
        )

    def stop_supervisor(self, binding: Mapping[str, str], container: str) -> AgentRpcResponse:
        self.stops.append(container)
        self.kube.terminated.add(container)
        if container == "agent" and self.lose_agent_phase:
            self.kube.fail_next_finalize_replace = True
        return AgentRpcResponse(1, 0, "", "", "stopped", False)


def _setup(
    *, sleeper: Callable[[float], None] | None = None
) -> tuple[_Kube, V2JobStore, _Transport, V2JobProvider]:
    kube = _Kube()
    store = V2JobStore(kube, clock=lambda: NOW)
    store.reserve_create(
        "request-1",
        DIGEST,
        "job-1",
        {"subjectRef": "s", "runtimePlanDigest": DIGEST, "workspace": {}},
    )
    store.mark_created("request-1", str(JOB_UID))
    store.bind_first_pod("request-1", str(POD_UID))
    transport = _Transport(kube)
    provider = V2JobProvider(
        kube,
        store,
        _Renderer(),
        clock=lambda: NOW,
        sleeper=sleeper,
        transport=transport,
    )
    return kube, store, transport, provider


def _credential(
    *,
    grant_ref: str = "grant-1",
    raw: bytes = b"synthetic-short-credential",
    agent_run_ref: str = "run-1",
    generation: int = 1,
) -> tuple[bytes, CredentialGrantMetadata]:
    payload = {
        "agentRunRef": agent_run_ref,
        "generation": generation,
        "launchBundleDigest": DIGEST,
        "audience": "agent",
        "credentialSha256": hashlib.sha256(raw).hexdigest(),
        "ttlSeconds": 300,
        "jobUid": str(JOB_UID),
        "podUid": str(POD_UID),
    }
    return raw, CredentialGrantMetadata(
        credential_grant_ref=grant_ref,
        credential_sha256=payload["credentialSha256"],
        grant_metadata_digest=canonical_digest(payload),
        agent_run_ref=agent_run_ref,
        generation=generation,
        launch_bundle_digest=DIGEST,
        audience="agent",
        ttl_seconds=300,
        job_uid=JOB_UID,
        pod_uid=POD_UID,
    )


def _start() -> AgentStartRequest:
    return AgentStartRequest(
        execution_envelope_ref="envelope-1",
        execution_envelope_digest=DIGEST,
        agent_run_ref="run-1",
        generation=1,
        launch_bundle_path="launch.json",
        launch_bundle_digest=DIGEST,
        launch_bundle_size_bytes=1,
        material_paths=["material.json"],
        credential_grant_ref="grant-1",
    )


def _reserve_accepted_generation(store: V2JobStore, request: AgentStartRequest) -> None:
    snapshot = GenerationSnapshot(
        job_ref="job-1",
        generation=request.generation,
        agent_run_ref=request.agent_run_ref,
        execution_envelope_ref=request.execution_envelope_ref,
        execution_envelope_digest=request.execution_envelope_digest,
        launch_bundle_path=request.launch_bundle_path,
        launch_bundle_digest=request.launch_bundle_digest,
        launch_bundle_size_bytes=request.launch_bundle_size_bytes,
        material_paths=request.material_paths,
        credential_grant_ref=request.credential_grant_ref,
        start_metadata_digest=canonical_digest(request.digest_payload()),
        runner_state=RunnerState.ACCEPTED,
        supervisor_alive=True,
        pid=None,
        exit_code=None,
        started_at=None,
        finished_at=None,
        observed_at=NOW,
        replayed=False,
        credential_acknowledged_at=None,
        credential_destroyed_at=None,
    )
    values = {
        "identityDigest": snapshot.start_metadata_digest,
        "jobUid": str(JOB_UID),
        "podUid": str(POD_UID),
        "payload": snapshot.model_dump_json(by_alias=True),
    }
    store.reserve_runtime("generation", "1", "job-1", values)


def _finalize(
    *, operations: list[str] | None = None, transfers: list[str] | None = None
) -> FinalizeJobRequest:
    spec = FinalizeSpec(
        operation_refs=operations or [], transfer_refs=transfers or [], drain_timeout_seconds=1
    )
    return FinalizeJobRequest(
        finalize_ref="finalize-1", request_digest=canonical_digest(spec), spec=spec
    )


def _runtime_values(state: str) -> dict[str, str]:
    return {
        "identityDigest": DIGEST,
        "jobUid": str(JOB_UID),
        "podUid": str(POD_UID),
        "payload": json.dumps({"state": state, "observedAt": NOW.isoformat()}),
    }


def test_generation_recovery_uses_retained_grant_and_never_claims_unproved_cleanup() -> None:
    kube, store, transport, provider = _setup()
    raw, metadata = _credential()
    provider.grant_credential("job-1", metadata, raw)
    request = _start()
    _reserve_accepted_generation(store, request)
    current_name = next(
        name for name, item in kube.config_maps.items() if item["data"].get("kind") == "generation"
    )
    legacy_name = f"kcs-v2-generation-{hashlib.sha256(b'1').hexdigest()[:32]}"
    kube.config_maps[legacy_name] = kube.config_maps.pop(current_name)
    kube.config_maps[legacy_name]["metadata"]["name"] = legacy_name
    kube.secret_delete_failures = 1

    with pytest.raises(CredentialDestroyFailedError):
        provider.start_agent("job-1", request)
    record = store.read_runtime("credential", "job-1", "grant-1")
    assert record is not None and record.values["cleanupTarget"] == "destroyed"
    failed = CredentialGrantSnapshot.model_validate_json(record.values["payload"])
    assert failed.state is CredentialState.DESTROY_FAILED
    provider.reconcile_credentials()
    deletes_after_absence_proof = kube.secret_deletes

    recovered = provider.start_agent("job-1", request)
    assert recovered.runner_state is RunnerState.EXITED
    assert recovered.credential_destroyed_at == NOW
    assert provider.inspect_credential_grant("job-1", "grant-1").state is CredentialState.DESTROYED
    assert transport.starts == 2 and kube.secret_deletes == deletes_after_absence_proof
    assert legacy_name in kube.config_maps and current_name not in kube.config_maps

    changed = request.model_copy(update={"launch_bundle_digest": "b" * 64})
    with pytest.raises(IdentityDigestConflict):
        provider.start_agent("job-1", changed)
    assert transport.starts == 2
    assert provider.start_agent("job-1", request).replayed is True
    assert transport.starts == 2

    rotated_raw, rotated_metadata = _credential(
        grant_ref="grant-2",
        raw=b"synthetic-rotated-credential",
        agent_run_ref="run-2",
        generation=2,
    )
    rotated = provider.grant_credential("job-1", rotated_metadata, rotated_raw)
    assert rotated.state is CredentialState.AVAILABLE and rotated.secret_present is True
    secret_name = next(iter(kube.secrets))
    retained_secret_uid = kube.secrets[secret_name]["metadata"]["uid"]
    deletes_before_restart = kube.secret_deletes
    audit_before_restart = list(kube.audit_bytes)

    restarted = V2JobProvider(
        kube,
        store,
        _Renderer(),
        clock=lambda: NOW,
        transport=_Transport(kube),
    )
    previous = restarted.inspect_credential_grant("job-1", "grant-1")
    current = restarted.inspect_credential_grant("job-1", "grant-2")
    assert secret_name in kube.secrets
    retained_secret = kube.secrets[secret_name]
    annotations = retained_secret["metadata"]["annotations"]
    assert previous.state is CredentialState.DESTROYED and previous.secret_present is False
    assert current.state is CredentialState.AVAILABLE and current.secret_present is True
    assert annotations["researchcosmos.io/grant-ref"] == "grant-2"
    assert annotations["researchcosmos.io/pod-uid"] == str(POD_UID)
    assert retained_secret["metadata"]["uid"] == retained_secret_uid
    assert kube.secret_deletes == deletes_before_restart
    assert kube.audit_bytes == audit_before_restart
    assert raw not in json.dumps(kube.config_maps).encode()
    assert raw not in b"\n".join(kube.audit_bytes)
    assert rotated_raw not in b"\n".join(kube.audit_bytes)
    print(
        "JOURNEY task5 credential-rotation",
        json.dumps(
            {
                "rawAuditUtf8": [event.decode() for event in kube.audit_bytes],
                "restart": {
                    "grant1": previous.model_dump(mode="json", by_alias=True),
                    "grant2": current.model_dump(mode="json", by_alias=True),
                    "retainedSecretUid": retained_secret_uid,
                    "secretDeletes": kube.secret_deletes,
                },
            },
            sort_keys=True,
        ),
    )


def test_finalize_drains_only_requested_records_and_recovers_lost_stop_phase() -> None:
    kube = _Kube()
    store = V2JobStore(kube, clock=lambda: NOW)
    store.reserve_create(
        "request-1",
        DIGEST,
        "job-1",
        {"subjectRef": "s", "runtimePlanDigest": DIGEST, "workspace": {}},
    )
    store.mark_created("request-1", str(JOB_UID))
    store.bind_first_pod("request-1", str(POD_UID))
    store.reserve_runtime("operation", "op-1", "job-1", _runtime_values("running"))
    store.reserve_runtime("operation", "op-unrequested", "job-1", _runtime_values("running"))
    store.reserve_runtime("transfer", "tx-1", "job-1", _runtime_values("streaming"))

    def finish_requested(_: float) -> None:
        for kind, ref, state in (
            ("operation", "op-1", "succeeded"),
            ("transfer", "tx-1", "completed"),
        ):
            record = store.read_runtime(kind, "job-1", ref)
            assert record is not None
            store.update_runtime(
                kind, "job-1", ref, {**record.values, "payload": _runtime_values(state)["payload"]}
            )

    transport = _Transport(kube)
    provider = V2JobProvider(
        kube, store, _Renderer(), clock=lambda: NOW, sleeper=finish_requested, transport=transport
    )
    before = provider.inspect("job-1")
    assert before.active_operation_refs == ["op-1", "op-unrequested"]
    assert [item.transfer_ref for item in before.transfer_observations] == ["tx-1"]
    transport.lose_agent_phase = True

    with pytest.raises(DependencyUnavailableError):
        provider.finalize("job-1", _finalize(operations=["op-1"], transfers=["tx-1"]))
    recovered = provider.finalize("job-1", _finalize(operations=["op-1"], transfers=["tx-1"]))
    assert recovered.created is False
    assert recovered.snapshot.terminal_operation_refs == ["op-1"]
    assert recovered.snapshot.active_operation_refs == ["op-unrequested"]
    assert transport.stops.count("agent") == 1 and transport.stops.count("workspace") == 1

    kube2, store2, transport2, provider2 = _setup()
    store2.reserve_runtime("operation", "op-failed", "job-1", _runtime_values("failed"))
    with pytest.raises(StateConflictError, match="failed"):
        provider2.finalize("job-1", _finalize(operations=["op-failed"]))
    assert transport2.stops == []


def test_finalize_returns_atomic_created_status_and_migrates_legacy_identity() -> None:
    kube, store, transport, provider = _setup()
    request = _finalize()
    legacy_values = {
        "identityDigest": request.request_digest,
        "jobUid": str(JOB_UID),
        "podUid": str(POD_UID),
        "payload": json.dumps({"state": "accepted", "observedAt": NOW.isoformat()}),
    }
    store.reserve_runtime("finalize", request.finalize_ref, "job-1", legacy_values)

    replay = provider.finalize("job-1", request)
    assert replay.created is False
    slot = store.read_runtime("finalize", "job-1", "slot")
    assert slot is not None and slot.values["finalizeRef"] == request.finalize_ref
    assert transport.stops == ["agent", "workspace"]

    kube2, _, _, provider2 = _setup()
    app = FastAPI()
    app.include_router(create_jobs_router(provider2, "token"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer token", "Content-Type": "application/json"}
    first = client.post(
        "/api/v2/jobs/job-1/finalize",
        headers=headers,
        json=request.model_dump(mode="json", by_alias=True),
    )
    second = client.post(
        "/api/v2/jobs/job-1/finalize",
        headers=headers,
        json=request.model_dump(mode="json", by_alias=True),
    )
    assert (first.status_code, second.status_code) == (202, 200)
    assert (
        len([item for item in kube2.config_maps.values() if item["data"].get("kind") == "finalize"])
        == 1
    )


def test_supervisor_generation_slot_and_frame_validation_are_strict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential_path = tmp_path / "credential"
    credential_path.write_bytes(b"fixture-credential")
    launches = 0

    class _Child:
        pid = 9
        returncode = 0

        def wait(self) -> None:
            return None

    def popen(command: list[str]) -> _Child:
        nonlocal launches
        launches += 1
        assert command == ["/bin/true"]
        return _Child()

    monkeypatch.setattr(supervisor.subprocess, "Popen", popen)
    slots_type = getattr(supervisor, "_GenerationSlots", None)
    assert slots_type is not None
    slots = slots_type(credential_path)
    frame: dict[str, object] = {
        "protocolVersion": 1,
        "generation": 1,
        "agentRunRef": "run-1",
        "executionEnvelopeRef": "env-1",
        "executionEnvelopeDigest": DIGEST,
        "launchBundlePath": "launch.json",
        "launchBundleDigest": DIGEST,
        "launchBundleSizeBytes": 1,
        "materialPaths": ["material.json"],
        "credentialGrantRef": "grant-1",
        "audience": "agent",
        "credentialSha256": hashlib.sha256(b"fixture-credential").hexdigest(),
    }
    assert slots.dispatch(frame) == slots.dispatch(frame)
    changed = {**frame, "audience": "other"}
    with pytest.raises(ValueError, match="generation"):
        slots.dispatch(changed)
    assert launches == 1
    with pytest.raises(ValueError):
        slots.dispatch({**frame, "generation": True})
    with pytest.raises(ValueError):
        slots.dispatch({**frame, "generation": 2, "launchBundleDigest": "G" * 64})
    with pytest.raises(ValueError):
        slots.dispatch({**frame, "generation": 2, "credentialSha256": "a" * 63})


class _ExecCore:
    def list_namespaced_pod(self, *, namespace: str, label_selector: str) -> object:
        return {"items": [{"metadata": {"name": "pod-1", "uid": str(POD_UID)}}]}

    def connect_get_namespaced_pod_exec(self, name: str, namespace: str, **kwargs: object) -> None:
        return None


class _WebSocket:
    def __init__(self, stdout: list[str], status: Mapping[str, object]) -> None:
        self.events: list[tuple[str, str]] = [("stdout", part) for part in stdout]
        self.events.extend((("status", json.dumps(status)), ("close", "")))
        self.stdout = ""
        self.channels: dict[int, str] = {}
        self.open = True

    def write_stdin(self, data: str) -> None:
        assert data.startswith("{")

    def is_open(self) -> bool:
        return self.open

    def update(self, timeout: float) -> None:
        kind, value = self.events.pop(0)
        if kind == "stdout":
            self.stdout += value
        elif kind == "status":
            self.channels[3] = self.channels.get(3, "") + value
        else:
            self.open = False

    def peek_stdout(self) -> bool:
        return bool(self.stdout)

    def read_stdout(self) -> str:
        value, self.stdout = self.stdout, ""
        return value

    def peek_stderr(self) -> bool:
        return False

    def read_stderr(self) -> str:
        return ""

    def read_channel(self, channel: int) -> str:
        return self.channels.pop(channel, "")

    def close(self) -> None:
        self.open = False


def test_kubernetes_exec_requires_fragmented_zero_status_and_sanitizes_nonzero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    success = _WebSocket(['{"ok":', "true}"], {"status": "Success"})
    monkeypatch.setattr("kubernetes.stream.stream", lambda *args, **kwargs: success)
    adapter = V2KubeAdapter("researchcosmos-v2", cast(Any, object()), cast(Any, _ExecCore()))
    binding = {"jobRef": "job-1", "jobUid": str(JOB_UID), "podUid": str(POD_UID)}
    output = adapter.exec_supervisor_rpc(
        binding, "agent", ["/opt/kcs/agent-supervisor", "rpc"], b"{}"
    )
    assert output == b'{"ok":true}'

    failed = _WebSocket(
        [],
        {
            "status": "Failure",
            "message": "command terminated with exit code 17; sensitive remote detail",
            "details": {"causes": [{"reason": "ExitCode", "message": "17"}]},
        },
    )
    monkeypatch.setattr("kubernetes.stream.stream", lambda *args, **kwargs: failed)
    with pytest.raises(DependencyUnavailableError) as error:
        adapter.exec_supervisor_rpc(binding, "agent", ["/opt/kcs/agent-supervisor", "rpc"], b"{}")
    assert "17" not in str(error.value) and "sensitive" not in str(error.value)

    transport = ExecRpcTransport(
        lambda binding, container, command, frame: (
            b'{"protocolVersion":true,"generation":1,"agentRunRef":"r","launchBundleDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"exited","supervisorAlive":true}'
        )
    )
    with pytest.raises(DependencyUnavailableError):
        transport.agent_rpc(binding, {})


def test_credential_http_role_and_streaming_cap_stop_before_provider() -> None:
    _, _, _, provider = _setup()
    base_headers = {
        "Authorization": "Bearer token",
        "Content-Type": "application/octet-stream",
        "KCS-Credential-Grant-Ref": "grant-1",
        "KCS-Credential-SHA256": DIGEST,
        "KCS-Grant-Metadata-Digest": DIGEST,
        "KCS-Agent-Run-Ref": "run-1",
        "KCS-Generation": "1",
        "KCS-Launch-Bundle-Digest": DIGEST,
        "KCS-Audience": "agent",
        "KCS-Credential-TTL-Seconds": "300",
        "KCS-Job-UID": str(JOB_UID),
        "KCS-Pod-UID": str(POD_UID),
    }
    forbidden_app = FastAPI()
    forbidden_app.include_router(
        create_jobs_router(provider, "token", caller_roles=frozenset({"v2-reader"}))
    )
    forbidden = TestClient(forbidden_app).post(
        "/api/v2/jobs/job-1/agent/credential-grants", headers=base_headers, content=b"short"
    )
    assert forbidden.status_code == 403 and forbidden.json()["error"]["code"] == "FORBIDDEN"

    capped_app = FastAPI()
    capped_app.include_router(create_jobs_router(provider, "token"))
    capped = TestClient(capped_app).post(
        "/api/v2/jobs/job-1/agent/credential-grants",
        headers=base_headers,
        content=b"x" * 65537,
    )
    assert capped.status_code == 413 and capped.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
