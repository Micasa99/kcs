"""One simulated, no-network vertical Journey for Task 5."""
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from kcs.jobs.canonical import canonical_digest
from kcs.jobs.contracts import (
    AgentStartRequest,
    CredentialGrantMetadata,
    FinalizeJobRequest,
    FinalizeSpec,
)
from kcs.jobs.provider import V2JobProvider
from kcs.jobs.store import V2JobStore
from kcs.jobs.transport import AgentRpcResponse

JOB_UID = UUID("00000000-0000-4000-8000-000000000001")
POD_UID = UUID("00000000-0000-4000-8000-000000000002")
DIGEST = "a" * 64


class _ConflictError(Exception):
    status = 409


class _Kube:
    namespace = "researchcosmos-v2"

    def __init__(self) -> None:
        self.config_maps: dict[str, dict[str, object]] = {}
        self.secrets: dict[str, dict[str, object]] = {}
        self.audit_bytes: list[bytes] = []
        self.secret_deletes = 0

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
        self.secrets[value["metadata"]["name"]] = value
        self.audit_bytes.append(b"secret-created")
        return value

    def delete_secret(self, name: str) -> bool:
        self.secret_deletes += 1
        self.secrets.pop(name, None)
        self.audit_bytes.append(b"secret-deleted")
        return True

    def read_job(self, job_ref: str) -> object:
        return {"metadata": {"uid": str(JOB_UID), "resourceVersion": "9"}, "status": {}}

    def list_job_pods(self, job_ref: str, job_uid: str | None = None) -> list[object]:
        return [
            {
                "metadata": {"uid": str(POD_UID)},
                "status": {
                    "containerStatuses": [
                        {"name": "agent", "ready": True, "restartCount": 0},
                        {"name": "workspace", "ready": True, "restartCount": 0},
                    ]
                },
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
    def __init__(self) -> None:
        self.starts = 0
        self.stops: list[str] = []

    def agent_rpc(self, binding: object, request: object) -> AgentRpcResponse:
        self.starts += 1
        value = request
        return AgentRpcResponse(
            1,
            value["generation"],
            value["agentRunRef"],
            value["launchBundleDigest"],
            "exited",
            True,
            7,
            0,
        )

    def stop_supervisor(self, binding: object, container: str) -> None:
        self.stops.append(container)


def test_grant_start_replay_and_finalize_preserve_job_reality() -> None:
    kube = _Kube()
    store = V2JobStore(kube, clock=lambda: datetime(2026, 8, 2, tzinfo=UTC))
    store.reserve_create(
        "request-1",
        DIGEST,
        "job-1",
        {"subjectRef": "s", "runtimePlanDigest": DIGEST, "workspace": {}},
    )
    store.mark_created("request-1", str(JOB_UID))
    store.bind_first_pod("request-1", str(POD_UID))
    transport = _Transport()
    provider = V2JobProvider(kube, store, _Renderer(), transport=transport)
    credential = b"synthetic-short-credential"
    metadata_payload = {
        "agentRunRef": "run-1",
        "generation": 1,
        "launchBundleDigest": DIGEST,
        "audience": "agent",
        "credentialSha256": hashlib.sha256(credential).hexdigest(),
        "ttlSeconds": 300,
        "jobUid": str(JOB_UID),
        "podUid": str(POD_UID),
    }
    metadata = CredentialGrantMetadata(
        credential_grant_ref="grant-1",
        credential_sha256=metadata_payload["credentialSha256"],
        grant_metadata_digest=canonical_digest(metadata_payload),
        agent_run_ref="run-1",
        generation=1,
        launch_bundle_digest=DIGEST,
        audience="agent",
        ttl_seconds=300,
        job_uid=JOB_UID,
        pod_uid=POD_UID,
    )
    granted = provider.grant_credential("job-1", metadata, credential)
    assert provider.grant_credential("job-1", metadata, credential) == granted
    start = AgentStartRequest(
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
    assert provider.start_agent("job-1", start).generation == 1
    assert provider.start_agent("job-1", start).replayed is True
    assert transport.starts == 1 and kube.secret_deletes == 1
    finalize = FinalizeJobRequest(
        finalize_ref="finalize-1",
        request_digest=canonical_digest(
            FinalizeSpec(operation_refs=[], transfer_refs=[], drain_timeout_seconds=1)
        ),
        spec=FinalizeSpec(operation_refs=[], transfer_refs=[], drain_timeout_seconds=1),
    )
    snapshot = provider.finalize("job-1", finalize)
    assert snapshot.job_uid == JOB_UID and snapshot.pod_uid == POD_UID
    assert transport.stops == ["agent", "workspace"]
    assert credential not in b"".join(kube.audit_bytes)
    assert credential not in json.dumps(kube.config_maps).encode()
