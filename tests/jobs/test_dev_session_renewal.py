from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from kcs.jobs.canonical import canonical_digest
from kcs.jobs.dev_session import DevSessionService
from kcs.jobs.native_contracts import DevSessionRenewRequest, NativeJobBindingSnapshot
from kcs.jobs.store import RuntimeRecord


def test_renew_rotates_browser_credential_without_waiting_for_pod_projection() -> None:
    now = datetime(2026, 8, 10, 10, 0, tzinfo=UTC)
    old_credential = "old-" + "a" * 40
    values = {
        "identityDigest": "1" * 64,
        "requestDigest": "1" * 64,
        "tenantRef": "tenant-1",
        "principalRef": "principal-1",
        "conversationRef": "conversation-1",
        "attemptRef": "attempt-1",
        "subjectRef": "subject-1",
        "jobUid": "11111111-1111-4111-8111-111111111111",
        "podUid": "22222222-2222-4222-8222-222222222222",
        "generation": "1",
        "state": "ready",
        "createdAt": now.isoformat(),
        "expiresAt": (now + timedelta(minutes=5)).isoformat(),
        "revokedAt": "",
        "observedAt": now.isoformat(),
        "credentialSha256": hashlib.sha256(old_credential.encode()).hexdigest(),
    }
    record = RuntimeRecord(
        kind="dev-session",
        identity="dev-session-1",
        job_ref="job-1",
        values=values,
    )

    class Store:
        current = record

        def read_runtime(self, kind: str, job_ref: str, identity: str):
            assert (kind, job_ref, identity) == (
                "dev-session",
                "job-1",
                "dev-session-1",
            )
            return self.current

        def update_runtime(self, kind: str, job_ref: str, identity: str, updated):
            assert (kind, job_ref, identity) == (
                "dev-session",
                "job-1",
                "dev-session-1",
            )
            self.current = replace(self.current, values=dict(updated))
            return self.current

    store = Store()

    class Kube:
        secret = None

        def upsert_secret(self, name: str, body):
            self.secret = body

        def read_secret(self, name: str):
            return self.secret

        def pod_relay_endpoint(self, job_ref: str, pod_uid: str):
            assert (job_ref, pod_uid) == ("job-1", values["podUid"])
            return "127.0.0.1", 19090

        def pod_container_image_id(self, job_ref: str, pod_uid: str, container: str):
            return f"image://{container}", True

    kube = Kube()
    binding = NativeJobBindingSnapshot.model_construct(
        root={
            "jobRef": "job-1",
            "jobUid": values["jobUid"],
            "podUid": values["podUid"],
            "subjectRef": values["subjectRef"],
            "bindingState": "ready",
            "latestRunnerGeneration": {"generation": 1},
        }
    )
    service = DevSessionService(
        store,
        kube,
        openvscode_image_ref=f"registry.example/openvscode@sha256:{'3' * 64}",
        binding_resolver=lambda _job_ref: binding,
        clock=lambda: now,
    )
    spec = {"ttlSeconds": 300}
    request = DevSessionRenewRequest.model_validate(
        {
            "renewRef": "renew-1",
            "requestDigest": canonical_digest(spec),
            "spec": spec,
        }
    )

    result = service.renew(
        "job-1", "dev-session-1", old_credential, request
    )

    assert result.created is True
    assert result.credential is not None
    assert store.current.values["credentialSha256"] == hashlib.sha256(
        result.credential.encode()
    ).hexdigest()
    assert store.current.values["renewRef"] == "renew-1"
    assert result.snapshot.root["state"] == "ready"
    assert kube.secret["metadata"]["name"].startswith("kcs-v2-dev-browser-")
