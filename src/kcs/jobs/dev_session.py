"""Durable M2 dev-session lifecycle over one exact Native Job binding."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from .errors import (
    DependencyUnavailableError,
    DevSessionCredentialError,
    DevSessionExpiredError,
    DevSessionIdentityConflictError,
    DevSessionRelayDownError,
    DevSessionRevokedError,
    JobNotFoundError,
    StaleBindingError,
    StateConflictError,
)
from .native_contracts import (
    DevSessionCreateRequest,
    DevSessionRenewRequest,
    DevSessionSnapshot,
    NativeJobBindingSnapshot,
)
from .renderer import dev_session_secret_name


@dataclass(frozen=True, slots=True)
class DevSessionMutation:
    snapshot: DevSessionSnapshot
    credential: str | None
    created: bool


@dataclass(frozen=True, slots=True)
class DevSessionRelayTarget:
    host: str
    port: int
    path: str


class DevSessionService:
    """Own non-secret session records and one optional projected credential slot."""

    def __init__(
        self,
        store: Any,
        kube: Any,
        *,
        openvscode_image_ref: str | None,
        binding_resolver: Callable[[str], NativeJobBindingSnapshot],
        clock: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], None] | None = None,
        monotonic: Callable[[], float] | None = None,
        projection_wait_seconds: float = 90.0,
        projection_poll_seconds: float = 1.0,
    ) -> None:
        if projection_wait_seconds <= 0:
            raise ValueError("dev-session projection wait must be positive")
        if projection_poll_seconds <= 0:
            raise ValueError("dev-session projection poll must be positive")
        self._store = store
        self._kube = kube
        self._image_ref = openvscode_image_ref
        self._binding_resolver = binding_resolver
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sleeper = sleeper or time.sleep
        self._monotonic = monotonic or time.monotonic
        self._projection_wait_seconds = projection_wait_seconds
        self._projection_poll_seconds = projection_poll_seconds

    def create(
        self,
        job_ref: str,
        request: DevSessionCreateRequest,
        binding: NativeJobBindingSnapshot,
    ) -> DevSessionMutation:
        self._require_enabled()
        spec = request.root["spec"]
        generation = _binding_generation(binding)
        if (
            str(binding.job_uid) != str(spec["jobUid"])
            or str(binding.pod_uid) != str(spec["podUid"])
            or binding.subject_ref != str(spec["subjectRef"])
            or generation != int(spec["generation"])
        ):
            raise StaleBindingError()
        for retained in self._store.list_runtime("dev-session", job_ref):
            values = dict(retained.values)
            if (
                retained.identity != request.root["devSessionRef"]
                and values.get("state") in {"opening", "ready"}
                and _parse_time(values.get("expiresAt")) > self._now()
            ):
                raise StateConflictError("The Job already has an active dev session")

        now = self._now()
        expires = now + timedelta(seconds=int(spec["ttlSeconds"]))
        values = {
            "identityDigest": str(request.root["requestDigest"]),
            "requestDigest": str(request.root["requestDigest"]),
            "tenantRef": str(spec["tenantRef"]),
            "principalRef": str(spec["principalRef"]),
            "conversationRef": str(spec["conversationRef"]),
            "attemptRef": str(spec["attemptRef"]),
            "subjectRef": str(spec["subjectRef"]),
            "jobUid": str(spec["jobUid"]),
            "podUid": str(spec["podUid"]),
            "generation": str(spec["generation"]),
            "state": "opening",
            "createdAt": now.isoformat(),
            "expiresAt": expires.isoformat(),
            "revokedAt": "",
            "observedAt": now.isoformat(),
        }
        record, created = self._store.reserve_runtime(
            "dev-session", str(request.root["devSessionRef"]), job_ref, values
        )
        retained = dict(record.values)
        if retained.get("identityDigest") != request.root["requestDigest"]:
            raise DevSessionIdentityConflictError()
        if not created:
            self._raise_terminal(retained)
            credential = self._secret_credential(job_ref)
            if credential is None:
                raise DevSessionRelayDownError()
            return DevSessionMutation(self._snapshot(record), credential, False)

        credential = secrets.token_urlsafe(32)
        values["credentialSha256"] = hashlib.sha256(credential.encode()).hexdigest()
        try:
            self._kube.upsert_secret(
                dev_session_secret_name(job_ref),
                self._secret_body(
                    job_ref,
                    binding,
                    str(request.root["devSessionRef"]),
                    credential,
                    expires,
                ),
            )
            record = self._store.update_runtime(
                "dev-session", job_ref, str(request.root["devSessionRef"]), values
            )
        except Exception:
            values.update(state="lost", observedAt=self._now().isoformat())
            try:
                self._store.update_runtime(
                    "dev-session", job_ref, str(request.root["devSessionRef"]), values
                )
            except Exception:
                pass
            raise
        return DevSessionMutation(self._snapshot(record), credential, True)

    def inspect(
        self, job_ref: str, dev_session_ref: str, credential: str
    ) -> DevSessionSnapshot:
        record = self._access(job_ref, dev_session_ref, credential)
        return self._snapshot(record)

    def renew(
        self,
        job_ref: str,
        dev_session_ref: str,
        credential: str,
        request: DevSessionRenewRequest,
    ) -> DevSessionMutation:
        record = self._access(job_ref, dev_session_ref, credential)
        values = dict(record.values)
        renew_ref = str(request.root["renewRef"])
        renew_digest = str(request.root["requestDigest"])
        pending_ref = values.get("pendingRenewRef")
        if pending_ref:
            if pending_ref != renew_ref or values.get("pendingRenewDigest") != renew_digest:
                raise DevSessionIdentityConflictError()
            rotated = self._pending_credential(job_ref, values)
            return self._complete_renewal(
                record,
                values,
                dev_session_ref=dev_session_ref,
                rotated=rotated,
            )
        retained_ref = values.get("renewRef")
        if retained_ref == renew_ref:
            if values.get("renewDigest") != renew_digest:
                raise DevSessionIdentityConflictError()
            raw = self._secret_credential(job_ref)
            if raw is None:
                raise DevSessionRelayDownError()
            return DevSessionMutation(self._snapshot(record), raw, False)
        if retained_ref and retained_ref != renew_ref:
            # The latest renewal is authoritative; a distinct new renewal is allowed.
            pass
        now = self._now()
        expires = now + timedelta(seconds=int(request.root["spec"]["ttlSeconds"]))
        rotated = secrets.token_urlsafe(32)
        rotated_digest = hashlib.sha256(rotated.encode()).hexdigest()
        binding = self._native_binding(job_ref)
        self._kube.upsert_secret(
            dev_session_secret_name(job_ref),
            self._secret_body(job_ref, binding, dev_session_ref, rotated, expires),
        )
        # Keep the old credential authoritative until the relay proves that
        # kubelet projected the new bytes.  The pending identity makes an
        # unknown-outcome retry recoverable without storing secret bytes.
        values.update(
            pendingRenewRef=renew_ref,
            pendingRenewDigest=renew_digest,
            pendingCredentialSha256=rotated_digest,
            pendingExpiresAt=expires.isoformat(),
            observedAt=now.isoformat(),
            state="opening",
        )
        record = self._store.update_runtime(
            "dev-session", job_ref, dev_session_ref, values
        )
        return self._complete_renewal(
            record,
            values,
            dev_session_ref=dev_session_ref,
            rotated=rotated,
        )

    def _complete_renewal(
        self,
        record: Any,
        values: dict[str, str],
        *,
        dev_session_ref: str,
        rotated: str,
    ) -> DevSessionMutation:
        if not self._wait_for_projected_credential(
            record.job_ref, values["podUid"], rotated
        ):
            raise DevSessionRelayDownError(
                "The rotated dev-session credential was not projected before the deadline"
            )
        values.update(
            renewRef=values["pendingRenewRef"],
            renewDigest=values["pendingRenewDigest"],
            credentialSha256=values["pendingCredentialSha256"],
            expiresAt=values["pendingExpiresAt"],
            observedAt=self._now().isoformat(),
            state="ready",
        )
        for name in (
            "pendingRenewRef",
            "pendingRenewDigest",
            "pendingCredentialSha256",
            "pendingExpiresAt",
        ):
            values.pop(name, None)
        committed = self._store.update_runtime(
            "dev-session", record.job_ref, dev_session_ref, values
        )
        return DevSessionMutation(self._snapshot(committed), rotated, True)

    def _pending_credential(self, job_ref: str, values: Mapping[str, str]) -> str:
        raw = self._secret_credential(job_ref)
        if raw is None:
            raise DevSessionRelayDownError()
        expected = values.get("pendingCredentialSha256", "")
        actual = hashlib.sha256(raw.encode()).hexdigest()
        if not expected or not hmac.compare_digest(expected, actual):
            raise DevSessionRelayDownError(
                "The pending dev-session credential does not match its projection"
            )
        return raw

    def _wait_for_projected_credential(
        self, job_ref: str, pod_uid: str, credential: str
    ) -> bool:
        deadline = self._monotonic() + self._projection_wait_seconds
        while True:
            try:
                host, port = self._kube.pod_relay_endpoint(job_ref, pod_uid)
                connection = http.client.HTTPConnection(host, port, timeout=3)
                try:
                    connection.request(
                        "GET",
                        "/",
                        headers={"X-RC-Dev-Session-Credential": credential},
                    )
                    response = connection.getresponse()
                    response.read(4096)
                    if 200 <= response.status < 400:
                        return True
                finally:
                    connection.close()
            except (OSError, http.client.HTTPException):
                pass
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return False
            self._sleeper(min(self._projection_poll_seconds, remaining))

    def revoke(
        self, job_ref: str, dev_session_ref: str, credential: str
    ) -> DevSessionSnapshot:
        record = self._access(job_ref, dev_session_ref, credential)
        record = self._revoke_record(record, "explicit_revoke")
        return self._snapshot(record)

    def revoke_for_job(self, job_ref: str, reason: str) -> int:
        """Close every live IDE binding before cancel/finalize/delete advances.

        This path deliberately needs no browser credential: it is called only
        from the already authenticated Job lifecycle.  It is idempotent so
        recovery can repeat the same close without reopening a session.
        """

        changed = 0
        for record in self._store.list_runtime("dev-session", job_ref):
            if dict(record.values).get("state") in {"opening", "ready"}:
                self._revoke_record(record, reason)
                changed += 1
        return changed

    def relay_target(
        self, job_ref: str, dev_session_ref: str, credential: str, path: str
    ) -> DevSessionRelayTarget:
        record = self._access(job_ref, dev_session_ref, credential)
        values = dict(record.values)
        try:
            host, port = self._kube.pod_relay_endpoint(job_ref, values["podUid"])
        except Exception as error:
            raise DevSessionRelayDownError() from error
        return DevSessionRelayTarget(host=host, port=port, path=path)

    def observe_relay_ready(
        self, job_ref: str, dev_session_ref: str, credential: str
    ) -> DevSessionSnapshot:
        """Publish ``ready`` only after the projected credential worked end to end."""

        record = self._access(job_ref, dev_session_ref, credential)
        values = dict(record.values)
        if values.get("state") == "opening":
            values.update(state="ready", observedAt=self._now().isoformat())
            record = self._store.update_runtime(
                "dev-session", job_ref, dev_session_ref, values
            )
        return self._snapshot(record)

    def reconcile(self) -> int:
        changed = 0
        now = self._now()
        for record in self._store.list_runtime("dev-session"):
            values = dict(record.values)
            if values.get("state") in {"opening", "ready"} and _parse_time(
                values.get("expiresAt")
            ) <= now:
                values.update(state="expired", observedAt=now.isoformat())
                self._store.update_runtime(
                    "dev-session", record.job_ref, record.identity, values
                )
                changed += 1
        return changed

    def _access(self, job_ref: str, identity: str, credential: str) -> Any:
        record = self._store.read_runtime("dev-session", job_ref, identity)
        if record is None:
            raise JobNotFoundError()
        values = dict(record.values)
        self._raise_terminal(values)
        supplied = hashlib.sha256(credential.encode()).hexdigest()
        if not values.get("credentialSha256") or not hmac.compare_digest(
            values["credentialSha256"], supplied
        ):
            raise DevSessionCredentialError()
        binding = self._native_binding(job_ref)
        if (
            str(binding.job_uid) != values.get("jobUid")
            or str(binding.pod_uid) != values.get("podUid")
            or _binding_generation(binding) != int(values.get("generation", "0"))
        ):
            raise StaleBindingError()
        return record

    def _snapshot(self, record: Any) -> DevSessionSnapshot:
        values = dict(record.values)
        now = self._now()
        state = values.get("state", "lost")
        if state in {"opening", "ready"} and _parse_time(values.get("expiresAt")) <= now:
            state = "expired"
        image_id: str | None = None
        relay_ready = False
        if state in {"opening", "ready"}:
            try:
                image_id, ide_ready = self._kube.pod_container_image_id(
                    record.job_ref, values["podUid"], "openvscode"
                )
                _relay_id, relay_ready = self._kube.pod_container_image_id(
                    record.job_ref, values["podUid"], "relay"
                )
                if not (ide_ready and relay_ready):
                    state = "opening"
                elif state != "ready":
                    # Container readiness does not prove that kubelet has projected
                    # the newly created or rotated credential.  The relay route
                    # promotes this record only after an authenticated request
                    # reaches loopback OpenVSCode.
                    state = "opening"
            except Exception:
                state = "lost"
        payload: dict[str, Any] = {
            "devSessionRef": record.identity,
            "requestDigest": values["requestDigest"],
            "tenantRef": values["tenantRef"],
            "principalRef": values["principalRef"],
            "conversationRef": values["conversationRef"],
            "attemptRef": values["attemptRef"],
            "subjectRef": values["subjectRef"],
            "jobRef": record.job_ref,
            "jobUid": values["jobUid"],
            "podUid": values["podUid"],
            "generation": int(values["generation"]),
            "scope": "workspace-ide",
            "state": state,
            "relayKind": "openvscode",
            "relayPath": (
                f"/api/v2/jobs/{quote(record.job_ref, safe='')}/dev-sessions/"
                f"{quote(record.identity, safe='')}/relay"
            ),
            "writable": True,
            "effectiveUid": 10002,
            "effectiveGid": 10001,
            "openVscodeImageRef": self._require_enabled(),
            "openVscodeImageId": image_id,
            "activeConnections": 0,
            "maximumConnections": 4,
            "createdAt": values["createdAt"],
            "expiresAt": values["expiresAt"],
            "revokedAt": values.get("revokedAt") or None,
            "observedAt": now.isoformat(),
        }
        return DevSessionSnapshot.model_validate(payload)

    def _secret_body(
        self,
        job_ref: str,
        binding: NativeJobBindingSnapshot,
        session_ref: str,
        credential: str,
        expires: datetime,
    ) -> dict[str, object]:
        return {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": dev_session_secret_name(job_ref),
                "labels": {"researchcosmos.io/managed-by": "v2-attempt-runtime"},
                "ownerReferences": [
                    {
                        "apiVersion": "batch/v1",
                        "kind": "Job",
                        "name": job_ref,
                        "uid": str(binding.job_uid),
                        "controller": False,
                        "blockOwnerDeletion": False,
                    }
                ],
                "annotations": {
                    "researchcosmos.io/job-uid": str(binding.job_uid),
                    "researchcosmos.io/pod-uid": str(binding.pod_uid),
                    "researchcosmos.io/dev-session-hash": hashlib.sha256(
                        session_ref.encode()
                    ).hexdigest()[:16],
                },
            },
            "type": "Opaque",
            "data": {
                "credential": base64.b64encode(credential.encode()).decode("ascii"),
                "expires-at": base64.b64encode(
                    str(int(expires.timestamp())).encode("ascii")
                ).decode("ascii"),
            },
        }

    def _secret_credential(self, job_ref: str) -> str | None:
        secret = self._kube.read_secret(dev_session_secret_name(job_ref))
        data = _mapping(_field(secret, "data", {})) if secret is not None else {}
        raw = data.get("credential")
        if not isinstance(raw, str):
            return None
        try:
            return base64.b64decode(raw, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

    def _revoke_record(self, record: Any, reason: str) -> Any:
        values = dict(record.values)
        if values.get("state") == "revoked":
            return record
        now = self._now()
        values.update(
            state="revoked",
            revokedAt=now.isoformat(),
            observedAt=now.isoformat(),
            revokeReason=reason,
        )
        secret_name = dev_session_secret_name(record.job_ref)
        if self._kube.read_secret(secret_name) is not None:
            self._kube.upsert_secret(
                secret_name,
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": secret_name},
                    "data": {"revoked": ""},
                },
            )
        return self._store.update_runtime(
            "dev-session", record.job_ref, record.identity, values
        )

    def _native_binding(self, job_ref: str) -> NativeJobBindingSnapshot:
        binding = self._binding_resolver(job_ref)
        if not isinstance(binding, NativeJobBindingSnapshot):
            raise StateConflictError("dev sessions require a Native Job")
        return binding

    def _require_enabled(self) -> str:
        if self._image_ref is None:
            raise DependencyUnavailableError("native dev-session images are not configured")
        return self._image_ref

    def _raise_terminal(self, values: Mapping[str, str]) -> None:
        if values.get("state") == "revoked":
            raise DevSessionRevokedError()
        if values.get("state") == "expired" or _parse_time(values.get("expiresAt")) <= self._now():
            raise DevSessionExpiredError()
        if values.get("state") == "lost":
            raise DevSessionRelayDownError()

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise RuntimeError("dev-session clock must be timezone-aware")
        return value.astimezone(UTC)


def _binding_generation(binding: NativeJobBindingSnapshot) -> int:
    generation = binding.root.get("latestRunnerGeneration")
    if not isinstance(generation, Mapping):
        raise StateConflictError("The Native runner has no active generation")
    return int(generation["generation"])


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=UTC)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(UTC)


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


__all__ = ["DevSessionMutation", "DevSessionRelayTarget", "DevSessionService"]
