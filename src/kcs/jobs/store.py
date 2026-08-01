"""Durable create reservation and deletion tombstones backed by ConfigMaps."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from .errors import (
    DependencyUnavailableError,
    IdentityDigestConflict,
    JobNotFoundError,
    ReplacementPodError,
    StateConflictError,
    TombstonedError,
)
from .kube import V2KubeAdapter

MANAGED_BY_LABEL = "researchcosmos.io/managed-by"
MANAGED_BY_VALUE = "v2-attempt-runtime"
RECORD_KIND_LABEL = "researchcosmos.io/record-kind"
RECORD_KIND_VALUE = "job-create"
PROVIDER_HASH_LABEL = "researchcosmos.io/provider-request-hash"
JOB_REF_HASH_LABEL = "researchcosmos.io/job-ref-hash"

_RECORD_VERSION = "1"
_UPDATE_ATTEMPTS = 4
_TERMINAL_STATES = frozenset(("succeeded", "failed", "canceled", "indeterminate"))
_CLEANUP_STATES = frozenset(("not_required", "pending", "complete", "failed", "indeterminate"))


@dataclass(frozen=True, slots=True)
class CreateRecord:
    """The restart-readable provider identity and binding record."""

    provider_request_id: str
    spec_digest: str
    job_ref: str
    state: str
    created_at: str
    updated_at: str
    spec_payload: Mapping[str, Any] | None = None
    job_uid: str | None = None
    pod_uid: str | None = None
    final_state: str | None = None
    delete_ref: str | None = None
    delete_request_digest: str | None = None
    cleanup_state: str | None = None
    cleanup_reason: str | None = None
    gpu_release_state: str | None = None
    gpu_release_reason: str | None = None
    indeterminate_reason: str | None = None
    deleted_at: str | None = None
    expires_at: str | None = None
    resource_version: str | None = None

    @property
    def is_tombstone(self) -> bool:
        return self.state == "deleted"

    def tombstone_payload(self) -> dict[str, object]:
        """Return the frozen public tombstone shape for a deleted record."""
        required = {
            "job_uid": self.job_uid,
            "final_state": self.final_state,
            "delete_ref": self.delete_ref,
            "delete_request_digest": self.delete_request_digest,
            "deleted_at": self.deleted_at,
            "expires_at": self.expires_at,
            "cleanup_state": self.cleanup_state,
            "gpu_release_state": self.gpu_release_state,
        }
        if not self.is_tombstone or any(value is None for value in required.values()):
            raise ValueError("record is not a complete deletion tombstone")
        observed_at = self.deleted_at
        return {
            "providerRequestId": self.provider_request_id,
            "specDigest": self.spec_digest,
            "jobRef": self.job_ref,
            "jobUid": self.job_uid,
            "podUid": self.pod_uid,
            "state": "deleted",
            "finalState": self.final_state,
            "deleteRef": self.delete_ref,
            "deleteRequestDigest": self.delete_request_digest,
            "createdAt": self.created_at,
            "cleanup": {
                "state": self.cleanup_state,
                "reason": self.cleanup_reason,
                "observedAt": observed_at,
            },
            "gpuRelease": {
                "state": self.gpu_release_state,
                "reason": self.gpu_release_reason,
                "observedAt": observed_at,
            },
            "credentialObservations": [],
            "transferObservations": [],
            "deletedAt": self.deleted_at,
            "expiresAt": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class CreateReservation:
    """The reservation plus whether this call created the authoritative record."""

    record: CreateRecord
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


class V2JobStore:
    """ConfigMap store for reservation-before-create and retained tombstones."""

    def __init__(
        self,
        kube: V2KubeAdapter,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._kube = kube
        self._clock = clock or (lambda: datetime.now(UTC))

    def reserve_create(
        self,
        provider_request_id: str,
        spec_digest: str,
        job_ref: str,
        spec_payload: Mapping[str, Any] | None = None,
        *,
        spec_json: str | None = None,
    ) -> CreateReservation:
        """Atomically reserve an idempotency key before creating the Kubernetes Job.

        ``spec_payload`` must be the already validated, non-secret OpenAPI ``spec``.  It
        is retained so a process restart can render or inspect the same request without a
        second database.  Authorization and credential bytes are never accepted here.
        """
        stored_spec = _normalize_spec(spec_payload, spec_json)
        now = _timestamp(self._clock())
        record = CreateRecord(
            provider_request_id=provider_request_id,
            spec_digest=spec_digest,
            job_ref=job_ref,
            state="reserved",
            created_at=now,
            updated_at=now,
            spec_payload=stored_spec,
        )
        try:
            created = self._kube.create_config_map(_config_map_body(record))
        except Exception as exc:
            if _status(exc) != 409:
                raise
            existing = self.read_create(provider_request_id)
            if existing is None:
                raise DependencyUnavailableError(
                    "Kubernetes reported a reservation conflict but no record was readable"
                ) from exc
            if existing.spec_digest != spec_digest:
                raise IdentityDigestConflict() from exc
            if existing.is_tombstone:
                raise TombstonedError(existing.tombstone_payload()) from exc
            return CreateReservation(record=existing, created=False)
        return CreateReservation(record=_record_from_config_map(created), created=True)

    def read_create(self, provider_request_id: str) -> CreateRecord | None:
        config_map = self._kube.read_config_map(_record_name(provider_request_id))
        if config_map is None:
            return None
        record = _record_from_config_map(config_map)
        if record.provider_request_id != provider_request_id:
            raise DependencyUnavailableError("ConfigMap reservation hash collision")
        return record

    def read_by_job_ref(self, job_ref: str) -> CreateRecord | None:
        selector = (
            f"{RECORD_KIND_LABEL}={RECORD_KIND_VALUE},{JOB_REF_HASH_LABEL}={_short_hash(job_ref)}"
        )
        matches = [
            _record_from_config_map(item)
            for item in self._kube.list_config_maps(selector)
            if _data(item).get("jobRef") == job_ref
        ]
        if not matches:
            return None
        if len(matches) != 1:
            raise DependencyUnavailableError("multiple reservation records have the same job ref")
        return matches[0]

    def mark_created(self, provider_request_id: str, job_uid: str) -> CreateRecord:
        """Bind the reservation to the immutable Kubernetes Job UID."""

        def mutate(current: CreateRecord) -> CreateRecord:
            _require_live(current)
            if current.job_uid is not None:
                if current.job_uid != job_uid:
                    raise StateConflictError("The provider identity is bound to another Job UID")
                return current
            if current.state == "indeterminate":
                raise StateConflictError("An indeterminate binding cannot acquire a Job UID")
            return replace(
                current,
                job_uid=job_uid,
                state="created",
                updated_at=_timestamp(self._clock()),
            )

        return self._update(provider_request_id, mutate)

    def bind_first_pod(self, provider_request_id: str, pod_uid: str) -> CreateRecord:
        """Persist the first Pod UID and reject replacement Pod rebinding."""

        def mutate(current: CreateRecord) -> CreateRecord:
            _require_live(current)
            if current.job_uid is None:
                raise StateConflictError("A Pod cannot be bound before the Job UID")
            if current.pod_uid is not None:
                if current.pod_uid != pod_uid:
                    raise ReplacementPodError()
                return current
            if current.state == "indeterminate":
                raise ReplacementPodError()
            return replace(
                current,
                pod_uid=pod_uid,
                state="bound",
                updated_at=_timestamp(self._clock()),
            )

        return self._update(provider_request_id, mutate)

    def mark_indeterminate(self, provider_request_id: str, reason: str) -> CreateRecord:
        """Durably prevent an ambiguous Job/Pod identity from being rebound."""
        if not reason:
            raise ValueError("an indeterminate binding requires a reason")

        def mutate(current: CreateRecord) -> CreateRecord:
            _require_live(current)
            if current.state == "indeterminate":
                return current
            return replace(
                current,
                state="indeterminate",
                indeterminate_reason=reason,
                updated_at=_timestamp(self._clock()),
            )

        return self._update(provider_request_id, mutate)

    def mark_deleted(
        self,
        provider_request_id: str,
        **values: object,
    ) -> CreateRecord:
        """Replace a live binding with its ownerless retained deletion tombstone."""
        deleted_at = _datetime_or_string(values.pop("deleted_at", None), "deleted_at")
        expires_at = _datetime_or_string(values.pop("expires_at", None), "expires_at")
        delete_ref = _string(values.pop("delete_ref", None), "delete_ref")
        delete_request_digest = _string(
            values.pop("delete_request_digest", None), "delete_request_digest"
        )
        final_state = _string(values.pop("final_state", None), "final_state")
        cleanup_state = _string(values.pop("cleanup_state", "complete"), "cleanup_state")
        cleanup_reason = _optional_string(values.pop("cleanup_reason", None), "cleanup_reason")
        gpu_release_state = _string(
            values.pop("gpu_release_state", "complete"), "gpu_release_state"
        )
        gpu_release_reason = _optional_string(
            values.pop("gpu_release_reason", None), "gpu_release_reason"
        )
        if values:
            raise ValueError(f"unknown deletion fields: {', '.join(sorted(values))}")
        if final_state not in _TERMINAL_STATES:
            raise ValueError("final_state is not a provider terminal state")
        if cleanup_state not in _CLEANUP_STATES or gpu_release_state not in _CLEANUP_STATES:
            raise ValueError("cleanup and GPU release must use a cleanup state")
        deleted = _timestamp(deleted_at)
        expires = _timestamp(expires_at)

        def mutate(current: CreateRecord) -> CreateRecord:
            if current.is_tombstone:
                if (
                    current.delete_ref != delete_ref
                    or current.delete_request_digest != delete_request_digest
                ):
                    raise IdentityDigestConflict()
                if (
                    current.final_state != final_state
                    or current.deleted_at != deleted
                    or current.expires_at != expires
                ):
                    raise StateConflictError(
                        "A retained tombstone cannot change terminal state or retention times"
                    )
                if (
                    current.cleanup_state == cleanup_state
                    and current.cleanup_reason == cleanup_reason
                    and current.gpu_release_state == gpu_release_state
                    and current.gpu_release_reason == gpu_release_reason
                ):
                    return current
                return replace(
                    current,
                    cleanup_state=cleanup_state,
                    cleanup_reason=cleanup_reason,
                    gpu_release_state=gpu_release_state,
                    gpu_release_reason=gpu_release_reason,
                    updated_at=_timestamp(self._clock()),
                )
            if current.job_uid is None:
                raise StateConflictError("A reservation without a Job UID cannot be deleted")
            return replace(
                current,
                state="deleted",
                final_state=final_state,
                delete_ref=delete_ref,
                delete_request_digest=delete_request_digest,
                cleanup_state=cleanup_state,
                cleanup_reason=cleanup_reason,
                gpu_release_state=gpu_release_state,
                gpu_release_reason=gpu_release_reason,
                deleted_at=deleted,
                expires_at=expires,
                updated_at=deleted,
            )

        return self._update(provider_request_id, mutate)

    def list_create(self) -> list[CreateRecord]:
        selector = f"{RECORD_KIND_LABEL}={RECORD_KIND_VALUE}"
        records = [_record_from_config_map(item) for item in self._kube.list_config_maps(selector)]
        return sorted(records, key=lambda item: (item.created_at, item.job_ref))

    # Clear aliases used by some provider call sites.
    bind_job = mark_created
    bind_pod = bind_first_pod
    list_records = list_create

    def purge_expired(self, now: datetime | str) -> int:
        """Delete only tombstones whose explicit retention time has elapsed."""
        boundary = _parse_timestamp(_timestamp(now))
        deleted = 0
        for record in self.list_create():
            if (
                record.is_tombstone
                and record.expires_at is not None
                and _parse_timestamp(record.expires_at) <= boundary
                and self._kube.delete_config_map(_record_name(record.provider_request_id))
            ):
                deleted += 1
        return deleted

    def _update(
        self,
        provider_request_id: str,
        mutate: Callable[[CreateRecord], CreateRecord],
    ) -> CreateRecord:
        name = _record_name(provider_request_id)
        for _ in range(_UPDATE_ATTEMPTS):
            config_map = self._kube.read_config_map(name)
            if config_map is None:
                raise JobNotFoundError()
            current = _record_from_config_map(config_map)
            if current.provider_request_id != provider_request_id:
                raise DependencyUnavailableError("ConfigMap reservation hash collision")
            desired = mutate(current)
            if desired == current:
                return current
            try:
                written = self._kube.replace_config_map(
                    name,
                    _config_map_body(desired, resource_version=current.resource_version),
                )
            except Exception as exc:
                if _status(exc) == 409:
                    continue
                raise
            return _record_from_config_map(written)
        raise DependencyUnavailableError("ConfigMap reservation changed concurrently")


def _require_live(record: CreateRecord) -> None:
    if record.is_tombstone:
        raise TombstonedError(record.tombstone_payload())


def _normalize_spec(
    spec_payload: Mapping[str, Any] | None,
    spec_json: str | None,
) -> Mapping[str, Any] | None:
    if spec_payload is not None and spec_json is not None:
        raise ValueError("provide spec_payload or spec_json, not both")
    value: object | None = spec_payload
    if spec_json is not None:
        try:
            value = json.loads(spec_json)
        except json.JSONDecodeError as exc:
            raise ValueError("spec_json must contain a JSON object") from exc
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("the retained spec must be a JSON object")
    # Round-tripping also proves the value is JSON serializable and detaches caller state.
    compact = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    loaded = json.loads(compact)
    return MappingProxyType(loaded)


def _record_name(provider_request_id: str) -> str:
    return f"kcs-v2-create-{_short_hash(provider_request_id, 32)}"


def _short_hash(value: str, length: int = 40) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def _config_map_body(
    record: CreateRecord,
    *,
    resource_version: str | None = None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "name": _record_name(record.provider_request_id),
        "labels": {
            MANAGED_BY_LABEL: MANAGED_BY_VALUE,
            RECORD_KIND_LABEL: RECORD_KIND_VALUE,
            PROVIDER_HASH_LABEL: _short_hash(record.provider_request_id),
            JOB_REF_HASH_LABEL: _short_hash(record.job_ref),
        },
        # The idempotency record must outlive Job garbage collection as a tombstone.
        "ownerReferences": [],
    }
    if resource_version is not None:
        metadata["resourceVersion"] = resource_version
    data = {
        "recordVersion": _RECORD_VERSION,
        "providerRequestId": record.provider_request_id,
        "specDigest": record.spec_digest,
        "jobRef": record.job_ref,
        "state": record.state,
        "createdAt": record.created_at,
        "updatedAt": record.updated_at,
    }
    optional = {
        "jobUid": record.job_uid,
        "podUid": record.pod_uid,
        "finalState": record.final_state,
        "deleteRef": record.delete_ref,
        "deleteRequestDigest": record.delete_request_digest,
        "cleanupState": record.cleanup_state,
        "cleanupReason": record.cleanup_reason,
        "gpuReleaseState": record.gpu_release_state,
        "gpuReleaseReason": record.gpu_release_reason,
        "indeterminateReason": record.indeterminate_reason,
        "deletedAt": record.deleted_at,
        "expiresAt": record.expires_at,
    }
    data.update({key: value for key, value in optional.items() if value is not None})
    if record.spec_payload is not None:
        data["specJson"] = json.dumps(
            dict(record.spec_payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata, "data": data}


def _record_from_config_map(config_map: Any) -> CreateRecord:
    data = _data(config_map)
    if data.get("recordVersion") != _RECORD_VERSION:
        raise DependencyUnavailableError("unsupported ConfigMap reservation record version")
    spec_payload: Mapping[str, Any] | None = None
    if "specJson" in data:
        try:
            decoded = json.loads(data["specJson"])
        except json.JSONDecodeError as exc:
            raise DependencyUnavailableError("retained create spec is not valid JSON") from exc
        if not isinstance(decoded, dict):
            raise DependencyUnavailableError("retained create spec is not a JSON object")
        spec_payload = MappingProxyType(decoded)
    metadata = _value(config_map, "metadata")
    return CreateRecord(
        provider_request_id=_required(data, "providerRequestId"),
        spec_digest=_required(data, "specDigest"),
        job_ref=_required(data, "jobRef"),
        state=_required(data, "state"),
        created_at=_required(data, "createdAt"),
        updated_at=_required(data, "updatedAt"),
        spec_payload=spec_payload,
        job_uid=data.get("jobUid"),
        pod_uid=data.get("podUid"),
        final_state=data.get("finalState"),
        delete_ref=data.get("deleteRef"),
        delete_request_digest=data.get("deleteRequestDigest"),
        cleanup_state=data.get("cleanupState"),
        cleanup_reason=data.get("cleanupReason"),
        gpu_release_state=data.get("gpuReleaseState"),
        gpu_release_reason=data.get("gpuReleaseReason"),
        indeterminate_reason=data.get("indeterminateReason"),
        deleted_at=data.get("deletedAt"),
        expires_at=data.get("expiresAt"),
        resource_version=_value(metadata, "resource_version")
        or _value(metadata, "resourceVersion"),
    )


def _data(config_map: Any) -> dict[str, str]:
    return dict(_value(config_map, "data") or {})


def _required(data: Mapping[str, str], key: str) -> str:
    value = data.get(key)
    if not value:
        raise DependencyUnavailableError(f"ConfigMap reservation is missing {key}")
    return value


def _value(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _status(exc: Exception) -> int | None:
    value = getattr(exc, "status", None)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _timestamp(value: datetime | str) -> str:
    if isinstance(value, str):
        parsed = _parse_timestamp(value)
    else:
        parsed = value
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    utc = parsed.astimezone(UTC)
    return utc.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _datetime_or_string(value: object, field: str) -> datetime | str:
    if not isinstance(value, (datetime, str)):
        raise ValueError(f"{field} must be an aware datetime or RFC 3339 string")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _string(value, field)


def _parse_timestamp(value: str) -> datetime:
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("timestamp must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed
