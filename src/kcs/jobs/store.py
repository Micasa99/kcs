"""Durable create reservation and deletion tombstones backed by ConfigMaps."""
# ruff: noqa: E501

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
_DELETE_PHASE_ORDER = {
    None: 0,
    "tombstone_persisted": 1,
    "credentials_destroyed": 2,
    "job_delete_requested": 3,
    "workload_absent": 4,
    "owner_records_deleted": 5,
    "complete": 6,
}


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
    native_recipe_snapshot_json: str | None = None
    job_uid: str | None = None
    pod_uid: str | None = None
    pod_incarnations_json: str | None = None
    final_state: str | None = None
    delete_ref: str | None = None
    delete_request_digest: str | None = None
    cleanup_state: str | None = None
    cleanup_reason: str | None = None
    cleanup_phase: str | None = None
    gpu_release_state: str | None = None
    gpu_release_reason: str | None = None
    credential_observations_json: str | None = None
    transfer_observations_json: str | None = None
    indeterminate_reason: str | None = None
    deleted_at: str | None = None
    expires_at: str | None = None
    resource_version: str | None = None

    @property
    def is_tombstone(self) -> bool:
        return self.state == "deleted"

    @property
    def is_deleting(self) -> bool:
        return self.state == "deleting"

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
            "credentialObservations": _observation_json(
                self.credential_observations_json, "credential observations"
            ),
            "transferObservations": _observation_json(
                self.transfer_observations_json, "transfer observations"
            ),
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


@dataclass(frozen=True, slots=True)
class RuntimeRecord:
    """A small non-secret ConfigMap record for grants, generations, or finalize."""

    kind: str
    identity: str
    job_ref: str
    values: Mapping[str, str]
    resource_version: str | None = None
    storage_name: str | None = None


@dataclass(frozen=True, slots=True)
class CatalogRecord:
    """Immutable, job-independent resolved catalog material."""

    kind: str
    identity: str
    digest: str
    payload: str
    storage_name: str | None = None


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
        self._scan_errors = 0

    def reserve_create(
        self,
        provider_request_id: str,
        spec_digest: str,
        job_ref: str,
        spec_payload: Mapping[str, Any] | None = None,
        *,
        spec_json: str | None = None,
        native_recipe_snapshot: Mapping[str, Any] | None = None,
    ) -> CreateReservation:
        """Atomically reserve an idempotency key before creating the Kubernetes Job.

        ``spec_payload`` must be the already validated, non-secret OpenAPI ``spec``.  It
        is retained so a process restart can render or inspect the same request without a
        second database.  Authorization and credential bytes are never accepted here.
        """
        stored_spec = _normalize_spec(spec_payload, spec_json)
        stored_recipe = _normalize_snapshot(native_recipe_snapshot)
        now = _timestamp(self._clock())
        record = CreateRecord(
            provider_request_id=provider_request_id,
            spec_digest=spec_digest,
            job_ref=job_ref,
            state="reserved",
            created_at=now,
            updated_at=now,
            spec_payload=stored_spec,
            native_recipe_snapshot_json=stored_recipe,
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

    def bind_pod_incarnation(
        self,
        provider_request_id: str,
        pod_uid: str,
        incarnation_json: str | None = None,
    ) -> CreateRecord:
        """Append and select one exact Pod UID under the retained Job UID.

        Kubernetes may replace a failed/deleted Job Pod without changing the
        Job or Research Attempt.  Selection is made by provider reconciliation;
        this store only makes the resulting incarnation lineage durable and
        replay-idempotent.
        """

        def mutate(current: CreateRecord) -> CreateRecord:
            _require_live(current)
            if current.job_uid is None:
                raise StateConflictError("A Pod cannot be bound before the Job UID")
            try:
                incarnations = list(json.loads(current.pod_incarnations_json or "[]"))
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise DependencyUnavailableError("Pod incarnation history is malformed") from error
            if any(
                not isinstance(item, dict)
                or not isinstance(item.get("podUid"), str)
                or not item["podUid"]
                for item in incarnations
            ):
                raise DependencyUnavailableError("Pod incarnation history is malformed")
            if incarnation_json is None:
                incarnation = {"podUid": pod_uid}
            else:
                try:
                    incarnation = json.loads(incarnation_json)
                except json.JSONDecodeError as error:
                    raise ValueError("Pod incarnation JSON is malformed") from error
                if not isinstance(incarnation, dict) or incarnation.get("podUid") != pod_uid:
                    raise ValueError("Pod incarnation identity differs from its binding")
            retained = next(
                (item for item in incarnations if item.get("podUid") == pod_uid), None
            )
            if current.pod_uid == pod_uid and retained == incarnation:
                return current
            if current.state == "indeterminate":
                raise ReplacementPodError()
            if retained is None:
                incarnations.append(pod_uid)
                incarnations[-1] = incarnation
            else:
                incarnations[incarnations.index(retained)] = incarnation
            return replace(
                current,
                pod_uid=pod_uid,
                pod_incarnations_json=json.dumps(
                    incarnations, sort_keys=True, separators=(",", ":")
                ),
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
        cleanup_phase = _optional_string(values.pop("cleanup_phase", None), "cleanup_phase")
        gpu_release_state = _string(
            values.pop("gpu_release_state", "complete"), "gpu_release_state"
        )
        gpu_release_reason = _optional_string(
            values.pop("gpu_release_reason", None), "gpu_release_reason"
        )
        credential_observations_json = _optional_observation_json(
            values.pop("credential_observations", None), "credential_observations"
        )
        transfer_observations_json = _optional_observation_json(
            values.pop("transfer_observations", None), "transfer_observations"
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
            if current.is_tombstone or current.is_deleting:
                if (
                    current.delete_ref != delete_ref
                    or current.delete_request_digest != delete_request_digest
                ):
                    raise IdentityDigestConflict()
                if current.final_state != final_state:
                    raise StateConflictError(
                        "A retained delete intent cannot change terminal state"
                    )
                if current.is_tombstone and (
                    current.deleted_at != deleted or current.expires_at != expires
                ):
                    raise StateConflictError("A retained tombstone cannot change retention times")
                retained_phase = cleanup_phase or current.cleanup_phase
                retained_credentials = (
                    credential_observations_json or current.credential_observations_json
                )
                retained_transfers = (
                    transfer_observations_json or current.transfer_observations_json
                )
                if current.cleanup_state == "complete" and cleanup_state != "complete":
                    raise StateConflictError("A complete tombstone cleanup cannot regress")
                if current.gpu_release_state in {"complete", "not_required"} and (
                    gpu_release_state != current.gpu_release_state
                ):
                    raise StateConflictError("A proven GPU release cannot regress")
                if _DELETE_PHASE_ORDER.get(retained_phase, -1) < _DELETE_PHASE_ORDER.get(
                    current.cleanup_phase, -1
                ):
                    raise StateConflictError("A deletion cleanup phase cannot regress")
                if (
                    current.cleanup_state == cleanup_state
                    and current.cleanup_reason == cleanup_reason
                    and current.cleanup_phase == retained_phase
                    and current.gpu_release_state == gpu_release_state
                    and current.gpu_release_reason == gpu_release_reason
                    and current.credential_observations_json == retained_credentials
                    and current.transfer_observations_json == retained_transfers
                ):
                    return current
                return replace(
                    current,
                    state="deleted" if cleanup_state == "complete" else "deleting",
                    cleanup_state=cleanup_state,
                    cleanup_reason=cleanup_reason,
                    cleanup_phase=retained_phase,
                    gpu_release_state=gpu_release_state,
                    gpu_release_reason=gpu_release_reason,
                    credential_observations_json=retained_credentials,
                    transfer_observations_json=retained_transfers,
                    deleted_at=deleted if cleanup_state == "complete" else None,
                    expires_at=expires if cleanup_state == "complete" else None,
                    updated_at=_timestamp(self._clock()),
                )
            if current.job_uid is None:
                raise StateConflictError("A reservation without a Job UID cannot be deleted")
            return replace(
                current,
                state="deleted" if cleanup_state == "complete" else "deleting",
                final_state=final_state,
                delete_ref=delete_ref,
                delete_request_digest=delete_request_digest,
                cleanup_state=cleanup_state,
                cleanup_reason=cleanup_reason,
                cleanup_phase=cleanup_phase,
                gpu_release_state=gpu_release_state,
                gpu_release_reason=gpu_release_reason,
                credential_observations_json=credential_observations_json or "[]",
                transfer_observations_json=transfer_observations_json or "[]",
                deleted_at=deleted if cleanup_state == "complete" else None,
                expires_at=expires if cleanup_state == "complete" else None,
                updated_at=_timestamp(self._clock()),
            )

        return self._update(provider_request_id, mutate)

    def list_create(self) -> list[CreateRecord]:
        selector = f"{RECORD_KIND_LABEL}={RECORD_KIND_VALUE}"
        records: list[CreateRecord] = []
        for item in self._kube.list_config_maps(selector):
            try:
                records.append(_record_from_config_map(item))
            except (DependencyUnavailableError, ValueError, TypeError):
                self._scan_errors += 1
        return sorted(records, key=lambda item: (item.created_at, item.job_ref))

    def reserve_runtime(
        self, kind: str, identity: str, job_ref: str, values: Mapping[str, str]
    ) -> tuple[RuntimeRecord, bool]:
        """Reserve one non-secret runtime identity before side effects."""
        existing = self.read_runtime(kind, job_ref, identity)
        if existing is not None:
            if existing.values.get("identityDigest") != values.get("identityDigest"):
                raise IdentityDigestConflict()
            return existing, False
        record = RuntimeRecord(kind=kind, identity=identity, job_ref=job_ref, values=dict(values))
        try:
            created = self._kube.create_config_map(_runtime_config_map_body(record))
        except Exception as exc:
            if _status(exc) != 409:
                raise
            existing = self.read_runtime(kind, job_ref, identity)
            if existing is None:
                raise DependencyUnavailableError(
                    "runtime record conflict was not readable"
                ) from exc
            if existing.job_ref != job_ref or existing.values.get("identityDigest") != values.get(
                "identityDigest"
            ):
                raise IdentityDigestConflict() from exc
            return existing, False
        return _runtime_record_from_config_map(created), True

    def reserve_catalog(
        self,
        kind: str,
        identity: str,
        digest: str,
        payload: Mapping[str, Any],
    ) -> tuple[CatalogRecord, bool]:
        """Persist immutable resolution output without a Job owner reference."""

        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        existing = self.read_catalog(kind, identity)
        if existing is not None:
            if existing.digest != digest or existing.payload != encoded:
                raise IdentityDigestConflict()
            return existing, False
        record = CatalogRecord(kind, identity, digest, encoded)
        try:
            created = self._kube.create_config_map(_catalog_config_map_body(record))
        except Exception as exc:
            if _status(exc) != 409:
                raise
            existing = self.read_catalog(kind, identity)
            if (
                existing is None
                or existing.digest != digest
                or existing.payload != encoded
            ):
                raise IdentityDigestConflict() from exc
            return existing, False
        return _catalog_record_from_config_map(created), True

    def read_catalog(self, kind: str, identity: str) -> CatalogRecord | None:
        value = self._kube.read_config_map(_catalog_record_name(kind, identity))
        if value is None:
            return None
        record = _catalog_record_from_config_map(value)
        if record.kind != kind or record.identity != identity:
            raise DependencyUnavailableError("catalog record hash collision")
        return record

    def read_runtime(self, kind: str, job_ref: str, identity: str) -> RuntimeRecord | None:
        config_map = self._kube.read_config_map(_runtime_record_name(kind, job_ref, identity))
        if config_map is None:
            config_map = self._kube.read_config_map(_legacy_runtime_record_name(kind, identity))
        if config_map is None:
            return None
        record = _runtime_record_from_config_map(config_map)
        if record.kind != kind or record.job_ref != job_ref or record.identity != identity:
            raise DependencyUnavailableError("runtime record hash collision")
        return record

    def list_runtime(
        self,
        kind: str,
        job_ref: str | None = None,
        *,
        strict: bool = False,
    ) -> list[RuntimeRecord]:
        selector = f"{RECORD_KIND_LABEL}=runtime-{kind}"
        if job_ref is not None:
            selector = f"{selector},{JOB_REF_HASH_LABEL}={_short_hash(job_ref)}"
        records: list[RuntimeRecord] = []
        for item in self._kube.list_config_maps(selector):
            try:
                record = _runtime_record_from_config_map(item)
            except (DependencyUnavailableError, ValueError, TypeError) as error:
                self._scan_errors += 1
                if strict:
                    raise DependencyUnavailableError(
                        "runtime record scan was incomplete"
                    ) from error
                continue
            if record.job_ref == job_ref or job_ref is None:
                records.append(record)
        return records

    def consume_scan_errors(self) -> int:
        errors = self._scan_errors
        self._scan_errors = 0
        return errors

    def delete_runtime_records(self, job_ref: str) -> int:
        """Remove owner-scoped runtime records left after foreground Job deletion."""
        selector = f"{JOB_REF_HASH_LABEL}={_short_hash(job_ref)}"
        deleted = 0
        for item in self._kube.list_config_maps(selector):
            data = _data(item)
            if data.get("jobRef") != job_ref or "kind" not in data:
                continue
            name = _value(_value(item, "metadata"), "name")
            if isinstance(name, str) and self._kube.delete_config_map(name):
                deleted += 1
        return deleted

    def has_runtime_records(self, job_ref: str) -> bool:
        selector = f"{JOB_REF_HASH_LABEL}={_short_hash(job_ref)}"
        return any(
            _data(item).get("jobRef") == job_ref and "kind" in _data(item)
            for item in self._kube.list_config_maps(selector)
        )

    def update_runtime(
        self, kind: str, job_ref: str, identity: str, values: Mapping[str, str]
    ) -> RuntimeRecord:
        for _ in range(_UPDATE_ATTEMPTS):
            current = self.read_runtime(kind, job_ref, identity)
            if current is None:
                raise JobNotFoundError()
            desired = RuntimeRecord(
                kind=kind,
                identity=identity,
                job_ref=current.job_ref,
                values=dict(values),
                resource_version=current.resource_version,
                storage_name=current.storage_name,
            )
            storage_name = current.storage_name or _runtime_record_name(kind, job_ref, identity)
            try:
                written = self._kube.replace_config_map(
                    storage_name,
                    _runtime_config_map_body(
                        desired,
                        resource_version=current.resource_version,
                        storage_name=storage_name,
                    ),
                )
            except Exception as exc:
                if _status(exc) == 409:
                    continue
                raise
            return _runtime_record_from_config_map(written)
        raise DependencyUnavailableError("runtime record changed concurrently")

    def compare_and_swap_runtime(
        self,
        kind: str,
        job_ref: str,
        identity: str,
        values: Mapping[str, str],
        *,
        expected_resource_version: str,
    ) -> RuntimeRecord | None:
        """Write exactly the runtime version the caller inspected, or report a lost CAS."""
        current = self.read_runtime(kind, job_ref, identity)
        if current is None:
            raise JobNotFoundError()
        if current.resource_version != expected_resource_version:
            return None
        storage_name = current.storage_name or _runtime_record_name(kind, job_ref, identity)
        desired = RuntimeRecord(
            kind=kind,
            identity=identity,
            job_ref=current.job_ref,
            values=dict(values),
            resource_version=current.resource_version,
            storage_name=storage_name,
        )
        try:
            written = self._kube.replace_config_map(
                storage_name,
                _runtime_config_map_body(
                    desired,
                    resource_version=expected_resource_version,
                    storage_name=storage_name,
                ),
            )
        except Exception as exc:
            if _status(exc) == 409:
                return None
            raise
        return _runtime_record_from_config_map(written)

    # Clear aliases used by some provider call sites.
    bind_job = mark_created
    bind_first_pod = bind_pod_incarnation
    bind_pod = bind_pod_incarnation
    list_records = list_create

    def purge_expired(self, now: datetime | str) -> int:
        """Delete only tombstones whose explicit retention time has elapsed."""
        boundary = _parse_timestamp(_timestamp(now))
        deleted = 0
        for record in self.list_create():
            if (
                record.is_tombstone
                and record.cleanup_state == "complete"
                and record.gpu_release_state in {"complete", "not_required"}
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
    if record.is_deleting:
        raise StateConflictError("A retained deletion intent cannot be changed by a live mutation")


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


def _normalize_snapshot(value: Mapping[str, Any] | None) -> str | None:
    if value is None:
        return None
    compact = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    decoded = json.loads(compact)
    if not isinstance(decoded, dict):
        raise ValueError("the native recipe snapshot must be a JSON object")
    return compact


def _record_name(provider_request_id: str) -> str:
    return f"kcs-v2-create-{_short_hash(provider_request_id, 32)}"


def _runtime_record_name(kind: str, job_ref: str, identity: str) -> str:
    return f"kcs-v2-{kind}-{_short_hash(f'{job_ref}:{identity}', 32)}"


def _catalog_record_name(kind: str, identity: str) -> str:
    return f"kcs-v2-catalog-{kind}-{_short_hash(identity, 32)}"


def _legacy_runtime_record_name(kind: str, identity: str) -> str:
    return f"kcs-v2-{kind}-{_short_hash(identity, 32)}"


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
        "podIncarnations": record.pod_incarnations_json or "[]",
        "nativeRecipeSnapshotJson": record.native_recipe_snapshot_json,
        "finalState": record.final_state,
        "deleteRef": record.delete_ref,
        "deleteRequestDigest": record.delete_request_digest,
        "cleanupState": record.cleanup_state,
        "cleanupReason": record.cleanup_reason,
        "cleanupPhase": record.cleanup_phase,
        "gpuReleaseState": record.gpu_release_state,
        "gpuReleaseReason": record.gpu_release_reason,
        "credentialObservationsJson": record.credential_observations_json,
        "transferObservationsJson": record.transfer_observations_json,
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
        native_recipe_snapshot_json=data.get("nativeRecipeSnapshotJson"),
        job_uid=data.get("jobUid"),
        pod_uid=data.get("podUid"),
        pod_incarnations_json=data.get("podIncarnations", "[]"),
        final_state=data.get("finalState"),
        delete_ref=data.get("deleteRef"),
        delete_request_digest=data.get("deleteRequestDigest"),
        cleanup_state=data.get("cleanupState"),
        cleanup_reason=data.get("cleanupReason"),
        cleanup_phase=data.get("cleanupPhase"),
        gpu_release_state=data.get("gpuReleaseState"),
        gpu_release_reason=data.get("gpuReleaseReason"),
        credential_observations_json=data.get("credentialObservationsJson"),
        transfer_observations_json=data.get("transferObservationsJson"),
        indeterminate_reason=data.get("indeterminateReason"),
        deleted_at=data.get("deletedAt"),
        expires_at=data.get("expiresAt"),
        resource_version=_value(metadata, "resource_version")
        or _value(metadata, "resourceVersion"),
    )


def _runtime_config_map_body(
    record: RuntimeRecord,
    *,
    resource_version: str | None = None,
    storage_name: str | None = None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "name": storage_name
        or record.storage_name
        or _runtime_record_name(record.kind, record.job_ref, record.identity),
        "labels": {
            MANAGED_BY_LABEL: MANAGED_BY_VALUE,
            RECORD_KIND_LABEL: f"runtime-{record.kind}",
            JOB_REF_HASH_LABEL: _short_hash(record.job_ref),
        },
        "ownerReferences": _runtime_owner_references(record),
    }
    if resource_version is not None:
        metadata["resourceVersion"] = resource_version
    data = {
        "recordVersion": _RECORD_VERSION,
        "kind": record.kind,
        "identity": record.identity,
        "jobRef": record.job_ref,
    }
    data.update(dict(record.values))
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata, "data": data}


def _runtime_owner_references(record: RuntimeRecord) -> list[dict[str, object]]:
    job_uid = record.values.get("jobUid")
    if not job_uid:
        raise ValueError("runtime records require the bound Job UID")
    return [
        {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "name": record.job_ref,
            "uid": job_uid,
            "controller": False,
            "blockOwnerDeletion": False,
        }
    ]


def _runtime_record_from_config_map(config_map: Any) -> RuntimeRecord:
    data = _data(config_map)
    if data.get("recordVersion") != _RECORD_VERSION:
        raise DependencyUnavailableError("unsupported ConfigMap runtime record version")
    metadata = _value(config_map, "metadata")
    values = {
        key: value
        for key, value in data.items()
        if key not in {"recordVersion", "kind", "identity", "jobRef"}
    }
    return RuntimeRecord(
        kind=_required(data, "kind"),
        identity=_required(data, "identity"),
        job_ref=_required(data, "jobRef"),
        values=MappingProxyType(values),
        resource_version=_value(metadata, "resource_version")
        or _value(metadata, "resourceVersion"),
        storage_name=_value(metadata, "name"),
    )


def _catalog_config_map_body(record: CatalogRecord) -> dict[str, object]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": _catalog_record_name(record.kind, record.identity),
            "labels": {
                MANAGED_BY_LABEL: MANAGED_BY_VALUE,
                RECORD_KIND_LABEL: f"catalog-{record.kind}",
            },
            "ownerReferences": [],
        },
        "data": {
            "recordVersion": _RECORD_VERSION,
            "kind": record.kind,
            "identity": record.identity,
            "digest": record.digest,
            "payload": record.payload,
        },
    }


def _catalog_record_from_config_map(config_map: Any) -> CatalogRecord:
    data = _data(config_map)
    if data.get("recordVersion") != _RECORD_VERSION:
        raise DependencyUnavailableError("unsupported ConfigMap catalog record version")
    metadata = _value(config_map, "metadata")
    return CatalogRecord(
        kind=_required(data, "kind"),
        identity=_required(data, "identity"),
        digest=_required(data, "digest"),
        payload=_required(data, "payload"),
        storage_name=_value(metadata, "name"),
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


def _optional_observation_json(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    if not all(isinstance(item, Mapping) for item in value):
        raise ValueError(f"{field} entries must be objects")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _observation_json(value: str | None, field: str) -> list[object]:
    try:
        decoded: object = json.loads(value or "[]")
    except json.JSONDecodeError as exc:
        raise DependencyUnavailableError(f"retained {field} are invalid") from exc
    if not isinstance(decoded, list) or not all(isinstance(item, dict) for item in decoded):
        raise DependencyUnavailableError(f"retained {field} are invalid")
    return decoded


def _parse_timestamp(value: str) -> datetime:
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("timestamp must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed
