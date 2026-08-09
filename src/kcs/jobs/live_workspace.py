"""Durable orchestration for immutable, bounded live-worktree snapshots."""

from __future__ import annotations

import hmac
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from .errors import (
    DependencyUnavailableError,
    IdentityDigestConflictError,
    InvalidPageTokenError,
    JobNotFoundError,
    KcsV2Error,
    LiveSnapshotExpiredError,
    LiveSnapshotStaleBindingError,
    PayloadTooLargeError,
    StateConflictError,
    UnsafePathError,
)
from .m2_contracts import (
    LiveWorkspaceDiffPage,
    LiveWorkspaceSnapshot,
    LiveWorkspaceSnapshotRequest,
)
from .native_contracts import NativeJobBindingSnapshot
from .transport import WorkspaceRpcReply, WorkspaceRpcTransportProtocol

_KIND = "live-snapshot"


class RuntimeStore(Protocol):
    def reserve_runtime(
        self, kind: str, identity: str, job_ref: str, values: Mapping[str, str]
    ) -> tuple[object, bool]: ...

    def read_runtime(self, kind: str, job_ref: str, identity: str) -> object | None: ...

    def update_runtime(
        self, kind: str, job_ref: str, identity: str, values: Mapping[str, str]
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class LiveSnapshotResult:
    snapshot: LiveWorkspaceSnapshot
    created: bool

    @property
    def replayed(self) -> bool:
        return not self.created


@dataclass(frozen=True, slots=True)
class LiveContentRange:
    content: bytes
    snapshot_digest: str
    content_sha256: str
    sequence: int
    offset: int
    end_offset: int
    total_size: int


class LiveWorkspaceRuntime:
    """Bind control-side snapshots to retained Job/Pod/generation identities."""

    def __init__(
        self,
        store: RuntimeStore,
        transport: WorkspaceRpcTransportProtocol | None,
        binding: Callable[[str], NativeJobBindingSnapshot],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._transport = transport
        self._binding = binding
        self._clock = clock or (lambda: datetime.now(UTC))

    def create(
        self,
        job_ref: str,
        request: LiveWorkspaceSnapshotRequest | Mapping[str, Any],
    ) -> LiveSnapshotResult:
        typed = (
            request
            if isinstance(request, LiveWorkspaceSnapshotRequest)
            else LiveWorkspaceSnapshotRequest.model_validate(dict(request))
        )
        spec = typed.root["spec"]
        binding = self._exact_binding(job_ref)
        self._require_request_identity(job_ref, binding, spec)
        self._require_base_manifest(job_ref, spec)
        snapshot_ref = str(typed.root["snapshotRef"])
        request_digest = str(typed.root["requestDigest"])
        values = {
            "identityDigest": request_digest,
            "jobUid": str(spec["jobUid"]),
            "podUid": str(spec["podUid"]),
            "generation": str(spec["generation"]),
            "baseManifestDigest": str(spec["baseManifestDigest"]),
            "state": "creating",
        }
        record, created = self._store.reserve_runtime(
            _KIND, snapshot_ref, job_ref, values
        )
        retained = _values(record)
        self._require_record_identity(retained, typed)
        if retained.get("state") == "released":
            raise StateConflictError("The retained live snapshot has been released")
        reply = self._rpc(
            binding,
            {
                "action": "createLiveWorkspaceSnapshot",
                "snapshotRef": snapshot_ref,
                "requestDigest": request_digest,
                "jobRef": job_ref,
                **spec,
            },
        )
        snapshot = self._snapshot_from_reply(job_ref, typed, reply)
        updated = {
            **retained,
            "state": "ready",
            "sequence": str(snapshot.root["sequence"]),
            "snapshotDigest": str(snapshot.root["snapshotDigest"]),
            "createdAt": str(snapshot.root["createdAt"]),
            "expiresAt": str(snapshot.root["expiresAt"]),
        }
        self._store.update_runtime(_KIND, job_ref, snapshot_ref, updated)
        return LiveSnapshotResult(snapshot=snapshot, created=created)

    def inspect(self, job_ref: str, snapshot_ref: str) -> LiveWorkspaceSnapshot:
        record, binding = self._record_and_binding(job_ref, snapshot_ref)
        values = _values(record)
        self._require_ready(values)
        request = _request_from_values(snapshot_ref, values)
        reply = self._rpc(
            binding,
            {
                "action": "inspectLiveWorkspaceSnapshot",
                "snapshotRef": snapshot_ref,
                "requestDigest": values["identityDigest"],
                "jobRef": job_ref,
                **_identity_fields(values),
            },
        )
        return self._snapshot_from_reply(job_ref, request, reply)

    def release(self, job_ref: str, snapshot_ref: str) -> LiveWorkspaceSnapshot:
        record, binding = self._record_and_binding(job_ref, snapshot_ref)
        values = _values(record)
        if values.get("state") == "released":
            raise StateConflictError("The retained live snapshot has already been released")
        self._require_not_expired(values)
        request = _request_from_values(snapshot_ref, values)
        reply = self._rpc(
            binding,
            {
                "action": "releaseLiveWorkspaceSnapshot",
                "snapshotRef": snapshot_ref,
                "requestDigest": values["identityDigest"],
                "jobRef": job_ref,
                **_identity_fields(values),
            },
        )
        snapshot = self._snapshot_from_reply(job_ref, request, reply)
        if snapshot.root["state"] != "released":
            raise DependencyUnavailableError("control did not confirm snapshot release")
        self._store.update_runtime(
            _KIND, job_ref, snapshot_ref, {**values, "state": "released"}
        )
        return snapshot

    def read_content(
        self,
        job_ref: str,
        snapshot_ref: str,
        path: str,
        *,
        offset: int = 0,
        limit_bytes: int = 1048576,
    ) -> LiveContentRange:
        if type(offset) is not int or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if type(limit_bytes) is not int or not 1 <= limit_bytes <= 1048576:
            raise PayloadTooLargeError("live content ranges are limited to 1 MiB")
        record, binding = self._record_and_binding(job_ref, snapshot_ref)
        values = _values(record)
        self._require_ready(values)
        reply = self._rpc(
            binding,
            {
                "action": "readLiveWorkspaceContent",
                "snapshotRef": snapshot_ref,
                "requestDigest": values["identityDigest"],
                "jobRef": job_ref,
                **_identity_fields(values),
                "path": path,
                "offset": offset,
                "limitBytes": limit_bytes,
            },
        )
        header = reply.header
        if reply.content_path is None:
            if header.get("sizeBytes") != 0:
                raise DependencyUnavailableError("control returned no live snapshot bytes")
            content = b""
        else:
            try:
                content = reply.content_path.read_bytes()
            finally:
                reply.content_path.unlink(missing_ok=True)
        if len(content) > limit_bytes or header.get("sizeBytes") != len(content):
            raise DependencyUnavailableError("control returned an invalid content range")
        if not hmac.compare_digest(
            str(header.get("snapshotDigest", "")), values["snapshotDigest"]
        ):
            raise IdentityDigestConflictError()
        try:
            return LiveContentRange(
                content=content,
                snapshot_digest=str(header["snapshotDigest"]),
                content_sha256=str(header["contentSha256"]),
                sequence=int(header["sequence"]),
                offset=int(header["offset"]),
                end_offset=int(header["endOffset"]),
                total_size=int(header["totalSize"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise DependencyUnavailableError("control returned invalid content metadata") from error

    def diff(
        self,
        job_ref: str,
        snapshot_ref: str,
        *,
        page_token: str | None = None,
        page_size: int = 50,
    ) -> LiveWorkspaceDiffPage:
        if type(page_size) is not int or not 1 <= page_size <= 200:
            raise ValueError("page_size must be between 1 and 200")
        record, binding = self._record_and_binding(job_ref, snapshot_ref)
        values = _values(record)
        self._require_ready(values)
        reply = self._rpc(
            binding,
            {
                "action": "getLiveWorkspaceDiff",
                "snapshotRef": snapshot_ref,
                "requestDigest": values["identityDigest"],
                "jobRef": job_ref,
                **_identity_fields(values),
                "pageToken": page_token,
                "pageSize": page_size,
            },
        )
        try:
            page = LiveWorkspaceDiffPage.model_validate(reply.header["page"])
        except (KeyError, TypeError, ValueError) as error:
            raise DependencyUnavailableError("control returned an invalid live diff") from error
        if not hmac.compare_digest(
            str(page.root["snapshotDigest"]), values["snapshotDigest"]
        ):
            raise IdentityDigestConflictError()
        return page

    def _record_and_binding(
        self, job_ref: str, snapshot_ref: str
    ) -> tuple[object, NativeJobBindingSnapshot]:
        record = self._store.read_runtime(_KIND, job_ref, snapshot_ref)
        if record is None:
            raise JobNotFoundError("The live workspace snapshot was not found")
        binding = self._exact_binding(job_ref)
        values = _values(record)
        if (
            values.get("jobUid") != str(binding.root["jobUid"])
            or values.get("podUid") != str(binding.root["podUid"])
            or values.get("generation") != str(_generation(binding))
        ):
            raise LiveSnapshotStaleBindingError()
        return record, binding

    def _exact_binding(self, job_ref: str) -> NativeJobBindingSnapshot:
        binding = self._binding(job_ref)
        if not isinstance(binding, NativeJobBindingSnapshot):
            raise StateConflictError("live workspace reads require a native binding")
        if binding.root.get("podUid") is None or binding.root.get("bindingState") in {
            "indeterminate",
            "deleting",
            "deleted",
        }:
            raise LiveSnapshotStaleBindingError()
        return binding

    @staticmethod
    def _require_request_identity(
        job_ref: str,
        binding: NativeJobBindingSnapshot,
        spec: Mapping[str, Any],
    ) -> None:
        if (
            str(spec["jobUid"]) != str(binding.root["jobUid"])
            or str(spec["podUid"]) != str(binding.root["podUid"])
            or int(spec["generation"]) != _generation(binding)
            or binding.root["jobRef"] != job_ref
        ):
            raise LiveSnapshotStaleBindingError()

    def _require_base_manifest(self, job_ref: str, spec: Mapping[str, Any]) -> None:
        generation = str(spec["generation"])
        record = self._store.read_runtime("runner-start", job_ref, generation)
        if record is None:
            raise StateConflictError("runner start identity is unavailable")
        try:
            retained = json.loads(_values(record)["requestSpec"])
            descriptor = retained["descriptor"]
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise DependencyUnavailableError("retained runner descriptor is invalid") from error
        if (
            descriptor.get("jobUid") != spec["jobUid"]
            or descriptor.get("podUid") != spec["podUid"]
            or descriptor.get("generation") != spec["generation"]
            or descriptor.get("baseManifestDigest") != spec["baseManifestDigest"]
        ):
            raise LiveSnapshotStaleBindingError(
                "The live snapshot base manifest differs from the runner generation"
            )

    @staticmethod
    def _require_record_identity(
        retained: Mapping[str, str], request: LiveWorkspaceSnapshotRequest
    ) -> None:
        spec = request.root["spec"]
        if (
            retained.get("identityDigest") != request.root["requestDigest"]
            or retained.get("jobUid") != spec["jobUid"]
            or retained.get("podUid") != spec["podUid"]
            or retained.get("generation") != str(spec["generation"])
            or retained.get("baseManifestDigest") != spec["baseManifestDigest"]
        ):
            raise IdentityDigestConflictError()

    def _require_ready(self, values: Mapping[str, str]) -> None:
        self._require_not_expired(values)
        if values.get("state") != "ready":
            raise StateConflictError("The live workspace snapshot is not readable")

    def _require_not_expired(self, values: Mapping[str, str]) -> None:
        expires = values.get("expiresAt")
        if expires is not None and self._clock() >= _datetime(expires):
            raise LiveSnapshotExpiredError()

    def _rpc(
        self, binding: NativeJobBindingSnapshot, header: Mapping[str, object]
    ) -> WorkspaceRpcReply:
        if self._transport is None:
            raise DependencyUnavailableError("workspace RPC transport is not configured")
        try:
            reply = self._transport.rpc(
                {
                    "runtimeLane": "native",
                    "jobRef": str(binding.root["jobRef"]),
                    "jobUid": str(binding.root["jobUid"]),
                    "podUid": str(binding.root["podUid"]),
                },
                header,
            )
        except KcsV2Error:
            raise
        except Exception as error:
            raise DependencyUnavailableError(
                "live workspace control response was not confirmed"
            ) from error
        if reply.header.get("ok") is not True:
            if reply.content_path is not None:
                reply.content_path.unlink(missing_ok=True)
            _raise_control_error(str(reply.header.get("code", "DEPENDENCY_UNAVAILABLE")))
        return reply

    @staticmethod
    def _snapshot_from_reply(
        job_ref: str,
        request: LiveWorkspaceSnapshotRequest,
        reply: WorkspaceRpcReply,
    ) -> LiveWorkspaceSnapshot:
        try:
            snapshot = LiveWorkspaceSnapshot.model_validate(reply.header["snapshot"])
        except (KeyError, TypeError, ValueError) as error:
            raise DependencyUnavailableError("control returned an invalid live snapshot") from error
        value = snapshot.root
        spec = request.root["spec"]
        if (
            value["snapshotRef"] != request.root["snapshotRef"]
            or value["requestDigest"] != request.root["requestDigest"]
            or value["jobRef"] != job_ref
            or value["jobUid"] != spec["jobUid"]
            or value["podUid"] != spec["podUid"]
            or value["generation"] != spec["generation"]
            or value["baseManifestDigest"] != spec["baseManifestDigest"]
        ):
            raise IdentityDigestConflictError()
        return snapshot


def _request_from_values(
    snapshot_ref: str, values: Mapping[str, str]
) -> LiveWorkspaceSnapshotRequest:
    return LiveWorkspaceSnapshotRequest.model_construct(
        root={
            "snapshotRef": snapshot_ref,
            "requestDigest": values["identityDigest"],
            "spec": {
                "jobUid": values["jobUid"],
                "podUid": values["podUid"],
                "generation": int(values["generation"]),
                "baseManifestDigest": values["baseManifestDigest"],
                # These bounds are irrelevant after creation and are not retained
                # in the small ConfigMap record. The snapshot reply is validated
                # against the immutable identity fields above.
                "ttlSeconds": 1,
                "maximumEntries": 1,
                "maximumBytes": 1,
            },
        }
    )


def _identity_fields(values: Mapping[str, str]) -> dict[str, object]:
    return {
        "jobUid": values["jobUid"],
        "podUid": values["podUid"],
        "generation": int(values["generation"]),
        "baseManifestDigest": values["baseManifestDigest"],
    }


def _generation(binding: NativeJobBindingSnapshot) -> int:
    latest = binding.root.get("latestRunnerGeneration")
    if not isinstance(latest, Mapping) or type(latest.get("generation")) is not int:
        raise StateConflictError("native runner generation is not active")
    return int(latest["generation"])


def _values(record: object) -> dict[str, str]:
    value = record.get("values") if isinstance(record, Mapping) else getattr(record, "values", None)
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
    ):
        raise DependencyUnavailableError("retained live snapshot record is invalid")
    return dict(value)


def _datetime(value: str) -> datetime:
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise DependencyUnavailableError("retained live snapshot timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise DependencyUnavailableError("retained live snapshot timestamp is invalid")
    return parsed.astimezone(UTC)


def _raise_control_error(code: str) -> None:
    if code == "IDENTITY_CONFLICT":
        raise IdentityDigestConflictError()
    if code == "STALE_BINDING":
        raise LiveSnapshotStaleBindingError()
    if code == "LIVE_SNAPSHOT_EXPIRED":
        raise LiveSnapshotExpiredError()
    if code == "INVALID_PAGE_TOKEN":
        raise InvalidPageTokenError()
    if code == "UNSAFE_PATH":
        raise UnsafePathError()
    if code == "PAYLOAD_TOO_LARGE":
        raise PayloadTooLargeError()
    if code == "NOT_FOUND":
        raise JobNotFoundError("The live workspace snapshot was not found")
    if code == "STATE_CONFLICT":
        raise StateConflictError()
    raise DependencyUnavailableError("workspace control rejected the live snapshot RPC")


__all__ = [
    "LiveContentRange",
    "LiveSnapshotResult",
    "LiveWorkspaceRuntime",
]
