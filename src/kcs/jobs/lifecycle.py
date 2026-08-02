"""Small durable helpers for cancel/delete phases and startup reconciliation."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, TypedDict, cast
from uuid import uuid4

from .contracts import ActionSnapshot, ActionState
from .errors import DependencyUnavailableError, StateConflictError

_SCHEMA_VERSION = 1
_CAS_ATTEMPTS = 12
_START_TRANSFER_EXCLUSIVE_KINDS = frozenset(
    {
        "agent-start",
        "transfer-stage",
        "transfer-reconcile",
        "transfer-cancel",
        "transfer-discard",
    }
)


class _ClaimIntent(TypedDict):
    kind: str
    ref: str
    version: int


class _ActiveClaim(TypedDict):
    token: str
    epoch: int
    holderIdentity: str
    intent: _ClaimIntent


class _CloseIdentity(TypedDict):
    kind: str
    ref: str
    digest: str
    requestSpec: str
    phase: str
    phaseOrdinal: int
    executorIdentity: str
    executionEpoch: int


class _LifecyclePayload(TypedDict):
    schemaVersion: int
    jobUid: str
    podUid: str
    gate: Literal["open", "closing", "closed"]
    epoch: int
    activeClaims: list[_ActiveClaim]
    close: _CloseIdentity | None


class LifecycleStore(Protocol):
    def reserve_runtime(
        self, kind: str, identity: str, job_ref: str, values: Mapping[str, str]
    ) -> tuple[object, bool]: ...

    def read_runtime(self, kind: str, job_ref: str, identity: str) -> object | None: ...

    def compare_and_swap_runtime(
        self,
        kind: str,
        job_ref: str,
        identity: str,
        values: Mapping[str, str],
        *,
        expected_resource_version: str,
    ) -> object | None: ...


@dataclass(frozen=True, slots=True)
class LifecycleClaim:
    """One durable mutation admission claim on the Job-owned lifecycle slot."""

    gate: LifecycleGate
    job_ref: str
    token: str

    def release(self) -> None:
        self.gate.release(self)


@dataclass(frozen=True, slots=True)
class LifecycleClose:
    """A retained close identity which can advance only through slot CAS updates."""

    gate: LifecycleGate
    job_ref: str
    kind: str
    ref: str
    digest: str
    request_spec: str
    executor_identity: str
    execution_epoch: int

    def phase(self, phase: str, *, closed: bool = False) -> None:
        self.gate.set_close_phase(self, phase, closed=closed)


class LifecycleGate:
    """Linearize every Job mutation and lifecycle close on one ConfigMap RV."""

    def __init__(self, store: LifecycleStore) -> None:
        self._store = store
        self._holder_identity = uuid4().hex

    def claim(
        self,
        job_ref: str,
        job_uid: str,
        pod_uid: str,
        kind: str,
        ref: str,
    ) -> LifecycleClaim:
        token = uuid4().hex
        for _ in range(_CAS_ATTEMPTS):
            record = self._slot(job_ref, job_uid, pod_uid)
            payload = _lifecycle_payload(record, job_uid, pod_uid)
            if payload["gate"] != "open":
                raise StateConflictError("The Job lifecycle gate is closing")
            claims = list(payload["activeClaims"])
            exclusive_conflict = kind in _START_TRANSFER_EXCLUSIVE_KINDS and any(
                item["intent"]["kind"] in _START_TRANSFER_EXCLUSIVE_KINDS for item in claims
            )
            duplicate_conflict = kind not in {"transfer-collect", "workspace-invoke"} and any(
                item["intent"]["kind"] == kind and item["intent"]["ref"] == ref for item in claims
            )
            if exclusive_conflict or duplicate_conflict:
                raise StateConflictError(
                    "The lifecycle mutation intent already has an active claim"
                )
            claim_epoch = int(payload["epoch"]) + 1
            claims.append(
                {
                    "token": token,
                    "epoch": claim_epoch,
                    "holderIdentity": self._holder_identity,
                    "intent": {"kind": kind, "ref": ref, "version": 1},
                }
            )
            desired = {**payload, "epoch": claim_epoch, "activeClaims": claims}
            if self._cas(record, desired) is not None:
                return LifecycleClaim(self, job_ref, token)
        raise DependencyUnavailableError("lifecycle claim changed concurrently")

    def intent_active(self, job_ref: str, kind: str, ref: str) -> bool:
        record = self._store.read_runtime("lifecycle", job_ref, "slot")
        if record is None:
            return False
        values = _values(record)
        payload = _lifecycle_payload(record, values.get("jobUid", ""), values.get("podUid", ""))
        return any(
            item["intent"]["kind"] == kind and item["intent"]["ref"] == ref
            for item in payload["activeClaims"]
        )

    def inspect(self, job_ref: str) -> Mapping[str, object] | None:
        record = self._store.read_runtime("lifecycle", job_ref, "slot")
        if record is None:
            return None
        values = _values(record)
        return _lifecycle_payload(record, values.get("jobUid", ""), values.get("podUid", ""))

    def release_proven_claims(
        self,
        job_ref: str,
        terminal_truth: Callable[[Mapping[str, object]], bool],
    ) -> int:
        """CAS-release only claims whose durable mutation truth is already terminal."""
        for _ in range(_CAS_ATTEMPTS):
            record = self._store.read_runtime("lifecycle", job_ref, "slot")
            if record is None:
                return 0
            values = _values(record)
            payload = _lifecycle_payload(record, values.get("jobUid", ""), values.get("podUid", ""))
            claims = [
                item for item in payload["activeClaims"] if not terminal_truth(item["intent"])
            ]
            if len(claims) == len(payload["activeClaims"]):
                return len(claims)
            desired = {**payload, "epoch": int(payload["epoch"]) + 1, "activeClaims": claims}
            if self._cas(record, desired) is not None:
                return len(claims)
        raise DependencyUnavailableError("lifecycle terminal claim release changed concurrently")

    def release(self, claim: LifecycleClaim) -> None:
        for _ in range(_CAS_ATTEMPTS):
            record = self._store.read_runtime("lifecycle", claim.job_ref, "slot")
            if record is None:
                raise DependencyUnavailableError("lifecycle slot disappeared")
            values = _values(record)
            payload = _lifecycle_payload(record, values.get("jobUid", ""), values.get("podUid", ""))
            claims = [item for item in payload["activeClaims"] if item["token"] != claim.token]
            if len(claims) == len(payload["activeClaims"]):
                return
            desired = {**payload, "epoch": int(payload["epoch"]) + 1, "activeClaims": claims}
            if self._cas(record, desired) is not None:
                return
        raise DependencyUnavailableError("lifecycle release changed concurrently")

    def begin_close(
        self,
        job_ref: str,
        job_uid: str,
        pod_uid: str,
        kind: str,
        ref: str,
        digest: str,
        request_spec: str,
    ) -> LifecycleClose:
        executor_identity = uuid4().hex
        identity = {
            "kind": kind,
            "ref": ref,
            "digest": digest,
            "requestSpec": request_spec,
        }
        for _ in range(_CAS_ATTEMPTS):
            record = self._slot(job_ref, job_uid, pod_uid)
            payload = _lifecycle_payload(record, job_uid, pod_uid)
            close = payload["close"]
            if isinstance(close, Mapping) and all(
                close.get(key) == value for key, value in identity.items()
            ):
                if payload["activeClaims"]:
                    raise StateConflictError("Lifecycle close cannot retain active claims")
                execution_epoch = int(close["executionEpoch"])
                if payload["gate"] == "closed":
                    return LifecycleClose(
                        self,
                        job_ref,
                        kind,
                        ref,
                        digest,
                        request_spec,
                        str(close["executorIdentity"]),
                        execution_epoch,
                    )
                desired = {
                    **payload,
                    "epoch": int(payload["epoch"]) + 1,
                    "close": {
                        **close,
                        "executorIdentity": executor_identity,
                        "executionEpoch": execution_epoch + 1,
                    },
                }
                if self._cas(record, desired) is not None:
                    return LifecycleClose(
                        self,
                        job_ref,
                        kind,
                        ref,
                        digest,
                        request_spec,
                        executor_identity,
                        execution_epoch + 1,
                    )
                continue
            if payload["activeClaims"]:
                raise StateConflictError("The Job has an active lifecycle mutation claim")
            gate = payload["gate"]
            prior_terminal = (
                gate == "closed"
                and isinstance(close, Mapping)
                and close.get("phase") == "succeeded"
                and kind == "delete"
                and close.get("kind") in {"cancel", "finalize"}
            )
            if gate != "open" and not prior_terminal:
                raise StateConflictError("Another lifecycle close identity is retained")
            desired = {
                **payload,
                "gate": "closing",
                "epoch": int(payload["epoch"]) + 1,
                "close": {
                    **identity,
                    "phase": "accepted",
                    "phaseOrdinal": 0,
                    "executorIdentity": executor_identity,
                    "executionEpoch": 1,
                },
            }
            if self._cas(record, desired) is not None:
                return LifecycleClose(
                    self,
                    job_ref,
                    kind,
                    ref,
                    digest,
                    request_spec,
                    executor_identity,
                    1,
                )
        raise DependencyUnavailableError("lifecycle close changed concurrently")

    def set_close_phase(self, close: LifecycleClose, phase: str, *, closed: bool = False) -> None:
        for _ in range(_CAS_ATTEMPTS):
            record = self._store.read_runtime("lifecycle", close.job_ref, "slot")
            if record is None:
                raise DependencyUnavailableError("lifecycle slot disappeared")
            values = _values(record)
            payload = _lifecycle_payload(record, values.get("jobUid", ""), values.get("podUid", ""))
            retained = payload["close"]
            expected = {
                "kind": close.kind,
                "ref": close.ref,
                "digest": close.digest,
                "requestSpec": close.request_spec,
            }
            if not isinstance(retained, Mapping) or any(
                retained.get(key) != value for key, value in expected.items()
            ):
                raise StateConflictError("Lifecycle close identity changed")
            if payload["gate"] == "closed":
                if closed and retained.get("phase") == phase:
                    return
                raise StateConflictError("Lifecycle close is terminal and cannot reopen")
            if (
                retained.get("executorIdentity") != close.executor_identity
                or retained.get("executionEpoch") != close.execution_epoch
            ):
                raise StateConflictError("Lifecycle close execution ownership changed")
            if payload["activeClaims"]:
                raise StateConflictError("Lifecycle cannot close with active mutation claims")
            retained_ordinal = int(retained["phaseOrdinal"])
            desired_ordinal = _close_phase_ordinal(close.kind, phase, retained_ordinal)
            if desired_ordinal < retained_ordinal:
                raise StateConflictError("Lifecycle close phase cannot regress")
            desired = {
                **payload,
                "gate": "closed" if closed else "closing",
                "epoch": int(payload["epoch"]) + 1,
                "close": {
                    **expected,
                    "phase": phase,
                    "phaseOrdinal": desired_ordinal,
                    "executorIdentity": close.executor_identity,
                    "executionEpoch": close.execution_epoch,
                },
            }
            if self._cas(record, desired) is not None:
                return
        raise DependencyUnavailableError("lifecycle close phase changed concurrently")

    def _slot(self, job_ref: str, job_uid: str, pod_uid: str) -> object:
        values = {
            "identityDigest": f"{job_uid}:{pod_uid}",
            "jobUid": job_uid,
            "podUid": pod_uid,
            "payload": json.dumps(
                {
                    "schemaVersion": _SCHEMA_VERSION,
                    "jobUid": job_uid,
                    "podUid": pod_uid,
                    "gate": "open",
                    "epoch": 0,
                    "activeClaims": [],
                    "close": None,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        }
        record, _ = self._store.reserve_runtime("lifecycle", "slot", job_ref, values)
        return record

    def _cas(self, record: object, payload: Mapping[str, object]) -> object | None:
        values = _values(record)
        resource_version = getattr(record, "resource_version", None)
        if not isinstance(resource_version, str) or not resource_version:
            raise DependencyUnavailableError("lifecycle slot has no resourceVersion")
        return self._store.compare_and_swap_runtime(
            "lifecycle",
            str(getattr(record, "job_ref", "")),
            "slot",
            {
                **values,
                "payload": json.dumps(payload, sort_keys=True, separators=(",", ":")),
            },
            expected_resource_version=resource_version,
        )


def _lifecycle_payload(record: object, job_uid: str, pod_uid: str) -> _LifecyclePayload:
    values = _values(record)
    try:
        payload = json.loads(values["payload"])
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise DependencyUnavailableError("lifecycle slot payload is invalid") from error
    if (
        not isinstance(payload, dict)
        or payload.get("schemaVersion") != _SCHEMA_VERSION
        or payload.get("jobUid") != job_uid
        or payload.get("podUid") != pod_uid
        or payload.get("gate") not in {"open", "closing", "closed"}
        or not isinstance(payload.get("epoch"), int)
        or not isinstance(payload.get("activeClaims"), list)
    ):
        raise DependencyUnavailableError("lifecycle slot binding or schema is invalid")
    claims = payload["activeClaims"]
    if not all(
        isinstance(item, dict)
        and set(item) == {"token", "epoch", "holderIdentity", "intent"}
        and isinstance(item.get("token"), str)
        and bool(item["token"])
        and isinstance(item.get("epoch"), int)
        and isinstance(item.get("holderIdentity"), str)
        and bool(item["holderIdentity"])
        and isinstance(item.get("intent"), dict)
        and set(item["intent"]) == {"kind", "ref", "version"}
        and isinstance(item["intent"].get("kind"), str)
        and bool(item["intent"]["kind"])
        and isinstance(item["intent"].get("ref"), str)
        and bool(item["intent"]["ref"])
        and item["intent"].get("version") == 1
        for item in claims
    ):
        raise DependencyUnavailableError("lifecycle active claims are invalid")
    close = payload.get("close")
    if close is not None:
        if not isinstance(close, dict) or not all(
            isinstance(close.get(key), str) and bool(close[key])
            for key in ("kind", "ref", "digest", "requestSpec", "phase")
        ):
            raise DependencyUnavailableError("lifecycle close identity is invalid")
        legacy_fields = {"kind", "ref", "digest", "requestSpec", "phase"}
        current_fields = legacy_fields | {
            "phaseOrdinal",
            "executorIdentity",
            "executionEpoch",
        }
        if set(close) == legacy_fields:
            close["phaseOrdinal"] = _close_phase_ordinal(str(close["kind"]), str(close["phase"]), 0)
            close["executorIdentity"] = "legacy-unowned"
            close["executionEpoch"] = 0
        elif (
            set(close) != current_fields
            or not isinstance(close.get("phaseOrdinal"), int)
            or int(close["phaseOrdinal"]) < 0
            or not isinstance(close.get("executorIdentity"), str)
            or not close["executorIdentity"]
            or not isinstance(close.get("executionEpoch"), int)
            or int(close["executionEpoch"]) < 0
        ):
            raise DependencyUnavailableError("lifecycle close execution authority is invalid")
    return cast(_LifecyclePayload, payload)


def _close_phase_ordinal(kind: str, phase: str, retained_ordinal: int) -> int:
    phases = {
        "cancel": {
            "accepted": 0,
            "collections_drained": 1,
            "credentials_revoked": 2,
            "agent_stopped": 3,
            "workspace_stopped": 4,
            "succeeded": 5,
        },
        "finalize": {
            "accepted": 0,
            "credentials_revoked": 1,
            "agent_stopped": 2,
            "workspace_stopped": 3,
            "succeeded": 4,
        },
        "delete": {
            "accepted": 0,
            "delete_intent_persisted": 1,
            "credentials_destroyed": 2,
            "job_delete_requested": 3,
            "workload_absent": 4,
            "cleanup_proven": 5,
        },
    }
    if phase == "indeterminate":
        return retained_ordinal
    try:
        return phases[kind][phase]
    except KeyError as error:
        raise DependencyUnavailableError("lifecycle close phase is invalid") from error


@dataclass
class ReconcileReport:
    """Counts from one repeatable reconciliation pass over durable provider reality."""

    scanned: int = 0
    reconciled: int = 0
    indeterminate: int = 0
    deleted: int = 0


def phase_payload(
    state: str,
    observed_at: datetime,
    *,
    output_loss_possible: bool = False,
    resume_from: str | None = None,
    reason: str | None = None,
) -> str:
    payload: dict[str, object] = {
        "state": state,
        "observedAt": observed_at.astimezone(UTC).isoformat(),
        "outputLossPossible": output_loss_possible,
    }
    if resume_from is not None:
        payload["resumeFrom"] = resume_from
    if reason is not None:
        payload["reason"] = reason
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def read_phase(record: object) -> tuple[str, bool, str | None]:
    values = _values(record)
    try:
        payload = json.loads(values["payload"])
    except (KeyError, TypeError, json.JSONDecodeError):
        return "indeterminate", True, None
    if not isinstance(payload, Mapping):
        return "indeterminate", True, None
    state = payload.get("state")
    if not isinstance(state, str) or not state:
        return "indeterminate", True, None
    output_loss = payload.get("outputLossPossible", False)
    if not isinstance(output_loss, bool):
        output_loss = True
    resume = payload.get("resumeFrom")
    return state, output_loss, resume if isinstance(resume, str) else None


def action_snapshot(records: Sequence[object], ref_key: str) -> ActionSnapshot:
    if not records:
        return ActionSnapshot(
            action_ref=None,
            request_digest=None,
            state=ActionState.NOT_REQUESTED,
            observed_at=None,
        )
    record = records[-1]
    values = _values(record)
    try:
        payload = json.loads(values["payload"])
        observed = datetime.fromisoformat(str(payload["observedAt"]).replace("Z", "+00:00"))
        retained_state = payload.get("state")
        state = {
            "succeeded": ActionState.SUCCEEDED,
            "indeterminate": ActionState.INDETERMINATE,
            "failed": ActionState.FAILED,
        }.get(retained_state, ActionState.ACCEPTED)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        state = ActionState.INDETERMINATE
        observed = datetime.now(UTC)
    return ActionSnapshot(
        action_ref=values.get(ref_key) or str(getattr(record, "identity", "slot")),
        request_digest=values.get("identityDigest"),
        state=state,
        observed_at=observed,
    )


def _values(record: object) -> Mapping[str, str]:
    retained = getattr(record, "values", {})
    if not isinstance(retained, Mapping):
        return {}
    return {str(key): str(value) for key, value in retained.items()}
