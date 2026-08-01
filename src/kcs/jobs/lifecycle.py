"""Small durable helpers for cancel/delete phases and startup reconciliation."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from .contracts import ActionSnapshot, ActionState


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
