"""RFC 8785 canonical JSON digest helpers for V2 idempotent mutations."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

import rfc8785
from pydantic import BaseModel


class DigestMismatchError(ValueError):
    """The caller supplied a digest that does not describe the declared payload."""


def _digest_payload(payload: Mapping[str, object] | BaseModel) -> Mapping[str, Any]:
    if isinstance(payload, BaseModel):
        # exclude_unset is intentional: the wire contract says omission is distinct from
        # explicitly selecting a default-valued field.
        return payload.model_dump(mode="json", by_alias=True, exclude_unset=True)
    return payload


def canonical_bytes(payload: Mapping[str, object] | BaseModel) -> bytes:
    """Return the RFC 8785 JCS representation of a mutation payload."""
    return rfc8785.dumps(_digest_payload(payload))


def canonical_digest(payload: Mapping[str, object] | BaseModel) -> str:
    """Return lowercase SHA-256 hex over the RFC 8785 JCS payload bytes."""
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def validate_request_digest(
    identity: str,
    supplied: str,
    payload: Mapping[str, object] | BaseModel,
) -> None:
    """Fail when ``supplied`` is not the canonical digest of ``payload``."""
    expected = canonical_digest(payload)
    if not hmac.compare_digest(supplied, expected):
        raise DigestMismatchError(f"digest mismatch for request identity {identity!r}")
