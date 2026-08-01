"""Fail-closed boundary between legacy debug tools and V2 workloads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

V2_NAMESPACE = "researchcosmos-v2"
V2_MANAGED_LABEL = "researchcosmos.io/managed-by"
V2_MANAGED_VALUE = "v2-attempt-runtime"
V2_EXCLUSION_SELECTOR = f"{V2_MANAGED_LABEL}!={V2_MANAGED_VALUE}"
LEGACY_TARGET_FORBIDDEN_MESSAGE = "Legacy debug access to V2 managed workloads is forbidden"


class LegacyTargetForbiddenError(PermissionError):
    """A safe, metadata-free refusal for every legacy debug surface."""

    def __init__(self) -> None:
        super().__init__(LEGACY_TARGET_FORBIDDEN_MESSAGE)


def assert_legacy_target_allowed(pod_metadata: object) -> None:
    """Reject a V2 namespace or managed label without exposing target metadata."""
    metadata = _value(pod_metadata, "metadata", pod_metadata)
    namespace = _value(metadata, "namespace")
    labels = _value(metadata, "labels", {})
    if namespace == V2_NAMESPACE or (
        isinstance(labels, Mapping) and labels.get(V2_MANAGED_LABEL) == V2_MANAGED_VALUE
    ):
        raise LegacyTargetForbiddenError()


def _value(source: object, name: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)
