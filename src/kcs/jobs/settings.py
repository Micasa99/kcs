"""Strict environment settings for the isolated KCS V2 runtime."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_SELECTOR_KEY = re.compile(
    r"^(?:[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?/)?"
    r"[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?$"
)
_SELECTOR_VALUE = re.compile(r"^[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?$")

DEFAULT_NAMESPACE = "researchcosmos-v2"
DEFAULT_NODE_SELECTOR = "researchcosmos.io/pool=gpu"


@dataclass(frozen=True, slots=True)
class V2RuntimeSettings:
    """Non-connection runtime configuration plus the fail-closed service token."""

    namespace: str
    node_selector: Mapping[str, str]
    api_mode: str
    service_token: str | None = field(repr=False)

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> V2RuntimeSettings:
        """Build validated settings without reading process-global environment state."""
        api_mode = environ.get("KCS_API_MODE", "v2")
        if api_mode != "v2":
            raise ValueError("KCS_API_MODE must be 'v2'")

        namespace = environ.get("KCS_V2_NAMESPACE", DEFAULT_NAMESPACE)
        if namespace == "default":
            raise ValueError("namespace 'default' is forbidden for the V2 runtime")
        if len(namespace) > 63 or _DNS_LABEL.fullmatch(namespace) is None:
            raise ValueError("KCS_V2_NAMESPACE must be a Kubernetes DNS label")

        selector = _parse_selector(environ.get("KCS_V2_NODE_SELECTOR", DEFAULT_NODE_SELECTOR))
        service_token = environ.get("KCS_V2_SERVICE_TOKEN") or None
        if environ.get("KCS_ENV") != "test" and service_token is None:
            raise ValueError("KCS_V2_SERVICE_TOKEN is required outside tests")

        return cls(
            namespace=namespace,
            node_selector=MappingProxyType(selector),
            api_mode=api_mode,
            service_token=service_token,
        )


def _parse_selector(raw: str) -> dict[str, str]:
    if not raw:
        raise ValueError("KCS_V2_NODE_SELECTOR cannot be empty")
    parsed: dict[str, str] = {}
    for expression in raw.split(","):
        if expression.count("=") != 1:
            raise ValueError("KCS_V2_NODE_SELECTOR entries must use key=value")
        key, value = expression.split("=", 1)
        if _SELECTOR_KEY.fullmatch(key) is None or _SELECTOR_VALUE.fullmatch(value) is None:
            raise ValueError("KCS_V2_NODE_SELECTOR contains an invalid key or value")
        if key in parsed:
            raise ValueError("KCS_V2_NODE_SELECTOR contains a duplicate key")
        parsed[key] = value
    return parsed
