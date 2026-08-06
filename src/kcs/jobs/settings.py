"""Strict environment settings for the isolated KCS V2 runtime."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_SELECTOR_NAME = re.compile(r"^[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?$")
_SELECTOR_VALUE = re.compile(r"^(?:[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?)?$")

DEFAULT_NAMESPACE = "researchcosmos-v2"
DEFAULT_NODE_SELECTOR = "researchcosmos.io/pool=gpu"
DEFAULT_WORKSPACE_STORAGE_CLASS = "kcs-workspace"


@dataclass(frozen=True, slots=True)
class V2RuntimeSettings:
    """Non-connection runtime configuration plus the fail-closed service token."""

    namespace: str
    node_selector: Mapping[str, str]
    api_mode: str
    service_token: str | None = field(repr=False)
    workspace_storage_class: str = DEFAULT_WORKSPACE_STORAGE_CLASS

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
        workspace_storage_class = environ.get(
            "KCS_V2_WORKSPACE_STORAGE_CLASS", DEFAULT_WORKSPACE_STORAGE_CLASS
        )
        if (
            len(workspace_storage_class) > 63
            or _DNS_LABEL.fullmatch(workspace_storage_class) is None
        ):
            raise ValueError(
                "KCS_V2_WORKSPACE_STORAGE_CLASS must be a Kubernetes DNS label"
            )
        service_token = environ.get("KCS_V2_SERVICE_TOKEN") or None
        if environ.get("KCS_ENV") != "test" and service_token is None:
            raise ValueError("KCS_V2_SERVICE_TOKEN is required outside tests")

        return cls(
            namespace=namespace,
            node_selector=MappingProxyType(selector),
            api_mode=api_mode,
            service_token=service_token,
            workspace_storage_class=workspace_storage_class,
        )


def _parse_selector(raw: str) -> dict[str, str]:
    if not raw:
        raise ValueError("KCS_V2_NODE_SELECTOR cannot be empty")
    parsed: dict[str, str] = {}
    for expression in raw.split(","):
        if expression.count("=") != 1:
            raise ValueError("KCS_V2_NODE_SELECTOR entries must use key=value")
        key, value = expression.split("=", 1)
        if not _valid_selector_key(key) or not _valid_selector_value(value):
            raise ValueError("KCS_V2_NODE_SELECTOR contains an invalid key or value")
        if key in parsed:
            raise ValueError("KCS_V2_NODE_SELECTOR contains a duplicate key")
        parsed[key] = value
    return parsed


def _valid_selector_key(key: str) -> bool:
    if key.count("/") > 1:
        return False
    if "/" in key:
        prefix, name = key.split("/", 1)
        if len(prefix) > 253 or any(
            len(label) > 63 or _DNS_LABEL.fullmatch(label) is None
            for label in prefix.split(".")
        ):
            return False
    else:
        name = key
    return len(name) <= 63 and _SELECTOR_NAME.fullmatch(name) is not None


def _valid_selector_value(value: str) -> bool:
    return len(value) <= 63 and _SELECTOR_VALUE.fullmatch(value) is not None
