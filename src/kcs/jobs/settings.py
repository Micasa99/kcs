"""Strict environment settings for the isolated KCS V2 runtime."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_SELECTOR_NAME = re.compile(r"^[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?$")
_SELECTOR_VALUE = re.compile(r"^(?:[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?)?$")

DEFAULT_NAMESPACE = "researchcosmos-v2"
DEFAULT_NODE_SELECTOR = "researchcosmos.io/pool=gpu"
DEFAULT_WORKSPACE_STORAGE_CLASS = "kcs-workspace"
DEFAULT_PROMETHEUS_URL = "http://kcs-prometheus.kcs-monitoring.svc.cluster.local:9090"
DEFAULT_EVENT_DB_PATH = Path("/var/lib/kcs-v2/events.sqlite3")


@dataclass(frozen=True, slots=True)
class V2RuntimeSettings:
    """Non-connection runtime configuration plus the fail-closed service token."""

    namespace: str
    node_selector: Mapping[str, str]
    api_mode: str
    service_token: str | None = field(repr=False)
    workspace_storage_class: str = DEFAULT_WORKSPACE_STORAGE_CLASS
    prometheus_url: str = DEFAULT_PROMETHEUS_URL
    prometheus_timeout_seconds: float = 3.0
    event_db_path: Path = DEFAULT_EVENT_DB_PATH

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
            raise ValueError("KCS_V2_WORKSPACE_STORAGE_CLASS must be a Kubernetes DNS label")
        service_token = environ.get("KCS_V2_SERVICE_TOKEN") or None
        if environ.get("KCS_ENV") != "test" and service_token is None:
            raise ValueError("KCS_V2_SERVICE_TOKEN is required outside tests")

        prometheus_url = environ.get("KCS_V2_PROMETHEUS_URL", DEFAULT_PROMETHEUS_URL)
        parsed_prometheus = urlsplit(prometheus_url)
        if (
            parsed_prometheus.scheme not in {"http", "https"}
            or not parsed_prometheus.hostname
            or parsed_prometheus.username is not None
            or parsed_prometheus.password is not None
            or parsed_prometheus.query
            or parsed_prometheus.fragment
        ):
            raise ValueError("KCS_V2_PROMETHEUS_URL must be an operator-controlled HTTP(S) URL")
        try:
            prometheus_timeout_seconds = float(
                environ.get("KCS_V2_PROMETHEUS_TIMEOUT_SECONDS", "3")
            )
        except ValueError:
            raise ValueError("KCS_V2_PROMETHEUS_TIMEOUT_SECONDS must be numeric") from None
        if not 0.1 <= prometheus_timeout_seconds <= 30:
            raise ValueError("KCS_V2_PROMETHEUS_TIMEOUT_SECONDS must be between 0.1 and 30")
        event_db_path = Path(
            environ.get(
                "KCS_V2_EVENT_DB_PATH",
                "/tmp/kcs-v2-events.sqlite3"
                if environ.get("KCS_ENV") == "test"
                else str(DEFAULT_EVENT_DB_PATH),
            )
        )
        if not event_db_path.is_absolute():
            raise ValueError("KCS_V2_EVENT_DB_PATH must be absolute")

        return cls(
            namespace=namespace,
            node_selector=MappingProxyType(selector),
            api_mode=api_mode,
            service_token=service_token,
            workspace_storage_class=workspace_storage_class,
            prometheus_url=prometheus_url.rstrip("/"),
            prometheus_timeout_seconds=prometheus_timeout_seconds,
            event_db_path=event_db_path,
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
            len(label) > 63 or _DNS_LABEL.fullmatch(label) is None for label in prefix.split(".")
        ):
            return False
    else:
        name = key
    return len(name) <= 63 and _SELECTOR_NAME.fullmatch(name) is not None


def _valid_selector_value(value: str) -> bool:
    return len(value) <= 63 and _SELECTOR_VALUE.fullmatch(value) is not None
