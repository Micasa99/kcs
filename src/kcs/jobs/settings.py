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
DEFAULT_NATIVE_PROVISION_SECONDS = 900
DEFAULT_NATIVE_CAPTURE_SECONDS = 900
DEFAULT_NATIVE_FINALIZE_SECONDS = 300


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
    native_recipe_registry_path: Path | None = None
    native_openvscode_image_volume: str | None = None
    native_dev_session_relay_image: str | None = None
    model_gateway_openai_base_url: str | None = None
    model_gateway_anthropic_base_url: str | None = None
    native_provision_seconds: int = DEFAULT_NATIVE_PROVISION_SECONDS
    native_capture_seconds: int = DEFAULT_NATIVE_CAPTURE_SECONDS
    native_finalize_seconds: int = DEFAULT_NATIVE_FINALIZE_SECONDS

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

        recipe_path_raw = environ.get("KCS_V2_NATIVE_RECIPE_REGISTRY")
        native_recipe_registry_path = Path(recipe_path_raw) if recipe_path_raw else None
        if (
            native_recipe_registry_path is not None
            and not native_recipe_registry_path.is_absolute()
        ):
            raise ValueError("KCS_V2_NATIVE_RECIPE_REGISTRY must be absolute")

        native_openvscode_image_volume = _optional_image_digest(
            environ.get("KCS_V2_OPENVSCODE_IMAGE_VOLUME"),
            "KCS_V2_OPENVSCODE_IMAGE_VOLUME",
        )
        native_dev_session_relay_image = _optional_image_digest(
            environ.get("KCS_V2_DEV_SESSION_RELAY_IMAGE"),
            "KCS_V2_DEV_SESSION_RELAY_IMAGE",
        )
        if (native_openvscode_image_volume is None) != (
            native_dev_session_relay_image is None
        ):
            raise ValueError(
                "KCS_V2_OPENVSCODE_IMAGE_VOLUME and KCS_V2_DEV_SESSION_RELAY_IMAGE "
                "must be configured together"
            )

        openai_base = _optional_https_url(
            environ.get("KCS_V2_MODEL_GATEWAY_OPENAI_BASE_URL"),
            "KCS_V2_MODEL_GATEWAY_OPENAI_BASE_URL",
        )
        anthropic_base = _optional_https_url(
            environ.get("KCS_V2_MODEL_GATEWAY_ANTHROPIC_BASE_URL"),
            "KCS_V2_MODEL_GATEWAY_ANTHROPIC_BASE_URL",
        )
        native_provision_seconds = _bounded_seconds(
            environ.get("KCS_V2_NATIVE_PROVISION_SECONDS", str(DEFAULT_NATIVE_PROVISION_SECONDS)),
            "KCS_V2_NATIVE_PROVISION_SECONDS",
        )
        native_capture_seconds = _bounded_seconds(
            environ.get("KCS_V2_NATIVE_CAPTURE_SECONDS", str(DEFAULT_NATIVE_CAPTURE_SECONDS)),
            "KCS_V2_NATIVE_CAPTURE_SECONDS",
        )
        native_finalize_seconds = _bounded_seconds(
            environ.get("KCS_V2_NATIVE_FINALIZE_SECONDS", str(DEFAULT_NATIVE_FINALIZE_SECONDS)),
            "KCS_V2_NATIVE_FINALIZE_SECONDS",
        )

        return cls(
            namespace=namespace,
            node_selector=MappingProxyType(selector),
            api_mode=api_mode,
            service_token=service_token,
            workspace_storage_class=workspace_storage_class,
            prometheus_url=prometheus_url.rstrip("/"),
            prometheus_timeout_seconds=prometheus_timeout_seconds,
            event_db_path=event_db_path,
            native_recipe_registry_path=native_recipe_registry_path,
            native_openvscode_image_volume=native_openvscode_image_volume,
            native_dev_session_relay_image=native_dev_session_relay_image,
            model_gateway_openai_base_url=openai_base,
            model_gateway_anthropic_base_url=anthropic_base,
            native_provision_seconds=native_provision_seconds,
            native_capture_seconds=native_capture_seconds,
            native_finalize_seconds=native_finalize_seconds,
        )


def _optional_https_url(raw: str | None, name: str) -> str | None:
    if raw is None:
        return None
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{name} must be an operator-controlled HTTPS URL")
    return raw.rstrip("/")


def _optional_image_digest(raw: str | None, name: str) -> str | None:
    if raw is None:
        return None
    if re.fullmatch(r".+@sha256:[0-9a-f]{64}", raw) is None:
        raise ValueError(f"{name} must be an exact OCI image digest")
    return raw


def _bounded_seconds(raw: str, name: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer") from None
    if not 1 <= value <= 86400:
        raise ValueError(f"{name} must be between 1 and 86400")
    return value


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
