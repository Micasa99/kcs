#!/usr/bin/env python3
"""Validate and generate deterministic KCS V2 OpenAPI review artifacts."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import re
import tempfile
import unicodedata
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, NamedTuple

import rfc8785
import yaml
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError
from openapi_spec_validator import validate

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "openapi" / "kcs-v2-jobs.openapi.yaml"
DEFAULT_OUTPUT = ROOT / "openapi" / "generated"
DEFAULT_PACKAGE_RESOURCE = ROOT / "src" / "kcs" / "openapi" / "kcs-v2-jobs.openapi.json"
HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}
EXCHANGE_FIELDS = {
    "scenario",
    "operationId",
    "request",
    "response",
    "replayOf",
    "conflictsWith",
}
REQUEST_EXAMPLE_FIELDS = {
    "path",
    "query",
    "headers",
    "contentType",
    "body",
    "bodyFixture",
    "bodyFile",
    "bodyPatch",
}
RESPONSE_EXAMPLE_FIELDS = {
    "status",
    "headers",
    "contentType",
    "body",
    "bodyFixture",
    "bodyFile",
    "bodyPatch",
}
NO_STORE_OPERATION_IDS = {
    "grantCredential",
    "inspectCredentialGrant",
    "grantRunnerCredential",
    "inspectRunnerCredentialGrant",
    "putTransferContent",
    "getTransferContent",
    "getCanonicalOpenApi",
    "getNvidiaTelemetry",
    "createTerminalSession",
    "inspectTerminalSession",
    "writeTerminalInput",
    "readTerminalOutput",
    "resizeTerminalSession",
    "closeTerminalSession",
    "resolveRuntimeAssembly",
    "createLiveWorkspaceSnapshot",
    "inspectLiveWorkspaceSnapshot",
    "releaseLiveWorkspaceSnapshot",
    "readLiveWorkspaceContent",
    "getLiveWorkspaceDiff",
    "createDevSession",
    "inspectDevSession",
    "renewDevSession",
    "revokeDevSession",
    "relayDevSession",
}
MUTATION_OPERATION_IDS = {
    "createJob",
    "grantCredential",
    "startAgent",
    "grantRunnerCredential",
    "startRunner",
    "stopRunner",
    "registerTransfer",
    "putTransferContent",
    "cancelTransfer",
    "discardTransfer",
    "invokeWorkspace",
    "finalizeJob",
    "cancelJob",
    "deleteJob",
    "createTerminalSession",
    "createLiveWorkspaceSnapshot",
    "createDevSession",
    "renewDevSession",
}
OPERATION_AUTHORIZATION = {
    "getCapacity": "v2-reader",
    "getQueue": "v2-reader",
    "getNodeTelemetry": "v2-reader",
    "getRuntimeEvents": "v2-reader",
    "getObservabilityHealth": "v2-reader",
    "createJob": "v2-mutator",
    "listJobs": "v2-reader",
    "inspectJob": "v2-reader",
    "deleteJob": "v2-mutator",
    "getRoleLogs": "v2-reader",
    "grantCredential": "v2-private-credential-writer",
    "inspectCredentialGrant": "v2-reader",
    "startAgent": "v2-mutator",
    "grantRunnerCredential": "v2-private-credential-writer",
    "inspectRunnerCredentialGrant": "v2-reader",
    "startRunner": "v2-mutator",
    "stopRunner": "v2-mutator",
    "resolveRuntimeRecipe": "v2-reader",
    "registerTransfer": "v2-mutator",
    "inspectTransfer": "v2-reader",
    "discardTransfer": "v2-mutator",
    "putTransferContent": "v2-mutator",
    "getTransferContent": "v2-reader",
    "cancelTransfer": "v2-mutator",
    "invokeWorkspace": "v2-mutator",
    "inspectWorkspaceOperation": "v2-reader",
    "finalizeJob": "v2-mutator",
    "cancelJob": "v2-mutator",
    "getCanonicalOpenApi": "v2-reader",
    "getNvidiaTelemetry": "v2-reader",
    "createTerminalSession": "v2-mutator",
    "inspectTerminalSession": "v2-reader",
    "writeTerminalInput": "v2-mutator",
    "readTerminalOutput": "v2-reader",
    "resizeTerminalSession": "v2-mutator",
    "closeTerminalSession": "v2-mutator",
    "resolveRuntimeAssembly": "v2-reader",
    "createLiveWorkspaceSnapshot": "v2-mutator",
    "inspectLiveWorkspaceSnapshot": "v2-reader",
    "releaseLiveWorkspaceSnapshot": "v2-mutator",
    "readLiveWorkspaceContent": "v2-reader",
    "getLiveWorkspaceDiff": "v2-reader",
    "createDevSession": "v2-mutator",
    "inspectDevSession": "v2-reader",
    "renewDevSession": "v2-mutator",
    "revokeDevSession": "v2-mutator",
    "relayDevSession": "v2-reader",
}
EXPECTED_OPERATION_LOCATIONS = {
    "getCapacity": ("get", "/api/v2/capacity"),
    "getQueue": ("get", "/api/v2/queue"),
    "getNodeTelemetry": ("get", "/api/v2/telemetry/nodes"),
    "getRuntimeEvents": ("get", "/api/v2/events"),
    "getObservabilityHealth": ("get", "/api/v2/healthz"),
    "createJob": ("post", "/api/v2/jobs"),
    "listJobs": ("get", "/api/v2/jobs"),
    "inspectJob": ("get", "/api/v2/jobs/{jobRef}"),
    "deleteJob": ("delete", "/api/v2/jobs/{jobRef}"),
    "getRoleLogs": ("get", "/api/v2/jobs/{jobRef}/logs"),
    "grantCredential": ("post", "/api/v2/jobs/{jobRef}/agent/credential-grants"),
    "inspectCredentialGrant": (
        "get",
        "/api/v2/jobs/{jobRef}/agent/credential-grants/{credentialGrantRef}",
    ),
    "startAgent": ("post", "/api/v2/jobs/{jobRef}/agent/start"),
    "grantRunnerCredential": (
        "post",
        "/api/v2/jobs/{jobRef}/runner/credential-grants",
    ),
    "inspectRunnerCredentialGrant": (
        "get",
        "/api/v2/jobs/{jobRef}/runner/credential-grants/{credentialGrantRef}",
    ),
    "startRunner": ("post", "/api/v2/jobs/{jobRef}/runner/start"),
    "stopRunner": ("post", "/api/v2/jobs/{jobRef}/runner/stop"),
    "resolveRuntimeRecipe": ("get", "/api/v2/runtime-recipes/resolve"),
    "registerTransfer": ("post", "/api/v2/jobs/{jobRef}/transfers"),
    "inspectTransfer": ("get", "/api/v2/jobs/{jobRef}/transfers/{transferRef}"),
    "discardTransfer": ("delete", "/api/v2/jobs/{jobRef}/transfers/{transferRef}"),
    "putTransferContent": (
        "put",
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
    ),
    "getTransferContent": (
        "get",
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
    ),
    "cancelTransfer": (
        "post",
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}/cancel",
    ),
    "invokeWorkspace": ("post", "/api/v2/jobs/{jobRef}/workspace/invoke"),
    "inspectWorkspaceOperation": (
        "get",
        "/api/v2/jobs/{jobRef}/operations/{operationRef}",
    ),
    "finalizeJob": ("post", "/api/v2/jobs/{jobRef}/finalize"),
    "cancelJob": ("post", "/api/v2/jobs/{jobRef}/cancel"),
    "getCanonicalOpenApi": ("get", "/api/v2/openapi.json"),
    "getNvidiaTelemetry": ("get", "/api/v2/jobs/{jobRef}/telemetry/nvidia"),
    "createTerminalSession": (
        "post",
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions",
    ),
    "inspectTerminalSession": (
        "get",
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}",
    ),
    "writeTerminalInput": (
        "post",
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}/input",
    ),
    "readTerminalOutput": (
        "get",
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}/output",
    ),
    "resizeTerminalSession": (
        "post",
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}/resize",
    ),
    "closeTerminalSession": (
        "delete",
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}",
    ),
    "resolveRuntimeAssembly": ("post", "/api/v2/runtime-assemblies/resolve"),
    "createLiveWorkspaceSnapshot": (
        "post",
        "/api/v2/jobs/{jobRef}/workspace/live-snapshots",
    ),
    "inspectLiveWorkspaceSnapshot": (
        "get",
        "/api/v2/jobs/{jobRef}/workspace/live-snapshots/{snapshotRef}",
    ),
    "releaseLiveWorkspaceSnapshot": (
        "delete",
        "/api/v2/jobs/{jobRef}/workspace/live-snapshots/{snapshotRef}",
    ),
    "readLiveWorkspaceContent": (
        "get",
        "/api/v2/jobs/{jobRef}/workspace/live-snapshots/{snapshotRef}/content",
    ),
    "getLiveWorkspaceDiff": (
        "get",
        "/api/v2/jobs/{jobRef}/workspace/live-snapshots/{snapshotRef}/diff",
    ),
    "createDevSession": ("post", "/api/v2/jobs/{jobRef}/dev-sessions"),
    "inspectDevSession": (
        "get",
        "/api/v2/jobs/{jobRef}/dev-sessions/{devSessionRef}",
    ),
    "renewDevSession": (
        "post",
        "/api/v2/jobs/{jobRef}/dev-sessions/{devSessionRef}/renew",
    ),
    "revokeDevSession": (
        "delete",
        "/api/v2/jobs/{jobRef}/dev-sessions/{devSessionRef}",
    ),
    "relayDevSession": (
        "get",
        "/api/v2/jobs/{jobRef}/dev-sessions/{devSessionRef}/relay",
    ),
}
EXPECTED_ROOT_FEATURES = {
    "transferModes": ["direct"],
    "rangeRequests": False,
    "signedTransfers": False,
    "nativeRunner": True,
    "liveWorkspaceSnapshots": True,
    "devSessionRelay": "openvscode",
    "exactCapabilityActivation": True,
    "runtimeRecipeDeliveryModes": ["assembled", "prebuilt"],
    "runtimeRecipeDeliveryDefault": "assembled.imageVolume",
}
EXPECTED_ROOT_LIMITS = {
    "refUtf8Bytes": 256,
    "environmentEntries": 32,
    "environmentKeyUtf8Bytes": 64,
    "environmentValueUtf8Bytes": 2048,
    "launchBundleBytes": 1048576,
    "credentialBytes": 65536,
    "operationStdoutBytes": 65536,
    "operationStderrBytes": 65536,
    "logsDefaultBytes": 65536,
    "logsMaximumBytes": 1048576,
    "directTransferBytes": 107374182400,
    "paginationDefault": 50,
    "paginationMaximum": 200,
    "tombstoneRetentionSeconds": 604800,
    "credentialTtlDefaultSeconds": 300,
    "credentialTtlMaximumSeconds": 900,
    "liveSnapshotMaximumEntries": 2000,
    "liveSnapshotMaximumBytes": 16777216,
    "liveContentRangeMaximumBytes": 1048576,
    "liveSnapshotTtlMaximumSeconds": 300,
    "devSessionTtlMaximumSeconds": 900,
    "devSessionMaximumConnections": 4,
}
CANONICAL_X_KCS_POLICY_SHA256 = "57f103f71fa3ca7fdf6f38f231900b1ab7d2689d42695d635c60ca2187cfb2bb"
CANONICAL_OPENAPI_SHA256 = "a4aab79cbc56060928b1f04a1e36b49fa17e77c6eed44e1ef60aba03c4b20408"
LOWER_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
REQUIRED_SCENARIOS = {
    "create-new",
    "create-replay",
    "create-conflict",
    "create-tombstone",
    "binding-inspect",
    "list-page",
    "logs-continuation",
    "grant-new",
    "grant-replay",
    "grant-acknowledged",
    "grant-destroyed",
    "start-new",
    "start-replay",
    "start-next-generation",
    "start-pod-loss",
    "transfer-stage",
    "transfer-stage-content",
    "transfer-collect",
    "transfer-collect-content",
    "transfer-collect-completed",
    "transfer-cancel",
    "transfer-discard",
    "transfer-restart",
    "invoke-new",
    "invoke-result-transfer",
    "invoke-inline-result",
    "invoke-indeterminate",
    "finalize-provider-quiesce",
    "cancel-output-loss",
    "delete-tombstone",
    "terminal-create",
    "typed-error",
    "m2-live-snapshot",
    "m2-live-snapshot-stale",
    "m2-log-cursor-gap",
    "m2-dev-session-revoked",
    "m2-capability-incompatible",
}
SECRET_VALUE = re.compile(
    r"(?ix)("
    r"(?:authorization|bearer|cookie|api[_-]?key|token|secret|credential)(?:\s+|\s*[:=])"
    r"|-----BEGIN\x20(?:[A-Z0-9]+\x20)*(?:PRIVATE\x20KEY|CERTIFICATE)-----"
    r"|(?:ssh-(?:rsa|ed25519)|kubeconfig|serviceaccount)"
    r"|[\"']?(?:client-(?:key|certificate)(?:-data)?|certificate-authority(?:-data)?|current-context)[\"']?\s*:"
    r"|[\"']?apiVersion[\"']?\s*:\s*[\"']?v1[\"']?[\s\S]{0,512}"
    r"[\"']?kind[\"']?\s*:\s*[\"']?Config[\"']?"
    r"|[\"']?kind[\"']?\s*:\s*[\"']?Config[\"']?[\s\S]{0,512}"
    r"[\"']?apiVersion[\"']?\s*:\s*[\"']?v1[\"']?"
    r"|[a-z][a-z0-9+.-]*://[^/@\s]+@"
    r")"
)
UNSAFE_PATH_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
SENSITIVE_ARTIFACT_KEYS = {
    "auth",
    "authorization",
    "token",
    "serviceaccounttoken",
    "secret",
    "credential",
    "bearertoken",
    "accesstoken",
    "refreshtoken",
    "apikey",
    "cookie",
    "password",
    "clientsecret",
    "privatekey",
    "providerkey",
    "sshkey",
    "sshprivatekey",
    "sshuser",
    "identityfile",
    "sshpath",
    "privatehost",
    "clientkey",
    "clientkeydata",
    "clientcertificate",
    "clientcertificatedata",
    "certificateauthority",
    "certificateauthoritydata",
    "currentcontext",
}
ARTIFACT_PRIVATE_PATH = re.compile(
    r"(?ix)(?:"
    r"(?<![A-Za-z0-9])~[/\\]"
    r"|(?<![A-Za-z0-9])/(?:Users|home)/[^/\\\s]+(?:[/\\]|$)"
    r"|(?<![A-Za-z0-9])/(?:root|var/root)(?:[/\\]|$)"
    r"|(?<![A-Za-z0-9])[A-Z]:[/\\]Users[/\\][^/\\\s]+(?:[/\\]|$)"
    r"|(?:^|[/\\])\.kube[/\\]config(?:\b|$)"
    r"|\bIdentityFile\s+\S+"
    r")"
)
ARTIFACT_PRIVATE_HOST = re.compile(
    r"(?i)(?<![A-Za-z0-9-])(?:"
    r"(?:[A-Za-z0-9-]+\.)+(?:internal|local|lan)|"
    r"(?:[A-Za-z0-9-]+\.)*localhost"
    r")(?:\.(?=$|[:/\s]))?(?![A-Za-z0-9.-])|\bHostName\s+\S+"
)
ARTIFACT_AUTH_VALUE = re.compile(
    r"(?ix)(?:"
    r"\b(?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic)\s+\S+"
    r"|\bbearer\s+[A-Za-z0-9._~+/=-]{4,}"
    r"|\b(?:cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|password|client[_-]?secret)"
    r"\s*[:=]\s*[^\s,;}]+"
    r"|-----BEGIN\x20(?:[A-Z0-9]+\x20)*PRIVATE\x20KEY-----"
    r"|[a-z][a-z0-9+.-]*://[^/@\s]+@"
    r")"
)
ARTIFACT_IP_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![0-9A-Fa-f:.])"
)
ARTIFACT_IPV4_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f:.])\d{1,3}(?:\.\d{1,3}){3}(?![0-9A-Za-z.])")
ARTIFACT_MIXED_IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"\d{1,3}(?:\.\d{1,3}){3}(?![0-9A-Fa-f:.])"
)
PRIVATE_ARTIFACT_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/32",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::/128",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)


class OpenAPIArtifactSet(NamedTuple):
    openapi_json: Path
    checksum: Path
    component_schemas: tuple[Path, ...]
    sha256: str
    validated_examples: int


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses ambiguous duplicate mapping keys."""


def _load_json_text(value: str, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"{label}: duplicate JSON key {key!r}")
            result[key] = item
        return result

    try:
        return json.loads(value, object_pairs_hook=unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label}: invalid JSON") from exc


def _contains_private_network(value: str) -> bool:
    matches = (
        match.group()
        for pattern in (
            ARTIFACT_IP_CANDIDATE,
            ARTIFACT_IPV4_CANDIDATE,
            ARTIFACT_MIXED_IPV6_CANDIDATE,
        )
        for match in pattern.finditer(value)
    )
    for candidate in matches:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if any(address in network for network in PRIVATE_ARTIFACT_NETWORKS):
            return True
    return False


def _validate_artifact_hygiene(value: Any, label: str, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            if normalized in SENSITIVE_ARTIFACT_KEYS:
                raise ValueError(f"{label}: artifact hygiene forbids sensitive key at {path}.{key}")
            _validate_artifact_hygiene(child, label, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_artifact_hygiene(child, label, f"{path}[{index}]")
        return
    if not isinstance(value, str):
        return
    if (
        ARTIFACT_PRIVATE_PATH.search(value)
        or ARTIFACT_PRIVATE_HOST.search(value)
        or ARTIFACT_AUTH_VALUE.search(value)
        or SECRET_VALUE.search(value)
        or _contains_private_network(value)
    ):
        raise ValueError(f"{label}: artifact hygiene forbids private material at {path}")


def _validate_binary_artifact_hygiene(value: bytes, label: str) -> None:
    decoded = value.decode("utf-8", errors="ignore")
    if not value.startswith(b"synthetic-") or (
        ARTIFACT_PRIVATE_PATH.search(decoded)
        or ARTIFACT_PRIVATE_HOST.search(decoded)
        or ARTIFACT_AUTH_VALUE.search(decoded)
        or SECRET_VALUE.search(decoded)
        or "-----BEGIN OPENSSH PRIVATE KEY-----" in decoded
        or _contains_private_network(decoded)
    ):
        raise ValueError(f"{label}: artifact hygiene forbids private binary material")


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _load_yaml(source: Path) -> dict[str, Any]:
    try:
        document = yaml.load(source.read_text(), Loader=_UniqueKeyLoader)
    except ValueError:
        raise
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML document: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{source} must contain an OpenAPI object")
    return document


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def jcs_sha256(value: Any) -> str:
    """Return lowercase SHA-256 of RFC 8785 canonical JSON bytes."""
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def jcs_projection_sha256(value: Mapping[str, Any], projection: str) -> str:
    """Hash one explicitly named payload projection, excluding sibling identity."""
    if projection not in value:
        raise ValueError(f"missing digest projection {projection!r}")
    return jcs_sha256(value[projection])


def _resolve_pointer(document: Any, ref: str) -> Any:
    if not ref.startswith("#/"):
        raise ValueError(f"only internal OpenAPI references are allowed: {ref}")
    current = document
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError) as exc:
                raise ValueError(f"dangling OpenAPI reference {ref}") from exc
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise ValueError(f"dangling OpenAPI reference {ref}")
    return current


def _iter_values(value: Any) -> Iterable[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _iter_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_values(child)


def _validate_references(document: dict[str, Any]) -> None:
    for value in _iter_values(document):
        if isinstance(value, dict) and "$ref" in value:
            ref = value["$ref"]
            if not isinstance(ref, str):
                raise ValueError(f"invalid OpenAPI reference {ref!r}")
            _resolve_pointer(document, ref)


def _dereference(document: dict[str, Any], value: Any) -> Any:
    seen: set[str] = set()
    while isinstance(value, dict) and "$ref" in value:
        ref = value["$ref"]
        if ref in seen:
            raise ValueError(f"cyclic OpenAPI reference {ref}")
        seen.add(ref)
        value = _resolve_pointer(document, ref)
    return value


def _component_bundle(name: str, schemas: dict[str, Any]) -> dict[str, Any]:
    def rewrite(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: (
                    item.replace("#/components/schemas/", "#/$defs/")
                    if key == "$ref" and isinstance(item, str)
                    else rewrite(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        return value

    rewritten = {schema_name: rewrite(schema) for schema_name, schema in schemas.items()}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": f"#/$defs/{name}",
        "$defs": rewritten,
    }


def _is_safe_relative_posix_path(value: object) -> bool:
    if not isinstance(value, str) or not value or value.startswith("/"):
        return False
    if (
        "\\" in value
        or any(unicodedata.category(char) in UNSAFE_PATH_CATEGORIES for char in value)
        or unicodedata.normalize("NFC", value) != value
    ):
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} for part in parts)


def _is_non_secret_runtime_value(value: object) -> bool:
    return isinstance(value, str) and SECRET_VALUE.search(value) is None


def _is_canonical_base64url(value: object) -> bool:
    if not isinstance(value, str) or not BASE64URL.fullmatch(value) or len(value) % 4 == 1:
        return False
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return False
    return base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() == value


FORMAT_CHECKER = FormatChecker()
FORMAT_CHECKER.checks("kcs-relative-posix-path")(_is_safe_relative_posix_path)
FORMAT_CHECKER.checks("kcs-non-secret-runtime-value")(_is_non_secret_runtime_value)
FORMAT_CHECKER.checks("kcs-base64url")(_is_canonical_base64url)


def _check_extended_limits(instance: Any, schema: Any, document: dict[str, Any]) -> None:
    if not isinstance(schema, dict):
        return
    schema = _dereference(document, schema)
    choices = schema.get("oneOf", [])
    if choices:
        for choice in choices:
            choice = _dereference(document, choice)
            if instance is None and choice.get("type") == "null":
                return
            candidate_type = choice.get("type")
            if (
                (candidate_type == "object" and isinstance(instance, dict))
                or (candidate_type == "array" and isinstance(instance, list))
                or (candidate_type == "string" and isinstance(instance, str))
                or (candidate_type == "integer" and isinstance(instance, int))
                or "$ref" in choice
            ):
                _check_extended_limits(instance, choice, document)
                return
    if isinstance(instance, str):
        max_utf8 = schema.get("x-kcs-maxUtf8Bytes")
        if max_utf8 is not None and len(instance.encode()) > max_utf8:
            raise ValueError(f"string exceeds {max_utf8} UTF-8 bytes")
        max_decoded = schema.get("x-kcs-maxDecodedBytes")
        if max_decoded is not None:
            try:
                decoded = base64.b64decode(instance, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError("value is not canonical base64") from exc
            if len(decoded) > max_decoded:
                raise ValueError(f"decoded content exceeds {max_decoded} bytes")
    if isinstance(instance, (dict, list)):
        max_canonical = schema.get("x-kcs-maxCanonicalBytes")
        if max_canonical is not None and len(rfc8785.dumps(instance)) > max_canonical:
            raise ValueError(f"canonical JSON exceeds {max_canonical} bytes")
    if isinstance(instance, dict):
        time_ordering = schema.get("x-kcs-time-ordering")
        if time_ordering is not None:
            if (
                not isinstance(time_ordering, list)
                or len(time_ordering) < 2
                or any(not isinstance(field, str) for field in time_ordering)
            ):
                raise ValueError("time ordering extension is invalid")
            try:
                timestamps = [_timestamp_sort_value(instance[field]) for field in time_ordering]
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("time ordering fields must be RFC 3339 timestamps") from exc
            if timestamps != sorted(timestamps):
                raise ValueError(f"time ordering {' <= '.join(time_ordering)} is violated")
        combined = schema.get("x-kcs-combinedMaxItems")
        if isinstance(combined, dict):
            properties = combined.get("properties", [])
            limit = combined.get("limit")
            if isinstance(limit, int) and isinstance(properties, list):
                count = sum(
                    len(instance.get(name, []))
                    for name in properties
                    if isinstance(name, str) and isinstance(instance.get(name, []), list)
                )
                if count > limit:
                    names = " and ".join(str(name) for name in properties)
                    raise ValueError(f"combined {names} exceed {limit} items")
        relations = schema.get("x-kcs-relations", [])
        if isinstance(relations, list):
            for relation in relations:
                if not isinstance(relation, dict) or relation.get("operator") != "<=":
                    continue
                left = relation.get("left")
                right = relation.get("right")
                if left in instance and right in instance and instance[left] > instance[right]:
                    raise ValueError(f"{left} must be <= {right}")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties")
        for key, value in instance.items():
            child_schema = properties.get(key, additional if isinstance(additional, dict) else {})
            _check_extended_limits(value, child_schema, document)
    if isinstance(instance, list) and isinstance(schema.get("items"), dict):
        if schema.get("x-kcs-casefoldUnique") is True:
            folded = [value.casefold() for value in instance if isinstance(value, str)]
            if len(folded) != len(set(folded)):
                raise ValueError("array contains a casefold collision")
        for value in instance:
            _check_extended_limits(value, schema["items"], document)


def _validate_instance(
    instance: Any, schema: dict[str, Any], document: dict[str, Any], label: str
) -> None:
    root_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **schema,
        "components": document["components"],
    }
    try:
        Draft202012Validator(root_schema, format_checker=FORMAT_CHECKER).validate(instance)
        _check_extended_limits(instance, schema, document)
    except ValidationError as exc:
        if exc.validator == "format" and exc.validator_value == "kcs-non-secret-runtime-value":
            raise ValueError(f"{label}: secret-shaped runtimeEnv value is forbidden") from exc
        raise ValueError(f"{label}: {exc}") from exc
    except ValueError as exc:
        raise ValueError(f"{label}: {exc}") from exc


def _fixture_path(examples_dir: Path, value: str, label: str) -> Path:
    candidate = (examples_dir / value).resolve()
    try:
        candidate.relative_to((examples_dir / "fixtures").resolve())
    except ValueError as exc:
        raise ValueError(f"{label}: fixture must be under examples/fixtures") from exc
    if not candidate.is_file():
        raise ValueError(f"{label}: fixture does not exist: {value}")
    return candidate


def _merge_patch(value: Any, patch: Any) -> Any:
    if not isinstance(patch, dict):
        return patch
    result = dict(value) if isinstance(value, dict) else {}
    for key, child in patch.items():
        result[key] = _merge_patch(result.get(key), child)
    return result


def _json_body(section: dict[str, Any], examples_dir: Path, label: str) -> Any:
    has_body = "body" in section
    has_fixture = "bodyFixture" in section
    if has_body == has_fixture:
        raise ValueError(f"{label}: specify exactly one of body or bodyFixture")
    if has_body:
        body = section["body"]
    else:
        path = _fixture_path(examples_dir, section["bodyFixture"], label)
        body = _load_json_text(path.read_text(), f"{label} fixture {path.name}")
    if "bodyPatch" in section:
        if not has_fixture or not isinstance(section["bodyPatch"], dict):
            raise ValueError(f"{label}: bodyPatch requires a JSON bodyFixture")
        body = _merge_patch(body, section["bodyPatch"])
    return body


def _binary_body(section: dict[str, Any], examples_dir: Path, label: str) -> bytes:
    if set(section) & {"body", "bodyFixture", "bodyPatch"}:
        raise ValueError(f"{label}: binary bodies must use bodyFile")
    if "bodyFile" not in section:
        raise ValueError(f"{label}: missing bodyFile")
    return _fixture_path(examples_dir, section["bodyFile"], label).read_bytes()


def _operation_index(document: dict[str, Any]) -> dict[str, tuple[str, str, dict[str, Any]]]:
    result: dict[str, tuple[str, str, dict[str, Any]]] = {}
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        raise ValueError("OpenAPI document paths must be an object")
    for path, path_item in paths.items():
        if not isinstance(path_item, Mapping):
            raise ValueError(f"OpenAPI document path item {path!r} must be an object")
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            if not isinstance(operation, Mapping):
                raise ValueError(
                    f"OpenAPI document operation {method.upper()} {path} must be an object"
                )
            operation_id = operation.get("operationId")
            if not operation_id or operation_id in result:
                raise ValueError(f"OpenAPI document has invalid operationId {operation_id!r}")
            result[operation_id] = (method, path, operation)
    return result


def _required_response_headers(response: Mapping[str, Any], label: str) -> list[str]:
    declared = response.get("headers", {})
    required = response.get("x-kcs-required-headers", [])
    if not isinstance(declared, Mapping):
        raise ValueError(f"{label}: response headers declaration must be an object")
    if not isinstance(required, list) or any(not isinstance(name, str) for name in required):
        raise ValueError(f"{label}: invalid required response header declaration")
    declared_names = list(declared)
    if any(not isinstance(name, str) for name in declared_names):
        raise ValueError(f"{label}: response header names must be strings")
    declared_folded = [name.casefold() for name in declared_names]
    required_folded = [name.casefold() for name in required]
    if (
        len(declared_folded) != len(set(declared_folded))
        or len(required_folded) != len(set(required_folded))
        or any(name not in declared for name in required)
    ):
        raise ValueError(f"{label}: invalid required response header declaration")
    return required


def _validate_response_header_policy(
    document: dict[str, Any],
    operation_id: str,
    operation: Mapping[str, Any],
    status: str,
    response: Mapping[str, Any],
) -> None:
    label = f"{operation_id} response {status}"
    required = set(_required_response_headers(response, label))
    declared = response.get("headers", {})
    expected: dict[str, Any | None] = {}
    cache_control = operation.get("x-kcs-cache-control")
    if operation_id in NO_STORE_OPERATION_IDS and cache_control != "no-store":
        raise ValueError(f"{operation_id}: response header policy must declare no-store")
    if cache_control == "no-store":
        expected["Cache-Control"] = "no-store"
    if operation_id == "getTransferContent" and status == "200":
        expected.update(
            {
                "Content-Length": None,
                "X-Content-SHA256": None,
                "X-KCS-Snapshot-Ref": None,
            }
        )
    if operation_id == "getCanonicalOpenApi" and status == "200":
        expected.update({"ETag": None, "X-KCS-API-Version": "2.5.0"})
    for name, expected_const in expected.items():
        if name not in required or name not in declared:
            raise ValueError(f"{label}: required response header {name} is not declared")
        header = _dereference(document, declared[name])
        if not isinstance(header, Mapping) or not isinstance(header.get("schema"), Mapping):
            raise ValueError(f"{label}: required response header {name} has no schema")
        schema = _dereference(document, header["schema"])
        if expected_const is not None and schema.get("const") != expected_const:
            raise ValueError(f"{label}: required response header {name} has the wrong constant")
    if operation_id == "getTransferContent" and status == "200":
        expected_schemas = {
            "Content-Length": {
                "type": "integer",
                "minimum": 0,
                "maximum": EXPECTED_ROOT_LIMITS["directTransferBytes"],
            },
            "X-Content-SHA256": {"$ref": "#/components/schemas/Sha256"},
            "X-KCS-Snapshot-Ref": {"$ref": "#/components/schemas/OpaqueRef"},
        }
        if any(
            _dereference(document, declared[name]).get("schema") != expected_schema
            for name, expected_schema in expected_schemas.items()
        ):
            raise ValueError(f"{label}: transfer integrity header policy is invalid")
    if operation_id == "getCanonicalOpenApi" and status == "200":
        etag = _dereference(document, declared["ETag"])
        if etag.get("schema") != {
            "type": "string",
            "pattern": "^[0-9a-f]{64}$",
        } or response.get("content") != {
            "application/json": {"schema": {"$ref": "#/components/schemas/OpenApiDocument"}}
        }:
            raise ValueError(f"{label}: canonical discovery integrity policy is invalid")


def _x_kcs_policy_sha256(document: Mapping[str, Any]) -> str:
    projection: dict[str, Any] = {}

    def visit(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            for raw_key, child in value.items():
                key = str(raw_key)
                escaped = key.replace("~", "~0").replace("/", "~1")
                child_path = f"{path}/{escaped}"
                if key.startswith("x-kcs-"):
                    projection[child_path] = child
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}/{index}")

    visit(document, "")
    return jcs_sha256(projection)


def _contract_value(document: Any, path: tuple[str | int, ...]) -> Any:
    value = document
    for segment in path:
        try:
            value = value[segment]
        except (KeyError, IndexError, TypeError):
            return None
    return value


def _validate_limit_carriers(document: Mapping[str, Any]) -> None:
    limits = EXPECTED_ROOT_LIMITS
    carriers: tuple[tuple[tuple[str | int, ...], int], ...] = (
        (("components", "schemas", "OpaqueRef", "maxLength"), limits["refUtf8Bytes"]),
        (
            ("components", "schemas", "Environment", "maxProperties"),
            limits["environmentEntries"],
        ),
        (
            ("components", "schemas", "Environment", "propertyNames", "maxLength"),
            limits["environmentKeyUtf8Bytes"],
        ),
        (
            ("components", "schemas", "Environment", "additionalProperties", "maxLength"),
            limits["environmentValueUtf8Bytes"],
        ),
        (
            (
                "components",
                "schemas",
                "AgentStartRequest",
                "properties",
                "launchBundleSizeBytes",
                "maximum",
            ),
            limits["launchBundleBytes"],
        ),
        (
            (
                "components",
                "schemas",
                "GenerationSnapshot",
                "properties",
                "launchBundleSizeBytes",
                "maximum",
            ),
            limits["launchBundleBytes"],
        ),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}/agent/credential-grants",
                "post",
                "requestBody",
                "content",
                "application/octet-stream",
                "schema",
                "maxLength",
            ),
            limits["credentialBytes"],
        ),
        (
            (
                "components",
                "schemas",
                "WorkspaceOperationSnapshot",
                "properties",
                "stdout",
                "maxLength",
            ),
            limits["operationStdoutBytes"],
        ),
        (
            (
                "components",
                "schemas",
                "WorkspaceOperationSnapshot",
                "properties",
                "stderr",
                "maxLength",
            ),
            limits["operationStderrBytes"],
        ),
        (
            ("components", "parameters", "LogLimit", "schema", "default"),
            limits["logsDefaultBytes"],
        ),
        (
            ("components", "parameters", "LogLimit", "schema", "maximum"),
            limits["logsMaximumBytes"],
        ),
        (
            ("components", "schemas", "RoleLogs", "properties", "content", "maxLength"),
            limits["logsMaximumBytes"],
        ),
        (
            ("components", "parameters", "PageSize", "schema", "default"),
            limits["paginationDefault"],
        ),
        (
            ("components", "parameters", "PageSize", "schema", "maximum"),
            limits["paginationMaximum"],
        ),
        (
            (
                "components",
                "schemas",
                "JobBindingSnapshotList",
                "properties",
                "items",
                "maxItems",
            ),
            limits["paginationMaximum"],
        ),
        (
            (
                "components",
                "schemas",
                "JobBindingSnapshotList",
                "properties",
                "tombstones",
                "maxItems",
            ),
            limits["paginationMaximum"],
        ),
        (
            ("components", "parameters", "CredentialTtlHeader", "schema", "maximum"),
            limits["credentialTtlMaximumSeconds"],
        ),
        (
            (
                "components",
                "schemas",
                "CredentialGrantSnapshot",
                "properties",
                "ttlSeconds",
                "maximum",
            ),
            limits["credentialTtlMaximumSeconds"],
        ),
        (
            (
                "components",
                "schemas",
                "TransferSpec",
                "properties",
                "declaredSizeBytes",
                "maximum",
            ),
            limits["directTransferBytes"],
        ),
        (
            (
                "components",
                "schemas",
                "TransferSpec",
                "properties",
                "authorizedMaxSizeBytes",
                "maximum",
            ),
            limits["directTransferBytes"],
        ),
        (
            (
                "components",
                "schemas",
                "TransferSnapshot",
                "properties",
                "actualSizeBytes",
                "oneOf",
                0,
                "maximum",
            ),
            limits["directTransferBytes"],
        ),
        (
            ("components", "parameters", "ContentLengthHeader", "schema", "maximum"),
            limits["directTransferBytes"],
        ),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
                "put",
                "requestBody",
                "content",
                "application/octet-stream",
                "schema",
                "maxLength",
            ),
            limits["directTransferBytes"],
        ),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
                "get",
                "responses",
                "200",
                "headers",
                "Content-Length",
                "schema",
                "maximum",
            ),
            limits["directTransferBytes"],
        ),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
                "get",
                "responses",
                "200",
                "content",
                "application/octet-stream",
                "schema",
                "maxLength",
            ),
            limits["directTransferBytes"],
        ),
        (
            (
                "components",
                "schemas",
                "LiveWorkspaceSnapshotSpec",
                "properties",
                "maximumEntries",
                "maximum",
            ),
            limits["liveSnapshotMaximumEntries"],
        ),
        (
            (
                "components",
                "schemas",
                "LiveWorkspaceSnapshotSpec",
                "properties",
                "maximumBytes",
                "maximum",
            ),
            limits["liveSnapshotMaximumBytes"],
        ),
        (
            (
                "components",
                "schemas",
                "LiveWorkspaceSnapshotSpec",
                "properties",
                "ttlSeconds",
                "maximum",
            ),
            limits["liveSnapshotTtlMaximumSeconds"],
        ),
        (
            ("components", "parameters", "LiveContentLimit", "schema", "maximum"),
            limits["liveContentRangeMaximumBytes"],
        ),
        (
            (
                "components",
                "schemas",
                "DevSessionCreateSpec",
                "properties",
                "ttlSeconds",
                "maximum",
            ),
            limits["devSessionTtlMaximumSeconds"],
        ),
        (
            (
                "components",
                "schemas",
                "DevSessionSnapshot",
                "properties",
                "maximumConnections",
                "const",
            ),
            limits["devSessionMaximumConnections"],
        ),
    )
    for path, expected in carriers:
        if _contract_value(document, path) != expected:
            raise ValueError(f"limit carrier {'/'.join(map(str, path))} is invalid")

    def verify_extension_pairs(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            for extension in ("x-kcs-maxUtf8Bytes", "x-kcs-maxBytes"):
                if extension in value and value.get("maxLength") != value[extension]:
                    raise ValueError(f"limit carrier {path}/{extension} disagrees with maxLength")
            for key, child in value.items():
                verify_extension_pairs(child, f"{path}/{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                verify_extension_pairs(child, f"{path}/{index}")

    verify_extension_pairs(document, "")


def _validate_format_carriers(document: Mapping[str, Any]) -> None:
    carriers: tuple[tuple[tuple[str | int, ...], str], ...] = (
        (
            ("components", "schemas", "Environment", "additionalProperties", "format"),
            "kcs-non-secret-runtime-value",
        ),
        (("components", "schemas", "SafeRelativePath", "format"), "kcs-relative-posix-path"),
        (("components", "schemas", "OpaqueCursor", "format"), "kcs-base64url"),
        (("components", "schemas", "OpaquePageToken", "format"), "kcs-base64url"),
        (("components", "schemas", "Timestamp", "format"), "date-time"),
        (("components", "schemas", "KubernetesUid", "format"), "uuid"),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}/agent/credential-grants",
                "post",
                "requestBody",
                "content",
                "application/octet-stream",
                "schema",
                "format",
            ),
            "binary",
        ),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
                "put",
                "requestBody",
                "content",
                "application/octet-stream",
                "schema",
                "format",
            ),
            "binary",
        ),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
                "get",
                "responses",
                "200",
                "content",
                "application/octet-stream",
                "schema",
                "format",
            ),
            "binary",
        ),
    )
    for path, expected in carriers:
        if _contract_value(document, path) != expected:
            raise ValueError(f"format carrier {'/'.join(map(str, path))} is invalid")


def _validate_frozen_contract_fingerprints(
    document: Mapping[str, Any], openapi_bytes: bytes | None = None
) -> None:
    if _x_kcs_policy_sha256(document) != CANONICAL_X_KCS_POLICY_SHA256:
        raise ValueError("machine policy extension fingerprint is invalid")
    serialized = _json_bytes(document) if openapi_bytes is None else openapi_bytes
    if hashlib.sha256(serialized).hexdigest() != CANONICAL_OPENAPI_SHA256:
        raise ValueError(
            "standard contract enforcement fingerprint is invalid; bump the API version "
            "and explicitly update the frozen fingerprint"
        )


def _validate_contract_extensions(document: dict[str, Any]) -> None:
    info = document.get("info", {})
    expected_legacy_authorization = {
        "v2NamespaceAccess": "denied",
        "podsExec": "denied",
        "secrets": "denied",
        "mutations": "denied",
    }
    expected_network_boundary = {
        "tlsRequired": True,
        "privateIngressRequired": True,
    }
    if (
        info.get("x-kcs-features") != EXPECTED_ROOT_FEATURES
        or info.get("x-kcs-limits") != EXPECTED_ROOT_LIMITS
        or document.get("x-kcs-contract-status") != "dormant"
        or document.get("x-kcs-legacy-authorization") != expected_legacy_authorization
        or document.get("x-kcs-network-boundary") != expected_network_boundary
    ):
        raise ValueError("root contract policy declaration is invalid")

    security_schemes = document.get("components", {}).get("securitySchemes", {})
    bearer = security_schemes.get("v2ServiceBearer", {})
    if (
        document.get("security") != [{"v2ServiceBearer": []}]
        or set(security_schemes) != {"v2ServiceBearer"}
        or {key: bearer.get(key) for key in ("type", "scheme", "bearerFormat")}
        != {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "opaque service token",
        }
    ):
        raise ValueError("global bearer security policy is invalid")
    if document.get("servers") != [{"url": "/"}]:
        raise ValueError("server security boundary is invalid")

    paths = document.get("paths", {})
    if not isinstance(paths, Mapping):
        raise ValueError("OpenAPI document paths must be an object")
    if "webhooks" in document:
        raise ValueError("webhook route surface is forbidden")
    for path, path_item in paths.items():
        if "servers" in path_item:
            raise ValueError(f"{path}: path server overrides are forbidden")
        unexpected_fields = set(path_item) - HTTP_METHODS - {"parameters"}
        if unexpected_fields:
            raise ValueError(f"{path}: frozen route surface has unexpected path item fields")
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, Mapping):
                continue
            if "servers" in operation:
                raise ValueError(f"{method.upper()} {path}: operation server override is forbidden")
            if "callbacks" in operation:
                raise ValueError(f"{method.upper()} {path}: callback route surface is forbidden")

    operations = _operation_index(document)
    actual_locations = {
        operation_id: (method, path)
        for operation_id, (method, path, _operation) in operations.items()
    }
    expected_paths = {path for _method, path in EXPECTED_OPERATION_LOCATIONS.values()}
    if actual_locations != EXPECTED_OPERATION_LOCATIONS or set(paths) != expected_paths:
        raise ValueError("frozen route surface operation locations are invalid")
    if any("security" in operation for _method, _path, operation in operations.values()):
        raise ValueError("operation security overrides are forbidden")

    expected_credential_privacy = {
        "x-kcs-private-ingress": True,
        "x-kcs-request-body-logging": "forbidden",
        "x-kcs-no-request-body-log": True,
        "x-kcs-redact-headers": [
            "Authorization",
            "KCS-Credential-SHA256",
            "KCS-Grant-Metadata-Digest",
        ],
        "x-kcs-rbac-boundary": "v2-namespace-only",
        "x-kcs-legacy-proxy-access": "denied",
    }
    for operation_id in ("grantCredential", "grantRunnerCredential"):
        credential_operation = operations.get(operation_id, (None, None, {}))[2]
        if any(
            credential_operation.get(key) != value
            for key, value in expected_credential_privacy.items()
        ):
            raise ValueError(f"{operation_id}: credential privacy policy declaration is invalid")

    expected_operation_policies = {
        "createJob": {
            "x-kcs-unknown-outcome-recovery": {
                "operationId": "listJobs",
                "method": "GET",
                "path": "/api/v2/jobs",
                "query": {
                    "providerRequestId": "$request.body#/providerRequestId",
                    "includeDeleted": True,
                },
                "combinedCollections": ["items", "tombstones"],
                "maximumMatches": 1,
                "compareDigest": {
                    "responseField": "specDigest",
                    "requestField": "specDigest",
                },
            }
        },
        "listJobs": {
            "x-kcs-ordering": {
                "strategy": "stable-key-merge",
                "collections": ["items", "tombstones"],
                "keys": ["createdAt", "jobRef"],
                "uniqueIdentities": ["jobRef", "providerRequestId", "jobUid"],
            },
            "x-kcs-page-token-binding": [
                "namespace",
                "providerRequestId",
                "subjectRef",
                "state",
                "createdAfter",
                "includeDeleted",
            ],
        },
        "getRoleLogs": {"x-kcs-cursor-binding": ["namespace", "jobRef", "podUid", "container"]},
        "putTransferContent": {"x-kcs-no-request-body-log": True},
        "invokeWorkspace": {"x-kcs-forward-body-unchanged": True},
        "finalizeJob": {"x-kcs-provider-only-quiesce": True},
    }
    for operation_id, expected_policy in expected_operation_policies.items():
        operation = operations.get(operation_id, (None, None, {}))[2]
        if any(operation.get(key) != value for key, value in expected_policy.items()):
            raise ValueError(f"{operation_id}: operation contract policy is invalid")
    canonical_operation = operations.get("getCanonicalOpenApi", (None, None, {}))[2]
    canonical_response = canonical_operation.get("responses", {}).get("200", {})
    if canonical_response.get("x-kcs-etag-derivation") != {
        "algorithm": "sha256",
        "source": "exact-response-bytes",
        "encoding": "lowercase-hex",
    }:
        raise ValueError("getCanonicalOpenApi: operation contract policy is invalid")

    schemas = document.get("components", {}).get("schemas", {})
    expected_schema_policies = (
        (
            schemas.get("Environment", {}),
            "x-kcs-secret-value-policy",
            "reject-secret-shaped-values",
        ),
        (schemas.get("JobSpec", {}), "x-kcs-default-semantics", "omission-is-distinct"),
        (
            schemas.get("SafeRelativePath", {}),
            "x-kcs-case-policy",
            "preserve-case-reject-casefold-collisions",
        ),
        (
            schemas.get("TransferSpec", {}),
            "x-kcs-path-collision-policy",
            "reject-existing-workspace-casefold-collision",
        ),
        (schemas.get("WorkspaceFrame", {}), "x-kcs-forward-unchanged", True),
        (schemas.get("OpaqueRef", {}), "x-kcs-maxUtf8Bytes", 256),
        (schemas.get("WorkspaceFrame", {}), "x-kcs-maxCanonicalBytes", 1048576),
        (
            schemas.get("WorkspaceOperationSnapshot", {}).get("properties", {}).get("stdout", {}),
            "x-kcs-maxUtf8Bytes",
            65536,
        ),
    )
    if any(schema.get(key) != expected for schema, key, expected in expected_schema_policies):
        raise ValueError("schema contract policy declaration is invalid")
    _validate_limit_carriers(document)
    _validate_format_carriers(document)
    safe_path = schemas.get("SafeRelativePath", {})
    expected_unicode_policy = {
        "normalization": "NFC",
        "rejectedGeneralCategories": ["Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"],
    }
    if safe_path.get("x-kcs-unicode-policy") != expected_unicode_policy:
        raise ValueError("SafeRelativePath Unicode policy declaration is invalid")
    tombstone = schemas.get("JobTombstone", {})
    if tombstone.get("x-kcs-time-ordering") != ["createdAt", "deletedAt", "expiresAt"]:
        raise ValueError("JobTombstone time ordering declaration is invalid")
    if schemas.get("JobBindingSnapshotList", {}).get("x-kcs-combinedMaxItems") != {
        "limit": 200,
        "properties": ["items", "tombstones"],
    }:
        raise ValueError("JobBindingSnapshotList combined limit declaration is invalid")
    if schemas.get("TransferSpec", {}).get("x-kcs-relations") != [
        {
            "left": "declaredSizeBytes",
            "operator": "<=",
            "right": "authorizedMaxSizeBytes",
        }
    ]:
        raise ValueError("TransferSpec size relation declaration is invalid")
    for schema_name in ("AgentStartRequest", "GenerationSnapshot"):
        material_paths = schemas.get(schema_name, {}).get("properties", {}).get("materialPaths", {})
        if material_paths.get("x-kcs-casefoldUnique") is not True:
            raise ValueError(f"{schema_name} material path uniqueness declaration is invalid")
    expected_inline_relation = {
        "canonicalization": "rfc8785-jcs",
        "value": "inlineResult",
        "size": "inlineResultSize",
        "digest": "inlineResultDigest",
        "exclusiveWith": "resultTransferRef",
    }
    if (
        schemas.get("WorkspaceOperationSnapshot", {}).get("x-kcs-inline-result-relation")
        != expected_inline_relation
    ):
        raise ValueError("inline result relation extension is invalid")
    error_codes = set(schemas.get("ErrorCode", {}).get("enum", []))
    recovery_actions = set(schemas.get("RecoveryAction", {}).get("enum", []))
    if set(operations) != set(OPERATION_AUTHORIZATION):
        raise ValueError("service authorization declaration has an unknown operation set")
    for operation_id, (_method, _path, operation) in operations.items():
        if operation.get("x-kcs-service-authorization") != OPERATION_AUTHORIZATION[operation_id]:
            raise ValueError(f"{operation_id}: service authorization declaration is invalid")
        responses = operation.get("responses")
        if not isinstance(responses, Mapping):
            raise ValueError(f"{operation_id}: responses must be an object")
        replay = operation.get("x-kcs-replay")
        digest_projection = operation.get("x-kcs-digest-projection")
        if operation_id in MUTATION_OPERATION_IDS and (
            not isinstance(digest_projection, Mapping) or not isinstance(replay, Mapping)
        ):
            raise ValueError(f"{operation_id}: mutation safety declaration is missing")
        if replay is not None:
            if not isinstance(replay, Mapping) or set(replay) != {
                "newStatus",
                "replayStatus",
                "conflictStatus",
                "conflictCode",
                "recoveryAction",
            }:
                raise ValueError(f"{operation_id}: mutation safety declaration is invalid")
            mapping = operation.get("x-kcs-error-codes", {})
            conflict_code = replay.get("conflictCode")
            rule = mapping.get(conflict_code)
            statuses_are_declared = all(
                not isinstance(replay.get(field), bool)
                and isinstance(replay.get(field), int)
                and str(replay[field]) in responses
                for field in ("newStatus", "replayStatus", "conflictStatus")
            )
            if (
                not statuses_are_declared
                or not isinstance(rule, dict)
                or rule.get("status") != replay.get("conflictStatus")
                or rule.get("recoveryAction") != replay.get("recoveryAction")
            ):
                raise ValueError(
                    f"{operation_id}: replay conflict mapping disagrees with error map"
                )
        error_map = operation.get("x-kcs-error-codes")
        if not isinstance(error_map, Mapping):
            raise ValueError(f"{operation_id}: error map declaration must be an object")
        if error_map.get("UNAUTHENTICATED") != {"status": 401, "recoveryAction": "none"} or (
            error_map.get("FORBIDDEN") != {"status": 403, "recoveryAction": "none"}
        ):
            raise ValueError(f"{operation_id}: authentication error policy is invalid")
        for code, rule in error_map.items():
            if (
                code not in error_codes
                or not isinstance(rule, Mapping)
                or set(rule) != {"status", "recoveryAction"}
                or isinstance(rule.get("status"), bool)
                or not isinstance(rule.get("status"), int)
                or str(rule.get("status")) not in responses
                or rule.get("recoveryAction") not in recovery_actions
            ):
                raise ValueError(f"{operation_id}: error map declaration is invalid")
        declared_error_statuses = {
            str(status) for status in responses if str(status).isdigit() and int(str(status)) >= 400
        }
        mapped_error_statuses = {str(rule["status"]) for rule in error_map.values()}
        if not declared_error_statuses <= mapped_error_statuses:
            raise ValueError(f"{operation_id}: error map declaration omits a response status")
        for status, raw_response in responses.items():
            response = _dereference(document, raw_response)
            if not isinstance(response, Mapping):
                raise ValueError(f"{operation_id} response {status}: response must be an object")
            _validate_response_header_policy(
                document, operation_id, operation, str(status), response
            )


def _parameters(
    document: dict[str, Any], path: str, operation: dict[str, Any]
) -> list[dict[str, Any]]:
    path_parameters = document["paths"][path].get("parameters", [])
    values = [*path_parameters, *operation.get("parameters", [])]
    return [_dereference(document, parameter) for parameter in values]


def _validate_parameter_examples(
    document: dict[str, Any],
    path: str,
    operation: dict[str, Any],
    request: dict[str, Any],
    label: str,
) -> None:
    groups = {
        "path": request.get("path", {}),
        "query": request.get("query", {}),
        "header": request.get("headers", {}),
    }
    declared: dict[str, dict[str, dict[str, Any]]] = {key: {} for key in groups}
    for parameter in _parameters(document, path, operation):
        where = parameter["in"]
        key = "header" if where == "header" else where
        declared[key][parameter["name"]] = parameter
    for where, supplied in groups.items():
        if not isinstance(supplied, dict):
            raise ValueError(f"{label}: request {where} values must be an object")
        unknown = set(supplied) - set(declared[where])
        if unknown:
            raise ValueError(f"{label}: undeclared {where} parameters: {sorted(unknown)}")
        for name, parameter in declared[where].items():
            if parameter.get("required") and name not in supplied:
                raise ValueError(f"{label}: missing required {where} parameter {name}")
        for name, value in supplied.items():
            schema = declared[where][name]["schema"]
            instance = value
            if (
                where == "query"
                and schema.get("type") == "array"
                and declared[where][name].get("style") == "form"
                and declared[where][name].get("explode") is True
                and not isinstance(value, list)
            ):
                instance = [value]
            _validate_instance(instance, schema, document, f"{label} {where} {name}")


def _validate_media(
    document: dict[str, Any],
    content: dict[str, Any],
    section: dict[str, Any],
    examples_dir: Path,
    label: str,
) -> tuple[Any | None, bytes | None]:
    content_type = section.get("contentType")
    if content_type not in content:
        raise ValueError(f"{label}: undeclared content type {content_type!r}")
    schema = content[content_type].get("schema", {})
    if content_type == "application/octet-stream":
        body_bytes = _binary_body(section, examples_dir, label)
        maximum = schema.get("x-kcs-maxBytes", schema.get("maxLength"))
        if maximum is not None and len(body_bytes) > maximum:
            raise ValueError(f"{label}: body exceeds {maximum} bytes")
        return None, body_bytes
    body = _json_body(section, examples_dir, label)
    _validate_instance(body, schema, document, label)
    return body, None


def _validate_section_metadata(
    section: Mapping[str, Any],
    content: Mapping[str, Any] | None,
    label: str,
) -> None:
    body_fields = {"body", "bodyFixture", "bodyFile", "bodyPatch"}
    supplied_body_fields = set(section) & body_fields
    if content is None:
        if "contentType" in section or supplied_body_fields:
            raise ValueError(f"{label}: route exchange metadata supplies an undeclared body")
        return

    content_type = section.get("contentType")
    if not isinstance(content_type, str) or content_type not in content:
        raise ValueError(f"{label}: route exchange metadata has an invalid contentType")
    if content_type == "application/octet-stream":
        if supplied_body_fields != {"bodyFile"}:
            raise ValueError(
                f"{label}: route exchange metadata for binary content requires only bodyFile"
            )
        return

    sources = set(section) & {"body", "bodyFixture"}
    if len(sources) != 1 or "bodyFile" in section:
        raise ValueError(f"{label}: route exchange metadata for JSON must select one body source")
    if "bodyPatch" in section and "bodyFixture" not in section:
        raise ValueError(f"{label}: route exchange metadata bodyPatch requires bodyFixture")


def _validate_exchange_metadata(
    exchange: Mapping[str, Any],
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    request_content: Mapping[str, Any] | None,
    response_content: Mapping[str, Any] | None,
    label: str,
) -> None:
    replay_of = exchange.get("replayOf")
    conflicts_with = exchange.get("conflictsWith")
    if replay_of is not None and not isinstance(replay_of, str):
        raise ValueError(f"{label}: route exchange metadata replayOf must be a string")
    if conflicts_with is not None and not isinstance(conflicts_with, str):
        raise ValueError(f"{label}: route exchange metadata conflictsWith must be a string")
    if replay_of is not None and conflicts_with is not None:
        raise ValueError(
            f"{label}: route exchange metadata cannot set replayOf and conflictsWith together"
        )
    status = response.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        raise ValueError(f"{label}: route exchange metadata status must be an integer")
    _validate_section_metadata(request, request_content, f"{label} request")
    _validate_section_metadata(response, response_content, f"{label} response")


def _header_value(headers: Mapping[str, Any], name: str, label: str) -> Any:
    if name not in headers:
        raise ValueError(f"{label}: missing header {name}")
    return headers[name]


def _assert_digest(actual: str, supplied: object, label: str) -> None:
    if not isinstance(supplied, str) or not LOWER_HEX_SHA256.fullmatch(supplied):
        raise ValueError(f"{label}: digest must be 64 lowercase hex")
    if supplied != actual:
        raise ValueError(f"{label}: digest mismatch; expected {actual}")


def _normalized_wire_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _find_semantic_header(headers: Mapping[str, Any], field: str, label: str) -> Any:
    expected = _normalized_wire_name(field)
    matches = [
        value for name, value in headers.items() if _normalized_wire_name(name).endswith(expected)
    ]
    if len(matches) != 1:
        raise ValueError(f"{label}: missing header carrying {field}")
    return matches[0]


def _projection_value(
    projection: Mapping[str, Any],
    request_body: Any | None,
    request_bytes: bytes | None,
    label: str,
) -> Any:
    source = projection.get("source")
    if source == "constant":
        if "value" not in projection:
            raise ValueError(f"{label}: constant digest projection has no value")
        return projection["value"]
    if source != "requestBody":
        raise ValueError(f"{label}: unsupported digest projection source {source!r}")
    if projection.get("encoding") == "raw-bytes":
        if request_bytes is None:
            raise ValueError(f"{label}: raw-byte digest projection has no request bytes")
        return request_bytes
    if request_body is None:
        raise ValueError(f"{label}: request-body digest projection has no request body")
    if "field" in projection:
        field = projection["field"]
        if not isinstance(request_body, dict) or field not in request_body:
            raise ValueError(f"{label}: digest projection field {field!r} is missing")
        return request_body[field]
    excluded = projection.get("exclude", [])
    if excluded:
        if not isinstance(request_body, dict) or not isinstance(excluded, list):
            raise ValueError(f"{label}: invalid digest projection exclusion")
        return {key: value for key, value in request_body.items() if key not in excluded}
    return request_body


def _projected_digest(
    projection: Mapping[str, Any],
    request_body: Any | None,
    request_bytes: bytes | None,
    label: str,
) -> str:
    value = _projection_value(projection, request_body, request_bytes, label)
    if projection.get("encoding") == "raw-bytes":
        return hashlib.sha256(value).hexdigest()
    return jcs_sha256(value)


def _digest_wire_value(
    field: str,
    location: str,
    request: Mapping[str, Any],
    request_body: Any | None,
    response_body: Any | None,
    response_headers: Mapping[str, Any],
    label: str,
) -> Any | None:
    if location == "body":
        if not isinstance(request_body, dict) or field not in request_body:
            raise ValueError(f"{label}: request body does not carry {field}")
        return request_body[field]
    if location == "header":
        return _find_semantic_header(request.get("headers", {}), field, label)
    if location == "response":
        if isinstance(response_body, dict) and field in response_body:
            return response_body[field]
        return None
    if location == "response-header":
        return _find_semantic_header(response_headers, field, label)
    raise ValueError(f"{label}: unsupported digest location {location!r}")


def _metadata_projection(
    definition: Mapping[str, Any], headers: Mapping[str, Any], label: str
) -> tuple[dict[str, Any], str]:
    projection = definition.get("projection")
    if not isinstance(projection, list) or not projection:
        raise ValueError(f"{label}: metadata digest projection must be a non-empty list")
    metadata: dict[str, Any] = {}
    for item in projection:
        if not isinstance(item, dict) or set(item) != {"field", "header"}:
            raise ValueError(f"{label}: invalid metadata digest projection entry")
        metadata[item["field"]] = _header_value(headers, item["header"], label)
    return metadata, jcs_sha256(metadata)


def _validate_declared_digest_projection(
    operation: Mapping[str, Any],
    request: Mapping[str, Any],
    request_body: Any | None,
    request_bytes: bytes | None,
    response_body: Any | None,
    response_headers: Mapping[str, Any],
    label: str,
) -> None:
    definition = operation.get("x-kcs-digest-projection")
    if definition is None:
        return
    if not isinstance(definition, dict):
        raise ValueError(f"{label}: digest projection extension must be an object")
    projection = definition.get("projection")
    if definition.get("digestOwnership") == "platform":
        if projection is not None:
            raise ValueError(f"{label}: platform-owned digest must not declare a projection")
        supplied = _digest_wire_value(
            definition["digest"],
            definition["digestLocation"],
            request,
            request_body,
            response_body,
            response_headers,
            label,
        )
        if not isinstance(supplied, str) or not LOWER_HEX_SHA256.fullmatch(supplied):
            raise ValueError(f"{label}: platform-owned digest must be 64 lowercase hex")
    else:
        if not isinstance(projection, dict):
            raise ValueError(f"{label}: digest projection is missing")
        actual = _projected_digest(projection, request_body, request_bytes, label)
        supplied = _digest_wire_value(
            definition["digest"],
            definition["digestLocation"],
            request,
            request_body,
            response_body,
            response_headers,
            label,
        )
        if supplied is not None:
            _assert_digest(actual, supplied, label)

    metadata_definition = definition.get("metadataDigest")
    if metadata_definition is not None:
        if not isinstance(metadata_definition, dict):
            raise ValueError(f"{label}: metadata digest definition must be an object")
        _metadata, actual = _metadata_projection(
            metadata_definition, request.get("headers", {}), label
        )
        supplied = _digest_wire_value(
            metadata_definition["field"],
            metadata_definition["digestLocation"],
            request,
            request_body,
            response_body,
            response_headers,
            label,
        )
        if supplied is not None:
            _assert_digest(actual, supplied, label)

    stored_definition = definition.get("storedIntegrityDigest")
    if stored_definition is not None:
        if not isinstance(stored_definition, dict) or not isinstance(
            stored_definition.get("projection"), dict
        ):
            raise ValueError(f"{label}: stored integrity digest projection is invalid")
        actual = _projected_digest(
            stored_definition["projection"], request_body, request_bytes, label
        )
        supplied = _digest_wire_value(
            stored_definition["field"],
            stored_definition["digestLocation"],
            request,
            request_body,
            response_body,
            response_headers,
            label,
        )
        if supplied is not None:
            _assert_digest(actual, supplied, label)


def _requested_resource_echo(
    document: Mapping[str, Any], spec: Mapping[str, Any], role: str
) -> dict[str, int]:
    schema_name = "AgentResources" if role == "agent" else "WorkspaceResources"
    resource_schema = document["components"]["schemas"][schema_name]["properties"]
    supplied = spec[role].get("resources", {})
    values = {
        name: supplied.get(name, definition.get("default"))
        for name, definition in resource_schema.items()
    }
    if role == "agent":
        values["gpu"] = 0
    values["storageGiB"] = spec["sharedWorkspace"]["sizeLimitGiB"]
    return values


def _query_parameter_default(
    document: Mapping[str, Any], operation: Mapping[str, Any], name: str
) -> Any:
    for parameter in operation.get("parameters", []):
        resolved = _dereference(document, parameter)
        if resolved.get("in") == "query" and resolved.get("name") == name:
            return resolved.get("schema", {}).get("default")
    return None


def _timestamp_sort_value(value: str) -> datetime:
    normalized = f"{value[:-1]}+00:00" if value.endswith(("Z", "z")) else value
    return datetime.fromisoformat(normalized)


def _validate_list_response(
    document: Mapping[str, Any],
    operation: Mapping[str, Any],
    request: Mapping[str, Any],
    response_body: Mapping[str, Any],
    label: str,
) -> None:
    query = request.get("query", {})
    items = response_body.get("items", [])
    tombstones = response_body.get("tombstones", [])
    records = [*items, *tombstones]

    include_deleted = query.get(
        "includeDeleted", _query_parameter_default(document, operation, "includeDeleted")
    )
    if tombstones and include_deleted is not True:
        raise ValueError(f"{label}: list response includes tombstones without includeDeleted")

    provider_request_id = query.get("providerRequestId")
    if provider_request_id is not None:
        if any(record.get("providerRequestId") != provider_request_id for record in records):
            raise ValueError(f"{label}: list response does not match providerRequestId filter")
        if len(records) > 1:
            raise ValueError(f"{label}: list response has multiple providerRequestId matches")

    subject_ref = query.get("subjectRef")
    if subject_ref is not None and (
        tombstones or any(item.get("subjectRef") != subject_ref for item in items)
    ):
        raise ValueError(f"{label}: list response does not match subjectRef filter")

    states = query.get("state")
    if states is not None:
        accepted_states = set(states if isinstance(states, list) else [states])
        if any(item.get("bindingState") not in accepted_states for item in items) or any(
            tombstone.get("state") not in accepted_states for tombstone in tombstones
        ):
            raise ValueError(f"{label}: list response does not match state filter")

    created_after = query.get("createdAfter")
    if created_after is not None:
        threshold = _timestamp_sort_value(created_after)
        if any(_timestamp_sort_value(record["createdAt"]) <= threshold for record in records):
            raise ValueError(f"{label}: list response does not match createdAfter filter")

    page_size = query.get("pageSize", _query_parameter_default(document, operation, "pageSize"))
    if not isinstance(page_size, int) or len(records) > page_size:
        raise ValueError(f"{label}: list response exceeds requested pageSize")

    ordering = operation.get("x-kcs-ordering")
    expected_ordering = {
        "strategy": "stable-key-merge",
        "collections": ["items", "tombstones"],
        "keys": ["createdAt", "jobRef"],
        "uniqueIdentities": ["jobRef", "providerRequestId", "jobUid"],
    }
    if ordering != expected_ordering:
        raise ValueError(f"{label}: list response ordering declaration is invalid")
    for field in ordering["uniqueIdentities"]:
        values = [record.get(field) for record in records]
        if len(values) != len(set(values)):
            raise ValueError(f"{label}: duplicate list identity {field}")
    for collection in (items, tombstones):
        keys = [(_timestamp_sort_value(item["createdAt"]), item["jobRef"]) for item in collection]
        if keys != sorted(keys):
            raise ValueError(f"{label}: list response is not deterministically ordered")


def _validate_logs_response(
    document: Mapping[str, Any],
    operation: Mapping[str, Any],
    request: Mapping[str, Any],
    response_body: Mapping[str, Any],
    label: str,
) -> None:
    query = request.get("query", {})
    if response_body.get("container") != query.get("container"):
        raise ValueError(f"{label}: logs response container does not match request")
    if response_body.get("inputCursor") != query.get("cursor"):
        raise ValueError(f"{label}: logs response inputCursor does not match request cursor")
    limit = query.get("limitBytes", _query_parameter_default(document, operation, "limitBytes"))
    if not isinstance(limit, int) or len(response_body.get("content", "").encode()) > limit:
        raise ValueError(f"{label}: logs response exceeds requested limitBytes")


def _validate_workspace_result(
    response_body: Mapping[str, Any], relation: Mapping[str, Any], label: str
) -> None:
    expected_relation = {
        "canonicalization": "rfc8785-jcs",
        "value": "inlineResult",
        "size": "inlineResultSize",
        "digest": "inlineResultDigest",
        "exclusiveWith": "resultTransferRef",
    }
    if relation != expected_relation:
        raise ValueError(f"{label}: inline result relation extension is invalid")
    inline = response_body.get(relation["value"])
    size = response_body.get(relation["size"])
    digest = response_body.get(relation["digest"])
    transfer_ref = response_body.get(relation["exclusiveWith"])
    if inline is None:
        if size is not None or digest is not None:
            raise ValueError(f"{label}: inline result fields are inconsistent")
        return
    canonical = rfc8785.dumps(inline)
    expected_digest = hashlib.sha256(canonical).hexdigest()
    if size != len(canonical) or digest != expected_digest or transfer_ref is not None:
        raise ValueError(f"{label}: inline result fields are inconsistent")


def _validate_digest_semantics(
    document: Mapping[str, Any],
    operation: Mapping[str, Any],
    operation_id: str,
    request: dict[str, Any],
    request_body: Any | None,
    request_bytes: bytes | None,
    response_body: Any | None,
    response_bytes: bytes | None,
    response_headers: Mapping[str, Any],
    label: str,
) -> None:
    headers = request.get("headers", {})
    _validate_declared_digest_projection(
        operation,
        request,
        request_body,
        request_bytes,
        response_body,
        response_headers,
        label,
    )
    if operation_id == "createJob":
        if isinstance(response_body, dict) and "specDigest" in response_body:
            _assert_digest(request_body["specDigest"], response_body["specDigest"], label)
            if response_body.get("providerRequestId") != request_body["providerRequestId"]:
                raise ValueError(f"{label}: response does not echo providerRequestId")
            spec = request_body["spec"]
            expected = {
                "subjectRef": spec["subjectRef"],
                "runtimePlanDigest": spec["runtimePlanDigest"],
            }
            physical_echo_matches = all(
                response_body.get(field) == value for field, value in expected.items()
            )
            for role in ("agent", "workspace"):
                role_snapshot = response_body.get(role)
                physical_echo_matches = physical_echo_matches and isinstance(role_snapshot, dict)
                if isinstance(role_snapshot, dict):
                    physical_echo_matches = physical_echo_matches and role_snapshot.get(
                        "requested"
                    ) == _requested_resource_echo(document, spec, role)
            if not physical_echo_matches:
                raise ValueError(f"{label}: create response does not echo accepted physical spec")
    elif operation_id == "grantCredential":
        raw_digest = hashlib.sha256(request_bytes or b"").hexdigest()
        metadata, metadata_digest = _metadata_projection(
            operation["x-kcs-digest-projection"]["metadataDigest"], headers, label
        )
        if isinstance(response_body, dict):
            expected = {
                "credentialGrantRef": headers["KCS-Credential-Grant-Ref"],
                "credentialSha256": raw_digest,
                "grantMetadataDigest": metadata_digest,
                "jobRef": request.get("path", {}).get("jobRef"),
                **metadata,
            }
            for field, value in expected.items():
                if response_body.get(field) != value:
                    raise ValueError(f"{label}: response does not echo {field}")
    elif operation_id == "startAgent":
        if isinstance(response_body, dict) and "startMetadataDigest" in response_body:
            expected = {
                "jobRef": request.get("path", {}).get("jobRef"),
                **request_body,
            }
            for field, value in expected.items():
                if response_body.get(field) != value:
                    raise ValueError(f"{label}: response does not echo {field}")
    elif operation_id in {
        "registerTransfer",
        "cancelTransfer",
        "finalizeJob",
        "cancelJob",
    }:
        if operation_id == "registerTransfer" and isinstance(response_body, dict):
            expected = {
                "jobRef": request.get("path", {}).get("jobRef"),
                "transferRef": request_body["transferRef"],
                "requestDigest": request_body["requestDigest"],
                "spec": request_body["spec"],
            }
            for field, value in expected.items():
                if response_body.get(field) != value:
                    raise ValueError(f"{label}: response does not echo {field}")
        action_field = {
            "cancelTransfer": "cancelAction",
            "finalizeJob": "finalizeAction",
            "cancelJob": "cancelAction",
        }.get(operation_id)
        if action_field and isinstance(response_body, dict) and action_field in response_body:
            action = response_body[action_field]
            identity_field = "cancelRef" if operation_id != "finalizeJob" else "finalizeRef"
            if action.get("actionRef") != request_body[identity_field]:
                raise ValueError(f"{label}: response does not echo {identity_field}")
            if action.get("requestDigest") != request_body["requestDigest"]:
                raise ValueError(f"{label}: response does not echo requestDigest")
    elif operation_id == "putTransferContent":
        digest = hashlib.sha256(request_bytes or b"").hexdigest()
        byte_count = len(request_bytes or b"")
        if _header_value(headers, "Content-Length", label) != byte_count:
            raise ValueError(f"{label}: Content-Length does not match body bytes")
        if isinstance(response_body, dict):
            if (
                response_body.get("state") != "completed"
                or response_body.get("verified") is not True
                or response_body.get("contentAvailable") is not True
                or response_body.get("completedAt") is None
            ):
                raise ValueError(f"{label}: uploaded transfer must be completed and verified")
            if (
                response_body.get("actualSizeBytes") != byte_count
                or response_body.get("spec", {}).get("declaredSizeBytes") != byte_count
            ):
                raise ValueError(f"{label}: uploaded transfer size does not match body bytes")
            if response_body.get("spec", {}).get("contentSha256") != digest:
                raise ValueError(f"{label}: transfer spec does not bind the uploaded bytes")
            if response_body.get("actualSha256") != digest:
                raise ValueError(f"{label}: response does not echo the actual byte digest")
    elif operation_id in {"discardTransfer", "deleteJob"}:
        digest = _header_value(headers, "KCS-Request-Digest", label)
        if isinstance(response_body, dict):
            if operation_id == "discardTransfer":
                action = response_body.get("discardAction", {})
                if action.get("actionRef") != headers.get("KCS-Discard-Ref"):
                    raise ValueError(f"{label}: response does not echo discardRef")
                if action.get("requestDigest") != digest:
                    raise ValueError(f"{label}: response does not echo requestDigest")
            elif response_body.get("deleteRef") != headers.get("KCS-Delete-Ref"):
                raise ValueError(f"{label}: response does not echo deleteRef")
            elif response_body.get("deleteRequestDigest") != digest:
                raise ValueError(f"{label}: response does not echo requestDigest")
    elif operation_id == "getTransferContent":
        if (
            "X-KCS-Snapshot-Ref" not in response_headers
            or response_headers.get("Cache-Control") != "no-store"
        ):
            raise ValueError(f"{label}: collect response must carry snapshot identity and no-store")
        digest = hashlib.sha256(response_bytes or b"").hexdigest()
        _assert_digest(
            digest,
            _header_value(response_headers, "X-Content-SHA256", label),
            label,
        )
        if _header_value(response_headers, "Content-Length", label) != len(response_bytes or b""):
            raise ValueError(f"{label}: response Content-Length does not match body bytes")
    elif operation_id == "listJobs" and isinstance(response_body, dict):
        _validate_list_response(document, operation, request, response_body, label)
    elif (
        operation_id == "getRoleLogs"
        and isinstance(response_body, dict)
        and _error_code(response_body) is None
    ):
        _validate_logs_response(document, operation, request, response_body, label)
    elif (
        operation_id == "invokeWorkspace"
        and isinstance(response_body, dict)
        and "storedFrameDigest" in response_body
    ):
        if response_body.get("operationRef") != headers.get("KCS-Operation-Ref"):
            raise ValueError(f"{label}: response does not echo operationRef")
        if response_body.get("requestDigest") != headers.get("KCS-Request-Digest"):
            raise ValueError(f"{label}: response does not echo requestDigest")
        expected_binding = {
            "jobUid": headers.get("KCS-Job-UID"),
            "podUid": headers.get("KCS-Pod-UID"),
        }
        if response_body.get("binding") != expected_binding:
            raise ValueError(f"{label}: response does not echo immutable binding")
    if (
        operation_id in {"invokeWorkspace", "inspectWorkspaceOperation"}
        and isinstance(response_body, dict)
        and _error_code(response_body) is None
    ):
        relation = document["components"]["schemas"]["WorkspaceOperationSnapshot"].get(
            "x-kcs-inline-result-relation", {}
        )
        _validate_workspace_result(response_body, relation, label)


def _error_code(response_body: Any) -> Any:
    if isinstance(response_body, dict):
        error = response_body.get("error")
        if isinstance(error, dict):
            return error.get("code")
    return None


def _validate_error_semantics(
    operation: Mapping[str, Any],
    status: str,
    request: Mapping[str, Any],
    response_body: Any,
    label: str,
) -> None:
    if not isinstance(response_body, Mapping) or not isinstance(
        response_body.get("error"), Mapping
    ):
        return
    error = response_body["error"]
    code = error.get("code")
    rule = operation.get("x-kcs-error-codes", {}).get(code)
    if (
        not isinstance(rule, Mapping)
        or str(rule.get("status")) != status
        or error.get("recoveryAction") != rule.get("recoveryAction")
    ):
        raise ValueError(f"{label}: response does not match operation error map")
    context = error.get("context", {})
    if not isinstance(context, Mapping):
        return
    for field in (
        "jobRef",
        "credentialGrantRef",
        "transferRef",
        "operationRef",
        "snapshotRef",
        "devSessionRef",
    ):
        expected = request.get("path", {}).get(field)
        if expected is not None and context.get(field) is not None and context[field] != expected:
            raise ValueError(f"{label}: error context does not match request path {field}")


def _validate_response_identity(request: Mapping[str, Any], response_body: Any, label: str) -> None:
    if not isinstance(response_body, dict) or _error_code(response_body) is not None:
        return
    for name, expected in request.get("path", {}).items():
        if name in response_body and response_body[name] != expected:
            raise ValueError(f"{label}: response does not match path {name}")


def _validate_scenario_semantics(
    scenario: str,
    status: str,
    request: Mapping[str, Any],
    request_body: Any,
    response_body: Any,
    label: str,
) -> None:
    expected_status = {
        "create-new": "201",
        "create-replay": "200",
        "create-conflict": "409",
        "create-tombstone": "410",
        "binding-inspect": "200",
        "list-page": "200",
        "logs-continuation": "200",
        "grant-new": "201",
        "grant-replay": "200",
        "grant-acknowledged": "200",
        "grant-destroyed": "200",
        "start-new": "202",
        "start-replay": "200",
        "start-next-generation": "202",
        "start-pod-loss": "409",
        "transfer-stage": "201",
        "transfer-stage-content": "200",
        "transfer-collect": "201",
        "transfer-collect-content": "200",
        "transfer-collect-completed": "200",
        "transfer-cancel": "202",
        "transfer-discard": "200",
        "transfer-restart": "200",
        "invoke-new": "202",
        "invoke-result-transfer": "200",
        "invoke-inline-result": "200",
        "invoke-indeterminate": "200",
        "finalize-provider-quiesce": "202",
        "cancel-output-loss": "202",
        "delete-tombstone": "200",
        "terminal-create": "201",
        "typed-error": "404",
        "m2-live-snapshot": "201",
        "m2-live-snapshot-stale": "410",
        "m2-log-cursor-gap": "410",
        "m2-dev-session-revoked": "410",
        "m2-capability-incompatible": "422",
    }
    if set(expected_status) != REQUIRED_SCENARIOS:
        raise ValueError("generator scenario status table does not cover required scenarios")
    if scenario not in expected_status:
        raise ValueError(f"{label}: unknown scenario {scenario!r}")
    if status != expected_status[scenario]:
        raise ValueError(f"{label}: scenario requires status {expected_status[scenario]}")

    if scenario == "create-conflict" and _error_code(response_body) != "IDENTITY_CONFLICT":
        raise ValueError(f"{label}: create conflict must use IDENTITY_CONFLICT")
    if scenario == "create-tombstone":
        error = response_body.get("error", {}) if isinstance(response_body, dict) else {}
        context = error.get("context", {}) if isinstance(error, dict) else {}
        if error.get("code") != "TOMBSTONED" or not isinstance(context.get("tombstone"), dict):
            raise ValueError(f"{label}: tombstone scenario must carry sanitized tombstone context")
        tombstone = context["tombstone"]
        if (
            tombstone.get("providerRequestId") != request_body.get("providerRequestId")
            or tombstone.get("specDigest") != request_body.get("specDigest")
            or context.get("jobRef") != tombstone.get("jobRef")
        ):
            raise ValueError(f"{label}: tombstone does not match create identity or digest")
    if scenario == "typed-error" and _error_code(response_body) != "NOT_FOUND":
        raise ValueError(f"{label}: typed 404 example must use NOT_FOUND")
    expected_m2_error = {
        "m2-live-snapshot-stale": "STALE_BINDING",
        "m2-log-cursor-gap": "CURSOR_GAP",
        "m2-dev-session-revoked": "DEV_SESSION_REVOKED",
        "m2-capability-incompatible": "CAPABILITY_ACTIVATION_INCOMPATIBLE",
    }.get(scenario)
    if expected_m2_error is not None and _error_code(response_body) != expected_m2_error:
        raise ValueError(f"{label}: M2 scenario must use {expected_m2_error}")
    if scenario == "grant-acknowledged" and response_body.get("state") != "acknowledged":
        raise ValueError(f"{label}: grant must be acknowledged")
    if scenario == "grant-destroyed":
        if (
            response_body.get("state") != "destroyed"
            or response_body.get("secretPresent") is not False
        ):
            raise ValueError(f"{label}: grant must be destroyed with no Secret observed")
    if scenario in {"start-new", "start-replay", "start-next-generation"}:
        expected_generation = 2 if scenario == "start-next-generation" else 1
        expected_replayed = scenario == "start-replay"
        if request_body.get("generation") != expected_generation:
            raise ValueError(f"{label}: request generation is not scenario-accurate")
        if response_body.get("generation") != expected_generation:
            raise ValueError(f"{label}: response generation is not scenario-accurate")
        if response_body.get("replayed") is not expected_replayed:
            raise ValueError(f"{label}: replayed flag is not scenario-accurate")
    if scenario == "start-pod-loss" and _error_code(response_body) not in {
        "STALE_BINDING",
        "REPLACEMENT_POD",
    }:
        raise ValueError(f"{label}: pod loss must be a binding identity error")
    if (
        scenario == "transfer-stage"
        and response_body.get("spec", {}).get("direction") != "stage_input"
    ):
        raise ValueError(f"{label}: stage scenario has the wrong direction")
    if (
        scenario == "transfer-collect"
        and response_body.get("spec", {}).get("direction") != "collect_output"
    ):
        raise ValueError(f"{label}: collect scenario has the wrong direction")
    if scenario == "transfer-cancel":
        if (
            response_body.get("state") != "canceled"
            or response_body.get("cancelAction", {}).get("state") != "succeeded"
        ):
            raise ValueError(f"{label}: cancel scenario must show its terminal action")
    if scenario == "transfer-discard":
        if (
            response_body.get("state") != "discarded"
            or response_body.get("discardAction", {}).get("state") != "succeeded"
        ):
            raise ValueError(f"{label}: discard scenario must show its terminal action")
    if scenario == "transfer-restart" and response_body.get("state") != "indeterminate":
        raise ValueError(f"{label}: restart example must expose indeterminate reality")
    if scenario == "transfer-collect-completed" and (
        response_body.get("state") != "completed"
        or response_body.get("verified") is not True
        or response_body.get("contentAvailable") is not True
        or response_body.get("snapshotRef") is None
        or response_body.get("completedAt") is None
        or response_body.get("actualSizeBytes")
        != response_body.get("spec", {}).get("declaredSizeBytes")
        or response_body.get("actualSha256") != response_body.get("spec", {}).get("contentSha256")
    ):
        raise ValueError(f"{label}: collect inspect must expose a completed snapshot")
    if scenario == "invoke-new" and response_body.get("state") != "accepted":
        raise ValueError(f"{label}: new invocation must be accepted")
    if scenario == "invoke-result-transfer":
        if response_body.get("state") != "succeeded" or not response_body.get("resultTransferRef"):
            raise ValueError(f"{label}: large result must name its collect transfer")
    if scenario == "invoke-inline-result" and (
        response_body.get("state") != "succeeded" or response_body.get("inlineResult") is None
    ):
        raise ValueError(f"{label}: inline result scenario must expose a succeeded result")
    if scenario == "invoke-indeterminate" and response_body.get("state") != "indeterminate":
        raise ValueError(f"{label}: unknown invocation outcome must remain indeterminate")
    if scenario == "finalize-provider-quiesce":
        action = response_body.get("finalizeAction", {})
        if response_body.get("bindingState") != "finalizing" or action.get(
            "actionRef"
        ) != request_body.get("finalizeRef"):
            raise ValueError(f"{label}: finalize must expose provider quiesce state")
    if scenario == "cancel-output-loss":
        action = response_body.get("cancelAction", {})
        if (
            response_body.get("bindingState") != "canceling"
            or response_body.get("outputLossPossible") is not True
            or action.get("actionRef") != request_body.get("cancelRef")
        ):
            raise ValueError(f"{label}: cancel must expose possible output loss")
    if scenario == "delete-tombstone" and response_body.get("state") != "deleted":
        raise ValueError(f"{label}: delete must return its retained tombstone")


def _validate_response_headers(
    document: dict[str, Any], response: dict[str, Any], example: dict[str, Any], label: str
) -> None:
    declared = response.get("headers", {})
    supplied = example.get("headers", {})
    if not isinstance(supplied, dict):
        raise ValueError(f"{label}: response headers must be an object")
    unknown = set(supplied) - set(declared)
    if unknown:
        raise ValueError(f"{label}: undeclared response headers: {sorted(unknown)}")
    required = _required_response_headers(response, label)
    missing = set(required) - set(supplied)
    if missing:
        raise ValueError(f"{label}: missing required response headers: {sorted(missing)}")
    for name, value in supplied.items():
        header = _dereference(document, declared[name])
        _validate_instance(value, header["schema"], document, f"{label} header {name}")


def _request_identity(record: Mapping[str, Any]) -> tuple[Any, ...]:
    extension = record["operation"].get("x-kcs-digest-projection", {})
    request = record["request"]
    body = record["requestBody"]
    values: list[Any] = []
    for item in extension.get("identity", []):
        where = item.get("in")
        name = item.get("name")
        if where == "body":
            value = body.get(name) if isinstance(body, dict) else None
        elif where == "header":
            value = request["headers"].get(name)
        else:
            value = request.get(where, {}).get(name)
        values.append(value)
    return tuple(values)


def _request_digest(record: Mapping[str, Any]) -> Any:
    extension = record["operation"].get("x-kcs-digest-projection", {})
    return _digest_wire_value(
        extension["digest"],
        extension["digestLocation"],
        record["request"],
        record["requestBody"],
        None,
        {},
        record["operationId"],
    )


def _require_cross_fields(
    actual: Mapping[str, Any],
    anchor: Mapping[str, Any],
    fields: Iterable[str],
    label: str,
) -> None:
    for field in fields:
        if actual.get(field) != anchor.get(field):
            raise ValueError(f"{label}: cross-exchange binding drift in {field}")


def _transfer_key(value: Mapping[str, Any]) -> tuple[Any, Any]:
    return value.get("jobRef"), value.get("transferRef")


def _validate_example_links(exchanges: Mapping[str, Mapping[str, Any]]) -> None:
    for scenario, record in exchanges.items():
        replay_of = record.get("replayOf")
        if replay_of is not None:
            target = exchanges.get(replay_of)
            if target is None:
                raise ValueError(f"{scenario}: replayOf target {replay_of!r} does not exist")
            if target["operationId"] != record["operationId"]:
                raise ValueError(f"{scenario}: replayOf must name the same operation")
            if target["request"] != record["request"]:
                raise ValueError(f"{scenario}: replayOf request is not byte-for-byte equivalent")
            replay_status = record["operation"].get("x-kcs-replay", {}).get("replayStatus")
            if replay_status is not None and record["status"] != str(replay_status):
                raise ValueError(f"{scenario}: replayOf response has the wrong status")

        conflicts_with = record.get("conflictsWith")
        if conflicts_with is not None:
            target = exchanges.get(conflicts_with)
            if target is None:
                raise ValueError(
                    f"{scenario}: conflictsWith target {conflicts_with!r} does not exist"
                )
            if target["operationId"] != record["operationId"]:
                raise ValueError(f"{scenario}: conflictsWith must name the same operation")
            if _request_identity(target) != _request_identity(record):
                raise ValueError(f"{scenario}: conflictsWith does not share intrinsic identity")
            if _request_digest(target) == _request_digest(record):
                raise ValueError(f"{scenario}: conflictsWith does not change the request digest")

    create_record = exchanges.get("create-new")
    if create_record is None or not isinstance(create_record.get("responseBody"), Mapping):
        raise ValueError("create-new: cross-exchange binding anchor is missing")
    create_anchor = create_record["responseBody"]
    create_request = create_record.get("requestBody")
    if not isinstance(create_request, Mapping):
        raise ValueError("create-new: cross-exchange request anchor is missing")
    job_ref = create_anchor.get("jobRef")
    job_uid = create_anchor.get("jobUid")
    pod_uid = create_anchor.get("podUid")

    job_snapshot_fields = (
        "jobRef",
        "providerHandle",
        "providerRequestId",
        "subjectRef",
        "runtimePlanDigest",
        "specDigest",
        "jobUid",
        "podUid",
        "createdAt",
    )
    for scenario, record in exchanges.items():
        body = record.get("responseBody")
        error_code = _error_code(body)
        request = record["request"]
        path = request.get("path", {})
        headers = request.get("headers", {})
        if path.get("jobRef") is not None and error_code != "NOT_FOUND":
            if path["jobRef"] != job_ref:
                raise ValueError(f"{scenario}: cross-exchange binding drift in request jobRef")
        for header_name, expected in (
            ("KCS-Job-UID", job_uid),
            ("KCS-Pod-UID", pod_uid),
        ):
            if header_name in headers and headers[header_name] != expected:
                raise ValueError(f"{scenario}: cross-exchange binding drift in {header_name}")

        if isinstance(body, Mapping):
            if error_code is None:
                for field, expected in (
                    ("jobRef", job_ref),
                    ("jobUid", job_uid),
                    ("podUid", pod_uid),
                ):
                    if field in body and body[field] != expected:
                        raise ValueError(
                            f"{scenario}: cross-exchange binding drift in response {field}"
                        )
                binding = body.get("binding")
                if isinstance(binding, Mapping):
                    _require_cross_fields(
                        binding,
                        {"jobUid": job_uid, "podUid": pod_uid},
                        ("jobUid", "podUid"),
                        scenario,
                    )
            if "providerHandle" in body and "bindingState" in body:
                _require_cross_fields(body, create_anchor, job_snapshot_fields, scenario)
                for role in ("agent", "workspace"):
                    actual_role = body.get(role)
                    anchor_role = create_anchor.get(role)
                    if (
                        isinstance(actual_role, Mapping)
                        and isinstance(anchor_role, Mapping)
                        and actual_role.get("requested") != anchor_role.get("requested")
                    ):
                        raise ValueError(
                            f"{scenario}: cross-exchange binding drift in "
                            f"{role} requested resources"
                        )
            error = body.get("error")
            if isinstance(error, Mapping) and error_code != "NOT_FOUND":
                context = error.get("context", {})
                if isinstance(context, Mapping) and context.get("jobRef") not in {
                    None,
                    job_ref,
                }:
                    raise ValueError(
                        f"{scenario}: cross-exchange binding drift in error context jobRef"
                    )

    create_tombstone_record = exchanges.get("create-tombstone")
    delete_tombstone_record = exchanges.get("delete-tombstone")
    if create_tombstone_record is not None:
        if create_tombstone_record.get("requestBody") != create_request:
            raise ValueError(
                "create-tombstone: cross-exchange binding drift in retained create request"
            )
        tombstone_body = create_tombstone_record.get("responseBody", {})
        tombstone = tombstone_body.get("error", {}).get("context", {}).get("tombstone")
        if not isinstance(tombstone, Mapping):
            raise ValueError("create-tombstone: cross-exchange binding tombstone is missing")
        _require_cross_fields(
            tombstone,
            create_anchor,
            ("providerRequestId", "specDigest", "jobRef", "jobUid", "podUid", "createdAt"),
            "create-tombstone",
        )
        if delete_tombstone_record is not None:
            delete_tombstone = delete_tombstone_record.get("responseBody")
            if delete_tombstone != tombstone:
                raise ValueError(
                    "delete-tombstone: cross-exchange binding drift from retained tombstone"
                )

    credential_record = exchanges.get("grant-new")
    credential_anchor = (
        credential_record.get("responseBody") if credential_record is not None else None
    )
    if not isinstance(credential_anchor, Mapping):
        raise ValueError("grant-new: cross-exchange binding credential anchor is missing")
    credential_fields = (
        "credentialGrantRef",
        "credentialSha256",
        "grantMetadataDigest",
        "agentRunRef",
        "generation",
        "launchBundleDigest",
        "audience",
        "ttlSeconds",
        "jobRef",
        "jobUid",
        "podUid",
        "acceptedAt",
        "availableAt",
        "expiresAt",
        "tombstoneExpiresAt",
    )
    credential_snapshots: dict[str, Mapping[str, Any]] = {}
    for scenario, record in exchanges.items():
        body = record.get("responseBody")
        if (
            not isinstance(body, Mapping)
            or "credentialGrantRef" not in body
            or "credentialSha256" not in body
        ):
            continue
        _require_cross_fields(body, credential_anchor, credential_fields, scenario)
        credential_snapshots[scenario] = body
        if body.get("ackAgentRunRef") is not None and body.get("ackAgentRunRef") != body.get(
            "agentRunRef"
        ):
            raise ValueError(f"{scenario}: cross-exchange binding drift in ackAgentRunRef")
        if body.get("ackGeneration") is not None and body.get("ackGeneration") != body.get(
            "generation"
        ):
            raise ValueError(f"{scenario}: cross-exchange binding drift in ackGeneration")
    acknowledged = credential_snapshots.get("grant-acknowledged")
    destroyed = credential_snapshots.get("grant-destroyed")
    if acknowledged is not None and destroyed is not None:
        _require_cross_fields(
            destroyed,
            acknowledged,
            ("availableAt", "acknowledgedAt", "ackAgentRunRef", "ackGeneration"),
            "grant-destroyed",
        )

    for scenario, record in exchanges.items():
        if record.get("operationId") != "startAgent" or not isinstance(
            record.get("requestBody"), Mapping
        ):
            continue
        start_request = record["requestBody"]
        if scenario in {"start-new", "start-replay", "start-pod-loss"}:
            _require_cross_fields(
                start_request,
                credential_anchor,
                ("credentialGrantRef", "agentRunRef", "generation", "launchBundleDigest"),
                scenario,
            )
            if credential_anchor.get("state") != "available":
                raise ValueError(
                    f"{scenario}: cross-exchange binding references an unusable credential grant"
                )

    transfer_anchors: dict[tuple[Any, Any], Mapping[str, Any]] = {}
    for scenario, record in exchanges.items():
        if record.get("operationId") != "registerTransfer":
            continue
        body = record.get("responseBody")
        if not isinstance(body, Mapping):
            continue
        key = _transfer_key(body)
        existing = transfer_anchors.get(key)
        if existing is not None:
            _require_cross_fields(
                body,
                existing,
                ("requestDigest", "spec", "jobUid", "podUid", "createdAt"),
                scenario,
            )
        else:
            transfer_anchors[key] = body

    transfer_fields = (
        "jobRef",
        "transferRef",
        "requestDigest",
        "jobUid",
        "podUid",
        "spec",
        "createdAt",
    )
    transfer_path_operations = {
        "inspectTransfer",
        "discardTransfer",
        "putTransferContent",
        "getTransferContent",
        "cancelTransfer",
    }
    for scenario, record in exchanges.items():
        body = record.get("responseBody")
        if isinstance(body, Mapping) and "transferRef" in body and "spec" in body:
            anchor = transfer_anchors.get(_transfer_key(body))
            if anchor is None:
                raise ValueError(f"{scenario}: cross-exchange binding has no transfer registration")
            _require_cross_fields(body, anchor, transfer_fields, scenario)
        if record.get("operationId") in transfer_path_operations:
            path = record["request"].get("path", {})
            key = (path.get("jobRef"), path.get("transferRef"))
            anchor = transfer_anchors.get(key)
            if anchor is None:
                raise ValueError(f"{scenario}: cross-exchange binding has no transfer registration")
            expected_direction = {
                "putTransferContent": "stage_input",
                "getTransferContent": "collect_output",
            }.get(record.get("operationId"))
            if (
                expected_direction is not None
                and anchor.get("spec", {}).get("direction") != expected_direction
            ):
                raise ValueError(
                    f"{scenario}: cross-exchange binding uses the wrong transfer direction"
                )

    cancel_job = exchanges.get("cancel-output-loss")
    if cancel_job is not None and isinstance(cancel_job.get("requestBody"), Mapping):
        cancel_path = cancel_job["request"].get("path", {})
        for transfer_ref in (
            cancel_job["requestBody"].get("spec", {}).get("finishCollectTransferRefs", [])
        ):
            anchor = transfer_anchors.get((cancel_path.get("jobRef"), transfer_ref))
            if anchor is None or anchor.get("spec", {}).get("direction") != "collect_output":
                raise ValueError(
                    "cancel-output-loss: finishCollectTransferRefs must name a "
                    "registered collect transfer"
                )

    workspace_anchors: dict[tuple[Any, Any], Mapping[str, Any]] = {}
    for _scenario, record in exchanges.items():
        if record.get("operationId") != "invokeWorkspace":
            continue
        body = record.get("responseBody")
        if isinstance(body, Mapping):
            workspace_anchors[(body.get("jobRef"), body.get("operationRef"))] = body
    workspace_fields = (
        "jobRef",
        "operationRef",
        "requestDigest",
        "storedFrameDigest",
        "binding",
        "acceptedAt",
    )
    for scenario, record in exchanges.items():
        body = record.get("responseBody")
        if (
            not isinstance(body, Mapping)
            or "operationRef" not in body
            or "storedFrameDigest" not in body
        ):
            continue
        key = (body.get("jobRef"), body.get("operationRef"))
        anchor = workspace_anchors.get(key)
        if anchor is not None:
            _require_cross_fields(body, anchor, workspace_fields, scenario)
        elif scenario in {"invoke-result-transfer", "invoke-indeterminate"}:
            raise ValueError(f"{scenario}: cross-exchange binding has no workspace invoke anchor")
        result_transfer_ref = body.get("resultTransferRef")
        if result_transfer_ref is not None:
            transfer = transfer_anchors.get((body.get("jobRef"), result_transfer_ref))
            if transfer is None or transfer.get("spec", {}).get("direction") != "collect_output":
                raise ValueError(
                    f"{scenario}: resultTransferRef must name a registered collect transfer"
                )

    finalize = exchanges.get("finalize-provider-quiesce")
    if finalize is not None and isinstance(finalize.get("requestBody"), Mapping):
        finalize_job_ref = finalize["request"].get("path", {}).get("jobRef")
        finalize_spec = finalize["requestBody"].get("spec", {})
        for operation_ref in finalize_spec.get("operationRefs", []):
            if (finalize_job_ref, operation_ref) not in workspace_anchors:
                raise ValueError(
                    "finalize-provider-quiesce: operationRefs must name registered work"
                )
        for transfer_ref in finalize_spec.get("transferRefs", []):
            if (finalize_job_ref, transfer_ref) not in transfer_anchors:
                raise ValueError(
                    "finalize-provider-quiesce: transferRefs must name registered work"
                )

    collect_content = exchanges.get("transfer-collect-content")
    collect_snapshot = exchanges.get("transfer-collect-completed")
    if collect_content is not None and collect_snapshot is not None:
        content_path = collect_content["request"]["path"]
        snapshot_path = collect_snapshot["request"]["path"]
        header_ref = collect_content["responseHeaders"].get("X-KCS-Snapshot-Ref")
        header_size = collect_content["responseHeaders"].get("Content-Length")
        header_digest = collect_content["responseHeaders"].get("X-Content-SHA256")
        snapshot_ref = collect_snapshot["responseBody"].get("snapshotRef")
        snapshot_size = collect_snapshot["responseBody"].get("actualSizeBytes")
        snapshot_digest = collect_snapshot["responseBody"].get("actualSha256")
        if (
            content_path != snapshot_path
            or header_ref != snapshot_ref
            or header_size != snapshot_size
            or header_digest != snapshot_digest
        ):
            raise ValueError("transfer collect content does not match its completed snapshot")


def _validate_examples(source: Path, document: dict[str, Any]) -> int:
    examples_dir = source.parent / "examples"
    fixtures_dir = examples_dir / "fixtures"
    example_paths = sorted(examples_dir.glob("*.json"))
    if not example_paths:
        raise ValueError(f"no sanitized route examples found in {examples_dir}")
    fixture_files = {path.resolve() for path in fixtures_dir.rglob("*") if path.is_file()}
    for artifact_path in sorted([*example_paths, *fixture_files]):
        label = str(artifact_path.relative_to(examples_dir))
        if artifact_path.suffix == ".json":
            value = _load_json_text(artifact_path.read_text(), label)
            _validate_artifact_hygiene(value, label)
        else:
            _validate_binary_artifact_hygiene(artifact_path.read_bytes(), label)
    expected_layout_files = {
        *(path.resolve() for path in example_paths),
        *fixture_files,
    }
    unexpected_layout = sorted(
        str(path.relative_to(examples_dir))
        for path in examples_dir.rglob("*")
        if path.is_file() and path.resolve() not in expected_layout_files
    )
    if unexpected_layout:
        raise ValueError(
            "invalid example tree layout; files must be top-level JSON route bundles "
            f"or fixtures: {unexpected_layout}"
        )
    operations = _operation_index(document)
    scenarios: set[str] = set()
    exchanges: dict[str, dict[str, Any]] = {}
    referenced_fixtures: set[Path] = set()
    validated = 0
    for example_path in example_paths:
        bundle = _load_json_text(example_path.read_text(), example_path.name)
        if not isinstance(bundle, dict) or not isinstance(bundle.get("exchanges"), list):
            raise ValueError(f"{example_path.name}: expected a route exchange bundle")
        unknown_bundle_fields = set(bundle) - {"exchanges"}
        if unknown_bundle_fields:
            raise ValueError(
                f"{example_path.name}: undeclared bundle fields: {sorted(unknown_bundle_fields)}"
            )
        for index, exchange in enumerate(bundle["exchanges"]):
            label = f"{example_path.name} exchange {index}"
            if not isinstance(exchange, dict):
                raise ValueError(f"{label}: exchange must be an object")
            unknown_exchange_fields = set(exchange) - EXCHANGE_FIELDS
            if unknown_exchange_fields:
                raise ValueError(
                    f"{label}: undeclared exchange fields: {sorted(unknown_exchange_fields)}"
                )
            scenario = exchange.get("scenario")
            if not isinstance(scenario, str) or scenario in scenarios:
                raise ValueError(f"{label}: scenario must be a unique string")
            scenarios.add(scenario)
            operation_id = exchange.get("operationId")
            if operation_id not in operations:
                raise ValueError(f"{label}: unknown operationId {operation_id!r}")
            _method, path, operation = operations[operation_id]
            request = exchange.get("request")
            response_example = exchange.get("response")
            if not isinstance(request, dict) or not isinstance(response_example, dict):
                raise ValueError(f"{label}: request and response must be objects")
            for section_name, section, allowed_fields in (
                ("request", request, REQUEST_EXAMPLE_FIELDS),
                ("response", response_example, RESPONSE_EXAMPLE_FIELDS),
            ):
                unknown_section_fields = set(section) - allowed_fields
                if unknown_section_fields:
                    raise ValueError(
                        f"{label}: undeclared {section_name} fields: "
                        f"{sorted(unknown_section_fields)}"
                    )
            request_body_spec = operation.get("requestBody")
            if request_body_spec is not None:
                request_body_spec = _dereference(document, request_body_spec)
            raw_status = response_example.get("status")
            if isinstance(raw_status, bool) or not isinstance(raw_status, int):
                raise ValueError(f"{label}: route exchange metadata status must be an integer")
            status = str(raw_status)
            if status not in operation["responses"]:
                raise ValueError(f"{label}: undeclared response status {status}")
            response = _dereference(document, operation["responses"][status])
            _validate_exchange_metadata(
                exchange,
                request,
                response_example,
                request_body_spec.get("content") if request_body_spec is not None else None,
                response.get("content"),
                label,
            )
            for section in (request, response_example):
                for fixture_key in ("bodyFixture", "bodyFile"):
                    fixture_name = section.get(fixture_key)
                    if fixture_name is not None:
                        referenced_fixtures.add(
                            _fixture_path(examples_dir, fixture_name, label).resolve()
                        )
            _validate_parameter_examples(document, path, operation, request, label)

            request_body: Any | None = None
            request_bytes: bytes | None = None
            if request_body_spec is not None:
                request_body, request_bytes = _validate_media(
                    document,
                    request_body_spec["content"],
                    request,
                    examples_dir,
                    f"{label} request",
                )
            elif set(request) & {"contentType", "body", "bodyFixture", "bodyFile"}:
                raise ValueError(f"{label}: operation has no request body")

            _validate_response_headers(document, response, response_example, label)
            response_body: Any | None = None
            response_bytes: bytes | None = None
            if "content" in response:
                try:
                    response_body, response_bytes = _validate_media(
                        document,
                        response["content"],
                        response_example,
                        examples_dir,
                        f"{label} response",
                    )
                except ValueError as exc:
                    if scenario == "create-tombstone" and "duplicate JSON key" not in str(exc):
                        raise ValueError(
                            f"{label}: tombstone scenario must carry sanitized tombstone context"
                        ) from exc
                    raise
            elif set(response_example) & {"contentType", "body", "bodyFixture", "bodyFile"}:
                raise ValueError(f"{label}: response has no body")
            _validate_digest_semantics(
                document,
                operation,
                operation_id,
                request,
                request_body,
                request_bytes,
                response_body,
                response_bytes,
                response_example.get("headers", {}),
                label,
            )
            _validate_error_semantics(operation, status, request, response_body, label)
            _validate_response_identity(request, response_body, label)
            _validate_scenario_semantics(
                scenario, status, request, request_body, response_body, label
            )
            exchanges[scenario] = {
                "operationId": operation_id,
                "operation": operation,
                "request": {
                    "path": request.get("path", {}),
                    "query": request.get("query", {}),
                    "headers": request.get("headers", {}),
                    "contentType": request.get("contentType"),
                    "body": request_body,
                    "bytes": request_bytes,
                },
                "requestBody": request_body,
                "status": status,
                "responseBody": response_body,
                "responseHeaders": response_example.get("headers", {}),
                "replayOf": exchange.get("replayOf"),
                "conflictsWith": exchange.get("conflictsWith"),
            }
            validated += 1
    missing = REQUIRED_SCENARIOS - scenarios
    if missing:
        raise ValueError(f"route examples are missing required scenarios: {sorted(missing)}")
    _validate_example_links(exchanges)
    unreferenced = sorted(path.name for path in fixture_files - referenced_fixtures)
    if unreferenced:
        raise ValueError(f"unreferenced fixture files: {unreferenced}")
    return validated


def generate_artifacts(source: Path, output_dir: Path) -> OpenAPIArtifactSet:
    """Parse, fully validate, and write deterministic artifacts for one source."""
    document = _load_yaml(source)
    if document.get("openapi") != "3.1.0" or document.get("info", {}).get("version") != "2.5.0":
        raise ValueError("source must declare OpenAPI 3.1.0 and API version 2.5.0")
    schemas = document.get("components", {}).get("schemas", {})
    if not schemas:
        raise ValueError("source must define component schemas")
    _validate_references(document)
    _validate_contract_extensions(document)
    try:
        validate(document)
    except Exception as exc:  # validator versions expose several concrete exceptions
        raise ValueError(f"OpenAPI document is invalid: {exc}") from exc

    component_bundles: dict[str, dict[str, Any]] = {}
    for name in sorted(schemas):
        bundle = _component_bundle(name, schemas)
        try:
            Draft202012Validator.check_schema(bundle)
        except SchemaError as exc:
            raise ValueError(f"component schema {name}: {exc.message}") from exc
        component_bundles[name] = bundle

    validated_examples = _validate_examples(source, document)
    openapi_bytes = _json_bytes(document)
    _validate_frozen_contract_fingerprints(document, openapi_bytes)

    output_dir.mkdir(parents=True, exist_ok=True)
    schema_dir = output_dir / "schemas"
    schema_dir.mkdir(exist_ok=True)
    for stale_schema in schema_dir.glob("*.schema.json"):
        stale_schema.unlink()

    openapi_json = output_dir / "kcs-v2-jobs.openapi.json"
    openapi_json.write_bytes(openapi_bytes)
    sha256 = hashlib.sha256(openapi_bytes).hexdigest()
    checksum = output_dir / "kcs-v2-jobs.openapi.sha256"
    checksum.write_text(f"{sha256}  {openapi_json.name}\n")

    component_paths: list[Path] = []
    for name, bundle in component_bundles.items():
        path = schema_dir / f"{name}.schema.json"
        path.write_bytes(_json_bytes(bundle))
        component_paths.append(path)

    return OpenAPIArtifactSet(
        openapi_json=openapi_json,
        checksum=checksum,
        component_schemas=tuple(component_paths),
        sha256=sha256,
        validated_examples=validated_examples,
    )


def _artifact_bytes(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def check_committed_artifacts(source: Path, committed_dir: Path) -> OpenAPIArtifactSet:
    """Regenerate into isolation and reject any byte-level committed drift."""
    with tempfile.TemporaryDirectory(prefix="kcs-v2-openapi-committed-") as temp:
        generated_dir = Path(temp) / "generated"
        artifacts = generate_artifacts(source, generated_dir)
        if not committed_dir.is_dir() or _artifact_bytes(generated_dir) != _artifact_bytes(
            committed_dir
        ):
            raise ValueError("committed generated artifacts are stale")
        return artifacts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--skip-package",
        action="store_true",
        help="freeze canonical review artifacts without replacing the served package",
    )
    args = parser.parse_args()

    source_document = _load_yaml(args.source)
    if source_document.get("x-kcs-contract-status") == "dormant" and not args.skip_package:
        raise SystemExit(
            "dormant contract requires --skip-package; served package activation is forbidden"
        )

    if args.check:
        with tempfile.TemporaryDirectory(prefix="kcs-v2-openapi-") as temp:
            first_dir = Path(temp) / "first"
            second_dir = Path(temp) / "second"
            first = generate_artifacts(args.source, first_dir)
            generate_artifacts(args.source, second_dir)
            if _artifact_bytes(first_dir) != _artifact_bytes(second_dir):
                raise SystemExit("generated artifacts are not deterministic")
            if not args.output_dir.is_dir() or _artifact_bytes(first_dir) != _artifact_bytes(
                args.output_dir
            ):
                raise SystemExit("committed generated artifacts are stale")
            if not args.skip_package and (
                not DEFAULT_PACKAGE_RESOURCE.is_file()
                or DEFAULT_PACKAGE_RESOURCE.read_bytes() != first.openapi_json.read_bytes()
            ):
                raise SystemExit("packaged canonical OpenAPI resource is stale")
            print(
                f"validated {first.validated_examples} route exchanges; "
                f"sha256 {first.sha256}  {first.openapi_json.name}"
            )
            return 0

    artifacts = generate_artifacts(args.source, args.output_dir)
    if not args.skip_package:
        DEFAULT_PACKAGE_RESOURCE.parent.mkdir(parents=True, exist_ok=True)
        DEFAULT_PACKAGE_RESOURCE.write_bytes(artifacts.openapi_json.read_bytes())
    print(f"{artifacts.sha256}  {artifacts.openapi_json.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
