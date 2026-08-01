#!/usr/bin/env python3
"""Validate and generate deterministic KCS V2 OpenAPI review artifacts."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import tempfile
import unicodedata
from collections.abc import Iterable, Mapping
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
HTTP_METHODS = {"delete", "get", "patch", "post", "put"}
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
    "typed-error",
}
SECRET_VALUE = re.compile(
    r"(?ix)("
    r"(?:authorization|bearer|cookie|api[_-]?key|token|secret|credential)(?:\s+|\s*[:=])"
    r"|-----BEGIN\x20(?:[A-Z0-9]+\x20)*(?:PRIVATE\x20KEY|CERTIFICATE)-----"
    r"|(?:ssh-(?:rsa|ed25519)|kubeconfig|serviceaccount)"
    r"|[a-z][a-z0-9+.-]*://[^/@\s]+@"
    r")"
)


class OpenAPIArtifactSet(NamedTuple):
    openapi_json: Path
    checksum: Path
    component_schemas: tuple[Path, ...]
    sha256: str
    validated_examples: int


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses ambiguous duplicate mapping keys."""


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
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
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
        try:
            body = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label}: invalid JSON fixture {path.name}") from exc
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


def _validate_contract_extensions(document: dict[str, Any]) -> None:
    for operation_id, (_method, _path, operation) in _operation_index(document).items():
        replay = operation.get("x-kcs-replay")
        if replay is None:
            continue
        mapping = operation.get("x-kcs-error-codes", {})
        conflict_code = replay.get("conflictCode")
        rule = mapping.get(conflict_code)
        if not isinstance(rule, dict) or rule.get("status") != replay.get("conflictStatus"):
            raise ValueError(f"{operation_id}: replay conflict mapping disagrees with error map")


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
            _validate_instance(
                value, declared[where][name]["schema"], document, f"{label} {where} {name}"
            )


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
        "typed-error": "404",
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
    if scenario == "logs-continuation" and response_body.get("container") != request.get(
        "query", {}
    ).get("container"):
        raise ValueError(f"{label}: logs response container does not match request")
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
        try:
            bundle = json.loads(example_path.read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(f"{example_path.name}: invalid JSON") from exc
        if not isinstance(bundle, dict) or not isinstance(bundle.get("exchanges"), list):
            raise ValueError(f"{example_path.name}: expected a route exchange bundle")
        for index, exchange in enumerate(bundle["exchanges"]):
            label = f"{example_path.name} exchange {index}"
            if not isinstance(exchange, dict):
                raise ValueError(f"{label}: exchange must be an object")
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
            request_body_spec = operation.get("requestBody")
            if request_body_spec is not None:
                request_body_spec = _dereference(document, request_body_spec)
                request_body, request_bytes = _validate_media(
                    document,
                    request_body_spec["content"],
                    request,
                    examples_dir,
                    f"{label} request",
                )
            elif set(request) & {"contentType", "body", "bodyFixture", "bodyFile"}:
                raise ValueError(f"{label}: operation has no request body")

            status = str(response_example.get("status"))
            if status not in operation["responses"]:
                raise ValueError(f"{label}: undeclared response status {status}")
            response = _dereference(document, operation["responses"][status])
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
                    if scenario == "create-tombstone":
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
    if document.get("openapi") != "3.1.0" or document.get("info", {}).get("version") != "2.0.0":
        raise ValueError("source must declare OpenAPI 3.1.0 and API version 2.0.0")
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
    output_dir.mkdir(parents=True, exist_ok=True)
    schema_dir = output_dir / "schemas"
    schema_dir.mkdir(exist_ok=True)
    for stale_schema in schema_dir.glob("*.schema.json"):
        stale_schema.unlink()

    openapi_json = output_dir / "kcs-v2-jobs.openapi.json"
    openapi_bytes = _json_bytes(document)
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
    args = parser.parse_args()

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
            print(
                f"validated {first.validated_examples} route exchanges; "
                f"sha256 {first.sha256}  {first.openapi_json.name}"
            )
            return 0

    artifacts = generate_artifacts(args.source, args.output_dir)
    print(f"{artifacts.sha256}  {artifacts.openapi_json.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
