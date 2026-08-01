#!/usr/bin/env python3
"""Generate deterministic KCS V2 OpenAPI and component-schema artifacts."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, NamedTuple

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "openapi" / "kcs-v2-jobs.openapi.yaml"
DEFAULT_OUTPUT = ROOT / "openapi" / "generated"


class OpenAPIArtifactSet(NamedTuple):
    openapi_json: Path
    checksum: Path
    component_schemas: tuple[Path, ...]
    sha256: str
    validated_examples: int


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


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


def _check_extended_limits(instance: Any, schema: Any, root: dict[str, Any]) -> None:
    if not isinstance(schema, dict):
        return
    if "$ref" in schema:
        prefix = "#/components/schemas/"
        ref = schema["$ref"]
        if isinstance(ref, str) and ref.startswith(prefix):
            _check_extended_limits(instance, root[ref.removeprefix(prefix)], root)
        return
    for choice in schema.get("oneOf", []):
        if choice.get("type") == "null" and instance is None:
            return
        if choice.get("type") == type(instance).__name__:
            _check_extended_limits(instance, choice, root)
            return
        if "$ref" in choice and instance is not None:
            _check_extended_limits(instance, choice, root)
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
    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties")
        for key, value in instance.items():
            child_schema = properties.get(key, additional if isinstance(additional, dict) else {})
            _check_extended_limits(value, child_schema, root)
    if isinstance(instance, list) and isinstance(schema.get("items"), dict):
        for value in instance:
            _check_extended_limits(value, schema["items"], root)


def _validate_examples(source: Path, document: dict[str, Any]) -> int:
    examples_dir = source.parent / "examples"
    example_paths = sorted(examples_dir.glob("*.json"))
    if not example_paths:
        raise ValueError(f"no sanitized examples found in {examples_dir}")

    schemas = document["components"]["schemas"]
    validated = 0
    for example_path in example_paths:
        schema_name = example_path.stem
        if schema_name not in schemas:
            raise ValueError(f"{example_path.name}: no component schema named {schema_name}")
        try:
            instance = json.loads(example_path.read_text())
            Draft202012Validator(
                {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "$ref": f"#/components/schemas/{schema_name}",
                    "components": {"schemas": schemas},
                }
            ).validate(instance)
            _check_extended_limits(instance, schemas[schema_name], schemas)
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            raise ValueError(f"{example_path.name}: {exc}") from exc
        validated += 1
    return validated


def generate_artifacts(source: Path, output_dir: Path) -> OpenAPIArtifactSet:
    """Parse, validate, and write deterministic artifacts for one canonical source."""
    document = yaml.safe_load(source.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{source} must contain an OpenAPI object")
    if document.get("openapi") != "3.1.0" or document.get("info", {}).get("version") != "2.0.0":
        raise ValueError("source must declare OpenAPI 3.1.0 and API version 2.0.0")
    schemas = document.get("components", {}).get("schemas", {})
    if not schemas:
        raise ValueError("source must define component schemas")

    validated_examples = _validate_examples(source, document)
    output_dir.mkdir(parents=True, exist_ok=True)
    schema_dir = output_dir / "schemas"
    schema_dir.mkdir(exist_ok=True)

    openapi_json = output_dir / "kcs-v2-jobs.openapi.json"
    openapi_bytes = _json_bytes(document)
    openapi_json.write_bytes(openapi_bytes)
    sha256 = hashlib.sha256(openapi_bytes).hexdigest()
    checksum = output_dir / "kcs-v2-jobs.openapi.sha256"
    checksum.write_text(f"{sha256}  {openapi_json.name}\n")

    component_paths: list[Path] = []
    for name in sorted(schemas):
        bundle = _component_bundle(name, schemas)
        try:
            Draft202012Validator.check_schema(bundle)
        except SchemaError as exc:
            raise ValueError(f"component schema {name}: {exc.message}") from exc
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
            print(
                f"validated {first.validated_examples} examples; "
                f"sha256 {first.sha256}  {first.openapi_json.name}"
            )
            return 0

    artifacts = generate_artifacts(args.source, args.output_dir)
    print(f"{artifacts.sha256}  {artifacts.openapi_json.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
