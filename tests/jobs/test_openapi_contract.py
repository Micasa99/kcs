from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "openapi" / "kcs-v2-jobs.openapi.yaml"
EXPECTED_PATHS = {
    "/api/v2/jobs",
    "/api/v2/jobs/{jobRef}",
    "/api/v2/jobs/{jobRef}/logs",
    "/api/v2/jobs/{jobRef}/agent/credential-grants",
    "/api/v2/jobs/{jobRef}/agent/credential-grants/{credentialGrantRef}",
    "/api/v2/jobs/{jobRef}/agent/start",
    "/api/v2/jobs/{jobRef}/transfers",
    "/api/v2/jobs/{jobRef}/transfers/{transferRef}",
    "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
    "/api/v2/jobs/{jobRef}/transfers/{transferRef}/cancel",
    "/api/v2/jobs/{jobRef}/workspace/invoke",
    "/api/v2/jobs/{jobRef}/operations/{operationRef}",
    "/api/v2/jobs/{jobRef}/finalize",
    "/api/v2/jobs/{jobRef}/cancel",
    "/api/v2/openapi.json",
}
EXPECTED_OPERATIONS = {
    "/api/v2/jobs": {"get", "post"},
    "/api/v2/jobs/{jobRef}": {"get", "delete"},
    "/api/v2/jobs/{jobRef}/logs": {"get"},
    "/api/v2/jobs/{jobRef}/agent/credential-grants": {"post"},
    "/api/v2/jobs/{jobRef}/agent/credential-grants/{credentialGrantRef}": {"get"},
    "/api/v2/jobs/{jobRef}/agent/start": {"post"},
    "/api/v2/jobs/{jobRef}/transfers": {"post"},
    "/api/v2/jobs/{jobRef}/transfers/{transferRef}": {"get", "delete"},
    "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content": {"get", "put"},
    "/api/v2/jobs/{jobRef}/transfers/{transferRef}/cancel": {"post"},
    "/api/v2/jobs/{jobRef}/workspace/invoke": {"post"},
    "/api/v2/jobs/{jobRef}/operations/{operationRef}": {"get"},
    "/api/v2/jobs/{jobRef}/finalize": {"post"},
    "/api/v2/jobs/{jobRef}/cancel": {"post"},
    "/api/v2/openapi.json": {"get"},
}
EXPECTED_ERROR_STATUSES = {
    "400",
    "401",
    "403",
    "404",
    "409",
    "410",
    "413",
    "415",
    "422",
    "429",
    "500",
    "503",
    "504",
}


def _load_openapi() -> dict:
    return yaml.safe_load(SOURCE.read_text())


def _load_generator_module():
    path = ROOT / "scripts" / "generate_v2_openapi_artifacts.py"
    spec = importlib.util.spec_from_file_location("generate_v2_openapi_artifacts", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_contract_freezes_version_routes_security_and_media_types() -> None:
    openapi = _load_openapi()

    assert openapi["openapi"] == "3.1.0"
    assert openapi["info"]["version"] == "2.0.0"
    assert set(openapi["paths"]) == EXPECTED_PATHS
    assert {
        path: {method for method in item if method in {"get", "post", "put", "delete"}}
        for path, item in openapi["paths"].items()
    } == EXPECTED_OPERATIONS
    assert openapi["security"] == [{"v2ServiceBearer": []}]
    assert set(openapi["components"]["securitySchemes"]) == {"v2ServiceBearer"}
    assert openapi["x-kcs-network-boundary"] == {
        "tlsRequired": True,
        "privateIngressRequired": True,
    }

    credential = openapi["paths"]["/api/v2/jobs/{jobRef}/agent/credential-grants"]["post"]
    assert "security" not in credential
    assert credential["x-kcs-private-ingress"] is True

    content = openapi["paths"]["/api/v2/jobs/{jobRef}/transfers/{transferRef}/content"]
    assert set(content["put"]["requestBody"]["content"]) == {"application/octet-stream"}
    assert set(content["get"]["responses"]["200"]["content"]) == {"application/octet-stream"}


def test_contract_uses_one_typed_error_envelope_for_every_required_status() -> None:
    openapi = _load_openapi()
    operations = [
        operation
        for path_item in openapi["paths"].values()
        for method, operation in path_item.items()
        if method in {"get", "post", "put", "delete", "patch"}
    ]

    seen_statuses: set[str] = set()
    for operation in operations:
        for status, response in operation["responses"].items():
            if status in EXPECTED_ERROR_STATUSES:
                schema = response["content"]["application/json"]["schema"]
                assert schema == {"$ref": "#/components/schemas/ErrorEnvelope"}
                seen_statuses.add(status)

    assert seen_statuses == EXPECTED_ERROR_STATUSES
    assert "TombstonedErrorEnvelope" not in openapi["components"]["schemas"]


def test_contract_enforces_frozen_limits_and_closed_mutating_payloads() -> None:
    document = _load_openapi()
    schemas = document["components"]["schemas"]

    assert schemas["OpaqueRef"]["maxLength"] == 256
    assert schemas["Environment"]["maxProperties"] == 32
    assert schemas["Environment"]["propertyNames"]["maxLength"] == 64
    assert schemas["Environment"]["additionalProperties"]["maxLength"] == 2048
    assert schemas["Environment"]["additionalProperties"]["format"] == (
        "kcs-non-secret-runtime-value"
    )
    assert schemas["JobSpec"]["properties"]["activeDeadlineSeconds"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 86400,
        "default": 21600,
    }
    assert schemas["WorkspaceResources"]["properties"]["gpu"]["maximum"] == 8
    assert "gpu" not in schemas["AgentResources"]["properties"]
    assert schemas["RoleLogs"]["properties"]["content"]["x-kcs-maxUtf8Bytes"] == 1048576
    assert (
        schemas["WorkspaceOperationSnapshot"]["properties"]["stdout"]["x-kcs-maxUtf8Bytes"] == 65536
    )
    assert schemas["SafeRelativePath"]["format"] == "kcs-relative-posix-path"
    assert schemas["WorkspaceFrame"]["x-kcs-maxCanonicalBytes"] == 1048576

    for name, schema in schemas.items():
        if name.endswith("Request"):
            assert schema["type"] == "object", name
            assert schema["additionalProperties"] is False, name


def test_generator_emits_deterministic_json_hash_and_validated_component_schemas(
    tmp_path: Path,
) -> None:
    module = _load_generator_module()
    first = module.generate_artifacts(SOURCE, tmp_path / "first")
    second = module.generate_artifacts(SOURCE, tmp_path / "second")

    first_bytes = first.openapi_json.read_bytes()
    second_bytes = second.openapi_json.read_bytes()
    assert first_bytes == second_bytes
    assert first_bytes.endswith(b"\n")
    assert (
        first_bytes
        == (
            json.dumps(json.loads(first_bytes), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
    )

    expected_hash = hashlib.sha256(first_bytes).hexdigest()
    assert first.sha256 == expected_hash
    assert first.checksum.read_text() == f"{expected_hash}  {first.openapi_json.name}\n"
    assert {path.stem.removesuffix(".schema") for path in first.component_schemas} == set(
        _load_openapi()["components"]["schemas"]
    )
    expected_examples = sum(
        len(json.loads(path.read_text())["exchanges"])
        for path in (ROOT / "openapi" / "examples").glob("*.json")
    )
    assert first.validated_examples == expected_examples
    assert first.validated_examples > 0


def test_generator_rejects_an_example_that_violates_its_route_schema(
    tmp_path: Path,
) -> None:
    module = _load_generator_module()
    copied_openapi = tmp_path / "openapi"
    shutil.copytree(SOURCE.parent, copied_openapi, ignore=shutil.ignore_patterns("generated"))
    bundle_path = copied_openapi / "examples" / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    create = next(item for item in bundle["exchanges"] if item["scenario"] == "create-new")
    create["request"] = {"contentType": "application/json", "body": {}}
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="jobs.json"):
        module.generate_artifacts(copied_openapi / SOURCE.name, tmp_path / "generated")


def test_regeneration_removes_obsolete_component_artifacts(tmp_path: Path) -> None:
    module = _load_generator_module()
    output_dir = tmp_path / "generated"
    stale = output_dir / "schemas" / "Obsolete.schema.json"
    stale.parent.mkdir(parents=True)
    stale.write_text("{}\n")

    artifacts = module.generate_artifacts(SOURCE, output_dir)

    assert not stale.exists()
    assert set(artifacts.component_schemas) == set((output_dir / "schemas").glob("*.schema.json"))
