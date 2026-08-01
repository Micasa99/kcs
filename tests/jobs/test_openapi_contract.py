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
    assert openapi["security"] == [{"serviceBearer": []}]

    log_parameters = openapi["paths"]["/api/v2/jobs/{jobRef}/logs"]["get"]["parameters"]
    assert log_parameters == [
        {"$ref": "#/components/parameters/Container"},
        {"$ref": "#/components/parameters/Cursor"},
        {"$ref": "#/components/parameters/LogLimit"},
    ]

    content = openapi["paths"][
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content"
    ]
    assert {method for method in content if method in {"put", "get"}} == {"put", "get"}
    assert set(content["put"]["requestBody"]["content"]) == {"application/octet-stream"}
    assert set(content["get"]["responses"]["200"]["content"]) == {
        "application/octet-stream"
    }


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


def test_contract_enforces_frozen_limits_and_closed_mutating_payloads() -> None:
    schemas = _load_openapi()["components"]["schemas"]

    assert schemas["OpaqueRef"]["maxLength"] == 256
    assert schemas["Environment"]["maxProperties"] == 32
    assert schemas["Environment"]["propertyNames"]["maxLength"] == 64
    assert schemas["Environment"]["additionalProperties"]["maxLength"] == 2048
    assert (
        schemas["CredentialGrantRequest"]["properties"]["credential"][
            "x-kcs-maxDecodedBytes"
        ]
        == 65536
    )
    assert schemas["CreateJobRequest"]["properties"]["deadlineSeconds"]["maximum"] == 86400
    assert schemas["CreateJobRequest"]["properties"]["deadlineSeconds"]["default"] == 21600
    assert schemas["WorkspaceResources"]["properties"]["gpu"]["maximum"] == 8
    assert schemas["AgentResources"]["properties"]["gpu"]["maximum"] == 0

    logs = schemas["RoleLogs"]
    assert logs["x-kcs-combinedUtf8Bytes"] == 1048576
    assert logs["properties"]["stdout"]["x-kcs-maxUtf8Bytes"] == 1048576
    assert logs["properties"]["stderr"]["x-kcs-maxUtf8Bytes"] == 1048576
    operation = schemas["WorkspaceOperation"]
    assert operation["properties"]["stdout"]["x-kcs-maxUtf8Bytes"] == 65536
    assert operation["properties"]["stderr"]["x-kcs-maxUtf8Bytes"] == 65536

    assert schemas["ResourceId"] == {"$ref": "#/components/schemas/OpaqueRef"}
    assert schemas["ActionId"] == {"$ref": "#/components/schemas/OpaqueRef"}
    assert "maxLength" not in schemas["AgentSpec"]["properties"]["image"]
    assert "maxLength" not in schemas["WorkspaceSpec"]["properties"]["image"]
    assert "maxLength" not in schemas["TransferRegisterRequest"]["properties"]["path"]
    assert schemas["WorkspaceInvokeRequest"]["properties"]["method"] == {
        "$ref": "#/components/schemas/OpaqueRef"
    }
    assert "maxProperties" not in schemas["WorkspaceInvokeRequest"]["properties"]["spec"]
    assert "maxLength" not in _load_openapi()["components"]["parameters"]["Cursor"]["schema"]
    assert "maxLength" not in _load_openapi()["components"]["parameters"]["PageToken"]["schema"]

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
    assert first_bytes == (
        json.dumps(json.loads(first_bytes), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()

    expected_hash = hashlib.sha256(first_bytes).hexdigest()
    assert first.sha256 == expected_hash
    assert len(expected_hash) == 64 and expected_hash == expected_hash.lower()
    assert first.checksum.read_text() == f"{expected_hash}  {first.openapi_json.name}\n"
    assert {path.stem.removesuffix(".schema") for path in first.component_schemas} == set(
        _load_openapi()["components"]["schemas"]
    )
    assert first.validated_examples == len(list((ROOT / "openapi" / "examples").glob("*.json")))
    assert first.validated_examples > 0


def test_generator_rejects_an_example_that_violates_its_named_schema(tmp_path: Path) -> None:
    module = _load_generator_module()
    copied_source = tmp_path / "openapi" / SOURCE.name
    copied_source.parent.mkdir()
    copied_source.write_bytes(SOURCE.read_bytes())
    examples = copied_source.parent / "examples"
    examples.mkdir()
    (examples / "CreateJobRequest.json").write_text("{}\n")

    with pytest.raises(ValueError, match="CreateJobRequest.json"):
        module.generate_artifacts(copied_source, tmp_path / "generated")


def test_digest_examples_match_their_synthetic_payload_bytes() -> None:
    credential = json.loads((SOURCE.parent / "examples/CredentialGrantRequest.json").read_text())
    launch = json.loads((SOURCE.parent / "examples/AgentStartRequest.json").read_text())
    invocation = json.loads((SOURCE.parent / "examples/WorkspaceInvokeRequest.json").read_text())

    assert credential["credentialSha256"] == (
        "44d8b78bec6ce60168d0849c40fd060d7ddf8d50d9194d99ce1f1240d84f7cbd"
    )
    assert launch["launchSha256"] == (
        "639b6feef1aea8b7b8afdfd30c96ecf7f3599eb1562cdc48836957f40f428146"
    )
    assert invocation["spec"] == {"providerRequestId": "attempt-sanitized-001"}
    assert invocation["specDigest"] == (
        "68ec081a086f7a5a594b7743e1509bff11715a774f2d522754652ca576c570e2"
    )


@pytest.mark.parametrize(
    ("filename", "digest_field"),
    [
        ("CredentialGrantRequest.json", "credentialSha256"),
        ("AgentStartRequest.json", "launchSha256"),
        ("WorkspaceInvokeRequest.json", "specDigest"),
    ],
)
def test_generator_rejects_digest_mismatch(
    tmp_path: Path, filename: str, digest_field: str
) -> None:
    module = _load_generator_module()
    copied_openapi = tmp_path / "openapi"
    shutil.copytree(SOURCE.parent, copied_openapi)
    example_path = copied_openapi / "examples" / filename
    example = json.loads(example_path.read_text())
    example[digest_field] = "0" * 64
    example_path.write_text(json.dumps(example) + "\n")

    with pytest.raises(ValueError, match=filename):
        module.generate_artifacts(copied_openapi / SOURCE.name, tmp_path / "generated")


def test_generator_enforces_combined_log_budget(tmp_path: Path) -> None:
    module = _load_generator_module()
    copied_openapi = tmp_path / "openapi"
    shutil.copytree(SOURCE.parent, copied_openapi)
    copied_source = copied_openapi / SOURCE.name
    document = yaml.safe_load(copied_source.read_text())
    logs = document["components"]["schemas"]["RoleLogs"]
    logs["x-kcs-combinedUtf8Bytes"] = 1048576
    logs["properties"]["stdout"]["maxLength"] = 1048576
    logs["properties"]["stdout"]["x-kcs-maxUtf8Bytes"] = 1048576
    logs["properties"]["stderr"]["maxLength"] = 1048576
    logs["properties"]["stderr"]["x-kcs-maxUtf8Bytes"] = 1048576
    copied_source.write_text(yaml.safe_dump(document, sort_keys=False))
    (copied_openapi / "examples" / "RoleLogs.json").write_text(
        json.dumps(
            {
                "jobRef": "job-sanitized-001",
                "container": "agent",
                "stdout": "a" * 600000,
                "stderr": "b" * 600000,
                "truncated": True,
            }
        )
        + "\n"
    )

    with pytest.raises(ValueError, match="RoleLogs.json"):
        module.generate_artifacts(copied_source, tmp_path / "generated")


def test_regeneration_removes_obsolete_component_artifacts(tmp_path: Path) -> None:
    module = _load_generator_module()
    output_dir = tmp_path / "generated"
    stale = output_dir / "schemas" / "Obsolete.schema.json"
    stale.parent.mkdir(parents=True)
    stale.write_text("{}\n")

    artifacts = module.generate_artifacts(SOURCE, output_dir)

    assert not stale.exists()
    assert set(artifacts.component_schemas) == set((output_dir / "schemas").glob("*.schema.json"))
