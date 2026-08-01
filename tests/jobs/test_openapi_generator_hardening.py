from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "openapi" / "kcs-v2-jobs.openapi.yaml"


def _load_generator_module():
    path = ROOT / "scripts" / "generate_v2_openapi_artifacts.py"
    spec = importlib.util.spec_from_file_location("generate_v2_openapi_artifacts", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _copy_openapi(tmp_path: Path) -> Path:
    destination = tmp_path / "openapi"
    shutil.copytree(SOURCE.parent, destination, ignore=shutil.ignore_patterns("generated"))
    return destination / SOURCE.name


def test_generator_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    source.write_text(source.read_text() + "\ninfo:\n  title: duplicate\n  version: 2.0.0\n")

    with pytest.raises(ValueError, match="duplicate YAML key.*info"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_dangling_openapi_references(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    document["paths"]["/api/v2/jobs"]["post"]["responses"]["201"]["content"]["application/json"][
        "schema"
    ] = {"$ref": "#/components/schemas/NoSuchSchema"}
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="NoSuchSchema"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_invalid_full_openapi_document(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    document["paths"] = []
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="OpenAPI document"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_rfc8785_vectors_and_identity_exclusion() -> None:
    module = _load_generator_module()
    assert module.jcs_sha256({"b": 2, "a": 1}) == (
        "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
    )
    assert module.jcs_sha256({"numbers": [1, 1.5, 1e-7]}) == (
        "8347f2e9f146a07d6257bcb96e2794e3bacc23272288998fdef75acd928602fb"
    )

    families = [
        {"identity": "provider-a", "spec": {"kind": "create"}},
        {"identity": "transfer-a", "spec": {"kind": "transfer"}},
        {"identity": "generation-1", "metadata": {"kind": "start"}},
        {"identity": "cancel-a", "spec": {"kind": "transfer-cancel"}},
        {"identity": "finalize-a", "spec": {"kind": "finalize"}},
        {"identity": "job-cancel-a", "spec": {"kind": "job-cancel"}},
    ]
    for value in families:
        projection = "metadata" if "metadata" in value else "spec"
        original = module.jcs_projection_sha256(value, projection)
        changed_identity = {**value, "identity": "changed"}
        changed_payload = {**value, projection: {"kind": "changed"}}
        assert module.jcs_projection_sha256(changed_identity, projection) == original
        assert module.jcs_projection_sha256(changed_payload, projection) != original
    assert module.jcs_sha256({}) == (
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    )


@pytest.mark.parametrize(
    "value",
    [
        "Bearer abc",
        "Authorization Bearer abc",
        "cookie abc",
        "api_key abc",
        "token abc",
        "secret abc",
        "credential abc",
    ],
)
def test_non_secret_runtime_format_rejects_bare_secret_markers(value: str) -> None:
    module = _load_generator_module()
    assert module._is_non_secret_runtime_value(value) is False


@pytest.mark.parametrize("value", ["inputs/\x7f.txt", "inputs/e\u0301.txt"])
def test_safe_relative_path_rejects_del_and_non_nfc(value: str) -> None:
    module = _load_generator_module()
    assert module._is_safe_relative_posix_path(value) is False


def test_generator_rejects_secret_shaped_runtime_environment_value(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "create-request.json"
    fixture = json.loads(fixture_path.read_text())
    fixture["spec"]["agent"]["runtimeEnv"] = {"HTTP_PROXY": "https://user:pass@example.invalid"}
    fixture_path.write_text(json.dumps(fixture) + "\n")

    with pytest.raises(ValueError, match="secret-shaped runtimeEnv"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    ("bundle_name", "scenario", "replacement_fixture", "message"),
    [
        (
            "credentials.json",
            "grant-acknowledged",
            "fixtures/credential-grant.json",
            "grant must be acknowledged",
        ),
        (
            "agent-start.json",
            "start-replay",
            "fixtures/generation.json",
            "replayed flag",
        ),
        (
            "jobs.json",
            "create-tombstone",
            "fixtures/error.json",
            "sanitized tombstone context",
        ),
    ],
)
def test_generator_rejects_scenario_labels_that_do_not_match_fixture_reality(
    tmp_path: Path,
    bundle_name: str,
    scenario: str,
    replacement_fixture: str,
    message: str,
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / bundle_name
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == scenario)
    exchange["response"]["bodyFixture"] = replacement_fixture
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match=message):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_placeholder_or_wrong_semantic_digest(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "create-request.json"
    fixture = json.loads(fixture_path.read_text())
    fixture["specDigest"] = "0" * 64
    fixture_path.write_text(json.dumps(fixture) + "\n")

    with pytest.raises(ValueError, match="digest mismatch"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_consumes_declared_digest_projection_instead_of_operation_id(
    tmp_path: Path,
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    projection = document["paths"]["/api/v2/jobs"]["post"]["x-kcs-digest-projection"]
    projection["projection"] = {"source": "requestBody", "field": "providerRequestId"}
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="digest mismatch"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_projection_on_platform_owned_workspace_digest(
    tmp_path: Path,
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    projection = document["paths"]["/api/v2/jobs/{jobRef}/workspace/invoke"]["post"][
        "x-kcs-digest-projection"
    ]
    projection["projection"] = {"source": "requestBody"}
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="platform-owned digest.*projection"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_broken_replay_link(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    replay = next(item for item in bundle["exchanges"] if item["scenario"] == "create-replay")
    replay["replayOf"] = "does-not-exist"
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="replayOf.*does-not-exist"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_binds_inspect_response_identity_to_path(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    inspect = next(item for item in bundle["exchanges"] if item["scenario"] == "binding-inspect")
    inspect["request"]["path"]["jobRef"] = "another-job"
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="response does not match path jobRef"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_transfer_size_relation_even_with_matching_digest(
    tmp_path: Path,
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_dir = source.parent / "examples" / "fixtures"
    request_path = fixture_dir / "transfer-stage-request.json"
    response_path = fixture_dir / "transfer-stage.json"
    request = json.loads(request_path.read_text())
    response = json.loads(response_path.read_text())
    request["spec"]["authorizedMaxSizeBytes"] = 10
    request["requestDigest"] = module.jcs_sha256(request["spec"])
    response["spec"] = request["spec"]
    response["requestDigest"] = request["requestDigest"]
    request_path.write_text(json.dumps(request) + "\n")
    response_path.write_text(json.dumps(response) + "\n")

    with pytest.raises(ValueError, match="declaredSizeBytes.*authorizedMaxSizeBytes"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_enforces_combined_live_and_tombstone_page_limit() -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"]["JobBindingSnapshotList"]
    instance = {"items": [{}] * 101, "tombstones": [{}] * 100}

    with pytest.raises(ValueError, match="combined items.*200"):
        module._check_extended_limits(instance, schema, document)


def test_committed_generated_artifacts_match_source_byte_for_byte(tmp_path: Path) -> None:
    module = _load_generator_module()
    actual = module.generate_artifacts(SOURCE, tmp_path / "generated")
    committed = SOURCE.parent / "generated"
    assert committed.is_dir()
    actual_files = {
        path.relative_to(actual.openapi_json.parent): path.read_bytes()
        for path in actual.openapi_json.parent.rglob("*")
        if path.is_file()
    }
    committed_files = {
        path.relative_to(committed): path.read_bytes()
        for path in committed.rglob("*")
        if path.is_file()
    }
    assert committed_files == actual_files


def test_committed_artifact_check_rejects_stale_bytes(tmp_path: Path) -> None:
    module = _load_generator_module()
    committed = tmp_path / "committed"
    module.generate_artifacts(SOURCE, committed)
    artifact = committed / "kcs-v2-jobs.openapi.json"
    artifact.write_bytes(artifact.read_bytes() + b" ")

    with pytest.raises(ValueError, match="committed generated artifacts are stale"):
        module.check_committed_artifacts(SOURCE, committed)
