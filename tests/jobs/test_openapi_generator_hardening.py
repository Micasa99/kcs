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
        "https://user@example.invalid",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
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


def test_generator_does_not_interpret_opaque_workspace_frame_fields() -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"]["WorkspaceFrame"]
    frame = {
        "protocol": "cosmos.workspace/1",
        "opaque": {"runtimeEnv": {"ANY_OWNER_FIELD": "Bearer owner-opaque-value"}},
    }

    module._validate_instance(frame, schema, document, "opaque workspace frame")


def test_error_envelope_conditionally_requires_tombstone_context() -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"]["ErrorEnvelope"]
    base = {
        "message": "synthetic",
        "retryable": False,
        "recoveryAction": "inspect_job",
        "requestId": "request-synthetic",
    }

    module._validate_instance(
        {"error": {**base, "code": "NOT_FOUND"}}, schema, document, "ordinary error"
    )
    with pytest.raises(ValueError, match="context.*required"):
        module._validate_instance(
            {"error": {**base, "code": "TOMBSTONED"}},
            schema,
            document,
            "tombstoned error",
        )

    valid = json.loads(
        (SOURCE.parent / "examples" / "fixtures" / "error-tombstoned.json").read_text()
    )
    module._validate_instance(valid, schema, document, "valid tombstoned error")
    for field, invalid in (("retryable", True), ("recoveryAction", "none")):
        value = json.loads(json.dumps(valid))
        value["error"][field] = invalid
        with pytest.raises(ValueError, match=field):
            module._validate_instance(value, schema, document, "invalid tombstoned error")


@pytest.mark.parametrize("schema_name", ["OpaqueCursor", "OpaquePageToken"])
def test_generator_rejects_noncanonical_base64url_tokens(schema_name: str) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"][schema_name]

    module._validate_instance("YQ", schema, document, "canonical token")
    with pytest.raises(ValueError, match="kcs-base64url"):
        module._validate_instance("A", schema, document, "noncanonical token")


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


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("subjectRef", "another-subject"),
        ("runtimePlanDigest", "2" * 64),
        ("agent.cpuMillis", 2000),
        ("agent.memoryMiB", 4096),
        ("agent.storageGiB", 21),
        ("workspace.cpuMillis", 3000),
        ("workspace.memoryMiB", 16384),
        ("workspace.gpu", 1),
        ("workspace.storageGiB", 21),
    ],
)
def test_generator_binds_create_snapshot_to_accepted_physical_spec(
    tmp_path: Path, field: str, replacement: object
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "job-binding.json"
    fixture = json.loads(fixture_path.read_text())
    if "." in field:
        role, resource = field.split(".")
        fixture[role]["requested"][resource] = replacement
    else:
        fixture[field] = replacement
    fixture_path.write_text(json.dumps(fixture) + "\n")

    with pytest.raises(ValueError, match="create response does not echo accepted physical spec"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    "case",
    [
        "create",
        "credential-bytes",
        "credential-metadata",
        "agent-start",
        "register-transfer",
        "transfer-content",
        "cancel-transfer",
        "workspace-frame",
        "finalize",
        "cancel-job",
        "discard",
        "delete",
    ],
)
def test_route_mutation_extensions_reject_changed_projected_payloads(
    tmp_path: Path, case: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    examples = source.parent / "examples"
    if case == "create":
        path = examples / "fixtures" / "create-request.json"
        body = json.loads(path.read_text())
        body["spec"]["activeDeadlineSeconds"] += 1
        path.write_text(json.dumps(body) + "\n")
    elif case == "credential-bytes":
        path = examples / "fixtures" / "credential.bin"
        path.write_bytes(path.read_bytes() + b"changed")
    elif case == "credential-metadata":
        path = examples / "credentials.json"
        bundle = json.loads(path.read_text())
        bundle["exchanges"][0]["request"]["headers"]["KCS-Audience"] = "changed-audience"
        path.write_text(json.dumps(bundle) + "\n")
    elif case == "agent-start":
        path = examples / "fixtures" / "agent-start-request.json"
        body = json.loads(path.read_text())
        body["agentRunRef"] = "changed-agent-run"
        path.write_text(json.dumps(body) + "\n")
    elif case == "register-transfer":
        path = examples / "fixtures" / "transfer-stage-request.json"
        body = json.loads(path.read_text())
        body["spec"]["path"] = "inputs/changed.bin"
        path.write_text(json.dumps(body) + "\n")
    elif case == "transfer-content":
        path = examples / "transfers.json"
        bundle = json.loads(path.read_text())
        exchange = next(
            item for item in bundle["exchanges"] if item["scenario"] == "transfer-stage-content"
        )
        exchange["request"]["headers"]["KCS-Content-SHA256"] = "1" * 64
        path.write_text(json.dumps(bundle) + "\n")
    elif case == "cancel-transfer":
        path = examples / "fixtures" / "transfer-cancel-request.json"
        body = json.loads(path.read_text())
        body["spec"]["reason"] = "changed-reason"
        path.write_text(json.dumps(body) + "\n")
    elif case == "workspace-frame":
        path = examples / "fixtures" / "workspace-frame.json"
        frame = json.loads(path.read_text())
        frame["payload"]["synthetic"] = False
        path.write_text(json.dumps(frame) + "\n")
    elif case in {"finalize", "cancel-job"}:
        name = "finalize-request.json" if case == "finalize" else "cancel-request.json"
        path = examples / "fixtures" / name
        body = json.loads(path.read_text())
        if case == "finalize":
            body["spec"]["drainTimeoutSeconds"] += 1
        else:
            body["spec"]["reason"] = "changed-reason"
        path.write_text(json.dumps(body) + "\n")
    else:
        path = examples / ("transfers.json" if case == "discard" else "jobs.json")
        bundle = json.loads(path.read_text())
        operation_id = "discardTransfer" if case == "discard" else "deleteJob"
        exchange = next(item for item in bundle["exchanges"] if item["operationId"] == operation_id)
        exchange["request"]["headers"]["KCS-Request-Digest"] = "1" * 64
        path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="digest mismatch"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_actual_route_extensions_exclude_identity_and_bind_projected_payload() -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    examples = SOURCE.parent / "examples"
    cases = {
        "createJob": ("jobs.json", "create-new"),
        "grantCredential": ("credentials.json", "grant-new"),
        "startAgent": ("agent-start.json", "start-new"),
        "registerTransfer": ("transfers.json", "transfer-stage"),
        "putTransferContent": ("transfers.json", "transfer-stage-content"),
        "cancelTransfer": ("transfers.json", "transfer-cancel"),
        "discardTransfer": ("transfers.json", "transfer-discard"),
        "invokeWorkspace": ("workspace.json", "invoke-new"),
        "finalizeJob": ("jobs.json", "finalize-provider-quiesce"),
        "cancelJob": ("jobs.json", "cancel-output-loss"),
        "deleteJob": ("jobs.json", "delete-tombstone"),
    }
    operations = {
        operation["operationId"]: operation
        for path_item in document["paths"].values()
        for method, operation in path_item.items()
        if method in {"post", "put", "delete"} and "x-kcs-digest-projection" in operation
    }
    assert set(cases) == set(operations)

    for operation_id, (bundle_name, scenario) in cases.items():
        bundle = json.loads((examples / bundle_name).read_text())
        exchange = next(item for item in bundle["exchanges"] if item["scenario"] == scenario)
        request = json.loads(json.dumps(exchange["request"]))
        body = None
        body_bytes = None
        if "bodyFixture" in request:
            body = json.loads((examples / request["bodyFixture"]).read_text())
        elif "bodyFile" in request:
            body_bytes = (examples / request["bodyFile"]).read_bytes()
        extension = operations[operation_id]["x-kcs-digest-projection"]
        definition = (
            extension["storedIntegrityDigest"]
            if extension.get("digestOwnership") == "platform"
            else extension
        )
        projection = definition["projection"]
        original = module._projected_digest(projection, body, body_bytes, operation_id)

        for identity in extension["identity"]:
            changed_body = json.loads(json.dumps(body)) if body is not None else None
            changed_request = json.loads(json.dumps(request))
            if identity["in"] == "body":
                current = changed_body[identity["name"]]
                changed_body[identity["name"]] = (
                    current + 1 if isinstance(current, int) else "changed"
                )
            else:
                group = "headers" if identity["in"] == "header" else identity["in"]
                changed_request.setdefault(group, {})[identity["name"]] = "changed"
            assert (
                module._projected_digest(projection, changed_body, body_bytes, operation_id)
                == original
            ), f"{operation_id}:{identity['name']}"
            if "metadataDigest" in extension:
                original_metadata = module._metadata_projection(
                    extension["metadataDigest"], request.get("headers", {}), operation_id
                )[1]
                changed_metadata = module._metadata_projection(
                    extension["metadataDigest"],
                    changed_request.get("headers", {}),
                    operation_id,
                )[1]
                assert changed_metadata == original_metadata, operation_id

        if "metadataDigest" in extension:
            metadata_definition = extension["metadataDigest"]
            metadata_headers = {item["header"] for item in metadata_definition["projection"]}
            assert "KCS-Credential-Grant-Ref" not in metadata_headers
            original_metadata = module._metadata_projection(
                metadata_definition, request["headers"], operation_id
            )[1]
            for item in metadata_definition["projection"]:
                changed_headers = dict(request["headers"])
                header = item["header"]
                current = changed_headers[header]
                if isinstance(current, int):
                    changed_headers[header] = current + 1
                elif header in {"KCS-Launch-Bundle-Digest", "KCS-Credential-SHA256"}:
                    changed_headers[header] = "1" * 64
                elif header in {"KCS-Job-UID", "KCS-Pod-UID"}:
                    changed_headers[header] = "33333333-3333-4333-8333-333333333333"
                else:
                    changed_headers[header] = "changed-value"
                assert (
                    module._metadata_projection(metadata_definition, changed_headers, operation_id)[
                        1
                    ]
                    != original_metadata
                ), item["field"]

        if projection.get("source") != "constant":
            if projection.get("encoding") == "raw-bytes":
                changed_projection = module._projected_digest(
                    projection, body, (body_bytes or b"") + b"changed", operation_id
                )
            else:
                payload_body = json.loads(json.dumps(body))
                if operation_id == "createJob":
                    payload_body["spec"]["subjectRef"] = "changed-subject"
                elif operation_id == "startAgent":
                    payload_body["executionEnvelopeRef"] = "changed-envelope"
                elif operation_id == "registerTransfer":
                    payload_body["spec"]["path"] = "inputs/changed.bin"
                elif operation_id == "cancelTransfer":
                    payload_body["spec"]["reason"] = "changed-reason"
                elif operation_id == "invokeWorkspace":
                    payload_body["payload"]["synthetic"] = False
                elif operation_id == "finalizeJob":
                    payload_body["spec"]["drainTimeoutSeconds"] += 1
                elif operation_id == "cancelJob":
                    payload_body["spec"]["reason"] = "changed-reason"
                else:
                    raise AssertionError(f"missing schema-valid payload mutation: {operation_id}")
                changed_projection = module._projected_digest(
                    projection, payload_body, body_bytes, operation_id
                )
            assert changed_projection != original, operation_id


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


def test_generator_rejects_replay_conflict_error_map_drift(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    operation = document["paths"]["/api/v2/jobs/{jobRef}/transfers/{transferRef}/content"]["put"]
    operation["x-kcs-replay"]["conflictStatus"] = 422
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="replay conflict mapping"):
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


@pytest.mark.parametrize(
    ("bundle_name", "scenario", "mutate", "message"),
    [
        (
            "transfers.json",
            "transfer-stage-content",
            lambda body: body.update({"verified": False}),
            "uploaded transfer must be completed and verified",
        ),
        (
            "transfers.json",
            "transfer-stage-content",
            lambda body: body.update({"completedAt": None}),
            "uploaded transfer must be completed and verified",
        ),
        (
            "transfers.json",
            "transfer-collect-completed",
            lambda body: body.update({"actualSizeBytes": 0}),
            "collect inspect must expose a completed snapshot",
        ),
        (
            "jobs.json",
            "logs-continuation",
            lambda body: body.update({"container": "workspace"}),
            "logs response container does not match request",
        ),
        (
            "jobs.json",
            "create-tombstone",
            lambda body: body["error"]["context"]["tombstone"].update(
                {"providerRequestId": "another-provider-request"}
            ),
            "tombstone does not match create identity",
        ),
        (
            "jobs.json",
            "create-tombstone",
            lambda body: body["error"]["context"]["tombstone"].update({"specDigest": "2" * 64}),
            "tombstone does not match create identity",
        ),
        (
            "jobs.json",
            "create-tombstone",
            lambda body: body["error"]["context"].update({"jobRef": "another-job"}),
            "tombstone does not match create identity",
        ),
    ],
)
def test_generator_binds_route_scenario_reality(
    tmp_path: Path,
    bundle_name: str,
    scenario: str,
    mutate,
    message: str,
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / bundle_name
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == scenario)
    fixture_path = source.parent / "examples" / exchange["response"]["bodyFixture"]
    body = json.loads(fixture_path.read_text())
    mutate(body)
    fixture_path.write_text(json.dumps(body) + "\n")

    with pytest.raises(ValueError, match=message):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("header", ["X-KCS-Snapshot-Ref", "Cache-Control"])
def test_generator_requires_collect_integrity_headers(tmp_path: Path, header: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "transfers.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(
        item for item in bundle["exchanges"] if item["scenario"] == "transfer-collect-content"
    )
    del exchange["response"]["headers"][header]
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(
        ValueError, match="collect response must carry snapshot identity and no-store"
    ):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_requires_content_and_completed_collect_scenarios(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "transfers.json"
    bundle = json.loads(bundle_path.read_text())
    removed = {
        "transfer-stage-content",
        "transfer-collect-content",
        "transfer-collect-completed",
    }
    bundle["exchanges"] = [
        exchange for exchange in bundle["exchanges"] if exchange["scenario"] not in removed
    ]
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="missing required scenarios.*transfer-stage-content"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    "mutation",
    [
        {
            "inlineResult": {"synthetic": True, "value": 7},
            "inlineResultSize": 28,
            "inlineResultDigest": (
                "fabcc34320756450ec872f7ea06c2ce2ea0f70ba87804a78620955c0f0842ca2"
            ),
        },
        {"inlineResult": None, "inlineResultSize": 1, "inlineResultDigest": "0" * 64},
    ],
)
def test_generator_relates_inline_workspace_result_fields(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = (
        source.parent / "examples" / "fixtures" / "workspace-operation-result-transfer.json"
    )
    fixture = json.loads(fixture_path.read_text())
    fixture.update(mutation)
    fixture_path.write_text(json.dumps(fixture) + "\n")

    with pytest.raises(ValueError, match="inline result fields are inconsistent"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_consumes_inline_result_relation_extension(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    relation = document["components"]["schemas"]["WorkspaceOperationSnapshot"][
        "x-kcs-inline-result-relation"
    ]
    relation["digest"] = "requestDigest"
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="inline result relation extension is invalid"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_binds_collect_bytes_to_completed_snapshot(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "transfer-collect-completed.json"
    fixture = json.loads(fixture_path.read_text())
    fixture["spec"]["declaredSizeBytes"] = 26
    fixture["actualSizeBytes"] = 26
    fixture_path.write_text(json.dumps(fixture) + "\n")

    with pytest.raises(ValueError, match="collect content does not match its completed snapshot"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("suffix", ["json", "bin"])
def test_generator_rejects_unreferenced_fixture(tmp_path: Path, suffix: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    orphan = source.parent / "examples" / "fixtures" / f"orphan.{suffix}"
    orphan.write_bytes(b"{}\n")

    with pytest.raises(ValueError, match=rf"unreferenced fixture.*orphan\.{suffix}"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("relative_path", ["orphan.bin", "notes/readme.txt"])
def test_generator_rejects_files_outside_example_tree_layout(
    tmp_path: Path, relative_path: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    orphan = source.parent / "examples" / relative_path
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_bytes(b"synthetic orphan\n")

    with pytest.raises(ValueError, match="invalid example tree layout.*orphan|readme"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_unknown_scenario_with_contract_error(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    bundle["exchanges"][0]["scenario"] = "unexpected-scenario"
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="unknown scenario 'unexpected-scenario'"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_casefold_colliding_material_paths(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "agent-start-request.json"
    fixture = json.loads(fixture_path.read_text())
    fixture["materialPaths"] = ["Inputs/Material.json", "inputs/material.json"]
    fixture_path.write_text(json.dumps(fixture) + "\n")

    with pytest.raises(ValueError, match="casefold collision"):
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
