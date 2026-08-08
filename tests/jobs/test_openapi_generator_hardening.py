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


@pytest.mark.parametrize(
    "value",
    [
        "client-key-data: c3ludGhldGlj",
        "client-certificate-data: c3ludGhldGlj",
        "certificate-authority-data: c3ludGhldGlj",
        "apiVersion: v1\nkind: Config\nclusters: []\nusers: []",
        "kind: Config\napiVersion: v1\nclusters: []\nusers: []",
        '"client-key-data": "c3ludGhldGlj"',
        '{"apiVersion":"v1","kind":"Config","clusters":[],"users":[]}',
    ],
)
def test_non_secret_runtime_format_rejects_kubernetes_client_material(value: str) -> None:
    module = _load_generator_module()
    assert module._is_non_secret_runtime_value(value) is False


@pytest.mark.parametrize("value", ["inputs/\x7f.txt", "inputs/e\u0301.txt"])
def test_safe_relative_path_rejects_del_and_non_nfc(value: str) -> None:
    module = _load_generator_module()
    assert module._is_safe_relative_posix_path(value) is False


@pytest.mark.parametrize(
    "value",
    [
        "inputs/\u0085.txt",
        "inputs/\u202e.txt",
        "inputs/\u2066.txt",
        "inputs/\ud800.txt",
        "inputs/\ue000.txt",
        "inputs/\u0378.txt",
        "inputs/\u2028.txt",
    ],
)
def test_safe_relative_path_rejects_unsafe_unicode_categories(value: str) -> None:
    module = _load_generator_module()
    assert module._is_safe_relative_posix_path(value) is False


def test_generator_consumes_safe_path_unicode_policy_extension(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    policy = document["components"]["schemas"]["SafeRelativePath"]["x-kcs-unicode-policy"]
    policy["rejectedGeneralCategories"].remove("Cf")
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="Unicode policy declaration"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_secret_shaped_runtime_environment_value() -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"]["Environment"]

    with pytest.raises(ValueError, match="secret-shaped runtimeEnv"):
        module._validate_instance(
            {"HTTP_PROXY": "https://user:pass@example.invalid"},
            schema,
            document,
            "runtime environment",
        )


def test_generator_does_not_interpret_opaque_workspace_frame_fields() -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"]["WorkspaceFrame"]
    frame = {
        "protocol": "cosmos.workspace/1",
        "opaque": {"runtimeEnv": {"ANY_OWNER_FIELD": "client-key-data: owner-opaque-value"}},
    }

    module._validate_instance(frame, schema, document, "opaque workspace frame")


@pytest.mark.parametrize(
    "opaque",
    [
        {"identityFile": "/Users/alice/.ssh/id_ed25519"},
        {"location": "/root/.ssh/id_ed25519"},
        {"location": "/root/.kube/config"},
        {"location": "~/.kube/config"},
        {"location": "/Users/alice/.kube/config"},
        {"location": "/Users/alice/project/data"},
        {"location": "/home/alice/work"},
        {"location": "/root/.aws/credentials"},
        {"endpoint": "kcs-control.internal"},
        {"token": "synthetic-owner-token"},
    ],
)
def test_generator_raw_artifact_scan_rejects_private_material_in_opaque_frame(
    tmp_path: Path, opaque: dict[str, str]
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "workspace-frame.json"
    frame = json.loads(fixture_path.read_text())
    frame["opaque"] = opaque
    fixture_path.write_text(json.dumps(frame) + "\n")

    with pytest.raises(ValueError, match="artifact hygiene"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_raw_artifact_scan_rejects_ssh_material_in_synthetic_binary(
    tmp_path: Path,
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "credential.bin"
    fixture_path.write_bytes(b"synthetic-fixture\nssh-ed25519 AAAATEST\n")

    with pytest.raises(ValueError, match="artifact hygiene"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_artifact_hygiene_allows_public_hosts_and_unrelated_internal_word() -> None:
    module = _load_generator_module()
    module._validate_artifact_hygiene(
        {
            "endpoint": "api.example.invalid",
            "nestedLabel": "api.internal.example.invalid",
            "nestedLabelUrl": "https://api.internal.example.invalid/v2/jobs",
            "path": "/workspace/synthetic-output",
            "note": "internal consistency and kube scheduling check",
            "documentationIps": ["192.0.2.1", "2001:db8::1", "::ffff:8.8.8.8"],
        },
        "public synthetic fixture",
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "localhost",
        "http://localhost:8080",
        "service.localhost",
        "localhost.",
        "https://service.localhost.:8443/v2/jobs",
        "kcs-control.internal.",
        "https://kcs-control.internal./v2/jobs",
    ],
)
def test_artifact_hygiene_rejects_private_host_endpoints(endpoint: str) -> None:
    module = _load_generator_module()

    with pytest.raises(ValueError, match="artifact hygiene"):
        module._validate_artifact_hygiene(
            {"endpoint": endpoint},
            "private synthetic fixture",
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "::ffff:127.0.0.1",
        "http://[::ffff:127.0.0.1]:8080",
        "::ffff:10.1.2.3",
        "0.0.0.0",
        "http://0.0.0.0:8080",
        "100.64.0.1",
        "::",
        "http://[::]:8080",
    ],
)
def test_artifact_hygiene_rejects_non_public_network_endpoints(endpoint: str) -> None:
    module = _load_generator_module()

    with pytest.raises(ValueError, match="artifact hygiene"):
        module._validate_artifact_hygiene(
            {"endpoint": endpoint},
            "non-public synthetic fixture",
        )


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
            "fixtures/error-tombstoned.json",
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
    if message == "sanitized tombstone context":
        fixture_path = source.parent / "examples" / replacement_fixture
        fixture = json.loads(fixture_path.read_text())
        fixture["error"]["context"].pop("tombstone")
        fixture_path.write_text(json.dumps(fixture) + "\n")
    else:
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
    native_fixtures = SOURCE.parent / "native-fixtures"
    cases = {
        "createJob": ("jobs.json", "create-new"),
        "grantCredential": ("credentials.json", "grant-new"),
        "startAgent": ("agent-start.json", "start-new"),
        "registerTransfer": ("transfers.json", "transfer-stage"),
        "putTransferContent": ("transfers.json", "transfer-stage-content"),
        "cancelTransfer": ("transfers.json", "transfer-cancel"),
        "discardTransfer": ("transfers.json", "transfer-discard"),
        "invokeWorkspace": ("workspace.json", "invoke-new"),
        "createTerminalSession": ("terminals.json", "terminal-create"),
        "finalizeJob": ("jobs.json", "finalize-provider-quiesce"),
        "cancelJob": ("jobs.json", "cancel-output-loss"),
        "deleteJob": ("jobs.json", "delete-tombstone"),
    }
    native_requests = {
        "grantRunnerCredential": {
            "request": {
                "headers": {
                    "KCS-Credential-Grant-Ref": "runner-grant-001",
                    "KCS-Credential-Kind": "modelGatewayToken",
                    "KCS-Agent-Run-Ref": "agent-run-001",
                    "KCS-Generation": "1",
                    "KCS-Native-Launch-Digest": "6" * 64,
                    "KCS-Audience": "model-gateway",
                    "KCS-Credential-SHA256": "4" * 64,
                    "KCS-Projection-TTL-Seconds": "180",
                    "KCS-Job-UID": "11111111-1111-4111-8111-111111111111",
                    "KCS-Pod-UID": "22222222-2222-4222-8222-222222222222",
                }
            },
            "bodyBytes": b"synthetic-native-runner-credential",
        },
        "startRunner": {
            "request": {},
            "body": json.loads((native_fixtures / "runner-start-request.json").read_text()),
        },
        "stopRunner": {
            "request": {},
            "body": json.loads((native_fixtures / "runner-stop-request.json").read_text()),
        },
    }
    operations = {
        operation["operationId"]: operation
        for path_item in document["paths"].values()
        for method, operation in path_item.items()
        if method in {"post", "put", "delete"} and "x-kcs-digest-projection" in operation
    }
    assert set(cases) | set(native_requests) == set(operations)

    for operation_id in operations:
        if operation_id in native_requests:
            native_request = native_requests[operation_id]
            request = json.loads(json.dumps(native_request["request"]))
            body = native_request.get("body")
            body_bytes = native_request.get("bodyBytes")
        else:
            bundle_name, scenario = cases[operation_id]
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
                elif operation_id == "createTerminalSession":
                    payload_body["spec"]["ttlSeconds"] += 1
                elif operation_id == "finalizeJob":
                    payload_body["spec"]["drainTimeoutSeconds"] += 1
                elif operation_id == "cancelJob":
                    payload_body["spec"]["reason"] = "changed-reason"
                elif operation_id == "startRunner":
                    payload_body["descriptor"]["executionEnvelopeRef"] = "changed-envelope"
                elif operation_id == "stopRunner":
                    payload_body["spec"]["reason"] = "cancel_requested"
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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("conflictStatus", 422),
        ("recoveryAction", "retry_same"),
        ("replayStatus", 299),
        ("newStatus", "200"),
    ],
)
def test_generator_rejects_replay_conflict_error_map_drift(
    tmp_path: Path, field: str, value: object
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    operation = document["paths"]["/api/v2/jobs/{jobRef}/transfers/{transferRef}/content"]["put"]
    operation["x-kcs-replay"][field] = value
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
    "case",
    [
        "provider-filter",
        "subject-filter",
        "state-filter",
        "created-after-filter",
        "include-deleted",
        "page-size",
        "ordering",
    ],
)
def test_generator_binds_list_page_to_filters_size_and_order(tmp_path: Path, case: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    examples = source.parent / "examples"
    bundle_path = examples / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == "list-page")
    fixture_path = examples / exchange["response"]["bodyFixture"]
    page = json.loads(fixture_path.read_text())
    job = json.loads((examples / "fixtures" / "job-binding.json").read_text())
    tombstone = json.loads((examples / "fixtures" / "tombstone.json").read_text())
    query = exchange["request"]["query"]

    if case == "provider-filter":
        job["providerRequestId"] = "another-provider-request"
        page["items"] = [job]
    elif case == "subject-filter":
        query["subjectRef"] = "attempt-synthetic-001"
        job["subjectRef"] = "another-attempt"
        page["items"] = [job]
    elif case == "state-filter":
        query["state"] = ["running"]
        job["bindingState"] = "failed"
        page["items"] = [job]
    elif case == "created-after-filter":
        query["createdAfter"] = "2026-08-01T00:00:01Z"
        page["items"] = [job]
    elif case == "include-deleted":
        page["tombstones"] = [tombstone]
    elif case == "page-size":
        query["pageSize"] = 1
        second = json.loads(json.dumps(job))
        second["jobRef"] = "job-synthetic-002"
        page["items"] = [job, second]
    else:
        second = json.loads(json.dumps(job))
        second["jobRef"] = "job-synthetic-000"
        page["items"] = [job, second]

    bundle_path.write_text(json.dumps(bundle) + "\n")
    fixture_path.write_text(json.dumps(page) + "\n")

    with pytest.raises(ValueError, match="list response"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    "case",
    [
        "default-include-deleted",
        "mixed-page-size",
        "item-created-at-order",
        "tombstone-created-at-order",
        "tombstone-job-ref-order",
        "offset-chronology",
    ],
)
def test_generator_binds_list_page_across_live_and_tombstone_collections(
    tmp_path: Path, case: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    examples = source.parent / "examples"
    bundle_path = examples / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == "list-page")
    fixture_path = examples / exchange["response"]["bodyFixture"]
    page = json.loads(fixture_path.read_text())
    job = json.loads((examples / "fixtures" / "job-binding.json").read_text())
    tombstone = json.loads((examples / "fixtures" / "tombstone.json").read_text())
    query = exchange["request"]["query"]
    query.pop("providerRequestId", None)

    if case == "default-include-deleted":
        query.pop("includeDeleted", None)
        page["tombstones"] = [tombstone]
    elif case == "mixed-page-size":
        query.update({"includeDeleted": True, "pageSize": 1})
        page.update({"items": [job], "tombstones": [tombstone]})
    elif case == "item-created-at-order":
        second = json.loads(json.dumps(job))
        job["createdAt"] = "2026-08-01T00:00:01Z"
        second.update(
            {
                "jobRef": "job-synthetic-002",
                "providerRequestId": "provider-request-synthetic-002",
                "jobUid": "33333333-3333-4333-8333-333333333333",
                "createdAt": "2026-08-01T00:00:00Z",
            }
        )
        page["items"] = [job, second]
    elif case == "tombstone-created-at-order":
        query["includeDeleted"] = True
        second = json.loads(json.dumps(tombstone))
        tombstone["createdAt"] = "2026-08-01T00:00:01Z"
        second.update(
            {
                "jobRef": "job-synthetic-002",
                "providerRequestId": "provider-request-synthetic-002",
                "jobUid": "33333333-3333-4333-8333-333333333333",
                "createdAt": "2026-08-01T00:00:00Z",
            }
        )
        page["tombstones"] = [tombstone, second]
    elif case == "tombstone-job-ref-order":
        query["includeDeleted"] = True
        second = json.loads(json.dumps(tombstone))
        second.update(
            {
                "jobRef": "job-synthetic-000",
                "providerRequestId": "provider-request-synthetic-002",
                "jobUid": "33333333-3333-4333-8333-333333333333",
            }
        )
        page["tombstones"] = [tombstone, second]
    else:
        second = json.loads(json.dumps(job))
        job["createdAt"] = "2026-08-01T00:30:00Z"
        second.update(
            {
                "jobRef": "job-synthetic-002",
                "providerRequestId": "provider-request-synthetic-002",
                "jobUid": "33333333-3333-4333-8333-333333333333",
                "createdAt": "2026-08-01T01:00:00+01:00",
            }
        )
        page["items"] = [job, second]

    bundle_path.write_text(json.dumps(bundle) + "\n")
    fixture_path.write_text(json.dumps(page) + "\n")

    with pytest.raises(ValueError, match="list response"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("case", ["duplicate-live", "duplicate-provider", "live-tombstone-overlap"])
def test_generator_rejects_duplicate_list_identities(tmp_path: Path, case: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    examples = source.parent / "examples"
    bundle_path = examples / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == "list-page")
    exchange["request"]["query"].pop("providerRequestId", None)
    exchange["request"]["query"]["includeDeleted"] = True
    fixture_path = examples / exchange["response"]["bodyFixture"]
    page = json.loads(fixture_path.read_text())
    job = json.loads((examples / "fixtures" / "job-binding.json").read_text())
    tombstone = json.loads((examples / "fixtures" / "tombstone.json").read_text())
    if case == "duplicate-live":
        page["items"] = [job, json.loads(json.dumps(job))]
    elif case == "duplicate-provider":
        second = json.loads(json.dumps(job))
        second.update(
            {
                "jobRef": "job-synthetic-002",
                "jobUid": "33333333-3333-4333-8333-333333333333",
            }
        )
        page["items"] = [job, second]
    else:
        page.update({"items": [job], "tombstones": [tombstone]})
    bundle_path.write_text(json.dumps(bundle) + "\n")
    fixture_path.write_text(json.dumps(page) + "\n")

    with pytest.raises(ValueError, match="duplicate list identity"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_consumes_list_stable_merge_extension(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    document["paths"]["/api/v2/jobs"]["get"]["x-kcs-ordering"]["strategy"] = "concatenate"
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="operation contract policy"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_accepts_scalar_state_filter(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    examples = source.parent / "examples"
    bundle_path = examples / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == "list-page")
    exchange["request"]["query"]["state"] = "running"
    fixture_path = examples / exchange["response"]["bodyFixture"]
    page = json.loads(fixture_path.read_text())
    job = json.loads((examples / "fixtures" / "job-binding.json").read_text())
    page["items"] = [job]
    bundle_path.write_text(json.dumps(bundle) + "\n")
    fixture_path.write_text(json.dumps(page) + "\n")

    module.generate_artifacts(source, tmp_path / "generated")


def test_generator_accepts_lowercase_rfc3339_timestamp(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    examples = source.parent / "examples"
    fixture_path = examples / "fixtures" / "job-list.json"
    page = json.loads(fixture_path.read_text())
    job = json.loads((examples / "fixtures" / "job-binding.json").read_text())
    job["createdAt"] = "2026-08-01t00:00:00z"
    page["items"] = [job]
    fixture_path.write_text(json.dumps(page) + "\n")

    module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_scalar_state_filter_mismatch(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    examples = source.parent / "examples"
    bundle_path = examples / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == "list-page")
    exchange["request"]["query"]["state"] = "running"
    fixture_path = examples / exchange["response"]["bodyFixture"]
    page = json.loads(fixture_path.read_text())
    job = json.loads((examples / "fixtures" / "job-binding.json").read_text())
    job["bindingState"] = "failed"
    page["items"] = [job]
    bundle_path.write_text(json.dumps(bundle) + "\n")
    fixture_path.write_text(json.dumps(page) + "\n")

    with pytest.raises(ValueError, match="list response.*state filter"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("case", ["different-cursor", "first-page"])
def test_generator_binds_logs_input_cursor_to_request(tmp_path: Path, case: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    examples = source.parent / "examples"
    bundle_path = examples / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == "logs-continuation")
    fixture_path = examples / exchange["response"]["bodyFixture"]
    logs = json.loads(fixture_path.read_text())
    if case == "different-cursor":
        logs["inputCursor"] = "YW5vdGhlcg"
    else:
        del exchange["request"]["query"]["cursor"]
    bundle_path.write_text(json.dumps(bundle) + "\n")
    fixture_path.write_text(json.dumps(logs) + "\n")

    with pytest.raises(ValueError, match="logs response inputCursor"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    ("bundle_name", "scenario"),
    [
        ("credentials.json", "grant-new"),
        ("credentials.json", "grant-replay"),
        ("credentials.json", "grant-acknowledged"),
        ("credentials.json", "grant-destroyed"),
        ("transfers.json", "transfer-stage-content"),
    ],
)
def test_generator_requires_declared_no_store_response_header(
    tmp_path: Path, bundle_name: str, scenario: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / bundle_name
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == scenario)
    del exchange["response"]["headers"]["Cache-Control"]
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="missing required response headers.*Cache-Control"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_invalid_required_header_extension_without_example(
    tmp_path: Path,
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    response = document["paths"]["/api/v2/openapi.json"]["get"]["responses"]["200"]
    response["x-kcs-required-headers"] = [{"not": "a header name"}]
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="invalid required response header declaration"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    "case",
    [
        "unexercised-invalid-extension",
        "credential-policy-removed",
        "discovery-contract-removed",
    ],
)
def test_generator_validates_required_header_policy_document_wide(
    tmp_path: Path, case: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    if case == "unexercised-invalid-extension":
        response = document["paths"]["/api/v2/jobs/{jobRef}/agent/credential-grants"]["post"][
            "responses"
        ]["401"]
        response["x-kcs-required-headers"] = ["No-Such-Header"]
    elif case == "credential-policy-removed":
        operation = document["paths"]["/api/v2/jobs/{jobRef}/agent/credential-grants"]["post"]
        operation.pop("x-kcs-cache-control")
        response = operation["responses"]["201"]
        response.pop("x-kcs-required-headers")
        response.pop("headers")
    else:
        operation = document["paths"]["/api/v2/openapi.json"]["get"]
        operation.pop("x-kcs-cache-control")
        response = operation["responses"]["200"]
        response.pop("x-kcs-required-headers")
        response.pop("headers")
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="required response header|response header policy"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    "case",
    [
        "etag-pattern",
        "discovery-body",
        "content-length-type",
        "content-digest-type",
        "snapshot-ref-type",
    ],
)
def test_contract_policy_requires_exact_integrity_response_carriers(case: str) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    if case in {"etag-pattern", "discovery-body"}:
        response = document["paths"]["/api/v2/openapi.json"]["get"]["responses"]["200"]
        if case == "etag-pattern":
            response["headers"]["ETag"]["schema"]["pattern"] = ".*"
        else:
            response["content"]["application/json"]["schema"] = {
                "$ref": "#/components/schemas/ErrorEnvelope"
            }
    else:
        response = document["paths"]["/api/v2/jobs/{jobRef}/transfers/{transferRef}/content"][
            "get"
        ]["responses"]["200"]
        if case == "content-length-type":
            response["headers"]["Content-Length"]["schema"]["type"] = "number"
        elif case == "content-digest-type":
            response["headers"]["X-Content-SHA256"]["schema"] = {
                "$ref": "#/components/schemas/OpaqueRef"
            }
        else:
            response["headers"]["X-KCS-Snapshot-Ref"]["schema"] = {
                "$ref": "#/components/schemas/Sha256"
            }

    with pytest.raises(ValueError, match="integrity.*policy"):
        module._validate_contract_extensions(document)


@pytest.mark.parametrize("location", ["bundle", "fixture"])
def test_generator_rejects_duplicate_json_keys(tmp_path: Path, location: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    if location == "bundle":
        path = source.parent / "examples" / "jobs.json"
        original = path.read_text()
        duplicate = '"request": {"privateSshPath": "/synthetic/private/ssh/id"}, "request": {'
        path.write_text(original.replace('"request": {', duplicate, 1))
    else:
        path = source.parent / "examples" / "fixtures" / "error-tombstoned.json"
        original = path.read_text()
        duplicate = '"context": {"privateSshPath": "/synthetic/private/ssh/id"}, "context": {'
        path.write_text(original.replace('"context": {', duplicate, 1))

    with pytest.raises(ValueError, match="duplicate JSON key"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_completed_transfer_with_unresolved_fields(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "transfer-stage.json"
    transfer = json.loads(fixture_path.read_text())
    transfer["state"] = "completed"
    fixture_path.write_text(json.dumps(transfer) + "\n")

    with pytest.raises(ValueError):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    "mutation",
    [
        {"state": "destroyed"},
        {"state": "destroyed", "secretPresent": False},
    ],
)
def test_generator_rejects_destroyed_grant_without_destruction_observation(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "credential-grant.json"
    grant = json.loads(fixture_path.read_text())
    grant.update(mutation)
    fixture_path.write_text(json.dumps(grant) + "\n")

    with pytest.raises(ValueError):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    ("fixture_name", "mutation"),
    [
        ("credential-grant.json", {"availableAt": None}),
        ("credential-grant.json", {"secretPresent": False}),
        ("credential-grant-acknowledged.json", {"ackGeneration": None}),
        ("credential-grant-acknowledged.json", {"ackGeneration": 2}),
        ("credential-grant-acknowledged.json", {"ackAgentRunRef": "another-agent-run"}),
        ("credential-grant-destroyed.json", {"destroyedAt": None}),
    ],
)
def test_generator_enforces_credential_state_field_coherence(
    tmp_path: Path, fixture_name: str, mutation: dict[str, object]
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / fixture_name
    grant = json.loads(fixture_path.read_text())
    grant.update(mutation)
    fixture_path.write_text(json.dumps(grant) + "\n")

    with pytest.raises(ValueError):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    ("fixture_name", "mutation"),
    [
        ("transfer-stage.json", {"actualSizeBytes": 22}),
        ("transfer-stage.json", {"verified": True}),
        ("transfer-canceled.json", {"completedAt": None}),
        ("transfer-discarded.json", {"completedAt": None}),
    ],
)
def test_generator_enforces_transfer_state_field_coherence(
    tmp_path: Path, fixture_name: str, mutation: dict[str, object]
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / fixture_name
    transfer = json.loads(fixture_path.read_text())
    transfer.update(mutation)
    fixture_path.write_text(json.dumps(transfer) + "\n")

    with pytest.raises(ValueError):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    ("fixture_name", "action_name", "action_mutation"),
    [
        ("transfer-canceled.json", "cancelAction", {"state": "failed"}),
        (
            "transfer-canceled.json",
            "cancelAction",
            {
                "state": "not_requested",
                "actionRef": None,
                "requestDigest": None,
                "observedAt": None,
            },
        ),
        ("transfer-discarded.json", "discardAction", {"state": "failed"}),
        (
            "transfer-discarded.json",
            "discardAction",
            {
                "state": "not_requested",
                "actionRef": None,
                "requestDigest": None,
                "observedAt": None,
            },
        ),
    ],
)
def test_transfer_terminal_state_requires_successful_matching_action(
    fixture_name: str,
    action_name: str,
    action_mutation: dict[str, object],
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"]["TransferSnapshot"]
    transfer = json.loads((SOURCE.parent / "examples" / "fixtures" / fixture_name).read_text())

    module._validate_instance(transfer, schema, document, "valid transfer terminal state")

    transfer[action_name].update(action_mutation)
    with pytest.raises(ValueError):
        module._validate_instance(transfer, schema, document, "invalid transfer terminal state")


@pytest.mark.parametrize(
    ("schema_name", "fixture_name", "mutation"),
    [
        ("JobBindingSnapshot", "job-binding.json", {"observedPodCount": 0}),
        (
            "GenerationSnapshot",
            "generation.json",
            {"runnerState": "exited", "finishedAt": None, "exitCode": None},
        ),
        (
            "WorkspaceOperationSnapshot",
            "workspace-operation-inline.json",
            {"finishedAt": None},
        ),
        (
            "WorkspaceOperationSnapshot",
            "workspace-operation-inline.json",
            {"exitCode": 7},
        ),
    ],
)
def test_canonical_schemas_enforce_observed_state_coherence(
    schema_name: str, fixture_name: str, mutation: dict[str, object]
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"][schema_name]
    instance = json.loads((SOURCE.parent / "examples" / "fixtures" / fixture_name).read_text())
    instance.update(mutation)

    with pytest.raises(ValueError):
        module._validate_instance(instance, schema, document, "state coherence")


@pytest.mark.parametrize(
    ("binding_state", "action_name"),
    [
        ("finalizing", "finalizeAction"),
        ("canceling", "cancelAction"),
        ("deleting", "deleteAction"),
    ],
)
def test_job_transition_state_requires_requested_matching_action(
    binding_state: str, action_name: str
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"]["JobBindingSnapshot"]
    instance = json.loads(
        (SOURCE.parent / "examples" / "fixtures" / "job-binding.json").read_text()
    )
    instance["bindingState"] = binding_state

    with pytest.raises(ValueError):
        module._validate_instance(instance, schema, document, "unrequested job transition")

    instance[action_name] = {
        "actionRef": f"{action_name}-synthetic",
        "requestDigest": "1" * 64,
        "state": "failed",
        "observedAt": "2026-08-01T00:00:00Z",
    }
    module._validate_instance(instance, schema, document, "observed failed job transition")


@pytest.mark.parametrize(
    "instance",
    [
        {
            "actionRef": "action-synthetic",
            "requestDigest": "1" * 64,
            "state": "not_requested",
            "observedAt": "2026-08-01T00:00:00Z",
        },
        {
            "actionRef": None,
            "requestDigest": None,
            "state": "accepted",
            "observedAt": None,
        },
    ],
)
def test_action_snapshot_state_binds_identity_and_observation(
    instance: dict[str, object],
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"]["ActionSnapshot"]

    with pytest.raises(ValueError):
        module._validate_instance(instance, schema, document, "action state coherence")


@pytest.mark.parametrize(
    "mutation",
    [
        {"deletedAt": "2026-07-31T23:59:59Z"},
        {"expiresAt": "2026-08-01T00:59:59Z"},
    ],
)
def test_generator_consumes_tombstone_time_ordering_extension(
    mutation: dict[str, object],
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    schema = document["components"]["schemas"]["JobTombstone"]
    tombstone = json.loads((SOURCE.parent / "examples" / "fixtures" / "tombstone.json").read_text())
    tombstone.update(mutation)

    with pytest.raises(ValueError, match="time ordering"):
        module._validate_instance(tombstone, schema, document, "tombstone")


@pytest.mark.parametrize("case", ["removed", "reordered"])
def test_generator_requires_exact_tombstone_time_ordering_extension(
    tmp_path: Path, case: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    tombstone = document["components"]["schemas"]["JobTombstone"]
    if case == "removed":
        tombstone.pop("x-kcs-time-ordering")
    else:
        tombstone["x-kcs-time-ordering"] = ["deletedAt", "createdAt", "expiresAt"]
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="JobTombstone time ordering declaration"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("location", ["bundle", "exchange", "request", "response"])
def test_generator_rejects_unknown_private_route_metadata(tmp_path: Path, location: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    target = {
        "bundle": bundle,
        "exchange": bundle["exchanges"][0],
        "request": bundle["exchanges"][0]["request"],
        "response": bundle["exchanges"][0]["response"],
    }[location]
    target["privateSshPath"] = "/synthetic/private/ssh/id"
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match=rf"undeclared {location} fields.*privateSshPath"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    "case",
    [
        "json-with-body-file",
        "body-patch-without-body",
        "string-status",
        "non-string-replay-link",
        "both-replay-and-conflict",
    ],
)
def test_generator_rejects_ambiguous_route_exchange_metadata(tmp_path: Path, case: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = bundle["exchanges"][0]
    if case == "json-with-body-file":
        exchange["request"]["bodyFile"] = "fixtures/credential.bin"
    elif case == "body-patch-without-body":
        inspect = next(
            item for item in bundle["exchanges"] if item["scenario"] == "binding-inspect"
        )
        inspect["request"]["bodyPatch"] = {"privateSshPath": "/synthetic/private/ssh/id"}
    elif case == "string-status":
        exchange["response"]["status"] = "201"
    elif case == "non-string-replay-link":
        exchange["replayOf"] = 7
    else:
        replay = next(item for item in bundle["exchanges"] if item["scenario"] == "create-replay")
        replay["conflictsWith"] = "create-new"
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="route exchange metadata"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("field", ["jobRef", "jobUid", "podUid"])
def test_generator_binds_tombstone_to_original_create_binding(tmp_path: Path, field: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "error-tombstoned.json"
    envelope = json.loads(fixture_path.read_text())
    tombstone = envelope["error"]["context"]["tombstone"]
    replacement = "job-other" if field == "jobRef" else "33333333-3333-4333-8333-333333333333"
    tombstone[field] = replacement
    if field == "jobRef":
        envelope["error"]["context"]["jobRef"] = replacement
    fixture_path.write_text(json.dumps(envelope) + "\n")

    with pytest.raises(ValueError, match="cross-exchange binding"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("case", ["provider-request", "spec-digest"])
def test_generator_binds_coupled_create_tombstone_to_create_anchor(
    tmp_path: Path, case: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == "create-tombstone")
    if case == "provider-request":
        exchange["request"]["bodyPatch"] = {"providerRequestId": "provider-request-other"}
        exchange["response"]["bodyPatch"] = {
            "error": {"context": {"tombstone": {"providerRequestId": "provider-request-other"}}}
        }
    else:
        request = json.loads(
            (source.parent / "examples" / exchange["request"]["bodyFixture"]).read_text()
        )
        request["spec"]["activeDeadlineSeconds"] += 1
        request["specDigest"] = module.jcs_sha256(request["spec"])
        exchange["request"]["bodyPatch"] = {
            "spec": request["spec"],
            "specDigest": request["specDigest"],
        }
        exchange["response"]["bodyPatch"] = {
            "error": {"context": {"tombstone": {"specDigest": request["specDigest"]}}}
        }
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="cross-exchange binding"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("field", ["requestDigest", "spec"])
def test_generator_binds_stage_content_to_registered_transfer(tmp_path: Path, field: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "transfer-stage-completed.json"
    transfer = json.loads(fixture_path.read_text())
    if field == "requestDigest":
        transfer[field] = "2" * 64
    else:
        transfer["spec"]["path"] = "inputs/other.bin"
    fixture_path.write_text(json.dumps(transfer) + "\n")

    with pytest.raises(ValueError, match="cross-exchange binding"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    ("bundle_name", "scenario", "patch"),
    [
        ("jobs.json", "create-replay", {"providerHandle": "provider-handle-other"}),
        (
            "jobs.json",
            "binding-inspect",
            {"providerRequestId": "provider-request-other"},
        ),
        (
            "jobs.json",
            "logs-continuation",
            {"jobUid": "33333333-3333-4333-8333-333333333333"},
        ),
        (
            "jobs.json",
            "finalize-provider-quiesce",
            {"jobUid": "33333333-3333-4333-8333-333333333333"},
        ),
        (
            "jobs.json",
            "delete-tombstone",
            {"finalState": "failed"},
        ),
        (
            "credentials.json",
            "grant-acknowledged",
            {"acceptedAt": "2026-08-01T00:00:59Z"},
        ),
        (
            "credentials.json",
            "grant-destroyed",
            {"grantMetadataDigest": "2" * 64},
        ),
        (
            "transfers.json",
            "transfer-cancel",
            {"createdAt": "2026-08-01T00:02:59Z"},
        ),
        (
            "transfers.json",
            "transfer-collect-completed",
            {"podUid": "33333333-3333-4333-8333-333333333333"},
        ),
        (
            "workspace.json",
            "invoke-result-transfer",
            {"storedFrameDigest": "2" * 64},
        ),
        (
            "workspace.json",
            "invoke-indeterminate",
            {"binding": {"podUid": "33333333-3333-4333-8333-333333333333"}},
        ),
    ],
)
def test_generator_rejects_cross_exchange_anchor_drift(
    tmp_path: Path, bundle_name: str, scenario: str, patch: dict[str, object]
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / bundle_name
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == scenario)
    existing = exchange["response"].get("bodyPatch", {})
    exchange["response"]["bodyPatch"] = module._merge_patch(existing, patch)
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="cross-exchange binding"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_binds_coupled_credential_availability_to_grant_anchor(
    tmp_path: Path,
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "credentials.json"
    bundle = json.loads(bundle_path.read_text())
    for exchange in bundle["exchanges"]:
        if exchange["scenario"] in {"grant-acknowledged", "grant-destroyed"}:
            exchange["response"]["bodyPatch"] = {"availableAt": "2026-08-01T00:01:02Z"}
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="cross-exchange binding"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_binds_transfer_path_and_response_to_registration(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "transfers.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(
        item for item in bundle["exchanges"] if item["scenario"] == "transfer-stage-content"
    )
    exchange["request"]["path"]["transferRef"] = "transfer-stage-other"
    exchange["response"]["bodyPatch"] = {"transferRef": "transfer-stage-other"}
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="cross-exchange binding"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    ("scenario", "replacement"),
    [
        ("transfer-collect-completed", "transfer-collect-other"),
        ("transfer-cancel", "transfer-stage-other"),
        ("transfer-restart", "transfer-stage-other"),
    ],
)
def test_generator_binds_all_transfer_lifecycle_paths_to_registration(
    tmp_path: Path, scenario: str, replacement: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "transfers.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == scenario)
    exchange["request"]["path"]["transferRef"] = replacement
    exchange["response"]["bodyPatch"] = {"transferRef": replacement}
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="cross-exchange binding"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("scenario", ["invoke-result-transfer", "invoke-indeterminate"])
def test_generator_binds_workspace_inspect_path_to_invoke_anchor(
    tmp_path: Path, scenario: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "workspace.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == scenario)
    exchange["request"]["path"]["operationRef"] = "operation-other"
    exchange["response"]["bodyPatch"] = {"operationRef": "operation-other"}
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="cross-exchange binding"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_binds_agent_start_to_retained_credential_grant(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "agent-start.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == "start-new")
    request_fixture = json.loads(
        (source.parent / "examples" / exchange["request"]["bodyFixture"]).read_text()
    )
    request_fixture["credentialGrantRef"] = "grant-other"
    metadata = {key: value for key, value in request_fixture.items() if key != "generation"}
    for linked in bundle["exchanges"]:
        if linked["scenario"] in {"start-new", "start-replay"}:
            linked["request"]["bodyPatch"] = {"credentialGrantRef": "grant-other"}
            linked["response"]["bodyPatch"] = {
                "credentialGrantRef": "grant-other",
                "startMetadataDigest": module.jcs_sha256(metadata),
            }
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="cross-exchange binding"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_rejects_fully_coupled_generation_one_grant_rebinding(
    tmp_path: Path,
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / "agent-start.json"
    bundle = json.loads(bundle_path.read_text())
    coupled = {
        "credentialGrantRef": "grant-other",
        "agentRunRef": "agent-run-other",
        "generation": 7,
        "launchBundleDigest": "7" * 64,
    }
    for exchange in bundle["exchanges"]:
        if exchange["scenario"] == "start-pod-loss":
            exchange["request"]["bodyPatch"] = coupled
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="cross-exchange binding"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    ("target", "field"),
    [("cancel", "finishCollectTransferRefs"), ("workspace", "resultTransferRef")],
)
def test_generator_only_links_authorized_collect_transfers(
    tmp_path: Path, target: str, field: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    if target == "cancel":
        request_path = source.parent / "examples" / "fixtures" / "cancel-request.json"
        request = json.loads(request_path.read_text())
        request["spec"][field] = ["transfer-stage-synthetic-001"]
        request["requestDigest"] = module.jcs_sha256(request["spec"])
        request_path.write_text(json.dumps(request) + "\n")
        bundle_path = source.parent / "examples" / "jobs.json"
        bundle = json.loads(bundle_path.read_text())
        exchange = next(
            item for item in bundle["exchanges"] if item["scenario"] == "cancel-output-loss"
        )
        exchange["response"]["bodyPatch"]["cancelAction"]["requestDigest"] = request[
            "requestDigest"
        ]
        bundle_path.write_text(json.dumps(bundle) + "\n")
    else:
        fixture_path = (
            source.parent / "examples" / "fixtures" / "workspace-operation-result-transfer.json"
        )
        operation = json.loads(fixture_path.read_text())
        operation[field] = "transfer-stage-synthetic-001"
        fixture_path.write_text(json.dumps(operation) + "\n")

    with pytest.raises(ValueError, match="registered collect transfer"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("field", ["operationRefs", "transferRefs"])
def test_generator_finalize_only_names_registered_work(tmp_path: Path, field: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    request_path = source.parent / "examples" / "fixtures" / "finalize-request.json"
    request = json.loads(request_path.read_text())
    request["spec"][field] = ["unregistered-work"]
    request["requestDigest"] = module.jcs_sha256(request["spec"])
    request_path.write_text(json.dumps(request) + "\n")
    bundle_path = source.parent / "examples" / "jobs.json"
    bundle = json.loads(bundle_path.read_text())
    exchange = next(
        item for item in bundle["exchanges"] if item["scenario"] == "finalize-provider-quiesce"
    )
    exchange["response"]["bodyPatch"]["finalizeAction"]["requestDigest"] = request["requestDigest"]
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="registered work"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    ("bundle_name", "scenario", "recovery_action"),
    [
        ("jobs.json", "create-conflict", "none"),
        ("agent-start.json", "start-pod-loss", "inspect_job"),
    ],
)
def test_generator_binds_error_examples_to_operation_error_map(
    tmp_path: Path, bundle_name: str, scenario: str, recovery_action: str
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    bundle_path = source.parent / "examples" / bundle_name
    bundle = json.loads(bundle_path.read_text())
    exchange = next(item for item in bundle["exchanges"] if item["scenario"] == scenario)
    exchange["response"]["bodyPatch"] = {"error": {"recoveryAction": recovery_action}}
    bundle_path.write_text(json.dumps(bundle) + "\n")

    with pytest.raises(ValueError, match="error map"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("case", ["unknown-code", "undeclared-status", "unknown-recovery"])
def test_generator_validates_entire_operation_error_map(tmp_path: Path, case: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    operation = document["paths"]["/api/v2/jobs/{jobRef}"]["get"]
    error_map = operation["x-kcs-error-codes"]
    if case == "unknown-code":
        error_map["BOGUS"] = {"status": 404, "recoveryAction": "none"}
    elif case == "undeclared-status":
        error_map["NOT_FOUND"]["status"] = 418
    else:
        error_map["NOT_FOUND"]["recoveryAction"] = "guess"
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="error map declaration"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("extension", ["x-kcs-digest-projection", "x-kcs-replay"])
def test_generator_requires_mutation_safety_extensions(tmp_path: Path, extension: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    document["paths"]["/api/v2/jobs"]["post"].pop(extension)
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="mutation safety declaration"):
        module.generate_artifacts(source, tmp_path / "generated")


def test_generator_requires_exact_operation_authorization(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    document["paths"]["/api/v2/jobs"]["post"]["x-kcs-service-authorization"] = "v2-reader"
    source.write_text(yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ValueError, match="service authorization declaration"):
        module.generate_artifacts(source, tmp_path / "generated")


def _mutate_contract_policy(
    document: dict[str, object], path: tuple[str, ...], replacement: object
) -> None:
    target = document
    for segment in path[:-1]:
        target = target[segment]
    if replacement is None:
        target.pop(path[-1])
    else:
        target[path[-1]] = replacement


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("security",), None),
        (("servers",), [{"url": "https://api.example.invalid"}]),
        (("components", "securitySchemes", "v2ServiceBearer", "scheme"), "basic"),
        (("paths", "/api/v2/jobs", "get", "security"), []),
    ],
)
def test_contract_policy_requires_exact_global_security_and_no_overrides(
    path: tuple[str, ...], replacement: object
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    _mutate_contract_policy(document, path, replacement)

    with pytest.raises(ValueError, match="security|server"):
        module._validate_contract_extensions(document)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("info", "x-kcs-features", "signedTransfers"), True),
        (("info", "x-kcs-limits", "tombstoneRetentionSeconds"), 1),
        (("info", "x-kcs-limits", "credentialBytes"), 1),
        (("info", "x-kcs-limits", "paginationDefault"), 1),
        (("x-kcs-legacy-authorization", "mutations"), "allowed"),
        (("x-kcs-network-boundary", "tlsRequired"), False),
        (("x-kcs-network-boundary", "privateIngressRequired"), False),
    ],
)
def test_contract_policy_requires_exact_root_machine_policy(
    path: tuple[str, ...], replacement: object
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    _mutate_contract_policy(document, path, replacement)

    with pytest.raises(ValueError, match="root contract policy"):
        module._validate_contract_extensions(document)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (
            (
                "paths",
                "/api/v2/jobs",
                "post",
                "x-kcs-unknown-outcome-recovery",
                "maximumMatches",
            ),
            2,
        ),
        (
            ("paths", "/api/v2/jobs", "get", "x-kcs-page-token-binding"),
            ["namespace", "providerRequestId"],
        ),
        (
            ("paths", "/api/v2/jobs/{jobRef}/logs", "get", "x-kcs-cursor-binding"),
            ["namespace", "jobRef", "container"],
        ),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}/workspace/invoke",
                "post",
                "x-kcs-forward-body-unchanged",
            ),
            False,
        ),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}/finalize",
                "post",
                "x-kcs-provider-only-quiesce",
            ),
            False,
        ),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
                "put",
                "x-kcs-no-request-body-log",
            ),
            False,
        ),
        (
            (
                "paths",
                "/api/v2/openapi.json",
                "get",
                "responses",
                "200",
                "x-kcs-etag-derivation",
            ),
            None,
        ),
    ],
)
def test_contract_policy_requires_exact_operation_machine_policy(
    path: tuple[str, ...], replacement: object
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    _mutate_contract_policy(document, path, replacement)

    with pytest.raises(ValueError, match="operation contract policy"):
        module._validate_contract_extensions(document)


@pytest.mark.parametrize(
    ("extension", "replacement"),
    [
        ("x-kcs-private-ingress", False),
        ("x-kcs-request-body-logging", "allowed"),
        ("x-kcs-no-request-body-log", False),
        ("x-kcs-redact-headers", ["Authorization"]),
        ("x-kcs-rbac-boundary", "cluster-wide"),
        ("x-kcs-legacy-proxy-access", "allowed"),
    ],
)
def test_contract_policy_requires_exact_credential_privacy_controls(
    extension: str, replacement: object
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    operation = document["paths"]["/api/v2/jobs/{jobRef}/agent/credential-grants"]["post"]
    operation[extension] = replacement

    with pytest.raises(ValueError, match="credential privacy policy"):
        module._validate_contract_extensions(document)


@pytest.mark.parametrize(
    ("operation_id", "code", "replacement"),
    [
        ("listJobs", "UNAUTHENTICATED", {"status": 401, "recoveryAction": "retry_same"}),
        ("listJobs", "FORBIDDEN", {"status": 403, "recoveryAction": "retry_same"}),
    ],
)
def test_contract_policy_requires_exact_authentication_error_semantics(
    operation_id: str, code: str, replacement: dict[str, object]
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    operation = module._operation_index(document)[operation_id][2]
    operation["x-kcs-error-codes"][code] = replacement

    with pytest.raises(ValueError, match="authentication error policy"):
        module._validate_contract_extensions(document)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("components", "schemas", "Environment", "x-kcs-secret-value-policy"), "allow"),
        (("components", "schemas", "JobSpec", "x-kcs-default-semantics"), "apply-defaults"),
        (("components", "schemas", "SafeRelativePath", "x-kcs-case-policy"), "fold-case"),
        (
            ("components", "schemas", "TransferSpec", "x-kcs-path-collision-policy"),
            "replace-existing",
        ),
        (("components", "schemas", "WorkspaceFrame", "x-kcs-forward-unchanged"), False),
        (("components", "schemas", "OpaqueRef", "x-kcs-maxUtf8Bytes"), 1),
        (("components", "schemas", "WorkspaceFrame", "x-kcs-maxCanonicalBytes"), 1),
        (
            (
                "components",
                "schemas",
                "WorkspaceOperationSnapshot",
                "properties",
                "stdout",
                "x-kcs-maxUtf8Bytes",
            ),
            1,
        ),
    ],
)
def test_contract_policy_requires_exact_schema_machine_policy(
    path: tuple[str, ...], replacement: object
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    _mutate_contract_policy(document, path, replacement)

    with pytest.raises(ValueError, match="schema contract policy"):
        module._validate_contract_extensions(document)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (
            ("paths", "/api/v2/jobs", "post", "x-kcs-digest-projection", "kind"),
            "implementation-defined",
        ),
        (
            (
                "paths",
                "/api/v2/jobs/{jobRef}",
                "get",
                "x-kcs-error-codes",
                "INTERNAL_ERROR",
                "recoveryAction",
            ),
            "retry_same",
        ),
        (
            (
                "components",
                "schemas",
                "RoleLogs",
                "properties",
                "content",
                "x-kcs-maxUtf8Bytes",
            ),
            None,
        ),
        (("info", "x-kcs-new-policy"), {"mode": "weakened"}),
    ],
)
def test_contract_policy_fingerprint_closes_all_machine_extension_drift(
    path: tuple[str, ...], replacement: object
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    _mutate_contract_policy(document, path, replacement)
    module._validate_contract_extensions(document)

    with pytest.raises(ValueError, match="machine policy extension fingerprint"):
        module._validate_frozen_contract_fingerprints(document)


@pytest.mark.parametrize(
    "case",
    [
        "trace-operation",
        "head-operation",
        "options-operation",
        "webhook",
        "callback",
        "path-server-override",
        "operation-server-override",
        "extra-path",
        "path-item-ref",
    ],
)
def test_contract_policy_rejects_extra_or_overridden_openapi_surface(case: str) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    if case in {"trace-operation", "head-operation", "options-operation"}:
        method = case.removesuffix("-operation")
        document["paths"]["/api/v2/jobs"][method] = {
            "operationId": f"anonymous{method.title()}",
            "security": [],
            "responses": {"204": {"description": "unexpected method surface"}},
        }
    elif case == "webhook":
        document["webhooks"] = {
            "unauthenticatedInbound": {
                "post": {
                    "operationId": "unauthenticatedWebhook",
                    "security": [],
                    "responses": {"204": {"description": "unexpected webhook surface"}},
                }
            }
        }
    elif case == "callback":
        document["paths"]["/api/v2/jobs"]["post"]["callbacks"] = {
            "unexpected": {
                "{$request.body#/callbackUrl}": {
                    "post": {
                        "operationId": "unexpectedCallback",
                        "security": [],
                        "responses": {"204": {"description": "unexpected callback"}},
                    }
                }
            }
        }
    elif case == "path-server-override":
        document["paths"]["/api/v2/jobs"]["servers"] = [{"url": "https://api.example.invalid"}]
    elif case == "operation-server-override":
        document["paths"]["/api/v2/jobs"]["get"]["servers"] = [
            {"url": "https://api.example.invalid"}
        ]
    elif case == "extra-path":
        document["paths"]["/api/v2/extra"] = {"description": "unexpected path surface"}
    else:
        document["components"]["pathItems"] = {
            "Bypass": {
                "post": {
                    "operationId": "pathItemBypass",
                    "security": [],
                    "responses": {"204": {"description": "unexpected referenced surface"}},
                }
            }
        }
        document["paths"]["/api/v2/bypass"] = {"$ref": "#/components/pathItems/Bypass"}

    with pytest.raises(ValueError, match="route surface|server|callback|webhook"):
        module._validate_contract_extensions(document)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("components", "schemas", "OpaqueRef", "maxLength"), 999),
        (("components", "schemas", "Environment", "maxProperties"), 999),
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
            999999,
        ),
        (("components", "parameters", "LogLimit", "schema", "default"), 1),
        (("components", "parameters", "PageSize", "schema", "maximum"), 201),
        (("components", "parameters", "CredentialTtlHeader", "schema", "maximum"), 901),
        (
            (
                "components",
                "schemas",
                "AgentStartRequest",
                "properties",
                "launchBundleSizeBytes",
                "maximum",
            ),
            1048577,
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
            107374182401,
        ),
        (
            (
                "components",
                "schemas",
                "RoleLogs",
                "properties",
                "content",
                "maxLength",
            ),
            1048577,
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
            65537,
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
            107374182401,
        ),
    ],
)
def test_contract_policy_requires_exact_limit_carriers(
    path: tuple[str, ...], replacement: object
) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    _mutate_contract_policy(document, path, replacement)

    with pytest.raises(ValueError, match="limit carrier"):
        module._validate_contract_extensions(document)


@pytest.mark.parametrize(
    "path",
    [
        ("components", "schemas", "Environment", "additionalProperties", "format"),
        ("components", "schemas", "SafeRelativePath", "format"),
        ("components", "schemas", "OpaqueCursor", "format"),
        ("components", "schemas", "OpaquePageToken", "format"),
        ("components", "schemas", "Timestamp", "format"),
        ("components", "schemas", "KubernetesUid", "format"),
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
    ],
)
def test_contract_policy_requires_exact_format_carriers(path: tuple[str, ...]) -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    _mutate_contract_policy(document, path, None)

    with pytest.raises(ValueError, match="format carrier"):
        module._validate_contract_extensions(document)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("components", "schemas", "ErrorEnvelope", "additionalProperties"), True),
        (("info", "title"), "Weakened API"),
        (
            (
                "components",
                "schemas",
                "ErrorEnvelope",
                "properties",
                "diagnostic",
            ),
            {"type": "string"},
        ),
    ],
)
def test_contract_policy_fingerprint_closes_standard_enforcement_drift(
    tmp_path: Path, path: tuple[str, ...], replacement: object
) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    document = yaml.safe_load(source.read_text())
    _mutate_contract_policy(document, path, replacement)
    source.write_text(yaml.safe_dump(document, sort_keys=False))
    output_dir = tmp_path / "generated"

    with pytest.raises(ValueError, match="standard contract enforcement fingerprint"):
        module.generate_artifacts(source, output_dir)
    assert not output_dir.exists()


def test_generator_binds_typed_error_context_to_request_path(tmp_path: Path) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    fixture_path = source.parent / "examples" / "fixtures" / "error-not-found.json"
    envelope = json.loads(fixture_path.read_text())
    envelope["error"]["context"]["jobRef"] = "another-missing-job"
    fixture_path.write_text(json.dumps(envelope) + "\n")

    with pytest.raises(ValueError, match="error context"):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize(
    ("bundle_name", "scenario", "mutate", "message"),
    [
        (
            "transfers.json",
            "transfer-stage-content",
            lambda body: body.update({"verified": False}),
            "True was expected|uploaded transfer must be completed and verified",
        ),
        (
            "transfers.json",
            "transfer-stage-content",
            lambda body: body.update({"completedAt": None}),
            "None is not of type 'string'|uploaded transfer must be completed and verified",
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

    with pytest.raises(ValueError, match="missing required response headers"):
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

    with pytest.raises(
        ValueError,
        match=(
            "cross-exchange binding drift in spec|"
            "collect content does not match its completed snapshot"
        ),
    ):
        module.generate_artifacts(source, tmp_path / "generated")


@pytest.mark.parametrize("suffix", ["json", "bin"])
def test_generator_rejects_unreferenced_fixture(tmp_path: Path, suffix: str) -> None:
    module = _load_generator_module()
    source = _copy_openapi(tmp_path)
    orphan = source.parent / "examples" / "fixtures" / f"orphan.{suffix}"
    orphan.write_bytes(b"{}\n" if suffix == "json" else b"synthetic-orphan\n")

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
