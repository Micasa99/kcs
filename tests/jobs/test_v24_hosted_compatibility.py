from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "openapi" / "kcs-v2-jobs.openapi.yaml"
SERVED_PACKAGE = ROOT / "src" / "kcs" / "openapi" / "kcs-v2-jobs.openapi.json"
NATIVE_FIXTURES = ROOT / "openapi" / "native-fixtures"
HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}
SERVED_23_SHA256 = "965ec1236bab74d2306ce96c97109abc12f80971f18dc32b3bb7602bc8fed526"
NATIVE_OPERATIONS = {
    "grantRunnerCredential",
    "inspectRunnerCredentialGrant",
    "startRunner",
    "stopRunner",
    "resolveRuntimeRecipe",
}
PROTECTED_HOSTED_SCHEMAS = {
    "AgentResources",
    "WorkspaceResources",
    "AgentSpec",
    "WorkspaceSpec",
    "SharedWorkspaceSpec",
    "JobSpec",
    "AgentRequestedResources",
    "AgentObservedResources",
    "WorkspaceRequestedResources",
    "WorkspaceObservedResources",
    "AgentRoleSnapshot",
    "WorkspaceRoleSnapshot",
    "GenerationSnapshot",
    "AgentStartRequest",
    "TerminalSessionSnapshot",
    "JobBindingSnapshot",
    "JobBindingSnapshotList",
    "RoleLogs",
    "CredentialGrantSnapshot",
    "FinalizeSpec",
    "FinalizeJobRequest",
}


def _load_generator_module():
    path = ROOT / "scripts" / "generate_v2_openapi_artifacts.py"
    spec = importlib.util.spec_from_file_location("generate_v2_openapi_artifacts", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _operations(document: dict) -> dict[str, tuple[str, str, dict]]:
    return {
        operation["operationId"]: (method, path, operation)
        for path, path_item in document["paths"].items()
        for method, operation in path_item.items()
        if method in HTTP_METHODS
    }


def test_v24_is_additive_over_the_frozen_served_v23_hosted_contract() -> None:
    current = yaml.safe_load(SOURCE.read_text())
    served = json.loads(SERVED_PACKAGE.read_text())
    current_operations = _operations(current)
    served_operations = _operations(served)

    assert served["info"]["version"] == "2.3.0"
    assert hashlib.sha256(SERVED_PACKAGE.read_bytes()).hexdigest() == SERVED_23_SHA256
    assert current["info"]["version"] == "2.4.0"
    assert current["x-kcs-contract-status"] == "dormant"
    assert len(served_operations) == 31
    assert len(current_operations) == 36
    assert set(current_operations) - set(served_operations) == NATIVE_OPERATIONS

    for operation_id, (method, path, old_operation) in served_operations.items():
        new_method, new_path, new_operation = current_operations[operation_id]
        assert (new_method, new_path) == (method, path), operation_id
        assert set(new_operation["responses"]) == set(old_operation["responses"]), operation_id
        assert {
            key: value for key, value in new_operation.items() if key.startswith("x-kcs-")
        } == {
            key: value for key, value in old_operation.items() if key.startswith("x-kcs-")
        }, operation_id

    current_schemas = current["components"]["schemas"]
    served_schemas = served["components"]["schemas"]
    for name in PROTECTED_HOSTED_SCHEMAS:
        assert current_schemas[name] == served_schemas[name], name
    assert current["components"]["parameters"]["Container"] == served["components"][
        "parameters"
    ]["Container"]


def test_dormant_generator_fails_closed_before_touching_the_served_package(
    tmp_path: Path,
) -> None:
    generator = ROOT / "scripts" / "generate_v2_openapi_artifacts.py"
    before = SERVED_PACKAGE.read_bytes()

    blocked = subprocess.run(
        [sys.executable, str(generator), "--output-dir", str(tmp_path / "blocked")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert blocked.returncode != 0
    assert "dormant contract requires --skip-package" in (blocked.stdout + blocked.stderr)
    assert SERVED_PACKAGE.read_bytes() == before
    assert hashlib.sha256(before).hexdigest() == SERVED_23_SHA256

    allowed = subprocess.run(
        [
            sys.executable,
            str(generator),
            "--check",
            "--skip-package",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr
    assert SERVED_PACKAGE.read_bytes() == before


def test_v24_native_arm_is_owned_by_kcs_and_has_no_m2_callable_surface() -> None:
    document = yaml.safe_load(SOURCE.read_text())
    schemas = document["components"]["schemas"]
    paths = document["paths"]

    assert "nodeSelector" not in schemas["NativeJobSpec"]["properties"]
    assert schemas["NativeJobSpec"]["x-kcs-placement-owner"] == "kcs"
    assert "ephemeralStorageMiB" in schemas["NativeRuntimeResources"]["required"]
    assert schemas["SelectedModelProtocol"]["enum"] == [
        "openai-responses",
        "openai-completions",
        "anthropic-messages",
    ]
    assert all("dev-session" not in path for path in paths)
    assert all(not ("/runner/" in path and "terminal" in path) for path in paths)


def test_v24_freezes_projection_ttl_finalize_barrier_and_two_delivery_arms() -> None:
    document = yaml.safe_load(SOURCE.read_text())
    schemas = document["components"]["schemas"]
    ttl = document["components"]["parameters"]["ProjectionTtlHeader"]["schema"]

    assert ttl["minimum"] == 120
    assert ttl["maximum"] == 900
    assert schemas["RunnerCredentialGrantSnapshot"]["properties"]["projectionTtlSeconds"][
        "minimum"
    ] == 120
    assert "gatewayTokenTtlSeconds" not in schemas["RunnerCredentialGrantSnapshot"]["properties"]
    assert "captureBarrier" in schemas["NativeFinalizeSpec"]["required"]
    assert schemas["NativeCaptureState"]["enum"] == ["complete", "failed", "indeterminate"]
    assert schemas["AssembledRecipeDelivery"]["properties"]["transport"]["const"] == (
        "imageVolume"
    )
    assert len(schemas["RuntimeRecipeDelivery"]["oneOf"]) == 2
    assert "platformImageVolumeDigest" in schemas["PrebuiltRecipeDelivery"]["required"]
    assert "platformImageVolumeRef" in schemas["PrebuiltActivationDeliveryReceipt"][
        "required"
    ]
    assert "admittedResources" in schemas["RuntimeRecipeActivationReceipt"]["required"]
    assert "ephemeralStorageLimitMiB" in schemas["NativeAdmittedResources"]["required"]
    assert document["info"]["x-kcs-features"]["runtimeRecipeDeliveryDefault"] == (
        "assembled.imageVolume"
    )
    assert "initExtract" not in SOURCE.read_text()


def test_recipe_fixtures_freeze_launcher_and_exact_mount_roles() -> None:
    expected_common = {
        "workspace": ("/workspace", False),
        "platform": ("/opt/rc-platform", True),
        "control": ("/run/rc-control", False),
        "credential": ("/var/run/rc/model-gateway", True),
        "userHome": ("/run/rc-user/home", False),
        "userTmp": ("/run/rc-user/tmp", False),
        "terminalHome": ("/run/rc-terminal/home", False),
        "terminalTmp": ("/run/rc-terminal/tmp", False),
    }
    for filename, assembled in (
        ("runtime-recipe-assembled.json", True),
        ("runtime-recipe-prebuilt.json", False),
    ):
        recipe = json.loads((NATIVE_FIXTURES / filename).read_text())
        assert recipe["launcherCommand"] == ["/opt/rc-platform/bin/rc-native-launcher"]
        assert recipe["controlCommand"] == ["/opt/kcs/workspace-sidecar", "rpc"]
        assert recipe["launcherSocketPath"] == "/run/rc-control/launcher.sock"
        mounts = {item["role"]: (item["mountPath"], item["readOnly"]) for item in recipe["mounts"]}
        expected = dict(expected_common)
        if assembled:
            expected["runner"] = ("/opt/rc-runner", True)
            assert recipe["runnerEntrypoint"][0].startswith("/opt/rc-runner/")
        assert mounts == expected


def test_start_runner_preconditions_bind_every_external_identity() -> None:
    document = yaml.safe_load(SOURCE.read_text())
    operation = document["paths"]["/api/v2/jobs/{jobRef}/runner/start"]["post"]
    preconditions = operation["x-kcs-native-start-preconditions"]

    assert preconditions["failureCodes"] == ["STALE_BINDING", "PRECONDITION_FAILED"]
    assert preconditions["softTimerOrigin"] == "successful-startRunner-ack"
    assert "request.nativeLaunchDigest=grant.nativeLaunchDigest" in preconditions[
        "credentialGrant"
    ]
    assert "job.recipeActivation.state=active" in preconditions["activeRecipe"]


def test_native_fixtures_validate_against_the_frozen_components() -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    fixture_schemas = {
        "create-request.json": "CreateJobRequest",
        "credential-grant.json": "RunnerCredentialGrantSnapshot",
        "runner-start-request.json": "RunnerStartRequest",
        "runner-generation.json": "NativeRunnerGenerationSnapshot",
        "runner-stop-request.json": "RunnerStopRequest",
        "runner-stop.json": "RunnerStopSnapshot",
        "runtime-recipe-assembled.json": "ResolvedRuntimeRecipe",
        "runtime-recipe-prebuilt.json": "ResolvedRuntimeRecipe",
        "finalize-request.json": "NativeFinalizeJobRequest",
        "recipe-activation.json": "RuntimeRecipeActivationReceipt",
        "recipe-activation-prebuilt.json": "RuntimeRecipeActivationReceipt",
        "runner-logs.json": "NativeRoleLogs",
        "runner-event.json": "RuntimeEvent",
        "native-terminal.json": "NativeTerminalSessionSnapshot",
    }

    for filename, schema_name in fixture_schemas.items():
        fixture = json.loads((NATIVE_FIXTURES / filename).read_text())
        schema = {"$ref": f"#/components/schemas/{schema_name}"}
        module._validate_instance(fixture, schema, document, filename)
    assert json.loads((NATIVE_FIXTURES / "credential-grant.json").read_text())[
        "projectionTtlSeconds"
    ] == 180
    stopped = json.loads((NATIVE_FIXTURES / "runner-stop.json").read_text())[
        "runnerObservation"
    ]
    assert (stopped["state"], stopped["stopCause"], stopped["processExit"]["kind"]) == (
        "killed",
        "soft_deadline",
        "signaled",
    )
    terminal = json.loads((NATIVE_FIXTURES / "native-terminal.json").read_text())
    assert terminal["ptyRef"] == terminal["terminalRef"]
    assert terminal["runnerPaused"] is True
    assert terminal["shellCommand"] == ["/bin/sh"]
    assert (terminal["effectiveUid"], terminal["effectiveGid"]) == (10002, 10001)
    assert terminal["effectiveCapabilities"] == []
    assert terminal["noNewPrivileges"] is True
    assert terminal["umask"] == "0002"
