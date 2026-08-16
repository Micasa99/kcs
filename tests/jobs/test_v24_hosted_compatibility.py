from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "openapi" / "kcs-v2-jobs.openapi.yaml"
SERVED_PACKAGE = ROOT / "src" / "kcs" / "openapi" / "kcs-v2-jobs.openapi.json"
NATIVE_FIXTURES = ROOT / "openapi" / "native-fixtures"
HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}
NATIVE_OPERATIONS = {
    "grantRunnerCredential",
    "inspectRunnerCredentialGrant",
    "startRunner",
    "stopRunner",
    "resolveRuntimeRecipe",
}
M2_OPERATIONS = {
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
PROJECT_WORKSPACE_OPERATIONS = {
    "ensureProjectWorkspace",
    "inspectProjectWorkspace",
    "createProjectDevSession",
    "inspectProjectDevSession",
    "renewProjectDevSession",
    "revokeProjectDevSession",
    "relayProjectDevSession",
    "createProjectWorkspaceSnapshot",
    "readProjectWorkspaceSnapshotContent",
    "registerProjectWorkspaceImport",
    "putProjectWorkspaceImportContent",
}
HOSTED_OPERATION_LOCATIONS = {
    "getCapacity": ("get", "/api/v2/capacity"),
    "getRuntimeEvents": ("get", "/api/v2/events"),
    "getObservabilityHealth": ("get", "/api/v2/healthz"),
    "listJobs": ("get", "/api/v2/jobs"),
    "createJob": ("post", "/api/v2/jobs"),
    "deleteJob": ("delete", "/api/v2/jobs/{jobRef}"),
    "inspectJob": ("get", "/api/v2/jobs/{jobRef}"),
    "grantCredential": ("post", "/api/v2/jobs/{jobRef}/agent/credential-grants"),
    "inspectCredentialGrant": (
        "get",
        "/api/v2/jobs/{jobRef}/agent/credential-grants/{credentialGrantRef}",
    ),
    "startAgent": ("post", "/api/v2/jobs/{jobRef}/agent/start"),
    "cancelJob": ("post", "/api/v2/jobs/{jobRef}/cancel"),
    "finalizeJob": ("post", "/api/v2/jobs/{jobRef}/finalize"),
    "getRoleLogs": ("get", "/api/v2/jobs/{jobRef}/logs"),
    "inspectWorkspaceOperation": (
        "get",
        "/api/v2/jobs/{jobRef}/operations/{operationRef}",
    ),
    "getNvidiaTelemetry": ("get", "/api/v2/jobs/{jobRef}/telemetry/nvidia"),
    "registerTransfer": ("post", "/api/v2/jobs/{jobRef}/transfers"),
    "discardTransfer": ("delete", "/api/v2/jobs/{jobRef}/transfers/{transferRef}"),
    "inspectTransfer": ("get", "/api/v2/jobs/{jobRef}/transfers/{transferRef}"),
    "cancelTransfer": (
        "post",
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}/cancel",
    ),
    "getTransferContent": (
        "get",
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
    ),
    "putTransferContent": (
        "put",
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
    ),
    "invokeWorkspace": ("post", "/api/v2/jobs/{jobRef}/workspace/invoke"),
    "createTerminalSession": (
        "post",
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions",
    ),
    "closeTerminalSession": (
        "delete",
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}",
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
    "getCanonicalOpenApi": ("get", "/api/v2/openapi.json"),
    "getQueue": ("get", "/api/v2/queue"),
    "getNodeTelemetry": ("get", "/api/v2/telemetry/nodes"),
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
PROTECTED_HOSTED_SCHEMA_SHA256 = {
    "AgentResources": "d1723db2b6c21e0ae8ca24dc6161d3201926c7bb92ae8e33692295d8eed2be52",
    "WorkspaceResources": "63249cbc5fa6ecb78fdb91e50918e54ecf06062ebd282bff134207058acd315e",
    "AgentSpec": "ba92f54c2903651198da1eb08196e0fc338745c60bb40821efcc7cf712340ce1",
    "WorkspaceSpec": "b470c07c94cce39857d1042f77fae7259eccced1443d1f4c76ab7cf7995d9713",
    "SharedWorkspaceSpec": "3c8e6ad062378a9cb46b2c144a21d84d8feeb9a68fb2ae9ec82c248c1035941f",
    "JobSpec": "10c9ba3a59fe3217819a051e785923d9e3f473d3935041db0218a9869b07cd97",
    "AgentRequestedResources": "0e8b379a1dc9b78b5a5e510ec3ab0f37ed888ea7f1836a82e64f2caddd0b7d76",
    "AgentObservedResources": "061769117340c1f91be000c3dbb333d44962e336d667b3513ae75814583e26b0",
    "WorkspaceRequestedResources": (
        "3dca75fbaf0dc5d85b42c673c5cdf7320bdf0a5b747113f1cb42ad7de2ae2467"
    ),
    "WorkspaceObservedResources": (
        "53378ce41aebfd30d5779ba86ee8f3f2fe61d6df3856cbd23f3f8f6db4c675b3"
    ),
    "AgentRoleSnapshot": "6b68f1722f62de7e721be7a9aa078e5f72a15c6f8614ec348c535537c4e1d3cb",
    "WorkspaceRoleSnapshot": "5de973d6d8b782ae60190c20a043e7c656ded6fa09696075a7414e8ca91af638",
    "GenerationSnapshot": "68de4c0a82aa5868b509ae6f9e7fb5ec2ade5364b68777bff387d2c863ca5086",
    "AgentStartRequest": "8864dc8177108cc9d29f4fd211f616fd3386c5a77f5a2b3c26df5f38923d46dc",
    "TerminalSessionSnapshot": "e074d0cfccbd3d81dc2787f407adb51fff9a4e3615391460c2f29a93100c77b7",
    "JobBindingSnapshot": "8f6b3282663f497c1118c73c0e1a77d44f0fed1e2592729701dcb9678be9f9d4",
    "JobBindingSnapshotList": "065150833b996d0776c32beae1dc1fc0d74261fd562d0116ebc7e34aacc6a990",
    "RoleLogs": "0a78b4307539a76f40d4a96175bbf7811b2a8df1c406e101c36f8c5e9add9f08",
    "CredentialGrantSnapshot": "a067e3da122da5d56590281453747d68dd0b59cb89ad267df80a9fb2cfde2c81",
    "FinalizeSpec": "243a6a976c242dd20b6966b39796f079c5ff3a5e76dfbd1b69a0a98e0b060391",
    "FinalizeJobRequest": "d5a81587450cfaeaa87609d6de2e7bc3f55dfe719cb33f541da75ed1ba342f3b",
}
PROTECTED_CONTAINER_SHA256 = "fe2ad31223b23a108a2fe264cf17052c911807adfcd667a8fdc3727a111a6b2a"


def _sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


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


def test_v26_active_contract_preserves_the_v24_hosted_decode_arm() -> None:
    current = yaml.safe_load(SOURCE.read_text())
    served = json.loads(SERVED_PACKAGE.read_text())
    current_operations = _operations(current)
    assert served["info"]["version"] == "2.7.0"
    assert current["info"]["version"] == "2.7.0"
    assert current["x-kcs-contract-status"] == "active"
    assert len(_operations(served)) == 58
    assert len(current_operations) == 58
    assert set(current_operations) - set(HOSTED_OPERATION_LOCATIONS) == (
        NATIVE_OPERATIONS | M2_OPERATIONS | PROJECT_WORKSPACE_OPERATIONS
    )

    for operation_id, expected_location in HOSTED_OPERATION_LOCATIONS.items():
        method, path, _operation = current_operations[operation_id]
        assert (method, path) == expected_location, operation_id

    current_schemas = current["components"]["schemas"]
    for name in PROTECTED_HOSTED_SCHEMAS:
        assert _sha256_json(current_schemas[name]) == PROTECTED_HOSTED_SCHEMA_SHA256[name], name
    assert (
        _sha256_json(current["components"]["parameters"]["Container"]) == PROTECTED_CONTAINER_SHA256
    )


def test_active_generated_contract_is_the_only_served_package() -> None:
    generated = ROOT / "openapi/generated/kcs-v2-jobs.openapi.json"
    assert generated.read_bytes() == SERVED_PACKAGE.read_bytes()


def test_v25_adds_only_the_frozen_m2_surface_to_the_kcs_owned_native_arm() -> None:
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
    assert "/api/v2/runtime-assemblies/resolve" in paths
    assert "/api/v2/jobs/{jobRef}/workspace/live-snapshots" in paths
    assert "/api/v2/jobs/{jobRef}/dev-sessions" in paths
    assert all(not ("/runner/" in path and "terminal" in path) for path in paths)


def test_v24_freezes_projection_ttl_finalize_barrier_and_two_delivery_arms() -> None:
    document = yaml.safe_load(SOURCE.read_text())
    schemas = document["components"]["schemas"]
    ttl = document["components"]["parameters"]["ProjectionTtlHeader"]["schema"]

    assert ttl["minimum"] == 120
    assert ttl["maximum"] == 900
    assert (
        schemas["RunnerCredentialGrantSnapshot"]["properties"]["projectionTtlSeconds"]["minimum"]
        == 120
    )
    assert "gatewayTokenTtlSeconds" not in schemas["RunnerCredentialGrantSnapshot"]["properties"]
    assert "captureBarrier" in schemas["NativeFinalizeSpec"]["required"]
    assert schemas["NativeCaptureState"]["enum"] == ["complete", "failed", "indeterminate"]
    assert schemas["AssembledRecipeDelivery"]["properties"]["transport"]["const"] == ("imageVolume")
    assert len(schemas["RuntimeRecipeDelivery"]["oneOf"]) == 2
    assert "platformImageVolumeDigest" in schemas["PrebuiltRecipeDelivery"]["required"]
    assert "platformImageVolumeRef" in schemas["PrebuiltActivationDeliveryReceipt"]["required"]
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
        assert recipe["controlCommand"] == ["/opt/kcs/workspace-sidecar", "serve"]
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
    assert "request.nativeLaunchDigest=grant.nativeLaunchDigest" in preconditions["credentialGrant"]
    assert "job.recipeActivation.state=active" in preconditions["activeRecipe"]


def test_native_fixtures_validate_against_the_frozen_components() -> None:
    module = _load_generator_module()
    document = yaml.safe_load(SOURCE.read_text())
    fixture_schemas = {
        "create-request.json": "CreateJobRequest",
        "create-request-capacity-insufficient.json": "CreateJobRequest",
        "credential-grant.json": "RunnerCredentialGrantSnapshot",
        "credential-grant-expired.json": "RunnerCredentialGrantSnapshot",
        "runner-start-request.json": "RunnerStartRequest",
        "runner-start-request-anthropic.json": "RunnerStartRequest",
        "runner-generation.json": "NativeRunnerGenerationSnapshot",
        "runner-generation-killed.json": "NativeRunnerGenerationSnapshot",
        "runner-stop-request.json": "RunnerStopRequest",
        "runner-stop-request-cancel.json": "RunnerStopRequest",
        "runner-stop.json": "RunnerStopSnapshot",
        "runner-stop-indeterminate.json": "RunnerStopSnapshot",
        "runtime-recipe-assembled.json": "ResolvedRuntimeRecipe",
        "runtime-recipe-prebuilt.json": "ResolvedRuntimeRecipe",
        "finalize-request.json": "NativeFinalizeJobRequest",
        "finalize-request-indeterminate.json": "NativeFinalizeJobRequest",
        "recipe-activation.json": "RuntimeRecipeActivationReceipt",
        "recipe-activation-prebuilt.json": "RuntimeRecipeActivationReceipt",
        "recipe-activation-evicted.json": "RuntimeRecipeActivationReceipt",
        "runner-logs.json": "NativeRoleLogs",
        "runner-logs-truncated.json": "NativeRoleLogs",
        "runner-event.json": "RuntimeEvent",
        "runner-event-hard-deadline.json": "RuntimeEvent",
        "native-terminal.json": "NativeTerminalSessionSnapshot",
        "native-terminal-closed.json": "NativeTerminalSessionSnapshot",
    }

    for filename, schema_name in fixture_schemas.items():
        fixture = json.loads((NATIVE_FIXTURES / filename).read_text())
        schema = {"$ref": f"#/components/schemas/{schema_name}"}
        module._validate_instance(fixture, schema, document, filename)
    assert (
        json.loads((NATIVE_FIXTURES / "credential-grant.json").read_text())["projectionTtlSeconds"]
        == 180
    )
    stopped = json.loads((NATIVE_FIXTURES / "runner-stop.json").read_text())["runnerObservation"]
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
    assert (
        json.loads((NATIVE_FIXTURES / "create-request-capacity-insufficient.json").read_text())[
            "spec"
        ]["native"]["resources"]["ephemeralStorageMiB"]
        == 128
    )
    assert json.loads((NATIVE_FIXTURES / "credential-grant-expired.json").read_text())[
        "secretPresent"
    ] is False
    evicted = json.loads((NATIVE_FIXTURES / "recipe-activation-evicted.json").read_text())
    assert (evicted["state"], evicted["deliveryFailure"], evicted["replacementPodCreated"]) == (
        "failed",
        "emptydir_evicted",
        False,
    )
