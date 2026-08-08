from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "openapi" / "kcs-v2-jobs.openapi.yaml"
MUTATING_METHODS = {"post", "put", "delete", "patch"}


def _openapi() -> dict:
    return yaml.safe_load(SOURCE.read_text())


def _operation(document: dict, operation_id: str) -> dict:
    for path_item in document["paths"].values():
        for method, operation in path_item.items():
            if (
                method in MUTATING_METHODS | {"get"}
                and operation.get("operationId") == operation_id
            ):
                return operation
    raise AssertionError(f"missing operationId {operation_id}")


def _parameter_names(document: dict, operation: dict) -> set[str]:
    names: set[str] = set()
    for parameter in operation.get("parameters", []):
        if "$ref" in parameter:
            parameter = document["components"]["parameters"][parameter["$ref"].rsplit("/", 1)[1]]
        names.add(parameter["name"])
    return names


def test_mutations_use_intrinsic_identities_and_machine_digest_projections() -> None:
    document = _openapi()
    assert "IdempotencyKey" not in document["components"]["parameters"]

    expected = {
        "createJob": (
            "rfc8785-jcs",
            [{"in": "body", "name": "providerRequestId"}],
            "specDigest",
            "body",
            {"source": "requestBody", "field": "spec"},
        ),
        "grantCredential": (
            "raw-body",
            [
                {"in": "path", "name": "jobRef"},
                {"in": "header", "name": "KCS-Credential-Grant-Ref"},
            ],
            "credentialSha256",
            "header",
            {"source": "requestBody", "encoding": "raw-bytes"},
        ),
        "startAgent": (
            "rfc8785-jcs",
            [
                {"in": "path", "name": "jobRef"},
                {"in": "body", "name": "generation"},
            ],
            "startMetadataDigest",
            "response",
            {"source": "requestBody", "exclude": ["generation"]},
        ),
        "registerTransfer": (
            "rfc8785-jcs",
            [
                {"in": "path", "name": "jobRef"},
                {"in": "body", "name": "transferRef"},
            ],
            "requestDigest",
            "body",
            {"source": "requestBody", "field": "spec"},
        ),
        "putTransferContent": (
            "raw-body",
            [
                {"in": "path", "name": "jobRef"},
                {"in": "path", "name": "transferRef"},
            ],
            "contentSha256",
            "header",
            {"source": "requestBody", "encoding": "raw-bytes"},
        ),
        "cancelTransfer": (
            "rfc8785-jcs",
            [
                {"in": "path", "name": "jobRef"},
                {"in": "path", "name": "transferRef"},
                {"in": "body", "name": "cancelRef"},
            ],
            "requestDigest",
            "body",
            {"source": "requestBody", "field": "spec"},
        ),
        "discardTransfer": (
            "rfc8785-jcs-empty-object",
            [
                {"in": "path", "name": "jobRef"},
                {"in": "path", "name": "transferRef"},
                {"in": "header", "name": "KCS-Discard-Ref"},
            ],
            "requestDigest",
            "header",
            {"source": "constant", "value": {}},
        ),
        "invokeWorkspace": (
            "external-owner-digest",
            [
                {"in": "path", "name": "jobRef"},
                {"in": "header", "name": "KCS-Operation-Ref"},
            ],
            "requestDigest",
            "header",
            None,
        ),
        "finalizeJob": (
            "rfc8785-jcs",
            [
                {"in": "path", "name": "jobRef"},
                {"in": "body", "name": "finalizeRef"},
            ],
            "requestDigest",
            "body",
            {"source": "requestBody", "field": "spec"},
        ),
        "cancelJob": (
            "rfc8785-jcs",
            [
                {"in": "path", "name": "jobRef"},
                {"in": "body", "name": "cancelRef"},
            ],
            "requestDigest",
            "body",
            {"source": "requestBody", "field": "spec"},
        ),
        "deleteJob": (
            "rfc8785-jcs-empty-object",
            [
                {"in": "path", "name": "jobRef"},
                {"in": "header", "name": "KCS-Delete-Ref"},
            ],
            "requestDigest",
            "header",
            {"source": "constant", "value": {}},
        ),
    }
    for operation_id, (kind, identity, digest, digest_location, projection) in expected.items():
        operation = _operation(document, operation_id)
        extension = operation["x-kcs-digest-projection"]
        assert extension["kind"] == kind, operation_id
        assert extension["identity"] == identity, operation_id
        assert extension["digest"] == digest, operation_id
        assert extension["digestLocation"] == digest_location, operation_id
        assert extension.get("projection") == projection, operation_id
        assert "Idempotency-Key" not in _parameter_names(document, operation)
        assert "200" in operation["responses"], operation_id
        assert "409" in operation["responses"], operation_id


def test_create_freezes_exact_identity_digest_and_physical_spec() -> None:
    document = _openapi()
    schemas = document["components"]["schemas"]
    request = schemas["CreateJobRequest"]
    assert request["additionalProperties"] is False
    assert request["required"] == ["providerRequestId", "specDigest", "spec"]
    assert set(request["properties"]) == {"providerRequestId", "specDigest", "spec"}

    spec = schemas["JobSpec"]
    assert set(spec["required"]) == {
        "subjectRef",
        "runtimePlanDigest",
        "agent",
        "workspace",
        "sharedWorkspace",
        "nodeSelector",
        "activeDeadlineSeconds",
    }
    assert spec["additionalProperties"] is False
    assert spec["x-kcs-default-semantics"] == "omission-is-distinct"
    assert schemas["AgentSpec"]["properties"]["command"]["const"] == ["/opt/kcs/agent-supervisor"]
    assert schemas["WorkspaceSpec"]["properties"]["command"]["const"] == [
        "/opt/kcs/workspace-sidecar"
    ]
    assert schemas["SharedWorkspaceSpec"]["properties"]["kind"]["const"] == "ephemeral"
    assert schemas["SharedWorkspaceSpec"]["properties"]["mountPath"]["const"] == "/workspace"
    assert schemas["NodeSelector"]["properties"]["researchcosmos.io/pool"]["const"] == "gpu"
    assert spec["properties"]["activeDeadlineSeconds"]["default"] == 21600
    assert spec["properties"]["activeDeadlineSeconds"]["maximum"] == 86400


def test_job_binding_snapshot_exposes_recoverable_kubernetes_reality() -> None:
    document = _openapi()
    schemas = document["components"]["schemas"]
    snapshot = schemas["JobBindingSnapshot"]
    required = {
        "jobRef",
        "providerHandle",
        "providerRequestId",
        "subjectRef",
        "runtimePlanDigest",
        "specDigest",
        "jobUid",
        "podUid",
        "resourceVersion",
        "nodeName",
        "bindingState",
        "bindingReason",
        "createdAt",
        "updatedAt",
        "startedAt",
        "finishedAt",
        "agent",
        "workspace",
        "latestAgentGeneration",
        "activeOperationRefs",
        "terminalOperationRefs",
        "credentialObservations",
        "transferObservations",
        "finalizeAction",
        "cancelAction",
        "deleteAction",
        "outputLossPossible",
        "cleanup",
        "gpuRelease",
    }
    assert required <= set(snapshot["required"])
    assert snapshot["additionalProperties"] is False
    assert "indeterminate" in schemas["JobBindingState"]["enum"]
    assert {"RequestedResources", "ObservedResources", "RoleSnapshot"}.isdisjoint(schemas)

    for role_name, requested_name, maxima in (
        ("AgentRoleSnapshot", "AgentRequestedResources", (8000, 32768, 0, 100)),
        ("WorkspaceRoleSnapshot", "WorkspaceRequestedResources", (64000, 262144, 8, 100)),
    ):
        role = schemas[role_name]
        assert {
            "containerId",
            "imageId",
            "state",
            "ready",
            "restartCount",
            "exitCode",
            "reason",
            "startedAt",
            "finishedAt",
            "requested",
            "observed",
        } <= set(role["required"])
        requested = schemas[requested_name]["properties"]
        assert requested["cpuMillis"]["maximum"] == maxima[0]
        assert requested["memoryMiB"]["maximum"] == maxima[1]
        assert requested["gpu"].get("maximum", requested["gpu"].get("const")) == maxima[2]
        assert requested["storageGiB"]["maximum"] == maxima[3]
        assert requested["cpuMillis"]["minimum"] == 1
        assert requested["memoryMiB"]["minimum"] == 1
        assert requested["storageGiB"]["minimum"] == 1
        assert requested["gpu"].get("minimum", requested["gpu"].get("const")) == 0
    assert snapshot["properties"]["agent"] == {
        "oneOf": [{"$ref": "#/components/schemas/AgentRoleSnapshot"}, {"type": "null"}]
    }
    assert snapshot["properties"]["workspace"] == {
        "oneOf": [{"$ref": "#/components/schemas/WorkspaceRoleSnapshot"}, {"type": "null"}]
    }

    for operation_id in ("createJob", "listJobs", "inspectJob", "finalizeJob", "cancelJob"):
        operation = _operation(document, operation_id)
        success = "201" if operation_id == "createJob" else "200"
        schema = operation["responses"][success]["content"]["application/json"]["schema"]
        expected_ref = (
            "#/components/schemas/AnyJobBindingSnapshotList"
            if operation_id == "listJobs"
            else "#/components/schemas/AnyJobBindingSnapshot"
        )
        assert schema == {"$ref": expected_ref}

    assert schemas["AnyJobBindingSnapshot"]["oneOf"] == [
        {"$ref": "#/components/schemas/JobBindingSnapshot"},
        {"$ref": "#/components/schemas/NativeJobBindingSnapshot"},
    ]


def test_list_and_logs_freeze_filters_ordering_and_cursor_recovery() -> None:
    document = _openapi()
    list_operation = _operation(document, "listJobs")
    assert _parameter_names(document, list_operation) == {
        "pageToken",
        "pageSize",
        "providerRequestId",
        "subjectRef",
        "state",
        "createdAfter",
        "includeDeleted",
    }
    assert list_operation["x-kcs-ordering"] == {
        "strategy": "stable-key-merge",
        "collections": ["items", "tombstones"],
        "keys": ["createdAt", "jobRef"],
        "uniqueIdentities": ["jobRef", "providerRequestId", "jobUid"],
    }
    assert list_operation["x-kcs-page-token-binding"] == [
        "namespace",
        "providerRequestId",
        "subjectRef",
        "state",
        "createdAfter",
        "includeDeleted",
    ]
    listing = document["components"]["schemas"]["JobBindingSnapshotList"]
    assert listing["x-kcs-combinedMaxItems"] == {
        "limit": 200,
        "properties": ["items", "tombstones"],
    }

    logs_operation = _operation(document, "getRoleLogs")
    logs = document["components"]["schemas"]["RoleLogs"]
    assert {
        "content",
        "inputCursor",
        "startCursor",
        "nextCursor",
        "truncated",
        "terminal",
        "podUid",
        "containerId",
        "observedAt",
    } <= set(logs["required"])
    assert "stdout" not in logs["properties"] and "stderr" not in logs["properties"]
    assert logs_operation["x-kcs-cursor-binding"] == ["namespace", "jobRef", "podUid", "container"]
    assert {"INVALID_CURSOR", "STALE_CURSOR"} <= set(logs_operation["x-kcs-error-codes"])


def test_credential_grant_is_private_bound_raw_stream_with_no_secret_json() -> None:
    document = _openapi()
    operation = _operation(document, "grantCredential")
    assert set(operation["requestBody"]["content"]) == {"application/octet-stream"}
    assert operation["x-kcs-service-authorization"] == "v2-private-credential-writer"
    assert operation["x-kcs-request-body-logging"] == "forbidden"
    assert operation["x-kcs-private-ingress"] is True
    assert {
        "KCS-Credential-Grant-Ref",
        "KCS-Credential-SHA256",
        "KCS-Grant-Metadata-Digest",
        "KCS-Agent-Run-Ref",
        "KCS-Generation",
        "KCS-Launch-Bundle-Digest",
        "KCS-Audience",
        "KCS-Job-UID",
        "KCS-Pod-UID",
        "KCS-Credential-TTL-Seconds",
    } <= _parameter_names(document, operation)
    metadata = operation["x-kcs-digest-projection"]["metadataDigest"]
    assert metadata == {
        "field": "grantMetadataDigest",
        "kind": "rfc8785-jcs",
        "digestLocation": "header",
        "projection": [
            {"field": "agentRunRef", "header": "KCS-Agent-Run-Ref"},
            {"field": "generation", "header": "KCS-Generation"},
            {"field": "launchBundleDigest", "header": "KCS-Launch-Bundle-Digest"},
            {"field": "audience", "header": "KCS-Audience"},
            {"field": "credentialSha256", "header": "KCS-Credential-SHA256"},
            {"field": "ttlSeconds", "header": "KCS-Credential-TTL-Seconds"},
            {"field": "jobUid", "header": "KCS-Job-UID"},
            {"field": "podUid", "header": "KCS-Pod-UID"},
        ],
    }
    for status in operation["responses"]:
        headers = operation["responses"][status]["headers"]
        assert headers["Cache-Control"]["schema"]["const"] == "no-store"
    inspect = _operation(document, "inspectCredentialGrant")
    for response in inspect["responses"].values():
        assert response["headers"]["Cache-Control"]["schema"]["const"] == "no-store"
    ttl = document["components"]["parameters"]["CredentialTtlHeader"]
    assert ttl["required"] is True
    assert "default" not in ttl["schema"]

    schemas = document["components"]["schemas"]
    assert "CredentialGrantRequest" not in schemas
    snapshot = schemas["CredentialGrantSnapshot"]
    assert "credential" not in snapshot["properties"]
    assert set(schemas["CredentialState"]["enum"]) == {
        "accepted",
        "available",
        "acknowledged",
        "consumed",
        "destroyed",
        "expired",
        "revoked",
        "destroy_failed",
        "indeterminate",
    }
    assert {
        "acknowledgedAt",
        "consumedAt",
        "destroyedAt",
        "secretPresent",
        "tombstoneExpiresAt",
    } <= set(snapshot["properties"])


def test_agent_start_is_generation_safe_metadata_only() -> None:
    document = _openapi()
    schemas = document["components"]["schemas"]
    request = schemas["AgentStartRequest"]
    assert "launch" not in request["properties"]
    assert set(request["required"]) == {
        "executionEnvelopeRef",
        "executionEnvelopeDigest",
        "agentRunRef",
        "generation",
        "launchBundlePath",
        "launchBundleDigest",
        "launchBundleSizeBytes",
        "materialPaths",
        "credentialGrantRef",
    }
    assert request["properties"]["generation"]["minimum"] == 1
    assert request["properties"]["launchBundleSizeBytes"]["maximum"] == 1048576
    assert schemas["GenerationSnapshot"]["properties"]["runnerState"]["$ref"].endswith(
        "RunnerState"
    )
    assert {"STALE_BINDING", "ILLEGAL_GENERATION", "IDENTITY_CONFLICT"} <= set(
        _operation(document, "startAgent")["x-kcs-error-codes"]
    )


def test_transfer_contract_freezes_relative_paths_direct_mode_and_recovery() -> None:
    document = _openapi()
    schemas = document["components"]["schemas"]
    request = schemas["TransferRegisterRequest"]
    assert set(request["required"]) == {"transferRef", "requestDigest", "spec"}
    spec = schemas["TransferSpec"]
    assert set(spec["properties"]["direction"]["enum"]) == {"stage_input", "collect_output"}
    assert spec["properties"]["path"] == {"$ref": "#/components/schemas/SafeRelativePath"}
    assert schemas["SafeRelativePath"]["format"] == "kcs-relative-posix-path"
    assert schemas["SafeRelativePath"]["x-kcs-case-policy"] == (
        "preserve-case-reject-casefold-collisions"
    )
    assert spec["x-kcs-path-collision-policy"] == "reject-existing-workspace-casefold-collision"
    assert spec["properties"]["mode"]["const"] == "direct"
    assert spec["properties"]["authorizedMaxSizeBytes"]["maximum"] == 107374182400
    assert spec["x-kcs-relations"] == [
        {"left": "declaredSizeBytes", "operator": "<=", "right": "authorizedMaxSizeBytes"}
    ]
    assert "overwritePolicy" in spec["required"]
    assert document["info"]["x-kcs-features"] == {
        "transferModes": ["direct"],
        "rangeRequests": False,
        "signedTransfers": False,
        "nativeRunner": True,
        "runtimeRecipeDeliveryDefault": "assembled.imageVolume",
        "runtimeRecipeDeliveryModes": ["assembled", "prebuilt"],
    }
    snapshot = schemas["TransferSnapshot"]
    assert {
        "requestDigest",
        "spec",
        "actualSizeBytes",
        "actualSha256",
        "contentAvailable",
        "cancelAction",
        "discardAction",
        "failureReason",
    } <= set(snapshot["required"])
    assert "indeterminate" in schemas["TransferState"]["enum"]
    content = _operation(document, "getTransferContent")["responses"]["200"]
    assert {"Content-Length", "X-Content-SHA256", "X-KCS-Snapshot-Ref"} <= set(content["headers"])


def test_workspace_invoke_preserves_opaque_cosmos_frame_and_both_digest_domains() -> None:
    document = _openapi()
    schemas = document["components"]["schemas"]
    invoke = _operation(document, "invokeWorkspace")
    request_schema = invoke["requestBody"]["content"]["application/json"]["schema"]
    assert request_schema == {"$ref": "#/components/schemas/WorkspaceFrame"}
    assert {
        "KCS-Operation-Ref",
        "KCS-Request-Digest",
        "KCS-Job-UID",
        "KCS-Pod-UID",
    } <= _parameter_names(document, invoke)
    assert "WorkspaceInvokeRequest" not in schemas
    frame = schemas["WorkspaceFrame"]
    assert frame["required"] == ["protocol"]
    assert frame["properties"] == {"protocol": {"type": "string", "const": "cosmos.workspace/1"}}
    assert frame["additionalProperties"] is True
    assert "action" not in frame["properties"]

    operation = schemas["WorkspaceOperationSnapshot"]
    assert {
        "jobRef",
        "operationRef",
        "requestDigest",
        "storedFrameDigest",
        "binding",
        "state",
        "exitCode",
        "stdout",
        "stderr",
        "stdoutTruncated",
        "stderrTruncated",
        "inlineResultSize",
        "inlineResultDigest",
        "inlineResult",
        "resultTransferRef",
        "acceptedAt",
        "startedAt",
        "finishedAt",
        "observedAt",
        "failureReason",
    } <= set(operation["required"])
    extension = invoke["x-kcs-digest-projection"]
    assert extension["kind"] == "external-owner-digest"
    assert "projection" not in extension
    assert extension["digestOwnership"] == "platform"
    assert extension["storedIntegrityDigest"] == {
        "field": "storedFrameDigest",
        "kind": "rfc8785-jcs",
        "digestLocation": "response",
        "projection": {"source": "requestBody"},
    }


def test_terminal_actions_tombstone_states_and_recovery_are_typed() -> None:
    document = _openapi()
    schemas = document["components"]["schemas"]
    finalize = schemas["FinalizeJobRequest"]
    assert set(finalize["required"]) == {"finalizeRef", "requestDigest", "spec"}
    assert "providerResultRef" not in finalize["properties"]
    assert set(schemas["FinalizeSpec"]["properties"]) == {
        "operationRefs",
        "transferRefs",
        "drainTimeoutSeconds",
    }
    cancel = schemas["CancelJobRequest"]
    assert set(cancel["required"]) == {"cancelRef", "requestDigest", "spec"}
    assert schemas["CancelSpec"]["properties"]["finishCollectTransferRefs"]["items"] == {
        "$ref": "#/components/schemas/OpaqueRef"
    }

    tombstone = schemas["JobTombstone"]
    assert {
        "providerRequestId",
        "specDigest",
        "jobRef",
        "jobUid",
        "podUid",
        "state",
        "finalState",
        "deleteRef",
        "deleteRequestDigest",
        "createdAt",
        "cleanup",
        "gpuRelease",
        "credentialObservations",
        "transferObservations",
        "deletedAt",
        "expiresAt",
    } <= set(tombstone["required"])
    assert tombstone["properties"]["state"]["const"] == "deleted"
    assert set(schemas["ProviderTerminalState"]["enum"]) == {
        "succeeded",
        "failed",
        "canceled",
        "indeterminate",
    }
    create = _operation(document, "createJob")
    assert "410" in create["responses"]
    assert create["responses"]["410"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorEnvelope"
    }
    assert create["x-kcs-unknown-outcome-recovery"] == {
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
    assert set(schemas["ActionState"]["enum"]) >= {
        "not_requested",
        "accepted",
        "running",
        "succeeded",
        "failed",
        "indeterminate",
    }
    assert set(schemas["CleanupState"]["enum"]) >= {
        "pending",
        "complete",
        "failed",
        "indeterminate",
    }


def test_errors_security_runtime_env_and_schema_discovery_are_machine_readable() -> None:
    document = _openapi()
    schemas = document["components"]["schemas"]
    codes = set(schemas["ErrorCode"]["enum"])
    assert {
        "INVALID_CURSOR",
        "STALE_CURSOR",
        "DIGEST_MISMATCH",
        "IDENTITY_CONFLICT",
        "STATE_CONFLICT",
        "STALE_BINDING",
        "REPLACEMENT_POD",
        "TOMBSTONED",
        "ILLEGAL_GENERATION",
        "CREDENTIAL_DESTROY_FAILED",
        "UNSAFE_PATH",
        "OVERWRITE_FORBIDDEN",
        "TRANSFER_BYTES_MISMATCH",
        "TRANSFER_INDETERMINATE",
        "OPERATION_INDETERMINATE",
    } <= codes
    assert set(schemas["RecoveryAction"]["enum"]) == {
        "retry_same",
        "inspect_job",
        "inspect_grant",
        "inspect_runner_credential_grant",
        "inspect_transfer",
        "inspect_operation",
        "inspect_terminal",
        "reattach",
        "reconcile",
        "new_attempt",
        "none",
    }
    assert schemas["ErrorEnvelope"]["properties"]["error"]["properties"]["code"] == {
        "$ref": "#/components/schemas/ErrorCode"
    }
    assert (
        schemas["Environment"]["additionalProperties"]["format"] == "kcs-non-secret-runtime-value"
    )
    assert schemas["Environment"]["x-kcs-secret-value-policy"] == "reject-secret-shaped-values"

    expected_authorization = {
        "createJob": "v2-mutator",
        "listJobs": "v2-reader",
            "getCapacity": "v2-reader",
            "getQueue": "v2-reader",
            "getNodeTelemetry": "v2-reader",
            "getRuntimeEvents": "v2-reader",
            "getObservabilityHealth": "v2-reader",
            "inspectJob": "v2-reader",
        "deleteJob": "v2-mutator",
        "getRoleLogs": "v2-reader",
        "getNvidiaTelemetry": "v2-reader",
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
        "createTerminalSession": "v2-mutator",
        "inspectTerminalSession": "v2-reader",
        "writeTerminalInput": "v2-mutator",
        "readTerminalOutput": "v2-reader",
        "resizeTerminalSession": "v2-mutator",
        "closeTerminalSession": "v2-mutator",
        "inspectWorkspaceOperation": "v2-reader",
        "finalizeJob": "v2-mutator",
        "cancelJob": "v2-mutator",
        "getCanonicalOpenApi": "v2-reader",
    }
    all_mapped_codes: set[str] = set()
    observed_operations: set[str] = set()
    for path_item in document["paths"].values():
        for method, operation in path_item.items():
            if method in MUTATING_METHODS | {"get"}:
                operation_id = operation["operationId"]
                observed_operations.add(operation_id)
                assert (
                    operation["x-kcs-service-authorization"] == expected_authorization[operation_id]
                )
                mapping = operation["x-kcs-error-codes"]
                assert mapping and isinstance(mapping, dict)
                all_mapped_codes.update(mapping)
                mapped_statuses = set()
                for code, rule in mapping.items():
                    assert code in codes
                    status = str(rule["status"])
                    assert status in operation["responses"]
                    assert rule["recoveryAction"] in schemas["RecoveryAction"]["enum"]
                    mapped_statuses.add(status)
                response_errors = {
                    status for status in operation["responses"] if int(status) >= 400
                }
                assert response_errors == mapped_statuses
                assert mapping["UNAUTHENTICATED"]["status"] == 401
                assert mapping["FORBIDDEN"]["status"] == 403
                if "requestBody" in operation:
                    assert mapping["UNSUPPORTED_MEDIA_TYPE"]["status"] == 415
    assert observed_operations == set(expected_authorization)

    assert all_mapped_codes == codes

    for operation_id in ("deleteJob", "discardTransfer"):
        operation = _operation(document, operation_id)
        assert operation["x-kcs-error-codes"]["DIGEST_MISMATCH"] == {
            "status": 422,
            "recoveryAction": "none",
        }

    discovery = _operation(document, "getCanonicalOpenApi")["responses"]["200"]
    assert discovery["headers"]["ETag"]["schema"]["pattern"] == "^[0-9a-f]{64}$"
    assert discovery["x-kcs-etag-derivation"] == {
        "algorithm": "sha256",
        "source": "exact-response-bytes",
        "encoding": "lowercase-hex",
    }
    assert discovery["headers"]["X-KCS-API-Version"]["schema"]["const"] == "2.4.0"
    assert discovery["headers"]["Cache-Control"]["schema"]["const"] == "no-store"
    assert document["x-kcs-legacy-authorization"] == {
        "v2NamespaceAccess": "denied",
        "podsExec": "denied",
        "secrets": "denied",
        "mutations": "denied",
    }


def test_recovery_gets_return_retained_indeterminate_and_cleanup_states_as_snapshots() -> None:
    document = _openapi()

    grant = _operation(document, "inspectCredentialGrant")
    assert "CREDENTIAL_EXPIRED" not in grant["x-kcs-error-codes"]
    assert "CREDENTIAL_DESTROY_FAILED" not in grant["x-kcs-error-codes"]
    assert "410" not in grant["responses"]

    transfer = _operation(document, "inspectTransfer")
    assert "TRANSFER_INDETERMINATE" not in transfer["x-kcs-error-codes"]

    workspace = _operation(document, "inspectWorkspaceOperation")
    assert "OPERATION_INDETERMINATE" not in workspace["x-kcs-error-codes"]


def test_every_replay_conflict_status_matches_its_error_map() -> None:
    document = _openapi()
    checked: set[str] = set()
    for path_item in document["paths"].values():
        for method, operation in path_item.items():
            if method not in MUTATING_METHODS or "x-kcs-replay" not in operation:
                continue
            replay = operation["x-kcs-replay"]
            rule = operation["x-kcs-error-codes"][replay["conflictCode"]]
            assert rule["status"] == replay["conflictStatus"], operation["operationId"]
            checked.add(operation["operationId"])
    assert "putTransferContent" in checked


def test_route_examples_cover_every_required_recovery_scenario() -> None:
    required = {
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
    scenarios: set[str] = set()
    for path in sorted((SOURCE.parent / "examples").glob("*.json")):
        bundle = json.loads(path.read_text())
        for exchange in bundle["exchanges"]:
            assert {"scenario", "operationId", "request", "response"} <= set(exchange)
            scenarios.add(exchange["scenario"])
    assert required <= scenarios
