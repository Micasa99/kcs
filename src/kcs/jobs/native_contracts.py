"""Canonical 2.7 native-runner and M2 wire models.

The native arm is intentionally validated from the packaged canonical OpenAPI
document.  This keeps the implementation and the frozen contract on one source
of truth while leaving every hosted 2.3 Pydantic model byte-for-byte unchanged.
"""

from __future__ import annotations

import importlib.resources
import json
import os
from functools import cache, lru_cache
from pathlib import Path
from typing import Any, ClassVar

from jsonschema import Draft202012Validator
from pydantic import RootModel, model_validator

from .canonical import canonical_digest
from .contracts import JobBindingState


@lru_cache(maxsize=1)
def _canonical_document() -> dict[str, Any]:
    override = os.environ.get("KCS_V2_OPENAPI_PATH")
    if override:
        candidate = Path(override)
        if not candidate.is_file():
            raise RuntimeError("KCS_V2_OPENAPI_PATH does not name a readable contract")
        try:
            value = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("KCS_V2_OPENAPI_PATH is not a valid contract") from error
        if value.get("info", {}).get("version") != "2.7.0":
            raise RuntimeError("KCS_V2_OPENAPI_PATH does not contain the active 2.7 contract")
        return value
    candidates = [
        Path(__file__).resolve().parents[3] / "openapi/generated/kcs-v2-jobs.openapi.json"
    ]
    for candidate in candidates:
        if candidate.is_file():
            value = json.loads(candidate.read_text(encoding="utf-8"))
            if value.get("info", {}).get("version") == "2.7.0":
                return value
    payload = (
        importlib.resources.files("kcs.openapi")
        .joinpath("kcs-v2-jobs.openapi.json")
        .read_text(encoding="utf-8")
    )
    value = json.loads(payload)
    if value.get("info", {}).get("version") != "2.7.0":
        raise RuntimeError("the served KCS package does not contain the active 2.7 contract")
    return value


@cache
def _component_validator(component: str) -> Draft202012Validator:
    document = _canonical_document()
    if component not in document.get("components", {}).get("schemas", {}):
        raise RuntimeError(f"canonical OpenAPI has no {component} component")
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": f"#/components/schemas/{component}",
        "components": document["components"],
    }
    return Draft202012Validator(schema)


class CanonicalNativeModel(RootModel[dict[str, Any]]):
    """A closed canonical component with normal root-object JSON serialization."""

    component: ClassVar[str]

    @model_validator(mode="after")
    def validate_canonical_component(self) -> CanonicalNativeModel:
        errors = sorted(
            _component_validator(self.component).iter_errors(self.root),
            key=lambda item: tuple(str(part) for part in item.absolute_path),
        )
        if errors:
            first = errors[0]
            path = ".".join(str(item) for item in first.absolute_path) or "$"
            raise ValueError(
                f"{self.component} violates canonical schema at {path}: {first.message}"
            )
        return self

    def wire(self) -> dict[str, Any]:
        return dict(self.root)


class NativeCreateJobRequest(CanonicalNativeModel):
    component = "CreateJobRequest"

    @model_validator(mode="after")
    def require_native_arm_and_digest(self) -> NativeCreateJobRequest:
        spec = self.root.get("spec")
        if (
            not isinstance(spec, dict)
            or "native" not in spec
            or "agent" in spec
            or "workspace" in spec
        ):
            raise ValueError("NativeCreateJobRequest requires exactly the native JobSpec arm")
        if canonical_digest(spec) != self.root.get("specDigest"):
            raise ValueError("specDigest does not match the native JobSpec")
        return self

    @property
    def provider_request_id(self) -> str:
        return str(self.root["providerRequestId"])

    @property
    def spec_digest(self) -> str:
        return str(self.root["specDigest"])

    @property
    def spec(self) -> dict[str, Any]:
        return self.root["spec"]


class ResolvedRuntimeRecipe(CanonicalNativeModel):
    component = "ResolvedRuntimeRecipe"

    @property
    def runner_ref(self) -> str:
        return str(self.root["runnerRef"])

    @property
    def environment_profile_ref(self) -> str:
        return str(self.root["environmentProfileRef"])


class RuntimeRecipeActivationReceipt(CanonicalNativeModel):
    component = "RuntimeRecipeActivationReceipt"


class RunnerCredentialGrantSnapshot(CanonicalNativeModel):
    component = "RunnerCredentialGrantSnapshot"


class RunnerStartRequest(CanonicalNativeModel):
    component = "RunnerStartRequest"

    @model_validator(mode="after")
    def validate_launch_digest(self) -> RunnerStartRequest:
        descriptor = self.root["descriptor"]
        if self.root["generation"] != descriptor["generation"]:
            raise ValueError("generation differs from descriptor.generation")
        if canonical_digest(descriptor) != self.root["nativeLaunchDigest"]:
            raise ValueError("nativeLaunchDigest does not match descriptor")
        return self


class NativeRunnerGenerationSnapshot(CanonicalNativeModel):
    component = "NativeRunnerGenerationSnapshot"


class RunnerStopRequest(CanonicalNativeModel):
    component = "RunnerStopRequest"

    @model_validator(mode="after")
    def validate_request_digest(self) -> RunnerStopRequest:
        if canonical_digest(self.root["spec"]) != self.root["requestDigest"]:
            raise ValueError("requestDigest does not match stop spec")
        return self


class RunnerStopSnapshot(CanonicalNativeModel):
    component = "RunnerStopSnapshot"


class NativeFinalizeJobRequest(CanonicalNativeModel):
    component = "NativeFinalizeJobRequest"

    @model_validator(mode="after")
    def validate_request_digest(self) -> NativeFinalizeJobRequest:
        if canonical_digest(self.root["spec"]) != self.root["requestDigest"]:
            raise ValueError("requestDigest does not match native finalize spec")
        return self


class NativeJobBindingSnapshot(CanonicalNativeModel):
    component = "NativeJobBindingSnapshot"

    @property
    def job_ref(self) -> str:
        return str(self.root["jobRef"])

    @property
    def job_uid(self) -> str:
        return str(self.root["jobUid"])

    @property
    def pod_uid(self) -> str | None:
        value = self.root["podUid"]
        return str(value) if value is not None else None

    @property
    def subject_ref(self) -> str:
        return str(self.root["subjectRef"])

    @property
    def binding_state(self) -> JobBindingState:
        return JobBindingState(str(self.root["bindingState"]))


class AnyJobBindingSnapshotList(CanonicalNativeModel):
    component = "AnyJobBindingSnapshotList"


class NativeRoleLogs(CanonicalNativeModel):
    component = "NativeRoleLogs"


class NativeTerminalSessionSnapshot(CanonicalNativeModel):
    component = "NativeTerminalSessionSnapshot"


class RuntimeAssemblyResolutionRequest(CanonicalNativeModel):
    component = "RuntimeAssemblyResolutionRequest"


class ResolvedRuntimeAssembly(CanonicalNativeModel):
    component = "ResolvedRuntimeAssembly"


class LiveWorkspaceSnapshotRequest(CanonicalNativeModel):
    component = "LiveWorkspaceSnapshotRequest"

    @model_validator(mode="after")
    def validate_request_digest(self) -> LiveWorkspaceSnapshotRequest:
        if canonical_digest(self.root["spec"]) != self.root["requestDigest"]:
            raise ValueError("requestDigest does not match live snapshot spec")
        return self


class LiveWorkspaceSnapshot(CanonicalNativeModel):
    component = "LiveWorkspaceSnapshot"


class LiveWorkspaceDiffPage(CanonicalNativeModel):
    component = "LiveWorkspaceDiffPage"


class DevSessionCreateRequest(CanonicalNativeModel):
    component = "DevSessionCreateRequest"

    @model_validator(mode="after")
    def validate_request_digest(self) -> DevSessionCreateRequest:
        if canonical_digest(self.root["spec"]) != self.root["requestDigest"]:
            raise ValueError("requestDigest does not match dev session spec")
        return self


class DevSessionRenewRequest(CanonicalNativeModel):
    component = "DevSessionRenewRequest"

    @model_validator(mode="after")
    def validate_request_digest(self) -> DevSessionRenewRequest:
        if canonical_digest(self.root["spec"]) != self.root["requestDigest"]:
            raise ValueError("requestDigest does not match dev session renew spec")
        return self


class DevSessionSnapshot(CanonicalNativeModel):
    component = "DevSessionSnapshot"


__all__ = [
    "AnyJobBindingSnapshotList",
    "NativeCreateJobRequest",
    "NativeFinalizeJobRequest",
    "NativeJobBindingSnapshot",
    "NativeRoleLogs",
    "NativeRunnerGenerationSnapshot",
    "NativeTerminalSessionSnapshot",
    "RuntimeAssemblyResolutionRequest",
    "ResolvedRuntimeAssembly",
    "LiveWorkspaceSnapshotRequest",
    "LiveWorkspaceSnapshot",
    "LiveWorkspaceDiffPage",
    "DevSessionCreateRequest",
    "DevSessionRenewRequest",
    "DevSessionSnapshot",
    "ResolvedRuntimeRecipe",
    "RunnerCredentialGrantSnapshot",
    "RunnerStartRequest",
    "RunnerStopRequest",
    "RunnerStopSnapshot",
    "RuntimeRecipeActivationReceipt",
]
