"""Typed models for the active, additive KCS 2.6 M2 surfaces.

The generated and packaged canonical document is the single schema authority.
Production deployment remains a separate operator checkpoint.
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


@lru_cache(maxsize=1)
def _m2_document() -> dict[str, Any]:
    override = os.environ.get("KCS_V25_OPENAPI_PATH")
    candidates = [
        Path(override) if override else None,
        Path(__file__).resolve().parents[3] / "openapi/generated/kcs-v2-jobs.openapi.json",
    ]
    for candidate in candidates:
        if candidate is None or not candidate.is_file():
            continue
        try:
            value = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("KCS 2.6 OpenAPI is unreadable") from error
        if value.get("info", {}).get("version") == "2.6.0":
            return value
    try:
        payload = (
            importlib.resources.files("kcs.openapi")
            .joinpath("kcs-v2-jobs.openapi.json")
            .read_text(encoding="utf-8")
        )
        value = json.loads(payload)
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("KCS 2.6 OpenAPI is unavailable") from error
    if value.get("info", {}).get("version") != "2.6.0":
        raise RuntimeError("the served KCS package is not the frozen 2.6 contract")
    return value


@cache
def _validator(component: str) -> Draft202012Validator:
    document = _m2_document()
    if component not in document.get("components", {}).get("schemas", {}):
        raise RuntimeError(f"KCS 2.6 OpenAPI has no {component} component")
    return Draft202012Validator(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": f"#/components/schemas/{component}",
            "components": document["components"],
        }
    )


class CanonicalM2Model(RootModel[dict[str, Any]]):
    component: ClassVar[str]

    @model_validator(mode="after")
    def validate_component(self) -> CanonicalM2Model:
        errors = sorted(
            _validator(self.component).iter_errors(self.root),
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


class RuntimeAssemblyResolutionRequest(CanonicalM2Model):
    component = "RuntimeAssemblyResolutionRequest"


class ResolvedRuntimeAssembly(CanonicalM2Model):
    component = "ResolvedRuntimeAssembly"


class CapabilityActivationPlan(CanonicalM2Model):
    component = "CapabilityActivationPlan"


class CapabilityActivationReceipt(CanonicalM2Model):
    component = "CapabilityActivationReceipt"


class LiveWorkspaceSnapshotRequest(CanonicalM2Model):
    component = "LiveWorkspaceSnapshotRequest"

    @model_validator(mode="after")
    def validate_request_digest(self) -> LiveWorkspaceSnapshotRequest:
        if canonical_digest(self.root["spec"]) != self.root["requestDigest"]:
            raise ValueError("requestDigest does not match live snapshot spec")
        return self


class LiveWorkspaceSnapshot(CanonicalM2Model):
    component = "LiveWorkspaceSnapshot"


class LiveWorkspaceDiffPage(CanonicalM2Model):
    component = "LiveWorkspaceDiffPage"


__all__ = [
    "CapabilityActivationPlan",
    "CapabilityActivationReceipt",
    "LiveWorkspaceDiffPage",
    "LiveWorkspaceSnapshot",
    "LiveWorkspaceSnapshotRequest",
    "ResolvedRuntimeAssembly",
    "RuntimeAssemblyResolutionRequest",
]
