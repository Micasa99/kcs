"""Exact, operator-curated Runner/Environment/Skill/Tool assembly resolution."""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from .canonical import canonical_digest
from .errors import (
    CapabilityActivationIncompatibleError,
    DependencyUnavailableError,
    DigestMismatchError,
)
from .m2_contracts import (
    CapabilityActivationPlan,
    CapabilityActivationReceipt,
    ResolvedRuntimeAssembly,
    RuntimeAssemblyResolutionRequest,
)
from .policy import validate_immutable_image, validate_opaque_ref
from .recipe_registry import NativeRecipeRegistry, runtime_recipe_snapshot_wire

_CAPABILITY_TARGET = re.compile(r"^/opt/rc-(skills|tools)/[A-Za-z0-9._-]+$")
_TOOL_DISCOVERY = re.compile(r"^/opt/rc-tools/[A-Za-z0-9._/-]+$")
_SKILL_DISCOVERY = re.compile(r"^/opt/rc-skills/[A-Za-z0-9._-]+$")
_PROTOCOLS = frozenset(
    {"openai-responses", "openai-completions", "anthropic-messages"}
)


class RecipeResolver(Protocol):
    def resolve(self, runner_ref: str, environment_profile_ref: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class CapabilityMaterial:
    kind: str
    capability_ref: str
    material_digest: str
    image_volume_digest: str
    source_path: str
    target_path: str
    runner_discovery_path: str
    runner_refs: frozenset[str]
    environment_profile_refs: frozenset[str]
    model_protocols: frozenset[str]

    def mount_wire(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "capabilityRef": self.capability_ref,
            "materialDigest": self.material_digest,
            "imageVolumeDigest": self.image_volume_digest,
            "sourcePath": self.source_path,
            "targetPath": self.target_path,
            "runnerDiscoveryPath": self.runner_discovery_path,
            "readOnly": True,
        }


class NativeCapabilityRegistry:
    """Read a closed registry of immutable, already-approved capability bundles."""

    def __init__(self, path: Path | None) -> None:
        self._materials: dict[tuple[str, str], CapabilityMaterial] = {}
        if path is not None:
            self._load(path)

    def _load(self, path: Path) -> None:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("native capability registry is unreadable") from error
        if not isinstance(document, dict) or set(document) != {"version", "capabilities"}:
            raise ValueError(
                "native capability registry must contain only version and capabilities"
            )
        if document["version"] != 1 or not isinstance(document["capabilities"], list):
            raise ValueError("native capability registry version is unsupported")
        for raw in document["capabilities"]:
            material = _material(raw)
            key = (material.kind, material.capability_ref)
            if key in self._materials:
                raise ValueError("native capability registry contains a duplicate exact ref")
            self._materials[key] = material

    def resolve(
        self,
        kind: str,
        pin: Mapping[str, Any],
        *,
        runner_ref: str,
        environment_profile_ref: str,
        selected_model_protocol: str,
    ) -> CapabilityMaterial:
        capability_ref = str(pin["capabilityRef"])
        material_digest = str(pin["materialDigest"])
        material = self._materials.get((kind, capability_ref))
        if material is None or not hmac.compare_digest(
            material.material_digest, material_digest
        ):
            raise CapabilityActivationIncompatibleError(
                f"The exact {kind} material is not registered"
            )
        if (
            runner_ref not in material.runner_refs
            or environment_profile_ref not in material.environment_profile_refs
            or selected_model_protocol not in material.model_protocols
        ):
            raise CapabilityActivationIncompatibleError(
                f"The exact {kind} material is incompatible with the selected runtime"
            )
        return material

    @property
    def count(self) -> int:
        return len(self._materials)


class RuntimeAssemblyResolver:
    """Resolve one immutable assembly without accepting image or command fields from RC."""

    def __init__(
        self,
        recipes: NativeRecipeRegistry | RecipeResolver,
        capabilities: NativeCapabilityRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._recipes = recipes
        self._capabilities = capabilities
        self._clock = clock or (lambda: datetime.now(UTC))

    def resolve(
        self, request: RuntimeAssemblyResolutionRequest | Mapping[str, Any]
    ) -> ResolvedRuntimeAssembly:
        typed = (
            request
            if isinstance(request, RuntimeAssemblyResolutionRequest)
            else RuntimeAssemblyResolutionRequest.model_validate(dict(request))
        )
        value = typed.root
        runner_ref = str(value["runnerRef"])
        environment_ref = str(value["environmentProfileRef"])
        protocol = str(value["selectedModelProtocol"])
        recipe = self._recipes.resolve(runner_ref, environment_ref)
        if not hmac.compare_digest(
            str(recipe.root["recipeDigest"]), str(value["recipeDigest"])
        ):
            raise DigestMismatchError("recipeDigest differs from the registered runtime recipe")
        if protocol not in recipe.root["supportedModelProtocols"]:
            raise CapabilityActivationIncompatibleError(
                "The runtime recipe does not support selectedModelProtocol"
            )

        skill_pins = _pins(value["skillPins"], "skill")
        tool_pins = _pins(value["toolPins"], "tool")
        # This digest covers RC's complete ResolvedCapabilitySet (AgentProfile,
        # Runner, Environment and dependency closure), not merely the pins KCS
        # sees here. KCS preserves it as opaque owner identity and independently
        # verifies every deployable Skill/Tool pin against its own registry.
        lock_digest = str(value["capabilityLockDigest"])

        mounts = [
            self._capabilities.resolve(
                kind,
                pin,
                runner_ref=runner_ref,
                environment_profile_ref=environment_ref,
                selected_model_protocol=protocol,
            ).mount_wire()
            for kind, pins in (("skill", skill_pins), ("tool", tool_pins))
            for pin in pins
        ]
        targets = [str(item["targetPath"]) for item in mounts]
        if len(targets) != len(set(targets)):
            raise CapabilityActivationIncompatibleError(
                "Capability bundles resolve to the same immutable mount target"
            )

        plan_payload: dict[str, Any] = {
            "capabilityLockDigest": lock_digest,
            "skillPins": skill_pins,
            "toolPins": tool_pins,
            "mounts": mounts,
        }
        plan_digest = canonical_digest(plan_payload)
        plan = CapabilityActivationPlan.model_validate(
            {
                "planRef": f"capability-plan-{plan_digest[:24]}",
                "planDigest": plan_digest,
                **plan_payload,
            }
        )
        stable_recipe = runtime_recipe_snapshot_wire(recipe)
        assembly_payload = {
            "recipe": stable_recipe,
            "selectedModelProtocol": protocol,
            "capabilityActivation": plan.wire(),
        }
        assembly_digest = canonical_digest(assembly_payload)
        response_recipe = recipe.wire()
        return ResolvedRuntimeAssembly.model_validate(
            {
                "assemblyRef": f"runtime-assembly-{assembly_digest[:24]}",
                "assemblyDigest": assembly_digest,
                "recipe": response_recipe,
                "selectedModelProtocol": protocol,
                "capabilityActivation": plan.wire(),
                "observedAt": _timestamp(self._clock()),
            }
        )


def capability_activation_receipt(
    plan: CapabilityActivationPlan | Mapping[str, Any],
    *,
    job_uid: str,
    pod_uid: str,
    generation: int,
    observed_mounts: Mapping[str, Mapping[str, Any]],
    observed_at: datetime,
) -> CapabilityActivationReceipt:
    """Reconcile actual image-volume observations against one exact activation plan."""

    plan_value = plan.root if isinstance(plan, CapabilityActivationPlan) else dict(plan)
    receipts: list[dict[str, Any]] = []
    state = "ready"
    failure_reason: str | None = None
    for expected in plan_value["mounts"]:
        target = str(expected["targetPath"])
        observed = observed_mounts.get(target)
        expected_image = str(expected["imageVolumeDigest"])
        if observed is None:
            state = "indeterminate"
            failure_reason = "capability mount observation is incomplete"
            image_ref, image_id, verified = expected_image, None, False
        else:
            image_ref = str(observed.get("imageVolumeRef", ""))
            image_id = observed.get("imageVolumeId")
            verified = bool(observed.get("verified")) and hmac.compare_digest(
                image_ref, expected_image
            )
            if not verified:
                state = "failed"
                failure_reason = "capability mount differs from the resolved activation plan"
        receipts.append(
            {
                "kind": expected["kind"],
                "capabilityRef": expected["capabilityRef"],
                "materialDigest": expected["materialDigest"],
                "imageVolumeRef": image_ref or expected_image,
                "imageVolumeId": image_id,
                "targetPath": target,
                "readOnly": True,
                "verified": verified,
            }
        )
    return CapabilityActivationReceipt.model_validate(
        {
            "planRef": plan_value["planRef"],
            "planDigest": plan_value["planDigest"],
            "jobUid": job_uid,
            "podUid": pod_uid,
            "generation": generation,
            "state": state,
            "mounts": receipts,
            "failureReason": failure_reason,
            "observedAt": _timestamp(observed_at),
        }
    )


def unavailable_runtime_assembly(*_: object, **__: object) -> ResolvedRuntimeAssembly:
    raise DependencyUnavailableError("runtime assembly registry is not configured")


def _material(value: object) -> CapabilityMaterial:
    required = {
        "kind",
        "capabilityRef",
        "materialDigest",
        "imageVolumeDigest",
        "sourcePath",
        "targetPath",
        "runnerDiscoveryPath",
        "runnerRefs",
        "environmentProfileRefs",
        "modelProtocols",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("native capability entry has an invalid shape")
    kind = value["kind"]
    if kind not in {"skill", "tool"}:
        raise ValueError("native capability kind is unsupported")
    capability_ref = validate_opaque_ref(str(value["capabilityRef"]))
    material_digest = str(value["materialDigest"])
    if not re.fullmatch(r"[0-9a-f]{64}", material_digest):
        raise ValueError("native capability material digest is invalid")
    image = validate_immutable_image(str(value["imageVolumeDigest"]))
    source = str(value["sourcePath"])
    source_parts = PurePosixPath(source)
    if not source_parts.is_absolute() or any(part in {".", ".."} for part in source_parts.parts):
        raise ValueError("native capability source path is unsafe")
    target = str(value["targetPath"])
    discovery = str(value["runnerDiscoveryPath"])
    if _CAPABILITY_TARGET.fullmatch(target) is None:
        raise ValueError("native capability target path is invalid")
    discovery_pattern = _SKILL_DISCOVERY if kind == "skill" else _TOOL_DISCOVERY
    if discovery_pattern.fullmatch(discovery) is None:
        raise ValueError("native capability discovery path is invalid")
    runners = _refs(value["runnerRefs"], "runnerRefs")
    environments = _refs(value["environmentProfileRefs"], "environmentProfileRefs")
    protocols = _strings(value["modelProtocols"], "modelProtocols")
    if not protocols.issubset(_PROTOCOLS):
        raise ValueError("native capability model protocol is unsupported")
    return CapabilityMaterial(
        kind=kind,
        capability_ref=capability_ref,
        material_digest=material_digest,
        image_volume_digest=image,
        source_path=source,
        target_path=target,
        runner_discovery_path=discovery,
        runner_refs=runners,
        environment_profile_refs=environments,
        model_protocols=protocols,
    )


def _refs(value: object, field: str) -> frozenset[str]:
    result = _strings(value, field)
    for item in result:
        validate_opaque_ref(item)
    return result


def _strings(value: object, field: str) -> frozenset[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ValueError(f"native capability {field} must be a non-empty unique list")
    return frozenset(value)


def _pins(value: object, kind: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise CapabilityActivationIncompatibleError(f"{kind} pins are invalid")
    pins = [
        {"capabilityRef": str(item["capabilityRef"]), "materialDigest": str(item["materialDigest"])}
        for item in value
    ]
    pins.sort(key=lambda item: (item["capabilityRef"], item["materialDigest"]))
    if len({item["capabilityRef"] for item in pins}) != len(pins):
        raise CapabilityActivationIncompatibleError(
            f"The same {kind} ref cannot be pinned more than once"
        )
    return pins


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = [
    "CapabilityMaterial",
    "NativeCapabilityRegistry",
    "RuntimeAssemblyResolver",
    "capability_activation_receipt",
]
