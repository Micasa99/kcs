"""Operator-curated exact native runtime recipe registry."""

from __future__ import annotations

import copy
import hmac
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_digest
from .errors import InvalidRequestError, RuntimeRecipeForbiddenError
from .native_contracts import ResolvedRuntimeRecipe


def _recipe_wire(
    recipe: ResolvedRuntimeRecipe | Mapping[str, Any],
) -> dict[str, Any]:
    if isinstance(recipe, ResolvedRuntimeRecipe):
        return copy.deepcopy(recipe.wire())
    return copy.deepcopy(dict(recipe))


def runtime_recipe_digest_payload(
    recipe: ResolvedRuntimeRecipe | Mapping[str, Any],
) -> dict[str, Any]:
    """Return the immutable recipe content covered by ``recipeDigest``.

    ``recipeDigest`` is self-referential and ``observedAt`` describes an API
    observation rather than runtime assembly content.  Every other canonical
    recipe field participates in the digest.
    """

    payload = _recipe_wire(recipe)
    payload.pop("recipeDigest", None)
    payload.pop("observedAt", None)
    return payload


def runtime_recipe_digest(
    recipe: ResolvedRuntimeRecipe | Mapping[str, Any],
) -> str:
    """Return the RFC 8785 SHA-256 digest for immutable recipe content."""

    return canonical_digest(runtime_recipe_digest_payload(recipe))


def runtime_recipe_snapshot_wire(
    recipe: ResolvedRuntimeRecipe | Mapping[str, Any],
) -> dict[str, Any]:
    """Return stable content suitable for a future create-time snapshot.

    The result deliberately omits the dynamic ``observedAt`` response field and
    carries a digest recomputed from the returned immutable content.
    """

    payload = runtime_recipe_digest_payload(recipe)
    payload["recipeDigest"] = canonical_digest(payload)
    return payload


class NativeRecipeRegistry:
    """Resolve one immutable recipe without becoming a scheduling authority."""

    def __init__(
        self,
        path: Path | None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._recipes: dict[tuple[str, str], ResolvedRuntimeRecipe] = {}
        if path is not None:
            self._load(path)

    def _load(self, path: Path) -> None:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("native recipe registry is unreadable") from error
        if not isinstance(document, dict) or set(document) != {"version", "recipes"}:
            raise ValueError("native recipe registry must contain only version and recipes")
        if document["version"] != 1 or not isinstance(document["recipes"], list):
            raise ValueError("native recipe registry version is unsupported")
        for item in document["recipes"]:
            if not isinstance(item, dict) or set(item) != {"recipe", "requires", "provides"}:
                raise ValueError("native recipe entry has an invalid shape")
            requires = item["requires"]
            provides = item["provides"]
            if (
                not isinstance(requires, list)
                or not isinstance(provides, list)
                or any(not isinstance(value, str) or not value for value in requires + provides)
                or not set(requires).issubset(provides)
            ):
                raise ValueError("native recipe requires must be a subset of provides")
            recipe = ResolvedRuntimeRecipe.model_validate(item["recipe"])
            supplied_digest = str(recipe.root["recipeDigest"])
            expected_digest = runtime_recipe_digest(recipe)
            if not hmac.compare_digest(supplied_digest, expected_digest):
                raise ValueError("native recipe digest does not match immutable content")
            key = (recipe.runner_ref, recipe.environment_profile_ref)
            if key in self._recipes:
                raise ValueError("native recipe registry contains a duplicate pair")
            self._recipes[key] = recipe

    def resolve(self, runner_ref: str, environment_profile_ref: str) -> ResolvedRuntimeRecipe:
        if not runner_ref or not environment_profile_ref:
            raise InvalidRequestError("runnerRef and environmentProfileRef are required")
        recipe = self._recipes.get((runner_ref, environment_profile_ref))
        if recipe is None:
            raise RuntimeRecipeForbiddenError()
        payload = recipe.wire()
        payload["observedAt"] = self._clock().isoformat()
        return ResolvedRuntimeRecipe.model_validate(payload)

    @property
    def count(self) -> int:
        return len(self._recipes)


__all__ = [
    "NativeRecipeRegistry",
    "runtime_recipe_digest",
    "runtime_recipe_digest_payload",
    "runtime_recipe_snapshot_wire",
]
