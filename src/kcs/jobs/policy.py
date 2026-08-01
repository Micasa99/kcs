"""Frozen input policy shared by the V2 contracts and Job renderer."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping

IMAGE_PATTERN = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
ALLOWED_RUNTIME_ENV = frozenset(
    {
        "LANG",
        "LC_ALL",
        "TZ",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "RC_PUBLIC_RUNTIME_BASE_URL",
    }
)

_SECRET_SHAPES = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(
        r"\b(?:api[_-]?key|access[_-]?token|authorization|cookie|password|secret)"
        r"\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"\bssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/=]+", re.IGNORECASE),
    re.compile(r"\b(?:client-key-data|client-certificate-data|current-context)\s*:", re.I),
)
_REJECTED_PATH_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


class PolicyViolationError(ValueError):
    """A request violates the frozen V2 workload policy."""


def validate_opaque_ref(value: str) -> str:
    """Enforce the OpenAPI byte limit without changing the exact identity."""
    if not value or len(value.encode("utf-8")) > 256:
        raise PolicyViolationError("opaque refs must contain 1 to 256 UTF-8 bytes")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise PolicyViolationError("opaque refs cannot contain control characters")
    return value


def validate_immutable_image(value: str) -> str:
    if IMAGE_PATTERN.fullmatch(value) is None:
        raise PolicyViolationError("formal images must be pinned by a lowercase sha256 digest")
    return value


def validate_runtime_environment(value: Mapping[str, str]) -> dict[str, str]:
    if len(value) > 32:
        raise PolicyViolationError("runtimeEnv may contain at most 32 entries")
    validated: dict[str, str] = {}
    for key, item in value.items():
        if key not in ALLOWED_RUNTIME_ENV or len(key.encode("utf-8")) > 64:
            raise PolicyViolationError(f"runtimeEnv key is not allowed: {key}")
        if len(item.encode("utf-8")) > 2048:
            raise PolicyViolationError(f"runtimeEnv value is too large: {key}")
        if any(pattern.search(item) for pattern in _SECRET_SHAPES):
            raise PolicyViolationError(f"runtimeEnv contains a secret-shaped value: {key}")
        validated[key] = item
    return validated


def validate_safe_relative_path(value: str) -> str:
    """Validate the lexical portion of the transfer path contract."""
    if not value or value.startswith("/") or "\\" in value:
        raise PolicyViolationError("path must be a non-empty relative POSIX path")
    if unicodedata.normalize("NFC", value) != value:
        raise PolicyViolationError("path must use NFC normalization")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PolicyViolationError("path contains an empty, dot, or dot-dot component")
    if any(unicodedata.category(character) in _REJECTED_PATH_CATEGORIES for character in value):
        raise PolicyViolationError("path contains a forbidden Unicode category")
    return value


def validate_casefold_unique_paths(values: Iterable[str]) -> list[str]:
    validated = [validate_safe_relative_path(value) for value in values]
    folded = [value.casefold() for value in validated]
    if len(folded) != len(set(folded)):
        raise PolicyViolationError("paths must be unique after Unicode case folding")
    return validated
