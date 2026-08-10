from __future__ import annotations

import pytest

from kcs.jobs.settings import V2RuntimeSettings


def test_settings_apply_formal_defaults_in_test_mode() -> None:
    settings = V2RuntimeSettings.from_env({"KCS_ENV": "test"})

    assert settings.namespace == "researchcosmos-v2"
    assert settings.node_selector == {"researchcosmos.io/pool": "gpu"}
    assert settings.api_mode == "v2"
    assert settings.service_token is None


def test_settings_require_service_token_outside_tests() -> None:
    with pytest.raises(ValueError, match="KCS_V2_SERVICE_TOKEN"):
        V2RuntimeSettings.from_env({})


def test_settings_accept_only_the_frozen_v2_mode() -> None:
    with pytest.raises(ValueError, match="KCS_API_MODE must be 'v2'"):
        V2RuntimeSettings.from_env(
            {"KCS_ENV": "test", "KCS_API_MODE": "v1"}
        )


def test_settings_reject_default_namespace() -> None:
    with pytest.raises(ValueError, match="namespace 'default' is forbidden"):
        V2RuntimeSettings.from_env(
            {"KCS_ENV": "test", "KCS_V2_NAMESPACE": "default"}
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("KCS_V2_NAMESPACE", "ResearchCosmos"),
        ("KCS_V2_NODE_SELECTOR", "researchcosmos.io/pool"),
        ("KCS_V2_NODE_SELECTOR", "=gpu"),
    ],
)
def test_settings_reject_malformed_namespace_and_selector(key: str, value: str) -> None:
    with pytest.raises(ValueError):
        V2RuntimeSettings.from_env({"KCS_ENV": "test", key: value})


def test_settings_parse_an_explicit_selector_without_connection_metadata() -> None:
    settings = V2RuntimeSettings.from_env(
        {
            "KCS_V2_SERVICE_TOKEN": "unit-test-placeholder",
            "KCS_V2_NODE_SELECTOR": "accelerator=nvidia,zone=attempts",
        }
    )

    assert settings.node_selector == {"accelerator": "nvidia", "zone": "attempts"}
    assert not hasattr(settings, "host")
    assert not hasattr(settings, "user")
    assert not hasattr(settings, "ssh_key")


def test_settings_repr_never_discloses_the_service_token() -> None:
    settings = V2RuntimeSettings.from_env(
        {"KCS_V2_SERVICE_TOKEN": "unit-test-placeholder"}
    )

    assert "unit-test-placeholder" not in repr(settings)


def test_settings_parse_exact_model_gateway_allowlists() -> None:
    settings = V2RuntimeSettings.from_env(
        {
            "KCS_ENV": "test",
            "KCS_V2_MODEL_GATEWAY_OPENAI_BASE_URL": (
                "https://product.example/main/openai/v1,"
                "https://product.example/test/openai/v1"
            ),
            "KCS_V2_MODEL_GATEWAY_ANTHROPIC_BASE_URL": (
                "https://product.example/main/anthropic,"
                "https://product.example/test/anthropic"
            ),
        }
    )

    assert settings.model_gateway_openai_base_urls == (
        "https://product.example/main/openai/v1",
        "https://product.example/test/openai/v1",
    )
    assert settings.model_gateway_anthropic_base_urls == (
        "https://product.example/main/anthropic",
        "https://product.example/test/anthropic",
    )


@pytest.mark.parametrize(
    "selector",
    [
        "bad..prefix/name=value",
        f"{'a' * 64}.example/name=value",
        f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 62}/name=value",
        f"prefix.example/{'n' * 64}=value",
        f"prefix.example/name={'v' * 64}",
    ],
)
def test_settings_reject_selector_components_outside_kubernetes_bounds(
    selector: str,
) -> None:
    with pytest.raises(ValueError, match="KCS_V2_NODE_SELECTOR"):
        V2RuntimeSettings.from_env(
            {"KCS_ENV": "test", "KCS_V2_NODE_SELECTOR": selector}
        )


def test_settings_accept_selector_components_at_kubernetes_bounds() -> None:
    prefix = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
    name = "n" * 63
    value = "v" * 63

    settings = V2RuntimeSettings.from_env(
        {"KCS_ENV": "test", "KCS_V2_NODE_SELECTOR": f"{prefix}/{name}={value}"}
    )

    assert settings.node_selector == {f"{prefix}/{name}": value}
