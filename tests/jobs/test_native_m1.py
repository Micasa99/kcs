from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kcs.jobs.canonical import canonical_digest
from kcs.jobs.errors import RuntimeRecipeForbiddenError
from kcs.jobs.native_contracts import NativeCreateJobRequest, NativeRunnerGenerationSnapshot
from kcs.jobs.provider import V2JobProvider, _native_post_ack_delivery_loss
from kcs.jobs.recipe_registry import NativeRecipeRegistry
from kcs.jobs.renderer import V2JobRenderer, runner_credential_secret_name
from kcs.jobs.settings import V2RuntimeSettings
from kcs.server.app import create_app

ROOT = Path(__file__).resolve().parents[2]


def _registry(tmp_path: Path) -> NativeRecipeRegistry:
    recipe = json.loads(
        (ROOT / "openapi/native-fixtures/runtime-recipe-assembled.json").read_text()
    )
    path = tmp_path / "recipes.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "recipes": [
                    {
                        "recipe": recipe,
                        "requires": ["linux-amd64", "workspace-rw"],
                        "provides": ["linux-amd64", "workspace-rw", "nvidia-gpu"],
                    }
                ],
            }
        )
    )
    return NativeRecipeRegistry(path)


def test_native_recipe_is_exact_and_unknown_pairs_fail_closed(tmp_path: Path) -> None:
    registry = _registry(tmp_path)

    resolved = registry.resolve("runner-codex", "env-default")
    assert resolved.root["delivery"]["mode"] == "assembled"
    assert registry.count == 1
    with pytest.raises(RuntimeRecipeForbiddenError):
        registry.resolve("runner-codex", "env-unknown")


def test_native_renderer_builds_only_runner_control_and_no_replacement(tmp_path: Path) -> None:
    body = json.loads((ROOT / "openapi/native-fixtures/create-request.json").read_text())
    body["specDigest"] = canonical_digest(body["spec"])
    request = NativeCreateJobRequest.model_validate(body)
    settings = V2RuntimeSettings(
        namespace="native-m1-test",
        node_selector={"researchcosmos.io/pool": "gpu"},
        api_mode="v2",
        service_token=None,
        model_gateway_openai_base_url="https://model-gateway.example/openai/v1",
        model_gateway_anthropic_base_url="https://model-gateway.example/anthropic",
    )

    job = V2JobRenderer(settings, _registry(tmp_path)).render(request)
    pod = job.spec.template.spec
    runner, control = pod.containers

    assert [item.name for item in pod.containers] == ["runner", "control"]
    assert job.spec.backoff_limit == 0
    assert job.spec.active_deadline_seconds == 5700
    assert pod.share_process_namespace is False
    assert pod.automount_service_account_token is False
    assert pod.init_containers is None
    assert runner.command == ["/opt/rc-platform/bin/rc-native-launcher"]
    assert runner.security_context.run_as_user == 0
    assert set(runner.security_context.capabilities.add) == {
        "CHOWN",
        "SETUID",
        "SETGID",
        "KILL",
    }
    assert control.security_context.run_as_user == 0
    assert {item.name: item.value for item in control.env}["TMPDIR"] == "/run/rc-control"
    assert all(item.name != "model-gateway-credential" for item in control.volume_mounts)
    credential = next(
        item for item in pod.volumes if item.name == "model-gateway-credential"
    )
    assert credential.secret.optional is True
    assert credential.secret.default_mode == 0o400
    assert credential.secret.secret_name == runner_credential_secret_name(job.metadata.name)
    assert runner.resources.requests["nvidia.com/gpu"] == "1"
    assert runner.resources.requests["ephemeral-storage"] == "4096Mi"
    assert all(item.image is None for item in pod.volumes if item.name.startswith("rc-user"))


def test_native_metrics_require_service_auth_and_expose_no_job_identity() -> None:
    class Provider:
        @staticmethod
        def reconcile_all() -> None:
            return None

        @staticmethod
        def collect_runtime_events() -> int:
            return 0

        @staticmethod
        def prometheus_metrics() -> str:
            return 'kcs_native_runner_generations{runner_state="running"} 1\n'

    settings = V2RuntimeSettings(
        namespace="native-m1-test",
        node_selector={"researchcosmos.io/pool": "gpu"},
        api_mode="v2",
        service_token="metrics-test-token",
    )
    with TestClient(
        create_app(api_mode="v2", v2_provider=Provider(), v2_settings=settings)
    ) as client:
        assert client.get("/metrics").status_code == 401
        response = client.get(
            "/metrics", headers={"Authorization": "Bearer metrics-test-token"}
        )

    assert response.status_code == 200
    assert response.text == 'kcs_native_runner_generations{runner_state="running"} 1\n'
    assert "jobRef" not in response.text


def test_post_ack_emptydir_eviction_is_output_loss_but_pre_ack_is_not() -> None:
    payload = json.loads(
        (ROOT / "openapi/native-fixtures/runner-generation.json").read_text()
    )
    started = NativeRunnerGenerationSnapshot.model_validate(payload)

    assert (
        _native_post_ack_delivery_loss(
            {"deliveryFailure": "emptydir_evicted"}, started
        )
        == "emptydir_evicted"
    )

    payload["credentialAcknowledgedAt"] = None
    not_started = NativeRunnerGenerationSnapshot.model_validate(payload)
    assert (
        _native_post_ack_delivery_loss(
            {"deliveryFailure": "emptydir_evicted"}, not_started
        )
        is None
    )


def test_recipe_refusal_increments_only_the_aggregate_metric() -> None:
    class RejectingRenderer:
        @staticmethod
        def resolve_recipe(_runner_ref: str, _environment_ref: str) -> None:
            raise RuntimeRecipeForbiddenError()

    class EmptyStore:
        @staticmethod
        def list_create() -> tuple[()]:
            return ()

    provider = object.__new__(V2JobProvider)
    provider._renderer = RejectingRenderer()
    provider._store = EmptyStore()
    provider._native_metrics_lock = threading.Lock()
    provider._native_recipe_forbidden_total = 0

    with pytest.raises(RuntimeRecipeForbiddenError):
        provider.resolve_runtime_recipe("unknown-runner", "unknown-environment")

    metrics = provider.prometheus_metrics()
    assert "kcs_native_recipe_forbidden_total 1\n" in metrics
    assert "unknown-runner" not in metrics
    assert "unknown-environment" not in metrics
