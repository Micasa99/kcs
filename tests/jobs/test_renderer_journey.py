from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path

FIXTURES = Path(__file__).parents[2] / "openapi" / "examples" / "fixtures"


def test_create_contract_renders_the_fixed_dual_role_job_journey() -> None:
    """Exercise the P1 boundary from canonical request bytes to a Kubernetes Job."""
    assert importlib.util.find_spec("kcs.jobs.contracts") is not None

    from kcs.jobs.canonical import canonical_digest
    from kcs.jobs.contracts import (
        CreateJobRequest,
        JobBindingSnapshot,
        JobBindingSnapshotList,
        JobTombstone,
        RoleLogs,
    )
    from kcs.jobs.renderer import V2JobRenderer, credential_secret_name
    from kcs.jobs.settings import V2RuntimeSettings

    canonical_body = json.loads((FIXTURES / "create-request.json").read_text())
    canonical_request = CreateJobRequest.model_validate(canonical_body)
    assert canonical_request.spec_digest == canonical_body["specDigest"]
    assert canonical_request.spec.digest_payload() == canonical_body["spec"]

    body = deepcopy(canonical_body)
    body["spec"]["workspace"]["resources"]["gpu"] = 1
    body["specDigest"] = canonical_digest(body["spec"])
    request = CreateJobRequest.model_validate(body)

    omitted_resources = json.loads(json.dumps(body["spec"]))
    omitted_resources["agent"].pop("resources")
    assert canonical_digest(omitted_resources) != canonical_digest(body["spec"])
    omitted_body = deepcopy(body)
    omitted_body["spec"] = omitted_resources
    omitted_body["specDigest"] = canonical_digest(omitted_resources)
    omitted_request = CreateJobRequest.model_validate(omitted_body)
    assert omitted_request.spec.digest_payload() == omitted_resources

    settings = V2RuntimeSettings(
        namespace="researchcosmos-v2",
        node_selector={"researchcosmos.io/pool": "gpu"},
        api_mode="v2",
        service_token=None,
    )
    job = V2JobRenderer(settings).render(request)
    pod = job.spec.template.spec
    agent, workspace = pod.containers

    assert job.api_version == "batch/v1"
    assert job.kind == "Job"
    assert job.metadata.namespace == "researchcosmos-v2"
    assert body["providerRequestId"] not in job.metadata.name
    assert (
        job.metadata.annotations["researchcosmos.io/provider-request-id"]
        == body["providerRequestId"]
    )
    assert job.metadata.labels["researchcosmos.io/managed-by"] == "v2-attempt-runtime"
    assert job.spec.completions == job.spec.parallelism == 1
    assert job.spec.backoff_limit == 0
    assert pod.restart_policy == "Never"
    assert pod.automount_service_account_token is False
    assert pod.service_account_name == "kcs-v2-workload"
    assert pod.host_network is False and pod.host_pid is False and pod.host_ipc is False
    assert [container.name for container in pod.containers] == ["agent", "workspace"]
    assert pod.node_selector == settings.node_selector

    workspace_volume = next(volume for volume in pod.volumes if volume.name == "workspace")
    credential_volume = next(volume for volume in pod.volumes if volume.name == "agent-credential")
    assert workspace_volume.empty_dir.size_limit == "20Gi"
    assert credential_volume.secret.optional is True
    assert credential_volume.secret.secret_name == credential_secret_name(job.metadata.name)
    assert [mount.mount_path for mount in agent.volume_mounts] == [
        "/workspace",
        "/var/run/kcs/credential",
    ]
    assert [mount.mount_path for mount in workspace.volume_mounts] == ["/workspace"]
    assert agent.resources.limits.get("nvidia.com/gpu") is None
    assert workspace.resources.limits["nvidia.com/gpu"] == "1"
    assert agent.security_context.privileged is False
    assert workspace.security_context.privileged is False

    assert (
        JobBindingSnapshot.model_validate_json(
            (FIXTURES / "job-binding.json").read_text()
        ).binding_state.value
        == "running"
    )
    assert JobBindingSnapshotList.model_validate_json(
        (FIXTURES / "job-list.json").read_text()
    ).next_page_token
    assert RoleLogs.model_validate_json((FIXTURES / "logs.json").read_text()).container.value == (
        "agent"
    )
    assert (
        JobTombstone.model_validate_json((FIXTURES / "tombstone.json").read_text()).state
        == "deleted"
    )
