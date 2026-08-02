#!/usr/bin/env python3
"""Run the deployed KCS V2 conformance Journey and retain raw evidence.

The script talks only to the deployed HTTPS API. Kubernetes reality and the two
operator mutations (API Deployment restart and UID-precondition Pod deletion)
arrive through explicit O0-O3 checkpoint files; no shell hook is accepted.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import ssl
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote, urlencode, urlsplit

import rfc8785
import yaml  # type: ignore[import-untyped]

SERVICE_TOKEN_ENV = "KCS_V2_SERVICE_TOKEN"
EMPTY_OBJECT_DIGEST = hashlib.sha256(rfc8785.dumps({})).hexdigest()
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IMAGE_PATTERN = re.compile(r"^.+@sha256:([0-9a-f]{64})$")
CHECKPOINT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
MAX_LOG_BYTES = 1_048_576
AGENT_PROBE = b"kcs-v2-agent-shared-probe\n"
WORKSPACE_PROBE = b"kcs-v2-workspace-shared-probe\n"
AGENT_PROBE_SHA256 = hashlib.sha256(AGENT_PROBE).hexdigest()
WORKSPACE_PROBE_SHA256 = hashlib.sha256(WORKSPACE_PROBE).hexdigest()
SAFE_RESPONSE_HEADERS = frozenset(
    {
        "cache-control",
        "content-length",
        "content-type",
        "etag",
        "retry-after",
        "x-content-sha256",
        "x-kcs-api-version",
        "x-kcs-snapshot-ref",
        "x-request-id",
    }
)


class JourneyError(RuntimeError):
    """A failed runtime exchange, checkpoint, or acceptance assertion."""


@dataclass(frozen=True, slots=True)
class Timeouts:
    request_seconds: float
    wait_seconds: float
    poll_seconds: float
    checkpoint_wait_seconds: float


@dataclass(frozen=True, slots=True)
class JourneyConfig:
    source: Path
    base_url: str
    ca_file: Path
    api_image: str
    expected_api_version: str
    expected_openapi_sha256: str
    agent_image: str
    workspace_image: str
    runtime_url: str
    node_selector: dict[str, str]
    shared_workspace_size_gib: int
    checkpoint_directory: Path
    timeouts: Timeouts

    @classmethod
    def load(cls, path: Path) -> JourneyConfig:
        try:
            raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as error:
            raise JourneyError("could not read the Journey config") from error
        except yaml.YAMLError as error:
            raise JourneyError("Journey config is not valid YAML") from error
        root = _mapping(raw, "config")
        api = _mapping(root.get("api"), "config.api")
        workloads = _mapping(root.get("workloads"), "config.workloads")
        operator = _mapping(root.get("operator"), "config.operator")
        timeout_values = _mapping(root.get("timeouts"), "config.timeouts")
        expected_root = {"api", "workloads", "operator", "timeouts"}
        if set(root) != expected_root:
            raise JourneyError("Journey config must contain only api/workloads/operator/timeouts")

        base_url = _string(api, "baseUrl", "config.api")
        parsed_base = urlsplit(base_url)
        if (
            parsed_base.scheme != "https"
            or parsed_base.hostname is None
            or parsed_base.username is not None
            or parsed_base.password is not None
            or parsed_base.query
            or parsed_base.fragment
            or parsed_base.path not in {"", "/"}
        ):
            raise JourneyError("api.baseUrl must be a credential-free HTTPS origin")
        api_hostname = parsed_base.hostname.casefold()
        if api_hostname == "localhost" or api_hostname.endswith(".localhost"):
            raise JourneyError("api.baseUrl must name the dedicated non-local KCS server")
        try:
            api_address = ipaddress.ip_address(api_hostname)
        except ValueError:
            pass
        else:
            if any(
                (
                    api_address.is_loopback,
                    api_address.is_unspecified,
                    api_address.is_link_local,
                    api_address.is_multicast,
                    api_address.is_reserved,
                )
            ):
                raise JourneyError("api.baseUrl must name the dedicated non-local KCS server")
        ca_file = _config_path(path, _string(api, "caFile", "config.api"))
        if not ca_file.is_file():
            raise JourneyError("api.caFile must name the operator-provided CA file")
        api_image = _immutable_image(_string(api, "image", "config.api"), "api.image")
        expected_version = _string(api, "expectedVersion", "config.api")
        expected_openapi = _sha256(
            _string(api, "expectedOpenapiSha256", "config.api"),
            "api.expectedOpenapiSha256",
        )
        if set(api) != {
            "baseUrl",
            "caFile",
            "image",
            "expectedVersion",
            "expectedOpenapiSha256",
        }:
            raise JourneyError("config.api has unknown or missing fields")

        agent_image = _immutable_image(
            _string(workloads, "agentImage", "config.workloads"), "workloads.agentImage"
        )
        workspace_image = _immutable_image(
            _string(workloads, "workspaceImage", "config.workloads"),
            "workloads.workspaceImage",
        )
        runtime_url = _runtime_url(_string(workloads, "runtimeUrl", "config.workloads"))
        selector_value = _mapping(workloads.get("nodeSelector"), "workloads.nodeSelector")
        if selector_value != {"researchcosmos.io/pool": "gpu"}:
            raise JourneyError("workloads.nodeSelector must select researchcosmos.io/pool=gpu")
        size_gib = _integer(
            workloads, "sharedWorkspaceSizeGiB", "config.workloads", minimum=1, maximum=100
        )
        if set(workloads) != {
            "agentImage",
            "workspaceImage",
            "runtimeUrl",
            "nodeSelector",
            "sharedWorkspaceSizeGiB",
        }:
            raise JourneyError("config.workloads has unknown or missing fields")

        checkpoint_directory = _config_path(
            path, _string(operator, "checkpointDirectory", "config.operator")
        )
        if set(operator) != {"checkpointDirectory"}:
            raise JourneyError("config.operator has unknown or missing fields")
        timeouts = Timeouts(
            request_seconds=_positive_number(timeout_values, "requestSeconds", "config.timeouts"),
            wait_seconds=_positive_number(timeout_values, "waitSeconds", "config.timeouts"),
            poll_seconds=_positive_number(timeout_values, "pollSeconds", "config.timeouts"),
            checkpoint_wait_seconds=_positive_number(
                timeout_values, "checkpointWaitSeconds", "config.timeouts"
            ),
        )
        if set(timeout_values) != {
            "requestSeconds",
            "waitSeconds",
            "pollSeconds",
            "checkpointWaitSeconds",
        }:
            raise JourneyError("config.timeouts has unknown or missing fields")
        return cls(
            source=path.resolve(),
            base_url=base_url.rstrip("/"),
            ca_file=ca_file,
            api_image=api_image,
            expected_api_version=expected_version,
            expected_openapi_sha256=expected_openapi,
            agent_image=agent_image,
            workspace_image=workspace_image,
            runtime_url=runtime_url,
            node_selector=dict(selector_value),
            shared_workspace_size_gib=size_gib,
            checkpoint_directory=checkpoint_directory,
            timeouts=timeouts,
        )


@dataclass(frozen=True, slots=True)
class Exchange:
    label: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def json_object(self) -> dict[str, Any]:
        try:
            value: Any = json.loads(self.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise JourneyError(f"{self.label}: response is not a JSON object") from error
        if not isinstance(value, dict):
            raise JourneyError(f"{self.label}: response is not a JSON object")
        return value

    def header(self, name: str) -> str | None:
        values = [value for key, value in self.headers if key.casefold() == name.casefold()]
        if len(values) > 1:
            raise JourneyError(f"{self.label}: response repeats {name}")
        return values[0] if values else None


@dataclass(frozen=True, slots=True)
class Binding:
    attempt: str
    provider_request_id: str
    spec_digest: str
    job_ref: str
    job_uid: str
    pod_uid: str
    create_request: dict[str, object]


@dataclass(frozen=True, slots=True)
class StartedGeneration:
    generation: int
    start_request: dict[str, object]
    credential_grant_ref: str
    transfer_ref: str


@dataclass(frozen=True, slots=True)
class Operation:
    operation_ref: str
    request_digest: str
    frame: dict[str, object]
    snapshot: dict[str, Any]


class EvidenceWriter:
    """Write exact response/log/file bytes and sanitized metadata without overwrite."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if self.root.exists() and any(self.root.iterdir()):
            raise JourneyError("evidence directory must be absent or empty")
        self.exchanges = self.root / "exchanges"
        self.logs = self.root / "logs"
        self.artifacts = self.root / "artifacts"
        self.checkpoints = self.root / "checkpoints"
        for directory in (self.exchanges, self.logs, self.artifacts, self.checkpoints):
            directory.mkdir(parents=True, exist_ok=True)
        self._sequence = 0

    def capture_exchange(
        self,
        *,
        label: str,
        method: str,
        path: str,
        request_summary: Mapping[str, object],
        status: int,
        headers: Sequence[tuple[str, str]],
        body: bytes,
    ) -> None:
        self._sequence += 1
        stem = f"{self._sequence:03d}-{_safe_name(label)}"
        body_name = f"{stem}.response.body"
        self.write_bytes(self.exchanges / body_name, body)
        selected: dict[str, list[str]] = {}
        for name, value in headers:
            normalized = name.casefold()
            if normalized in SAFE_RESPONSE_HEADERS:
                selected.setdefault(normalized, []).append(value)
        self.write_json(
            self.exchanges / f"{stem}.exchange.json",
            {
                "capturedAt": _now(),
                "operation": label,
                "request": {"method": method, "path": path, **dict(request_summary)},
                "response": {
                    "status": status,
                    "headers": selected,
                    "rawBodyFile": body_name,
                    "rawBodyBytes": len(body),
                    "rawBodySha256": _bytes_sha256(body),
                },
            },
        )

    def write_log(self, attempt: str, phase: str, role: str, content: str) -> dict[str, object]:
        raw = content.encode("utf-8")
        relative = Path(_safe_name(attempt)) / f"{_safe_name(phase)}-{role}.log"
        target = self.logs / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        self.write_bytes(target, raw)
        return {
            "file": str(Path("logs") / relative),
            "bytes": len(raw),
            "sha256": _bytes_sha256(raw),
        }

    def write_artifact(self, relative: Path, content: bytes) -> dict[str, object]:
        target = self.artifacts / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        self.write_bytes(target, content)
        return {
            "file": str(Path("artifacts") / relative),
            "bytes": len(content),
            "sha256": _bytes_sha256(content),
        }

    def retain_checkpoint(
        self,
        name: str,
        result_bytes: bytes,
        files: Sequence[Path],
    ) -> list[dict[str, object]]:
        directory = self.checkpoints / name
        directory.mkdir(parents=True, exist_ok=True)
        self.write_bytes(directory / "result.json", result_bytes)
        retained: list[dict[str, object]] = []
        for index, source in enumerate(files, start=1):
            if not source.is_file() or source.is_symlink():
                raise JourneyError(f"checkpoint {name}: evidence file is absent or a symlink")
            destination = directory / f"{index:02d}-{_safe_name(source.name)}"
            try:
                with source.open("rb") as input_stream, destination.open("xb") as output_stream:
                    shutil.copyfileobj(input_stream, output_stream)
            except OSError as error:
                raise JourneyError(f"checkpoint {name}: could not retain evidence file") from error
            content = destination.read_bytes()
            retained.append(
                {
                    "file": str(destination.relative_to(self.root)),
                    "bytes": len(content),
                    "sha256": _bytes_sha256(content),
                }
            )
        self.write_json(directory / "index.json", {"checkpoint": name, "files": retained})
        return retained

    def write_summary(self, value: Mapping[str, object]) -> None:
        self.write_json(self.root / "summary.json", value)

    def write_manifest(self) -> None:
        entries: list[dict[str, object]] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and path.name != "manifest.sha256.json":
                content = path.read_bytes()
                entries.append(
                    {
                        "path": str(path.relative_to(self.root)),
                        "bytes": len(content),
                        "sha256": _bytes_sha256(content),
                    }
                )
        self.write_json(
            self.root / "manifest.sha256.json",
            {"algorithm": "sha256", "generatedAt": _now(), "files": entries},
        )

    @staticmethod
    def write_bytes(path: Path, content: bytes) -> None:
        try:
            with path.open("xb") as stream:
                stream.write(content)
        except FileExistsError as error:
            raise JourneyError(f"evidence file already exists: {path}") from error
        except OSError as error:
            raise JourneyError(f"could not write evidence file: {path}") from error

    @classmethod
    def write_json(cls, path: Path, value: Mapping[str, object]) -> None:
        cls.write_bytes(path, _pretty_json(value))


class KcsV2Client:
    """No-redirect HTTPS client with an explicit CA and hidden bearer token."""

    def __init__(
        self,
        config: JourneyConfig,
        token: str,
        evidence: EvidenceWriter,
    ) -> None:
        parsed = urlsplit(config.base_url)
        assert parsed.hostname is not None
        self._host = parsed.hostname
        self._port = parsed.port
        self._token = token
        self._timeout = config.timeouts.request_seconds
        try:
            self._tls_context = ssl.create_default_context(cafile=str(config.ca_file))
        except (OSError, ssl.SSLError) as error:
            raise JourneyError("could not load api.caFile") from error
        self._evidence = evidence

    def request(
        self,
        *,
        label: str,
        method: str,
        path: str,
        query: Mapping[str, str] | None = None,
        json_body: Mapping[str, object] | None = None,
        raw_body: bytes | None = None,
        content_type: str | None = None,
        headers: Mapping[str, str] | None = None,
        authenticated: bool = True,
        sensitive_body: bool = False,
    ) -> Exchange:
        if json_body is not None and raw_body is not None:
            raise JourneyError(f"{label}: request cannot have JSON and raw bodies")
        target = path if not query else f"{path}?{urlencode(query)}"
        request_headers = {"Accept": "application/json"}
        if authenticated:
            request_headers["Authorization"] = f"Bearer {self._token}"
        body: bytes | None = None
        request_summary: dict[str, object] = {}
        if json_body is not None:
            body = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode()
            request_headers["Content-Type"] = "application/json"
            request_summary["jsonBody"] = dict(json_body)
        elif raw_body is not None:
            body = raw_body
            request_headers["Content-Type"] = content_type or "application/octet-stream"
            request_headers["Content-Length"] = str(len(raw_body))
            request_summary["rawBody"] = {
                "bytes": len(raw_body),
                "sha256": _bytes_sha256(raw_body),
                "redacted": sensitive_body,
            }
        if headers:
            request_headers.update(headers)
        safe_request_headers = {
            name: value
            for name, value in request_headers.items()
            if name.casefold() not in {"authorization"}
        }
        request_summary["headers"] = safe_request_headers

        connection = http.client.HTTPSConnection(
            self._host,
            self._port,
            timeout=self._timeout,
            context=self._tls_context,
        )
        try:
            connection.request(method, target, body=body, headers=request_headers)
            response = connection.getresponse()
            response_body = response.read()
            response_headers = tuple(response.getheaders())
            status = response.status
        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            raise JourneyError(
                f"{label}: HTTPS transport failed ({type(error).__name__})"
            ) from error
        finally:
            connection.close()
        self._evidence.capture_exchange(
            label=label,
            method=method,
            path=target,
            request_summary=request_summary,
            status=status,
            headers=response_headers,
            body=response_body,
        )
        return Exchange(label, status, response_headers, response_body)


class OperatorCheckpoints:
    """File handshake for real Kubernetes evidence, never an executable hook."""

    def __init__(self, config: JourneyConfig, evidence: EvidenceWriter) -> None:
        self._root = config.checkpoint_directory
        self._root.mkdir(parents=True, exist_ok=True)
        self._wait_seconds = config.timeouts.checkpoint_wait_seconds
        self._poll_seconds = config.timeouts.poll_seconds
        self._evidence = evidence

    def wait(
        self,
        name: str,
        *,
        expected: Mapping[str, object],
        required_facts: Sequence[str],
        instructions: Sequence[str],
        validator: Callable[[Mapping[str, object]], None] | None = None,
    ) -> dict[str, Any]:
        if not CHECKPOINT_PATTERN.fullmatch(name):
            raise JourneyError("invalid operator checkpoint name")
        request_path = self._root / f"{name}.request.json"
        result_path = self._root / f"{name}.result.json"
        request_body = {
            "checkpoint": name,
            "createdAt": _now(),
            "expected": dict(expected),
            "requiredFacts": list(required_facts),
            "instructions": list(instructions),
            "resultFile": result_path.name,
            "forbidden": [
                "Kubernetes Secret .data",
                "bearer tokens or credentials",
                "replacement of the expected UID",
            ],
        }
        request_bytes = _pretty_json(request_body)
        EvidenceWriter.write_bytes(request_path, request_bytes)
        retained_request = self._evidence.checkpoints / name / "request.json"
        retained_request.parent.mkdir(parents=True, exist_ok=True)
        EvidenceWriter.write_bytes(retained_request, request_bytes)
        request_sha = _bytes_sha256(request_bytes)
        print(f"operator checkpoint {name}: complete {request_path} -> {result_path}")
        deadline = time.monotonic() + self._wait_seconds
        while not result_path.is_file():
            if time.monotonic() >= deadline:
                raise JourneyError(f"operator checkpoint {name}: timed out")
            time.sleep(self._poll_seconds)
        try:
            result_bytes = result_path.read_bytes()
            raw: Any = json.loads(result_bytes)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise JourneyError(f"operator checkpoint {name}: invalid result JSON") from error
        result = _mapping(raw, f"checkpoint {name} result")
        if (
            result.get("checkpoint") != name
            or result.get("requestSha256") != request_sha
            or result.get("status") != "passed"
            or not isinstance(result.get("completedAt"), str)
            or not _valid_timestamp(str(result.get("completedAt")))
        ):
            raise JourneyError(f"operator checkpoint {name}: result identity/status mismatch")
        observed = _mapping(result.get("observed"), f"checkpoint {name}.observed")
        _require_subset(expected, observed, f"checkpoint {name}.observed")
        facts = _mapping(result.get("facts"), f"checkpoint {name}.facts")
        for fact in required_facts:
            if facts.get(fact) is not True:
                raise JourneyError(f"operator checkpoint {name}: fact {fact} is not true")
        evidence_names = result.get("evidenceFiles")
        if not isinstance(evidence_names, list) or not evidence_names:
            raise JourneyError(f"operator checkpoint {name}: evidenceFiles must be non-empty")
        evidence_files: list[Path] = []
        for value in evidence_names:
            if not isinstance(value, str) or not value or Path(value).is_absolute():
                raise JourneyError(f"operator checkpoint {name}: unsafe evidence file name")
            resolved = (self._root / value).resolve()
            try:
                resolved.relative_to(self._root.resolve())
            except ValueError as error:
                raise JourneyError(
                    f"operator checkpoint {name}: evidence escapes directory"
                ) from error
            evidence_files.append(resolved)
        if validator is not None:
            validator(result)
        self._evidence.retain_checkpoint(name, result_bytes, evidence_files)
        return dict(result)


class AttemptJourney:
    """One evidence session containing normal, cancel, and Pod-loss terminal branches."""

    def __init__(
        self,
        config: JourneyConfig,
        client: KcsV2Client,
        evidence: EvidenceWriter,
        checkpoints: OperatorCheckpoints,
        service_token: str,
    ) -> None:
        self.config = config
        self.client = client
        self.evidence = evidence
        self.checkpoints = checkpoints
        self.service_token = service_token.encode()
        self.session = uuid.uuid4().hex[:16]
        self.credentials: list[bytes] = []
        self.deleted: list[dict[str, object]] = []

    def run(self) -> dict[str, object]:
        contract = self._verify_contract()
        baseline = self.checkpoints.wait(
            "o0-deployment-baseline",
            expected={
                "apiImage": self.config.api_image,
                "agentImage": self.config.agent_image,
                "workspaceImage": self.config.workspace_image,
                "nodeSelector": self.config.node_selector,
            },
            required_facts=(
                "twoNodesReady",
                "gpuWorkerLabeled",
                "gpuAllocatableObserved",
                "apiImageDigestMatched",
                "legacyRbacDenied",
                "debugProxyDenied",
                "protectedPortsPrivate",
                "resourceBaselineCaptured",
                "secretMetadataOnly",
            ),
            instructions=(
                "Capture Ready nodes/InternalIP, GPU allocatable, imageID and initial resources.",
                "Capture legacy auth can-i denials, proxy denial, listeners and firewall/overlay.",
                "Read Secret metadata only; never read Secret .data.",
            ),
        )
        normal = self._attempt_normal()
        canceled = self._attempt_cancel()
        pod_loss = self._attempt_pod_loss()
        final = self.checkpoints.wait(
            "o2-final-resource-baseline",
            expected={
                "deletedJobRefs": [item["jobRef"] for item in self.deleted],
                "deleteRefs": [item["deleteRef"] for item in self.deleted],
            },
            required_facts=(
                "managedRuntimeAtBaseline",
                "gpuAtBaseline",
                "apiHealthy",
                "onlyExpectedTombstonesRemain",
                "rawLogsRead",
                "secretMetadataOnly",
            ),
            instructions=(
                "Capture final Job/Pod/runtime ConfigMap/Secret metadata and GPU allocation.",
                "Allow only the expected retained create tombstones; API Deployment stays healthy.",
                "Actually read the retained raw agent/workspace/API logs before setting "
                "rawLogsRead.",
            ),
        )
        summary: dict[str, object] = {
            "evidenceFormatVersion": 2,
            "sessionRef": self.session,
            "result": "passed",
            "completedAt": _now(),
            "contract": contract,
            "operatorBaseline": _checkpoint_summary(baseline),
            "attempts": {"normal": normal, "cancel": canceled, "podLoss": pod_loss},
            "operatorFinal": _checkpoint_summary(final),
            "statement": (
                "This session used the deployed HTTPS API plus operator-supplied dedicated-server "
                "Kubernetes evidence; it is not local KCS/k3s evidence."
            ),
        }
        scan = self._secret_scan()
        if scan["totalHits"] != 0:
            raise JourneyError("secret scan found prohibited values; see count-only report")
        self.evidence.write_summary(summary)
        self.evidence.write_manifest()
        return summary

    def _verify_contract(self) -> dict[str, object]:
        unauthorized = self.client.request(
            label="contract-unauthenticated",
            method="GET",
            path="/api/v2/openapi.json",
            authenticated=False,
        )
        _expect_status(unauthorized, 401)
        authorized = self.client.request(
            label="contract-canonical",
            method="GET",
            path="/api/v2/openapi.json",
        )
        _expect_status(authorized, 200)
        digest = _bytes_sha256(authorized.body)
        if not hmac.compare_digest(digest, self.config.expected_openapi_sha256):
            raise JourneyError("contract-canonical: exact OpenAPI digest differs")
        if authorized.header("ETag") != digest:
            raise JourneyError("contract-canonical: ETag differs from exact response digest")
        if authorized.header("X-KCS-API-Version") != self.config.expected_api_version:
            raise JourneyError("contract-canonical: API version differs")
        return {
            "apiVersion": self.config.expected_api_version,
            "openapiSha256": digest,
            "unauthenticatedStatus": unauthorized.status,
        }

    def _attempt_normal(self) -> dict[str, object]:
        binding = self._create_attempt("attempt-a-normal")
        material = b"kcs-v2-stage-input\n"
        material_path = "attempt-a/generation-1/material.txt"
        material_ref = self._stage(binding, material_path, material, "a-material")

        generation_one = self._start_generation(
            binding,
            generation=1,
            action={"protocol": "kcs.conformance/1", "action": "sharedWrite"},
            material_paths=[material_path],
        )
        shared_read = self._invoke(
            binding,
            "a-read-agent",
            {"protocol": "cosmos.workspace/1", "action": "sharedRead", "sourceRole": "agent"},
            replay=True,
            conflict=True,
        )
        _expect_inline_probe(shared_read.snapshot, "workspace_shared_read", AGENT_PROBE_SHA256, 26)
        before_restart_log = self._role_logs(binding, "before-restart", "workspace")
        if _event_count(before_restart_log, "workspace_shared_read") != 1:
            raise JourneyError("attempt A: sharedRead side effect count before restart is not one")

        restart = self.checkpoints.wait(
            "o1-api-restart",
            expected={
                "jobRef": binding.job_ref,
                "jobUid": binding.job_uid,
                "attemptPodUid": binding.pod_uid,
            },
            required_facts=(
                "apiPodUidChanged",
                "attemptPodUidUnchanged",
                "apiLogsCaptured",
                "workloadShapeMatched",
                "workloadImageDigestsMatched",
                "debugProxyDeniedForAttempt",
                "secretMetadataOnly",
            ),
            instructions=(
                "Capture the old API Pod UID, restart deployment/kcs-v2-api, wait Ready, "
                "capture the new UID.",
                "Set facts.oldApiPodUid and facts.newApiPodUid to those exact different UID "
                "strings in addition to the required boolean facts.",
                "Capture both API Pod logs and Job/Pod YAML; verify one Pod/two roles/shared "
                "emptyDir, GPU only on workspace, tokenless workload SA, and exact imageIDs.",
                "Prove the real legacy debug identity cannot exec the bound Attempt Pod.",
            ),
            validator=_validate_restart_checkpoint,
        )
        replay = self.client.request(
            label="a-create-replay-after-api-restart",
            method="POST",
            path="/api/v2/jobs",
            json_body=binding.create_request,
        )
        _expect_status(replay, 200)
        _expect_binding(replay.json_object(), binding, "create replay after API restart")
        self._inspect_same_binding(binding, "a-inspect-after-api-restart")
        retained_material = self._inspect_transfer(
            binding, material_ref, "a-material-after-api-restart"
        )
        _expect_completed_transfer(retained_material, binding, material_ref, material)
        retained_operation = self._inspect_operation(
            binding, shared_read.operation_ref, "a-operation-after-api-restart"
        )
        _expect_succeeded_operation(
            retained_operation,
            binding,
            shared_read.operation_ref,
            shared_read.request_digest,
            "a-operation-after-api-restart",
            retained=shared_read.snapshot,
        )
        retained_grant = self._inspect_grant(
            binding, generation_one.credential_grant_ref, "a-grant-after-api-restart"
        )
        if (
            retained_grant.get("state") != "destroyed"
            or retained_grant.get("secretPresent") is not False
        ):
            raise JourneyError("attempt A: generation credential changed after API restart")
        start_replay = self._request_same_until(
            label="a-start-replay-after-api-restart",
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/agent/start",
            json_body=generation_one.start_request,
            success_statuses={200},
        )
        _expect_generation_snapshot(
            start_replay.json_object(),
            binding,
            generation_one.start_request,
            replayed=True,
            label="a-start-replay-after-api-restart",
        )
        invoke_replay = self._invoke_existing(binding, shared_read, "a-invoke-replay-after-restart")
        _expect_status(invoke_replay, 200)
        _expect_succeeded_operation(
            invoke_replay.json_object(),
            binding,
            shared_read.operation_ref,
            shared_read.request_digest,
            "a-invoke-replay-after-restart",
            retained=shared_read.snapshot,
        )
        after_restart_log = self._role_logs(binding, "after-restart", "workspace")
        if _event_count(after_restart_log, "workspace_shared_read") != 1:
            raise JourneyError("attempt A: operation replay repeated its side effect")

        workspace_write = self._invoke(
            binding,
            "a-workspace-write",
            {"protocol": "cosmos.workspace/1", "action": "sharedWrite"},
        )
        _expect_inline_probe(
            workspace_write.snapshot, "workspace_shared_write", WORKSPACE_PROBE_SHA256, 30
        )
        self._start_generation(
            binding,
            generation=2,
            action={
                "protocol": "kcs.conformance/1",
                "action": "sharedRead",
                "sourceRole": "workspace",
            },
        )
        self._start_generation(
            binding,
            generation=3,
            action={"protocol": "kcs.conformance/1", "action": "observeNoGpu"},
        )
        gpu = self._invoke(
            binding,
            "a-observe-gpu",
            {"protocol": "cosmos.workspace/1", "action": "observeGpu"},
        )
        gpu_result = _inline_result(gpu.snapshot, "attempt A workspace GPU")
        if (
            gpu_result.get("event") != "workspace_gpu_observation"
            or gpu_result.get("ok") is not True
            or not isinstance(gpu_result.get("gpuCount"), int)
            or int(gpu_result["gpuCount"]) < 1
        ):
            raise JourneyError("attempt A: workspace did not prove real nvidia-smi GPU access")
        self._start_generation(
            binding,
            generation=4,
            action={"protocol": "kcs.conformance/1", "action": "probeRuntimeUrl"},
        )
        agent_log = self._role_logs(binding, "after-generations", "agent")
        workspace_log = self._role_logs(binding, "after-generations", "workspace")
        _expect_log_event(agent_log, "agent_shared_write", AGENT_PROBE_SHA256)
        _expect_log_event(agent_log, "agent_shared_read", WORKSPACE_PROBE_SHA256)
        no_gpu = _single_log_event(agent_log, "agent_gpu_observation")
        if no_gpu.get("ok") is not True or no_gpu.get("gpuDeviceCount") != 0:
            raise JourneyError("attempt A: agent role observed a GPU")
        runtime = _single_log_event(agent_log, "runtime_url_observation")
        if runtime.get("ok") is not True or runtime.get("scheme") not in {"http", "https"}:
            raise JourneyError("attempt A: external runtime URL was not reachable")
        if _event_count(workspace_log, "workspace_shared_read") != 1:
            raise JourneyError("attempt A: sharedRead side effect count changed")

        collect_ref = self._register_collect(
            binding,
            path=".kcs-conformance/workspace.probe",
            content=WORKSPACE_PROBE,
            label="a-collect-workspace-probe",
        )
        collected, snapshot_ref = self._collect(binding, collect_ref, "a-collect-workspace-probe")
        if collected != WORKSPACE_PROBE:
            raise JourneyError("attempt A: collected workspace probe bytes differ")
        transfer_snapshot = self._inspect_transfer(
            binding, collect_ref, "a-collect-workspace-probe-inspect"
        )
        _expect_completed_transfer(transfer_snapshot, binding, collect_ref, collected)
        if transfer_snapshot.get("snapshotRef") != snapshot_ref:
            raise JourneyError("attempt A: collect header and transfer snapshot identity differ")
        collected_replay, replay_snapshot_ref = self._collect(
            binding, collect_ref, "a-collect-workspace-probe-replay"
        )
        if collected_replay != collected or replay_snapshot_ref != snapshot_ref:
            raise JourneyError("attempt A: collect replay bytes or snapshot identity differ")

        finalize_spec: dict[str, object] = {
            "operationRefs": [
                shared_read.operation_ref,
                workspace_write.operation_ref,
                gpu.operation_ref,
            ],
            "transferRefs": [collect_ref],
            "drainTimeoutSeconds": 300,
        }
        finalize_body = {
            "finalizeRef": self._ref("a-finalize"),
            "requestDigest": _digest(finalize_spec),
            "spec": finalize_spec,
        }
        finalized = self._new_and_replay_action(
            binding,
            label="a-finalize",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/finalize",
            body=finalize_body,
            action_field="finalizeAction",
            action_ref=_string(finalize_body, "finalizeRef", "finalize request"),
            request_digest=_string(finalize_body, "requestDigest", "finalize request"),
        )
        if (
            finalized.get("bindingState") != "succeeded"
            or finalized.get("outputLossPossible") is not False
        ):
            raise JourneyError("attempt A: finalize did not retain an honest succeeded snapshot")
        _expect_roles_terminal(finalized, "attempt A finalize")
        finalized_operation = self._inspect_operation(
            binding, shared_read.operation_ref, "a-operation-after-finalize"
        )
        _expect_succeeded_operation(
            finalized_operation,
            binding,
            shared_read.operation_ref,
            shared_read.request_digest,
            "a-operation-after-finalize",
            retained=shared_read.snapshot,
        )
        finalized_transfer = self._inspect_transfer(
            binding, collect_ref, "a-collect-after-finalize"
        )
        _expect_completed_transfer(finalized_transfer, binding, collect_ref, collected)
        if finalized_transfer.get("snapshotRef") != snapshot_ref:
            raise JourneyError("attempt A: finalized collect snapshot identity changed")
        terminal_agent_log = self._role_logs(
            binding, "after-finalize", "agent", require_terminal=True
        )
        terminal_workspace_log = self._role_logs(
            binding, "after-finalize", "workspace", require_terminal=True
        )
        _expect_log_event(terminal_agent_log, "agent_shared_write", AGENT_PROBE_SHA256)
        _expect_log_event(terminal_agent_log, "agent_shared_read", WORKSPACE_PROBE_SHA256)
        _expect_log_event(terminal_workspace_log, "workspace_shared_write", WORKSPACE_PROBE_SHA256)
        if _event_count(terminal_workspace_log, "workspace_shared_read") != 1:
            raise JourneyError("attempt A: terminal logs changed sharedRead side-effect count")
        terminal = self.checkpoints.wait(
            "o2-attempt-a-finalized",
            expected={
                "jobRef": binding.job_ref,
                "jobUid": binding.job_uid,
                "podUid": binding.pod_uid,
            },
            required_facts=(
                "attemptTerminalRetained",
                "rolesTerminated",
                "runtimeOwnerReferencesCaptured",
                "credentialSecretsAbsent",
                "gpuAtBaseline",
                "secretMetadataOnly",
            ),
            instructions=(
                "Capture retained Job/Pod and runtime ConfigMap metadata/ownerReferences.",
                "Capture credential Secret absence and GPU release; never read Secret .data.",
            ),
        )
        tombstone = self._delete(binding, "a-delete", expected_final_state="succeeded")
        return {
            "binding": _binding_summary(binding),
            "restart": _checkpoint_summary(restart),
            "terminal": _checkpoint_summary(terminal),
            "finalizeRef": finalize_body["finalizeRef"],
            "collectRef": collect_ref,
            "delete": tombstone,
        }

    def _attempt_cancel(self) -> dict[str, object]:
        binding = self._create_attempt("attempt-b-cancel")
        operation = self._invoke(
            binding,
            "b-workspace-write",
            {"protocol": "cosmos.workspace/1", "action": "sharedWrite"},
        )
        collect_ref = self._register_collect(
            binding,
            path=".kcs-conformance/workspace.probe",
            content=WORKSPACE_PROBE,
            label="b-uncollected-workspace-probe",
        )
        unused_grant_ref = self._grant_only(binding, "b-unused-grant", generation=1)
        cancel_spec: dict[str, object] = {
            "finishCollectTransferRefs": [],
            "reason": "provider-interrupt-conformance",
        }
        cancel_body = {
            "cancelRef": self._ref("b-cancel"),
            "requestDigest": _digest(cancel_spec),
            "spec": cancel_spec,
        }
        canceled = self._new_and_replay_action(
            binding,
            label="b-cancel",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/cancel",
            body=cancel_body,
            action_field="cancelAction",
            action_ref=_string(cancel_body, "cancelRef", "cancel request"),
            request_digest=_string(cancel_body, "requestDigest", "cancel request"),
        )
        if (
            canceled.get("bindingState") != "canceled"
            or canceled.get("outputLossPossible") is not True
        ):
            raise JourneyError("attempt B: cancel did not report possible uncollected output loss")
        _expect_roles_terminal(canceled, "attempt B cancel")
        grant = self._inspect_grant(binding, unused_grant_ref, "b-grant-after-cancel")
        if (
            grant.get("state") not in {"revoked", "destroyed"}
            or grant.get("secretPresent") is not False
        ):
            raise JourneyError("attempt B: active credential was not revoked and destroyed")
        transfer = self._inspect_transfer(binding, collect_ref, "b-transfer-after-cancel")
        _expect_registered_collect(
            transfer,
            binding,
            collect_ref,
            path=".kcs-conformance/workspace.probe",
            content=WORKSPACE_PROBE,
        )
        canceled_operation = self._inspect_operation(
            binding, operation.operation_ref, "b-operation-after-cancel"
        )
        _expect_succeeded_operation(
            canceled_operation,
            binding,
            operation.operation_ref,
            operation.request_digest,
            "b-operation-after-cancel",
            retained=operation.snapshot,
        )
        self._role_logs(binding, "after-cancel", "agent", require_terminal=True)
        canceled_workspace_log = self._role_logs(
            binding, "after-cancel", "workspace", require_terminal=True
        )
        _expect_log_event(canceled_workspace_log, "workspace_shared_write", WORKSPACE_PROBE_SHA256)
        terminal = self.checkpoints.wait(
            "o2-attempt-b-canceled",
            expected={
                "jobRef": binding.job_ref,
                "jobUid": binding.job_uid,
                "podUid": binding.pod_uid,
            },
            required_facts=(
                "attemptTerminalRetained",
                "rolesTerminated",
                "credentialSecretsAbsent",
                "gpuAtBaseline",
                "secretMetadataOnly",
            ),
            instructions=(
                "Capture retained canceled Pod/log reality and uncollected transfer metadata.",
                "Capture credential Secret absence and GPU release; never read Secret .data.",
            ),
        )
        tombstone = self._delete(binding, "b-delete", expected_final_state="canceled")
        return {
            "binding": _binding_summary(binding),
            "cancelRef": cancel_body["cancelRef"],
            "uncollectedTransferRef": collect_ref,
            "outputLossPossible": True,
            "terminal": _checkpoint_summary(terminal),
            "delete": tombstone,
        }

    def _attempt_pod_loss(self) -> dict[str, object]:
        binding = self._create_attempt("attempt-c-pod-loss")
        checkpoint = self.checkpoints.wait(
            "o3-attempt-c-pod-delete",
            expected={
                "jobRef": binding.job_ref,
                "jobUid": binding.job_uid,
                "podUid": binding.pod_uid,
            },
            required_facts=(
                "uidPreconditionApplied",
                "podMissingOrReplacementObserved",
                "retainedBindingNotAdopted",
                "secretMetadataOnly",
            ),
            instructions=(
                "Delete only the bound Pod using DeleteOptions.preconditions.uid equal to podUid.",
                "Capture the raw deletion response and missing/replacement Pod YAML/UID reality.",
            ),
            validator=_validate_pod_delete_checkpoint,
        )
        deadline = time.monotonic() + self.config.timeouts.wait_seconds
        snapshot: dict[str, Any]
        attempt = 0
        while True:
            attempt += 1
            inspected = self.client.request(
                label=f"c-inspect-indeterminate-{attempt:02d}",
                method="GET",
                path=f"/api/v2/jobs/{_q(binding.job_ref)}",
            )
            _expect_status(inspected, 200)
            snapshot = inspected.json_object()
            if snapshot.get("bindingState") == "indeterminate":
                break
            if time.monotonic() >= deadline:
                raise JourneyError("attempt C: timed out waiting for indeterminate binding")
            time.sleep(self.config.timeouts.poll_seconds)
        if snapshot.get("jobUid") != binding.job_uid or snapshot.get("podUid") != binding.pod_uid:
            raise JourneyError("attempt C: KCS adopted a replacement Job/Pod UID")
        create_replay = self.client.request(
            label="c-create-replay-after-pod-loss",
            method="POST",
            path="/api/v2/jobs",
            json_body=binding.create_request,
        )
        _expect_status(create_replay, 200)
        replay_body = create_replay.json_object()
        if (
            replay_body.get("jobUid") != binding.job_uid
            or replay_body.get("podUid") != binding.pod_uid
        ):
            raise JourneyError("attempt C: create replay adopted replacement identity")
        blocked_ref = self._ref("c-blocked-operation")
        frame: dict[str, object] = {"protocol": "cosmos.workspace/1", "action": "sharedWrite"}
        blocked = self.client.request(
            label="c-invoke-after-pod-loss",
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/workspace/invoke",
            json_body=frame,
            headers={
                "KCS-Operation-Ref": blocked_ref,
                "KCS-Request-Digest": _digest(frame),
                "KCS-Job-UID": binding.job_uid,
                "KCS-Pod-UID": binding.pod_uid,
            },
        )
        _expect_status(blocked, 409)
        _expect_error_code(blocked, {"REPLACEMENT_POD", "STALE_BINDING"})
        absent = self.client.request(
            label="c-inspect-blocked-operation",
            method="GET",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/operations/{_q(blocked_ref)}",
        )
        _expect_status(absent, 404)
        tombstone = self._delete(binding, "c-delete", expected_final_state="indeterminate")
        return {
            "binding": _binding_summary(binding),
            "operatorPodDelete": _checkpoint_summary(checkpoint),
            "bindingState": "indeterminate",
            "blockedOperationRef": blocked_ref,
            "delete": tombstone,
        }

    def _create_attempt(self, attempt: str) -> Binding:
        provider_request_id = self._ref(attempt)
        spec: dict[str, object] = {
            "subjectRef": self._ref(f"{attempt}-subject"),
            "runtimePlanDigest": _digest(
                {"protocol": "kcs.conformance/1", "session": self.session, "attempt": attempt}
            ),
            "agent": {
                "image": self.config.agent_image,
                "command": ["/opt/kcs/agent-supervisor"],
                "resources": {"cpuMillis": 1000, "memoryMiB": 2048},
                "runtimeEnv": {
                    "LANG": "C.UTF-8",
                    "RC_PUBLIC_RUNTIME_BASE_URL": self.config.runtime_url,
                },
            },
            "workspace": {
                "image": self.config.workspace_image,
                "command": ["/opt/kcs/workspace-sidecar"],
                "resources": {"cpuMillis": 2000, "memoryMiB": 8192, "gpu": 1},
                "runtimeEnv": {
                    "TZ": "UTC",
                    "RC_PUBLIC_RUNTIME_BASE_URL": self.config.runtime_url,
                },
            },
            "sharedWorkspace": {
                "kind": "ephemeral",
                "mountPath": "/workspace",
                "sizeLimitGiB": self.config.shared_workspace_size_gib,
            },
            "nodeSelector": self.config.node_selector,
            "activeDeadlineSeconds": 21600,
        }
        request: dict[str, object] = {
            "providerRequestId": provider_request_id,
            "specDigest": _digest(spec),
            "spec": spec,
        }
        created = self.client.request(
            label=f"{attempt}-create",
            method="POST",
            path="/api/v2/jobs",
            json_body=request,
        )
        _expect_status(created, 201)
        created_body = created.json_object()
        replayed = self.client.request(
            label=f"{attempt}-create-replay",
            method="POST",
            path="/api/v2/jobs",
            json_body=request,
        )
        _expect_status(replayed, 200)
        deadline = time.monotonic() + self.config.timeouts.wait_seconds
        count = 0
        while True:
            count += 1
            inspected = self.client.request(
                label=f"{attempt}-inspect-ready-{count:02d}",
                method="GET",
                path=f"/api/v2/jobs/{_q(_string(created_body, 'jobRef', 'create response'))}",
            )
            _expect_status(inspected, 200)
            body = inspected.json_object()
            if _binding_ready(body):
                break
            if time.monotonic() >= deadline:
                raise JourneyError(f"{attempt}: timed out waiting for one Ready two-role Pod")
            time.sleep(self.config.timeouts.poll_seconds)
        binding = Binding(
            attempt=attempt,
            provider_request_id=provider_request_id,
            spec_digest=_string(request, "specDigest", "create request"),
            job_ref=_string(body, "jobRef", "inspect response"),
            job_uid=_string(body, "jobUid", "inspect response"),
            pod_uid=_string(body, "podUid", "inspect response"),
            create_request=request,
        )
        _expect_binding(created_body, binding, "create", allow_unbound_pod_uid=True)
        _expect_binding(
            replayed.json_object(), binding, "create replay", allow_unbound_pod_uid=True
        )
        _expect_binding(body, binding, "inspect ready")
        return binding

    def _stage(self, binding: Binding, path: str, content: bytes, label: str) -> str:
        transfer_ref = self._ref(f"{label}-stage")
        spec: dict[str, object] = {
            "direction": "stage_input",
            "path": path,
            "declaredSizeBytes": len(content),
            "authorizedMaxSizeBytes": len(content),
            "contentSha256": _bytes_sha256(content),
            "mode": "direct",
            "overwritePolicy": "forbid",
        }
        request = {
            "transferRef": transfer_ref,
            "requestDigest": _digest(spec),
            "spec": spec,
        }
        registered = self.client.request(
            label=f"{label}-register",
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/transfers",
            json_body=request,
        )
        _expect_status(registered, 201)
        replay = self.client.request(
            label=f"{label}-register-replay",
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/transfers",
            json_body=request,
        )
        _expect_status(replay, 200)
        artifact_name = Path(binding.attempt) / f"{_safe_name(label)}.stage"
        self.evidence.write_artifact(artifact_name, content)
        for suffix in ("content", "content-replay"):
            completed = self.client.request(
                label=f"{label}-{suffix}",
                method="PUT",
                path=f"/api/v2/jobs/{_q(binding.job_ref)}/transfers/{_q(transfer_ref)}/content",
                raw_body=content,
                headers={"KCS-Content-SHA256": _bytes_sha256(content)},
            )
            _expect_status(completed, 200)
            _expect_completed_transfer(completed.json_object(), binding, transfer_ref, content)
        inspected = self._inspect_transfer(binding, transfer_ref, f"{label}-inspect")
        _expect_completed_transfer(inspected, binding, transfer_ref, content)
        return transfer_ref

    def _start_generation(
        self,
        binding: Binding,
        *,
        generation: int,
        action: Mapping[str, object],
        material_paths: Sequence[str] = (),
    ) -> StartedGeneration:
        launch = rfc8785.dumps(cast(Any, dict(action)))
        launch_path = f"{binding.attempt}/generation-{generation}/launch.json"
        transfer_ref = self._stage(
            binding,
            launch_path,
            launch,
            f"{binding.attempt}-generation-{generation}-launch",
        )
        grant_ref = self._grant_only(
            binding,
            f"{binding.attempt}-generation-{generation}",
            generation=generation,
            launch_digest=_bytes_sha256(launch),
        )
        start_request: dict[str, object] = {
            "executionEnvelopeRef": self._ref(f"{binding.attempt}-envelope-{generation}"),
            "executionEnvelopeDigest": _digest(
                {"attempt": binding.attempt, "generation": generation, "action": dict(action)}
            ),
            "agentRunRef": self._ref(f"{binding.attempt}-run-{generation}"),
            "generation": generation,
            "launchBundlePath": launch_path,
            "launchBundleDigest": _bytes_sha256(launch),
            "launchBundleSizeBytes": len(launch),
            "materialPaths": list(material_paths),
            "credentialGrantRef": grant_ref,
        }
        started = self._request_same_until(
            label=f"{binding.attempt}-start-{generation}",
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/agent/start",
            json_body=start_request,
            success_statuses={200, 202},
        )
        started_body = started.json_object()
        _expect_generation_snapshot(
            started_body,
            binding,
            start_request,
            replayed=started.status == 200,
            label=f"{binding.attempt}-start-{generation}",
        )
        replay = self._request_same_until(
            label=f"{binding.attempt}-start-{generation}-replay",
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/agent/start",
            json_body=start_request,
            success_statuses={200},
        )
        _expect_generation_snapshot(
            replay.json_object(),
            binding,
            start_request,
            replayed=True,
            label=f"{binding.attempt}-start-{generation}-replay",
        )
        grant = self._inspect_grant(
            binding, grant_ref, f"{binding.attempt}-grant-{generation}-destroyed"
        )
        if grant.get("state") != "destroyed" or grant.get("secretPresent") is not False:
            raise JourneyError(f"{binding.attempt}: generation credential was not destroyed")
        return StartedGeneration(generation, start_request, grant_ref, transfer_ref)

    def _grant_only(
        self,
        binding: Binding,
        label: str,
        *,
        generation: int,
        launch_digest: str | None = None,
    ) -> str:
        credential = f"kcs-v2-credential-{secrets.token_hex(32)}".encode()
        self.credentials.append(credential)
        credential_sha = _bytes_sha256(credential)
        grant_ref = self._ref(f"{label}-grant")
        launch_sha = launch_digest or _bytes_sha256(
            rfc8785.dumps({"protocol": "kcs.conformance/1", "action": "sharedWrite"})
        )
        agent_run_ref = self._ref(f"{binding.attempt}-run-{generation}")
        audience = "kcs-conformance-agent"
        metadata: dict[str, object] = {
            "agentRunRef": agent_run_ref,
            "generation": generation,
            "launchBundleDigest": launch_sha,
            "audience": audience,
            "credentialSha256": credential_sha,
            "ttlSeconds": 300,
            "jobUid": binding.job_uid,
            "podUid": binding.pod_uid,
        }
        granted = self.client.request(
            label=f"{label}-grant",
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/agent/credential-grants",
            raw_body=credential,
            sensitive_body=True,
            headers={
                "KCS-Credential-Grant-Ref": grant_ref,
                "KCS-Credential-SHA256": credential_sha,
                "KCS-Grant-Metadata-Digest": _digest(metadata),
                "KCS-Agent-Run-Ref": agent_run_ref,
                "KCS-Generation": str(generation),
                "KCS-Launch-Bundle-Digest": launch_sha,
                "KCS-Audience": audience,
                "KCS-Credential-TTL-Seconds": "300",
                "KCS-Job-UID": binding.job_uid,
                "KCS-Pod-UID": binding.pod_uid,
            },
        )
        _expect_status(granted, 201)
        if granted.header("Cache-Control") != "no-store":
            raise JourneyError(f"{label}: credential response is not no-store")
        body = granted.json_object()
        if (
            body.get("credentialGrantRef") != grant_ref
            or body.get("credentialSha256") != credential_sha
            or body.get("state") != "available"
            or body.get("secretPresent") is not True
        ):
            raise JourneyError(f"{label}: credential grant reality differs")
        return grant_ref

    def _invoke(
        self,
        binding: Binding,
        label: str,
        frame: dict[str, object],
        *,
        replay: bool = False,
        conflict: bool = False,
    ) -> Operation:
        operation_ref = self._ref(label)
        request_digest = _digest(frame)
        response = self.client.request(
            label=f"{label}-invoke",
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/workspace/invoke",
            json_body=frame,
            headers={
                "KCS-Operation-Ref": operation_ref,
                "KCS-Request-Digest": request_digest,
                "KCS-Job-UID": binding.job_uid,
                "KCS-Pod-UID": binding.pod_uid,
            },
        )
        _expect_status(response, 202)
        snapshot = response.json_object()
        _expect_succeeded_operation(
            snapshot, binding, operation_ref, request_digest, f"{label}-invoke"
        )
        operation = Operation(operation_ref, request_digest, frame, snapshot)
        if replay:
            replayed = self._invoke_existing(binding, operation, f"{label}-replay")
            _expect_status(replayed, 200)
            _expect_succeeded_operation(
                replayed.json_object(),
                binding,
                operation_ref,
                request_digest,
                f"{label}-replay",
                retained=snapshot,
            )
        if conflict:
            conflicting: dict[str, object] = {
                "protocol": "cosmos.workspace/1",
                "action": "sharedWrite",
            }
            if conflicting == frame:
                conflicting = {
                    "protocol": "cosmos.workspace/1",
                    "action": "sharedRead",
                    "sourceRole": "agent",
                }
            conflict_response = self.client.request(
                label=f"{label}-conflict",
                method="POST",
                path=f"/api/v2/jobs/{_q(binding.job_ref)}/workspace/invoke",
                json_body=conflicting,
                headers={
                    "KCS-Operation-Ref": operation_ref,
                    "KCS-Request-Digest": _digest(conflicting),
                    "KCS-Job-UID": binding.job_uid,
                    "KCS-Pod-UID": binding.pod_uid,
                },
            )
            _expect_status(conflict_response, 409)
            _expect_error_code(conflict_response, {"IDENTITY_CONFLICT"})
        return operation

    def _invoke_existing(self, binding: Binding, operation: Operation, label: str) -> Exchange:
        return self.client.request(
            label=label,
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/workspace/invoke",
            json_body=operation.frame,
            headers={
                "KCS-Operation-Ref": operation.operation_ref,
                "KCS-Request-Digest": operation.request_digest,
                "KCS-Job-UID": binding.job_uid,
                "KCS-Pod-UID": binding.pod_uid,
            },
        )

    def _register_collect(
        self,
        binding: Binding,
        *,
        path: str,
        content: bytes,
        label: str,
    ) -> str:
        transfer_ref = self._ref(label)
        spec: dict[str, object] = {
            "direction": "collect_output",
            "path": path,
            "declaredSizeBytes": len(content),
            "authorizedMaxSizeBytes": len(content),
            "contentSha256": _bytes_sha256(content),
            "mode": "direct",
            "overwritePolicy": "forbid",
        }
        request = {
            "transferRef": transfer_ref,
            "requestDigest": _digest(spec),
            "spec": spec,
        }
        response = self.client.request(
            label=f"{label}-register",
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/transfers",
            json_body=request,
        )
        _expect_status(response, 201)
        replay = self.client.request(
            label=f"{label}-register-replay",
            method="POST",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/transfers",
            json_body=request,
        )
        _expect_status(replay, 200)
        return transfer_ref

    def _collect(self, binding: Binding, transfer_ref: str, label: str) -> tuple[bytes, str]:
        response = self.client.request(
            label=label,
            method="GET",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/transfers/{_q(transfer_ref)}/content",
        )
        _expect_status(response, 200)
        digest = _bytes_sha256(response.body)
        if response.header("X-Content-SHA256") != digest:
            raise JourneyError(f"{label}: X-Content-SHA256 differs from raw bytes")
        length = response.header("Content-Length")
        if length is None or not length.isdigit() or int(length) != len(response.body):
            raise JourneyError(f"{label}: Content-Length differs from raw bytes")
        snapshot_ref = response.header("X-KCS-Snapshot-Ref")
        if not snapshot_ref:
            raise JourneyError(f"{label}: snapshot ref is absent")
        self.evidence.write_artifact(
            Path(binding.attempt) / f"{_safe_name(label)}.collected", response.body
        )
        return response.body, snapshot_ref

    def _role_logs(
        self, binding: Binding, phase: str, role: str, *, require_terminal: bool = False
    ) -> str:
        deadline = time.monotonic() + self.config.timeouts.wait_seconds
        cursor: str | None = None
        pages: list[str] = []
        page = 0
        while True:
            page += 1
            query = {"container": role, "limitBytes": str(MAX_LOG_BYTES)}
            if cursor is not None:
                query["cursor"] = cursor
            response = self.client.request(
                label=f"{binding.attempt}-logs-{phase}-{role}-{page:02d}",
                method="GET",
                path=f"/api/v2/jobs/{_q(binding.job_ref)}/logs",
                query=query,
            )
            if response.status in {409, 503}:
                if time.monotonic() >= deadline:
                    raise JourneyError(f"{binding.attempt}: timed out waiting for {role} logs")
                time.sleep(self.config.timeouts.poll_seconds)
                continue
            _expect_status(response, 200)
            body = response.json_object()
            if (
                body.get("jobRef") != binding.job_ref
                or body.get("jobUid") != binding.job_uid
                or body.get("podUid") != binding.pod_uid
                or body.get("container") != role
            ):
                raise JourneyError(f"{binding.attempt}: {role} log binding differs")
            content = body.get("content")
            if not isinstance(content, str):
                raise JourneyError(f"{binding.attempt}: {role} log content is not text")
            pages.append(content)
            truncated = body.get("truncated")
            terminal = body.get("terminal")
            if not isinstance(truncated, bool) or not isinstance(terminal, bool):
                raise JourneyError(f"{binding.attempt}: {role} log state is invalid")
            next_cursor = body.get("nextCursor")
            if not truncated:
                break
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
                raise JourneyError(f"{binding.attempt}: {role} log cursor did not advance")
            cursor = next_cursor
        if require_terminal and terminal is not True:
            raise JourneyError(f"{binding.attempt}: {role} logs are not terminal")
        combined = "".join(pages)
        self.evidence.write_log(binding.attempt, phase, role, combined)
        return combined

    def _request_same_until(
        self,
        *,
        label: str,
        method: str,
        path: str,
        success_statuses: set[int],
        json_body: Mapping[str, object] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Exchange:
        deadline = time.monotonic() + self.config.timeouts.wait_seconds
        retry = 0
        response = self.client.request(
            label=label,
            method=method,
            path=path,
            json_body=json_body,
            headers=headers,
        )
        while response.status in {503, 504}:
            error = response.json_object().get("error")
            if not isinstance(error, dict) or error.get("recoveryAction") != "retry_same":
                raise JourneyError(
                    f"{response.label}: transient response did not require retry_same"
                )
            if time.monotonic() >= deadline:
                raise JourneyError(f"{label}: same-request recovery timed out")
            retry += 1
            time.sleep(self.config.timeouts.poll_seconds)
            response = self.client.request(
                label=f"{label}-retry-{retry:02d}",
                method=method,
                path=path,
                json_body=json_body,
                headers=headers,
            )
        if response.status not in success_statuses:
            expected = "/".join(str(status) for status in sorted(success_statuses))
            raise JourneyError(
                f"{response.label}: expected HTTP {expected}, got {response.status}; "
                "read the captured raw response"
            )
        return response

    def _new_and_replay_action(
        self,
        binding: Binding,
        *,
        label: str,
        path: str,
        body: Mapping[str, object],
        action_field: str,
        action_ref: str,
        request_digest: str,
    ) -> dict[str, Any]:
        first = self._request_same_until(
            label=label,
            method="POST",
            path=path,
            json_body=body,
            success_statuses={200, 202},
        )
        first_body = first.json_object()
        _expect_binding(first_body, binding, label)
        _expect_close_action(first_body, action_field, action_ref, request_digest, f"{label} first")
        replay = self._request_same_until(
            label=f"{label}-replay",
            method="POST",
            path=path,
            json_body=body,
            success_statuses={200},
        )
        replay_body = replay.json_object()
        _expect_binding(replay_body, binding, f"{label} replay")
        _expect_close_action(
            replay_body, action_field, action_ref, request_digest, f"{label} replay"
        )
        if (
            replay_body.get("bindingState") != first_body.get("bindingState")
            or replay_body.get("outputLossPossible") != first_body.get("outputLossPossible")
            or replay_body.get(action_field) != first_body.get(action_field)
        ):
            raise JourneyError(f"{label}: replay terminal state differs")
        return replay_body

    def _delete(
        self, binding: Binding, label: str, *, expected_final_state: str
    ) -> dict[str, object]:
        delete_ref = self._ref(label)
        path = f"/api/v2/jobs/{_q(binding.job_ref)}"
        headers = {
            "KCS-Delete-Ref": delete_ref,
            "KCS-Request-Digest": EMPTY_OBJECT_DIGEST,
        }
        response = self._request_same_until(
            label=label,
            method="DELETE",
            path=path,
            headers=headers,
            success_statuses={200},
        )
        tombstone = response.json_object()
        _expect_tombstone(tombstone, binding, delete_ref, expected_final_state)
        replay = self._request_same_until(
            label=f"{label}-replay",
            method="DELETE",
            path=path,
            headers=headers,
            success_statuses={200},
        )
        replay_tombstone = replay.json_object()
        _expect_tombstone(replay_tombstone, binding, delete_ref, expected_final_state)
        if replay_tombstone != tombstone:
            raise JourneyError(f"{label}: delete replay changed the retained tombstone")
        inspected = self.client.request(label=f"{label}-inspect-tombstone", method="GET", path=path)
        _expect_status(inspected, 410)
        _expect_error_code(inspected, {"TOMBSTONED"})
        inspected_tombstone = _error_tombstone(inspected, f"{label} inspect")
        _expect_tombstone(inspected_tombstone, binding, delete_ref, expected_final_state)
        if inspected_tombstone != tombstone:
            raise JourneyError(f"{label}: inspect returned a different retained tombstone")
        create_replay = self.client.request(
            label=f"{label}-create-after-delete",
            method="POST",
            path="/api/v2/jobs",
            json_body=binding.create_request,
        )
        _expect_status(create_replay, 410)
        _expect_error_code(create_replay, {"TOMBSTONED"})
        create_tombstone = _error_tombstone(create_replay, f"{label} create replay")
        _expect_tombstone(create_tombstone, binding, delete_ref, expected_final_state)
        if create_tombstone != tombstone:
            raise JourneyError(f"{label}: create replay returned a different tombstone")
        result = {
            "jobRef": binding.job_ref,
            "deleteRef": delete_ref,
            "finalState": tombstone.get("finalState"),
            "cleanupState": _nested(tombstone, "cleanup", "state"),
            "gpuReleaseState": _nested(tombstone, "gpuRelease", "state"),
        }
        self.deleted.append(result)
        return result

    def _inspect_same_binding(self, binding: Binding, label: str) -> dict[str, Any]:
        response = self.client.request(
            label=label, method="GET", path=f"/api/v2/jobs/{_q(binding.job_ref)}"
        )
        _expect_status(response, 200)
        body = response.json_object()
        _expect_binding(body, binding, label)
        return body

    def _inspect_transfer(self, binding: Binding, transfer_ref: str, label: str) -> dict[str, Any]:
        response = self.client.request(
            label=label,
            method="GET",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/transfers/{_q(transfer_ref)}",
        )
        _expect_status(response, 200)
        body = response.json_object()
        if body.get("jobRef") != binding.job_ref or body.get("transferRef") != transfer_ref:
            raise JourneyError(f"{label}: transfer identity differs")
        return body

    def _inspect_operation(
        self, binding: Binding, operation_ref: str, label: str
    ) -> dict[str, Any]:
        response = self.client.request(
            label=label,
            method="GET",
            path=f"/api/v2/jobs/{_q(binding.job_ref)}/operations/{_q(operation_ref)}",
        )
        _expect_status(response, 200)
        body = response.json_object()
        if body.get("jobRef") != binding.job_ref or body.get("operationRef") != operation_ref:
            raise JourneyError(f"{label}: operation identity differs")
        return body

    def _inspect_grant(self, binding: Binding, grant_ref: str, label: str) -> dict[str, Any]:
        response = self.client.request(
            label=label,
            method="GET",
            path=(f"/api/v2/jobs/{_q(binding.job_ref)}/agent/credential-grants/{_q(grant_ref)}"),
        )
        _expect_status(response, 200)
        if response.header("Cache-Control") != "no-store":
            raise JourneyError(f"{label}: grant inspection is not no-store")
        body = response.json_object()
        if body.get("jobRef") != binding.job_ref or body.get("credentialGrantRef") != grant_ref:
            raise JourneyError(f"{label}: credential grant identity differs")
        return body

    def _ref(self, suffix: str) -> str:
        return f"journey-{self.session}-{suffix}"

    def _secret_scan(self) -> dict[str, object]:
        credential_encodings = [
            encoded
            for credential in self.credentials
            for encoded in (
                credential,
                credential.hex().encode(),
                base64.b64encode(credential),
            )
        ]
        literal_patterns = [self.service_token, *credential_encodings]
        regex_patterns = (
            re.compile(rb"(?i)authorization\s*[:=]\s*bearer\s+[^\s\"']+"),
            re.compile(rb"\bsk-[A-Za-z0-9_-]{16,}\b"),
        )
        hits: list[dict[str, object]] = []
        total = 0
        sources = [path for path in sorted(self.evidence.root.rglob("*")) if path.is_file()]
        sources.append(self.config.source)
        for path in sources:
            try:
                content = path.read_bytes()
            except OSError as error:
                raise JourneyError("secret scan could not read an evidence file") from error
            count = sum(content.count(pattern) for pattern in literal_patterns if pattern)
            count += sum(len(pattern.findall(content)) for pattern in regex_patterns)
            if count:
                label = (
                    str(path.relative_to(self.evidence.root))
                    if path.is_relative_to(self.evidence.root)
                    else "journey-config"
                )
                hits.append({"path": label, "hitCount": count})
                total += count
        report: dict[str, object] = {
            "generatedAt": _now(),
            "scannedFileCount": len(sources),
            "totalHits": total,
            "files": hits,
            "note": "Only paths and hit counts are recorded; matched values are never emitted.",
        }
        self.evidence.write_json(self.evidence.root / "secret-scan.json", report)
        return report


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise JourneyError(f"{label} must be an object")
    return dict(value)


def _string(value: Mapping[str, object], key: str, label: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise JourneyError(f"{label}.{key} must be a non-empty string")
    return result


def _integer(
    value: Mapping[str, object],
    key: str,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    result = value.get(key)
    if type(result) is not int or not minimum <= result <= maximum:
        raise JourneyError(f"{label}.{key} must be between {minimum} and {maximum}")
    return result


def _positive_number(value: Mapping[str, object], key: str, label: str) -> float:
    result = value.get(key)
    if isinstance(result, bool) or not isinstance(result, (int, float)) or result <= 0:
        raise JourneyError(f"{label}.{key} must be greater than zero")
    return float(result)


def _config_path(config_path: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return (config_path.parent / path).resolve() if not path.is_absolute() else path.resolve()


def _sha256(value: str, label: str) -> str:
    if not SHA256_PATTERN.fullmatch(value):
        raise JourneyError(f"{label} must be lowercase SHA-256 hex")
    return value


def _immutable_image(value: str, label: str) -> str:
    match = IMAGE_PATTERN.fullmatch(value)
    if match is None or match.group(1) == "0" * 64:
        raise JourneyError(f"{label} must be a nonzero digest-pinned image")
    return value


def _runtime_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise JourneyError("workloads.runtimeUrl must be a credential-free HTTP(S) URL")
    hostname = parsed.hostname.casefold()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise JourneyError("workloads.runtimeUrl must not be loopback")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return value
    if any(
        (
            address.is_loopback,
            address.is_unspecified,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
        )
    ):
        raise JourneyError("workloads.runtimeUrl must use a routable non-loopback address")
    return value


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: Mapping[str, object]) -> str:
    try:
        return _bytes_sha256(rfc8785.dumps(cast(Any, dict(value))))
    except (rfc8785.CanonicalizationError, TypeError) as error:
        raise JourneyError("value cannot be represented as RFC 8785 JCS") from error


def _pretty_json(value: Mapping[str, object]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _valid_timestamp(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.") or "item"


def _q(value: str) -> str:
    return quote(value, safe="")


def _expect_status(exchange: Exchange, expected: int) -> None:
    if exchange.status != expected:
        raise JourneyError(
            f"{exchange.label}: expected HTTP {expected}, got {exchange.status}; "
            "read the captured raw response"
        )


def _expect_error_code(exchange: Exchange, expected: set[str]) -> None:
    error = exchange.json_object().get("error")
    code = error.get("code") if isinstance(error, dict) else None
    if code not in expected:
        raise JourneyError(f"{exchange.label}: unexpected error code")


def _error_tombstone(exchange: Exchange, label: str) -> dict[str, Any]:
    error = exchange.json_object().get("error")
    context = error.get("context") if isinstance(error, dict) else None
    tombstone = context.get("tombstone") if isinstance(context, dict) else None
    if not isinstance(tombstone, dict):
        raise JourneyError(f"{label}: TOMBSTONED response omitted its retained tombstone")
    return dict(tombstone)


def _binding_ready(body: Mapping[str, object]) -> bool:
    agent = body.get("agent")
    workspace = body.get("workspace")
    return bool(
        body.get("podUid")
        and body.get("observedPodCount") == 1
        and isinstance(agent, dict)
        and isinstance(workspace, dict)
        and agent.get("state") == "running"
        and agent.get("ready") is True
        and workspace.get("state") == "running"
        and workspace.get("ready") is True
    )


def _expect_binding(
    body: Mapping[str, object],
    binding: Binding,
    label: str,
    *,
    allow_unbound_pod_uid: bool = False,
) -> None:
    if (
        body.get("providerRequestId") != binding.provider_request_id
        or body.get("specDigest") != binding.spec_digest
        or body.get("jobRef") != binding.job_ref
        or body.get("jobUid") != binding.job_uid
    ):
        raise JourneyError(f"{label}: immutable Job binding differs")
    pod_uid = body.get("podUid")
    if pod_uid not in ({None, binding.pod_uid} if allow_unbound_pod_uid else {binding.pod_uid}):
        raise JourneyError(f"{label}: immutable Pod UID differs")


def _expect_generation_snapshot(
    body: Mapping[str, object],
    binding: Binding,
    request: Mapping[str, object],
    *,
    replayed: bool,
    label: str,
) -> None:
    projected = {key: value for key, value in request.items() if key != "generation"}
    expected = {
        "jobRef": binding.job_ref,
        "generation": request.get("generation"),
        "agentRunRef": request.get("agentRunRef"),
        "executionEnvelopeRef": request.get("executionEnvelopeRef"),
        "executionEnvelopeDigest": request.get("executionEnvelopeDigest"),
        "launchBundlePath": request.get("launchBundlePath"),
        "launchBundleDigest": request.get("launchBundleDigest"),
        "launchBundleSizeBytes": request.get("launchBundleSizeBytes"),
        "materialPaths": request.get("materialPaths"),
        "credentialGrantRef": request.get("credentialGrantRef"),
        "startMetadataDigest": _digest(projected),
        "runnerState": "exited",
        "supervisorAlive": True,
        "exitCode": 0,
        "replayed": replayed,
    }
    if any(body.get(key) != value for key, value in expected.items()):
        raise JourneyError(f"{label}: generation snapshot differs from the exact start request")
    for field in ("credentialAcknowledgedAt", "credentialDestroyedAt"):
        value = body.get(field)
        if not isinstance(value, str) or not _valid_timestamp(value):
            raise JourneyError(f"{label}: {field} is absent")


def _expect_succeeded_operation(
    body: Mapping[str, object],
    binding: Binding,
    operation_ref: str,
    request_digest: str,
    label: str,
    *,
    retained: Mapping[str, object] | None = None,
) -> None:
    operation_binding = body.get("binding")
    inline_result = body.get("inlineResult")
    if (
        body.get("jobRef") != binding.job_ref
        or body.get("operationRef") != operation_ref
        or body.get("requestDigest") != request_digest
        or body.get("storedFrameDigest") != request_digest
        or operation_binding != {"jobUid": binding.job_uid, "podUid": binding.pod_uid}
        or body.get("state") != "succeeded"
        or body.get("exitCode") != 0
        or not isinstance(inline_result, dict)
    ):
        raise JourneyError(f"{label}: workspace operation identity or terminal state differs")
    inline_bytes = rfc8785.dumps(cast(Any, inline_result))
    if (
        body.get("inlineResultSize") != len(inline_bytes)
        or body.get("inlineResultDigest") != _bytes_sha256(inline_bytes)
        or body.get("resultTransferRef") is not None
    ):
        raise JourneyError(f"{label}: inline operation result integrity differs")
    if retained is not None:
        stable_fields = (
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
            "failureReason",
        )
        if any(body.get(field) != retained.get(field) for field in stable_fields):
            raise JourneyError(f"{label}: retained operation result changed")


def _expect_close_action(
    body: Mapping[str, object],
    action_field: str,
    action_ref: str,
    request_digest: str,
    label: str,
) -> None:
    action = body.get(action_field)
    if (
        not isinstance(action, dict)
        or action.get("actionRef") != action_ref
        or action.get("requestDigest") != request_digest
        or action.get("state") != "succeeded"
    ):
        raise JourneyError(f"{label}: retained close action identity differs")


def _binding_summary(binding: Binding) -> dict[str, object]:
    return {
        "providerRequestId": binding.provider_request_id,
        "specDigest": binding.spec_digest,
        "jobRef": binding.job_ref,
        "jobUid": binding.job_uid,
        "podUid": binding.pod_uid,
    }


def _expect_completed_transfer(
    body: Mapping[str, object], binding: Binding, transfer_ref: str, content: bytes
) -> None:
    if (
        body.get("jobRef") != binding.job_ref
        or body.get("jobUid") != binding.job_uid
        or body.get("podUid") != binding.pod_uid
        or body.get("transferRef") != transfer_ref
        or body.get("state") != "completed"
        or body.get("actualSizeBytes") != len(content)
        or body.get("actualSha256") != _bytes_sha256(content)
        or body.get("verified") is not True
        or body.get("contentAvailable") is not True
    ):
        raise JourneyError("completed transfer reality differs from staged bytes")


def _expect_registered_collect(
    body: Mapping[str, object],
    binding: Binding,
    transfer_ref: str,
    *,
    path: str,
    content: bytes,
) -> None:
    spec: dict[str, object] = {
        "direction": "collect_output",
        "path": path,
        "declaredSizeBytes": len(content),
        "authorizedMaxSizeBytes": len(content),
        "contentSha256": _bytes_sha256(content),
        "mode": "direct",
        "overwritePolicy": "forbid",
    }
    if (
        body.get("jobRef") != binding.job_ref
        or body.get("jobUid") != binding.job_uid
        or body.get("podUid") != binding.pod_uid
        or body.get("transferRef") != transfer_ref
        or body.get("requestDigest") != _digest(spec)
        or body.get("spec") != spec
        or body.get("state") != "registered"
        or body.get("actualSizeBytes") is not None
        or body.get("actualSha256") is not None
        or body.get("verified") is not False
        or body.get("contentAvailable") is not False
        or body.get("snapshotRef") is not None
        or body.get("completedAt") is not None
    ):
        raise JourneyError("uncollected transfer reality differs from its registration")


def _inline_result(snapshot: Mapping[str, object], label: str) -> dict[str, Any]:
    result = snapshot.get("inlineResult")
    if not isinstance(result, dict):
        raise JourneyError(f"{label}: inlineResult is absent")
    return dict(result)


def _expect_inline_probe(
    snapshot: Mapping[str, object], event: str, digest: str, size: int
) -> None:
    result = _inline_result(snapshot, event)
    if (
        result.get("event") != event
        or result.get("ok") is not True
        or result.get("sha256") != digest
        or result.get("sizeBytes") != size
    ):
        raise JourneyError(f"{event}: shared-file digest observation differs")


def _log_events(content: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in content.splitlines():
        try:
            value: Any = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and isinstance(value.get("event"), str):
            events.append(dict(value))
    return events


def _event_count(content: str, event: str) -> int:
    return sum(item.get("event") == event for item in _log_events(content))


def _single_log_event(content: str, event: str) -> dict[str, Any]:
    matches = [item for item in _log_events(content) if item.get("event") == event]
    if len(matches) != 1:
        raise JourneyError(f"raw logs contain {len(matches)} {event} events, expected one")
    return matches[0]


def _expect_log_event(content: str, event: str, digest: str) -> None:
    item = _single_log_event(content, event)
    if item.get("ok") is not True or item.get("sha256") != digest:
        raise JourneyError(f"raw log event {event} has the wrong digest/result")


def _expect_roles_terminal(body: Mapping[str, object], label: str) -> None:
    for role in ("agent", "workspace"):
        value = body.get(role)
        if not isinstance(value, dict) or value.get("state") != "terminated":
            raise JourneyError(f"{label}: {role} is not terminated")


def _nested(body: Mapping[str, object], parent: str, field: str) -> object:
    value = body.get(parent)
    return value.get(field) if isinstance(value, dict) else None


def _expect_tombstone(
    body: Mapping[str, object],
    binding: Binding,
    delete_ref: str,
    expected_final_state: str,
) -> None:
    if (
        body.get("providerRequestId") != binding.provider_request_id
        or body.get("specDigest") != binding.spec_digest
        or body.get("jobRef") != binding.job_ref
        or body.get("jobUid") != binding.job_uid
        or body.get("podUid") != binding.pod_uid
        or body.get("state") != "deleted"
        or body.get("finalState") != expected_final_state
        or body.get("deleteRef") != delete_ref
        or body.get("deleteRequestDigest") != EMPTY_OBJECT_DIGEST
        or _nested(body, "cleanup", "state") != "complete"
        or _nested(body, "gpuRelease", "state") not in {"complete", "not_required"}
    ):
        raise JourneyError("delete tombstone does not prove bound cleanup")


def _require_subset(
    expected: Mapping[str, object], observed: Mapping[str, object], label: str
) -> None:
    for key, value in expected.items():
        actual = observed.get(key)
        if isinstance(value, dict):
            if not isinstance(actual, dict):
                raise JourneyError(f"{label}.{key} is absent")
            _require_subset(value, actual, f"{label}.{key}")
        elif actual != value:
            raise JourneyError(f"{label}.{key} differs from the checkpoint request")


def _validate_restart_checkpoint(result: Mapping[str, object]) -> None:
    facts = _mapping(result.get("facts"), "restart checkpoint facts")
    old_uid = facts.get("oldApiPodUid")
    new_uid = facts.get("newApiPodUid")
    if not isinstance(old_uid, str) or not isinstance(new_uid, str) or old_uid == new_uid:
        raise JourneyError("restart checkpoint must retain two different API Pod UIDs")


def _validate_pod_delete_checkpoint(result: Mapping[str, object]) -> None:
    observed = _mapping(result.get("observed"), "Pod delete checkpoint observed")
    facts = _mapping(result.get("facts"), "Pod delete checkpoint facts")
    if facts.get("preconditionUid") != observed.get("podUid"):
        raise JourneyError("Pod delete checkpoint did not use the retained Pod UID precondition")


def _checkpoint_summary(result: Mapping[str, object]) -> dict[str, object]:
    return {
        "checkpoint": result.get("checkpoint"),
        "status": result.get("status"),
        "completedAt": result.get("completedAt"),
        "facts": result.get("facts"),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one deployed KCS V2 evidence session with normal/cancel/Pod-loss Attempts."
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    token = os.environ.get(SERVICE_TOKEN_ENV)
    if token is None or not token or any(character.isspace() for character in token):
        print(f"error: {SERVICE_TOKEN_ENV} must contain the service token", file=sys.stderr)
        return 2
    try:
        config = JourneyConfig.load(arguments.config)
        evidence = EvidenceWriter(arguments.evidence_dir)
        client = KcsV2Client(config, token, evidence)
        summary = AttemptJourney(
            config,
            client,
            evidence,
            OperatorCheckpoints(config, evidence),
            token,
        ).run()
    except JourneyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    attempts = summary.get("attempts")
    print("KCS V2 standalone Journey passed (normal, cancel, Pod loss).")
    print(f"attempts: {len(attempts) if isinstance(attempts, dict) else 0}")
    print(f"evidence: {arguments.evidence_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
