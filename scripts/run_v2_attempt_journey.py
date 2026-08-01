#!/usr/bin/env python3
"""Drive the standalone KCS V2 create-to-delete runtime journey over HTTPS."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import rfc8785

SERVICE_TOKEN_ENV = "KCS_V2_SERVICE_TOKEN"
MAX_LOG_BYTES = 1_048_576
EMPTY_OBJECT_DIGEST = hashlib.sha256(rfc8785.dumps({})).hexdigest()
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
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
    """A failed runtime exchange or acceptance check."""


@dataclass(frozen=True, slots=True)
class Exchange:
    """One captured HTTP response."""

    label: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def json_object(self) -> dict[str, Any]:
        try:
            value = json.loads(self.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise JourneyError(f"{self.label}: response is not a JSON object") from error
        if not isinstance(value, dict):
            raise JourneyError(f"{self.label}: response is not a JSON object")
        return value


@dataclass(frozen=True, slots=True)
class BindingIdentity:
    """The immutable identity carried across create, inspect, logs, and tombstone."""

    provider_request_id: str
    spec_digest: str
    job_ref: str
    job_uid: str
    pod_uid: str | None


class EvidenceWriter:
    """Persist exact response bytes and a deliberately small safe header projection."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.exchanges = root / "exchanges"
        self.logs = root / "logs"
        if (root / "summary.json").exists() or any(
            directory.exists() and any(directory.iterdir())
            for directory in (self.exchanges, self.logs)
        ):
            raise JourneyError("evidence directory already contains journey evidence")
        self.exchanges.mkdir(parents=True, exist_ok=True)
        self.logs.mkdir(parents=True, exist_ok=True)
        self._sequence = 0

    def capture(
        self,
        *,
        label: str,
        method: str,
        path: str,
        status: int,
        headers: Sequence[tuple[str, str]],
        body: bytes,
    ) -> str:
        self._sequence += 1
        stem = f"{self._sequence:02d}-{label}"
        body_name = f"{stem}.response.body"
        self._write_bytes(self.exchanges / body_name, body)

        selected: dict[str, list[str]] = {}
        for name, value in headers:
            normalized = name.casefold()
            if normalized in SAFE_RESPONSE_HEADERS:
                selected.setdefault(normalized, []).append(value)
        metadata = {
            "operation": label,
            "request": {"method": method, "path": path},
            "response": {
                "status": status,
                "headers": selected,
                "rawBodyFile": body_name,
                "rawBodyBytes": len(body),
                "rawBodySha256": hashlib.sha256(body).hexdigest(),
            },
        }
        self._write_json(self.exchanges / f"{stem}.response.json", metadata)
        return stem

    def capture_role_log(self, role: str, content: str) -> dict[str, object]:
        raw = content.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        filename = f"{role}.log"
        self._write_bytes(self.logs / filename, raw)
        self._write_bytes(
            self.logs / f"{filename}.sha256",
            f"{digest}  {filename}\n".encode("ascii"),
        )
        return {"file": f"logs/{filename}", "bytes": len(raw), "sha256": digest}

    def write_summary(self, summary: Mapping[str, object]) -> None:
        self._write_json(self.root / "summary.json", summary)

    @staticmethod
    def _write_bytes(path: Path, content: bytes) -> None:
        try:
            with path.open("xb") as stream:
                stream.write(content)
        except FileExistsError as error:
            raise JourneyError(f"evidence file already exists: {path}") from error

    @classmethod
    def _write_json(cls, path: Path, value: Mapping[str, object]) -> None:
        cls._write_bytes(
            path,
            (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
        )


class KcsV2Client:
    """Small no-redirect client that never records or exposes its bearer token."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        timeout_seconds: float,
        allow_http: bool,
        evidence: EvidenceWriter,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.username is not None or parsed.password is not None:
            raise JourneyError("base URL must not contain credentials")
        if parsed.query or parsed.fragment:
            raise JourneyError("base URL must not contain a query or fragment")
        if parsed.path not in {"", "/"}:
            raise JourneyError("base URL must be an origin without an API path")
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise JourneyError("base URL must be an absolute HTTP(S) origin")
        if parsed.scheme == "http" and not (allow_http and _is_loopback_host(parsed.hostname)):
            raise JourneyError("HTTP is allowed only for an explicit local loopback simulation")
        if parsed.scheme == "https" and allow_http:
            raise JourneyError("--allow-http is only meaningful with a local HTTP base URL")

        self._scheme = parsed.scheme
        self._host = parsed.hostname
        self._port = parsed.port
        self._token = token
        self._timeout_seconds = timeout_seconds
        self._evidence = evidence

    def request(
        self,
        *,
        label: str,
        method: str,
        path: str,
        query: Mapping[str, str] | None = None,
        json_body: Mapping[str, object] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Exchange:
        target = path
        if query:
            target = f"{path}?{urlencode(query)}"

        request_headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._token}",
        }
        body: bytes | None = None
        if json_body is not None:
            body = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)

        connection = self._connection()
        try:
            connection.request(method, target, body=body, headers=request_headers)
            response = connection.getresponse()
            response_body = response.read()
            response_headers = tuple(response.getheaders())
            status = response.status
        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            raise JourneyError(f"{label}: transport failed ({type(error).__name__})") from error
        finally:
            connection.close()

        self._evidence.capture(
            label=label,
            method=method,
            path=target,
            status=status,
            headers=response_headers,
            body=response_body,
        )
        return Exchange(label, status, response_headers, response_body)

    def _connection(self) -> http.client.HTTPConnection:
        if self._scheme == "https":
            return http.client.HTTPSConnection(
                self._host,
                self._port,
                timeout=self._timeout_seconds,
                context=ssl.create_default_context(),
            )
        return http.client.HTTPConnection(
            self._host,
            self._port,
            timeout=self._timeout_seconds,
        )


class AttemptJourney:
    """Current vertical journey, with room for transfer/start/invoke steps later."""

    def __init__(
        self,
        *,
        client: KcsV2Client,
        evidence: EvidenceWriter,
        request_body: dict[str, object],
        wait_seconds: float,
        poll_seconds: float,
    ) -> None:
        self.client = client
        self.evidence = evidence
        self.request_body = request_body
        self.wait_seconds = wait_seconds
        self.poll_seconds = poll_seconds

    def run(self) -> dict[str, object]:
        provider_request_id = _required_string(self.request_body, "providerRequestId", "request")
        spec_digest = _required_string(self.request_body, "specDigest", "request")

        created = self.client.request(
            label="create",
            method="POST",
            path="/api/v2/jobs",
            json_body=self.request_body,
        )
        _expect_status(created, 201)
        created_body = created.json_object()
        created_identity = _binding_identity(created_body, "create")
        _expect_request_identity(created_identity, provider_request_id, spec_digest, "create")

        replayed = self.client.request(
            label="create-replay",
            method="POST",
            path="/api/v2/jobs",
            json_body=self.request_body,
        )
        _expect_status(replayed, 200)
        replayed_identity = _binding_identity(replayed.json_object(), "create-replay")
        _expect_same_binding(created_identity, replayed_identity, "create replay")

        inspected_body = self._inspect_until_pod(created_identity.job_ref)
        inspected_identity = _binding_identity(inspected_body, "inspect")
        _expect_same_binding(created_identity, inspected_identity, "inspect")
        _expect_same_binding(replayed_identity, inspected_identity, "inspect after replay")
        if inspected_identity.pod_uid is None:
            raise JourneyError("inspect: no immutable Pod UID was observed")
        if replayed_identity.pod_uid is None:
            bound_replay = self.client.request(
                label="create-replay-bound",
                method="POST",
                path="/api/v2/jobs",
                json_body=self.request_body,
            )
            _expect_status(bound_replay, 200)
            bound_replay_identity = _binding_identity(
                bound_replay.json_object(), "create-replay-bound"
            )
            _expect_same_binding(inspected_identity, bound_replay_identity, "bound create replay")

        log_evidence: dict[str, object] = {}
        for role in ("agent", "workspace"):
            logs_body = self._role_logs_when_ready(inspected_identity, role)
            content = logs_body.get("content")
            if not isinstance(content, str):
                raise JourneyError(f"logs-{role}: content is not a string")
            log_evidence[role] = self.evidence.capture_role_log(role, content)

        listed = self.client.request(
            label="list-live",
            method="GET",
            path="/api/v2/jobs",
            query={
                "providerRequestId": provider_request_id,
                "includeDeleted": "false",
                "pageSize": "200",
            },
        )
        _expect_status(listed, 200)
        _expect_live_list_member(listed.json_object(), inspected_identity)

        delete_ref = f"journey-delete-{uuid.uuid4().hex}"
        deleted = self._delete_until_complete(inspected_identity.job_ref, delete_ref)
        tombstone = deleted.json_object()
        _expect_tombstone(tombstone, inspected_identity, delete_ref)

        retained = self.client.request(
            label="inspect-tombstone",
            method="GET",
            path=f"/api/v2/jobs/{quote(inspected_identity.job_ref, safe='')}",
        )
        _expect_status(retained, 410)
        _expect_tombstone_error(retained.json_object(), inspected_identity, delete_ref)

        listed_deleted = self.client.request(
            label="list-tombstone",
            method="GET",
            path="/api/v2/jobs",
            query={
                "providerRequestId": provider_request_id,
                "includeDeleted": "true",
                "pageSize": "200",
            },
        )
        _expect_status(listed_deleted, 200)
        _expect_deleted_list_member(listed_deleted.json_object(), inspected_identity, delete_ref)

        summary: dict[str, object] = {
            "evidenceFormatVersion": 1,
            "result": "passed",
            "request": {
                "providerRequestId": provider_request_id,
                "specDigest": spec_digest,
            },
            "binding": {
                "jobRef": inspected_identity.job_ref,
                "jobUid": inspected_identity.job_uid,
                "podUid": inspected_identity.pod_uid,
            },
            "logs": log_evidence,
            "delete": {
                "deleteRef": delete_ref,
                "deleteRequestDigest": EMPTY_OBJECT_DIGEST,
                "finalState": tombstone.get("finalState"),
                "cleanupState": _nested_value(tombstone, "cleanup", "state"),
                "gpuReleaseState": _nested_value(tombstone, "gpuRelease", "state"),
            },
            "checks": [
                "create returned 201 and exact replay returned 200",
                "Job and Pod identity remained stable through replay and inspect",
                "agent and workspace logs carried the immutable binding",
                "live list contained the binding",
                "delete returned a complete tombstone",
                "inspect returned TOMBSTONED and includeDeleted listed the tombstone",
            ],
        }
        self.evidence.write_summary(summary)
        return summary

    def _inspect_until_pod(self, job_ref: str) -> dict[str, Any]:
        deadline = time.monotonic() + self.wait_seconds
        attempt = 0
        while True:
            attempt += 1
            inspected = self.client.request(
                label=f"inspect-{attempt:02d}",
                method="GET",
                path=f"/api/v2/jobs/{quote(job_ref, safe='')}",
            )
            _expect_status(inspected, 200)
            body = inspected.json_object()
            if body.get("podUid") is not None:
                return body
            if time.monotonic() >= deadline:
                raise JourneyError("inspect: timed out waiting for the immutable Pod UID")
            time.sleep(self.poll_seconds)

    def _role_logs_when_ready(
        self,
        identity: BindingIdentity,
        role: str,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self.wait_seconds
        attempt = 0
        while True:
            attempt += 1
            label = f"logs-{role}" if attempt == 1 else f"logs-{role}-retry-{attempt:02d}"
            logs = self.client.request(
                label=label,
                method="GET",
                path=f"/api/v2/jobs/{quote(identity.job_ref, safe='')}/logs",
                query={"container": role, "limitBytes": str(MAX_LOG_BYTES)},
            )
            if logs.status == 200:
                body = logs.json_object()
                _expect_log_identity(body, identity, role)
                return body
            if logs.status not in {409, 503}:
                _expect_status(logs, 200)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise JourneyError(f"logs-{role}: timed out waiting for readable logs")
            time.sleep(min(self.poll_seconds, remaining))

    def _delete_until_complete(self, job_ref: str, delete_ref: str) -> Exchange:
        deadline = time.monotonic() + self.wait_seconds
        attempt = 0
        while True:
            attempt += 1
            label = "delete" if attempt == 1 else f"delete-replay-{attempt:02d}"
            deleted = self.client.request(
                label=label,
                method="DELETE",
                path=f"/api/v2/jobs/{quote(job_ref, safe='')}",
                headers={
                    "KCS-Delete-Ref": delete_ref,
                    "KCS-Request-Digest": EMPTY_OBJECT_DIGEST,
                },
            )
            if deleted.status == 200:
                return deleted
            if deleted.status != 504:
                _expect_status(deleted, 200)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise JourneyError("delete: timed out replaying the retained delete identity")
            time.sleep(min(self.poll_seconds, remaining))


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost" or host.casefold().endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _load_request(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_bytes())
    except OSError as error:
        raise JourneyError("could not read the request JSON") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise JourneyError("request JSON is invalid") from error
    if not isinstance(value, dict):
        raise JourneyError("request JSON must be an object")
    unexpected = set(value) - {"providerRequestId", "specDigest", "spec"}
    if unexpected:
        raise JourneyError("request JSON does not have the canonical create-request shape")
    _required_string(value, "providerRequestId", "request")
    spec = value.get("spec")
    if not isinstance(spec, dict):
        raise JourneyError("request.spec must be an object")
    try:
        expected_digest = hashlib.sha256(rfc8785.dumps(spec)).hexdigest()
    except (rfc8785.CanonicalizationError, TypeError) as error:
        raise JourneyError("request.spec cannot be represented as RFC 8785 JCS") from error

    supplied = value.get("specDigest")
    if supplied is None:
        value["specDigest"] = expected_digest
    elif not isinstance(supplied, str) or not SHA256_PATTERN.fullmatch(supplied):
        raise JourneyError("request.specDigest must be lowercase SHA-256 hex")
    elif not hmac.compare_digest(supplied, expected_digest):
        raise JourneyError("request.specDigest does not match RFC 8785 JCS(spec)")
    return value


def _required_string(value: Mapping[str, object], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise JourneyError(f"{label}: {field} must be a non-empty string")
    return result


def _optional_string(value: Mapping[str, object], field: str, label: str) -> str | None:
    result = value.get(field)
    if result is not None and (not isinstance(result, str) or not result):
        raise JourneyError(f"{label}: {field} must be null or a non-empty string")
    return result


def _binding_identity(body: Mapping[str, object], label: str) -> BindingIdentity:
    return BindingIdentity(
        provider_request_id=_required_string(body, "providerRequestId", label),
        spec_digest=_required_string(body, "specDigest", label),
        job_ref=_required_string(body, "jobRef", label),
        job_uid=_required_string(body, "jobUid", label),
        pod_uid=_optional_string(body, "podUid", label),
    )


def _expect_request_identity(
    identity: BindingIdentity,
    provider_request_id: str,
    spec_digest: str,
    label: str,
) -> None:
    if identity.provider_request_id != provider_request_id or identity.spec_digest != spec_digest:
        raise JourneyError(f"{label}: response does not carry the request identity and digest")


def _expect_same_binding(
    expected: BindingIdentity,
    actual: BindingIdentity,
    label: str,
) -> None:
    if (
        expected.provider_request_id != actual.provider_request_id
        or expected.spec_digest != actual.spec_digest
        or expected.job_ref != actual.job_ref
        or expected.job_uid != actual.job_uid
    ):
        raise JourneyError(f"{label}: stable Job binding changed")
    if expected.pod_uid is not None and actual.pod_uid != expected.pod_uid:
        raise JourneyError(f"{label}: immutable Pod UID changed or disappeared")


def _expect_log_identity(
    body: Mapping[str, object],
    identity: BindingIdentity,
    role: str,
) -> None:
    if (
        body.get("jobRef") != identity.job_ref
        or body.get("jobUid") != identity.job_uid
        or body.get("podUid") != identity.pod_uid
        or body.get("container") != role
    ):
        raise JourneyError(f"logs-{role}: immutable log identity does not match inspect")


def _expect_live_list_member(body: Mapping[str, object], identity: BindingIdentity) -> None:
    items = body.get("items")
    tombstones = body.get("tombstones")
    if not isinstance(items, list) or not isinstance(tombstones, list):
        raise JourneyError("list-live: items and tombstones must be arrays")
    matches = [
        item for item in items if isinstance(item, dict) and item.get("jobRef") == identity.job_ref
    ]
    if len(matches) != 1:
        raise JourneyError("list-live: expected exactly one matching live binding")
    listed_identity = _binding_identity(matches[0], "list-live")
    _expect_same_binding(identity, listed_identity, "list-live")
    if any(
        isinstance(item, dict) and item.get("providerRequestId") == identity.provider_request_id
        for item in tombstones
    ):
        raise JourneyError("list-live: request identity unexpectedly appears as a tombstone")


def _expect_tombstone(
    body: Mapping[str, object],
    identity: BindingIdentity,
    delete_ref: str,
) -> None:
    if (
        body.get("providerRequestId") != identity.provider_request_id
        or body.get("specDigest") != identity.spec_digest
        or body.get("jobRef") != identity.job_ref
        or body.get("jobUid") != identity.job_uid
        or body.get("podUid") != identity.pod_uid
        or body.get("state") != "deleted"
        or body.get("deleteRef") != delete_ref
        or body.get("deleteRequestDigest") != EMPTY_OBJECT_DIGEST
    ):
        raise JourneyError("delete: tombstone does not retain the immutable binding")
    if _nested_value(body, "cleanup", "state") != "complete":
        raise JourneyError("delete: workload cleanup is not complete")
    if _nested_value(body, "gpuRelease", "state") not in {"complete", "not_required"}:
        raise JourneyError("delete: GPU release is not complete or not required")


def _expect_tombstone_error(
    body: Mapping[str, object],
    identity: BindingIdentity,
    delete_ref: str,
) -> None:
    error = body.get("error")
    if not isinstance(error, dict) or error.get("code") != "TOMBSTONED":
        raise JourneyError("inspect-tombstone: expected TOMBSTONED error envelope")
    context = error.get("context")
    tombstone = context.get("tombstone") if isinstance(context, dict) else None
    if not isinstance(tombstone, dict):
        raise JourneyError("inspect-tombstone: missing retained tombstone context")
    _expect_tombstone(tombstone, identity, delete_ref)


def _expect_deleted_list_member(
    body: Mapping[str, object],
    identity: BindingIdentity,
    delete_ref: str,
) -> None:
    items = body.get("items")
    tombstones = body.get("tombstones")
    if not isinstance(items, list) or not isinstance(tombstones, list):
        raise JourneyError("list-tombstone: items and tombstones must be arrays")
    if any(isinstance(item, dict) and item.get("jobRef") == identity.job_ref for item in items):
        raise JourneyError("list-tombstone: deleted binding remains in live items")
    matches = [
        item
        for item in tombstones
        if isinstance(item, dict) and item.get("jobRef") == identity.job_ref
    ]
    if len(matches) != 1:
        raise JourneyError("list-tombstone: expected exactly one retained tombstone")
    _expect_tombstone(matches[0], identity, delete_ref)


def _nested_value(body: Mapping[str, object], parent: str, field: str) -> object:
    nested = body.get(parent)
    return nested.get(field) if isinstance(nested, dict) else None


def _expect_status(exchange: Exchange, expected: int) -> None:
    if exchange.status != expected:
        raise JourneyError(
            f"{exchange.label}: expected HTTP {expected}, got {exchange.status}; "
            "see captured response evidence"
        )


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the KCS V2 create/replay/inspect/log/list/delete runtime journey."
    )
    parser.add_argument("--base-url", required=True, help="KCS API origin (HTTPS required)")
    parser.add_argument("--request-json", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="allow HTTP only for an injected local loopback simulation",
    )
    parser.add_argument("--timeout-seconds", type=_positive_float, default=30.0)
    parser.add_argument("--wait-seconds", type=_positive_float, default=120.0)
    parser.add_argument("--poll-seconds", type=_positive_float, default=2.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    token = os.environ.get(SERVICE_TOKEN_ENV)
    if token is None or not token or any(character.isspace() for character in token):
        print(f"error: {SERVICE_TOKEN_ENV} must contain the service token", file=sys.stderr)
        return 2

    try:
        request_body = _load_request(args.request_json)
        evidence = EvidenceWriter(args.evidence_dir)
        client = KcsV2Client(
            base_url=args.base_url,
            token=token,
            timeout_seconds=args.timeout_seconds,
            allow_http=args.allow_http,
            evidence=evidence,
        )
        summary = AttemptJourney(
            client=client,
            evidence=evidence,
            request_body=request_body,
            wait_seconds=args.wait_seconds,
            poll_seconds=args.poll_seconds,
        ).run()
    except JourneyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    binding = summary["binding"]
    assert isinstance(binding, dict)
    print(
        "KCS V2 journey passed: "
        f"jobRef={binding['jobRef']} jobUid={binding['jobUid']} podUid={binding['podUid']}"
    )
    print(f"evidence: {args.evidence_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
