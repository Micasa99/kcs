"""Namespace-bound Kubernetes operations for the KCS V2 attempt runtime.

The adapter deliberately receives already constructed Kubernetes clients.  Loading a
kubeconfig and deciding whether to use in-cluster credentials belongs to the service
bootstrap, so importing this module never discovers or contacts a cluster.
"""

from __future__ import annotations

import base64
import json
import math
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from .errors import (
    DependencyTimeoutError,
    DependencyUnavailableError,
    InvalidCursorError,
    StaleCursorError,
)

Role = Literal["agent", "workspace"]

_ROLE_NAMES = frozenset(("agent", "workspace"))
_TIMESTAMPED_LOG_LINE = re.compile(r"^(\S+) ?(.*)$")


class BatchV1Api(Protocol):
    """The small generated BatchV1Api surface used by this adapter."""

    def create_namespaced_job(self, *, namespace: str, body: Any) -> Any: ...

    def read_namespaced_job(self, *, name: str, namespace: str) -> Any: ...

    def delete_namespaced_job(
        self,
        *,
        name: str,
        namespace: str,
        propagation_policy: str,
        grace_period_seconds: int | None = None,
    ) -> Any: ...

    def patch_namespaced_job(self, *, name: str, namespace: str, body: Any) -> Any: ...


class CoreV1Api(Protocol):
    """The small generated CoreV1Api surface used by this adapter."""

    def list_namespaced_pod(self, *, namespace: str, label_selector: str) -> Any: ...

    def read_namespaced_pod(self, *, name: str, namespace: str) -> Any: ...

    def read_namespaced_pod_log(self, *, name: str, namespace: str, **kwargs: Any) -> str: ...

    def patch_namespaced_pod(self, *, name: str, namespace: str, body: Any) -> Any: ...

    def create_namespaced_config_map(self, *, namespace: str, body: Any) -> Any: ...

    def read_namespaced_config_map(self, *, name: str, namespace: str) -> Any: ...

    def replace_namespaced_config_map(self, *, name: str, namespace: str, body: Any) -> Any: ...

    def delete_namespaced_config_map(self, *, name: str, namespace: str) -> Any: ...

    def list_namespaced_config_map(
        self, *, namespace: str, label_selector: str | None = None
    ) -> Any: ...

    def create_namespaced_secret(self, *, namespace: str, body: Any) -> Any: ...

    def delete_namespaced_secret(self, *, name: str, namespace: str) -> Any: ...

    def connect_get_namespaced_pod_exec(self, name: str, namespace: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class LogRead:
    """One bounded page of a single immutable Pod/container log stream."""

    content: str
    start_cursor: str
    next_cursor: str | None
    truncated: bool
    terminal: bool
    container_id: str | None


class V2KubeAdapter:
    """A fixed-namespace façade over the BatchV1 and CoreV1 clients."""

    def __init__(
        self,
        namespace: str,
        batch_api: BatchV1Api,
        core_api: CoreV1Api,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not namespace or namespace == "default":
            raise ValueError("the V2 adapter requires a non-default namespace")
        self.namespace = namespace
        self._batch = batch_api
        self._core = core_api
        self._clock = clock or (lambda: datetime.now(UTC))

    def create_job(self, body: Any) -> Any:
        """Create a rendered Job in the adapter namespace."""
        return self._batch.create_namespaced_job(namespace=self.namespace, body=body)

    def read_job(self, job_ref: str) -> Any | None:
        """Read a Job by its deterministic job ref, returning ``None`` for 404."""
        try:
            return self._batch.read_namespaced_job(name=job_ref, namespace=self.namespace)
        except Exception as exc:
            if _status(exc) == 404:
                return None
            raise

    def delete_job(
        self,
        job_ref: str,
        *,
        propagation_policy: str = "Foreground",
        grace_period_seconds: int | None = None,
    ) -> None:
        """Delete a Job and its Pod; an already absent Job is successful."""
        try:
            self._batch.delete_namespaced_job(
                name=job_ref,
                namespace=self.namespace,
                propagation_policy=propagation_policy,
                grace_period_seconds=grace_period_seconds,
            )
        except Exception as exc:
            if _status(exc) == 404:
                return
            raise

    def list_job_pods(self, job_ref: str, job_uid: str | None = None) -> list[Any]:
        """List Pods belonging to one Job using controller-populated labels."""
        selectors = [f"batch.kubernetes.io/job-name={job_ref}"]
        if job_uid is not None:
            selectors.append(f"batch.kubernetes.io/controller-uid={job_uid}")
        result = self._core.list_namespaced_pod(
            namespace=self.namespace,
            label_selector=",".join(selectors),
        )
        return list(_value(result, "items") or ())

    def read_role_logs(
        self,
        job_ref: str,
        pod_uid: str,
        container: str,
        cursor: str | None,
        limit_bytes: int,
    ) -> LogRead:
        """Read a bounded timestamp-based page for ``agent`` or ``workspace``.

        Kubernetes does not expose a byte-offset log API.  The cursor therefore stores
        the last Kubernetes log timestamp and is bound to namespace, Job, Pod UID and
        container.  The API request always carries ``limit_bytes`` and never downloads an
        unbounded stream.  An incomplete final line at the byte limit is withheld,
        reported through ``truncated``, and does not advance the timestamp boundary.
        """
        if container not in _ROLE_NAMES:
            raise ValueError("container must be 'agent' or 'workspace'")
        role = cast(Role, container)
        if limit_bytes < 1:
            raise ValueError("limit_bytes must be positive")

        boundary = self._decode_cursor(cursor, job_ref, pod_uid, role)
        start_cursor = self._encode_cursor(job_ref, pod_uid, role, boundary)
        pod = self._pod_with_uid(job_ref, pod_uid)
        pod_name = str(_value(_value(pod, "metadata"), "name"))
        status = _container_status(pod, role)

        kwargs: dict[str, Any] = {
            "container": container,
            "timestamps": True,
            "limit_bytes": limit_bytes,
        }
        if boundary is not None:
            kwargs["since_seconds"] = self._since_seconds(boundary)
        raw = self._core.read_namespaced_pod_log(
            name=pod_name,
            namespace=self.namespace,
            **kwargs,
        )
        raw = raw or ""
        fetched_bytes = len(raw.encode("utf-8"))
        partial_final_line = fetched_bytes >= limit_bytes and bool(raw) and not raw.endswith("\n")
        content, latest_timestamp = _parse_timestamped_log(
            raw,
            boundary,
            drop_final_partial=partial_final_line,
        )
        content, clipped = _utf8_prefix(content, limit_bytes)
        truncated = clipped or fetched_bytes >= limit_bytes
        terminal = _value(_value(status, "state"), "terminated") is not None
        container_id = _value(status, "container_id")

        next_boundary = latest_timestamp or boundary
        next_cursor = None
        if next_boundary is not None and (truncated or not terminal):
            next_cursor = self._encode_cursor(job_ref, pod_uid, role, next_boundary)
        elif truncated:
            # A single over-limit partial line cannot be advanced safely with the
            # timestamp-only Kubernetes API.  Return the same boundary explicitly
            # instead of claiming those unseen bytes were consumed.
            next_cursor = start_cursor
        return LogRead(
            content=content,
            start_cursor=start_cursor,
            next_cursor=next_cursor,
            truncated=truncated,
            terminal=terminal,
            container_id=str(container_id) if container_id is not None else None,
        )

    def _since_seconds(self, boundary: str) -> int:
        """Translate an absolute cursor boundary to the public Pod log API option."""
        now = self._clock()
        if now.tzinfo is None:
            raise RuntimeError("the Kubernetes adapter clock must be timezone-aware")
        elapsed = (now.astimezone(UTC) - _parse_rfc3339(boundary).astimezone(UTC)).total_seconds()
        # sinceSeconds is integer and relative to apiserver time.  One second of overlap
        # avoids skipping the boundary through rounding; the parser removes duplicates.
        return max(1, math.ceil(elapsed) + 1)

    def patch_job_annotations(self, job_ref: str, annotations: Mapping[str, str]) -> Any:
        return self._batch.patch_namespaced_job(
            name=job_ref,
            namespace=self.namespace,
            body={"metadata": {"annotations": dict(annotations)}},
        )

    def patch_pod_annotations(self, pod_name: str, annotations: Mapping[str, str]) -> Any:
        return self._core.patch_namespaced_pod(
            name=pod_name,
            namespace=self.namespace,
            body={"metadata": {"annotations": dict(annotations)}},
        )

    @staticmethod
    def annotations(resource: Any) -> dict[str, str]:
        metadata = _value(resource, "metadata")
        return dict(_value(metadata, "annotations") or {})

    def create_config_map(self, body: Any) -> Any:
        return self._core.create_namespaced_config_map(namespace=self.namespace, body=body)

    def read_config_map(self, name: str) -> Any | None:
        try:
            return self._core.read_namespaced_config_map(name=name, namespace=self.namespace)
        except Exception as exc:
            if _status(exc) == 404:
                return None
            raise

    def replace_config_map(self, name: str, body: Any) -> Any:
        return self._core.replace_namespaced_config_map(
            name=name,
            namespace=self.namespace,
            body=body,
        )

    def delete_config_map(self, name: str) -> bool:
        try:
            self._core.delete_namespaced_config_map(name=name, namespace=self.namespace)
        except Exception as exc:
            if _status(exc) == 404:
                return False
            raise
        return True

    def list_config_maps(self, label_selector: str | None = None) -> list[Any]:
        result = self._core.list_namespaced_config_map(
            namespace=self.namespace,
            label_selector=label_selector,
        )
        return list(_value(result, "items") or ())

    def create_secret(self, body: Any) -> Any:
        return self._core.create_namespaced_secret(namespace=self.namespace, body=body)

    def delete_secret(self, name: str) -> bool:
        try:
            self._core.delete_namespaced_secret(name=name, namespace=self.namespace)
        except Exception as exc:
            if _status(exc) == 404:
                return False
            raise
        return True

    def exec_supervisor_rpc(
        self, binding: Mapping[str, str], container: str, command: list[str], frame: bytes
    ) -> bytes:
        """Exec a fixed supervisor command in the immutable bound Pod."""
        from kubernetes.stream import stream  # type: ignore[import-untyped]

        pod = self._pod_with_uid(binding["jobRef"], binding["podUid"])
        pod_name = str(_value(_value(pod, "metadata"), "name"))
        websocket: Any = stream(
            self._core.connect_get_namespaced_pod_exec,
            pod_name,
            self.namespace,
            container=container,
            command=command,
            stderr=True,
            stdin=True,
            stdout=True,
            tty=False,
            _preload_content=False,
        )
        websocket.write_stdin(frame.decode("utf-8"))
        output: list[str] = []
        errors: list[str] = []
        deadline = time.monotonic() + 10
        try:
            while websocket.is_open() and time.monotonic() < deadline:
                websocket.update(timeout=1)
                while websocket.peek_stdout():
                    output.append(str(websocket.read_stdout()))
                while websocket.peek_stderr():
                    errors.append(str(websocket.read_stderr()))
            if websocket.is_open():
                raise DependencyTimeoutError("supervisor exec did not complete")
            if errors:
                raise DependencyUnavailableError("supervisor exec returned an error stream")
            status = _exec_status(websocket.read_channel(3))
            if status != 0:
                raise DependencyUnavailableError("supervisor exec did not succeed")
            encoded = "".join(output).encode("utf-8")
            if len(encoded) > 65536:
                raise DependencyUnavailableError("supervisor exec response exceeded its bound")
            return encoded
        except (DependencyTimeoutError, DependencyUnavailableError):
            raise
        except Exception as error:
            raise DependencyUnavailableError("supervisor exec dependency failed") from error
        finally:
            websocket.close()

    def exec_workspace_rpc(
        self,
        binding: Mapping[str, str],
        header_frame: bytes,
        body_path: Path | None,
        response_path: Path,
        max_response_bytes: int,
    ) -> None:
        """Stream raw binary channels through the single fixed workspace RPC argv."""
        from kubernetes.stream import stream

        pod = self._pod_with_uid(binding["jobRef"], binding["podUid"])
        pod_name = str(_value(_value(pod, "metadata"), "name"))
        websocket: Any = stream(
            self._core.connect_get_namespaced_pod_exec,
            pod_name,
            self.namespace,
            container="workspace",
            command=["/opt/kcs/workspace-sidecar", "rpc"],
            stderr=True,
            stdin=True,
            stdout=True,
            tty=False,
            binary=True,
            _preload_content=False,
        )
        written = 0
        try:
            websocket.write_channel(0, header_frame)
            if body_path is not None:
                with body_path.open("rb") as source:
                    while chunk := source.read(1024 * 1024):
                        websocket.write_channel(0, chunk)
            deadline = time.monotonic() + 300
            with response_path.open("wb") as output:
                while websocket.is_open() and time.monotonic() < deadline:
                    websocket.update(timeout=1)
                    while websocket.peek_stdout():
                        chunk = websocket.read_stdout()
                        if not isinstance(chunk, bytes):
                            raise DependencyUnavailableError(
                                "workspace exec returned a non-binary stdout channel"
                            )
                        written += len(chunk)
                        if written > max_response_bytes:
                            raise DependencyUnavailableError(
                                "workspace exec response exceeded its bound"
                            )
                        output.write(chunk)
                    if websocket.peek_stderr():
                        raise DependencyUnavailableError("workspace exec returned an error stream")
                output.flush()
                os.fsync(output.fileno())
            if websocket.is_open():
                raise DependencyTimeoutError("workspace exec did not complete")
            if _exec_status(websocket.read_channel(3)) != 0:
                raise DependencyUnavailableError("workspace exec did not succeed")
        except (DependencyTimeoutError, DependencyUnavailableError):
            raise
        except Exception as error:
            raise DependencyUnavailableError("workspace exec dependency failed") from error
        finally:
            websocket.close()

    def _pod_with_uid(self, job_ref: str, pod_uid: str) -> Any:
        matches = [
            pod
            for pod in self.list_job_pods(job_ref)
            if str(_value(_value(pod, "metadata"), "uid")) == pod_uid
        ]
        if len(matches) != 1:
            raise StaleCursorError()
        return matches[0]

    def _encode_cursor(
        self,
        job_ref: str,
        pod_uid: str,
        container: Role,
        timestamp: str | None,
    ) -> str:
        payload = {
            "v": 1,
            "namespace": self.namespace,
            "jobRef": job_ref,
            "podUid": pod_uid,
            "container": container,
            "timestamp": timestamp,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    def _decode_cursor(
        self,
        cursor: str | None,
        job_ref: str,
        pod_uid: str,
        container: Role,
    ) -> str | None:
        if cursor is None:
            return None
        try:
            padding = "=" * (-len(cursor) % 4)
            decoded = base64.b64decode(cursor + padding, altchars=b"-_", validate=True)
            payload = json.loads(decoded)
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise InvalidCursorError() from exc
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise InvalidCursorError()
        identity = (
            payload.get("namespace"),
            payload.get("jobRef"),
            payload.get("podUid"),
            payload.get("container"),
        )
        if identity != (self.namespace, job_ref, pod_uid, container):
            raise StaleCursorError()
        timestamp = payload.get("timestamp")
        if timestamp is not None and not isinstance(timestamp, str):
            raise InvalidCursorError()
        if timestamp is not None:
            _parse_rfc3339(timestamp)
        return timestamp


def _status(exc: Exception) -> int | None:
    value = getattr(exc, "status", None)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _exec_status(raw: object) -> int:
    """Parse Kubernetes' remote-command status channel without exposing its body."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise DependencyUnavailableError("supervisor exec status was invalid") from error
    if not isinstance(raw, str) or not raw:
        raise DependencyUnavailableError("supervisor exec status was absent")
    try:
        status = json.loads(raw)
    except json.JSONDecodeError as error:
        raise DependencyUnavailableError("supervisor exec status was invalid") from error
    if not isinstance(status, dict):
        raise DependencyUnavailableError("supervisor exec status was invalid")
    if status.get("status") == "Success":
        return 0
    details = status.get("details")
    causes = details.get("causes") if isinstance(details, dict) else None
    if not isinstance(causes, list):
        raise DependencyUnavailableError("supervisor exec status was indeterminate")
    exit_codes = [
        cause.get("message")
        for cause in causes
        if isinstance(cause, dict) and cause.get("reason") == "ExitCode"
    ]
    if len(exit_codes) != 1 or not isinstance(exit_codes[0], str):
        raise DependencyUnavailableError("supervisor exec status was indeterminate")
    try:
        code = int(exit_codes[0])
    except ValueError as error:
        raise DependencyUnavailableError("supervisor exec status was invalid") from error
    if str(code) != exit_codes[0] or code <= 0:
        raise DependencyUnavailableError("supervisor exec status was invalid")
    return code


def _value(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _container_status(pod: Any, role: Role) -> Any | None:
    status = _value(pod, "status")
    for item in _value(status, "container_statuses") or ():
        if _value(item, "name") == role:
            return item
    return None


def _parse_rfc3339(value: str) -> datetime:
    normalized = value
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    # Kubernetes timestamps may have nanoseconds while datetime supports microseconds.
    match = re.match(r"^(.*\.)(\d{6})\d+(?=\+|-)", normalized)
    if match is not None:
        normalized = match.group(1) + match.group(2) + normalized[match.end() :]
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise InvalidCursorError() from exc
    if parsed.tzinfo is None:
        raise InvalidCursorError()
    return parsed


def _parse_timestamped_log(
    raw: str,
    boundary: str | None,
    *,
    drop_final_partial: bool = False,
) -> tuple[str, str | None]:
    content: list[str] = []
    latest: str | None = None
    lines = raw.splitlines(keepends=True)
    boundary_time = _parse_rfc3339(boundary) if boundary is not None else None
    for index, line in enumerate(lines):
        if drop_final_partial and index == len(lines) - 1 and not line.endswith("\n"):
            break
        match = _TIMESTAMPED_LOG_LINE.match(line.rstrip("\n"))
        if match is None:
            content.append(line)
            continue
        timestamp, message = match.groups()
        try:
            timestamp_time = _parse_rfc3339(timestamp)
        except InvalidCursorError:
            content.append(line)
            continue
        if boundary_time is not None and timestamp_time <= boundary_time:
            continue
        latest = timestamp
        content.append(message + ("\n" if line.endswith("\n") else ""))
    return "".join(content), latest


def _utf8_prefix(value: str, limit_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit_bytes:
        return value, False
    prefix = encoded[:limit_bytes]
    while prefix:
        try:
            return prefix.decode("utf-8"), True
        except UnicodeDecodeError as exc:
            prefix = prefix[: exc.start]
    return "", True
