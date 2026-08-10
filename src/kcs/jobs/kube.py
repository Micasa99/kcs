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
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from kubernetes.utils.quantity import parse_quantity  # type: ignore[import-untyped]

from .errors import (
    DependencyTimeoutError,
    DependencyUnavailableError,
    InvalidCursorError,
    StaleCursorError,
)

Role = Literal["agent", "workspace", "runner", "control"]

_ROLE_NAMES = frozenset(("agent", "workspace", "runner", "control"))
_TIMESTAMPED_LOG_LINE = re.compile(r"^(\S+) ?(.*)$")


class BatchV1Api(Protocol):
    """The small generated BatchV1Api surface used by this adapter."""

    def create_namespaced_job(self, *, namespace: str, body: Any) -> Any: ...

    def read_namespaced_job(self, *, name: str, namespace: str) -> Any: ...

    def list_namespaced_job(self, *, namespace: str, label_selector: str) -> Any: ...

    def delete_namespaced_job(
        self,
        *,
        name: str,
        namespace: str,
        body: Any,
    ) -> Any: ...

    def patch_namespaced_job(self, *, name: str, namespace: str, body: Any) -> Any: ...


class CoreV1Api(Protocol):
    """The small generated CoreV1Api surface used by this adapter."""

    def list_namespaced_pod(self, *, namespace: str, label_selector: str) -> Any: ...

    def list_node(self) -> Any: ...

    def list_namespaced_event(self, *, namespace: str) -> Any: ...

    def read_namespaced_pod(self, *, name: str, namespace: str) -> Any: ...

    def read_namespaced_pod_log(self, *, name: str, namespace: str, **kwargs: Any) -> Any: ...

    def patch_namespaced_pod(self, *, name: str, namespace: str, body: Any) -> Any: ...

    def patch_namespaced_secret(self, *, name: str, namespace: str, body: Any) -> Any: ...

    def create_namespaced_config_map(self, *, namespace: str, body: Any) -> Any: ...

    def read_namespaced_config_map(self, *, name: str, namespace: str) -> Any: ...

    def replace_namespaced_config_map(self, *, name: str, namespace: str, body: Any) -> Any: ...

    def delete_namespaced_config_map(self, *, name: str, namespace: str) -> Any: ...

    def list_namespaced_config_map(
        self, *, namespace: str, label_selector: str | None = None
    ) -> Any: ...

    def create_namespaced_secret(self, *, namespace: str, body: Any) -> Any: ...

    def read_namespaced_secret(self, *, name: str, namespace: str) -> Any: ...

    def delete_namespaced_secret(self, *, name: str, namespace: str, body: Any) -> Any: ...

    def connect_get_namespaced_pod_exec(self, name: str, namespace: str, **kwargs: Any) -> Any: ...

    def create_namespaced_persistent_volume_claim(self, *, namespace: str, body: Any) -> Any: ...

    def read_namespaced_persistent_volume_claim(self, *, name: str, namespace: str) -> Any: ...


class AppsV1Api(Protocol):
    """Deployment surface used only by durable Project Workspace services."""

    def create_namespaced_deployment(self, *, namespace: str, body: Any) -> Any: ...

    def read_namespaced_deployment(self, *, name: str, namespace: str) -> Any: ...


class CustomObjectsApi(Protocol):
    """The metrics.k8s.io read used for one bound Pod observation."""

    def get_namespaced_custom_object(
        self,
        *,
        group: str,
        version: str,
        namespace: str,
        plural: str,
        name: str,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class LogRead:
    """One bounded page of a single immutable Pod/container log stream."""

    content: str
    start_cursor: str
    next_cursor: str | None
    truncated: bool
    terminal: bool
    container_id: str | None


@dataclass(frozen=True, slots=True)
class ExecRead:
    """Bounded output from one fixed, non-interactive Workspace probe."""

    stdout: str
    stderr: str
    exit_code: int


@dataclass(slots=True)
class _TerminalProcess:
    binding: tuple[str, str, str]
    websocket: Any
    output: bytearray
    base_cursor: int
    lock: threading.Lock


class V2KubeAdapter:
    """A fixed-namespace façade over the BatchV1 and CoreV1 clients."""

    def __init__(
        self,
        namespace: str,
        batch_api: BatchV1Api,
        core_api: CoreV1Api,
        *,
        apps_api: AppsV1Api | None = None,
        metrics_api: CustomObjectsApi | None = None,
        exec_core_api_factory: Callable[[], CoreV1Api] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not namespace or namespace == "default":
            raise ValueError("the V2 adapter requires a non-default namespace")
        self.namespace = namespace
        self._batch = batch_api
        self._core = core_api
        self._apps = apps_api
        self._metrics = metrics_api
        self._exec_core_api_factory = exec_core_api_factory or (lambda: self._core)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._terminals: dict[str, _TerminalProcess] = {}
        self._terminals_lock = threading.Lock()

    def create_job(self, body: Any) -> Any:
        """Create a rendered Job in the adapter namespace."""
        return self._batch.create_namespaced_job(namespace=self.namespace, body=body)

    def create_persistent_volume_claim(self, body: Any) -> Any:
        return self._core.create_namespaced_persistent_volume_claim(
            namespace=self.namespace, body=body
        )

    def read_persistent_volume_claim(self, name: str) -> Any | None:
        try:
            return self._core.read_namespaced_persistent_volume_claim(
                name=name, namespace=self.namespace
            )
        except Exception as exc:
            if _status(exc) == 404:
                return None
            raise

    def create_deployment(self, body: Any) -> Any:
        if self._apps is None:
            raise DependencyUnavailableError("Kubernetes Apps API is not configured")
        return self._apps.create_namespaced_deployment(namespace=self.namespace, body=body)

    def read_deployment(self, name: str) -> Any | None:
        if self._apps is None:
            raise DependencyUnavailableError("Kubernetes Apps API is not configured")
        try:
            return self._apps.read_namespaced_deployment(name=name, namespace=self.namespace)
        except Exception as exc:
            if _status(exc) == 404:
                return None
            raise

    def list_pods(self, label_selector: str) -> list[Any]:
        result = self._core.list_namespaced_pod(
            namespace=self.namespace, label_selector=label_selector
        )
        return list(_value(result, "items") or ())

    def read_pod(self, name: str) -> Any | None:
        try:
            return self._core.read_namespaced_pod(name=name, namespace=self.namespace)
        except Exception as exc:
            if _status(exc) == 404:
                return None
            raise

    def bound_pod(self, pod_name: str, pod_uid: str) -> Any:
        pod = self.read_pod(pod_name)
        if pod is None or str(_value(_value(pod, "metadata"), "uid")) != pod_uid:
            raise StaleCursorError()
        return pod

    def project_relay_endpoint(self, pod_name: str, pod_uid: str) -> tuple[str, int]:
        pod = self.bound_pod(pod_name, pod_uid)
        pod_ip = _value(_value(pod, "status"), "pod_ip") or _value(
            _value(pod, "status"), "podIP"
        )
        if not isinstance(pod_ip, str) or not pod_ip:
            raise DependencyUnavailableError("the bound Workspace Pod has no relay address")
        return pod_ip, 8080

    def project_container_image_id(
        self, pod_name: str, pod_uid: str, container: str
    ) -> tuple[str | None, bool]:
        pod = self.bound_pod(pod_name, pod_uid)
        status = _value(pod, "status")
        statuses = list(_value(status, "container_statuses") or ()) + list(
            _value(status, "init_container_statuses") or ()
        )
        for item in statuses:
            if _value(item, "name") == container:
                image_id = _value(item, "image_id") or _value(item, "imageID")
                return (str(image_id) if image_id else None, bool(_value(item, "ready")))
        return None, False

    def list_nodes(self) -> list[Any]:
        """List cluster Node facts for the read-only capacity feed."""
        return list(_value(self._core.list_node(), "items") or ())

    def list_managed_jobs(self) -> list[Any]:
        """List only KCS V2 Jobs in the fixed runtime namespace."""
        from .cluster_feed import MANAGED_SELECTOR

        result = self._batch.list_namespaced_job(
            namespace=self.namespace,
            label_selector=MANAGED_SELECTOR,
        )
        return list(_value(result, "items") or ())

    def list_managed_pods(self) -> list[Any]:
        """List only KCS V2 Pods in the fixed runtime namespace."""
        from .cluster_feed import MANAGED_SELECTOR

        result = self._core.list_namespaced_pod(
            namespace=self.namespace,
            label_selector=MANAGED_SELECTOR,
        )
        return list(_value(result, "items") or ())

    def list_runtime_events(self) -> list[Any]:
        """List namespace Events; the collector applies managed-object filtering."""

        result = self._core.list_namespaced_event(namespace=self.namespace)
        return list(_value(result, "items") or ())

    def read_pod_usage(self, pod_name: str) -> dict[str, dict[str, int]]:
        """Return per-container CPU/memory usage from Metrics Server.

        Absence remains an error at this adapter boundary; the provider turns
        it into nullable observation fields so Job inspection stays usable
        while Metrics Server is warming up.
        """

        if self._metrics is None:
            raise RuntimeError("metrics.k8s.io client is not configured")
        payload = self._metrics.get_namespaced_custom_object(
            group="metrics.k8s.io",
            version="v1beta1",
            namespace=self.namespace,
            plural="pods",
            name=pod_name,
        )
        containers = payload.get("containers") if isinstance(payload, Mapping) else None
        if not isinstance(containers, list):
            raise ValueError("PodMetrics has no containers")
        result: dict[str, dict[str, int]] = {}
        for container in containers:
            if not isinstance(container, Mapping):
                continue
            name = container.get("name")
            usage = container.get("usage")
            if not isinstance(name, str) or not isinstance(usage, Mapping):
                continue
            cpu = parse_quantity(str(usage.get("cpu", ""))) * 1000
            memory = parse_quantity(str(usage.get("memory", ""))) / (1024 * 1024)
            if cpu < 0 or memory < 0:
                raise ValueError("PodMetrics contains a negative quantity")
            result[name] = {
                "cpuMillis": math.ceil(cpu),
                "memoryMiB": math.ceil(memory),
            }
        if not result:
            raise ValueError("PodMetrics contains no usable container observations")
        return result

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
        job_uid: str,
        *,
        propagation_policy: str = "Foreground",
        grace_period_seconds: int | None = None,
    ) -> None:
        """Delete a Job and its Pod; an already absent Job is successful."""
        delete_options: dict[str, Any] = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "propagationPolicy": propagation_policy,
            "preconditions": {"uid": job_uid},
        }
        if grace_period_seconds is not None:
            delete_options["gracePeriodSeconds"] = grace_period_seconds
        try:
            self._batch.delete_namespaced_job(
                name=job_ref,
                namespace=self.namespace,
                body=delete_options,
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
        """Read a bounded timestamp-based page for one hosted or native role.

        Kubernetes does not expose a byte-offset log API.  The cursor therefore stores
        the last Kubernetes log timestamp and is bound to namespace, Job, Pod UID and
        container.  The API request always carries ``limit_bytes`` and never downloads an
        unbounded stream.  An incomplete final line at the byte limit is withheld,
        reported through ``truncated``, and does not advance the timestamp boundary.
        """
        if container not in _ROLE_NAMES:
            raise ValueError("container must be agent, workspace, runner, or control")
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
        response = self._core.read_namespaced_pod_log(
            name=pod_name,
            namespace=self.namespace,
            _preload_content=False,
            **kwargs,
        )
        raw = _decode_log_body(response)
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

    def upsert_secret(self, name: str, body: Any) -> Any:
        """Create or patch one fixed namespace-bound Secret slot."""
        try:
            return self._core.create_namespaced_secret(namespace=self.namespace, body=body)
        except Exception as exc:
            if _status(exc) != 409:
                raise
        return self._core.patch_namespaced_secret(
            name=name,
            namespace=self.namespace,
            body=body,
        )

    def read_secret(self, name: str) -> Any | None:
        """Observe one namespace-bound Secret, returning ``None`` only for a proven 404."""
        try:
            return self._core.read_namespaced_secret(name=name, namespace=self.namespace)
        except Exception as exc:
            if _status(exc) == 404:
                return None
            raise

    def delete_secret(self, name: str, secret_uid: str) -> bool:
        """Request deletion and return true only after namespace-bound absence proof."""
        try:
            self._core.delete_namespaced_secret(
                name=name,
                namespace=self.namespace,
                body={
                    "apiVersion": "v1",
                    "kind": "DeleteOptions",
                    "preconditions": {"uid": secret_uid},
                },
            )
        except Exception as exc:
            if _status(exc) != 404:
                raise
        for attempt in range(20):
            if self.read_secret(name) is None:
                return True
            if attempt < 19:
                time.sleep(0.05)
        return False

    def pod_relay_endpoint(self, job_ref: str, pod_uid: str) -> tuple[str, int]:
        """Return the exact bound Pod IP for the private M2 relay."""
        pod = self._pod_with_uid(job_ref, pod_uid)
        pod_ip = _value(_value(pod, "status"), "pod_ip") or _value(
            _value(pod, "status"), "podIP"
        )
        if not isinstance(pod_ip, str) or not pod_ip:
            raise DependencyUnavailableError("the bound Pod has no routable relay address")
        return pod_ip, 8080

    def pod_container_image_id(
        self, job_ref: str, pod_uid: str, container: str
    ) -> tuple[str | None, bool]:
        pod = self._pod_with_uid(job_ref, pod_uid)
        status = _value(pod, "status")
        statuses = list(_value(status, "container_statuses") or ()) + list(
            _value(status, "init_container_statuses") or ()
        )
        for item in statuses:
            if _value(item, "name") == container:
                image_id = _value(item, "image_id") or _value(item, "imageID")
                return (str(image_id) if image_id else None, bool(_value(item, "ready")))
        return None, False

    def exec_supervisor_rpc(
        self, binding: Mapping[str, str], container: str, command: list[str], frame: bytes
    ) -> bytes:
        """Exec a fixed supervisor command in the immutable bound Pod."""
        from kubernetes.stream import stream  # type: ignore[import-untyped]

        pod = self._pod_with_uid(binding["jobRef"], binding["podUid"])
        pod_name = str(_value(_value(pod, "metadata"), "name"))
        exec_core = self._exec_core_api_factory()
        websocket: Any = stream(
            exec_core.connect_get_namespaced_pod_exec,
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
        # The fixed in-pod RPC client reads one bounded JSON frame from stdin
        # until EOF before it connects to the supervisor socket.  Kubernetes
        # exec keeps channel 0 open after ``write_stdin``; on the negotiated
        # v5 channel protocol it must be closed explicitly or every agent RPC
        # waits until this adapter's deadline and is reported as a 504.
        websocket.close_channel(0)
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

        pod = (
            self.bound_pod(binding["podName"], binding["podUid"])
            if binding.get("runtimeLane") == "project"
            else self._pod_with_uid(binding["jobRef"], binding["podUid"])
        )
        pod_name = str(_value(_value(pod, "metadata"), "name"))
        exec_core = self._exec_core_api_factory()
        lane = binding.get("runtimeLane")
        container = (
            "workspace-control"
            if lane == "project"
            else "control"
            if lane == "native"
            else "workspace"
        )
        websocket: Any = stream(
            exec_core.connect_get_namespaced_pod_exec,
            pod_name,
            self.namespace,
            container=container,
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

    def exec_workspace_readonly(
        self,
        binding: Mapping[str, str],
        command: tuple[str, ...],
        *,
        timeout_seconds: float = 15.0,
        output_limit_bytes: int = 65536,
    ) -> ExecRead:
        """Run one provider-owned read probe in the exact Workspace container.

        The command is supplied only by trusted provider code, never by an API
        request.  Exact Job/Pod UID lookup is repeated immediately before exec,
        so a stale binding cannot drift to a replacement Pod.
        """

        from kubernetes.stream import stream  # type: ignore[import-untyped]

        if not command or timeout_seconds <= 0 or output_limit_bytes < 1:
            raise ValueError("readonly Workspace exec parameters are invalid")
        pod = self._pod_with_uid(binding["jobRef"], binding["podUid"])
        pod_name = str(_value(_value(pod, "metadata"), "name"))
        native = binding.get("runtimeLane") == "native"
        websocket: Any = stream(
            self._exec_core_api_factory().connect_get_namespaced_pod_exec,
            pod_name,
            self.namespace,
            container="runner" if native else "workspace",
            command=list(command),
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
            _preload_content=False,
        )
        stdout: list[str] = []
        stderr: list[str] = []
        observed_bytes = 0
        deadline = time.monotonic() + timeout_seconds
        try:
            while websocket.is_open() and time.monotonic() < deadline:
                websocket.update(timeout=1)
                while websocket.peek_stdout():
                    chunk = str(websocket.read_stdout())
                    observed_bytes += len(chunk.encode("utf-8"))
                    if observed_bytes > output_limit_bytes:
                        raise DependencyUnavailableError(
                            "readonly Workspace probe exceeded its output bound"
                        )
                    stdout.append(chunk)
                while websocket.peek_stderr():
                    chunk = str(websocket.read_stderr())
                    observed_bytes += len(chunk.encode("utf-8"))
                    if observed_bytes > output_limit_bytes:
                        raise DependencyUnavailableError(
                            "readonly Workspace probe exceeded its output bound"
                        )
                    stderr.append(chunk)
            if websocket.is_open():
                raise DependencyTimeoutError("readonly Workspace probe did not complete")
            return ExecRead(
                stdout="".join(stdout),
                stderr="".join(stderr),
                exit_code=_exec_status(websocket.read_channel(3)),
            )
        except (DependencyTimeoutError, DependencyUnavailableError):
            raise
        except Exception as error:
            raise DependencyUnavailableError("readonly Workspace probe failed") from error
        finally:
            websocket.close()

    def open_workspace_terminal(
        self,
        binding: Mapping[str, str],
        terminal_ref: str,
        *,
        rows: int = 24,
        columns: int = 80,
    ) -> None:
        """Open one PTY in the exact Workspace container, never the Agent."""

        from kubernetes.stream import stream  # type: ignore[import-untyped]

        if not terminal_ref or not 1 <= rows <= 1000 or not 1 <= columns <= 1000:
            raise ValueError("terminal parameters are invalid")
        pod = self._pod_with_uid(binding["jobRef"], binding["podUid"])
        pod_name = str(_value(_value(pod, "metadata"), "name"))
        identity = (binding["jobRef"], binding["jobUid"], binding["podUid"])
        with self._terminals_lock:
            if terminal_ref in self._terminals:
                retained = self._terminals[terminal_ref]
                if retained.binding != identity:
                    raise StaleCursorError()
                return
            websocket: Any = stream(
                self._exec_core_api_factory().connect_get_namespaced_pod_exec,
                pod_name,
                self.namespace,
                container="workspace",
                command=["/bin/sh"],
                stderr=True,
                stdin=True,
                stdout=True,
                tty=True,
                _preload_content=False,
            )
            websocket.write_channel(
                4,
                json.dumps({"Height": rows, "Width": columns}, separators=(",", ":")),
            )
            self._terminals[terminal_ref] = _TerminalProcess(
                binding=identity,
                websocket=websocket,
                output=bytearray(),
                base_cursor=0,
                lock=threading.Lock(),
            )

    def write_workspace_terminal(
        self,
        binding: Mapping[str, str],
        terminal_ref: str,
        content: bytes,
    ) -> None:
        if len(content) > 65536:
            raise ValueError("terminal input exceeds its bound")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("terminal input must be UTF-8") from error
        session = self._terminal(binding, terminal_ref)
        with session.lock:
            if not session.websocket.is_open():
                raise StaleCursorError()
            session.websocket.write_stdin(text)

    def read_workspace_terminal(
        self,
        binding: Mapping[str, str],
        terminal_ref: str,
        cursor: int,
        limit_bytes: int,
    ) -> tuple[bytes, int, bool]:
        if cursor < 0 or not 1 <= limit_bytes <= 65536:
            raise ValueError("terminal output cursor or limit is invalid")
        session = self._terminal(binding, terminal_ref)
        with session.lock:
            if session.websocket.is_open():
                session.websocket.update(timeout=0)
                while session.websocket.peek_stdout():
                    session.output.extend(_terminal_bytes(session.websocket.read_stdout()))
                while session.websocket.peek_stderr():
                    session.output.extend(_terminal_bytes(session.websocket.read_stderr()))
                if len(session.output) > 1048576:
                    drop = len(session.output) - 1048576
                    del session.output[:drop]
                    session.base_cursor += drop
            if cursor < session.base_cursor:
                raise StaleCursorError()
            offset = cursor - session.base_cursor
            content = bytes(session.output[offset : offset + limit_bytes])
            next_cursor = cursor + len(content)
            return content, next_cursor, bool(session.websocket.is_open())

    def resize_workspace_terminal(
        self,
        binding: Mapping[str, str],
        terminal_ref: str,
        *,
        rows: int,
        columns: int,
    ) -> None:
        session = self._terminal(binding, terminal_ref)
        with session.lock:
            if not session.websocket.is_open():
                raise StaleCursorError()
            session.websocket.write_channel(
                4,
                json.dumps({"Height": rows, "Width": columns}, separators=(",", ":")),
            )

    def close_workspace_terminal(
        self,
        binding: Mapping[str, str],
        terminal_ref: str,
    ) -> bool:
        identity = (binding["jobRef"], binding["jobUid"], binding["podUid"])
        with self._terminals_lock:
            session = self._terminals.get(terminal_ref)
            if session is None:
                return False
            if session.binding != identity:
                raise StaleCursorError()
            del self._terminals[terminal_ref]
        with session.lock:
            try:
                if session.websocket.is_open():
                    session.websocket.write_stdin("exit\n")
            finally:
                session.websocket.close()
        return True

    def terminal_is_open(self, binding: Mapping[str, str], terminal_ref: str) -> bool:
        try:
            return bool(self._terminal(binding, terminal_ref).websocket.is_open())
        except StaleCursorError:
            return False

    def _terminal(
        self,
        binding: Mapping[str, str],
        terminal_ref: str,
    ) -> _TerminalProcess:
        identity = (binding["jobRef"], binding["jobUid"], binding["podUid"])
        with self._terminals_lock:
            session = self._terminals.get(terminal_ref)
        if session is None or session.binding != identity:
            raise StaleCursorError()
        # A deleted/replaced immutable Pod invalidates the PTY immediately.
        self._pod_with_uid(binding["jobRef"], binding["podUid"])
        return session

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


def _terminal_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise DependencyUnavailableError("Workspace terminal output was invalid")


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


def _decode_log_body(response: object) -> str:
    """Decode the raw Kubernetes log body without the client's ``str(bytes)`` coercion."""
    release = getattr(response, "release_conn", None)
    try:
        body = getattr(response, "data", response)
        if isinstance(body, bytes):
            try:
                return body.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DependencyUnavailableError(
                    "Kubernetes log response is not valid UTF-8"
                ) from exc
        if isinstance(body, str):
            return body
        if body is None:
            return ""
        raise DependencyUnavailableError("Kubernetes log response has an unexpected type")
    finally:
        if callable(release):
            release()


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
