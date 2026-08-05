"""Read-only Kubernetes capacity and pending-Job observations for KCS V2."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol

from kubernetes.utils.quantity import parse_quantity  # type: ignore[import-untyped]

from .contracts import (
    CapacityNodeSnapshot,
    CapacitySnapshot,
    CpuCapacitySnapshot,
    GpuCapacitySnapshot,
    MemoryCapacitySnapshot,
    PendingJobSnapshot,
    QueueReason,
    QueueRequestedResources,
    QueueSnapshot,
)
from .errors import DependencyUnavailableError
from .renderer import MANAGED_BY

MANAGED_LABEL = "researchcosmos.io/managed-by"
MANAGED_SELECTOR = f"{MANAGED_LABEL}={MANAGED_BY}"
DISPLAY_NODE_LABEL = "researchcosmos.io/display-compute-node"
POOL_LABEL = "researchcosmos.io/pool"
GPU_RESOURCE = "nvidia.com/gpu"

_TERMINAL_POD_PHASES = frozenset({"Succeeded", "Failed"})
_IMAGE_PULL_REASONS = frozenset(
    {"ErrImagePull", "ImagePullBackOff", "InvalidImageName", "RegistryUnavailable"}
)
_URL = re.compile(r"\b(?:https?|docker)://\S+", re.IGNORECASE)
_IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")


class ClusterFeedKubeProtocol(Protocol):
    """The read-only adapter surface used to rebuild both snapshots."""

    def list_nodes(self) -> Sequence[object]: ...

    def list_managed_jobs(self) -> Sequence[object]: ...

    def list_managed_pods(self) -> Sequence[object]: ...


@dataclass(frozen=True, slots=True)
class _Requests:
    gpu: int = 0
    cpu_milli: int = 0
    memory_bytes: int = 0

    def __add__(self, other: _Requests) -> _Requests:
        return _Requests(
            gpu=self.gpu + other.gpu,
            cpu_milli=self.cpu_milli + other.cpu_milli,
            memory_bytes=self.memory_bytes + other.memory_bytes,
        )

    def maximum(self, other: _Requests) -> _Requests:
        return _Requests(
            gpu=max(self.gpu, other.gpu),
            cpu_milli=max(self.cpu_milli, other.cpu_milli),
            memory_bytes=max(self.memory_bytes, other.memory_bytes),
        )


class ClusterFeed:
    """Project current apiserver facts without introducing a second state store."""

    def __init__(
        self,
        kube: ClusterFeedKubeProtocol,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._kube = kube
        self._clock = clock or (lambda: datetime.now(UTC))

    def capacity(self) -> CapacitySnapshot:
        try:
            nodes = list(self._kube.list_nodes())
            pods = list(self._kube.list_managed_pods())
            requested_by_node: dict[str, _Requests] = {}
            jobs_by_node: dict[str, set[str]] = {}
            for pod in pods:
                if _pod_phase(pod) in _TERMINAL_POD_PHASES:
                    continue
                node_name = _text(_path(pod, "spec", "node_name"))
                if node_name is None:
                    continue
                requested_by_node[node_name] = requested_by_node.get(
                    node_name, _Requests()
                ) + _pod_requests(_path(pod, "spec"))
                job_ref = _job_ref_for_pod(pod)
                if job_ref is not None:
                    jobs_by_node.setdefault(node_name, set()).add(job_ref)

            snapshots: list[CapacityNodeSnapshot] = []
            for node in nodes:
                node_name = _required_text(node, "metadata", "name")
                labels = _mapping(_path(node, "metadata", "labels"))
                status = _path(node, "status")
                capacity = _mapping(_value(status, "capacity"))
                allocatable = _mapping(_value(status, "allocatable"))
                requests = requested_by_node.get(node_name, _Requests())
                true_conditions = sorted(
                    {
                        condition_type
                        for condition in _sequence(_value(status, "conditions"))
                        if _text(_value(condition, "status")) == "True"
                        and (condition_type := _text(_value(condition, "type"))) is not None
                    }
                )
                snapshots.append(
                    CapacityNodeSnapshot(
                        display_compute_node=_display_node(node_name, labels),
                        pool=_text(labels.get(POOL_LABEL)) or "unlabeled",
                        ready="Ready" in true_conditions,
                        conditions=true_conditions,
                        gpu=GpuCapacitySnapshot(
                            kind=GPU_RESOURCE,
                            capacity=_quantity(capacity.get(GPU_RESOURCE), "gpu"),
                            allocatable=_quantity(allocatable.get(GPU_RESOURCE), "gpu"),
                            requested_by_managed_jobs=requests.gpu,
                        ),
                        cpu=CpuCapacitySnapshot(
                            capacity_milli=_quantity(capacity.get("cpu"), "cpu"),
                            allocatable_milli=_quantity(allocatable.get("cpu"), "cpu"),
                            requested_by_managed_jobs_milli=requests.cpu_milli,
                        ),
                        memory=MemoryCapacitySnapshot(
                            capacity_bytes=_quantity(capacity.get("memory"), "memory"),
                            allocatable_bytes=_quantity(
                                allocatable.get("memory"), "memory"
                            ),
                            requested_by_managed_jobs_bytes=requests.memory_bytes,
                        ),
                        managed_job_count=len(jobs_by_node.get(node_name, set())),
                    )
                )
            snapshots.sort(key=lambda item: item.display_compute_node)
            return CapacitySnapshot(observed_at=self._observed_at(), nodes=snapshots)
        except DependencyUnavailableError:
            raise
        except Exception as exc:
            raise DependencyUnavailableError(
                "Kubernetes capacity observation is unavailable"
            ) from exc

    def display_compute_node(self, node_name: str) -> str:
        """Return the same redacted node identity used by capacity snapshots."""

        try:
            for node in self._kube.list_nodes():
                observed_name = _required_text(node, "metadata", "name")
                if observed_name == node_name:
                    labels = _mapping(_path(node, "metadata", "labels"))
                    return _display_node(observed_name, labels)
        except Exception as exc:
            raise DependencyUnavailableError(
                "Kubernetes compute-node observation is unavailable"
            ) from exc
        raise DependencyUnavailableError(
            "Kubernetes compute-node observation is unavailable"
        )

    def queue(self) -> QueueSnapshot:
        try:
            jobs = list(self._kube.list_managed_jobs())
            pods = list(self._kube.list_managed_pods())
            pods_by_job: dict[str, list[object]] = {}
            for pod in pods:
                job_ref = _job_ref_for_pod(pod)
                if job_ref is not None:
                    pods_by_job.setdefault(job_ref, []).append(pod)

            pending: list[PendingJobSnapshot] = []
            for job in jobs:
                if _job_is_terminal(job):
                    continue
                job_ref = _required_text(job, "metadata", "name")
                job_pods = pods_by_job.get(job_ref, [])
                active_pods = [
                    pod for pod in job_pods if _pod_phase(pod) not in _TERMINAL_POD_PHASES
                ]
                if any(_pod_ready(pod) for pod in active_pods):
                    continue
                if job_pods and not active_pods:
                    continue
                pod = min(active_pods, key=_created_sort_key) if active_pods else None
                pod_spec = (
                    _path(pod, "spec")
                    if pod is not None
                    else _path(job, "spec", "template", "spec")
                )
                requests = _pod_requests(pod_spec)
                reason, message = _queue_reason(job, pod)
                annotations = _mapping(_path(job, "metadata", "annotations"))
                subject_ref = _text(annotations.get("researchcosmos.io/subject-ref"))
                if subject_ref is None:
                    raise ValueError("managed Job is missing its subject-ref annotation")
                pending.append(
                    PendingJobSnapshot(
                        job_ref=job_ref,
                        subject_ref=subject_ref,
                        created_at=_required_datetime(job, "metadata", "creation_timestamp"),
                        reason=reason,
                        message=_bounded_message(message),
                        requested=QueueRequestedResources(
                            gpu=requests.gpu,
                            cpu_milli=requests.cpu_milli,
                            memory_bytes=requests.memory_bytes,
                        ),
                    )
                )
            pending.sort(key=lambda item: (item.created_at, item.job_ref))
            return QueueSnapshot(observed_at=self._observed_at(), pending=pending)
        except DependencyUnavailableError:
            raise
        except Exception as exc:
            raise DependencyUnavailableError("Kubernetes queue observation is unavailable") from exc

    def _observed_at(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("cluster feed clock must be timezone-aware")
        return value


def _display_node(node_name: str, labels: Mapping[str, object]) -> str:
    explicit = _text(labels.get(DISPLAY_NODE_LABEL))
    if explicit is not None:
        return explicit
    return f"compute-{hashlib.sha256(node_name.encode('utf-8')).hexdigest()[:12]}"


def _pod_requests(spec: object) -> _Requests:
    regular = _Requests()
    for container in _sequence(_value(spec, "containers")):
        regular += _resource_map_requests(
            _mapping(_path(container, "resources", "requests"))
        )
    init_maximum = _Requests()
    for container in _sequence(_value(spec, "init_containers")):
        init_maximum = init_maximum.maximum(
            _resource_map_requests(_mapping(_path(container, "resources", "requests")))
        )
    effective = regular.maximum(init_maximum)
    pod_level = _mapping(_path(spec, "resources", "requests"))
    if "cpu" in pod_level:
        effective = _Requests(
            gpu=effective.gpu,
            cpu_milli=_quantity(pod_level.get("cpu"), "cpu"),
            memory_bytes=effective.memory_bytes,
        )
    if "memory" in pod_level:
        effective = _Requests(
            gpu=effective.gpu,
            cpu_milli=effective.cpu_milli,
            memory_bytes=_quantity(pod_level.get("memory"), "memory"),
        )
    return effective + _resource_map_requests(_mapping(_value(spec, "overhead")))


def _resource_map_requests(resources: Mapping[str, object]) -> _Requests:
    return _Requests(
        gpu=_quantity(resources.get(GPU_RESOURCE), "gpu"),
        cpu_milli=_quantity(resources.get("cpu"), "cpu"),
        memory_bytes=_quantity(resources.get("memory"), "memory"),
    )


def _quantity(value: object | None, kind: str) -> int:
    if value is None:
        return 0
    parsed: Decimal = parse_quantity(str(value))
    scaled = parsed * 1000 if kind == "cpu" else parsed
    if scaled < 0 or scaled != scaled.to_integral_value():
        raise ValueError(f"invalid Kubernetes {kind} quantity")
    return int(scaled)


def _queue_reason(job: object, pod: object | None) -> tuple[QueueReason, str]:
    facts = _status_facts(job)
    if pod is not None:
        facts.extend(_status_facts(pod))
    quota_fact = next(
        (
            fact
            for fact in facts
            if any(marker in fact.lower() for marker in ("quota", "resourcequota"))
        ),
        None,
    )
    if quota_fact is not None:
        return QueueReason.QUOTA, quota_fact

    if pod is None:
        return QueueReason.PROVISIONING, "Kubernetes has not created the managed Pod yet"

    for status in _container_statuses(pod):
        waiting = _path(status, "state", "waiting")
        waiting_reason = _text(_value(waiting, "reason"))
        if waiting_reason in _IMAGE_PULL_REASONS:
            return QueueReason.IMAGE_PULL, f"managed Pod image wait: {waiting_reason}"

    for condition in _sequence(_path(pod, "status", "conditions")):
        if (
            _text(_value(condition, "type")) == "PodScheduled"
            and _text(_value(condition, "status")) == "False"
            and _text(_value(condition, "reason")) == "Unschedulable"
        ):
            return (
                QueueReason.UNSCHEDULABLE,
                _text(_value(condition, "message"))
                or "Kubernetes reports the managed Pod as unschedulable",
            )

    phase = _pod_phase(pod)
    if phase in {"Pending", "Running"}:
        return QueueReason.PROVISIONING, (
            next(iter(facts), None)
            or "Kubernetes has not reported the managed Pod ready"
        )
    return QueueReason.UNKNOWN, next(iter(facts), "Kubernetes reported no queue reason")


def _status_facts(resource: object) -> list[str]:
    facts: list[str] = []
    for condition in _sequence(_path(resource, "status", "conditions")):
        for field in ("reason", "message"):
            value = _text(_value(condition, field))
            if value is not None:
                facts.append(value)
    return facts


def _container_statuses(pod: object) -> list[object]:
    status = _path(pod, "status")
    return [
        *_sequence(_value(status, "init_container_statuses")),
        *_sequence(_value(status, "container_statuses")),
    ]


def _bounded_message(value: str) -> str:
    cleaned = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in value
    )
    cleaned = _URL.sub("<redacted-url>", cleaned)
    cleaned = _IP_ADDRESS.sub("<redacted-address>", cleaned)
    cleaned = " ".join(cleaned.split())
    raw = cleaned.encode("utf-8")[:512]
    return raw.decode("utf-8", errors="ignore")


def _job_is_terminal(job: object) -> bool:
    return any(
        _text(_value(condition, "type")) in {"Complete", "Failed"}
        and _text(_value(condition, "status")) == "True"
        for condition in _sequence(_path(job, "status", "conditions"))
    )


def _pod_ready(pod: object) -> bool:
    return _pod_phase(pod) == "Running" and any(
        _text(_value(condition, "type")) == "Ready"
        and _text(_value(condition, "status")) == "True"
        for condition in _sequence(_path(pod, "status", "conditions"))
    )


def _pod_phase(pod: object) -> str:
    return _text(_path(pod, "status", "phase")) or "Unknown"


def _job_ref_for_pod(pod: object) -> str | None:
    labels = _mapping(_path(pod, "metadata", "labels"))
    value = labels.get("batch.kubernetes.io/job-name") or labels.get("job-name")
    return _text(value)


def _created_sort_key(resource: object) -> tuple[str, str]:
    created = _value(_path(resource, "metadata"), "creation_timestamp")
    name = _text(_path(resource, "metadata", "name")) or ""
    return (str(created or ""), name)


def _required_datetime(resource: object, *path: str) -> datetime:
    value = _path(resource, *path)
    if isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None:
        return value
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is not None and parsed.utcoffset() is not None:
            return parsed
    raise ValueError(f"required Kubernetes datetime {'.'.join(path)} is unavailable")


def _required_text(resource: object, *path: str) -> str:
    value = _text(_path(resource, *path))
    if value is None:
        raise ValueError(f"required Kubernetes field {'.'.join(path)} is unavailable")
    return value


def _path(value: object, *parts: str) -> object | None:
    current: object | None = value
    for part in parts:
        current = _value(current, part)
    return current


def _value(value: object | None, name: str) -> object | None:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _mapping(value: object | None) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object | None) -> Sequence[object]:
    return value if isinstance(value, (list, tuple)) else ()


def _text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


__all__ = ["ClusterFeed", "MANAGED_SELECTOR"]
