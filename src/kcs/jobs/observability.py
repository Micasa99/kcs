"""Durable KCS runtime events and Prometheus-backed cluster telemetry."""

from __future__ import annotations

import base64
import json
import math
import sqlite3
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol

import requests

from .cluster_feed import display_compute_node
from .contracts import (
    NodeCpuTelemetry,
    NodeMemoryTelemetry,
    NodeTelemetryList,
    NodeTelemetrySnapshot,
    ObservabilityHealth,
    RuntimeEvent,
    RuntimeEventKind,
    RuntimeEventPage,
)
from .errors import DependencyUnavailableError, InvalidCursorError

_RECORDING_RULES = frozenset(
    {
        "kcs:node_cpu_utilization_percent",
        "kcs:node_memory_used_bytes",
        "kcs:node_memory_total_bytes",
        "kcs:gpu_utilization_percent",
        "kcs:gpu_memory_used_mib",
        "kcs:gpu_memory_total_mib",
        "kcs:gpu_temperature_celsius",
        "kcs:gpu_power_watts",
        "kcs:gpu_ecc_volatile_errors",
        "kcs:gpu_xid_last_code",
    }
)
_RECORDING_QUERY = '{__name__=~"' + "|".join(sorted(_RECORDING_RULES)) + '"}'
_MANAGED_LABEL = "researchcosmos.io/managed-by"
_MANAGED_VALUE = "kcs-v2"
_JOB_LABEL = "batch.kubernetes.io/job-name"
_IMAGE_REASONS = frozenset(
    {"ErrImagePull", "ImagePullBackOff", "InvalidImageName", "RegistryUnavailable"}
)
_NATIVE_EVENT_KINDS = {
    "FailedScheduling": RuntimeEventKind.SCHEDULING,
    "FailedMount": RuntimeEventKind.SCHEDULING,
    "FailedAttachVolume": RuntimeEventKind.SCHEDULING,
    "ErrImagePull": RuntimeEventKind.IMAGE_PULL,
    "ImagePullBackOff": RuntimeEventKind.IMAGE_PULL,
    "BackOff": RuntimeEventKind.IMAGE_PULL,
    "OOMKilling": RuntimeEventKind.OOM,
}


class ObservabilityKubeProtocol(Protocol):
    def list_nodes(self) -> Sequence[object]: ...

    def list_managed_jobs(self) -> Sequence[object]: ...

    def list_managed_pods(self) -> Sequence[object]: ...

    def list_runtime_events(self) -> Sequence[object]: ...


class InvalidEventCursorError(InvalidCursorError):
    default_message = "The runtime event cursor is invalid"


@dataclass(frozen=True, slots=True)
class _Sample:
    name: str
    labels: Mapping[str, str]
    timestamp: datetime
    value: float


class PrometheusClient:
    """Small fail-closed client for the KCS-internal Prometheus API."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 3.0,
        session: requests.Session | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._session = session or requests.Session()
        self._clock = clock or (lambda: datetime.now(UTC))

    def recording_samples(self) -> list[_Sample]:
        payload = self._get_json("/api/v1/query", params={"query": _RECORDING_QUERY})
        data = payload.get("data")
        result = data.get("result") if isinstance(data, Mapping) else None
        if payload.get("status") != "success" or not isinstance(result, list):
            raise DependencyUnavailableError("Prometheus returned an invalid telemetry response")
        samples: list[_Sample] = []
        for item in result:
            if not isinstance(item, Mapping):
                continue
            metric = item.get("metric")
            raw_value = item.get("value")
            if (
                not isinstance(metric, Mapping)
                or not isinstance(raw_value, list)
                or len(raw_value) != 2
            ):
                continue
            name = metric.get("__name__")
            if not isinstance(name, str) or name not in _RECORDING_RULES:
                continue
            try:
                timestamp = datetime.fromtimestamp(float(raw_value[0]), UTC)
                value = float(raw_value[1])
            except (TypeError, ValueError, OverflowError):
                continue
            if not math.isfinite(value):
                continue
            labels = {
                str(key): str(label_value)
                for key, label_value in metric.items()
                if isinstance(key, str) and isinstance(label_value, str)
            }
            samples.append(_Sample(name=name, labels=labels, timestamp=timestamp, value=value))
        return samples

    def health(self) -> ObservabilityHealth:
        try:
            payload = self._get_json("/api/v1/targets", params={"state": "active"})
            data = payload.get("data")
            targets = data.get("activeTargets") if isinstance(data, Mapping) else None
            if payload.get("status") != "success" or not isinstance(targets, list):
                raise ValueError("invalid targets payload")
        except Exception:
            return ObservabilityHealth(
                prometheus="down",
                dcgm="down",
                kube_state_metrics="down",
                oldest_scrape_age_seconds=None,
            )

        now = self._aware_now()
        target_health: dict[str, list[bool]] = {
            "kcs-dcgm-exporter": [],
            "kcs-kube-state-metrics": [],
        }
        ages: list[int] = []
        for target in targets:
            if not isinstance(target, Mapping):
                continue
            labels = target.get("labels")
            job = labels.get("job") if isinstance(labels, Mapping) else None
            if isinstance(job, str) and job in target_health:
                target_health[job].append(target.get("health") == "up")
            scraped_at = _parse_time(target.get("lastScrape"))
            if scraped_at is not None:
                ages.append(max(0, int((now - scraped_at).total_seconds())))
        return ObservabilityHealth(
            prometheus="up",
            dcgm=_target_status(target_health["kcs-dcgm-exporter"]),
            kube_state_metrics=_target_status(target_health["kcs-kube-state-metrics"]),
            oldest_scrape_age_seconds=max(ages) if ages else None,
        )

    def _get_json(self, path: str, *, params: Mapping[str, str]) -> Mapping[str, Any]:
        try:
            response = self._session.get(
                f"{self._base_url}{path}",
                params=dict(params),
                timeout=self._timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as error:
            raise DependencyUnavailableError("Prometheus is unavailable") from error
        if not isinstance(payload, Mapping):
            raise DependencyUnavailableError("Prometheus returned a non-object response")
        return payload

    def _aware_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("observability clock must be timezone-aware")
        return now


class EventStore:
    """A bounded SQLite event ring with restart-stable monotonic sequences."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], datetime] | None = None,
        maximum_events: int = 10_000,
        retention: timedelta = timedelta(hours=24),
    ) -> None:
        if maximum_events < 1:
            raise ValueError("maximum_events must be positive")
        if retention <= timedelta(0):
            raise ValueError("retention must be positive")
        self._path = path
        self._clock = clock or (lambda: datetime.now(UTC))
        self._maximum_events = maximum_events
        self._retention = retention
        self._lock = threading.RLock()
        self._initialize()

    def record_state(
        self,
        observation_key: str,
        signature: str,
        *,
        kind: RuntimeEventKind | None = None,
        job_ref: str | None = None,
        compute_node: str | None = None,
        detail: Mapping[str, object] | None = None,
        occurred_at: datetime | None = None,
    ) -> bool:
        if len(observation_key.encode("utf-8")) > 512 or not observation_key:
            raise ValueError("observation key is invalid")
        if len(signature.encode("utf-8")) > 2048:
            raise ValueError("observation signature is too large")
        if kind is None and detail is not None:
            raise ValueError("detail requires an event kind")
        event_time = occurred_at or self._aware_now()
        detail_json = None
        if kind is not None:
            detail_json = _detail_json(detail or {})
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT signature FROM observations WHERE observation_key = ?",
                (observation_key,),
            ).fetchone()
            if prior is not None and prior[0] == signature:
                connection.commit()
                return False
            connection.execute(
                """
                INSERT INTO observations(observation_key, signature, observed_at)
                VALUES (?, ?, ?)
                ON CONFLICT(observation_key) DO UPDATE SET
                    signature = excluded.signature,
                    observed_at = excluded.observed_at
                """,
                (observation_key, signature, event_time.timestamp()),
            )
            if kind is not None:
                connection.execute(
                    """
                    INSERT INTO events(occurred_at, kind, job_ref, compute_node, detail_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        event_time.timestamp(),
                        kind.value,
                        job_ref,
                        compute_node,
                        detail_json,
                    ),
                )
            self._trim(connection, event_time)
            connection.commit()
            return kind is not None

    def page(self, cursor: str | None, limit: int) -> RuntimeEventPage:
        if limit < 1 or limit > 200:
            raise ValueError("event page limit must be between 1 and 200")
        requested = 0 if cursor is None else _decode_cursor(cursor)
        with self._lock, self._connect() as connection:
            now = self._aware_now()
            connection.execute("BEGIN IMMEDIATE")
            self._trim(connection, now)
            bounds = connection.execute(
                "SELECT MIN(sequence), MAX(sequence) FROM events"
            ).fetchone()
            earliest = int(bounds[0]) if bounds and bounds[0] is not None else None
            watermark_row = connection.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = 'events'"
            ).fetchone()
            watermark = int(watermark_row[0]) if watermark_row is not None else 0
            if requested > watermark:
                raise InvalidEventCursorError()
            truncated = requested != 0 and (
                (earliest is not None and requested < earliest - 1)
                or (earliest is None and requested < watermark)
            )
            if truncated:
                start = earliest - 1 if earliest is not None else watermark
            else:
                start = requested
            rows = connection.execute(
                """
                SELECT sequence, occurred_at, kind, job_ref, compute_node, detail_json
                FROM events WHERE sequence > ? ORDER BY sequence ASC LIMIT ?
                """,
                (start, limit),
            ).fetchall()
            connection.commit()
        events = [
            RuntimeEvent(
                sequence=int(row[0]),
                occurred_at=datetime.fromtimestamp(float(row[1]), UTC),
                kind=RuntimeEventKind(str(row[2])),
                job_ref=row[3],
                compute_node=row[4],
                detail=json.loads(str(row[5])),
            )
            for row in rows
        ]
        next_sequence = events[-1].sequence if events else (start if truncated else requested)
        return RuntimeEventPage(
            events=events,
            next_cursor=_encode_cursor(max(0, next_sequence)),
            truncated=truncated,
        )

    def _initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                CREATE TABLE IF NOT EXISTS observations (
                    observation_key TEXT PRIMARY KEY,
                    signature TEXT NOT NULL,
                    observed_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at REAL NOT NULL,
                    kind TEXT NOT NULL,
                    job_ref TEXT,
                    compute_node TEXT,
                    detail_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_occurred_at
                    ON events(occurred_at);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=10, isolation_level=None)

    def _trim(self, connection: sqlite3.Connection, now: datetime) -> None:
        cutoff = (now - self._retention).timestamp()
        connection.execute("DELETE FROM events WHERE occurred_at < ?", (cutoff,))
        threshold = connection.execute(
            "SELECT sequence FROM events ORDER BY sequence DESC LIMIT 1 OFFSET ?",
            (self._maximum_events - 1,),
        ).fetchone()
        if threshold is not None:
            connection.execute("DELETE FROM events WHERE sequence < ?", (int(threshold[0]),))

    def _aware_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("event-store clock must be timezone-aware")
        return now


class RuntimeEventCollector:
    """Project managed Kubernetes state transitions into the durable event ring."""

    def __init__(
        self,
        kube: ObservabilityKubeProtocol,
        store: EventStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._kube = kube
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))

    def collect(self) -> int:
        now = self._aware_now()
        nodes = list(self._kube.list_nodes())
        jobs = list(self._kube.list_managed_jobs())
        pods = list(self._kube.list_managed_pods())
        native_events = list(self._kube.list_runtime_events())
        display_nodes = {
            name: display_compute_node(name, _mapping(_path(node, "metadata", "labels")))
            for node in nodes
            if (name := _text(_path(node, "metadata", "name"))) is not None
        }
        emitted = 0
        for node in nodes:
            emitted += self._collect_node(node, display_nodes, now)
        managed_pod_uids: dict[str, tuple[str | None, str | None]] = {}
        managed_job_uids: dict[str, str] = {}
        for job in jobs:
            emitted += self._collect_job(job, now)
            uid = _text(_path(job, "metadata", "uid"))
            name = _text(_path(job, "metadata", "name"))
            if uid is not None and name is not None:
                managed_job_uids[uid] = name
        for pod in pods:
            labels = _mapping(_path(pod, "metadata", "labels"))
            job_ref = _text(labels.get(_JOB_LABEL))
            node_name = _text(_path(pod, "spec", "node_name"))
            compute_node = display_nodes.get(node_name) if node_name is not None else None
            emitted += self._collect_pod(pod, job_ref, compute_node, now)
            uid = _text(_path(pod, "metadata", "uid"))
            if uid is not None:
                managed_pod_uids[uid] = (job_ref, compute_node)
        for event in native_events:
            emitted += self._collect_native_event(
                event,
                managed_pod_uids,
                managed_job_uids,
                now,
            )
        return emitted

    def _collect_node(
        self,
        node: object,
        display_nodes: Mapping[str, str],
        now: datetime,
    ) -> int:
        name = _text(_path(node, "metadata", "name"))
        uid = _text(_path(node, "metadata", "uid")) or name
        if name is None or uid is None:
            return 0
        conditions = sorted(
            condition_type
            for condition in _sequence(_path(node, "status", "conditions"))
            if _text(_value(condition, "status")) == "True"
            and (condition_type := _text(_value(condition, "type"))) is not None
        )
        detail: dict[str, object] = {"ready": "Ready" in conditions, "conditions": conditions}
        signature = _signature(detail)
        return int(
            self._store.record_state(
                f"node:{uid}",
                signature,
                kind=RuntimeEventKind.NODE_CONDITION,
                compute_node=display_nodes[name],
                detail=detail,
                occurred_at=now,
            )
        )

    def _collect_job(self, job: object, now: datetime) -> int:
        uid = _text(_path(job, "metadata", "uid"))
        job_ref = _text(_path(job, "metadata", "name"))
        if uid is None or job_ref is None:
            return 0
        status = _path(job, "status")
        phase = "pending"
        reason: str | None = None
        for condition in _sequence(_value(status, "conditions")):
            if _text(_value(condition, "status")) != "True":
                continue
            condition_type = _text(_value(condition, "type"))
            if condition_type == "Complete":
                phase = "succeeded"
                reason = _bounded_token(_text(_value(condition, "reason")))
            elif condition_type == "Failed":
                phase = "failed"
                reason = _bounded_token(_text(_value(condition, "reason")))
            elif condition_type == "Suspended":
                phase = "suspended"
        if phase == "pending" and _integer(_value(status, "active"), 0) > 0:
            phase = "running"
        detail: dict[str, object] = {"phase": phase}
        if reason is not None:
            detail["reason"] = reason
        return int(
            self._store.record_state(
                f"job:{uid}:phase",
                _signature(detail),
                kind=RuntimeEventKind.JOB_PHASE,
                job_ref=job_ref,
                detail=detail,
                occurred_at=now,
            )
        )

    def _collect_pod(
        self,
        pod: object,
        job_ref: str | None,
        compute_node: str | None,
        now: datetime,
    ) -> int:
        uid = _text(_path(pod, "metadata", "uid"))
        if uid is None:
            return 0
        emitted = 0
        scheduled = next(
            (
                condition
                for condition in _sequence(_path(pod, "status", "conditions"))
                if _text(_value(condition, "type")) == "PodScheduled"
            ),
            None,
        )
        if scheduled is not None and _text(_value(scheduled, "status")) == "False":
            detail: dict[str, object] = {
                "state": "pending",
                "reason": _bounded_token(_text(_value(scheduled, "reason"))) or "unknown",
            }
            emitted += int(
                self._store.record_state(
                    f"pod:{uid}:scheduling",
                    _signature(detail),
                    kind=RuntimeEventKind.SCHEDULING,
                    job_ref=job_ref,
                    compute_node=compute_node,
                    detail=detail,
                    occurred_at=now,
                )
            )
        else:
            self._store.record_state(f"pod:{uid}:scheduling", "clear")

        statuses = [
            *_sequence(_path(pod, "status", "init_container_statuses")),
            *_sequence(_path(pod, "status", "container_statuses")),
        ]
        for status in statuses:
            container = _bounded_token(_text(_value(status, "name"))) or "unknown"
            waiting = _path(status, "state", "waiting")
            waiting_reason = _text(_value(waiting, "reason"))
            if waiting_reason in _IMAGE_REASONS:
                detail = {"container": container, "reason": waiting_reason}
                emitted += int(
                    self._store.record_state(
                        f"pod:{uid}:image:{container}",
                        _signature(detail),
                        kind=RuntimeEventKind.IMAGE_PULL,
                        job_ref=job_ref,
                        compute_node=compute_node,
                        detail=detail,
                        occurred_at=now,
                    )
                )
            else:
                self._store.record_state(f"pod:{uid}:image:{container}", "clear")
            terminated = _path(status, "last_state", "terminated")
            if _text(_value(terminated, "reason")) == "OOMKilled":
                restart_count = _integer(_value(status, "restart_count"), 0)
                detail = {"container": container, "restartCount": restart_count}
                emitted += int(
                    self._store.record_state(
                        f"pod:{uid}:oom:{container}",
                        _signature(detail),
                        kind=RuntimeEventKind.OOM,
                        job_ref=job_ref,
                        compute_node=compute_node,
                        detail=detail,
                        occurred_at=now,
                    )
                )
        return emitted

    def _collect_native_event(
        self,
        event: object,
        managed_pods: Mapping[str, tuple[str | None, str | None]],
        managed_jobs: Mapping[str, str],
        now: datetime,
    ) -> int:
        involved = _value(event, "involved_object")
        uid = _text(_value(involved, "uid"))
        if uid is None:
            return 0
        job_ref: str | None = None
        compute_node: str | None = None
        if uid in managed_pods:
            job_ref, compute_node = managed_pods[uid]
        elif uid in managed_jobs:
            job_ref = managed_jobs[uid]
        else:
            return 0
        reason = _text(_value(event, "reason"))
        kind = _NATIVE_EVENT_KINDS.get(reason or "")
        if kind is None:
            return 0
        event_uid = _text(_path(event, "metadata", "uid"))
        if event_uid is None:
            return 0
        count = _integer(_value(event, "count"), 1)
        detail: dict[str, object] = {"reason": reason or "unknown", "count": count}
        return int(
            self._store.record_state(
                f"kubernetes-event:{event_uid}",
                str(count),
                kind=kind,
                job_ref=job_ref,
                compute_node=compute_node,
                detail=detail,
                occurred_at=_event_time(event) or now,
            )
        )

    def _aware_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("event collector clock must be timezone-aware")
        return now


class V2Observability:
    """Public service boundary shared by the additive V2 observability routes."""

    def __init__(
        self,
        kube: ObservabilityKubeProtocol,
        prometheus: PrometheusClient,
        events: EventStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._kube = kube
        self._prometheus = prometheus
        self._events = events
        self._clock = clock or (lambda: datetime.now(UTC))
        self._collector = RuntimeEventCollector(kube, events, clock=self._clock)

    def telemetry_nodes(self) -> NodeTelemetryList:
        samples = self._prometheus.recording_samples()
        now = self._aware_now()
        observed_at = max((sample.timestamp for sample in samples), default=now)
        nodes = self._node_payloads(samples)
        return NodeTelemetryList(observed_at=observed_at, kcs_now=now, nodes=nodes)

    def events(self, cursor: str | None, limit: int) -> RuntimeEventPage:
        return self._events.page(cursor, limit)

    def healthz(self) -> ObservabilityHealth:
        return self._prometheus.health()

    def collect(self) -> int:
        return self._collector.collect()

    def record_runner_phase(
        self,
        job_ref: str,
        compute_node: str | None,
        generation: int,
        observation: Mapping[str, object],
    ) -> bool:
        """Persist one deduplicated launcher-authored runner transition."""
        process_exit = observation.get("processExit")
        protocol_terminal = observation.get("protocolTerminal")
        if not isinstance(process_exit, Mapping) or not isinstance(
            protocol_terminal, Mapping
        ):
            raise DependencyUnavailableError("native runner observation is malformed")
        detail: dict[str, object] = {
            "generation": generation,
            "state": observation["state"],
            "sequence": observation["sequence"],
            "stateDigest": observation["stateDigest"],
            "stopCause": observation["stopCause"],
            "processExitKind": process_exit["kind"],
            "exitCode": process_exit.get("exitCode"),
            "signal": process_exit.get("signal"),
            "protocolTerminalObserved": protocol_terminal["observed"],
        }
        observed_at = _parse_time(observation.get("observedAt")) or self._aware_now()
        return self._events.record_state(
            f"runner:{job_ref}:{generation}",
            str(observation["stateDigest"]),
            kind=RuntimeEventKind.RUNNER_PHASE,
            job_ref=job_ref,
            compute_node=compute_node,
            detail=detail,
            occurred_at=observed_at,
        )

    def _node_payloads(self, samples: Sequence[_Sample]) -> list[NodeTelemetrySnapshot]:
        node_values: dict[str, dict[str, float]] = {}
        gpu_values: dict[tuple[str, str], dict[str, object]] = {}
        for sample in samples:
            node = _sample_label(sample.labels, "node", "Hostname", "hostname")
            if node is None:
                continue
            if sample.name.startswith("kcs:node_"):
                node_values.setdefault(node, {})[sample.name] = sample.value
                continue
            device = _sample_label(sample.labels, "UUID", "uuid", "device", "gpu")
            if device is None:
                continue
            gpu_payload_values = gpu_values.setdefault(
                (node, device), {"deviceId": device, "podRef": _pod_ref(sample.labels)}
            )
            if gpu_payload_values["podRef"] is None:
                gpu_payload_values["podRef"] = _pod_ref(sample.labels)
            field = {
                "kcs:gpu_utilization_percent": "utilizationPercent",
                "kcs:gpu_memory_used_mib": "memoryUsedMiB",
                "kcs:gpu_memory_total_mib": "memoryTotalMiB",
                "kcs:gpu_temperature_celsius": "temperatureCelsius",
                "kcs:gpu_power_watts": "powerWatts",
                "kcs:gpu_ecc_volatile_errors": "eccVolatileErrors",
                "kcs:gpu_xid_last_code": "xidLastCode",
            }.get(sample.name)
            if field is None:
                continue
            if field in {"memoryUsedMiB", "memoryTotalMiB", "eccVolatileErrors", "xidLastCode"}:
                gpu_payload_values[field] = max(0, int(sample.value))
            elif field == "utilizationPercent" and 0 <= sample.value <= 100:
                gpu_payload_values[field] = float(sample.value)
            elif field in {"temperatureCelsius", "powerWatts"} and sample.value >= 0:
                gpu_payload_values[field] = float(sample.value)

        nodes_from_cluster = list(self._kube.list_nodes())
        display_by_name = {
            name: display_compute_node(name, _mapping(_path(node, "metadata", "labels")))
            for node in nodes_from_cluster
            if (name := _text(_path(node, "metadata", "name"))) is not None
        }
        # Kubernetes is authoritative for the node set.  Ignore stale or
        # malformed Prometheus labels instead of projecting phantom nodes.
        raw_names = sorted(display_by_name)
        if len(raw_names) > 64:
            raise DependencyUnavailableError("Prometheus returned more than 64 compute nodes")
        result: list[NodeTelemetrySnapshot] = []
        for raw_name in raw_names:
            node_sample_values = node_values.get(raw_name, {})
            node_payload: dict[str, object] = {
                "computeNode": display_by_name.get(raw_name, display_compute_node(raw_name, {})),
                "gpus": [
                    gpu_payload
                    for (node, _device), gpu_payload in sorted(gpu_values.items())
                    if node == raw_name
                ][:16],
            }
            cpu = node_sample_values.get("kcs:node_cpu_utilization_percent")
            if cpu is not None and 0 <= cpu <= 100:
                node_payload["cpu"] = NodeCpuTelemetry(utilization_percent=float(cpu))
            memory_used = node_sample_values.get("kcs:node_memory_used_bytes")
            memory_total = node_sample_values.get("kcs:node_memory_total_bytes")
            if (
                memory_used is not None
                and memory_total is not None
                and 0 <= memory_used <= memory_total
                and memory_total >= 1
            ):
                node_payload["memory"] = NodeMemoryTelemetry(
                    used_bytes=int(memory_used),
                    total_bytes=int(memory_total),
                )
            try:
                result.append(NodeTelemetrySnapshot.model_validate(node_payload))
            except ValueError as error:
                raise DependencyUnavailableError(
                    "Prometheus telemetry values were invalid"
                ) from error
        return result

    def _aware_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("observability clock must be timezone-aware")
        return now


def _target_status(values: Sequence[bool]) -> Literal["up", "down"]:
    return "up" if values and all(values) else "down"


def _encode_cursor(sequence: int) -> str:
    payload = f"v1:{sequence}".encode("ascii")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> int:
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode((cursor + padding).encode("ascii")).decode("ascii")
        version, separator, value = raw.partition(":")
        if separator != ":" or version != "v1" or not value.isdigit():
            raise ValueError
        sequence = int(value)
        if sequence < 0:
            raise ValueError
        return sequence
    except (UnicodeError, ValueError):
        raise InvalidEventCursorError() from None


def _detail_json(detail: Mapping[str, object]) -> str:
    encoded = json.dumps(detail, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 1024:
        raise ValueError("event detail exceeds 1 KiB")
    return encoded


def _signature(detail: Mapping[str, object]) -> str:
    return _detail_json(detail)


def _sample_label(labels: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        value = labels.get(name)
        if value:
            return value[:253]
    return None


def _pod_ref(labels: Mapping[str, str]) -> str | None:
    pod = _sample_label(labels, "pod")
    if pod is None:
        return None
    namespace = _sample_label(labels, "namespace")
    return f"{namespace}/{pod}"[:256] if namespace is not None else pod[:256]


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _event_time(event: object) -> datetime | None:
    for value in (
        _value(event, "event_time"),
        _value(event, "last_timestamp"),
        _path(event, "metadata", "creation_timestamp"),
    ):
        if isinstance(value, datetime):
            return value.astimezone(UTC) if value.tzinfo is not None else None
        parsed = _parse_time(value)
        if parsed is not None:
            return parsed
    return None


def _bounded_token(value: str | None) -> str | None:
    if value is None:
        return None
    sanitized = "".join(
        character for character in value if character.isalnum() or character in "._-"
    )
    return sanitized[:128] or None


def _integer(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, str)):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object) -> Sequence[object]:
    return value if isinstance(value, (list, tuple)) else ()


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _value(value: object, name: str) -> object:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _path(value: object, *names: str) -> object:
    current = value
    for name in names:
        current = _value(current, name)
    return current
