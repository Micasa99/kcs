from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import requests

from kcs.jobs.contracts import RuntimeEventKind
from kcs.jobs.errors import DependencyUnavailableError
from kcs.jobs.observability import EventStore, PrometheusClient, V2Observability


class _Response:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self._payload


class _Session:
    def __init__(self, responses: dict[str, object] | None = None) -> None:
        self._responses = responses

    def get(self, url: str, **_kwargs: object) -> _Response:
        if self._responses is None:
            raise requests.ConnectionError("offline")
        path = "/" + url.split("/", 3)[-1]
        return _Response(self._responses[path])


class _Kube:
    def list_nodes(self) -> list[object]:
        return [
            {
                "metadata": {
                    "name": "gpu-raw",
                    "labels": {"researchcosmos.io/display-compute-node": "compute-gpu"},
                }
            }
        ]

    def list_managed_jobs(self) -> list[object]:
        return []

    def list_managed_pods(self) -> list[object]:
        return []

    def list_runtime_events(self) -> list[object]:
        return []


def _query_payload() -> dict[str, object]:
    def sample(name: str, value: str, **labels: str) -> dict[str, object]:
        return {
            "metric": {"__name__": name, "node": "gpu-raw", **labels},
            "value": [1786114800, value],
        }

    return {
        "status": "success",
        "data": {
            "result": [
                sample("kcs:node_cpu_utilization_percent", "31.2"),
                sample("kcs:node_memory_used_bytes", "1024"),
                sample("kcs:node_memory_total_bytes", "4096"),
                sample("kcs:gpu_utilization_percent", "72", UUID="GPU-1"),
                sample("kcs:gpu_memory_used_mib", "1024", UUID="GPU-1"),
                sample("kcs:gpu_memory_total_mib", "24564", UUID="GPU-1"),
            ]
        },
    }


def test_telemetry_uses_recording_rules_and_preserves_omission(tmp_path: Path) -> None:
    session = _Session({"/api/v1/query": _query_payload()})
    service = V2Observability(
        _Kube(),
        PrometheusClient("http://prometheus", session=session),  # type: ignore[arg-type]
        EventStore(tmp_path / "events.sqlite3"),
        clock=lambda: datetime(2026, 8, 7, 15, 0, 1, tzinfo=UTC),
    )

    payload = service.telemetry_nodes().model_dump(mode="json", by_alias=True, exclude_unset=True)

    assert payload["nodes"] == [
        {
            "computeNode": "compute-gpu",
            "cpu": {"utilizationPercent": 31.2},
            "memory": {"usedBytes": 1024, "totalBytes": 4096},
            "gpus": [
                {
                    "deviceId": "GPU-1",
                    "utilizationPercent": 72.0,
                    "memoryUsedMiB": 1024,
                    "memoryTotalMiB": 24564,
                    "podRef": None,
                }
            ],
        }
    ]


def test_prometheus_outage_is_typed_for_telemetry_but_health_stays_200_shape() -> None:
    client = PrometheusClient("http://prometheus", session=_Session())  # type: ignore[arg-type]

    with pytest.raises(DependencyUnavailableError):
        client.recording_samples()
    assert client.health().model_dump(mode="json", by_alias=True) == {
        "prometheus": "down",
        "dcgm": "down",
        "kubeStateMetrics": "down",
        "oldestScrapeAgeSeconds": None,
    }


def test_event_ring_persists_sequence_and_clips_expired_cursor(tmp_path: Path) -> None:
    path = tmp_path / "events.sqlite3"
    now = datetime(2026, 8, 7, 15, 0, tzinfo=UTC)
    store = EventStore(path, clock=lambda: now, maximum_events=2, retention=timedelta(days=1))
    store.record_state(
        "job:a", "pending", kind=RuntimeEventKind.JOB_PHASE, detail={"phase": "pending"}
    )
    first_cursor = store.page(None, 200).next_cursor
    store.record_state(
        "job:a", "running", kind=RuntimeEventKind.JOB_PHASE, detail={"phase": "running"}
    )
    store.record_state(
        "job:a", "succeeded", kind=RuntimeEventKind.JOB_PHASE, detail={"phase": "succeeded"}
    )
    store.record_state(
        "node:a", "not-ready", kind=RuntimeEventKind.NODE_CONDITION, detail={"ready": False}
    )

    clipped = EventStore(
        path, clock=lambda: now, maximum_events=2, retention=timedelta(days=1)
    ).page(first_cursor, 200)
    assert clipped.truncated is True
    assert [event.sequence for event in clipped.events] == [3, 4]

    reopened = EventStore(path, clock=lambda: now, maximum_events=2, retention=timedelta(days=1))
    reopened.record_state(
        "node:a", "ready", kind=RuntimeEventKind.NODE_CONDITION, detail={"ready": True}
    )
    assert reopened.page(None, 200).events[-1].sequence == 5
