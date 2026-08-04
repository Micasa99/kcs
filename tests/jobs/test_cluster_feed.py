from __future__ import annotations

from datetime import UTC, datetime

from kcs.jobs.cluster_feed import ClusterFeed


class _Kube:
    def __init__(self) -> None:
        resources = {
            "containers": [
                {"resources": {"requests": {"cpu": "1", "memory": "2Gi"}}},
                {
                    "resources": {
                        "requests": {
                            "cpu": "8",
                            "memory": "32Gi",
                            "nvidia.com/gpu": "1",
                        }
                    }
                },
            ]
        }
        self.nodes = [
            {
                "metadata": {"name": "private-control", "labels": {}},
                "status": {
                    "capacity": {"cpu": "16", "memory": "32Gi"},
                    "allocatable": {"cpu": "16", "memory": "31Gi"},
                    "conditions": [{"type": "Ready", "status": "True"}],
                },
            },
            {
                "metadata": {
                    "name": "private-gpu-host",
                    "labels": {
                        "researchcosmos.io/display-compute-node": "gpu-node-1",
                        "researchcosmos.io/pool": "gpu",
                    },
                },
                "status": {
                    "capacity": {
                        "cpu": "44",
                        "memory": "220Gi",
                        "nvidia.com/gpu": "4",
                    },
                    "allocatable": {
                        "cpu": "44",
                        "memory": "210Gi",
                        "nvidia.com/gpu": "4",
                    },
                    "conditions": [{"type": "Ready", "status": "True"}],
                },
            },
        ]
        self.jobs = [
            {
                "metadata": {
                    "name": "ready-job",
                    "creation_timestamp": "2026-08-05T03:00:00Z",
                    "annotations": {"researchcosmos.io/subject-ref": "attempt-ready"},
                },
                "spec": {"template": {"spec": resources}},
                "status": {"conditions": []},
            },
            {
                "metadata": {
                    "name": "pending-job",
                    "creation_timestamp": "2026-08-05T03:01:00Z",
                    "annotations": {"researchcosmos.io/subject-ref": "attempt-pending"},
                },
                "spec": {"template": {"spec": resources}},
                "status": {"conditions": []},
            },
        ]
        self.pods = [
            {
                "metadata": {
                    "name": "ready-pod",
                    "creation_timestamp": "2026-08-05T03:00:01Z",
                    "labels": {"batch.kubernetes.io/job-name": "ready-job"},
                },
                "spec": {**resources, "node_name": "private-gpu-host"},
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True"}],
                },
            },
            {
                "metadata": {
                    "name": "pending-pod",
                    "creation_timestamp": "2026-08-05T03:01:01Z",
                    "labels": {"batch.kubernetes.io/job-name": "pending-job"},
                },
                "spec": resources,
                "status": {
                    "phase": "Pending",
                    "conditions": [
                        {
                            "type": "PodScheduled",
                            "status": "False",
                            "reason": "Unschedulable",
                            "message": (
                                "0/2 nodes available at 10.255.250.2: "
                                "insufficient nvidia.com/gpu"
                            ),
                        }
                    ],
                },
            },
        ]

    def list_nodes(self):
        return self.nodes

    def list_managed_jobs(self):
        return self.jobs

    def list_managed_pods(self):
        return self.pods


def test_capacity_and_queue_are_fresh_kubernetes_projections() -> None:
    observed_at = datetime(2026, 8, 5, 3, 2, tzinfo=UTC)
    feed = ClusterFeed(_Kube(), clock=lambda: observed_at)

    capacity = feed.capacity().model_dump(mode="json", by_alias=True)
    gpu_node = next(node for node in capacity["nodes"] if node["pool"] == "gpu")
    assert gpu_node["displayComputeNode"] == "gpu-node-1"
    assert gpu_node["gpu"] == {
        "kind": "nvidia.com/gpu",
        "capacity": 4,
        "allocatable": 4,
        "requestedByManagedJobs": 1,
    }
    assert gpu_node["cpu"]["requestedByManagedJobsMilli"] == 9000
    assert gpu_node["memory"]["requestedByManagedJobsBytes"] == 34 * 1024**3
    assert gpu_node["managedJobCount"] == 1
    assert all("private-" not in node["displayComputeNode"] for node in capacity["nodes"])
    assert "utilization" not in str(capacity).lower()

    queue = feed.queue().model_dump(mode="json", by_alias=True)
    assert len(queue["pending"]) == 1
    item = queue["pending"][0]
    assert item["jobRef"] == "pending-job"
    assert item["subjectRef"] == "attempt-pending"
    assert item["reason"] == "unschedulable"
    assert item["requested"] == {
        "gpu": 1,
        "cpuMilli": 9000,
        "memoryBytes": 34 * 1024**3,
    }
    assert "10.255.250.2" not in item["message"]
    assert len(item["message"].encode("utf-8")) <= 512
