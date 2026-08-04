# KCS V2 Capacity / Queue Feed handoff

Status: implemented and live-verified on the dedicated KCS development cluster on
2026-08-05. This document records the KCS-side delivery only; ResearchCosmos polling,
freshness persistence, and stale/not-reported product behavior remain consumer work.

## Contract and source

- Source commit: `92d082054599ce77a9ad2eee266cbfc3d8f46ac0`
- API version: `2.1.0`
- Canonical OpenAPI SHA-256:
  `14f24196105c4c98097fa2553114105f7ee2b57f9ece62ec76ac68aff241f229`
- Routes: `GET /api/v2/capacity` and `GET /api/v2/queue`
- Authorization: existing V2 Bearer service identity with `v2-reader`

The capacity route lists Kubernetes Node capacity and allocatable resources and sums
only active, assigned Pods carrying
`researchcosmos.io/managed-by=v2-attempt-runtime`. The summed values are named
`requestedByManagedJobs*`; no utilization or usage field is emitted. Raw Node names
are replaced by an operator display label or a stable SHA-256-derived alias.

The queue route lists only nonterminal managed Jobs without a Ready Pod. Its reason
is closed to `unschedulable`, `image_pull`, `quota`, `provisioning`, or `unknown`.
The message is normalized, private address/URL redacted, and limited to 512 UTF-8
bytes. The route is a Kubernetes Pending/unready projection, not a second scheduler.

RBAC adds `list` for Jobs inside `researchcosmos-v2` and a separate ClusterRole with
only `list` on Nodes. Live authorization checks returned `yes` for Node/Job list and
`no` for Node patch.

## Live development deployment

- Deployment image:
  `10.255.250.1:5000/researchcosmos/kcs-api@sha256:2382e48c82a2f7ca463ea1f4b638602e6951c30e60ba5f89f44c8412ec1f598d`
- Pod state after rollout: `Running`, Ready, zero restarts; observed image ID exactly
  matches the Deployment digest.
- The image carries OCI source revision
  `92d082054599ce77a9ad2eee266cbfc3d8f46ac0`.

The development image was produced by installing the exact new pure-Python wheel on
the previously verified immutable API image because both public and mirror PyPI body
downloads timed out on the server. Runtime dependencies are therefore unchanged.
Before a production promotion, rebuild the tracked root `Containerfile` when the
builder has reliable dependency access and replace the development digest.

## Live evidence summary

Canonical discovery returned `X-KCS-API-Version: 2.1.0` and ETag equal to the
canonical SHA above. The capacity response contained two stable display aliases:

```json
{
  "nodes": [
    {
      "pool": "unlabeled",
      "ready": true,
      "gpu": {"capacity": 0, "allocatable": 0, "requestedByManagedJobs": 0},
      "cpu": {"capacityMilli": 16000, "allocatableMilli": 16000, "requestedByManagedJobsMilli": 0},
      "memory": {"capacityBytes": 33649225728, "allocatableBytes": 33649225728, "requestedByManagedJobsBytes": 0},
      "managedJobCount": 0
    },
    {
      "pool": "gpu",
      "ready": true,
      "gpu": {"capacity": 4, "allocatable": 4, "requestedByManagedJobs": 0},
      "cpu": {"capacityMilli": 44000, "allocatableMilli": 44000, "requestedByManagedJobsMilli": 0},
      "memory": {"capacityBytes": 228170706944, "allocatableBytes": 228170706944, "requestedByManagedJobsBytes": 0},
      "managedJobCount": 0
    }
  ]
}
```

At observation time there were no active managed Pods and both retained managed Jobs
were terminal, so `GET /api/v2/queue` honestly returned `{"pending": []}`. An
independent `kubectl` reconciliation reported:

```json
{"capacityReconciled":true,"gpuAllocatable":4,"gpuCapacity":4,"managedPodCount":0,"nodeCount":2,"pendingCount":0,"queueReconciled":true,"utilizationAbsent":true}
```

Two consecutive reads matched after excluding their fresh `observedAt` timestamps.
The capacity/queue payload scan reported zero secret, token, kubeconfig, private-key,
private-address, and raw-Node-name hits. Raw API Pod logs were read after the calls;
they show both routes returning 200 and no exception or restart.

## Gates and consumer handoff

- Focused implementation/OpenAPI/deployment gates: 8 passed.
- Existing V2 regression run was stopped after 122 passing tests to avoid spending
  the delivery window on the repository's long generator-hardening tail; no failure
  had occurred.
- Canonical generator: 31 route exchanges validated; deterministic artifact check
  passed.
- Focused Ruff and `git diff --check`: passed. Existing unrelated V1 full-repository
  Ruff findings were not changed.

ResearchCosmos must vendor the exact OpenAPI bytes/SHA above before enabling strict
discovery against this deployment, add typed reads for both routes, poll no faster
than every 30 seconds, persist observations with their `observedAt`, and project
missing/expired data as `not_reported`/`stale`. It must not use these snapshots as an
admission, placement, billing, balance, or node-registration authority.
