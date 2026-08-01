# KCS V2 Hosted Attempt API 2.0.0

The wire authority is `openapi/kcs-v2-jobs.openapi.yaml` (OpenAPI 3.1.0). Generated
JSON is compact, key-sorted UTF-8 JSON with one trailing newline. Its identity is the
64-lowercase-hex SHA-256 of those exact bytes. Component JSON Schemas and the checksum
line are deterministic build artifacts; generated output is not the source of truth.

KCS owns provider workload reality only. Provider references are opaque, and KCS does
not import ResearchCosmos state/contracts or infer research success.

## Runtime boundary and topology

The formal namespace is `researchcosmos-v2`; the default node selector is
`researchcosmos.io/pool=gpu`. One provider request creates one `batch/v1 Job`. The first
Pod UID is immutable for that attempt. The Pod has exactly two containers, `agent` and
`workspace`, sharing `/workspace`. A replacement Pod or more than one Pod makes the
attempt `indeterminate` rather than silently changing its identity.

KCS initiates `pods/exec` and runs `/opt/kcs/agent-supervisor rpc` or
`/opt/kcs/workspace-sidecar rpc`. There is no Pod-local TCP listener. Production uses
`KCS_API_MODE=v2`, TLS/private ingress, and fail-closed bearer service authentication
from `KCS_V2_SERVICE_TOKEN`. V2 and legacy use distinct Kubernetes identities.

## Frozen routes

| Purpose | Method and path |
|---|---|
| Create/list | `POST/GET /api/v2/jobs` |
| Inspect/delete | `GET/DELETE /api/v2/jobs/{jobRef}` |
| Role logs | `GET /api/v2/jobs/{jobRef}/logs?container=agent\|workspace&cursor=&limitBytes=` |
| Grant/inspect credential | `POST /api/v2/jobs/{jobRef}/agent/credential-grants`; `GET /api/v2/jobs/{jobRef}/agent/credential-grants/{credentialGrantRef}` |
| Start agent | `POST /api/v2/jobs/{jobRef}/agent/start` |
| Register/inspect transfer | `POST /api/v2/jobs/{jobRef}/transfers`; `GET /api/v2/jobs/{jobRef}/transfers/{transferRef}` |
| Transfer content | `PUT/GET /api/v2/jobs/{jobRef}/transfers/{transferRef}/content` |
| Cancel/discard transfer | `POST .../{transferRef}/cancel`; `DELETE .../{transferRef}` |
| Invoke/inspect workspace | `POST /api/v2/jobs/{jobRef}/workspace/invoke`; `GET /api/v2/jobs/{jobRef}/operations/{operationRef}` |
| Finalize/cancel | `POST /api/v2/jobs/{jobRef}/finalize`; `POST /api/v2/jobs/{jobRef}/cancel` |
| Canonical OpenAPI | `GET /api/v2/openapi.json` |

## Digests and idempotency

Create computes RFC 8785 JCS over `spec` only and hashes those canonical bytes with
SHA-256. Authorization, `Idempotency-Key`, job/action identities, and deadline are
outside the spec payload digest. Raw credential bytes and raw transfer bytes each have
their own SHA-256 and are never conflated with the create digest. Image references must
match `name@sha256:<64 lowercase hex>`.

| Mutation | Identity | Same identity and same payload | Same identity and different payload |
|---|---|---|---|
| Create | `Idempotency-Key` plus spec digest | Return the original job reality | `409` conflict |
| Credential grant | `Idempotency-Key` plus raw credential digest/TTL | Return the original grant | `409` conflict |
| Agent start | `Idempotency-Key` plus launch digest | Return original acceptance/state | `409` conflict |
| Transfer register/cancel/discard | `Idempotency-Key` plus action payload | Return original transfer state | `409` conflict |
| Workspace invoke | `Idempotency-Key` plus invocation spec digest | Return original operation | `409` conflict |
| Finalize/cancel/delete | `Idempotency-Key` plus action payload | Return retained current/terminal reality | `409` conflict |

Idempotency never rewrites observed Kubernetes reality. A missing object with a live
create/delete tombstone is resolved from the namespace-scoped tombstone.

## State machines

Job states are `provisioning`, `running`, `finalizing`, `succeeded`, `failed`,
`canceling`, `canceled`, `indeterminate`, and `deleted`.

| From | Trigger | To | Meaning |
|---|---|---|---|
| create | Job submitted | `provisioning` | Pod UID and nullable provisioning fields are unresolved |
| `provisioning` | First and only Pod becomes usable | `running` | Immutable Pod UID bound; two-container topology verified |
| `provisioning`/`running` | replacement/multiple Pod or irreconcilable observation | `indeterminate` | KCS cannot assert one-attempt reality |
| `running` | finalize accepted | `finalizing` | Successful provider work is quiescing |
| `finalizing` | quiescence succeeds/fails | `succeeded`/`failed` | Terminal workload reality is retained |
| non-terminal | cancel accepted | `canceling` | Interruption begins; output loss is possible |
| `canceling` | interruption observed | `canceled` | Interrupted terminal reality retained |
| any retained state | delete completes | `deleted` | Workload reality removed; tombstone retained |

`finalize` quiesces successful provider work and does not declare research success.
`cancel` interrupts and explicitly reports possible output loss. `delete` removes
workload reality but retains a namespace-scoped tombstone.

Credential grant states are `pending`, `projected`, `acknowledged`,
`deletion_failed`, and `expired`. A Job render declares one deterministic optional
Secret projection, mounted only in `agent` at `/var/run/kcs/credential`. At most one
grant is active. Agent ACK triggers Secret deletion; deletion failure remains
inspectable without exposing the credential.

Transfer states are `registered`, `staging`, `available`, `streaming`, `completed`,
`canceling`, `canceled`, `discarded`, and `failed`. V2.0.0 supports only direct stream.
Control is JSON; content is separate `application/octet-stream`. Stage writes a
temporary file, validates size/digest, then atomically renames. Collect authorizes an
immutable snapshot and verifies the streamed bytes.

Workspace operation states are `accepted`, `running`, `succeeded`, `failed`, and
`indeterminate`. Supervisor and sidecar results retain bounded stdout/stderr independently.

## Frozen limits and defaults

| Item | Default | Maximum/rule |
|---|---:|---:|
| Opaque ref | — | 256 UTF-8 bytes |
| Environment | — | 32 entries; key 64 bytes; value 2048 bytes |
| Environment keys | — | exactly `LANG`, `LC_ALL`, `TZ`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `RC_PUBLIC_RUNTIME_BASE_URL` |
| Launch | — | 1 MiB |
| Credential raw bytes | — | 64 KiB |
| Supervisor stdout/stderr | — | 64 KiB each |
| Logs response | 64 KiB | 1 MiB |
| Direct transfer | — | 100 GiB |
| Pagination | 50 | 200 |
| Agent CPU/memory/GPU | 1 CPU / 2 GiB / 0 | 8 CPU / 32 GiB / GPU forbidden |
| Workspace CPU/memory/GPU | 2 CPU / 8 GiB / 0 | 64 CPU / 256 GiB / 8 GPU |
| Workspace storage | 20 GiB | 100 GiB |
| Deadline | 21600 s | 86400 s |
| Credential TTL | 300 s | 900 s |
| Create/delete tombstone | 604800 s | namespace scoped |

All other live metadata is Job-owned until explicit delete.

## Errors and disclosure

One `ErrorEnvelope` serves `400`, `401`, `403`, `404`, `409`, `410`, `413`, `415`,
`422`, `429`, `500`, `503`, and `504`. It contains a stable code, sanitized message,
retryability, request ID, and optional field details. It never returns raw Kubernetes
objects, raw credential data, Authorization, private ingress metadata, or connection
metadata.

## Artifact generation

Run:

```sh
.venv/bin/python scripts/generate_v2_openapi_artifacts.py --check
```

The check parses the YAML, validates every named sanitized example against its actual
component schema (including decoded-byte/UTF-8 extensions), validates all emitted
Draft 2020-12 component bundles, generates twice, and compares every output byte.
