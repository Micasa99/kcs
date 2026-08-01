# KCS V2 Hosted Attempt API 2.0.0

The wire authority is `openapi/kcs-v2-jobs.openapi.yaml` (OpenAPI 3.1.0). KCS owns
provider workload reality only: it accepts opaque owner references, does not import
ResearchCosmos schemas or state machines, and never infers research success.

Generated OpenAPI JSON is compact, key-sorted UTF-8 JSON with one trailing newline.
Its ETag and artifact identity are the 64-lowercase-hex SHA-256 of those exact bytes.
Generated component schemas and the checksum file are deterministic review artifacts;
the YAML remains the source of truth. The committed
[canonical compact JSON](../openapi/generated/kcs-v2-jobs.openapi.json) and
[checksum](../openapi/generated/kcs-v2-jobs.openapi.sha256) currently have digest
`6c7cc850a81b578a7380b4938030536335b114f68f0a4ccefc9923d1167663d9`.

## Runtime boundary and topology

The formal namespace is `researchcosmos-v2`; the formal node selector is exactly
`researchcosmos.io/pool=gpu`. A development machine is never a formal KCS host.

One `providerRequestId` creates one `batch/v1 Job`. Its first Pod UID is immutable for
the attempt. The Pod has exactly two containers, `agent` and `workspace`, which share
the ephemeral `/workspace` volume. A replacement Pod or more than one observed Pod
makes the binding `indeterminate`; KCS must not silently adopt a new Pod identity.

The container PID 1 commands are fixed to the single-element argv arrays
`["/opt/kcs/agent-supervisor"]` and `["/opt/kcs/workspace-sidecar"]`. KCS later
initiates Kubernetes `pods/exec` with the respective `rpc` subcommand. Neither
container exposes a Pod-local TCP listener.

Production uses `KCS_API_MODE=v2`. All V2 routes use fail-closed Bearer service
authentication from `KCS_V2_SERVICE_TOKEN` over TLS and are reachable only through
private ingress. Credential upload adds the narrower private credential-writer role,
forbidden request-body logging, sensitive-header redaction, and
`Cache-Control: no-store`. V2 and legacy use distinct Kubernetes identities.

## Frozen routes

| Purpose | Method and path |
|---|---|
| Create/list | `POST /api/v2/jobs`; `GET /api/v2/jobs` |
| Inspect/delete | `GET /api/v2/jobs/{jobRef}`; `DELETE /api/v2/jobs/{jobRef}` |
| Role logs | `GET /api/v2/jobs/{jobRef}/logs` |
| Grant/inspect credential | `POST /api/v2/jobs/{jobRef}/agent/credential-grants`; `GET /api/v2/jobs/{jobRef}/agent/credential-grants/{credentialGrantRef}` |
| Start agent generation | `POST /api/v2/jobs/{jobRef}/agent/start` |
| Register/inspect transfer | `POST /api/v2/jobs/{jobRef}/transfers`; `GET /api/v2/jobs/{jobRef}/transfers/{transferRef}` |
| Transfer content | `PUT /api/v2/jobs/{jobRef}/transfers/{transferRef}/content`; `GET /api/v2/jobs/{jobRef}/transfers/{transferRef}/content` |
| Cancel/discard transfer | `POST /api/v2/jobs/{jobRef}/transfers/{transferRef}/cancel`; `DELETE /api/v2/jobs/{jobRef}/transfers/{transferRef}` |
| Invoke/inspect workspace | `POST /api/v2/jobs/{jobRef}/workspace/invoke`; `GET /api/v2/jobs/{jobRef}/operations/{operationRef}` |
| Finalize/cancel | `POST /api/v2/jobs/{jobRef}/finalize`; `POST /api/v2/jobs/{jobRef}/cancel` |
| Canonical OpenAPI | `GET /api/v2/openapi.json` |

The OpenAPI endpoint returns the exact committed canonical JSON with `ETag` equal to
its SHA-256, `X-KCS-API-Version: 2.0.0`, and `Cache-Control: no-store`.

## Identity, digest, replay, and recovery

There is no generic `Idempotency-Key`. Every mutation has one protocol-named
intrinsic identity. Here, "identity field" means only the field or tuple in the
table's intrinsic-identity column; immutable binding metadata such as `agentRunRef`,
generation, or Job/Pod UID may still be part of another mutation's explicit digest
projection. JSON digests are SHA-256 of RFC 8785 JCS over the named projection, and
the intrinsic identity plus `Authorization` are outside it. A declared KCS-owned JSON
digest that does not match recomputation is `DIGEST_MISMATCH`; the platform-owned
workspace `requestDigest` is the explicit exception and is compared, not recomputed.
Reusing a retained identity with changed projected data is `IDENTITY_CONFLICT`.
Every retained response echoes its stable identity and applicable digest or digests.

| Mutation | Intrinsic identity | Exact digest projection | New | Exact replay | Changed identity binding | Unknown-outcome recovery |
|---|---|---|---:|---:|---|---|
| Create job | `providerRequestId` | `specDigest = SHA-256(JCS(spec))` | `201` | `200` | `409 IDENTITY_CONFLICT` | `inspect_job` |
| Grant credential | `credentialGrantRef` | `credentialSha256 = SHA-256(raw body)` and `grantMetadataDigest = SHA-256(JCS({agentRunRef, generation, launchBundleDigest, audience, credentialSha256, ttlSeconds, jobUid, podUid}))` | `201` | `200` | Either digest differs: `409 IDENTITY_CONFLICT` | `inspect_grant` |
| Start agent | `(jobRef, generation)` | KCS-internal `startMetadataDigest = SHA-256(JCS(public request fields except generation))`; it is not supplied by the client | `202` | `200` | `409 IDENTITY_CONFLICT` | `inspect_job` |
| Register transfer | `(jobRef, transferRef)` | `requestDigest = SHA-256(JCS(spec))` | `201` | `200` | `409 IDENTITY_CONFLICT` | `inspect_transfer` |
| Upload transfer bytes | `(jobRef, transferRef)` | `contentSha256 = SHA-256(raw body)` | `200` | `200` | `409 TRANSFER_BYTES_MISMATCH`; invalid declared bytes may be `422` | `inspect_transfer` |
| Cancel transfer | `(jobRef, transferRef, cancelRef)` | `requestDigest = SHA-256(JCS(spec))` | `202` | `200` | `409 IDENTITY_CONFLICT` | `inspect_transfer` |
| Discard transfer | `(jobRef, transferRef, discardRef)` | `requestDigest = SHA-256(JCS({}))` | `200` | `200` | `409 IDENTITY_CONFLICT` | `inspect_transfer` |
| Invoke workspace | `(jobRef, operationRef)` | Platform-owned `requestDigest`; KCS separately stores `storedFrameDigest = SHA-256(JCS(full frame))` | `202` | `200` | Changed platform digest or full frame: `409 IDENTITY_CONFLICT` | `inspect_operation` |
| Finalize job | `(jobRef, finalizeRef)` | `requestDigest = SHA-256(JCS(spec))` | `202` | `200` | `409 IDENTITY_CONFLICT` | `inspect_job` |
| Cancel job | `(jobRef, cancelRef)` | `requestDigest = SHA-256(JCS(spec))` | `202` | `200` | `409 IDENTITY_CONFLICT` | `inspect_job` |
| Delete job | `(jobRef, deleteRef)` | `requestDigest = SHA-256(JCS({}))` | `200` | `200` | `409 IDENTITY_CONFLICT` | `inspect_job` |

The constant empty-object digest used by discard and delete is
`44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`.
An unconfirmed mutation is never guessed to have succeeded or failed; only its
matching inspect route establishes retained reality.

If a create response is lost, recover with
`GET /api/v2/jobs?providerRequestId=<same>&includeDeleted=true`. During live and
tombstone retention this filter returns exactly zero or one matching record across
the live `items` and retained `tombstones` arrays, never one in each. Zero means no
retained create identity is established, so the caller may retry the exact create.
One means the caller must compare the returned `specDigest`: an exact match
establishes the retained live or tombstoned result, while a different digest is an
identity conflict and must not be retried as new. A live match is inspected by
`jobRef`; a tombstone match is handled as retained deletion until its advertised
expiry.

## Create request and physical provider spec

`CreateJobRequest` is exactly:

```json
{
  "providerRequestId": "opaque provider identity",
  "specDigest": "sha256-of-rfc8785-jcs-spec",
  "spec": {}
}
```

`providerRequestId` is outside the digest. `spec` contains every physical input that
can change the rendered Job:

- `subjectRef` and `runtimePlanDigest`;
- pinned `agent` image, fixed supervisor command, CPU/memory resources, and
  `runtimeEnv`;
- pinned `workspace` image, fixed sidecar command, CPU/memory/GPU resources, and
  `runtimeEnv`;
- `sharedWorkspace: {kind: "ephemeral", mountPath: "/workspace", sizeLimitGiB: ...}`;
- the closed `nodeSelector`; and
- `activeDeadlineSeconds`.

Images must match `name@sha256:<64 lowercase hex>`. Mutable images, arbitrary
commands, arbitrary selectors, secret injection, or physical provider facts outside
`spec` are invalid. `spec` has `additionalProperties: false` throughout its semantic
objects.

Omission is distinct from explicitly supplying a documented default. KCS hashes the
exact accepted JSON `spec`; it does not insert defaults into a hidden normalization
projection before hashing. Consequently, an omitted optional default and an explicit
default can render the same resource while retaining different `specDigest` values.

## Job snapshots, list, logs, and lifecycle

Create and its replay, inspect, live list entries, finalize and its replay, and cancel
and its replay use a `JobBindingSnapshot`, not a coarse Job shell. Delete and its
replay instead return `JobTombstone`. A binding snapshot includes:

- `jobRef`, the recoverable `providerHandle`, `providerRequestId`, `subjectRef`,
  `runtimePlanDigest`, and `specDigest`;
- Job UID, nullable first Pod UID, resource version, node, binding state/reason,
  observed Pod count, and created/updated/started/finished/observed timestamps;
- closed `agent` and `workspace` role snapshots with container/image IDs, ready state,
  waiting/running/terminated observation, restart count, exit code/reason,
  start/finish timestamps, and requested resources;
- separately observed CPU, memory, GPU, and storage values. An unavailable observation
  is `null`, never a fabricated zero;
- the latest non-secret generation/supervisor snapshot;
- active and terminal workspace operation refs, credential cleanup observations, and
  transfer observations;
- finalize, cancel, and delete action snapshots, `outputLossPossible`, general
  cleanup, and GPU-release observations.

During provisioning, the schema explicitly permits unresolved Pod, resource version,
node, role, generation, start, and finish observations to be `null`. Absence is not
converted to an invented value.

Job binding states are `provisioning | bound | running | finalizing | succeeded |
failed | canceling | canceled | indeterminate | deleting | deleted`. Role states are
`waiting | running | terminated | unknown | indeterminate`. Replacement or multiple
Pod identity is always visible as `indeterminate`.

| Provider event | Binding transition/observation |
|---|---|
| Create accepted, no immutable Pod yet | `provisioning` |
| First and only Pod identity bound and topology checked | `bound`, then `running` when usable |
| Replacement/multiple Pod or unknowable side effect | `indeterminate` |
| Finalize accepted | `finalizing`, then provider `succeeded`, `failed`, or `indeterminate` |
| Cancel accepted | `canceling`, then `canceled`, `failed`, or `indeterminate`; report output-loss possibility |
| Delete in progress/completed | `deleting`, then workload removed and a `deleted` tombstone retained |

Here `succeeded` means the provider quiesce/workload action succeeded; it says nothing
about the owning research outcome.

`GET /api/v2/jobs` accepts `pageToken`, `pageSize`, `providerRequestId`, `subjectRef`,
repeatable `state`, `createdAfter`, and `includeDeleted`. Results are ordered by
`(createdAt, jobRef)`. Page tokens are opaque, canonically encoded unpadded base64url,
bounded to 4096 bytes, and bound to the namespace and complete filter set. Malformed,
non-canonical, and stale tokens return `INVALID_PAGE_TOKEN` and `STALE_PAGE_TOKEN`
respectively.

Role logs are the actual combined Kubernetes container log, returned as bounded
`content`; they are not modeled as fictitious stdout/stderr streams. A response
includes the requested/input cursor, start cursor, next cursor, truncation and
terminal flags, Job UID, immutable Pod UID, role/container identity, container ID,
and observation time. Cursors are opaque, canonically encoded unpadded base64url,
bounded to 4096 bytes, and bound to namespace, job, immutable Pod, and role.
Malformed, non-canonical, or stale values return `INVALID_CURSOR` or `STALE_CURSOR`.

### Finalize, cancel, and delete

`finalize` is provider-only quiescence. Its closed spec contains only
`operationRefs`, `transferRefs`, and a bounded `drainTimeoutSeconds`, and may name only
already-authorized work. It intentionally has no `providerResultRef` and does not
import or imply a ResearchCosmos outcome.

`cancel` may finish only the pre-authorized collect transfers named by
`finishCollectTransferRefs`; it revokes credentials, stops workloads, observes GPU
release, and reports possible output loss. It never manufactures an output manifest.
Both actions retain terminal Job/Pod/log reality.

Finalize, cancel, and delete each occupy the singular action slot exposed in the Job
snapshot. KCS serializes their state transitions per job. The same action ref and
digest replays the retained action; reusing that ref with another digest is
`IDENTITY_CONFLICT`; an incompatible new action while another transition is active is
`STATE_CONFLICT`. If KCS cannot establish which side effect occurred, it records
`indeterminate` and the caller recovers through job inspection.

`delete` has no request body. `KCS-Delete-Ref` carries `deleteRef` and
`KCS-Request-Digest` carries the constant empty-object digest. Delete first persists
a namespace-scoped `JobTombstone`, then removes workload reality. The tombstone
retains `providerRequestId`, `specDigest`, `jobRef`, original Job/Pod UIDs, final state,
delete ref/digest, cleanup observation, deletion time, and expiry.

The new delete and its exact replay are synchronous `200` responses containing the
tombstone. `deleting` remains useful for inspect/recovery observations while removal
is in progress or its outcome is uncertain. During the seven-day retention window:

- replaying the same delete returns the tombstone with `200`;
- `GET /api/v2/jobs/{jobRef}` and a create with the same identity/spec digest return
  `410 TOMBSTONED` with sanitized tombstone context;
- the same `providerRequestId` with another `specDigest` returns `409`; and
- no new Job or Pod UID may be created.

`includeDeleted=true` adds retained tombstones to the list response's separate
`tombstones` array; tombstones are not coerced into live `JobBindingSnapshot` items.
The tombstone is not an idempotency record for credential, generation, transfer, or
operation mutations, which must fail closed rather than redispatch after job deletion.
After expiry, the deleted resource is unknown, inspect returns `404 NOT_FOUND`, and
the retention guarantee no longer prevents a later authorized create from being
treated as new.

## Private credential grant

`POST /api/v2/jobs/{jobRef}/agent/credential-grants` accepts only
`application/octet-stream`, with at most 64 KiB. Real credential bytes never appear
in JSON, examples, logs, generated review artifacts, or responses; the route-example
suite uses only an explicitly synthetic binary fixture, never a credential JSON
field. The request is
service-to-service only over TLS/private ingress, requires the private credential
writer authorization role, forbids body logging, redacts sensitive headers, and
returns `Cache-Control: no-store`. Bearer service auth is the V2.0.0 wire mechanism;
mTLS is not mandatory.

The request metadata is carried by these typed headers:

| Header | Meaning |
|---|---|
| `KCS-Credential-Grant-Ref` | Client-issued `credentialGrantRef` identity |
| `KCS-Credential-SHA256` | SHA-256 of the raw request bytes |
| `KCS-Grant-Metadata-Digest` | JCS digest of the exact non-secret metadata projection |
| `KCS-Agent-Run-Ref` | Bound AgentRun reference |
| `KCS-Generation` | Positive agent generation |
| `KCS-Launch-Bundle-Digest` | Bound launch bundle digest |
| `KCS-Audience` | Credential audience |
| `KCS-Credential-TTL-Seconds` | Required explicit TTL; use frozen default 300 when no other TTL is selected; maximum 900 seconds |
| `KCS-Job-UID` / `KCS-Pod-UID` | Immutable workload binding |

The metadata digest projection is exactly `{agentRunRef, generation,
launchBundleDigest, audience, credentialSha256, ttlSeconds, jobUid, podUid}`. It
excludes `credentialGrantRef` and the raw body. The TTL header is required, so the
client always hashes an explicit `ttlSeconds` member (normally `300`), never an
omitted member or hidden server default. A replay requires both the exact byte digest
and exact metadata digest. A replay may retry cleanup, but it must never create a
replacement active Secret.

One deterministic optional Secret projection is declared when the Job is rendered.
At most one grant is active; another grant while one is active returns
`409 CREDENTIAL_ACTIVE`. It is mounted only in `agent` at
`/var/run/kcs/credential`; the workspace container cannot read it. A correctly bound
agent ACK triggers Secret deletion. The inspectable, non-secret lifecycle is
`accepted | available | acknowledged | consumed | destroyed | expired | revoked |
destroy_failed | indeterminate`, with a TTL tombstone.

`accepted` means KCS retained the grant metadata and bytes for projection;
`available` means the declared Secret projection is observed; `acknowledged` means
the matching supervisor/AgentRun generation ACKed it; `consumed` is the agent's
non-secret consumption observation; and `destroyed` means the Kubernetes Secret is
observed absent after cleanup. `expired` and `revoked` make the grant unusable and
drive cleanup, `destroy_failed` exposes a failed Secret deletion, and `indeterminate`
means KCS cannot prove the side effect. These states do not claim issuer-side
revocation, erasure from agent memory, or erasure of bytes a workload copied before
ACK. The non-secret record remains inspectable until the returned
`tombstoneExpiresAt`. In particular, retained `expired`, `destroy_failed`, and
`indeterminate` grants remain successful `200` inspect snapshots; they are not
converted to error envelopes merely because their lifecycle state is terminal or
uncertain. After retention ends, inspection may return `404 NOT_FOUND`.

`CredentialGrantSnapshot` never returns credential bytes. It echoes all identity,
byte digest, metadata digest, launch/generation/audience, Job/Pod binding, TTL and
expiry data, ACK binding, timestamps, Secret presence, destruction state/failure,
and observation time.

## Agent generation start

`AgentStartRequest` contains exactly these public fields:

```text
executionEnvelopeRef
executionEnvelopeDigest
agentRunRef
generation
launchBundlePath
launchBundleDigest
launchBundleSizeBytes
materialPaths
credentialGrantRef
```

It contains no launch bytes, token bytes, public `requestDigest`, or caller-supplied
Job/Pod binding. Launch and runtime material must already be staged at normalized safe
relative paths; the launch bundle is limited to 1 MiB. The path `jobRef` supplies the
provider binding, and KCS separately rejects stale immutable Job/Pod reality.

`(jobRef, generation)` is the start identity. KCS computes and exposes the internal
`startMetadataDigest` over all eight non-generation request fields. A same-generation
request replays only when every envelope, launch, material, AgentRun, and grant value
is unchanged. The referenced grant must match the request's `agentRunRef`, generation,
and `launchBundleDigest` and must match the currently retained Job/Pod binding; a
mismatch is a state, stale-binding, replacement-Pod, or identity conflict rather than
a new start. A generation is positive; after generation N is retained, only N+1 is
accepted, and only while the same supervisor and immutable Pod are alive and
generation N's child has a known terminal runner state (`exited` or `failed`). An
`indeterminate` predecessor is not safe to advance.

`materialPaths` binds normalized paths, not new public content digests. Their content
must already have been staged and verified under retained transfer/provider reality;
the start route neither uploads nor replaces it. Runtime code must resolve the
already-staged content before dispatch and must not treat an in-flight or
`indeterminate` transfer as ready. Paths preserve the caller's case, but the list is
case-fold unique so differently cased aliases cannot name one material twice. The
public request shape intentionally adds no transfer refs or material bytes.

The generation snapshot includes generation, AgentRun/envelope identity and digests,
launch path/digest/size, material paths, grant ref, internal metadata digest, runner
state, supervisor liveness, PID/exit code, start/finish/observation timestamps, replay
state, and credential ACK/destruction observation. Runner states are `not_started |
accepted | starting | running | exited | failed | indeterminate`. Pod loss or
replacement produces `indeterminate` and requires a new Attempt, never an in-place
generation. Job inspect exposes the latest generation. Because a later generation
cannot supersede an uncertain or nonterminal predecessor, `inspect_job` remains the
recovery surface for an uncertain start.

## Direct transfers

Registration is exactly `{transferRef, requestDigest, spec}` with the digest over
`spec`. The closed transfer spec contains:

- `direction: stage_input | collect_output`;
- a normalized relative POSIX `path`, never a `/workspace/...` absolute path;
- `declaredSizeBytes`, `authorizedMaxSizeBytes`, and `contentSha256`;
- `mode: direct`; and
- `overwritePolicy: forbid | replace_authorized`.

KCS rejects an empty or absolute path, `.`, `..`, empty/repeated segments, NUL/control
bytes, symlink traversal, Unicode normalization ambiguity, and unauthorized
replacement. It preserves path case but rejects registration when the requested path
case-folds to an existing workspace path.

V2.0.0 supports authenticated direct `application/octet-stream` only, up to 100 GiB.
It exposes no signed URL or transfer token and implements no `Range` request mode.
Clients must use the OpenAPI feature declaration (`transferModes: [direct]`,
`rangeRequests: false`, `signedTransfers: false`) to negotiate or fail closed.

JSON control and content bytes are separate. Stage PUT supplies
`KCS-Content-SHA256` and `Content-Length`; KCS streams to a private temporary file,
counts and hashes bytes, validates the authorized path/size/digest, fsyncs as
applicable, and atomically renames. Interrupted or uncertain installs remain
inspectable and are never exposed as success. A byte-identical replay is idempotent;
mismatched replay bytes cannot replace the final file and return
`409 TRANSFER_BYTES_MISMATCH`. A semantically invalid first upload, such as bytes
that do not satisfy the registered declared size or digest, is a distinct validation
failure and may return `422`; it is not mislabeled as a changed replay.

The transfer registration operation and content PUT have distinct route/action-kind
identity domains even though each is scoped by the same `(jobRef, transferRef)`; their
JSON `requestDigest` and raw `contentSha256` records are never interchangeable.
`collect_output` registration occurs only once an authorized immutable output
snapshot has a declared size and digest. `replace_authorized` is not self-authorizing:
the caller's service policy and retained provider state must permit replacement, or
KCS returns `OVERWRITE_FORBIDDEN`.

Collect GET streams an authorized immutable snapshot and returns `Content-Length`,
`X-Content-SHA256`, `X-KCS-Snapshot-Ref`, and `Cache-Control: no-store`. It never
streams a moving path without a retained snapshot identity.

`TransferSnapshot` echoes transfer identity/request digest, full safe spec, immutable
Job/Pod binding, state, actual size/digest, verification and availability, snapshot
identity, timestamps, sanitized failure reason, and cancel/discard action snapshots.
States are `registered | staging | available | streaming | completed | canceling |
canceled | discarded | failed | indeterminate`. Cancel uses
`{cancelRef, requestDigest, spec}`, where the closed spec has only an optional bounded
`reason`. Discard uses `KCS-Discard-Ref` and the constant empty-object digest. Each has
stable replay; after restart, inspect alone determines whether retry is safe. Cancel
or discard never implies that content disappeared unless the returned snapshot's
availability and action observations establish it.

Retained transfer states, including `indeterminate`, remain `200` inspect snapshots
until their retention ends. An uncertain state is provider reality to reconcile, not
an inspect-route error response; after retention ends the resource may become
`404 NOT_FOUND`.

## Opaque workspace invocation

The workspace invoke body is the complete existing `cosmos.workspace/1` frame object
itself. It is not wrapped in `{method, spec}`, translated, or replaced with a copied
KCS command schema. KCS constrains only that it is a JSON object with
`protocol: "cosmos.workspace/1"` and at most 1 MiB of canonical JSON; all remaining
properties stay opaque. "Forwarded unchanged" means the parsed JSON object and its
member values are not translated, normalized into a KCS command schema, or mutated;
original HTTP whitespace and member order are not separate semantic identity.
Any owner-named or owner-identity fields inside the frame remain uninterpreted opaque
members. KCS neither treats them as authorization/binding inputs nor compares them
with KCS headers or path parameters.

The platform supplies typed metadata in headers:

- `KCS-Operation-Ref`: platform-issued `operationRef`;
- `KCS-Request-Digest`: platform-owned `requestDigest`;
- `KCS-Job-UID`: immutable Job UID; and
- `KCS-Pod-UID`: immutable Pod UID.

The path already supplies `jobRef`. The frame's own `request_digest` and
`frame_digest` fields remain untouched in their original inner protocol domains. KCS
does not silently substitute its platform header digest for either inner digest and
does not copy the owning platform's schemas to interpret them.

KCS additionally computes `storedFrameDigest = SHA-256(JCS(full frame))`, persists it
before dispatch, and echoes it without mutating the frame. Thus a replay requires the
same `operationRef`, platform `requestDigest`, and complete frame. A changed frame is
`409 IDENTITY_CONFLICT` even when its platform digest header was reused.

The supplied `KCS-Job-UID` and `KCS-Pod-UID` must match both current immutable reality
and the retained operation binding. A mismatch returns `STALE_BINDING` or
`REPLACEMENT_POD`; it is not hidden by a matching platform or stored-frame digest.

`WorkspaceOperationSnapshot` binds and exposes both `jobRef` and `operationRef`, plus
the platform request digest, stored full-frame digest, immutable binding, state, exit
code, independently bounded
stdout/stderr and truncation flags, inline-result size/digest and optional bounded
inline object (at most 64 KiB canonical JSON), optional `resultTransferRef` for larger
data, accepted/started/finished/observed timestamps, and sanitized failure reason.
When an inline object is present, its size is the UTF-8 byte length of RFC 8785 JCS and
its digest is SHA-256 of those exact bytes; the value, size, and digest are all null or
all present. An inline result and `resultTransferRef` are mutually exclusive.
Operation states are
`accepted | running | succeeded | failed | indeterminate`; Job inspect lists active
and terminal operation refs. A `resultTransferRef` is reported only when the provider
sidecar/RPC result names an already-authorized collect transfer; KCS does not derive
one by interpreting opaque frame fields.

Retained operation states, including `indeterminate`, remain `200` inspect snapshots
until their retention ends. Inspection reports uncertain reality rather than
converting it to an error; after retention ends the operation may be `404 NOT_FOUND`.

## Frozen states, limits, and defaults

Separate state domains prevent guessed success:

| Domain | Closed states |
|---|---|
| Job binding | `provisioning`, `bound`, `running`, `finalizing`, `succeeded`, `failed`, `canceling`, `canceled`, `indeterminate`, `deleting`, `deleted` |
| Container role | `waiting`, `running`, `terminated`, `unknown`, `indeterminate` |
| Runner generation | `not_started`, `accepted`, `starting`, `running`, `exited`, `failed`, `indeterminate` |
| Credential | `accepted`, `available`, `acknowledged`, `consumed`, `destroyed`, `expired`, `revoked`, `destroy_failed`, `indeterminate` |
| Transfer | `registered`, `staging`, `available`, `streaming`, `completed`, `canceling`, `canceled`, `discarded`, `failed`, `indeterminate` |
| Workspace operation | `accepted`, `running`, `succeeded`, `failed`, `indeterminate` |
| Finalize/cancel/delete action | `not_requested`, `accepted`, `running`, `succeeded`, `failed`, `indeterminate` |
| Secret/resource/GPU cleanup | `not_required`, `pending`, `complete`, `failed`, `indeterminate` |

| Item | Default | Maximum/rule |
|---|---:|---:|
| Opaque ref | — | 256 UTF-8 bytes |
| Runtime environment | — | 32 entries; key 64 bytes; value 2048 bytes |
| Runtime environment keys | — | exactly `LANG`, `LC_ALL`, `TZ`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `RC_PUBLIC_RUNTIME_BASE_URL` |
| Launch bundle | — | 1 MiB |
| Credential raw bytes | — | 64 KiB |
| Workspace frame canonical JSON | — | 1 MiB |
| Workspace operation stdout/stderr | — | 64 KiB each, independently truncated |
| Combined role-log response | 64 KiB | 1 MiB |
| Direct transfer | — | 100 GiB |
| Pagination | 50 | 200 |
| Agent CPU/memory/GPU | 1 CPU / 2 GiB / 0 | 8 CPU / 32 GiB / GPU forbidden |
| Workspace CPU/memory/GPU | 2 CPU / 8 GiB / 0 | 64 CPU / 256 GiB / 8 GPU |
| Shared workspace storage | 20 GiB | 100 GiB |
| Active deadline | 21600 s | 86400 s |
| Credential TTL | 300 s | 900 s |
| Create/delete tombstone | 604800 s | namespace scoped |

All other live metadata is Job-owned until explicit delete.
Requested CPU, memory, and storage snapshot values have a minimum of one; only GPU
requests may be zero where the role permits them.

## Authentication, authorization, and disclosure

Bearer service authentication, TLS, and private ingress are required globally for
all V2 routes. Raw credential upload additionally requires the private
credential-writer role, forbidden body logging, sensitive-header redaction, and
`Cache-Control: no-store`. mTLS may be deployed as an infrastructure
control but is not a V2.0.0 wire requirement. Routes additionally require the
declared service authorization role: `v2-reader`, `v2-mutator`, or, for raw
credential upload, `v2-private-credential-writer`.

| Required role | Routes |
|---|---|
| `v2-reader` | list/inspect jobs, role logs, inspect credential grant, inspect transfer, collect content GET, inspect workspace operation, canonical OpenAPI GET |
| `v2-mutator` | create/delete job, start agent, register/cancel/discard transfer, stage content PUT, invoke workspace, finalize job, cancel job |
| `v2-private-credential-writer` | raw credential grant POST only |

The Bearer token is opaque; mapping an authenticated service identity to these roles
is an implementation policy, not another wire field. Authorization is evaluated on
every request, including an otherwise valid replay; a retained identity never grants
authority by itself.

Legacy/debug identities have no V2 namespace API access, V2 mutation authority,
`pods/exec`, or Secret authority. The later RBAC implementation must enforce this
documented fail-closed matrix.

`runtimeEnv` accepts only the seven public allowlisted keys above and also rejects
secret-shaped values even under an allowed key. Rejected values include proxy URLs
with userinfo; Authorization, Bearer, cookie, API-key, token, secret, or credential
material; PEM blocks; SSH material; and Kubernetes credentials. Secrets, private
hosts, users, SSH paths, tokens, provider keys, and connection metadata must not be
emitted by KCS into tracked files, examples, control-plane logs, errors, or reports.
The authorized role-log route and bounded workspace stdout/stderr or inline results
contain workload-originated data; KCS does not claim an arbitrary workload could not
print a secret. Those responses remain private, authorized surfaces and are never
copied into KCS diagnostics or error envelopes.

Credential upload additionally forbids request-body logging, requires private
ingress, redacts sensitive headers, and uses `Cache-Control: no-store`. Browser/debug
credentials are invalid.

## Typed errors and recovery

One `ErrorEnvelope` serves `400`, `401`, `403`, `404`, `409`, `410`, `413`, `415`,
`422`, `429`, `500`, `503`, and `504`. It carries a closed `code`, sanitized message,
`retryable`, typed `recoveryAction`, request ID, optional field details, and optional
sanitized resource/tombstone context. It never exposes raw Kubernetes objects,
credential bytes, `Authorization`, private ingress metadata, or connection metadata.

The closed code set distinguishes malformed cursor/page token, authentication and
authorization, digest/identity/state/precondition conflicts, stale binding or
replacement Pod, tombstones/not-found, illegal generation, active/expired/
destroy-failed credentials, unsafe paths/overwrite, transfer byte mismatch or
indeterminate transfer, indeterminate operation, payload/media errors, capacity/rate
limits, dependency unavailable/timeout, and sanitized internal failure.

Recovery actions are `retry_same | inspect_job | inspect_grant | inspect_transfer |
inspect_operation | reconcile | new_attempt | none`. `indeterminate` is an explicit
state and recovery condition; it is never collapsed into guessed `failed` or
`succeeded`.

## Artifact generation

Run:

```sh
.venv/bin/python scripts/generate_v2_openapi_artifacts.py --check
```

The check rejects duplicate YAML keys, dangling or invalid references, and an invalid
full OpenAPI 3.1 document. It validates route-level examples against the actual
request/response/header/query/media schemas, verifies semantic JCS and raw-byte
digests plus UTF-8/byte extensions, emits every component schema, generates twice,
and compares those generated outputs byte for byte. The test suite separately
regenerates the artifact set and compares it with the committed canonical JSON,
component schemas, and checksum.
