# KCS V2 Attempt Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a canonical, independently recoverable KCS V2 Attempt Runtime in which one provider request owns one fixed `agent + workspace` Kubernetes Job/Pod, with real deployment on the dedicated KCS control server and separate GPU worker.

**Architecture:** Keep legacy `/api/v1` container and shell functions as debug-only code, but build V2 as a separate `kcs.jobs` domain with its own fail-closed service authentication, Kubernetes client/identity, namespace, Job renderer, Kubernetes-backed idempotency records, and provider orchestration. Use Job/Pod annotations, Job-owned ConfigMaps, a predeclared optional Secret projection, and namespace-scoped create/delete tombstones as recoverable reality; do not add a central database. KCS controls fixed supervisor/sidecar RPC commands through Kubernetes `pods/exec`; neither formal container opens a Pod-local TCP listener.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, Kubernetes Python client, RFC 8785 JCS, PyYAML, pytest/httpx, Ruff, Mypy, OCI images, k3s/containerd, NVIDIA device plugin.

## Execution adjustment: runtime evidence first

Per the owner direction on 2026-08-01, execute the remaining tasks as working vertical
slices rather than expanding defensive test matrices. Keep only narrow contract checks
that fail for a real runtime invariant. The primary sequence is `create -> Job/Pod ->
inspect/log -> transfer/invoke -> start/cancel/delete`, followed by the dedicated-server
standalone Journey. Completion evidence comes from raw API responses, Kubernetes
Job/Pod/events, both role logs, file digests, restart behavior, and resource cleanup;
test counts are supporting evidence only. The development Mac remains a source, build,
and deployment client and must not run the formal KCS/k3s runtime.

## Global Constraints

- Actual implementation base: `origin/main@8ca9be59028522e35d39ecae131b6e9ffd5f4c74`; design-review baseline: `6f3d85102616bd4ab35a690f31179ed06c7a23e5`.
- Formal API version is `2.0.0`; canonical source is `openapi/kcs-v2-jobs.openapi.yaml`; generated canonical JSON is hashed with lowercase SHA-256 hex.
- Digest wire representation is exactly 64 lowercase hexadecimal characters. Create hashes RFC 8785 JCS of `spec` only. Every other mutation hashes its schema-defined payload only; identity refs and Authorization are excluded. Raw transfer/credential bytes have a separate byte SHA-256.
- `/api/v2/jobs` is the only formal Hosted Work Agent entry point. `/api/v1` remains debug-only and must never select, exec, upload to, or mutate a V2 managed resource.
- One `providerRequestId` creates at most one `batch/v1 Job`; the first observed Pod UID becomes immutable binding reality. A second/replacement Pod UID makes the binding `indeterminate` and blocks start, transfer, invoke, finalize, and normal completion.
- The formal Pod has exactly `agent` and `workspace`, both mounting the same `emptyDir` at `/workspace`. Only `workspace` may request `nvidia.com/gpu`.
- Job policy is fixed: `completions=1`, `parallelism=1`, `backoffLimit=0`, `restartPolicy=Never`, `automountServiceAccountToken=false`, no hostPath/runtime socket/host SSH key/host PID/IPC/network, and `privileged=false`.
- Containers may run as root, use writable root filesystems, access the network, and install temporary dependencies. The two containers are operational roles, not strong mutual security domains.
- Formal images must be immutable `name@sha256:<64 lowercase hex>` references. Mutable tags are rejected.
- Formal namespace defaults to `researchcosmos-v2`; GPU selector defaults to `researchcosmos.io/pool=gpu`. Client selectors are limited to provider-configured keys/values.
- Provider defaults/maxima: agent `1 CPU/2Gi`, maximum `8 CPU/32Gi`, no GPU; workspace `2 CPU/8Gi/0 GPU`, maximum `64 CPU/256Gi/8 GPU`; shared workspace default `20Gi`, maximum `100Gi`; deadline default `21600s`, maximum `86400s`.
- Wire limits: mutation refs 256 UTF-8 bytes; runtime env 32 entries, key 64 bytes, value 2048 bytes; launch bundle `1 MiB`; credential body `64 KiB`; inline stdout and stderr `64 KiB` each; log page default `64 KiB`, maximum `1 MiB`; direct transfer maximum `100 GiB`.
- Allowed runtime environment keys are exactly `LANG`, `LC_ALL`, `TZ`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and `RC_PUBLIC_RUNTIME_BASE_URL`. Names/values resembling keys, bearer tokens, cookies, SSH/Kubernetes credentials, or PEM data are rejected.
- Pagination default/max is `50/200`; cursors are opaque base64url provider cursors. Log container is the closed enum `agent | workspace`.
- Create/delete tombstones survive without Job owner references for `604800s` (7 days). Operation, transfer, start, finalize, cancel, and grant metadata remain Job-owned until explicit delete. Credential TTL defaults to `300s` and is capped at `900s`.
- `finalize` is the non-research-semantic successful quiesce action. It drains already-authorized work, revokes credentials, stops both PID 1 supervisors, and preserves the terminated Job/Pod/logs until delete. `cancel` interrupts and reports possible output loss. `delete` destroys workload reality while retaining only the create/delete tombstone.
- Credential delivery uses one deterministic optional Secret projection declared when the Job is rendered and mounted read-only only in `agent` at `/var/run/kcs/credential`. At most one active grant occupies it. Matching supervisor ACK triggers immediate Secret deletion; deletion failure is an inspectable blocking observation.
- Supervisor and sidecar control uses KCS-initiated `pods/exec` of fixed commands: `/opt/kcs/agent-supervisor rpc` and `/opt/kcs/workspace-sidecar rpc`. Those commands connect to container-private Unix sockets owned by PID 1. No Pod-local TCP/HTTP/gRPC listener is permitted.
- Transfer control and bytes are separate: JSON registration, octet-stream content upload/download, inspect, cancel, and discard. Stage writes a private temporary file, verifies size/digest/path/symlink policy, then atomically renames. Collect snapshots and verifies authorized output before streaming.
- V2 authentication is fail-closed Bearer service authentication from `KCS_V2_SERVICE_TOKEN`, with TLS/private ingress in deployment. Credential byte upload uses the same dedicated service identity plus `Cache-Control: no-store`; browser/debug credentials are not valid.
- V2 and legacy/debug use separate Kubernetes clients and identities. Production runs V2 in `KCS_API_MODE=v2`; legacy/debug identities have no V2 namespace Job, Pod, `pods/exec`, ConfigMap, or Secret permissions.
- KCS owns physical provider observations only. It never imports ResearchCosmos database/contracts, interprets research success, invents output manifests, or mints Artifact/Receipt/Outcome/Closure facts.
- The development machine is only a source/build/deployment client. Formal KCS API and k3s server run on the dedicated KCS control server; formal GPU Pods run on the separate 4090 worker.
- All commits use author `zhangbo <226653803@qq.com>` with no coauthor trailer. Credentials, private host metadata, SSH paths, tokens, and provider keys never enter Git, logs, examples, or Review Packs.

## Frozen Route Set

```text
POST   /api/v2/jobs
GET    /api/v2/jobs
GET    /api/v2/jobs/{jobRef}
GET    /api/v2/jobs/{jobRef}/logs?container=agent|workspace&cursor=&limitBytes=
POST   /api/v2/jobs/{jobRef}/agent/credential-grants
GET    /api/v2/jobs/{jobRef}/agent/credential-grants/{credentialGrantRef}
POST   /api/v2/jobs/{jobRef}/agent/start
POST   /api/v2/jobs/{jobRef}/transfers
GET    /api/v2/jobs/{jobRef}/transfers/{transferRef}
PUT    /api/v2/jobs/{jobRef}/transfers/{transferRef}/content
GET    /api/v2/jobs/{jobRef}/transfers/{transferRef}/content
POST   /api/v2/jobs/{jobRef}/transfers/{transferRef}/cancel
DELETE /api/v2/jobs/{jobRef}/transfers/{transferRef}
POST   /api/v2/jobs/{jobRef}/workspace/invoke
GET    /api/v2/jobs/{jobRef}/operations/{operationRef}
POST   /api/v2/jobs/{jobRef}/finalize
POST   /api/v2/jobs/{jobRef}/cancel
DELETE /api/v2/jobs/{jobRef}
GET    /api/v2/openapi.json
```

## File Structure

```text
openapi/kcs-v2-jobs.openapi.yaml                 canonical wire authority
openapi/generated/kcs-v2-jobs.openapi.json       deterministic generated JSON
openapi/generated/kcs-v2-jobs.openapi.sha256     SHA-256 of generated JSON bytes
openapi/examples/*.json                          schema-valid sanitized examples
src/kcs/jobs/contracts.py                        strict wire/domain models and enums
src/kcs/jobs/canonical.py                        RFC 8785 digest projections
src/kcs/jobs/policy.py                           resource/env/path/image validation
src/kcs/jobs/settings.py                         non-secret V2 provider configuration
src/kcs/jobs/renderer.py                         pure Job and fixed Secret-volume renderer
src/kcs/jobs/kube.py                             narrow real Kubernetes adapter
src/kcs/jobs/store.py                            Kubernetes record/tombstone persistence
src/kcs/jobs/transport.py                        fixed exec RPC and transfer transport
src/kcs/jobs/provider.py                         lifecycle/idempotency/recovery orchestration
src/kcs/jobs/errors.py                           one typed V2 error taxonomy
src/kcs/server/routes/jobs.py                    FastAPI-only V2 adapter
src/kcs/conformance/agent_supervisor.py           echo supervisor fixture
src/kcs/conformance/workspace_sidecar.py          echo sidecar fixture
deploy/v2/*                                      namespaces, RBAC, API and runtime assets
scripts/generate_v2_openapi_artifacts.py          deterministic schemas/hash/examples check
scripts/run_v2_attempt_journey.py                 real standalone Journey and Review Pack
docs/v2-hosted-attempt-api.md                     consumer/deployment handoff
docs/development/kcs-v1-as-built.md               audited legacy baseline and gaps
```

---

### Task 1: Freeze canonical OpenAPI, limits, state machines, and configuration

**Files:**
- Create: `openapi/kcs-v2-jobs.openapi.yaml`, `openapi/examples/*.json`, `scripts/generate_v2_openapi_artifacts.py`, `docs/development/kcs-v1-as-built.md`, `docs/v2-hosted-attempt-api.md`, `src/kcs/jobs/settings.py`, `tests/jobs/test_openapi_contract.py`, `tests/jobs/test_settings.py`
- Modify: `pyproject.toml`, `.gitignore`

**Interfaces:**
- `V2RuntimeSettings.from_env(environ: Mapping[str, str]) -> V2RuntimeSettings`
- `generate_artifacts(source: Path, output_dir: Path) -> OpenAPIArtifactSet`
- Produces every request/response/error schema for the frozen route set before runtime route implementation begins.

- [ ] **Step 1: Write contract/settings tests that fail before the files exist.**

```python
assert openapi["openapi"] == "3.1.0"
assert openapi["info"]["version"] == "2.0.0"
assert set(expected_paths) == set(openapi["paths"])
assert settings.namespace == "researchcosmos-v2"
assert settings.node_selector == {"researchcosmos.io/pool": "gpu"}
assert settings.api_mode == "v2"
```

- [ ] **Step 2: Author the complete OpenAPI and AS-BUILT/state/idempotency/error/limit tables.** Use one error envelope and the exact limits/global decisions above. Mutating schemas set `additionalProperties: false`; opaque refs have explicit length/pattern rules; nullable provisioning fields are declared.
- [ ] **Step 3: Implement deterministic artifact generation.** Parse YAML, serialize the complete document with sorted compact JSON plus trailing newline, generate component JSON Schemas, validate every sanitized example, and write only the hash value plus generated filename.
- [ ] **Step 4: Implement strict non-secret settings.** Require V2 service token outside tests, reject namespace `default`, and keep host/user/SSH connection metadata out of the model.
- [ ] **Step 5: Verify and commit.**

```bash
.venv/bin/pytest tests/jobs/test_openapi_contract.py tests/jobs/test_settings.py -v
.venv/bin/python scripts/generate_v2_openapi_artifacts.py --check
.venv/bin/ruff check src/kcs/jobs/settings.py tests/jobs scripts/generate_v2_openapi_artifacts.py
git commit -m "feat(v2): freeze canonical jobs wire"
```

### Task 2: Implement strict contracts, canonical digests, policy, and Job rendering

**Files:**
- Create: `src/kcs/jobs/__init__.py`, `src/kcs/jobs/contracts.py`, `src/kcs/jobs/canonical.py`, `src/kcs/jobs/policy.py`, `src/kcs/jobs/renderer.py`, `tests/jobs/test_contracts.py`, `tests/jobs/test_canonical.py`, `tests/jobs/test_policy.py`, `tests/jobs/test_renderer.py`
- Modify: `pyproject.toml`

**Interfaces:**
- `canonical_digest(payload: Mapping[str, object]) -> str`
- `validate_request_digest(identity: str, supplied: str, payload: Mapping[str, object]) -> None`
- `V2JobRenderer(settings: V2RuntimeSettings).render(request: CreateJobRequest) -> client.V1Job`
- `credential_secret_name(job_ref: str) -> str` returns the deterministic Secret name referenced by the optional agent-only volume.

- [ ] **Step 1: Write RED digest/policy/renderer tests.**

```python
assert canonical_digest({"b": 1, "a": 2}) == canonical_digest({"a": 2, "b": 1})
with pytest.raises(DigestMismatchError):
    validate_request_digest("req-1", "0" * 64, spec.model_dump(mode="json"))
assert [c.name for c in job.spec.template.spec.containers] == ["agent", "workspace"]
assert job.spec.template.spec.automount_service_account_token is False
assert job.spec.template.spec.containers[0].resources.limits.get("nvidia.com/gpu") is None
assert job.spec.template.spec.containers[1].resources.limits["nvidia.com/gpu"] == "1"
```

- [ ] **Step 2: Implement RFC 8785 hashing and strict Pydantic models equivalent to OpenAPI.** Reject unknown fields, mutable images, secret env, oversized launch/resource values, arbitrary selectors, and any mount path other than `/workspace`.
- [ ] **Step 3: Render the complete immutable Job.** Include exact refs only in annotations, bounded hashes in labels, fixed roles, shared `emptyDir`, optional Secret projection only in `agent`, security policy, deadline, and no ServiceAccount token or host surface.
- [ ] **Step 4: Add complete negative tests and a golden sanitized Job YAML fixture.** Assert every security field and ensure no credential or private metadata appears.
- [ ] **Step 5: Verify and commit.**

```bash
.venv/bin/pytest tests/jobs/test_contracts.py tests/jobs/test_canonical.py tests/jobs/test_policy.py tests/jobs/test_renderer.py -v
.venv/bin/ruff check src/kcs/jobs tests/jobs
git commit -m "feat(v2): render fixed dual-role attempt jobs"
```

### Task 3: Add the Kubernetes adapter, durable request store, create/list/inspect/logs

**Files:**
- Create: `src/kcs/jobs/kube.py`, `src/kcs/jobs/store.py`, `src/kcs/jobs/provider.py`, `tests/jobs/fakes.py`, `tests/jobs/test_store.py`, `tests/jobs/test_provider_create.py`, `tests/jobs/test_provider_inspect.py`, `tests/jobs/test_provider_logs.py`

**Interfaces:**
- `V2KubeAdapter` owns `BatchV1Api`, `CoreV1Api`, and only the configured V2 namespace.
- `V2JobStore.reserve_create(request) -> CreateReservation`, `mark_created(...)`, `mark_deleted(...)`, and `read_create(provider_request_id)` use namespace-scoped ConfigMaps without Job owner references.
- `V2JobProvider.create(request) -> CreateResult`, `list_jobs(query) -> JobPage`, `inspect(job_ref) -> JobBindingSnapshot`, `logs(job_ref, role, cursor, limit_bytes) -> LogPage`.

- [ ] **Step 1: Write RED fake-adapter tests for replay, conflict, lost response, provisioning-null Pod fields, pagination/log cursors, restart reconstruction, and replacement/multiple Pod detection.**

```python
first = provider.create(request)
assert provider.create(request).snapshot.job_uid == first.snapshot.job_uid
assert fake.created_job_count == 1
with pytest.raises(IdentityDigestConflict):
    provider.create(conflicting_request)
assert rebuilt_provider.inspect(first.snapshot.job_ref).job_uid == first.snapshot.job_uid
fake.add_replacement_pod(first.snapshot.job_ref)
assert provider.inspect(first.snapshot.job_ref).state == BindingState.INDETERMINATE
```

- [ ] **Step 2: Implement reservation-before-create and Kubernetes reconciliation.** Deterministic names plus reservation records prevent duplicate Jobs across response loss/restart. Bind and annotate the first Pod UID; inspect all Pods by Job controller UID and fail closed on additional UIDs.
- [ ] **Step 3: Implement requested/limited versus optional observed resource fields.** Never represent unavailable utilization as zero. Reject create when no matching schedulable node has requested GPU and sufficient ephemeral-storage policy headroom.
- [ ] **Step 4: Implement bounded role logs and opaque cursors.** The adapter passes the explicit container name and redacts credential/token/signed-URL patterns from provider-generated messages.
- [ ] **Step 5: Verify and commit.**

```bash
.venv/bin/pytest tests/jobs/test_store.py tests/jobs/test_provider_create.py tests/jobs/test_provider_inspect.py tests/jobs/test_provider_logs.py -v
.venv/bin/ruff check src/kcs/jobs tests/jobs
git commit -m "feat(v2): persist and inspect attempt bindings"
```

### Task 4: Expose the fail-closed V2 HTTP surface and canonical runtime schema

**Files:**
- Create: `src/kcs/jobs/errors.py`, `src/kcs/server/routes/jobs.py`, `tests/jobs/test_jobs_routes.py`, `tests/jobs/test_error_contract.py`
- Modify: `src/kcs/server/app.py`, `src/kcs/server/routes/__init__.py`, `src/kcs/server/services.py`, `src/kcs/server/main.py`

**Interfaces:**
- `require_v2_caller(request: Request) -> V2Caller` never retains/returns the raw token.
- `get_v2_provider() -> V2JobProvider` uses only the V2 Kubernetes client.
- Every framework/domain error becomes `KcsV2ErrorResponse`; `/api/v2/openapi.json` serves the committed generated JSON with `ETag` equal to its SHA-256.

- [ ] **Step 1: Write RED HTTP tests for missing/wrong/correct service auth, 201-versus-200 create replay, typed 409/410/413/415 errors, list/filter/cursors, role logs, request correlation, and no secret reflection.**
- [ ] **Step 2: Add `KCS_API_MODE=v1|v2|combined`.** Production V2 mode registers only system health plus V2 routes; combined mode exists for development but still uses distinct clients.
- [ ] **Step 3: Register routes and custom validation/error handlers without request-body logging.** Credential/content paths always receive `Cache-Control: no-store`; raw Kubernetes exceptions are sanitized.
- [ ] **Step 4: Compare FastAPI operation IDs/methods/statuses/models against the canonical OpenAPI in tests.** Runtime code may not silently add a second wire contract.
- [ ] **Step 5: Verify and commit.**

```bash
.venv/bin/pytest tests/jobs/test_jobs_routes.py tests/jobs/test_error_contract.py -v
.venv/bin/python scripts/generate_v2_openapi_artifacts.py --check
git commit -m "feat(v2): expose authenticated jobs API"
```

### Task 5: Implement credential grants, agent generations, and graceful finalize

**Files:**
- Create: `src/kcs/jobs/transport.py`, `src/kcs/conformance/__init__.py`, `src/kcs/conformance/agent_supervisor.py`, `tests/jobs/test_credential_grants.py`, `tests/jobs/test_agent_start.py`, `tests/jobs/test_finalize.py`, `tests/conformance/test_agent_supervisor.py`
- Modify: `src/kcs/jobs/provider.py`, `src/kcs/jobs/store.py`, `src/kcs/jobs/kube.py`, `src/kcs/server/routes/jobs.py`

**Interfaces:**
- `grant_credential(job_ref, metadata, raw_bytes) -> CredentialGrantSnapshot`
- `start_agent(job_ref, request) -> AgentGenerationSnapshot`
- `finalize(job_ref, request) -> FinalizeSnapshot`
- `ExecRpcTransport.agent_rpc(binding, request) -> AgentRpcResponse` executes only `/opt/kcs/agent-supervisor rpc`.

- [ ] **Step 1: Write RED grant/start/finalize tests.** Cover same-ref replay, changed byte/meta digest conflict, 64 KiB limit, TTL expiry, Secret deletion after exact ACK, delete failure observation, generation replay/conflict, legal N+1 only after child exit, Pod-loss rejection, and finalize retaining terminal Job/Pod/logs.

```python
grant = provider.grant_credential(job_ref, metadata, b"synthetic-short-credential")
assert provider.grant_credential(job_ref, metadata, b"synthetic-short-credential") == grant
assert b"synthetic-short-credential" not in fake.audit_bytes
assert provider.start_agent(job_ref, start).generation == 1
assert fake.agent_start_count == 1
assert provider.finalize(job_ref, finalize).state == FinalizeState.TERMINATED
```

- [ ] **Step 2: Implement the fixed optional Secret slot and non-secret grant records.** Bind grant to Job UID, Pod UID, AgentRun, generation, audience, and launch digest. Persist `accepted|available|acknowledged|consumed|destroyed|expired|revoked|destroy_failed|indeterminate`.
- [ ] **Step 3: Implement agent RPC and echo supervisor.** PID 1 owns a private Unix socket; `rpc` connects locally, validates protocol version/generation/digest, consumes the projected credential, starts one child, and returns a matching ACK without credential bytes.
- [ ] **Step 4: Implement finalize as provider quiesce only.** Reject new work, wait for already-registered operations/transfers under the request drain policy, revoke credentials, ask both supervisors to exit, and retain terminal reality.
- [ ] **Step 5: Verify and commit.**

```bash
.venv/bin/pytest tests/jobs/test_credential_grants.py tests/jobs/test_agent_start.py tests/jobs/test_finalize.py tests/conformance/test_agent_supervisor.py -v
git commit -m "feat(v2): control agent generations and finalize"
```

### Task 6: Implement transfer content and exactly-once workspace operations

**Files:**
- Create: `src/kcs/conformance/workspace_sidecar.py`, `tests/jobs/test_transfers.py`, `tests/jobs/test_workspace_operations.py`, `tests/conformance/test_workspace_sidecar.py`
- Modify: `src/kcs/jobs/provider.py`, `src/kcs/jobs/store.py`, `src/kcs/jobs/kube.py`, `src/kcs/jobs/transport.py`, `src/kcs/server/routes/jobs.py`

**Interfaces:**
- `register_transfer(job_ref, request) -> TransferSnapshot`
- `stage_transfer_content(job_ref, transfer_ref, stream) -> TransferSnapshot`
- `open_collected_content(job_ref, transfer_ref) -> VerifiedContent`
- `cancel_transfer(...)`, `discard_transfer(...)`, `inspect_transfer(...)`
- `invoke_workspace(job_ref, request) -> OperationSnapshot`, `inspect_operation(...)`.

- [ ] **Step 1: Write RED tests for normalized relative paths, traversal/symlink/overwrite denial, exact size/digest, atomic rename, partial-upload cleanup, upload/download replay, restart inspect, ConfigMap-before-side-effect, changed operation digest conflict, output truncation, result digest, and exactly one side-effect count.**

```python
provider.register_transfer(job_ref, stage)
provider.stage_transfer_content(job_ref, stage.transfer_ref, io.BytesIO(b"input"))
assert fake.read_workspace("inputs/a.txt") == b"input"
with pytest.raises(PathPolicyRejected):
    provider.register_transfer(job_ref, stage.model_copy(update={"relative_path": "../escape"}))
result = provider.invoke_workspace(job_ref, invoke)
assert provider.invoke_workspace(job_ref, invoke) == result
assert fake.workspace_side_effect_count == 1
```

- [ ] **Step 2: Implement direct stream staging/collection with control-node temp files and fixed workspace RPC finalize/snapshot commands.** Bytes never enter JSON. Signed URL mode is not advertised in V2.0.0 because authenticated direct streaming fully satisfies the required transport choice.
- [ ] **Step 3: Implement operation ConfigMap persistence before dispatch.** On KCS restart, query the surviving sidecar through fixed RPC; if terminal truth cannot be recovered, return `indeterminate` and never redispatch.
- [ ] **Step 4: Implement the echo workspace sidecar.** PID 1 owns a private Unix socket, spawns counted commands, reports inspect/cancel, and provides transfer path validation; it exposes no TCP port.
- [ ] **Step 5: Verify and commit.**

```bash
.venv/bin/pytest tests/jobs/test_transfers.py tests/jobs/test_workspace_operations.py tests/conformance/test_workspace_sidecar.py -v
git commit -m "feat(v2): add trusted transfers and workspace operations"
```

### Task 7: Implement cancel, delete, tombstones, and startup reconciliation

**Files:**
- Create: `tests/jobs/test_cancel.py`, `tests/jobs/test_delete.py`, `tests/jobs/test_reconcile.py`
- Modify: `src/kcs/jobs/provider.py`, `src/kcs/jobs/store.py`, `src/kcs/jobs/kube.py`, `src/kcs/server/routes/jobs.py`, `src/kcs/server/app.py`

**Interfaces:**
- `cancel(job_ref, request) -> CancelSnapshot`
- `delete(job_ref, request_identity: ActionIdentity) -> DeleteSnapshot`
- `reconcile_all() -> ReconcileReport` runs at V2 service startup and is safe to repeat.

- [ ] **Step 1: Write RED tests for cancel replay/conflict, draining only pre-authorized collect transfers, `outputsMayBeLost`, supervisor/sidecar stop, Secret cleanup, terminal log/snapshot retention, GPU release observation, delete replay, owner-record garbage collection, surviving create tombstone, 410 create/inspect behavior, and crash points around every side effect.**
- [ ] **Step 2: Implement cancel without inventing output manifests.** Graceful RPC stop must leave the Pod object terminal; inability to prove stop/credential destruction is `indeterminate`, not success.
- [ ] **Step 3: Implement delete ordering.** Persist the non-owner tombstone first, delete Secret and Job with foreground propagation, verify owned records/Pod disappear, then mark deleted. Same action ref/digest replays; changed digest conflicts.
- [ ] **Step 4: Implement startup reconciliation from reservations, Jobs/Pods, annotations, ConfigMaps, Secret presence, and live supervisor/sidecar inspect.** No in-memory map is authoritative.
- [ ] **Step 5: Verify and commit.**

```bash
.venv/bin/pytest tests/jobs/test_cancel.py tests/jobs/test_delete.py tests/jobs/test_reconcile.py -v
git commit -m "feat(v2): recover cancel and delete lifecycle"
```

### Task 8: Isolate every legacy debug surface and fix configured SSH identity use

**Files:**
- Create: `src/kcs/legacy_guard.py`, `tests/test_v2_proxy_isolation.py`, `tests/test_ssh_identity.py`, `deploy/v2/rbac.yaml`, `deploy/v2/network-policy.yaml`
- Modify: `src/kcs/shell_proxy.py`, `src/kcs/k8s.py`, `src/kcs/server/routes/containers.py`, `src/kcs/server/routes/shell_proxy_routes.py`, `src/kcs/server/routes/shell_sessions.py`, `src/kcs/server/services.py`, `src/kcs/server/models.py`, `src/kcs/cli.py`, `README.md`, `src/kcs/static/index.html`

**Interfaces:**
- `assert_legacy_target_allowed(pod_metadata) -> None` denies `researchcosmos.io/managed-by=v2-attempt-runtime` and denies the V2 namespace before exec/upload/shell/proxy work.
- `_run_ssh(..., identity_file: str | None, ...)` adds `-i <expanded explicit path>` and `IdentitiesOnly=yes` without logging the path.

- [ ] **Step 1: Write RED tests that exercise Claude proxy, HTTP exec/upload/shell sessions, CLI shell, and generic pod selection against a V2 managed Pod.** Each must fail before any `pods/exec`, `kubectl cp`, socket, or file mutation call.
- [ ] **Step 2: Centralize and apply the legacy guard at all target-resolution boundaries.** UI/README label V1 shell paths `debug-only` and direct formal diagnostics to V2 inspect/log.
- [ ] **Step 3: Thread `WorkerNode.ssh_key` through every SSH call.** Validate regular-file ownership/permissions, never log it, remove the existing k3s-token prefix log, and preserve password pipe behavior.
- [ ] **Step 4: Add RBAC/network policy.** V2 API identity receives only required verbs in `researchcosmos-v2`; workload ServiceAccount has no token; legacy/debug identity receives no V2 permissions. Tests parse and assert the policy matrix.
- [ ] **Step 5: Verify and commit.**

```bash
.venv/bin/pytest tests/test_v2_proxy_isolation.py tests/test_ssh_identity.py -v
.venv/bin/ruff check src/kcs tests/test_v2_proxy_isolation.py tests/test_ssh_identity.py
git commit -m "feat(v2): isolate formal jobs from debug access"
```

### Task 9: Package OCI images and dedicated two-host deployment assets

**Files:**
- Create: `Containerfile`, `deploy/v2/namespace.yaml`, `deploy/v2/kcs-api.yaml`, `deploy/v2/conformance-agent.Containerfile`, `deploy/v2/conformance-workspace.Containerfile`, `deploy/v2/config.example.yaml`, `deploy/v2/kcs-v2.service`, `scripts/deploy_v2_control.sh`, `scripts/deploy_v2_worker.sh`, `tests/deploy/test_manifests.py`, `tests/deploy/test_scripts.py`
- Modify: `pyproject.toml`, `docs/v2-hosted-attempt-api.md`, `README.md`

**Interfaces:**
- Deployment scripts require explicit environment/config values and accept SSH aliases only from the operator environment; they contain no host/user/key defaults.
- KCS API image runs `KCS_API_MODE=v2` and uses its dedicated ServiceAccount/client identity. Conformance image commands exist at the exact fixed RPC paths.

- [ ] **Step 1: Write RED manifest/script tests.** Assert dedicated namespaces/identities, no workload token/hostPath/privilege/host namespace, V2 API TLS/secret references, GPU selector, immutable image inputs, and no private connection literals.
- [ ] **Step 2: Build reproducible linux/amd64 OCI definitions.** Workspace fixture is based on a digest-pinned NVIDIA CUDA runtime; agent fixture and KCS API are digest-pinned Python bases. Emit source revision and license labels.
- [ ] **Step 3: Implement idempotent remote deployment scripts.** Control script verifies SSH first, installs/configures k3s server and V2 API only on the dedicated control host, applies RBAC/TLS/service secret without echoing values, and records sanitized versions. Worker script joins the separate GPU host, configures NVIDIA runtime/device plugin, labels the node, and never installs KCS API there.
- [ ] **Step 4: Document overlay/firewall prerequisites.** Scripts fail closed unless a non-public control-plane address and allowed peer CIDRs are supplied; they never expose k3s, kubelet, or VXLAN directly to the public internet.
- [ ] **Step 5: Verify locally and commit.**

```bash
.venv/bin/pytest tests/deploy -v
.venv/bin/python -m build
git commit -m "build(v2): package dedicated runtime deployment"
```

### Task 10: Run the dedicated-server deployment and standalone Journey

**Files:**
- Create: `scripts/run_v2_attempt_journey.py`, `tests/test_v2_journey.py`, `review-pack/.gitignore`
- Modify: `docs/v2-hosted-attempt-api.md`

**Interfaces:**
- `run_v2_attempt_journey.py --config deploy/v2/config.runtime.yaml --evidence-dir review-pack/kcs-v2-standalone` drives only the deployed KCS HTTPS API; it never uses local Kubernetes as formal evidence.
- `tests/test_v2_journey.py` is marked `v2_live` and skips unless `KCS_V2_LIVE=1`.

- [ ] **Step 1: Write the opt-in Journey test before deployment.** It asserts one Job/Pod, exact roles/shared digests, workspace GPU/agent no GPU, transfer integrity, operation replay/conflict, restart same UIDs, legal next generation, Pod-loss indeterminate, finalize retention, cancel retention/output-loss honesty, delete cleanup/tombstone, proxy denial, and resource baseline recovery.
- [ ] **Step 2: Restore/verify dedicated control-host SSH and approved private/overlay connectivity.** If the host still closes SSH or firewall/overlay authority is absent, retain code commits and record P5/P6 as externally blocked; never deploy KCS locally.
- [ ] **Step 3: Deploy k3s/KCS on the dedicated control server and join/configure the separate GPU worker.** Build/push images from a linux/amd64-capable environment, record immutable digests, run `kubectl auth can-i` matrices, verify node label/GPU/runtime, and verify authorized/unauthorized HTTPS behavior.
- [ ] **Step 4: Execute the complete standalone Journey and service restart.** Evidence includes sanitized API responses, Job/Pod UIDs, Kubernetes YAML, container logs, hashes, operation side-effect counter, before/after resource snapshots, and cleanup.
- [ ] **Step 5: Generate Review Pack and secret scan.** The scan reports only file paths and hit counts; no matched value is printed. Keep the private runtime config untracked.
- [ ] **Step 6: Commit only sanitized tooling/docs, never runtime evidence containing private topology.**

```bash
KCS_V2_LIVE=1 .venv/bin/pytest tests/test_v2_journey.py -v
.venv/bin/python scripts/run_v2_attempt_journey.py --config deploy/v2/config.runtime.yaml --evidence-dir review-pack/kcs-v2-standalone
git commit -m "test(v2): add standalone attempt journey"
```

### Task 11: Close quality, generated-artifact, author, and handoff gates

**Files:**
- Modify: all files required to remove pre-existing and new Ruff/Mypy/build/test failures without changing V1 behavior; `README.md`, `docs/v2-hosted-attempt-api.md`
- Create: `docs/v2-standalone-handoff.md`

**Interfaces:**
- Final handoff records actual base/head, commits, OpenAPI version/hash, deployed image digests/topology, Journey refs/UID outcomes, restart/finalize/cancel/delete/proxy/resource results, secret-scan path/count summary, and explicit limitations.

- [ ] **Step 1: Add the missing declared runtime dependency `python-multipart` and make legacy live tests opt-in when no kubeconfig is present.** Pure V2/unit tests remain mandatory everywhere; real legacy/V2 tests run on the dedicated cluster.
- [ ] **Step 2: Remove all Ruff findings and strict Mypy errors in touched/new V2 code, then address the inherited repository findings needed for the requested all-green gate without weakening configured rules.**
- [ ] **Step 3: Regenerate and check OpenAPI artifacts, build wheel/sdist and OCI images, verify immutable digests, and run all non-live tests.**
- [ ] **Step 4: On the deployed environment, rerun the full live suite and standalone Journey immediately before the completion claim.**
- [ ] **Step 5: Verify Git state and authors.** No credential/private handoff path may be tracked; every branch commit author is exactly `zhangbo <226653803@qq.com>`; no coauthor trailers exist.
- [ ] **Step 6: Commit final quality/handoff changes.**

```bash
.venv/bin/python scripts/generate_v2_openapi_artifacts.py --check
.venv/bin/pytest -m "not v2_live and not legacy_live" -v
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/python -m build
git diff --check
git status --short
git log --format='%an <%ae>%n%b' 8ca9be59028522e35d39ecae131b6e9ffd5f4c74..HEAD
git commit -m "chore(v2): close delivery quality gates"
```

## Self-Review Results

- Spec coverage: Tasks 1–7 cover P0–P3 wire, renderer, routes, persistence, restart, credential, start, transfer, invoke, finalize/cancel/delete and indeterminate behavior; Task 8 covers P4 isolation and SSH identity; Tasks 9–10 cover P5–P6 dedicated deployment/Journey; Task 11 covers final quality/handoff.
- No second ResearchCosmos schema/state machine is introduced; only opaque refs and `cosmos.workspace/1` frames cross the boundary.
- The credential mount is realizable because its stable optional Secret volume is declared before Pod creation.
- Successful finalize is separate from cancellation and deletion, so a terminal successful Pod/log snapshot can be retained without calling interruption “success.”
- Transfer bytes have explicit retryable content routes and never enter control JSON.
- The formal deployment boundary explicitly excludes the development machine.
- Placeholder scan: commands use committed example/runtime paths and named environment variables; private values remain external by design.
- Type/interface consistency: provider, store, transport, route, and conformance interfaces are introduced before downstream use and use the same identity/digest model.
