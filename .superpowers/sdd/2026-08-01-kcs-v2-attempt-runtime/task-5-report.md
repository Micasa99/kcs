# Task 5 — credential grants, agent generations, and graceful finalize

## Implementation

Implemented the KCS V2 credential/start/finalize vertical slice. Credential bytes enter only
through the octet-stream route, are checked against the supplied SHA-256 and canonical metadata
digest, and are written only to the fixed optional agent Secret projection. Kubernetes ConfigMaps
retain only non-secret grant, generation, and finalize observations. Replays compare the retained
identity digest; different values conflict. A 64 KiB limit, one-active-grant rule, TTL expiry,
immediate Secret delete after a matching agent RPC acknowledgement, and inspectable
`destroy_failed` state are implemented.

Agent start persists generation N before dispatch and sends one fixed
`/opt/kcs/agent-supervisor rpc` request. The same generation/digest is replay-only; N+1 requires
the retained child to be exited while PID 1 remains alive. Pod/binding loss is rejected. Finalize
is a provider quiesce: it rejects new work, revokes grants, asks the fixed agent and workspace
supervisors to stop, and deliberately does not delete Job/Pod/log reality. Its wire result is the
canonical `JobBindingSnapshot` (not a second finalize model).

Files changed: `contracts.py`, `errors.py`, `kube.py`, `provider.py`, `store.py`, `routes/jobs.py`;
new `jobs/transport.py`, `conformance/agent_supervisor.py`, and one simulated Journey test.

## Verification

Commands and results:

```text
.venv/bin/ruff check <touched files>                 -> All checks passed!
.venv/bin/ruff format --check <touched files>        -> 10 files already formatted
.venv/bin/mypy --strict <touched sources>            -> Success: no issues found in 9 source files
.venv/bin/python -m py_compile <touched sources>     -> exit 0
.venv/bin/python scripts/generate_v2_openapi_artifacts.py --check
  -> validated 31 route exchanges; sha256 efcbb64fc1d96ec5f7797eda92405a4ae5c596b3a7864dad6396e423a09e193e
.venv/bin/pytest tests/jobs/test_task5_journey.py -v -> 1 passed
git diff --check                                     -> exit 0
```

No legacy/live suite, local server, network, SSH, Kubernetes cluster, k3s, or deployment was run.

## Sanitized Journey evidence

```text
HTTP grant request
  Content-Type: application/octet-stream
  KCS-Credential-Grant-Ref: grant-1
  KCS-Credential-SHA256: 1a67ce36fa0f392f26c4f72367269626365d658f7fa6ae43e5c57dab84d7fd5f
  raw body: [REDACTED 26 bytes]
HTTP grant response: 201 available; replay response: 200 available

supervisor RPC request (credential omitted)
  {"agentRunRef":"run-1","credentialGrantRef":"grant-1","generation":1,
   "launchBundleDigest":"aaaaaaaa...","protocolVersion":1}
supervisor RPC response
  {"protocolVersion":1,"generation":1,"agentRunRef":"run-1",
   "launchBundleDigest":"aaaaaaaa...","state":"exited","supervisorAlive":true,
   "pid":7,"exitCode":0}
start result: generation=1; exact replay=true; dispatch count=1
Secret delete count after matching ACK=1; grant inspect state=destroyed
finalize: stopped=[agent, workspace]; retained jobUid and podUid remain observable
```

Secret nonappearance check in the Journey asserted the synthetic credential bytes are absent from
the fake Kubernetes audit byte stream and from every retained ConfigMap record. The report and the
captured RPC frame likewise use only a digest and a byte count, never the credential value.

## Self-review and concerns

- `provider.py` grew substantially because it remains the existing load-bearing orchestration seam.
  A later focused extraction of grant/generation helpers would improve maintainability, but no
  unrelated refactor was made here.
- The store deliberately retains non-secret payload JSON in ConfigMaps; Secret data is never copied
  into those records or provider snapshots.
- The conformance supervisor is only a deterministic Unix-socket echo fixture. The production
  supervisor/runtime binary remains owned by ResearchCosmos as required.
