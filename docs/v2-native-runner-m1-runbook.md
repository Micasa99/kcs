# KCS V2.4 native runner M1 runbook

This runbook operates the M1 native lane without changing the hosted lane. The
canonical contract is `openapi/kcs-v2-jobs.openapi.yaml`; generated and packaged
bytes must all have SHA-256
`3a09c318f85faa20ae8273c372e2bed186dbab60d122667f031989a9b75db84f`.
Production deployment is a separate owner checkpoint.

## 1. Build and register immutable images

Build the API from `Containerfile`, the production control sidecar from
`deploy/v2/native-runtime-control.Containerfile`, and the platform image volume from
`native/launcher/Containerfile`. The fixed probes in
`kcs.conformance.workspace_sidecar` remain a test/hosted-conformance wrapper and are
not the native control authority. Push each image to the KCS-managed registry and
resolve the registry digest; tags are never accepted in a recipe. The runner image
volume is a digest-pinned image containing the native CLI and its own runtime. The
environment image is the experiment filesystem and must not contain platform
credentials.

Copy `deploy/v2/native-recipe-registry.example.json` outside Git, replace every
example digest/ref, recompute the canonical recipe digest, and validate it by
starting KCS with `KCS_V2_NATIVE_RECIPE_REGISTRY` pointing at that file. Registration
fails unless `requires` is a subset of `provides`; an unregistered exact pair returns
typed 403. The committed ConfigMap is deliberately empty so applying manifests does
not silently authorize native workloads.

## 2. Configure Model Gateway and egress

Set the two HTTPS base URLs and canonical operator-owned platform CIDRs in
`kcs-v2-native-runtime-config`; KCS accepts only exact configured values from a native
Job. KCS creates and observes the Attempt NetworkPolicy before it creates the Job.
The native Pod receives only KCS API ingress for its control relay, DNS egress, and
TCP 443 egress to those CIDRs. Do not add provider keys to KCS:
ResearchCosmos grants an Attempt-scoped gateway token through
`grantRunnerCredential`.

The projection Secret is late-created after jobUID/podUID exist, mounted only into
the runtime as `/var/run/rc/model-gateway/token`, and must be root:root `0400` on
Secret-backed tmpfs. Use a projection TTL of 180 seconds unless an approved policy
chooses another value in 120..900. After `startRunner` ACK, verify the Secret was
deleted and that inspect/log/event/Pod/ConfigMap surfaces contain no token bytes.

## 3. Lifecycle order

The required order is create → stage → grantRunnerCredential → startRunner ACK →
runner running/exited/killed → capture while both containers live →
finalizeJob(captureBarrier) → durable launcher finalize receipt → control
`commitFinalize` → launcher/control exit → Job terminal. `backoffLimit=0`; a second
Pod UID is a contract failure. Soft deadline starts only at the successful start ACK
and stops the child, not launcher/control. Hard deadline, eviction, node loss, or
ENOSPC may destroy the Pod and must set output-loss/indeterminate facts rather than
simulate a runner result.

The production control durably records the launcher's finalize acknowledgement
before replying to the API. The private control action `inspectNativeFinalize`
reconciles the exact
jobUID/podUID/finalizeRef/generation and launcher request digest after an API ACK
loss. The control process accepts shutdown only after such a receipt exists and the
control has sent `commitFinalize` with the retained `finalizeReceipt.receiptDigest`
and verified its committed ACK. If that ACK is interrupted, control validates the
exact committed `/run/rc-control/finalize-receipt.json` identity; it never infers
commit from a missing launcher socket. Only then may control wait for launcher exit
and shut down.

Use `GET /api/v2/jobs/{jobRef}`, `GET /api/v2/events`, and bounded runner/control logs
for diagnosis. The launcher state file and socket are private platform surfaces;
never use root kube-exec as the terminal implementation.

The launcher no longer exits on the initial `finalize` ACK. Control must retain the
returned `finalizeReceipt.receiptDigest`, then send the internal `commitFinalize`
command with `finalizeReceiptDigest`; only its ACK commits launcher exit. On retry,
reconcile `/run/rc-control/finalize-receipt.json` and repeat the exact identity. Do not
restore the former 500 ms exit timer or infer finalize success from socket loss.

## 4. Isolated canary

Create a new namespace name for every canary. Snapshot
`researchcosmos-v2/kcs-v2-api` availability before and after; do not apply, patch,
restart, or delete anything in that namespace. Install namespace-local RBAC, API,
TLS/token/config, exact recipes, NetworkPolicy and images.

Exercise at least these journeys with unique ids: natural hello-task, stopRunner,
cancel/revoke, hard deadline, invalid recipe, insufficient ephemeral storage, and
terminal pause/read/replay/close. Record job/pod YAML, events, both raw logs, API
request/response envelopes with credentials redacted, state digests, image IDs,
timings, NetworkPolicy allow/deny probes, and secret scans. Delete only the exact
canary namespace after evidence capture and prove it is absent.

Cold pull and registry authentication must be measured on a node that does not
already cache the exact digests. If such a node is unavailable, record the SLO as
`not_reported`; cached-pull timings must not be presented as cold-pull evidence.

## 5. Monitoring

The authenticated `/metrics` endpoint exports aggregate native binding, runner,
stop, recipe-delivery, credential, hard-deadline and output-loss gauges without job
or subject labels. Prometheus uses the same service bearer from a mirrored secret
and verifies the internal API CA. Follow `deploy/v2/monitoring/RUNBOOK.md` for the
alerts. NetworkPolicy-denial metrics remain `not_reported` until CNI audit telemetry
is installed; canary allow/deny commands are the M1 evidence.

## 6. Rollback and production gate

Before owner approval, rollback means deleting only the isolated canary namespace.
For an approved production rollout, retain the prior 2.3 API image/manifest and
state snapshot; first verify the 31 hosted operation locations and hosted schema
fingerprints, then deploy one API replica and run hosted smoke before admitting a
native recipe. A failed smoke rolls back the API image/config without deleting
managed Jobs or their state PVC.

## 7. 2026-08-09 isolated MLE canary

The first joint ResearchCosmos MLE success path ran in the isolated
`rc-native-m1-20260809` canary. It used API image
`sha256:8eee7c1e093a2672dca98e4347f407e24b00aaa7875a01f8835753c8fdcf56ac`
from source commit `330b3d6531e1ef452367cda543d6a1e50398b1c2`, with the contract SHA named
at the top of this runbook.

One native Codex Job staged the six-file MLE workspace, ran autonomously as UID
10001, exited 0, and remained capturable until ResearchCosmos sealed a complete
NativeAttemptCapture and finalized the Job. During the full staging and runner path,
the canary API Pod remained Ready with restart count 0. Runner and control logs were
read and attested; ResearchCosmos completed its result basis, verdict, cleanup, and
closure.

This run exposed event-loop starvation caused by synchronous provider/file writes in
async transfer routes. Those calls now run off the API event loop; the successful
Journey used the rebuilt image above. A retained earlier canary Job and PVC were
removed through the typed KCS delete operation after exact identity checks.

The production `researchcosmos-v2` namespace was not patched, restarted, or rolled
out and remains on v2.3. This canary closes the natural success path only. Gateway
429, report-missing, cancel/revoke, hard-deadline/indeterminate, ENOSPC/eviction, and
hosted/native parallel Journeys remain production gates.

## 8. 2026-08-09 runtime closeout canary

The production-runtime closeout used KCS source commit `75d176c` and the same
contract SHA recorded at the top of this runbook. The isolated canary resolved these
exact images:

- API: `sha256:c0e9a2bb4c499d0a06ed54a9ea3a3ad96993780f0cc598d329d57d8951c3c402`
- platform launcher: `sha256:e20cc626b9f81eb4e76e7ce0e85740a5e358cb9bdcb6d5986c7b6f39e38bf212`
- production control: `sha256:aba95ef4c22ae9bdde57d85ed4a7215670070457c69d07d6fdfc81dc0d6ce62c`
- Codex runner: `sha256:096612527c31300383ff4dd1c0227642cad03bf2212e0a8ace64952af230f110`

The registered Codex/environment exact pair resolved to recipe digest
`0a5b9f071738d98a279bde4c6e6f12d17c1844160aa1b81f256cd1ccdd511abd`.
There was no approximate version selection or assembled-to-prebuilt fallback.

One native Codex Job received a six-file MLE workspace and completed autonomously as
UID 10001. It executed the supplied baseline, adapted to the actually installed
stdlib-only environment, improved validation log-loss from `1.5283` to `0.3860`, and
produced a structurally verified 1,958-row submission plus research record,
explanation, validation evidence, metrics, trace, and `RESULT.md`. KCS observed a
natural exit code 0 and the raw `turn.completed` protocol terminal. ResearchCosmos
sealed a complete 21-item NativeAttemptCapture with no omissions, truncations, or
possible output loss, read both runner and control raw logs, finalized and deleted
the Job, completed cleanup, and sealed a succeeded ResearchOutcome and
ResearchClosure. The canary API remained Ready with zero restarts.

The final ResearchRun-rooted pack then rejected one ResearchCosmos ownership
invariant: the six ResearchRun input refs were compared to seven physical
`input_material` rows because the Attempt-derived `TASK.md` was committed through
that same owner table. This is a consumer-side lineage-membership defect, not a KCS
runtime failure; the raw terminal/capture/cleanup facts remain preserved. KCS does
not add a compatibility path for it. The ResearchCosmos fix must distinguish
ResearchRun-declared inputs from reachable Attempt-derived staged materials while
continuing to verify both exact refs and bytes.

The closeout used only the isolated `rc-native-closeout-2a400da` namespace. No
production namespace was changed. The transient Job and workload PVC were removed
after capture; the namespace-local canary API remains available for the consumer
lineage fix and a detached pack rerun.
