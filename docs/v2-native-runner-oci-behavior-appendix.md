# KCS OpenAPI 2.5 native-runner OCI behavior appendix

Status: **M1 implemented; M2 dormant freeze**. The implementation branch serves
OpenAPI 2.4.0 at SHA-256
`3a09c318f85faa20ae8273c372e2bed186dbab60d122667f031989a9b75db84f` and implements
the native provider/renderer/launcher path. OpenAPI 2.5.0 at SHA-256
`a4aab79cbc56060928b1f04a1e36b49fa17e77c6eed44e1ef60aba03c4b20408` freezes M2 as
`dormant`; it is generated for review but is not packaged, served, or deployed.
Production `researchcosmos-v2` is unchanged.

## 1. Delivery selection and immutable image roles

The recipe registry exposes exactly two delivery arms:

1. `assembled` is the default and always means Kubernetes `image` volumes. The
   environment image is the runtime container root filesystem; the platform and
   runner images are separately mounted read-only image volumes; the control image
   is the control-sidecar root filesystem.
2. `prebuilt` is an explicitly registered image for a specific runner/environment
   combination. Platform remains a separate read-only image volume. A missing
   registered prebuilt recipe is an admission failure; a cluster without
   ImageVolume support cannot run the native lane.

There is no `initExtract` arm and no runtime fallback from `assembled` to
`prebuilt`. KCS selects one authorized recipe before Pod creation and records that
choice. This avoids a second writable copy, the associated disk peak, and ambiguous
assembly identity.

All image references in a recipe are digest-pinned. The activation receipt records
the requested references and actual runtime image IDs for the environment,
platform image volume, runner image volume, and control image. A prebuilt receipt
records the prebuilt, platform image-volume, and control reference/ID pairs.

## 2. Volume and capacity contract

| Role | Mount/medium | Ownership and mode | Mutability |
| --- | --- | --- | --- |
| shared workspace | `/workspace` (`worktree` below it), disk-backed shared workspace | worktree `10001:10001`, setgid `2775` after root staging | agent and terminal group-writable with `umask 0002`; control access is policy-limited |
| platform image | `/opt/rc-platform`, Kubernetes image volume in both delivery arms | image-owned | read-only |
| runner image | `/opt/rc-runner`, Kubernetes image volume in `assembled` | image-owned | read-only |
| gateway credential | `/var/run/rc/model-gateway/token`, Secret-backed tmpfs | `root:root`, `0400` | launcher reads once; never mounted into control |
| control state | `/run/rc-control`, private control volume | `root:root`, `0700` | launcher and control read/write; experiment child cannot access |
| agent home | `/run/rc-user/home`, writable runtime volume | `10001:10001`, `0700` | experiment child only |
| agent tmp | `/run/rc-user/tmp`, writable runtime volume | `10001:10001`, `0700` | experiment child only |
| terminal home | `/run/rc-terminal/home`, writable runtime volume | `10002:10001`, `0700` | launcher-mediated terminal only |
| terminal tmp | `/run/rc-terminal/tmp`, writable runtime volume | `10002:10001`, `0700` | launcher-mediated terminal only |

Root staging recursively group-normalizes only the managed worktree: directories
become group-readable/writable/setgid, regular files become group-readable/writable
while preserving existing execute bits, and symlink traversal outside the worktree
is rejected (an equivalent default-ACL policy is acceptable). This makes staged
`0644` source files editable by terminal UID `10002` without widening other mounts.

`native.resources.ephemeralStorageMiB` covers only Pod writable layers, logs, and
disk-backed `emptyDir` usage. OCI image layers are not reported as Pod ephemeral
usage. Recipe resolution and activation instead carry
`imageFsCompressedBytes`/`imageFsUnpackedBytes`, estimated by KCS after layer
deduplication across environment, platform, and runner images. KCS admission and
node-headroom policy consume that separate image-filesystem estimate. Activation
also records the admitted CPU, memory, accelerator, and ephemeral-storage requests
and limits separately from observed peak usage.

Implementation gate: exact admission headroom, workspace `sizeLimit`, and hard
deadline values remain `EVIDENCE-PENDING`; they must be frozen from the production
policy rather than inferred from a canary.

## 3. Identity and security boundary

Evidence-backed canary facts:

- launcher PID 1 ran as UID/GID `0`;
- the agent child ran as UID/GID `10001`, with `CapEff=0`, working directory
  `/workspace/worktree`, `HOME=/run/rc-user/home`, and
  `TMPDIR=/run/rc-user/tmp`;
- the control sidecar ran as UID/GID `0` and token lookup returned `ENOENT`; the
  experiment child was denied access to `/run/rc-control` with `EACCES`;
- runtime used a read-only root filesystem, dropped ambient capabilities, and did
  not use privileged or host namespaces.

Frozen implementation requirement:

- recipe identity records runtime/launcher UID/GID `0`, experiment child UID/GID
  `10001`, and terminal UID/GID `10002:10001`;
- runtime launcher: drop `ALL`, add only `CHOWN`, `SETUID`, `SETGID`, and `KILL`;
  `CHOWN` is used only before launch to transfer kubelet/control-created writable
  paths to the exact experiment identity (the first M1 live Pod proved that the
  earlier three-capability freeze fails with `EPERM` on an EmptyDir root); immediately
  before child exec, clear supplementary groups, set GID/UID `10001`, set
  `no_new_privs`, and verify zero effective capabilities;
- control: drop `ALL`, add only `DAC_OVERRIDE` for the managed-worktree capture
  boundary, use a read-only root filesystem, and never use privileged mode or host
  PID/network/IPC namespaces;
- the runtime container's only PID 1 command is
  `/opt/rc-platform/bin/rc-native-launcher`; a recipe's `runnerEntrypoint` is child
  argv and is never installed directly as PID 1;
- control serves workspace RPC as its recipe-pinned container PID 1 command,
  `/opt/kcs/workspace-sidecar serve`; the separately fixed
  `/opt/kcs/workspace-sidecar rpc` command is the API-side exec client and talks
  to the launcher only through `/run/rc-control/launcher.sock`; it does not exec the
  root runtime container; its private temporary directory is the same bounded
  `/run/rc-control` EmptyDir (`TMPDIR=/run/rc-control`), never the read-only image
  root;
- PodSpec/container environment contains configured gateway base URLs, model route,
  and only the credential file path. Launcher reads the credential and injects the
  short-lived protocol secret only into the native agent child process environment;
  it disappears with that child. Credential bytes never enter PodSpec/container
  env, API observations, events, logs, receipts, control, or terminal shells.
- before spawning a native CLI, the launcher resolves a closed declarative adapter by
  the exact recipe-owned `RC_NATIVE_RUNNER_REF`. M1 declares `runner-codex`
  (`codex-responses-v1`, `codex-jsonl`) and `runner-pi` (`pi-models-v1`, `pi-jsonl`),
  including the exact executable, supported model protocols, prompt delivery, private
  configuration writer, and terminal trace events. Codex receives an exact
  `model_providers.*` Responses configuration and Pi receives an exact `models.json`.
  API-key fields name child environment variables; token bytes are never serialized
  into either file. An unknown runnerRef, protocol, or executable fails with a typed
  launcher error; there is no basename-selected or silent bare-exec fallback. The two
  M1 declarations are retained for the already published images. A new immutable
  runner image instead supplies the closed declaration at
  `/opt/rc-runner/etc/rc-runner-adapter.json`; an `environment-only-v1` adapter may
  use an image-owned wrapper for runner-specific setup. Adding such a runner therefore
  does not add a KCS core protocol branch or launcher heuristic.

Provider implementation and isolated canary evidence must satisfy these requirements
before production activation.

The existing six workspace terminal operation IDs and paths are lane-additive in
2.4. Hosted bindings retain the original `workspace` response shape. For a native
binding, control asks the launcher to create the PTY in the runtime container; the
launcher applies the terminal identity transition and starts it as UID/GID
`10002:10001`, with zero capabilities, `no_new_privs`, `umask 0002`, and cwd
`/workspace/worktree`. The native response records
`container=runner`, `launcherMediated=true`, effective identity, and cwd. KCS must
not implement this as direct Kubernetes exec into the root launcher. No separate
native terminal path is added. OpenAPI 2.5 adds a distinct, scoped developer-session
relay for IDE traffic; it does not replace or fork the PTY wire.
The terminal shell receives a fresh bounded shell environment and does not inherit
the agent child's model-gateway token path or token-bearing process environment.
Native terminal creation first pauses the runner and the snapshot therefore fixes
`runnerPaused=true`. Launcher starts only `/bin/sh`; absence of that registered
shell is a typed dependency failure, never a fallback to arbitrary exec. Closing
the PTY resumes the runner only when that session initiated the pause and no
deadline/cancel/terminal condition has superseded it.
The distinct terminal UID is mandatory isolation: UID `10002` must not be able to
read the UID `10001` agent child's `/proc/<pid>/environ`. A conformance test must
prove this denial. Runner pause remains mandatory for worktree-write concurrency,
not as a substitute for secret isolation.

### Control state file and launcher socket

Launcher atomically publishes `/run/rc-control/runner-state.json` as closed JSON.
The required fields are `schemaVersion` (constant `1`), `jobUid`, `podUid`,
`generation`, monotonic `sequence`,
`state`, `stateDigest`, `childPid`, `processExit` (`kind`, `exitCode`, `signal`),
`stopCause`, `protocolTerminal` (`observed`, `eventKind`, `stopReason`,
`errorCode`), `childStartedAt`, `childFinishedAt`, and `observedAt`. `stateDigest`
is SHA-256 over RFC 8785 JCS of the document with `stateDigest` omitted. Publisher
writes a same-directory temporary file, sets `root:root`/`0600`, fsyncs it, renames
over the destination, and fsyncs the directory. Control rejects a sequence rollback,
digest mismatch, binding mismatch, partial document, unknown field, or symlink.

`/run/rc-control/launcher.sock` is a `root:root`/`0600` Unix stream socket. Each
frame is a four-byte unsigned big-endian payload length followed by at most `131072`
bytes of RFC 8785 canonical UTF-8 JSON. Request frames are closed objects with
`schemaVersion` (constant `1`), `command` (`credentialStatus`, `start`, `inspect`,
`stop`, `finalize`, `commitFinalize`, `createPty`, `writePty`, `readPty`, `resizePty`,
or `closePty`),
`requestRef`, `requestDigest`,
`jobUid`, `podUid`, `generation`, and command-specific `payload`. ACK frames are
closed objects with `schemaVersion=1`, the same binding and request fields plus `state` (`accepted`,
`completed`, or `failed`), `replayed`, `observedAt`, and nullable `errorCode`.
Identity is `(command, requestRef, jobUid, podUid, generation)`; first write wins,
the same digest replays the stable ACK, and a different digest is a conflict.
`createPty` pins UID/GID `10002:10001`, cwd `/workspace/worktree`, `/bin/sh`, TTL,
`HOME=/run/rc-terminal/home`, `TMPDIR=/run/rc-terminal/tmp`, and a non-secret
environment allowlist, and its ACK returns `ptyRef` (equal to the public
`terminalRef`) and `expiresAt`. `writePty` carries `ptyRef` and base64 input bytes;
`resizePty` carries `ptyRef`, rows, and columns; `closePty` carries `ptyRef` and a
reason. All three use first-wins request identity; writes/resizes after close or TTL
expiry fail with the existing typed terminal state error.

PTY input writes are never performed while holding the launcher-wide state mutex.
Each terminal has a single-writer gate and a two-second write deadline; deadline
expiry closes that PTY and returns `pty_write_timeout`. Thus a stalled terminal
consumer cannot block `inspect`, `stop`, `finalize`, or another terminal session.
Exact input attempts/acceptance and observed output chunks are appended as ordered,
binding-scoped base64 facts to
`/run/rc-control/terminal-session.jsonl`; the file is platform-owned and is not a
research-result authority.

Launcher-to-control PTY output is a closed event frame with `schemaVersion=1`,
`event=ptyOutput`, `ptyRef`, exact binding/generation, monotonic `startCursor` and
`nextCursor` byte offsets, base64 bytes (at most `65536` decoded bytes), `eof`, and
`occurredAt`. Control validates contiguous cursors, durably bounds/caches output,
and serves the existing cursor-based read operation, including stable replay. EOF,
explicit close, or TTL expiry closes the PTY first-wins. The socket never accepts
arbitrary exec or shell commands.

## 4. Credential, lifecycle, deadline, and replacement behavior

The KCS Secret-projection lease is distinct from the model-gateway token claim
lifetime. The projection contract is `120..900` seconds; sanitized fixtures use
`180`. The lower bound includes observed kubelet projection delays of approximately
`47` and `55` seconds. Gateway claim expiry remains opaque to KCS and must cover the
projection interval plus the authorized runner window; it is not a KCS schema field.

`startRunner` acceptance is the only soft-timer origin. A replay does not restart
that timer. Before ACK, KCS verifies the descriptor job/pod IDs against the exact
binding; assembly/recipe/task/protocol against the frozen job spec and active
activation receipt; and the grant against job/pod, agentRun, generation, and
nativeLaunchDigest. Staging and recipe activation must be active, and the grant must
be available and unexpired. Violations are `STALE_BINDING` or
`PRECONDITION_FAILED`; the soft timer cannot start on a failed precondition.

`stopRunner` sends TERM and then KILL to the child only; launcher and
control remain available to observe exit and capture output. KCS records process
exit/signal, stop cause, and protocol terminal/error fields separately and never
maps any of them to research success.

The runner state `exited` is reserved for `natural_exit`. A child terminated for
`stop_requested`, `soft_deadline`, `cancel_requested`, `oom_killed`, or
`hard_deadline` is `killed`, even when the raw process observation is a normal Unix
signal such as `SIGTERM`.

An eviction, `ENOSPC`, image-volume mount failure, node loss, or hard deadline is a
terminal delivery/runtime classification for that binding. KCS does not create a
replacement Pod; the activation receipt fixes `replacementPodCreated=false` and
the binding admits at most one Pod incarnation.

Native finalize requires a capture receipt and fence bound to the exact
`jobUid`/`podUid`/generation and runner-observation sequence/digest. Capture state is
`complete`, `failed`, or `indeterminate`. Provider finalization reports the capture
barrier; it does not infer the research result.

Launcher finalization is a recoverable two-phase internal wire. `finalize` first
atomically writes root-only `/run/rc-control/finalize-receipt.json`, containing the
request ref/digest, capture receipt digest, binding, generation, stable receipt digest,
and acceptance time, then ACKs with `launcherAlive=true`. Replaying the same identity
returns that receipt; a different identity is rejected. The launcher does not exit.
After KCS has durably retained the ACK, control sends `commitFinalize` with the receipt
digest. The launcher persists `state=committed`, writes the ACK, and only then exits.
Control may read the receipt after an interrupted ACK and reconcile rather than infer
success from a missing socket. This internal command is not a public ResearchCosmos
operation.

Existing transfer paths and schemas are lane-additive: hosted bindings dispatch to
the workspace sidecar, while native bindings dispatch to control. Control remains
alive through the capture barrier. Transfer and capture work must never be sent to
the root launcher or experiment child.

## 5. Observability

The minimum evidence surface is:

- activation receipt: recipe/assembly digests, selected delivery arm, requested
  references, actual image IDs, image-filesystem estimates, requested/observed Pod
  resources, node, delivery failure, and no-replacement assertion;
- runner generation: start ACK/soft deadline, credential acknowledge/destruction,
  launcher liveness, monotonically sequenced runner observation, raw process exit,
  stop cause, and protocol terminal/error observation;
- `runner_phase` runtime events with sequence and state digest;
- bounded cursor logs for `runner` and `control` containers, subject to the existing
  log redaction and size policy;
- exact runner stdout/stderr append-only tees at
  `/run/rc-control/runner-stdout.raw` and `/run/rc-control/runner-stderr.raw`, plus the
  agent-authored stdout JSONL at `/workspace/worktree/.trajectory/session.jsonl`.
  Each complete stdout line is also emitted to the runner container log as `RCJL|...`;
  the selected adapter observes terminal JSONL facts but never changes agent behavior.

## 6. Remote evidence register

| Probe | Observed fact | Freeze consequence |
| --- | --- | --- |
| initial init-copy canary | disk pressure/EmptyDir eviction on the large copy path | reject init-copy delivery; require explicit ephemeral and image-fs accounting |
| K3s 1.36 ImageVolume canary | digest-pinned agent image mounted read-only; environment image present; Node/Pi/Codex launched; worktree write succeeded; runner mount write was denied; ephemeral request `64 MiB`/limit `256 MiB`; completion about `3.30s`; image events reported both images already present; no approximately `687 MiB` copy | `assembled.imageVolume` is the default; activation must record admitted request/limit |
| optional Secret projection canaries | projection became visible after about `47s` and `55s`; a `60s` projection lease was exhausted before start | minimum projection lease `120s`; fixture/recommendation `180s` |
| M1 registry pull canary | the exact platform ImageVolume digest was absent on the target node, authenticated pull succeeded in `301ms` (reported image size `1,364,805` bytes), and subsequent mounts used the cached digest; the exact runner and environment digests were already cached | registry authentication and an exact platform-image cold pull are proven; a full uncached assembly SLO remains `not_reported` |
| M2 live-worktree Journey | a real Codex child ran for `20.66s`; 24 operator samples observed monotonic runner sequence plus changing worktree and metrics bytes; capture/finalize ended `succeeded` | live reads must be immutable, binding-scoped snapshots; ad-hoc mixed-moment reads are forbidden |
| M2 PTY/stop Journey | existing six PTY operations accepted input/resize/read/replay/close, replayed identical output, captured the terminal edit, then stop/capture/finalize ended `succeeded` | reuse the 2.4 PTY; add only explicit `CURSOR_GAP` retention semantics |
| M2 OpenVSCode relay | OpenVSCode `1.109.5` ran loopback as `10002:10001`; outer relay returned `401` for bad credential, `410` after expiry/revoke, and `101` for WebSocket; exact image cold pull was `3.355s` | browser reaches KCS only through RC same-origin ticketing and binding-scoped relay; no direct credential or public Pod endpoint |
| M2 capability activation | exact Skill and Tool image volumes pulled in `236ms`/`259ms`, were read-only, and a real Codex run read the Skill, invoked the Tool, and produced captured results | resolve immutable capability pins to an exact activation plan and record actual mounted image IDs/digests |

Private raw probe artifacts remain outside the repository. Before production
activation, the evidence owner attaches sanitized command output and timestamps to
the release review. The M1 canary proves registry authentication and one exact
platform-image cold pull, but does not present cached runner/environment timings as
a full cold-assembly SLO.

## 7. M2 additive behavior

### 7.1 Live workspace

KCS creates a bounded immutable snapshot from one exact
`jobUid`/`podUid`/generation. Control walks `/workspace/worktree` using directory
file descriptors, never follows symlinks, and freezes entry metadata and content
bytes before returning a sequence and digest. Tree, diff, and ranged-content reads
refer only to that snapshot. A Pod-incarnation mismatch is `STALE_BINDING`; expiry
is `LIVE_SNAPSHOT_EXPIRED`. Limits and omissions are explicit, and captured output
remains the only sealed result authority.

Container logs and PTY output keep their 2.4 cursor wires. If requested bytes have
fallen out of the retention window, KCS returns `CURSOR_GAP` with the requested and
earliest retained opaque cursors. It never silently jumps forward.

### 7.2 Developer session

The registered OpenVSCode release is `1.109.5`; the upstream release tar SHA-256 is
`b433bf4f0227321a7014d8460d10a8f958adc0f45aa79bd889e84e65e8f88363`. The probe
image is digest-pinned as
`10.255.250.1:5000/researchcosmos/rc-openvscode-server@sha256:f81187d7c9480c74cddbc3eec3955c239d492b4fbc1cb023b14c154f8b2d4e40`.
It is mounted read-only outside the environment image and runs as terminal identity
`10002:10001`, with its own HOME/TMP, against the group-writable worktree. It binds
only `127.0.0.1:3000`. `--without-connection-token` is permitted only behind the
KCS outer relay; no Pod port is public.

The KCS dev-session credential is returned only to the RC backend, is never exposed
to browser JavaScript, and is bound to tenant, principal, conversation, Attempt,
job UID, Pod UID, generation, TTL, and connection limit. RC issues its own
same-origin browser ticket and proxies HTTP/WebSocket traffic. Renew rotates the KCS
credential; expiry and revoke are immediate and typed. Replacement Pod identity is
stale, not transparently reattached. KCS strips credentials before proxying and does
not pass them to OpenVSCode. Extensions are curated/cached through platform policy;
arbitrary Open VSX egress is disabled by default.

### 7.3 Exact Skill and Tool activation

RC sends exact capability refs and material digests; it never sends arbitrary image
or command fields in `CreateJob`. KCS resolves the approved runner/environment recipe
plus pins to one immutable `CapabilityActivationPlan`. Each bundle is a digest-pinned
image volume mounted read-only under `/opt/rc-skills/<id>` or
`/opt/rc-tools/<id>`. Launcher maps only the plan-declared discovery paths into the
selected runner. The activation receipt records requested refs/material digests,
resolved image refs, actual image IDs, target paths, binding/generation, and state.

Missing registration, protocol/platform incompatibility, material mismatch, or
unavailable bundle fails loudly before runner start. There is no runtime download,
mutable plugin install, host-path fallback, or silent omission. Agent-native shell
and file operations remain sandbox capabilities; only externally governed Tools are
activated through this catalog path.
