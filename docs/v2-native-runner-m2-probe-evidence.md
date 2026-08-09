# Native Runner M2 remote probe evidence

Status: **remote probes closed; source implementation active; production unchanged**.
Probes ran on the
real KCS/GPU cluster in the isolated namespace
`rc-native-m2-v25-20260809`. Production `researchcosmos-v2` was not changed. Raw
HTTP exchanges, Pod/Job YAML, Kubernetes events, runner/control logs, and checksum
manifests remain on `RCkcs2` under `kcs-m2-evidence/`.

The canonical active OpenAPI 2.5 SHA-256 is
`89fe3c925c1b5f8d97d60b3fb3998e0ac361a4c0fea30dc3d377e9b89d8089e9`.
The production deployment remains an explicit operator checkpoint and was not
changed by this implementation.

## Findings

| Spike | Real result | Contract decision | Raw evidence directory |
| --- | --- | --- | --- |
| live worktree + trace | Codex ran `20.66s`, exited `0`, emitted `turn.completed`; 24 samples observed worktree/metrics progression; two captures, finalize, and Job ended `succeeded` | create an immutable, bounded snapshot bound to job UID, Pod UID, generation, sequence, and digest; captured revision remains authoritative | `kcs-m2-evidence/live-pty-r4/` |
| existing PTY + stop | input, resize, read, identical cursor replay, close, DNS, and Gateway access worked; arbitrary external egress was denied; the terminal edit was captured; stop/capture/finalize ended `succeeded` | reuse all six 2.4 PTY operations; add only typed retention gap semantics | `kcs-m2-evidence/pty-stop-r5/` |
| OpenVSCode relay | OpenVSCode `1.109.5` ran loopback as `10002:10001`; invalid credential=`401`, expired/revoked=`410`, WebSocket upgrade=`101`; worktree edit succeeded without credential exposure | add binding-scoped create/inspect/renew/revoke/relay; browser receives only an RC same-origin ticket | `kcs-m2-evidence/dev-session-r1/` |
| exact Skill/Tool activation | real Codex read the exact Skill, invoked the exact Tool, and wrote captured results; both bundle mounts rejected writes; runner identity was `10001` | exact pins resolve to immutable read-only image volumes plus activation receipt; incompatibility fails before start | `kcs-m2-evidence/capability-activation-r4/` |

## Exact material facts

- OpenVSCode release tar SHA-256:
  `b433bf4f0227321a7014d8460d10a8f958adc0f45aa79bd889e84e65e8f88363`.
- OpenVSCode image:
  `10.255.250.1:5000/researchcosmos/rc-openvscode-server@sha256:f81187d7c9480c74cddbc3eec3955c239d492b4fbc1cb023b14c154f8b2d4e40`;
  reported size `78,000,205` bytes; cold pull `3.355s`.
- Relay image:
  `10.255.250.1:5000/researchcosmos/rc-dev-session-relay@sha256:9742fecb2cbe9a69c6b91b37cac8b6a2e50ef98aabbd0c1842e570099e9540d0`;
  relay binary SHA-256
  `283b40e50478461b32bce9f33123ae7c4415a570ef83e2d5caff9361e759c696`.
- Active, source-rebuildable relay image:
  `10.255.250.1:5000/researchcosmos/rc-dev-session-relay@sha256:7c684bc24bd04b2dd883b56c40d3df9674e01b1d292aaa4d3084ce3008ebaa04`;
  its auditable Go source and pinned builder are under `native/dev_session_relay/`.
- Active capability images are the exact registry entries in
  `deploy/v2/native-capability-registry.example.json`; the deployed registry remains
  deny-by-default until an operator explicitly copies those reviewed entries.
- Skill image:
  `10.255.250.1:5000/researchcosmos/rc-skill-reproducible-probe@sha256:ff8a774d304e226403a49067a877c7bc42d2202b4fbfcb41f4f679bcefb9c2f6`;
  material SHA-256
  `449e8e4ff4e46e4ee243771dcf62ecf0f33edc67722a13c7b0c808eced4a37b4`;
  cold pull `236ms`.
- Tool image:
  `10.255.250.1:5000/researchcosmos/rc-tool-probe@sha256:a0530296eab3c486b9155f6c44a57c7dfe0c1f0bdce81d7ee20a03e5fdbe0dce`;
  material SHA-256
  `ef751deee661e26cf3e0945f8ee4c9baae475e2c15e01f45655028521308267b`;
  cold pull `259ms`.

## Negative evidence retained

- Reading live files one by one can mix moments; a single immutable snapshot is
  required.
- The real transfer root is `worktree/...`, not `/workspace/...` or a caller-chosen
  host path.
- A stale Pod incarnation must fail typed; no replacement or transparent reattach.
- Direct experiment UID `10001` cannot read a root-owned `0400` gateway projection;
  launcher must read the credential before dropping identity.
- A Tool binary absent from the declared discovery path is not found; launcher must
  apply the exact activation plan rather than guessing paths.
- Runner exit without a live control sidecar loses the capture window; control must
  remain alive through capture/finalize.

The one temporary Quick Tunnel was used only to expose the isolated mock Model
Gateway to the canary Pod. It was not a Product↔KCS runtime path and is removed with
the probe namespace and temporary credentials. The resulting product contract is
still direct HTTPS KCS Native with no SSH, local, or tunnel fallback.

See the single behavior authority
[`v2-native-runner-oci-behavior-appendix.md`](v2-native-runner-oci-behavior-appendix.md)
for the frozen implementation rules.
