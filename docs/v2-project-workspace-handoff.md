# Durable Project Workspace handoff

Status: **KCS implementation complete; isolated remote canary passed; production
unchanged**.

The only supported flow is:

```text
durable Project Workspace
→ exact Project snapshot / WorkspaceBaseManifest
→ isolated Attempt Git checkout
→ existing CaptureFence / sealed WorkspaceRevision
→ new retained Project checkout
```

Git is an operator and user convenience, not the ResearchCosmos identity
authority. The Project has one persistent Git history. An Attempt initializes a
separate ephemeral repository from exact staged bytes; it never shares the
Project PVC or `.git` directory. Import creates a new `rc/retained/*` branch and
checkout and never overwrites or merges the current Project checkout.

## Active contract and images

- OpenAPI version: `2.6.0`, 58 operations.
- Canonical JSON SHA-256:
  `28f34463af110af835b13a68f256f8b7bae3825098e0759ba09498f3857338dd`.
- Source implementation commit:
  `f5648385c71111a2aeeafdcbc5b7e3f06fa8d59c`.
- Canary API image:
  `10.255.250.1:5000/researchcosmos/kcs-api@sha256:8bfa5d673f08b2014b82e655603885ca27d8a34948dce0f18955e48b4ac57b34`.
- Workspace control image:
  `10.255.250.1:5000/researchcosmos/kcs-control@sha256:f6c49b621a7d8a10e369937aead5e040962b29057fe886163f9b01b2678ea524`.
- AICOSMOS Workspace extension ImageVolume:
  `10.255.250.1:5000/researchcosmos/aicosmos-workspace-vsix@sha256:48f5daf6f3ec900ad14d014dcc14905d9868df24f27d58dde24242f9e805c292`;
  raw VSIX SHA-256
  `5ffad8795df18e9fd4c1ae70d4c5f66ec5ee07afce069e3579a17c56c0804ff7`.

The operator must copy these exact refs into the deployment configuration. There
is no local, SSH, Hosted, empty-directory, or mutable-tag fallback.

## Remote acceptance

The canary ran in isolated namespace `kcs-durable-canary-20260810`; it did not
modify `researchcosmos-v2`. Raw non-secret evidence is retained on `RCkcs2` under
`/data/kcs-build-durable/evidence/`.

The observed functional chain was:

1. KCS created a 5 GiB persistent Project PVC and one CPU-only three-container
   Workspace Deployment (`workspace-control`, OpenVSCode, relay) on the real
   worker. The exact VSIX was installed and listed by OpenVSCode.
2. The Project snapshot returned two files, tree digest
   `23347c8d09cd118c1a2ea1275ebb06418995a886b5a6761e8ade10f8a50b84e3`,
   and Project base commit `015e0bed539152841f46528be030dca24885dde3`.
3. Deleting and recreating the Workspace Pod advanced generation 5 → 6 while the
   files, Project commit, PVC, extension, and IDE remained available.
4. An isolated Attempt staged the exact tree into branch
   `rc/attempt/ddb213c034d40546b2ad7d16`, changed the worktree, and captured three
   files as tree digest
   `92476db6f2338f22bdf28e6dec64a85ae2d14109edb50c96d7af12bd1ef07e6d`.
5. Import of `workspace_revision:canary-result` created retained checkout
   `checkout_a4b6a7bf856ecd23475ee510` at commit
   `86ad4f6f5e2af2912207a76a914520656770e406`; the original Project checkout was
   still clean and unchanged.
6. OpenVSCode HTTP relay returned 200. A session bound to the replaced Pod returned
   typed 409, and a revoked current session returned typed 410.

After evidence collection, the canary namespace, both canary PVCs, and its
temporary cluster binding were deleted and confirmed absent. Ephemeral canary
credentials were removed from the evidence directory. The production
`researchcosmos-v2` namespace was not changed.

## Deliberate boundary

This increment uses the existing single-node RWO storage class and bounded
snapshot/import bytes. RWX storage, cross-node migration, object-store transport,
automatic merge/rebase, Project deletion policy, and multi-region HA remain
separate infrastructure work. Existing Attempt CaptureFence, result authority,
finalize, cleanup, and closure semantics are unchanged.
