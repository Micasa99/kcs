<p align="center"><img src="src/kcs/static/icon.svg" width="140" alt="kcs"></p>

Container controller made simpler than k3s — declarative cluster config,
dashboard, REST API, and Claude Code shell integration.

The dashboard, `/api/v1` exec/upload/shell routes, `kcs ssh`, and
`CLAUDE_CODE_SHELL` proxy are **debug-only**. They reject V2 managed workloads;
formal V2 diagnostics use `/api/v2/jobs/{jobRef}` inspect and role-scoped log APIs.

## Setup

Requires **Python ≥ 3.12**, **k3s**, and **kubectl**.

```bash
pip install -e ".[dev]"
```

Optional: `docker` for image builds, `sshpass` for worker password auth.

Formal V2 is packaged separately from this V1 development quick start. Its API runs
only as the `kcs-v2-api` Deployment in the dedicated `researchcosmos-v2` namespace;
there is no host-mode V2 API service and a development machine is never a formal KCS
or k3s host.

## Quick start

```bash
kcs serve --port 8000 --config cluster.toml
```

```toml
# cluster.toml
api_key = "<secret>"           # required
nfs_path = "/srv/nfs/k3s"

[[workers]]
host = "<ip>"
user = "root"
password = "<ssh-password>"    # optional — uses pipe, never environ
```

Open `http://localhost:8000` for the dashboard, `http://localhost:8000/docs` for the API docs.

On startup, kcs applies the config: joins workers, deploys the NFS provisioner, prunes stale nodes. Already-joined workers are skipped. No manual steps.

## Dashboard

Topology view of the entire cluster — server, workers, containers, hardware usage bars (CPU / memory / GPU), node health, and NFS status. Create, stop, start, scale, and delete containers from the UI. Shell proxy management with one-click start/stop and copy-to-clipboard.

## CLI

```bash
kcs build -t myapp:v1 .           # build image → cluster registry
kcs ssh web                       # interactive shell
```

## Coding agent shell (debug-only)

Start from the dashboard (container detail → Start). A wrapper script is created at `~/.local/bin/kcs-bash-<container>`. Point Claude Code at it:

```bash
CLAUDE_CODE_SHELL=~/.local/bin/kcs-bash-<container> claude
```

Every Bash command now runs inside the container, with working directory and env preserved.
This path is for V1 debugging only and cannot select or modify a formal V2 Attempt Pod.

## Security

| area | approach |
|------|----------|
| API | `api_key` required in config |
| Network | bind `127.0.0.1` by default |
| TLS | `--ssl-certfile`/`--ssl-keyfile` |
| Rate limit | 120 req/min |
| Shell proxy | Unix socket, `0600` |
| SSH | pipe fd, never environ |
| NFS | `root_squash`, `755`, worker-only export |

## Dedicated V2 packaging and deployment

The root `Containerfile` builds the V2 API image. The two
`deploy/v2/conformance-*.Containerfile` definitions build the fixed agent and CUDA
workspace smoke fixtures. All bases are pinned to linux/amd64 manifest digests and
`requirements.lock` pins the API runtime graph. The build backend is fixed to
`setuptools==80.9.0` and `wheel==0.45.1`, and image builds install those exact tools
before building without isolation. Published API and workload image
references must be immutable `name@sha256:<digest>` values; the
`registry.example.invalid` values in committed YAML are deliberate non-runnable
all-zero placeholders, not published image claims; deployment rejects them. The
operator supplies the API and four monitoring image references through the five
`KCS_*_IMAGE` variables documented in `deploy/v2/config.example.yaml`, so source
manifests do not bind a particular registry or server address.

Start with `deploy/v2/config.example.yaml`, exporting every corresponding value from
an untracked operator environment. Both scripts perform a mutation-free local
validation mode:

```bash
scripts/deploy_v2_control.sh --check
scripts/deploy_v2_worker.sh --check
```

Without `--check`, the scripts require explicit SSH-config aliases. The control
script changes only the dedicated k3s server, V2 API namespace/RBAC/TLS Secrets, and
the KCS-internal monitoring namespace and TLS Service port-forward. The worker script
changes only the separate k3s agent, NVIDIA container runtime/device plugin, GPU node
label, and the KCS internal-registry trust/auth copied from the control node over the
authenticated deployment channel. Registry credentials remain untracked and are
never rendered by the script. There is no localhost or local-k3s fallback.

The control/worker addresses and allowed CIDRs must be wholly inside IPv4 RFC1918,
CGNAT `100.64.0.0/10`, or IPv6 ULA `fc00::/7` topology. k3s, kubelet, and VXLAN must
not be reachable from public interfaces. The
TLS certificate needs the configured private DNS/IP SAN; consumers trust the
operator-provided CA. `kcs-v2.service` forwards only the TLS ClusterIP Service to the
explicit nonpublic control address. The API image itself remains in-cluster-only.
The installed port-forward wrapper independently rejects public, wildcard,
loopback, unspecified, link-local, multicast, reserved, or non-control binds before
execing its one fixed `k3s kubectl port-forward` command. An existing k3s binary is
accepted only when its exact requested version and effective private service flags
and node identity/role match; mismatches fail closed before deployment.
The scripts validate `allowedPeerCidrs` but do not rewrite an existing host firewall;
Task 10 must record the operator-managed firewall/overlay proof.
The exact `KCS_NVIDIA_TOOLKIT_VERSION` package must be available from an already
configured trusted NVIDIA apt repository. Both nodes must already reach and
authenticate to the immutable image registry; configure node-level k3s
`registries.yaml` for a private registry. Task 10 proves the real image pulls.

V2.3 deploys Prometheus, Alertmanager, kube-state-metrics, and dcgm-exporter only
inside `kcs-monitoring`. Their Services are ClusterIP-only; raw time series never
leave KCS. Authenticated consumers use `/api/v2/telemetry/nodes`, `/api/v2/events`,
and `/api/v2/healthz`. Operational checks and failure recovery are documented in
`deploy/v2/monitoring/RUNBOOK.md`. SSH is an operator deployment transport, not a
runtime API dependency: Product and developer clients connect to the configured KCS
HTTPS endpoint with its CA and Bearer token.

The source tree now implements the additive V2.4 native-runner M1 lane while
preserving all 31 hosted operation locations and hosted request shapes. Native
recipes remain deny-by-default until an operator installs exact digest mappings;
production activation is a separate owner checkpoint. See
`docs/v2-native-runner-m1-runbook.md` and
`docs/v2-native-runner-oci-behavior-appendix.md`.

The additive OpenAPI 2.5 M2 contract is active in source and package at SHA-256
`89fe3c925c1b5f8d97d60b3fb3998e0ac361a4c0fea30dc3d377e9b89d8089e9`.
It adds immutable live-workspace snapshots, a scoped OpenVSCode relay, exact
Skill/Tool activation, and explicit cursor-gap errors; it does not add another PTY
or runtime fallback. Production activation remains an operator checkpoint. See
`docs/v2-native-runner-m2-probe-evidence.md`.

`scripts/run_v2_attempt_journey.py` is the Task 10 standalone Journey. One invocation
drives the normal, cancel, and UID-precondition Pod-loss branches and retains raw API,
role-log, transfer, and operator-checkpoint evidence. It is valid only against the
dedicated KCS control server and separate GPU worker; local Docker builds, local
process smokes, and local k3s are never formal deployment evidence. See
`docs/v2-hosted-attempt-api.md` for the O0-O3 operator boundary and Review Pack shape.

## Tests

```bash
pytest -q \
  tests/jobs/test_native_m1.py \
  tests/jobs/test_v24_hosted_compatibility.py \
  tests/jobs/test_v2_acceptance_matrix.py \
  tests/jobs/test_openapi_contract.py
```

These focused contract/lifecycle checks are the pre-deploy gate. Formal acceptance is
the real remote Journey described above and in the native runbook; a local smoke or a
test count is not deployment evidence.
