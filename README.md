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
all-zero placeholders, not published image claims; deployment rejects them.

Start with `deploy/v2/config.example.yaml`, exporting every corresponding value from
an untracked operator environment. Both scripts perform a mutation-free local
validation mode:

```bash
scripts/deploy_v2_control.sh --check
scripts/deploy_v2_worker.sh --check
```

Without `--check`, the scripts require explicit SSH-config aliases. The control
script changes only the dedicated k3s server, V2 API namespace/RBAC/TLS Secrets, and
the private TLS Service port-forward. The worker script changes only the separate
k3s agent, NVIDIA container runtime/device plugin, and GPU node label. There is no
localhost or local-k3s fallback.

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

The current `scripts/run_v2_attempt_journey.py` is an early API smoke, not the full
standalone Journey. Task 10 expands it with dedicated-host Kubernetes/GPU/restart/
cancel/delete evidence; local Docker builds and local process smokes are never formal
deployment evidence.

## Tests

```bash
pytest tests/ -v                # 29 integration tests
python tests/performance.py     # throughput + latency benchmarks
```
