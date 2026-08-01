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

## Tests

```bash
pytest tests/ -v                # 29 integration tests
python tests/performance.py     # throughput + latency benchmarks
```
