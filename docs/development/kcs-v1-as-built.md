# KCS V1 AS-BUILT (development/debug only)

This document records the repository state immediately before the hosted-attempt V2
domain was introduced. It is descriptive, not a compatibility contract. V1 remains a
development/debug surface and is not the formal ResearchCosmos provider runtime.

## Application and configuration

The FastAPI application in `src/kcs/server/app.py` mounts static dashboard assets and
registers the system, container, cluster, shell-proxy, and shell-session routers. The
CLI targets `/api/v1` on localhost. The server entry point requires a local TOML/YAML
cluster configuration, applies it through the singleton `ClusterService`, optionally
repairs NFS, and then starts Uvicorn.

V1 authentication is a configured shared `api_key`/`KCS_API_KEY`. When it is absent,
the V1 middleware allows requests. Static files and interactive documentation are
excluded from that middleware. This behavior is intentionally not reused by V2,
whose service bearer authentication is fail-closed.

The V1 `ClusterConfig` contains backend, API key, local privilege, NFS, and worker
connection fields. The service performs host setup and can use local subprocesses,
SSH, kubectl, and Kubernetes client operations. Those fields and behaviors are not
part of `V2RuntimeSettings`.

## V1 resource and route shape

V1 models an independently named “container” and exposes create/list/inspect/delete,
start/stop/scale, logs, exec, upload, Pod listing, build/image, cluster apply, system,
and shell surfaces. A create request accepts a mutable image reference, optional host
volumes, arbitrary environment, replica count, node pinning, and optional resources.
The service may derive a name from an image and may resolve locally built image tags.

V1 errors are generally FastAPI `detail` strings and may be built directly from caught
exceptions. Upload selects an NFS direct write when possible and otherwise invokes
`kubectl cp`. Exec and interactive shell flows are direct V1 debugging tools. These
are not the V2 error, transfer, or supervisor protocols.

## Isolation boundary

V2 is a new domain under `src/kcs/jobs`, `/api/v2`, and the canonical source
`openapi/kcs-v2-jobs.openapi.yaml`. It does not import V1 container models or inherit
V1 permissive authentication. Production mode is `KCS_API_MODE=v2`; the V2 service
and legacy/debug service use distinct Kubernetes identities. No development machine
is a formal KCS host.
