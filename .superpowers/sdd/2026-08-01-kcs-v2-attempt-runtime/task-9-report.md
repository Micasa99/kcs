# Task 9 report — packaged runtime and dedicated two-host deployment assets

## Result

Base commit: `8cdea7bc055a5b1a33de91398b1cf815c6be3c8e`

Branch: `codex/kcs-v2-attempt-runtime`

Requested implementation commit subject:
`build(v2): package dedicated runtime deployment`

Review-fix commit subject:
`fix(v2): harden dedicated runtime deployment`

Review-fix round 2 commit subject:
`fix(v2): validate effective k3s runtime identity`

Author/committer: `zhangbo <226653803@qq.com>`

Task 9 packages the existing V2 provider without deploying it:

- the canonical compact OpenAPI is a generator-owned, byte-identical
  `kcs.openapi` wheel resource; the route no longer resolves a source-tree
  path, and the generator/check enforces the package copy;
- the API and both conformance Containerfiles use fixed linux/amd64 base
  manifests, require a nonempty source revision, emit OCI source/revision/
  license labels, and use the exact root `requirements.lock` for the API;
- agent start verifies the staged launch bundle bytes and runs only a closed
  conformance action in a real bounded child, retaining the real child PID;
  workspace invoke executes the corresponding fixed actions instead of
  echoing caller-supplied success/output;
- both fixture PID 1 commands support no-argument serve and only the fixed
  `rpc` stdin/stdout path. The allowlist covers bidirectional fixed shared-file
  probes/digests, real workspace `nvidia-smi`, agent no-device observation,
  and `RC_PUBLIC_RUNTIME_BASE_URL` reachability. The probe rejects loopback,
  unspecified, link-local, multicast, and reserved resolutions, connects
  directly to a validated address while preserving Host/TLS SNI, and never
  re-resolves, proxies, or follows redirects. Events are
  sanitized compact JSON lines; there is no shell or caller-selected command,
  path, content, URL, or result;
- the API is a one-replica `Recreate` Kubernetes Deployment on the control
  selector, with its dedicated ServiceAccount, TLS/Bearer Secrets, HTTPS
  startup/readiness/liveness probes, TMPDIR `emptyDir`, ephemeral-storage
  requests/limits, and a TLS-only ClusterIP Service;
- the workload ServiceAccount remains tokenless and unbound; existing
  ingress-only deny NetworkPolicy semantics remain unchanged; RBAC contains
  the exact adapter verbs and attempt Jobs retain only the GPU selector;
- the fixed-digest NVIDIA device-plugin DaemonSet is selected only to the GPU
  pool. The worker script installs an explicitly pinned toolkit package,
  configures the NVIDIA containerd runtime as default, labels the GPU node,
  and applies that plugin;
- control/worker scripts require explicit SSH-config aliases, supported
  addresses/CIDRs, pinned versions, exact no-newline token files, and have no
  host/user/key or local fallback. `--check` validates only. Real deploy paths
  bind k3s/kubelet to private addresses, reject IPv4/IPv6/star wildcard
  listeners plus any other-address TCP 6443/10250 or UDP 8472 listener, verify TLS SAN material, stop named V1 debug units, and reject
  the named legacy ServiceAccount in V2/cluster-wide bindings;
- existing k3s fails closed unless exact requested version, effective private
  service arguments, interface, node identity, and role match. The effective
  systemd `argv[]` is parsed with `shlex`; critical singleton and key-scoped
  values must occur exactly once, so later conflicting flags cannot override a
  safe-looking earlier value;
- the worker installs/starts or validates k3s, then proves the exact Ready node
  name/InternalIP through the control API before any NVIDIA package/runtime
  mutation. Only its second bounded phase installs/configures NVIDIA, restarts
  the agent, and proceeds to the final InternalIP/GPU-label proof;
- `kcs-v2.service` invokes an installed narrow wrapper that validates an exact
  RFC1918/CGNAT/ULA control bind and execs only the fixed TLS ClusterIP Service
  port-forward. Runtime secrets/config/evidence are ignored. Docs call
  the existing Journey an early smoke and reserve full P6 evidence for Task 10.

No SSH, remote mutation, deployment, local KCS, local k3s, or Kubernetes
runtime was used.

## Files

Packaging/resource:

- `.dockerignore`, `Containerfile`, `requirements.lock`, `pyproject.toml`;
- `src/kcs/openapi/__init__.py` and generated
  `src/kcs/openapi/kcs-v2-jobs.openapi.json`;
- `scripts/generate_v2_openapi_artifacts.py` and
  `src/kcs/server/routes/jobs.py`.

Fixed conformance runtime:

- `src/kcs/conformance/actions.py`, `action_runner.py`,
  `agent_supervisor.py`, and `workspace_sidecar.py`;
- `deploy/v2/conformance-agent.Containerfile` and
  `deploy/v2/conformance-workspace.Containerfile`;
- minimal required Task 5/6/7 Journey fixture updates for the closed actions.

Deployment/docs:

- `deploy/v2/namespace.yaml`, `kcs-api.yaml`, `config.example.yaml`,
  `kcs-v2.service`, `kcs-v2-port-forward.py`,
  `kcs-v2-validate-k3s-exec.py`, and `nvidia-device-plugin.yaml`;
- existing `deploy/v2/rbac.yaml` and `network-policy.yaml` were preserved;
- `scripts/deploy_v2_control.sh`, `scripts/deploy_v2_worker.sh`;
- `.gitignore`, `README.md`, `docs/v2-hosted-attempt-api.md`;
- exactly one new focused test:
  `tests/deploy/test_task9_packaging_journey.py`.

## TDD evidence

Initial RED:

```text
.venv/bin/pytest -q -s tests/deploy/test_task9_packaging_journey.py
ModuleNotFoundError: No module named 'kcs.openapi'
1 failed in 0.05s
```

The failure was the intended missing installed-package resource, not a test
syntax/setup error. The final focused command is green:

Review fix round 1 first tightened the same single Journey. Its RED was the
floating build backend:

```text
assert ['setuptools>=68.0', 'wheel'] ==
       ['setuptools==80.9.0', 'wheel==0.45.1']
1 failed in 0.04s
```

A mutation check removing CGNAT from the supported topology then failed the
Journey at the real control `--check` subprocess before support was restored.
No additional test file was added.

Review fix round 2 added one behavior to that same Journey. RED failed because
the effective-argv validator did not exist; GREEN runs the real validator with
a valid systemd `argv[]` and proves that appending a conflicting second
`--bind-address` returns only the sanitized configuration-mismatch error.

```text
.venv/bin/pytest -q -s tests/deploy/test_task9_packaging_journey.py
1 passed in 0.55s
```

## Raw focused Journey events and interpretation

```jsonl
{"event":"canonical_package_resource","sha256":"efcbb64fc1d96ec5f7797eda92405a4ae5c596b3a7864dad6396e423a09e193e"}
{"event":"api_manifest_contract","imageState":"non_runnable_placeholder"}
{"event":"oci_inputs_pinned","runtime_requirements":49}
{"event":"shared_agent_to_workspace","sha256":"913a1506a91d42b2486c28eb56358718859ba4732231f22452f74404c1d9cd55"}
{"event":"shared_workspace_to_agent","sha256":"043387c384035d7976448577990a75406a512aa0aefab7a5ee1cee685a5d2c59"}
{"event":"agent_gpu_observation","gpuDeviceCount":0,"ok":true,"protocolVersion":1}
{"code":"LOOPBACK_RUNTIME_URL","event":"runtime_url_observation","ok":false,"protocolVersion":1}
{"bodySize":0,"code":"GPU_UNAVAILABLE","event":"workspace_gpu_observation","ok":false,"protocolVersion":1}
{"event":"deployment_check","ok":true,"script":"deploy_v2_control"}
{"event":"deployment_check","ok":true,"script":"deploy_v2_worker"}
```

The lines were read manually. The canonical digest is the frozen expected
value. The two different shared-probe digests round-trip in opposite
directions through the same real directory. The local agent truthfully sees
no NVIDIA device. The API manifest event explicitly classifies the committed
all-zero image as a non-runnable placeholder; the deploy gate rejects it and the
positive check uses a distinct nonzero synthetic digest. The workspace does not
fake GPU success: because this Mac is
not a formal GPU host and has no `nvidia-smi`, it returns the fixed
`GPU_UNAVAILABLE` observation. The unsafe loopback URL is rejected before connection;
Task 10 must prove a real non-loopback success. Both script checks emitted one
success event without entering SSH.

## Verification

- `bash -n scripts/deploy_v2_control.sh scripts/deploy_v2_worker.sh`: pass.
- `shellcheck`: unavailable on this machine; no result claimed.
- `.venv/bin/python -m build`: pass; the isolated build log installed exactly
  `setuptools==80.9.0` and `wheel==0.45.1`; clean wheel and sdist produced, and
  the wheel contains the package OpenAPI resource and fixed entrypoints.
- isolated temporary Python 3.12 environment, wheel installed with
  `--no-deps`: package resource smoke passed with
  `sha256=efcbb64f...09e193e`, `bytes=103962`; installed fixed action runner
  returned the actual local no-GPU JSON line. The repeated fix-round smoke
  emitted `isolated_wheel_smoke` with `openapiBytes=103962` and the exact digest.
- scoped Ruff lint and format check over all changed Python/test files: pass.
- scoped strict Mypy over the five touched runtime/wrapper source modules:
  `Success: no issues found in 5 source files`.
- review-fix round 2 Ruff/format plus strict Mypy over the new effective-argv
  validator and updated Journey: pass; Mypy reports no issues in its source file.
- `py_compile` over all changed Python/runtime/test entrypoints: pass.
- `.venv/bin/python scripts/generate_v2_openapi_artifacts.py --check`: pass;
  `validated 31 route exchanges`, canonical SHA-256 exactly
  `efcbb64fc1d96ec5f7797eda92405a4ae5c596b3a7864dad6396e423a09e193e`.
- relevant Task 5–8 regressions: `12 passed, 1 warning in 1.25s`. The warning
  is the inherited Starlette TestClient/httpx deprecation.
- `git diff --check`: pass.

## OCI availability and non-evidence

`docker buildx version` succeeded:

```text
github.com/docker/buildx v0.30.1-desktop.1
```

Registry inspection resolved the exact linux/amd64 manifests used here:

- Python 3.12.11 slim bookworm:
  `sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49`;
- NVIDIA CUDA 12.8.1 runtime Ubuntu 24.04:
  `sha256:828c4d878adcaa4265d80c95d8ec877149b49bb2419a4cf3bb6aa889bbb7ca2e`;
- NVIDIA device plugin v0.19.0 linux/amd64:
  `sha256:7bf6ab18378be099493c9fe50f9cd2d559e0d81f17742d7ac188365408579d5d`.

The required API image build was attempted and stopped immediately:

```text
ERROR: Cannot connect to the Docker daemon at unix:///Users/bo/.docker/run/docker.sock.
Is the docker daemon running?
```

The shared daemon blocker also prevents the two conformance builds, so no
local OCI image build or image digest is claimed. No image was pushed. Even a
successful local build would be supporting evidence only, never formal P5/P6
evidence.

## Known boundaries / Task 10 obligations

- No dedicated host was contacted and no live RBAC `kubectl auth can-i`, TLS,
  k3s, GPU, runtime URL, restart, cancel, delete, or resource-recovery proof
  exists yet. Task 10 owns all of those formal results.
- `allowedPeerCidrs` is validated but the scripts deliberately do not rewrite
  an existing host firewall. Task 10 must prove that the operator-managed
  firewall/overlay allows only the declared peers and denies public paths.
- The committed API/conformance image references are deliberately invalid
  digest-shaped placeholders. A publisher must build/push linux/amd64 images,
  record their real digests, and render `name@sha256` references.
- The workspace image has a digest-pinned CUDA base and a locked KCS wheel, but
  Ubuntu `ca-certificates`, `python3-minimal`, and `python3-pip` still resolve
  from the distribution repository during build; that layer is not claimed
  bit-for-bit reproducible. The NVIDIA toolkit installed on the worker is
  explicitly version-pinned.
- Python build-backend versions are exact and Containerfiles build with
  `--no-build-isolation`, but `pip` still downloads those artifacts from the
  configured online index without committed hashes or an offline wheelhouse.
  Repository trust and artifact integrity for those downloads remain a publisher
  boundary; this task does not claim an offline reproducible build.
- The deployment scripts require an already configured secure SSH alias and an
  NVIDIA package repository capable of serving the exact requested toolkit
  version. They intentionally fail instead of guessing a host, user, key,
  public topology, mutable version, or local fallback.
- Both nodes must already reach/authenticate to the immutable image registry;
  private registry credentials/configuration remain operator-owned k3s node
  configuration. Task 10 must prove the actual image pulls.
- Runtime Secret bytes, private topology/config, and Review Pack evidence stay
  untracked. No model/provider key was added.
