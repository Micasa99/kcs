# KCS V2.3 observability live review

Observed on 2026-08-08 (Asia/Shanghai) against the dedicated two-node KCS cluster.
This file contains no credential, private address, raw Kubernetes node name, or
workload output.

## Published identity

- Source revision: `a9e7a2cebea08f98c7a0792ad78638cf480994ad`
- API image digest: `sha256:ce54ad81f09874a2efc574eb11d5727b227d19e7941d8476d811ad671e89afc6`
- OpenAPI version: `2.3.0` (31 operations)
- Canonical OpenAPI SHA-256: `965ec1236bab74d2306ce96c97109abc12f80971f18dc32b3bb7602bc8fed526`
- Image revision/license labels and the packaged OpenAPI bytes were read back from
  the published image and matched the values above.

## Live cluster result

- Both the control node and GPU worker were `Ready` on the pinned k3s release.
- API, Prometheus, Alertmanager, kube-state-metrics, and dcgm-exporter Pods were all
  `Running` and ready with zero restarts after the final rollout.
- Prometheus reported all five scrape targets up: self, kube-state-metrics,
  dcgm-exporter, and cAdvisor for both nodes.
- The authenticated public KCS endpoint returned `200` for the three additive
  routes with the gateway CA trusted; the same request without a Bearer token
  returned `401`. `healthz` reported Prometheus/DCGM/kube-state-metrics all `up`.
- `telemetry/nodes` returned both redacted compute nodes. CPU and memory were present
  for both; the GPU node returned four RTX 4090 devices with real utilization, VRAM,
  temperature, power, ECC, and XID observations. The CPU node returned `gpus: []`.
- An isolated one-GPU probe produced a non-null
  `podRef=researchcosmos-v2/kcs-v23-telemetry-probe` for its allocated device. After
  deletion, the next observation returned every `podRef` to null.
- Runtime events returned ordered node-condition and retained managed Job-phase
  entries. API Recreate preserved the maximum sequence and cursor; replay from the
  pre-restart cursor returned `truncated=false` and no duplicate events.
- During a reversible dcgm-exporter stop, `healthz` stayed HTTP 200 and reported only
  `dcgm=down`; after restoration all three dependencies returned to `up`.
- Canonical discovery returned `Cache-Control: no-store`, version `2.3.0`, and an ETag
  equal to the exact response-body SHA-256.

## Raw-log review

The final API log contained successful startup, health probes, and `200` responses
for capacity, queue, telemetry, events, health, and OpenAPI, with no traceback,
exception, warning, or 5xx line. Prometheus loaded its persistent TSDB and rules
without warning/error. dcgm-exporter initialized DCGM, exposed the required metrics,
and reported only the expected unsupported profiling-metric warning; profiling
metrics are outside this contract and standard GPU metrics were read successfully.

## Validation and remaining operator work

- Artifact generation/check passed with 32 route exchanges.
- Focused observability/OpenAPI/security/deployment checks passed; a broader run was
  stopped after 91 passing tests because it exercised unrelated long-running suites.
- Monitoring images are immutable and mirrored to the KCS-internal registry so node
  startup does not depend on public registry reachability.
- Alertmanager currently routes to its internal sink because no external receiver was
  supplied. A production receiver, PVC backup policy, and HA remain infrastructure
  work rather than API correctness gaps.
- The currently reachable authenticated HTTPS endpoint is temporary. Moving it to a
  stable DNS name and standard port does not change the KCS API or require SSH in the
  Product runtime path.
