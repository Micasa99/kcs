# KCS V2 observability runbook

This stack is internal to KCS. It observes Kubernetes and GPU reality; it does not
make scheduling decisions and it never rewrites missing telemetry as zero.

## First checks

Run `kubectl -n kcs-monitoring get pods,pvc` and inspect the failing Pod's unabridged
log. Then call authenticated `GET /api/v2/healthz`. Do not restart managed Attempt
Jobs while diagnosing the monitoring plane.

## KcsDcgmExporterDown

Check the DaemonSet Pod is on the GPU node, uses RuntimeClass `nvidia`, and can read
`/var/lib/kubelet/pod-resources`. Run `nvidia-smi` on the node and inspect exporter
logs for an NVML/DCGM/driver compatibility error. A missing metric remains omitted
from `/api/v2/telemetry/nodes` until the exporter is healthy.

## KcsKubeStateMetricsDown

Check the Deployment and its ClusterRoleBinding. Confirm `/metrics` is reachable at
the Service and that the Prometheus target is up before restarting the Pod.

## KcsGpuXidError

Record the public compute-node identity, GPU UUID, XID code, affected Attempt and
time. Inspect `dmesg`/NVIDIA logs on that node. Cordon or drain only through an
operator-approved maintenance action; never let the telemetry service mutate nodes.

## KcsGpuVolatileEccError

Correlate GPU UUID and affected Attempt, preserve the raw exporter sample, then run
the NVIDIA health checks appropriate for the card. Consumer GPUs may omit this field
when DCGM reports it unsupported.

## KcsNodeNotReady

Inspect Node conditions and kubelet/k3s-agent logs. Preserve running workload and
event evidence before any restart. Node names exposed outside KCS must remain the
redacted `compute-*` identity.

## KcsManagedPodPending

Read `GET /api/v2/queue`, `GET /api/v2/events`, Pod conditions and namespace Events.
Distinguish unschedulable resources, image pull, quota and ordinary provisioning.
Do not report requested resources as utilization.

## KcsNativeMetricsUnavailable

Verify the mirrored `kcs-v2-service-token` and `kcs-v2-api-ca` Secrets exist only in
`kcs-monitoring`, then inspect the `kcs-v2-api` Prometheus target. The bearer token
must equal the API service token and `ca.crt` must validate the internal Service DNS
name. Never disable TLS verification to make the target green.

## KcsNativeStopFailed

Read the Job's `runnerStopAction`, `latestRunnerGeneration.runnerObservation`, and
`runner_phase` events before touching the Pod. A failed or indeterminate stop keeps
the Pod available for bounded capture; do not delete it or manually kill containers.

## KcsNativeHardDeadline

Archive Job/Pod YAML, both container logs, runtime events and the latest launcher
state. Hard deadline destroys the Pod, so record `outputLossPossible=true`; do not
claim that capture completed and do not create a replacement Pod.

## KcsNativeStorageFailure

Distinguish `enospc` from `emptydir_evicted`, compare the requested
`ephemeralStorageMiB` with writable volume limits and node disk pressure, and retain
imageFS compressed/unpacked bytes separately. This is a platform delivery failure,
not an agent exit or OOM.

## KcsNativeOutputLossPossible

Preserve the exact jobUID/podUID/generation and capture barrier, then reconcile with
ResearchCosmos. The flag cannot be cleared by retrying inspection; only a new Attempt
may execute again.

## KcsNativeCredentialProjectionFailed

Inspect the typed runner grant state and projection timestamps without reading the
Secret value. An expired pre-ACK grant is safe to replace with a new generation;
an indeterminate grant requires reconciliation and exact Secret-absence proof first.

## KcsNativeRecipeForbiddenSurge

Compare rejected exact runner/environment refs with the operator-curated registry.
Do not authorize a wildcard or mutable tag to silence this alert. Repeated unknown
pairs usually mean the RC capability lock and the deployed recipe catalog diverged.

## Native metric credentials

Before applying the monitoring Deployment, create two operator-managed Secrets in
`kcs-monitoring`: `kcs-v2-service-token` with key `service-token`, and
`kcs-v2-api-ca` with key `ca.crt`. Values are copied through the secret manager, not
committed or printed. The `/metrics` endpoint accepts the same bearer as `/api/v2`
and returns aggregate states only—no job refs, subjects or credentials.

Kubernetes NetworkPolicy deny events are not available from the current CNI, so
network-policy violation telemetry remains honestly `not_reported`; validate the
deny/allow paths with the canary probe and add CNI audit metrics before alerting on
that signal.

## Retention and recovery

Prometheus retains 15 days (bounded to 15 GB). Runtime events retain the tighter of
24 hours or 10,000 entries in `/var/lib/kcs-v2/events.sqlite3`; their sequence is
restart-stable. Restore the PVC from infrastructure backup when required. A clipped
event cursor resumes at the earliest retained event with `truncated=true`.
