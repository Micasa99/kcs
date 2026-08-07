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

## Retention and recovery

Prometheus retains 15 days (bounded to 15 GB). Runtime events retain the tighter of
24 hours or 10,000 entries in `/var/lib/kcs-v2/events.sqlite3`; their sequence is
restart-stable. Restore the PVC from infrastructure backup when required. A clipped
event cursor resumes at the earliest retained event with `truncated=true`.
