# KCS 2.7 Attempt Network Owner

Status: implemented locally; not pushed, deployed, or exercised against a live cluster.

## Contract and retained history

- New hosted and native Job specs require `networkClass: none|restricted`.
- Both requested classes render the same deny-by-default policy. The class is retained only as the requested class annotation and observed attestation value.
- New snapshots require nullable `networkPolicy`. It reports only the observed policy reference, UID, resource version, spec digest, requested class, and observation time; it does not attest CNI enforcement.
- A retained pre-2.7 spec without `networkClass` remains readable and cleanable. KCS does not map it to a new class, does not look for or delete a policy, and returns `networkPolicy: null`.
- A 2.7 record whose deterministic policy is missing or whose managed identity/spec has drifted is marked indeterminate. KCS never creates a policy after observing that its Job already exists.

## Owner transaction

The create mutation order is durable reservation, deterministic NetworkPolicy create/read/exact managed-field validation, then Job create. A lost policy-create response is reconciled by reading the deterministic policy name; absence or drift stops before Job creation.

The policy selects only the Attempt's provider-request hash and allows only:

- DNS to `kube-system` Pods labeled `k8s-app=kube-dns`, UDP/TCP 53;
- TCP 443 to canonical operator-configured `KCS_V2_PLATFORM_EGRESS_CIDRS`;
- for native Attempts only, ingress from the KCS API Pod to the control relay on TCP 8080.

CIDR configuration rejects non-canonical networks, duplicates, more than 16 entries, and IPv4/IPv6 default routes. The deployment pins `ai-cosmos.cn`'s currently resolved edge as `124.70.64.81/32`. If that hostname changes address, the operator must update the ConfigMap and roll out KCS before admitting new Attempts.

Cleanup first confirms the Job and its Pods absent, then revalidates the deterministic policy owner/spec, deletes with a UID precondition, confirms absence, and only then clears owner runtime records.

## Deployment surface

- `NetworkingV1Api` is injected into the existing Kubernetes adapter.
- The service account has only create/get/delete on namespaced NetworkPolicies.
- The API Deployment receives the validated CIDR ConfigMap value.
- The obsolete static native NetworkPolicy example and conflicting runbook instructions are removed.

## Focused verification

- `py_compile` passed for all changed Python runtime/generator modules.
- Ruff passed for all changed Python runtime/generator modules and version assertions.
- The OpenAPI generator `--check` passed 37 route exchanges and reproduced SHA-256 `50e64d3ecea417edea910c2848d0b2ad2a75943c16fcfd6dc347dbcf7fa30dd4` byte-stably.
- One ephemeral in-memory fake proved `reserve -> policy create -> policy read -> Job create`, identical `none`/`restricted` policy specs, CIDR rejection, and legacy null/no-read behavior.
- `git diff --check` passed.

No broad tests were run, and no test file was added.
