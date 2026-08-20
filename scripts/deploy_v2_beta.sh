#!/usr/bin/env bash
set -euo pipefail

# This is intentionally separate from deploy_v2_control.sh.  It never reads,
# applies, or patches Stable deployment assets.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NAMESPACE=researchcosmos-v2-beta
MODE=check
OUTPUT_DIR=

usage() {
  echo "usage: $0 [--check | --render DIR | --apply]" >&2
  exit 2
}

case ${1:---check} in
  --check) MODE=check ;;
  --render)
    [[ $# -eq 2 ]] || usage
    MODE=render
    OUTPUT_DIR=$2
    ;;
  --apply) MODE=apply ;;
  *) usage ;;
esac

required=(
  KCS_BETA_API_IMAGE KCS_BETA_RUNTIME_CONFIG_DIR
  KCS_BETA_TLS_CERT_FILE KCS_BETA_TLS_KEY_FILE KCS_BETA_SERVICE_TOKEN_FILE
  KCS_BETA_BACKEND_CA_FILE
)
for name in "${required[@]}"; do
  [[ -n ${!name:-} ]] || { echo "required environment variable is absent: $name" >&2; exit 2; }
done

[[ $KCS_BETA_API_IMAGE =~ ^[^[:space:]@\|]+@sha256:[0-9a-f]{64}$ && \
   $KCS_BETA_API_IMAGE != *@sha256:0000000000000000000000000000000000000000000000000000000000000000 ]] || {
  echo "KCS_BETA_API_IMAGE must be a nonzero digest-pinned image" >&2
  exit 2
}
for path in \
  "$KCS_BETA_TLS_CERT_FILE" "$KCS_BETA_TLS_KEY_FILE" \
  "$KCS_BETA_SERVICE_TOKEN_FILE" "$KCS_BETA_BACKEND_CA_FILE"
do
  [[ -f $path && -s $path ]] || { echo "required file is absent or empty: $path" >&2; exit 2; }
done
[[ -d $KCS_BETA_RUNTIME_CONFIG_DIR ]] || {
  echo "KCS_BETA_RUNTIME_CONFIG_DIR must name an untracked Beta config directory" >&2
  exit 2
}
if [[ $(tail -c 1 -- "$KCS_BETA_SERVICE_TOKEN_FILE" | od -An -t u1 | tr -d ' ') == 10 ]]; then
  echo "KCS_BETA_SERVICE_TOKEN_FILE must contain exact bytes without a trailing newline" >&2
  exit 2
fi

check_certificate_host() {
  python3 - "$1" "$2" <<'PY'
import ssl
import sys

certificate = ssl._ssl._test_decode_cert(sys.argv[1])
ssl.match_hostname(certificate, sys.argv[2])
PY
}
check_certificate_host "$KCS_BETA_TLS_CERT_FILE" "kcs-v2-beta-api.${NAMESPACE}.svc.cluster.local"
check_certificate_host "$KCS_BETA_TLS_CERT_FILE" "10-255-250-1.sslip.io"

if [[ $MODE == render ]]; then
  [[ $OUTPUT_DIR != / && -n $OUTPUT_DIR ]] || { echo "unsafe render directory" >&2; exit 2; }
  mkdir -p -- "$OUTPUT_DIR"
  STAGE=$OUTPUT_DIR
  CLEANUP=0
else
  STAGE=$(mktemp -d)
  CLEANUP=1
fi
cleanup() {
  [[ $CLEANUP -eq 1 ]] && rm -rf -- "$STAGE"
}
trap cleanup EXIT
umask 077

escape_sed() {
  sed 's/[\\&|]/\\&/g'
}
api_image_escaped=$(printf '%s' "$KCS_BETA_API_IMAGE" | escape_sed)
install -m 0600 "$ROOT/deploy/v2/overlays/beta/namespace.yaml" "$STAGE/namespace.yaml"
install -m 0600 "$ROOT/deploy/v2/overlays/beta/bootstrap.yaml" "$STAGE/bootstrap.yaml"
install -m 0600 "$ROOT/deploy/v2/overlays/beta/cluster.yaml" "$STAGE/cluster.yaml"
install -m 0600 "$ROOT/deploy/v2/overlays/beta/model-gateway-middleware.yaml" "$STAGE/model-gateway-middleware.yaml"
install -m 0600 "$ROOT/deploy/v2/overlays/beta/model-gateway.yaml" "$STAGE/model-gateway.yaml"

runtime_files=(
  recipes.json capabilities.json openvscode-image-volume dev-session-relay-image
  project-workspace-control-image project-workspace-vsix-image-volume
  project-workspace-vsix-sha256 openai-base-url anthropic-base-url platform-egress-cidrs
)
for name in "${runtime_files[@]}"; do
  [[ -f $KCS_BETA_RUNTIME_CONFIG_DIR/$name && -s $KCS_BETA_RUNTIME_CONFIG_DIR/$name ]] || {
    echo "Beta runtime config bundle lacks $name" >&2
    exit 2
  }
done
python3 - "$KCS_BETA_RUNTIME_CONFIG_DIR/recipes.json" \
  "$KCS_BETA_RUNTIME_CONFIG_DIR/capabilities.json" <<'PY'
import json
import sys

for path, collection in ((sys.argv[1], "recipes"), (sys.argv[2], "capabilities")):
    with open(path, encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict) or not isinstance(value.get("version"), int):
        raise SystemExit(f"{path} must be a versioned JSON object")
    if not isinstance(value.get(collection), list):
        raise SystemExit(f"{path} must contain a {collection} array")
PY
read_scalar() {
  local path=$1 value
  value=$(<"$KCS_BETA_RUNTIME_CONFIG_DIR/$path")
  [[ $value != *$'\n'* && -n $value ]] || {
    echo "Beta runtime config value $path must be one nonempty line" >&2
    exit 2
  }
  printf '%s' "$value"
}
validate_runtime_image() {
  local name=$1 value
  value=$(read_scalar "$name")
  [[ $value =~ ^[^[:space:]@\|]+@sha256:[0-9a-f]{64}$ && \
     $value != *@sha256:0000000000000000000000000000000000000000000000000000000000000000 ]] || {
    echo "Beta runtime config value $name must be a nonzero digest-pinned image" >&2
    exit 2
  }
}
for name in openvscode-image-volume dev-session-relay-image project-workspace-control-image \
  project-workspace-vsix-image-volume; do
  validate_runtime_image "$name"
done
[[ $(read_scalar project-workspace-vsix-sha256) =~ ^[0-9a-f]{64}$ && \
   $(read_scalar project-workspace-vsix-sha256) != 0000000000000000000000000000000000000000000000000000000000000000 ]] || {
  echo "Beta runtime config VSIX digest must be nonzero lowercase SHA-256" >&2
  exit 2
}
[[ $(read_scalar openai-base-url) == https://10-255-250-1.sslip.io/ai4sci/cosmos/model-gateway/openai/v1,https://ai-cosmos.cn/ai4sci-local/cosmos/model-gateway/openai/v1 && \
   $(read_scalar anthropic-base-url) == https://10-255-250-1.sslip.io/ai4sci/cosmos/model-gateway/anthropic,https://ai-cosmos.cn/ai4sci-local/cosmos/model-gateway/anthropic && \
   $(read_scalar platform-egress-cidrs) == 10.255.250.1/32,124.70.64.81/32 ]] || {
  echo "Beta runtime config must use only the approved Test and local Product gateways" >&2
  exit 2
}
sed "s|__KCS_BETA_API_IMAGE__|$api_image_escaped|" \
  "$ROOT/deploy/v2/overlays/beta/api.yaml" >"$STAGE/api.yaml"
kubectl -n "$NAMESPACE" create configmap kcs-v2-beta-native-runtime-config \
  --from-file=recipes.json="$KCS_BETA_RUNTIME_CONFIG_DIR/recipes.json" \
  --from-file=capabilities.json="$KCS_BETA_RUNTIME_CONFIG_DIR/capabilities.json" \
  --from-literal=openvscode-image-volume="$(read_scalar openvscode-image-volume)" \
  --from-literal=dev-session-relay-image="$(read_scalar dev-session-relay-image)" \
  --from-literal=project-workspace-control-image="$(read_scalar project-workspace-control-image)" \
  --from-literal=project-workspace-vsix-image-volume="$(read_scalar project-workspace-vsix-image-volume)" \
  --from-literal=project-workspace-vsix-sha256="$(read_scalar project-workspace-vsix-sha256)" \
  --from-literal=openai-base-url="$(read_scalar openai-base-url)" \
  --from-literal=anthropic-base-url="$(read_scalar anthropic-base-url)" \
  --from-literal=platform-egress-cidrs="$(read_scalar platform-egress-cidrs)" \
  --dry-run=client -o yaml >"$STAGE/runtime-config.yaml"

kubectl -n "$NAMESPACE" create secret tls kcs-v2-beta-tls \
  --cert="$KCS_BETA_TLS_CERT_FILE" --key="$KCS_BETA_TLS_KEY_FILE" \
  --dry-run=client -o yaml >"$STAGE/api-tls.yaml"
kubectl -n "$NAMESPACE" create secret generic kcs-v2-beta-service-token \
  --from-file=service-token="$KCS_BETA_SERVICE_TOKEN_FILE" \
  --dry-run=client -o yaml >"$STAGE/service-token.yaml"
kubectl -n "$NAMESPACE" create secret generic kcs-v2-beta-backend-ca \
  --from-file=ca.crt="$KCS_BETA_BACKEND_CA_FILE" \
  --dry-run=client -o yaml >"$STAGE/backend-ca.yaml"

rendered=(
  "$STAGE/namespace.yaml" "$STAGE/bootstrap.yaml" "$STAGE/runtime-config.yaml" "$STAGE/api-tls.yaml"
  "$STAGE/service-token.yaml" "$STAGE/backend-ca.yaml" "$STAGE/api.yaml"
  "$STAGE/model-gateway-middleware.yaml" "$STAGE/model-gateway.yaml" "$STAGE/cluster.yaml"
)
file_args() {
  FILE_ARGS=()
  local path
  for path in "$@"; do
    FILE_ARGS+=(-f "$path")
  done
}
if grep -Eq '(^|[^A-Za-z0-9-])researchcosmos-v2([^A-Za-z0-9-]|$)|kube-system|kcs.ai-cosmos.cn' "${rendered[@]}"; then
  echo "rendered Beta input contains a forbidden Stable or shared-resource reference" >&2
  exit 1
fi

python3 - "${rendered[@]}" <<'PY'
import sys

import yaml

expected = {
    ("rbac.authorization.k8s.io/v1", "ClusterRole", "kcs-v2-beta-capacity-reader"),
    ("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "kcs-v2-beta-capacity-reader"),
    ("v1", "ConfigMap", "kcs-v2-beta-native-runtime-config"),
    ("apps/v1", "Deployment", "kcs-v2-beta-api"),
    ("discovery.k8s.io/v1", "EndpointSlice", "kcs-v2-beta-model-gateway-relay"),
    ("networking.k8s.io/v1", "Ingress", "kcs-v2-beta-model-gateway"),
    ("traefik.io/v1alpha1", "Middleware", "kcs-v2-beta-model-gateway-strip-prefix"),
    ("v1", "LimitRange", "kcs-v2-beta-limits"),
    ("v1", "Namespace", "researchcosmos-v2-beta"),
    ("networking.k8s.io/v1", "NetworkPolicy", "kcs-v2-beta-project-workspace-ingress"),
    ("networking.k8s.io/v1", "NetworkPolicy", "kcs-v2-beta-workload-deny-ingress"),
    ("v1", "PersistentVolumeClaim", "kcs-v2-beta-api-state"),
    ("scheduling.k8s.io/v1", "PriorityClass", "kcs-v2-beta-low"),
    ("v1", "ResourceQuota", "kcs-v2-beta-quota"),
    ("rbac.authorization.k8s.io/v1", "Role", "kcs-v2-beta-api"),
    ("rbac.authorization.k8s.io/v1", "RoleBinding", "kcs-v2-beta-api"),
    ("v1", "Secret", "kcs-v2-beta-backend-ca"),
    ("v1", "Secret", "kcs-v2-beta-service-token"),
    ("v1", "Secret", "kcs-v2-beta-tls"),
    ("v1", "Service", "kcs-v2-beta-api"),
    ("v1", "Service", "kcs-v2-beta-model-gateway-relay"),
    ("v1", "ServiceAccount", "kcs-v2-beta-api"),
    ("v1", "ServiceAccount", "kcs-v2-beta-workload"),
}
observed = set()
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as source:
        for document in yaml.safe_load_all(source):
            if not isinstance(document, dict):
                raise SystemExit(f"{path} contains a non-object YAML document")
            metadata = document.get("metadata")
            if not isinstance(metadata, dict) or not isinstance(metadata.get("name"), str):
                raise SystemExit(f"{path} has an object without metadata.name")
            observed.add((document.get("apiVersion"), document.get("kind"), metadata["name"]))
if observed != expected:
    raise SystemExit(f"rendered objects are outside the Beta allowlist: {observed ^ expected}")
PY

if [[ $MODE == render ]]; then
  printf '%s\n' "$STAGE"
  exit 0
fi

printf '{"event":"kcs_beta_render_check","objects":23,"ok":true}\n'
[[ $MODE == check ]] && exit 0

server_validate() {
  file_args "$@"
  kubectl apply --server-side --dry-run=server \
    --field-manager=kcs-v2-beta-deployer "${FILE_ARGS[@]}"
}
client_validate() {
  file_args "$@"
  kubectl apply --dry-run=client --validate=false "${FILE_ARGS[@]}" >/dev/null
}
server_diff() {
  file_args "$@"
  set +e
  kubectl diff --server-side --field-manager=kcs-v2-beta-deployer "${FILE_ARGS[@]}"
  status=$?
  set -e
  [[ $status -le 1 ]] || return "$status"
}
apply_phase() {
  file_args "$@"
  client_validate "$@"
  server_validate "$@"
  # Secret bytes are already constrained by the object allowlist and server
  # dry-run. Never print their base64 payloads through kubectl diff.
  if ! grep -Eq '^kind: Secret$' "$@"; then
    server_diff "$@"
  fi
  kubectl apply --server-side --field-manager=kcs-v2-beta-deployer "${FILE_ARGS[@]}"
}

# ClusterRole/Binding/PriorityClass are deliberately excluded from --apply: an
# administrator reviews and applies cluster.yaml separately before this script
# receives a Beta namespace-scoped deploy credential.
apply_phase "$STAGE/namespace.yaml"
apply_phase "$STAGE/bootstrap.yaml" "$STAGE/runtime-config.yaml"
apply_phase "$STAGE/api-tls.yaml" "$STAGE/service-token.yaml" "$STAGE/backend-ca.yaml"
apply_phase "$STAGE/model-gateway-middleware.yaml"
apply_phase "$STAGE/model-gateway.yaml"
apply_phase "$STAGE/api.yaml"
kubectl -n "$NAMESPACE" rollout restart deployment/kcs-v2-beta-api
kubectl -n "$NAMESPACE" rollout status deployment/kcs-v2-beta-api --timeout=180s
printf '{"event":"kcs_beta_apply","ok":true}\n'
