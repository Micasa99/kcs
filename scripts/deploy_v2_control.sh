#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CHECK_ONLY=0
if [[ ${1:-} == "--check" ]]; then
  CHECK_ONLY=1
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

required=(
  KCS_CONTROL_SSH_ALIAS KCS_CONTROL_PRIVATE_ADDRESS KCS_WORKER_PRIVATE_ADDRESS
  KCS_ALLOWED_PEER_CIDRS KCS_PORT_FORWARD_ADDRESS KCS_TLS_SAN KCS_K3S_VERSION
  KCS_API_IMAGE KCS_TLS_CERT_FILE KCS_TLS_KEY_FILE KCS_SERVICE_TOKEN_FILE
  KCS_LEGACY_DEBUG_UNITS KCS_LEGACY_SERVICE_ACCOUNT
)
for name in "${required[@]}"; do
  if [[ -z ${!name:-} ]]; then
    echo "required environment variable is absent: $name" >&2
    exit 2
  fi
done

validate_alias() {
  [[ $1 =~ ^[A-Za-z][A-Za-z0-9_.-]*$ ]] || {
    echo "SSH targets must be explicit ssh-config aliases" >&2
    exit 2
  }
}

validate_exact_file() {
  [[ -f $1 && -s $1 ]] || { echo "required file is absent or empty" >&2; exit 2; }
  if [[ $(tail -c 1 -- "$1" | od -An -t u1 | tr -d ' ') == 10 ]]; then
    echo "token files must contain exact bytes without a trailing newline" >&2
    exit 2
  fi
}

validate_alias "$KCS_CONTROL_SSH_ALIAS"
[[ $KCS_API_IMAGE =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] || {
  echo "KCS_API_IMAGE must be a digest-pinned image" >&2
  exit 2
}
[[ $KCS_K3S_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || {
  echo "KCS_K3S_VERSION must be an exact k3s release" >&2
  exit 2
}
[[ -f $KCS_TLS_CERT_FILE && -s $KCS_TLS_CERT_FILE ]]
[[ -f $KCS_TLS_KEY_FILE && -s $KCS_TLS_KEY_FILE ]]
validate_exact_file "$KCS_SERVICE_TOKEN_FILE"

python3 - <<'PY'
import ipaddress
import os

def address(name: str) -> ipaddress._BaseAddress:
    value = ipaddress.ip_address(os.environ[name])
    if value.is_global or value.is_loopback or value.is_unspecified or value.is_link_local:
        raise SystemExit(f"{name} must be a nonpublic routed address")
    return value

control = address("KCS_CONTROL_PRIVATE_ADDRESS")
worker = address("KCS_WORKER_PRIVATE_ADDRESS")
forward = address("KCS_PORT_FORWARD_ADDRESS")
if forward != control:
    raise SystemExit("KCS_PORT_FORWARD_ADDRESS must be the control private address")
networks = [ipaddress.ip_network(value.strip()) for value in os.environ["KCS_ALLOWED_PEER_CIDRS"].split(",")]
if not networks or any(net.is_global or net.is_loopback for net in networks):
    raise SystemExit("KCS_ALLOWED_PEER_CIDRS must contain only nonpublic peer CIDRs")
if not any(control in net for net in networks) or not any(worker in net for net in networks):
    raise SystemExit("allowed peer CIDRs must contain both dedicated hosts")

san = os.environ["KCS_TLS_SAN"]
try:
    san_address = ipaddress.ip_address(san)
except ValueError:
    labels = san.split(".")
    if len(san) > 253 or any(
        not label or len(label) > 63 or not label[0].isalnum() or not label[-1].isalnum()
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        raise SystemExit("KCS_TLS_SAN must be a valid DNS name or IP address")
else:
    if san_address.is_global or san_address.is_loopback or san_address.is_unspecified:
        raise SystemExit("an IP KCS_TLS_SAN must be nonpublic and non-loopback")
PY

if [[ $CHECK_ONLY -eq 1 ]]; then
  printf '{"event":"deployment_check","ok":true,"script":"deploy_v2_control"}\n'
  exit 0
fi

ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" true
if python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$KCS_TLS_SAN" \
  >/dev/null 2>&1; then
  openssl x509 -in "$KCS_TLS_CERT_FILE" -noout -checkip "$KCS_TLS_SAN" >/dev/null
else
  openssl x509 -in "$KCS_TLS_CERT_FILE" -noout -checkhost "$KCS_TLS_SAN" >/dev/null
fi

ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo bash -s -- \
  "$KCS_CONTROL_PRIVATE_ADDRESS" "$KCS_WORKER_PRIVATE_ADDRESS" "$KCS_TLS_SAN" \
  "$KCS_K3S_VERSION" "$KCS_LEGACY_DEBUG_UNITS" "$KCS_LEGACY_SERVICE_ACCOUNT" <<'REMOTE'
set -euo pipefail
control_address=$1
worker_address=$2
tls_san=$3
k3s_version=$4
legacy_units=$5
legacy_service_account=$6

ip -o address show | grep -F -- " $control_address/" >/dev/null || {
  echo "control private/overlay address is not configured" >&2
  exit 1
}
interface=$(ip route get "$worker_address" | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
[[ -n $interface ]] || { echo "no private/overlay route to worker" >&2; exit 1; }

for unit in ${legacy_units//,/ }; do
  [[ $unit =~ ^[A-Za-z0-9_.@-]+$ ]] || { echo "invalid legacy debug unit" >&2; exit 1; }
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
  if systemctl is-active --quiet "$unit"; then
    echo "legacy debug service remains active" >&2
    exit 1
  fi
done

if ! command -v k3s >/dev/null; then
  curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$k3s_version" \
    INSTALL_K3S_EXEC="server --bind-address=$control_address --advertise-address=$control_address --node-ip=$control_address --tls-san=$tls_san --node-label=researchcosmos.io/role=control --flannel-iface=$interface --kubelet-arg=address=$control_address" sh -
fi
systemctl enable --now k3s >/dev/null
k3s kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null
validate_listener() {
  local endpoint=$1
  local allowed_address=$2
  local port=${endpoint##*:}
  local host=${endpoint%:*}
  host=${host#[}
  host=${host%]}
  host=${host%%%*}
  if ! python3 -c '
import ipaddress, sys
observed = ipaddress.ip_address(sys.argv[1])
allowed = ipaddress.ip_address(sys.argv[2])
raise SystemExit(0 if observed.is_loopback or observed == allowed else 1)
' "$host" "$allowed_address"; then
    echo "listener on protected port $port is not bound to loopback/private role address" >&2
    exit 1
  fi
}
while IFS= read -r listener; do
  case "${listener##*:}" in
    6443|10250) validate_listener "$listener" "$control_address" ;;
  esac
done < <(ss -H -lnt | awk '{print $4}')
while IFS= read -r listener; do
  case "${listener##*:}" in
    8472) validate_listener "$listener" "$control_address" ;;
  esac
done < <(ss -H -lnu | awk '{print $4}')
if k3s kubectl get rolebindings -n researchcosmos-v2 -o jsonpath='{range .items[*].subjects[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -Fx -- "$legacy_service_account" >/dev/null; then
  echo "legacy service account has a V2 RoleBinding" >&2
  exit 1
fi
if k3s kubectl get clusterrolebindings -o json | python3 -c '
import json, sys
name = sys.argv[1]
items = json.load(sys.stdin).get("items", [])
raise SystemExit(any(
    subject.get("kind") == "ServiceAccount" and subject.get("name") == name
    for item in items for subject in (item.get("subjects") or [])
))
' "$legacy_service_account"; then
  :
else
  echo "legacy service account has a cluster-wide binding" >&2
  exit 1
fi
REMOTE

for manifest in namespace.yaml rbac.yaml network-policy.yaml; do
  ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo k3s kubectl apply -f - \
    <"$ROOT/deploy/v2/$manifest" >/dev/null
done

sed "s|registry.example.invalid/researchcosmos/kcs-api@sha256:0000000000000000000000000000000000000000000000000000000000000000|$KCS_API_IMAGE|" \
  "$ROOT/deploy/v2/kcs-api.yaml" | \
  ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo k3s kubectl apply -f - >/dev/null

secret_dir=$(mktemp -d)
trap 'rm -rf -- "$secret_dir"' EXIT
install -m 0600 "$KCS_TLS_CERT_FILE" "$secret_dir/tls.crt"
install -m 0600 "$KCS_TLS_KEY_FILE" "$secret_dir/tls.key"
install -m 0600 "$KCS_SERVICE_TOKEN_FILE" "$secret_dir/service-token"
tar -C "$secret_dir" -cf - tls.crt tls.key service-token | \
  ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo bash -s <<'REMOTE'
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
umask 077
tar -C "$tmp" -xf -
k3s kubectl -n researchcosmos-v2 create secret tls kcs-v2-tls \
  --cert="$tmp/tls.crt" --key="$tmp/tls.key" --dry-run=client -o yaml | \
  k3s kubectl apply -f - >/dev/null
k3s kubectl -n researchcosmos-v2 create secret generic kcs-v2-service-token \
  --from-file=service-token="$tmp/service-token" --dry-run=client -o yaml | \
  k3s kubectl apply -f - >/dev/null
REMOTE

ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo tee /etc/systemd/system/kcs-v2.service \
  <"$ROOT/deploy/v2/kcs-v2.service" >/dev/null
printf 'KCS_PORT_FORWARD_ADDRESS=%s\n' "$KCS_PORT_FORWARD_ADDRESS" | \
  ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
    'sudo install -d -m 0750 /etc/kcs-v2 && sudo tee /etc/kcs-v2/port-forward.env >/dev/null'
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  'sudo systemctl daemon-reload && sudo systemctl enable --now kcs-v2.service >/dev/null && sudo k3s kubectl -n researchcosmos-v2 rollout status deployment/kcs-v2-api --timeout=180s'
printf '{"event":"control_deployment","ok":true}\n'
