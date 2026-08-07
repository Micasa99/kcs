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
  KCS_LEGACY_DEBUG_UNITS KCS_LEGACY_SERVICE_ACCOUNT KCS_WORKSPACE_STORAGE_ROOT
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
  echo "KCS_API_IMAGE must be a nonzero digest-pinned image" >&2
  exit 2
}
[[ $KCS_API_IMAGE != *@sha256:0000000000000000000000000000000000000000000000000000000000000000 ]] || {
  echo "KCS_API_IMAGE must be a nonzero digest-pinned image" >&2
  exit 2
}
[[ $KCS_K3S_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || {
  echo "KCS_K3S_VERSION must be an exact k3s release" >&2
  exit 2
}
[[ $KCS_WORKSPACE_STORAGE_ROOT =~ ^/[A-Za-z0-9_./-]+$ && \
   $KCS_WORKSPACE_STORAGE_ROOT != / && \
   $KCS_WORKSPACE_STORAGE_ROOT != /var && \
   $KCS_WORKSPACE_STORAGE_ROOT != /home && \
   $KCS_WORKSPACE_STORAGE_ROOT != *'/../'* && \
   $KCS_WORKSPACE_STORAGE_ROOT != */.. ]] || {
  echo "KCS_WORKSPACE_STORAGE_ROOT must be a dedicated absolute data-disk path" >&2
  exit 2
}
[[ -f $KCS_TLS_CERT_FILE && -s $KCS_TLS_CERT_FILE ]]
[[ -f $KCS_TLS_KEY_FILE && -s $KCS_TLS_KEY_FILE ]]
validate_exact_file "$KCS_SERVICE_TOKEN_FILE"

python3 - <<'PY'
import ipaddress
import os

SUPPORTED = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"
))

def supported_address(value: ipaddress._BaseAddress) -> bool:
    return any(value.version == network.version and value in network for network in SUPPORTED)

def address(name: str) -> ipaddress._BaseAddress:
    value = ipaddress.ip_address(os.environ[name])
    if any((value.is_global, value.is_loopback, value.is_unspecified, value.is_link_local,
            value.is_multicast, value.is_reserved)) or not supported_address(value):
        raise SystemExit(f"{name} must be a nonpublic routed address")
    return value

def unsafe_network(value: ipaddress._BaseNetwork) -> bool:
    endpoints = (value.network_address, value.broadcast_address)
    return not any(
        value.version == network.version and value.subnet_of(network) for network in SUPPORTED
    ) or any((value.is_global, value.is_loopback, value.is_unspecified, value.is_link_local,
                value.is_multicast, value.is_reserved)) or any(
        any((item.is_global, item.is_loopback, item.is_unspecified, item.is_link_local,
             item.is_multicast, item.is_reserved))
        for item in endpoints
    )

control = address("KCS_CONTROL_PRIVATE_ADDRESS")
worker = address("KCS_WORKER_PRIVATE_ADDRESS")
forward = address("KCS_PORT_FORWARD_ADDRESS")
if forward != control:
    raise SystemExit("KCS_PORT_FORWARD_ADDRESS must be the control private address")
networks = [ipaddress.ip_network(value.strip()) for value in os.environ["KCS_ALLOWED_PEER_CIDRS"].split(",")]
if not networks or any(unsafe_network(net) for net in networks):
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
    if any((san_address.is_global, san_address.is_loopback, san_address.is_unspecified,
            san_address.is_link_local, san_address.is_multicast, san_address.is_reserved)) \
            or not supported_address(san_address):
        raise SystemExit("an IP KCS_TLS_SAN must be nonpublic and non-loopback")
PY

if [[ $CHECK_ONLY -eq 1 ]]; then
  printf '{"event":"deployment_check","ok":true,"script":"deploy_v2_control"}\n'
  exit 0
fi

ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" true
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  'sudo install -d -m 0755 /usr/local/libexec && sudo tee /usr/local/libexec/kcs-v2-validate-k3s-exec >/dev/null && sudo chmod 0755 /usr/local/libexec/kcs-v2-validate-k3s-exec' \
  <"$ROOT/deploy/v2/kcs-v2-validate-k3s-exec.py"
if python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$KCS_TLS_SAN" \
  >/dev/null 2>&1; then
  openssl x509 -in "$KCS_TLS_CERT_FILE" -noout -checkip "$KCS_TLS_SAN" >/dev/null
else
  openssl x509 -in "$KCS_TLS_CERT_FILE" -noout -checkhost "$KCS_TLS_SAN" >/dev/null
fi

ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo bash -s -- \
  "$KCS_CONTROL_PRIVATE_ADDRESS" "$KCS_WORKER_PRIVATE_ADDRESS" "$KCS_TLS_SAN" \
  "$KCS_K3S_VERSION" "$KCS_LEGACY_DEBUG_UNITS" "$KCS_LEGACY_SERVICE_ACCOUNT" \
  "$KCS_WORKSPACE_STORAGE_ROOT" <<'REMOTE'
set -euo pipefail
control_address=$1
worker_address=$2
tls_san=$3
k3s_version=$4
legacy_units=$5
legacy_service_account=$6
workspace_storage_root=$7

ip -o address show | grep -F -- " $control_address/" >/dev/null || {
  echo "control private/overlay address is not configured" >&2
  exit 1
}
interface=$(ip route get "$worker_address" | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
[[ -n $interface ]] || { echo "no private/overlay route to worker" >&2; exit 1; }
[[ $interface =~ ^[A-Za-z0-9_.:@-]+$ ]] || { echo "private/overlay interface is invalid" >&2; exit 1; }

validate_control_node() {
  k3s kubectl get nodes -l researchcosmos.io/role=control -o json 2>/dev/null | python3 -c '
import json, sys
expected = sys.argv[1]
items = json.load(sys.stdin).get("items", [])
raise SystemExit(0 if any(
    any(address.get("type") == "InternalIP" and address.get("address") == expected
        for address in item.get("status", {}).get("addresses", []))
    for item in items
) else 1)
' "$control_address"
}

validate_k3s_install() {
  local installed_version
  installed_version=$(k3s --version 2>/dev/null | awk 'NR == 1 {print $3}')
  [[ $installed_version == "$k3s_version" ]] || return 1
  systemctl show --property=ExecStart --value k3s 2>/dev/null | \
    /usr/local/libexec/kcs-v2-validate-k3s-exec \
      control "$control_address" "$tls_san" "$interface" "$workspace_storage_root" || return 1
  if systemctl is-active --quiet k3s && ! validate_control_node; then
    return 1
  fi
}
if command -v k3s >/dev/null && ! validate_k3s_install; then
  echo "existing k3s version or private service configuration mismatch" >&2
  exit 1
fi

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
    INSTALL_K3S_EXEC="server --bind-address=$control_address --advertise-address=$control_address --node-ip=$control_address --tls-san=$tls_san --node-label=researchcosmos.io/role=control --flannel-iface=$interface --kubelet-arg=address=$control_address --default-local-storage-path=$workspace_storage_root" sh -
fi
systemctl enable --now k3s >/dev/null
if ! validate_k3s_install; then
  echo "started k3s version or private service configuration mismatch" >&2
  exit 1
fi
k3s kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null
if ! validate_control_node; then
  echo "started k3s control role or private node address mismatch" >&2
  exit 1
fi
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

for manifest in \
  namespace.yaml kube-state-metrics.yaml dcgm-exporter.yaml \
  alertmanager.yaml prometheus.yaml; do
  ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo k3s kubectl apply -f - \
    <"$ROOT/deploy/v2/monitoring/$manifest" >/dev/null
done

sed "s|registry.example.invalid/researchcosmos/kcs-api@sha256:0000000000000000000000000000000000000000000000000000000000000000|$KCS_API_IMAGE|" \
  "$ROOT/deploy/v2/kcs-api.yaml" | \
  ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo k3s kubectl apply -f - >/dev/null

secret_dir=$(mktemp -d)
trap 'rm -rf -- "$secret_dir"' EXIT
install -m 0600 "$KCS_TLS_CERT_FILE" "$secret_dir/tls.crt"
install -m 0600 "$KCS_TLS_KEY_FILE" "$secret_dir/tls.key"
install -m 0600 "$KCS_SERVICE_TOKEN_FILE" "$secret_dir/service-token"
secret_archive="$secret_dir/secrets.tar"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$secret_dir" -cf "$secret_archive" \
  tls.crt tls.key service-token
chmod 0600 "$secret_archive"
remote_secret_archive=$(ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  'umask 077; mktemp /tmp/kcs-v2-secrets.XXXXXX.tar')
[[ $remote_secret_archive == /tmp/kcs-v2-secrets.*.tar ]] || {
  echo "unsafe remote Secret archive path" >&2
  exit 1
}
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "umask 077; cat >'$remote_secret_archive'" <"$secret_archive"
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo bash -s -- \
  "$remote_secret_archive" <<'REMOTE'
set -euo pipefail
archive=$1
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"; rm -f -- "$archive"' EXIT
umask 077
tar -C "$tmp" -xf "$archive"
k3s kubectl -n researchcosmos-v2 create secret tls kcs-v2-tls \
  --cert="$tmp/tls.crt" --key="$tmp/tls.key" --dry-run=client -o yaml | \
  k3s kubectl apply -f - >/dev/null
k3s kubectl -n researchcosmos-v2 create secret generic kcs-v2-service-token \
  --from-file=service-token="$tmp/service-token" --dry-run=client -o yaml | \
  k3s kubectl apply -f - >/dev/null
REMOTE

ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo tee /etc/systemd/system/kcs-v2.service \
  <"$ROOT/deploy/v2/kcs-v2.service" >/dev/null
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  'sudo install -d -m 0755 /usr/local/libexec && sudo tee /usr/local/libexec/kcs-v2-port-forward >/dev/null && sudo chmod 0755 /usr/local/libexec/kcs-v2-port-forward' \
  <"$ROOT/deploy/v2/kcs-v2-port-forward.py"
printf 'KCS_PORT_FORWARD_ADDRESS=%s\nKCS_CONTROL_PRIVATE_ADDRESS=%s\n' \
  "$KCS_PORT_FORWARD_ADDRESS" "$KCS_CONTROL_PRIVATE_ADDRESS" | \
  ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
    'sudo install -d -m 0750 /etc/kcs-v2 && sudo tee /etc/kcs-v2/port-forward.env >/dev/null'
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  'sudo systemctl daemon-reload && sudo systemctl enable kcs-v2.service >/dev/null && sudo k3s kubectl -n researchcosmos-v2 rollout status deployment/kcs-v2-api --timeout=180s && sudo k3s kubectl -n kcs-monitoring rollout status deployment/kcs-kube-state-metrics --timeout=180s && sudo k3s kubectl -n kcs-monitoring rollout status deployment/kcs-prometheus --timeout=180s && sudo k3s kubectl -n kcs-monitoring rollout status deployment/kcs-alertmanager --timeout=180s && sudo k3s kubectl -n kcs-monitoring rollout status daemonset/kcs-dcgm-exporter --timeout=180s && sudo systemctl restart kcs-v2.service && sudo systemctl is-active --quiet kcs-v2.service'
observed_k3s_version=$(ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s --version 2>/dev/null | awk 'NR == 1 {print \$3}'")
[[ $observed_k3s_version == "$KCS_K3S_VERSION" ]] || {
  echo "observed control k3s version mismatch" >&2
  exit 1
}
printf '{"event":"control_deployment","observedK3sVersion":"%s","ok":true,"requestedK3sVersion":"%s"}\n' \
  "$observed_k3s_version" "$KCS_K3S_VERSION"
