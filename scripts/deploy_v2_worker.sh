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
  KCS_CONTROL_SSH_ALIAS KCS_WORKER_SSH_ALIAS KCS_CONTROL_PRIVATE_ADDRESS
  KCS_WORKER_PRIVATE_ADDRESS KCS_ALLOWED_PEER_CIDRS KCS_K3S_VERSION
  KCS_K3S_TOKEN_FILE KCS_WORKER_NODE_NAME KCS_NVIDIA_TOOLKIT_VERSION
)
for name in "${required[@]}"; do
  if [[ -z ${!name:-} ]]; then
    echo "required environment variable is absent: $name" >&2
    exit 2
  fi
done
for alias in "$KCS_CONTROL_SSH_ALIAS" "$KCS_WORKER_SSH_ALIAS"; do
  [[ $alias =~ ^[A-Za-z][A-Za-z0-9_.-]*$ ]] || {
    echo "SSH targets must be explicit ssh-config aliases" >&2
    exit 2
  }
done
[[ $KCS_WORKER_NODE_NAME =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || {
  echo "KCS_WORKER_NODE_NAME must be a DNS-compatible node name" >&2
  exit 2
}
[[ $KCS_K3S_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || {
  echo "KCS_K3S_VERSION must be an exact k3s release" >&2
  exit 2
}
[[ $KCS_NVIDIA_TOOLKIT_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]] || {
  echo "KCS_NVIDIA_TOOLKIT_VERSION must be an exact package version" >&2
  exit 2
}
[[ -f $KCS_K3S_TOKEN_FILE && -s $KCS_K3S_TOKEN_FILE ]] || {
  echo "KCS_K3S_TOKEN_FILE is absent or empty" >&2
  exit 2
}
if [[ $(tail -c 1 -- "$KCS_K3S_TOKEN_FILE" | od -An -t u1 | tr -d ' ') == 10 ]]; then
  echo "join token file must contain exact bytes without a trailing newline" >&2
  exit 2
fi

python3 - <<'PY'
import ipaddress
import os

control = ipaddress.ip_address(os.environ["KCS_CONTROL_PRIVATE_ADDRESS"])
worker = ipaddress.ip_address(os.environ["KCS_WORKER_PRIVATE_ADDRESS"])
if any(value.is_global or value.is_loopback or value.is_unspecified or value.is_link_local for value in (control, worker)):
    raise SystemExit("dedicated host addresses must be nonpublic routed addresses")
networks = [ipaddress.ip_network(value.strip()) for value in os.environ["KCS_ALLOWED_PEER_CIDRS"].split(",")]
if not networks or any(net.is_global or net.is_loopback for net in networks):
    raise SystemExit("allowed peer CIDRs must contain only nonpublic peer CIDRs")
if not any(control in net for net in networks) or not any(worker in net for net in networks):
    raise SystemExit("allowed peer CIDRs must contain both dedicated hosts")
PY

if [[ $CHECK_ONLY -eq 1 ]]; then
  printf '{"event":"deployment_check","ok":true,"script":"deploy_v2_worker"}\n'
  exit 0
fi

ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" true
ssh -o BatchMode=yes -- "$KCS_WORKER_SSH_ALIAS" true

remote_token_path=$(ssh -o BatchMode=yes -- "$KCS_WORKER_SSH_ALIAS" \
  'umask 077; tmp=$(mktemp); printf "%s" "$tmp"')
[[ $remote_token_path == /tmp/* ]] || { echo "unsafe remote token path" >&2; exit 1; }
cleanup_remote_token() {
  ssh -o BatchMode=yes -- "$KCS_WORKER_SSH_ALIAS" "rm -f -- '$remote_token_path'" \
    >/dev/null 2>&1 || true
}
trap cleanup_remote_token EXIT
ssh -o BatchMode=yes -- "$KCS_WORKER_SSH_ALIAS" "umask 077; cat >'$remote_token_path'" \
  <"$KCS_K3S_TOKEN_FILE"

ssh -o BatchMode=yes -- "$KCS_WORKER_SSH_ALIAS" sudo bash -s -- \
  "$KCS_CONTROL_PRIVATE_ADDRESS" "$KCS_WORKER_PRIVATE_ADDRESS" "$KCS_K3S_VERSION" \
  "$KCS_WORKER_NODE_NAME" "$remote_token_path" "$KCS_NVIDIA_TOOLKIT_VERSION" <<'REMOTE'
set -euo pipefail
control_address=$1
worker_address=$2
k3s_version=$3
node_name=$4
token_path=$5
toolkit_version=$6
trap 'rm -f -- "$token_path"' EXIT

ip -o address show | grep -F -- " $worker_address/" >/dev/null || {
  echo "worker private/overlay address is not configured" >&2
  exit 1
}
interface=$(ip route get "$control_address" | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
[[ -n $interface ]] || { echo "no private/overlay route to control" >&2; exit 1; }
command -v nvidia-smi >/dev/null
nvidia-smi >/dev/null
installed_toolkit=$(dpkg-query -W -f='${Version}' nvidia-container-toolkit 2>/dev/null || true)
if [[ $installed_toolkit != "$toolkit_version" ]]; then
  apt-get update
  apt-get install --yes --no-install-recommends "nvidia-container-toolkit=$toolkit_version"
fi
command -v nvidia-ctk >/dev/null

if ! command -v k3s >/dev/null; then
  token=$(cat "$token_path")
  curl -sfL https://get.k3s.io | K3S_URL="https://$control_address:6443" \
    K3S_TOKEN="$token" INSTALL_K3S_VERSION="$k3s_version" \
    INSTALL_K3S_EXEC="agent --node-name=$node_name --node-ip=$worker_address --flannel-iface=$interface --kubelet-arg=address=$worker_address" sh -
fi
nvidia-ctk runtime configure --runtime=containerd \
  --config=/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl --set-as-default
systemctl enable --now k3s-agent >/dev/null
systemctl restart k3s-agent
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
    10250) validate_listener "$listener" "$worker_address" ;;
  esac
done < <(ss -H -lnt | awk '{print $4}')
while IFS= read -r listener; do
  case "${listener##*:}" in
    8472) validate_listener "$listener" "$worker_address" ;;
  esac
done < <(ss -H -lnu | awk '{print $4}')
REMOTE
trap - EXIT

ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s kubectl label node '$KCS_WORKER_NODE_NAME' researchcosmos.io/pool=gpu --overwrite >/dev/null"
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo k3s kubectl apply -f - \
  <"$ROOT/deploy/v2/nvidia-device-plugin.yaml" >/dev/null
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s kubectl wait --for=condition=Ready node/'$KCS_WORKER_NODE_NAME' --timeout=180s >/dev/null"
printf '{"event":"worker_deployment","ok":true}\n'
