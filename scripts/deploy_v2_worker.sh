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
  KCS_WORKER_WORKSPACE_ROOT
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
[[ $KCS_WORKER_WORKSPACE_ROOT =~ ^/[A-Za-z0-9_./-]+$ && \
   $KCS_WORKER_WORKSPACE_ROOT != / && \
   $KCS_WORKER_WORKSPACE_ROOT != /var && \
   $KCS_WORKER_WORKSPACE_ROOT != /home && \
   $KCS_WORKER_WORKSPACE_ROOT != *'/../'* && \
   $KCS_WORKER_WORKSPACE_ROOT != */.. ]] || {
  echo "KCS_WORKER_WORKSPACE_ROOT must be a dedicated absolute data-disk path" >&2
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

SUPPORTED = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"
))

def supported_address(value: ipaddress._BaseAddress) -> bool:
    return any(value.version == network.version and value in network for network in SUPPORTED)

control = ipaddress.ip_address(os.environ["KCS_CONTROL_PRIVATE_ADDRESS"])
worker = ipaddress.ip_address(os.environ["KCS_WORKER_PRIVATE_ADDRESS"])
if any(any((value.is_global, value.is_loopback, value.is_unspecified, value.is_link_local,
            value.is_multicast, value.is_reserved)) or not supported_address(value)
       for value in (control, worker)):
    raise SystemExit("dedicated host addresses must be nonpublic routed addresses")

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

networks = [ipaddress.ip_network(value.strip()) for value in os.environ["KCS_ALLOWED_PEER_CIDRS"].split(",")]
if not networks or any(unsafe_network(net) for net in networks):
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
ssh -o BatchMode=yes -- "$KCS_WORKER_SSH_ALIAS" \
  'sudo install -d -m 0755 /usr/local/libexec && sudo tee /usr/local/libexec/kcs-v2-validate-k3s-exec >/dev/null && sudo chmod 0755 /usr/local/libexec/kcs-v2-validate-k3s-exec' \
  <"$ROOT/deploy/v2/kcs-v2-validate-k3s-exec.py"
ssh -o BatchMode=yes -- "$KCS_WORKER_SSH_ALIAS" \
  'sudo tee /etc/systemd/system/kcs-v2-kubelet-metrics-relay.service >/dev/null' \
  <"$ROOT/deploy/v2/kcs-v2-kubelet-metrics-relay.service"
sed "s/@WORKER_PRIVATE_ADDRESS@/$KCS_WORKER_PRIVATE_ADDRESS/g" \
  "$ROOT/deploy/v2/kcs-v2-kubelet-metrics-relay.socket.in" | \
  ssh -o BatchMode=yes -- "$KCS_WORKER_SSH_ALIAS" \
    'sudo tee /etc/systemd/system/kcs-v2-kubelet-metrics-relay.socket >/dev/null'

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
  "$KCS_WORKER_NODE_NAME" "$remote_token_path" "$KCS_NVIDIA_TOOLKIT_VERSION" \
  "$KCS_WORKER_WORKSPACE_ROOT" <<'REMOTE'
set -euo pipefail
control_address=$1
worker_address=$2
k3s_version=$3
node_name=$4
token_path=$5
toolkit_version=$6
workspace_root=$7
trap 'rm -f -- "$token_path"' EXIT

ip -o address show | grep -F -- " $worker_address/" >/dev/null || {
  echo "worker private/overlay address is not configured" >&2
  exit 1
}
interface=$(ip route get "$control_address" | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
[[ -n $interface ]] || { echo "no private/overlay route to control" >&2; exit 1; }
[[ $interface =~ ^[A-Za-z0-9_.:@-]+$ ]] || { echo "private/overlay interface is invalid" >&2; exit 1; }

command -v nvidia-smi >/dev/null
nvidia-smi >/dev/null
installed_toolkit=$(dpkg-query -W -f='${Version}' nvidia-container-toolkit 2>/dev/null || true)
if [[ $installed_toolkit != "$toolkit_version" ]]; then
  apt-get update
  apt-get install --yes --no-install-recommends "nvidia-container-toolkit=$toolkit_version"
fi
command -v nvidia-container-runtime >/dev/null

# KCS workspaces are dynamically provisioned under this directory.  Require a
# separate filesystem so a large experiment cannot consume the OS disk.
install -d -m 0710 "$workspace_root"
root_device=$(findmnt -n -o SOURCE -T /)
workspace_device=$(findmnt -n -o SOURCE -T "$workspace_root")
[[ -n $root_device && -n $workspace_device && $root_device != "$workspace_device" ]] || {
  echo "worker workspace root must be backed by a non-root filesystem" >&2
  exit 1
}

validate_k3s_install() {
  local installed_version
  installed_version=$(k3s --version 2>/dev/null | awk 'NR == 1 {print $3}')
  [[ $installed_version == "$k3s_version" ]] || return 1
  systemctl show --property=ExecStart --value k3s-agent 2>/dev/null | \
    /usr/local/libexec/kcs-v2-validate-k3s-exec \
      worker "$control_address" "$worker_address" "$node_name" "$interface" || return 1
}
if command -v k3s >/dev/null; then
  installed_version=$(k3s --version 2>/dev/null | awk 'NR == 1 {print $3}')
  [[ $installed_version == "$k3s_version" ]] || {
    echo "existing k3s version mismatch" >&2
    exit 1
  }
fi
if ! validate_k3s_install; then
  token=$(cat "$token_path")
  curl -sfL https://get.k3s.io | K3S_URL="https://$control_address:6443" \
    K3S_TOKEN="$token" INSTALL_K3S_VERSION="$k3s_version" \
    INSTALL_K3S_EXEC="agent --server=https://$control_address:6443 --node-name=$node_name --node-ip=$worker_address --flannel-iface=$interface --kubelet-arg=address=127.0.0.1 --default-runtime=nvidia" sh -
fi
systemctl enable --now k3s-agent >/dev/null
systemctl restart k3s-agent
systemctl daemon-reload
systemctl enable --now kcs-v2-kubelet-metrics-relay.socket >/dev/null
if ! validate_k3s_install; then
  echo "started k3s version or private service configuration mismatch" >&2
  exit 1
fi
REMOTE
trap - EXIT

ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s kubectl wait --for=condition=Ready node/'$KCS_WORKER_NODE_NAME' --timeout=180s >/dev/null"
if ! ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s kubectl get node '$KCS_WORKER_NODE_NAME' -o json" | python3 -c '
import json, sys
expected_address = sys.argv[1]
node = json.load(sys.stdin)
addresses = node.get("status", {}).get("addresses", [])
raise SystemExit(0 if node.get("metadata", {}).get("name") == sys.argv[2] and any(
    item.get("type") == "InternalIP" and item.get("address") == expected_address
    for item in addresses
) else 1)
' "$KCS_WORKER_PRIVATE_ADDRESS" "$KCS_WORKER_NODE_NAME"; then
  echo "live worker node identity or private address mismatch" >&2
  exit 1
fi

ssh -o BatchMode=yes -- "$KCS_WORKER_SSH_ALIAS" sudo bash -s -- \
  "$KCS_CONTROL_PRIVATE_ADDRESS" "$KCS_WORKER_PRIVATE_ADDRESS" "$KCS_K3S_VERSION" \
  "$KCS_WORKER_NODE_NAME" "$KCS_NVIDIA_TOOLKIT_VERSION" \
  "$KCS_WORKER_WORKSPACE_ROOT" <<'REMOTE'
set -euo pipefail
control_address=$1
worker_address=$2
k3s_version=$3
node_name=$4
toolkit_version=$5
workspace_root=$6
interface=$(ip route get "$control_address" | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
[[ -n $interface && $interface =~ ^[A-Za-z0-9_.:@-]+$ ]] || {
  echo "private/overlay interface is invalid" >&2
  exit 1
}
command -v nvidia-smi >/dev/null
nvidia-smi >/dev/null
installed_toolkit=$(dpkg-query -W -f='${Version}' nvidia-container-toolkit 2>/dev/null || true)
[[ $installed_toolkit == "$toolkit_version" ]]
command -v nvidia-container-runtime >/dev/null
[[ $(findmnt -n -o SOURCE -T "$workspace_root") != \
   $(findmnt -n -o SOURCE -T /) ]] || {
  echo "dedicated workspace storage is not active" >&2
  exit 1
}
installed_version=$(k3s --version 2>/dev/null | awk 'NR == 1 {print $3}')
[[ $installed_version == "$k3s_version" ]] || {
  echo "started k3s version mismatch" >&2
  exit 1
}
systemctl show --property=ExecStart --value k3s-agent 2>/dev/null | \
  /usr/local/libexec/kcs-v2-validate-k3s-exec \
    worker "$control_address" "$worker_address" "$node_name" "$interface" || {
      echo "started k3s private service configuration mismatch" >&2
      exit 1
    }
k3s crictl info 2>/dev/null | python3 -c '
import json, sys
info = json.load(sys.stdin)
containerd = info.get("config", {}).get("containerd", {})
conditions = {
    item.get("type"): item.get("status")
    for item in info.get("status", {}).get("conditions", [])
}
if (
    containerd.get("defaultRuntimeName") != "nvidia"
    or "nvidia" not in containerd.get("runtimes", {})
    or conditions.get("RuntimeReady") is not True
    or conditions.get("NetworkReady") is not True
):
    raise SystemExit("K3s CRI is not ready with NVIDIA as the default runtime")
'
grep -F 'conf_dir = "/var/lib/rancher/k3s/agent/etc/cni/net.d"' \
  /var/lib/rancher/k3s/agent/etc/containerd/config.toml >/dev/null
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

ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s kubectl label node '$KCS_WORKER_NODE_NAME' researchcosmos.io/pool=gpu --overwrite >/dev/null"
workspace_config_patch=$(
  ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
    "sudo k3s kubectl -n kube-system get configmap local-path-config -o json" | \
    python3 "$ROOT/scripts/configure_v2_workspace_storage.py" \
      "$KCS_WORKER_NODE_NAME" "$KCS_WORKER_WORKSPACE_ROOT"
)
printf '%s' "$workspace_config_patch" | \
  ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
    'patch=$(cat); sudo k3s kubectl -n kube-system patch configmap local-path-config --type=merge -p "$patch" >/dev/null'
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo k3s kubectl apply -f - \
  <"$ROOT/deploy/v2/workspace-storage-class.yaml" >/dev/null
# The local-path provisioner is a storage control-plane component.  Keep it off
# GPU workers so a provisioner restart never waits on a worker-only image pull
# or consumes experiment capacity.
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s kubectl -n kube-system patch deployment local-path-provisioner --type=merge -p='{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":{\"kubernetes.io/os\":\"linux\",\"researchcosmos.io/role\":\"control\"}}}}}' >/dev/null"
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s kubectl -n kube-system rollout restart deployment/local-path-provisioner >/dev/null && sudo k3s kubectl -n kube-system rollout status deployment/local-path-provisioner --timeout=180s >/dev/null"
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" sudo k3s kubectl apply -f - \
  <"$ROOT/deploy/v2/nvidia-device-plugin.yaml" >/dev/null
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s kubectl -n kube-system rollout status daemonset/nvidia-device-plugin-daemonset --timeout=180s >/dev/null"
ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s kubectl wait --for=condition=Ready node/'$KCS_WORKER_NODE_NAME' --timeout=180s >/dev/null"
if ! ssh -o BatchMode=yes -- "$KCS_CONTROL_SSH_ALIAS" \
  "sudo k3s kubectl get node '$KCS_WORKER_NODE_NAME' -o json" | python3 -c '
import json, sys
expected_address = sys.argv[1]
node = json.load(sys.stdin)
labels = node.get("metadata", {}).get("labels", {})
addresses = node.get("status", {}).get("addresses", [])
capacity = node.get("status", {}).get("capacity", {}).get("nvidia.com/gpu")
allocatable = node.get("status", {}).get("allocatable", {}).get("nvidia.com/gpu")
raise SystemExit(0 if labels.get("researchcosmos.io/pool") == "gpu" and any(
    item.get("type") == "InternalIP" and item.get("address") == expected_address
    for item in addresses
) and capacity is not None and allocatable is not None
    and int(capacity) > 0 and int(allocatable) > 0 else 1)
' "$KCS_WORKER_PRIVATE_ADDRESS"; then
  echo "started worker identity, private address, GPU label, or allocatable GPU mismatch" >&2
  exit 1
fi
observed_k3s_version=$(ssh -o BatchMode=yes -- "$KCS_WORKER_SSH_ALIAS" \
  "sudo k3s --version 2>/dev/null | awk 'NR == 1 {print \$3}'")
[[ $observed_k3s_version == "$KCS_K3S_VERSION" ]] || {
  echo "observed worker k3s version mismatch" >&2
  exit 1
}
printf '{"event":"worker_deployment","observedK3sVersion":"%s","ok":true,"requestedK3sVersion":"%s"}\n' \
  "$observed_k3s_version" "$KCS_K3S_VERSION"
