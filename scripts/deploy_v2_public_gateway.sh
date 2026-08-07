#!/usr/bin/env bash
set -euo pipefail

required=(
  KCS_PUBLIC_HOST
  KCS_PUBLIC_TLS_CERT_FILE
  KCS_PUBLIC_TLS_KEY_FILE
  KCS_BACKEND_CA_FILE
)
for name in "${required[@]}"; do
  if [[ -z ${!name:-} ]]; then
    echo "required environment variable is absent: $name" >&2
    exit 2
  fi
done

public_hosts=("$KCS_PUBLIC_HOST")
if [[ -n ${KCS_PUBLIC_EXTRA_HOSTS:-} ]]; then
  read -r -a extra_public_hosts <<<"$KCS_PUBLIC_EXTRA_HOSTS"
  public_hosts+=("${extra_public_hosts[@]}")
fi
for public_host in "${public_hosts[@]}"; do
  if [[ ! $public_host =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]]; then
    echo "KCS public hosts must be DNS hostnames" >&2
    exit 2
  fi
done
for path in \
  "$KCS_PUBLIC_TLS_CERT_FILE" \
  "$KCS_PUBLIC_TLS_KEY_FILE" \
  "$KCS_BACKEND_CA_FILE"
do
  [[ -f $path && -s $path ]] || {
    echo "required certificate file is absent or empty" >&2
    exit 2
  }
done

for public_host in "${public_hosts[@]}"; do
  openssl x509 -in "$KCS_PUBLIC_TLS_CERT_FILE" -noout \
    -checkhost "$public_host" >/dev/null
done
certificate_key=$(openssl x509 -in "$KCS_PUBLIC_TLS_CERT_FILE" -pubkey -noout | sha256sum)
private_key=$(openssl pkey -in "$KCS_PUBLIC_TLS_KEY_FILE" -pubout | sha256sum)
[[ $certificate_key == "$private_key" ]] || {
  echo "public gateway certificate and key do not match" >&2
  exit 2
}

namespace=${KCS_V2_NAMESPACE:-researchcosmos-v2}
backend_server_name=${KCS_BACKEND_TLS_SERVER_NAME:-10.255.250.1}
kubectl=(sudo k3s kubectl)

"${kubectl[@]}" -n "$namespace" create secret tls kcs-v2-public-gateway-tls \
  --cert="$KCS_PUBLIC_TLS_CERT_FILE" \
  --key="$KCS_PUBLIC_TLS_KEY_FILE" \
  --dry-run=client -o yaml | "${kubectl[@]}" apply -f -
"${kubectl[@]}" -n "$namespace" create secret generic kcs-v2-backend-ca \
  --from-file=ca.crt="$KCS_BACKEND_CA_FILE" \
  --dry-run=client -o yaml | "${kubectl[@]}" apply -f -

"${kubectl[@]}" apply -f - <<EOF
apiVersion: traefik.io/v1alpha1
kind: ServersTransport
metadata:
  name: kcs-v2-backend
  namespace: ${namespace}
spec:
  serverName: ${backend_server_name}
  rootCAsSecrets:
    - kcs-v2-backend-ca
---
apiVersion: v1
kind: Service
metadata:
  name: kcs-v2-public
  namespace: ${namespace}
  annotations:
    traefik.ingress.kubernetes.io/service.serversscheme: https
    traefik.ingress.kubernetes.io/service.serverstransport: ${namespace}-kcs-v2-backend@kubernetescrd
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: kcs-v2-api
  ports:
    - name: https
      port: 443
      targetPort: https
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kcs-v2-public
  namespace: ${namespace}
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
spec:
  ingressClassName: traefik
  tls:
    - hosts:
        - ${KCS_PUBLIC_HOST}
      secretName: kcs-v2-public-gateway-tls
  rules:
    - host: ${KCS_PUBLIC_HOST}
      http:
        paths:
          - path: /api/v2
            pathType: Prefix
            backend:
              service:
                name: kcs-v2-public
                port:
                  name: https
EOF

for public_host in "${public_hosts[@]:1}"; do
  existing_tls_hosts=$(
    "${kubectl[@]}" -n "$namespace" get ingress kcs-v2-public \
      -o jsonpath='{.spec.tls[0].hosts[*]}'
  )
  if ! grep -Fqw -- "$public_host" <<<"$existing_tls_hosts"; then
    tls_patch=$(printf \
      '[{"op":"add","path":"/spec/tls/0/hosts/-","value":"%s"}]' \
      "$public_host")
    "${kubectl[@]}" -n "$namespace" patch ingress kcs-v2-public \
      --type=json -p "$tls_patch"
  fi

  existing_rule_hosts=$(
    "${kubectl[@]}" -n "$namespace" get ingress kcs-v2-public \
      -o jsonpath='{.spec.rules[*].host}'
  )
  if ! grep -Fqw -- "$public_host" <<<"$existing_rule_hosts"; then
    rule_patch=$(printf \
      '[{"op":"add","path":"/spec/rules/-","value":{"host":"%s","http":{"paths":[{"path":"/api/v2","pathType":"Prefix","backend":{"service":{"name":"kcs-v2-public","port":{"name":"https"}}}}]}}}]' \
      "$public_host")
    "${kubectl[@]}" -n "$namespace" patch ingress kcs-v2-public \
      --type=json -p "$rule_patch"
  fi
done

"${kubectl[@]}" -n "$namespace" get ingress kcs-v2-public
