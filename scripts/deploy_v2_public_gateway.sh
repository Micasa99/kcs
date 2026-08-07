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

if [[ ! $KCS_PUBLIC_HOST =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]]; then
  echo "KCS_PUBLIC_HOST must be a DNS hostname" >&2
  exit 2
fi
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

openssl x509 -in "$KCS_PUBLIC_TLS_CERT_FILE" -noout \
  -checkhost "$KCS_PUBLIC_HOST" >/dev/null
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

"${kubectl[@]}" -n "$namespace" get ingress kcs-v2-public
