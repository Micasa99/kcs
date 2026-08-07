# KCS V2 public HTTPS gateway

KCS remains the authority for its cluster, workers and storage. Product
clients receive only one HTTPS base URL, a CA bundle and a service-token file;
they do not need SSH, K3s or GPU-node addresses.

Install a Traefik ingress from the KCS control node after placing the public
certificate, private key and the existing backend CA in root-readable files:

```bash
export KCS_PUBLIC_HOST=kcs.example.org
export KCS_PUBLIC_TLS_CERT_FILE=/secure/path/public.crt
export KCS_PUBLIC_TLS_KEY_FILE=/secure/path/public.key
export KCS_BACKEND_CA_FILE=/secure/path/backend-ca.pem
sudo -E ./scripts/deploy_v2_public_gateway.sh
```

The script verifies the hostname and key pair, creates Kubernetes secrets, and
publishes only `/api/v2/*`. Traefik verifies the existing private KCS API TLS
certificate through a `ServersTransport`; service bearer authorization remains
mandatory. Certificate bytes and tokens are never committed.

DNS and the cloud firewall must deliver TCP 443 to the KCS Traefik service.
The Product runtime callback is a separate, system-trusted HTTPS endpoint that
KCS Jobs must be able to reach with Attempt-scoped credentials.

