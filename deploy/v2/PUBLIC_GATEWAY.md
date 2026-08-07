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
export KCS_PUBLIC_TRUST_BUNDLE_FILE=/secure/path/public-client-ca.pem
export KCS_BACKEND_CA_FILE=/secure/path/backend-ca.pem
# Optional temporary or migration hostnames already covered by the certificate.
export KCS_PUBLIC_EXTRA_HOSTS='36-103-234-82.sslip.io'
sudo -E ./scripts/deploy_v2_public_gateway.sh
```

The script verifies the hostname, key pair, and the complete public client
trust chain with OpenSSL strict server-purpose validation before it creates
Kubernetes secrets and publishes only `/api/v2/*`. For a private root CA,
`basicConstraints = critical, CA:TRUE` and
`keyUsage = critical, keyCertSign, cRLSign` are required; the leaf needs a SAN
for every advertised hostname and `extendedKeyUsage = serverAuth`. Traefik
verifies the existing private KCS API TLS certificate through a
`ServersTransport`; service bearer authorization remains mandatory.
Certificate bytes and tokens are never committed.

DNS and the cloud firewall must deliver TCP 443 to the KCS Traefik service.
The Product runtime callback is a separate, system-trusted HTTPS endpoint that
KCS Jobs must be able to reach with Attempt-scoped credentials.

If a hosting platform blocks public ports 80 and 443, permit Traefik's existing
`websecure` NodePort instead. Discover it rather than hard-coding it:

```bash
sudo k3s kubectl -n kube-system get service traefik \
  -o jsonpath='{.spec.ports[?(@.name=="websecure")].nodePort}{"\n"}'
```

Clients then use `https://<certificate-covered-host>:<node-port>`. This is a
temporary transport address; the KCS API, bearer authentication and Product
callback contracts are unchanged.

Some hosting platforms acknowledge a custom NodePort rule but do not deliver
payload bytes to the host. In that case, use an already-permitted high port on
the KCS control host and terminate TLS with Nginx (or an equivalent reverse
proxy), forwarding only `/api/v2/*` to the private KCS API with backend CA
verification enabled. The current hosted deployment uses port 8888 for this
reason. Do not bind the private API itself to the public interface.
