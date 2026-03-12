# Hosting Model

BareMetalWeb runs as a Native AOT–compiled binary inside thin containers on Azure Kubernetes Service (AKS). Kestrel terminates TLS directly — there is no ingress controller or reverse proxy in the path.

---

## Infrastructure Diagram

```
                      ┌──────────────────────────────────┐
                      │        Azure DNS                 │
                      │  metal.willeastbury.com  A-rec   │
                      │        → 85.210.153.1            │
                      └──────────────┬───────────────────┘
                                     │
                                     ▼
                      ┌──────────────────────────────────┐
                      │     AKS LoadBalancer Service     │
                      │  :80  → containerPort 5232 (http)│
                      │  :443 → containerPort 5233 (https│
                      │         (TCP pass-through)       │
                      └──────────────┬───────────────────┘
                                     │
                      ┌──────────────▼───────────────────┐
                      │   Kestrel (Native AOT binary)    │
                      │   :5232  HTTP                    │
                      │   :5233  HTTPS (TLS termination) │
                      │                                  │
                      │   /app/tls/tls.crt + tls.key     │
                      │   mounted from K8s Secret        │
                      │   (baremetalweb-tls)              │
                      └──────────────────────────────────┘
```

---

## Components

### DNS

| Record | Type | Value | TTL |
|--------|------|-------|-----|
| `metal.willeastbury.com` | A | AKS LoadBalancer external IP | 300 s |

The A record is managed in the **Azure DNS zone** `willeastbury.com` (resource group `global-buddy-will-rg`).

### AKS Cluster

| Property | Value |
|----------|-------|
| Cluster name | `metalcluster` |
| Resource group | `Personal` |
| Namespace | `baremetalweb` |
| Workload | `StatefulSet/baremetalweb` |
| Replicas | 1 (scalable) |
| Storage | 10 Gi managed-csi PVC per pod |

### Container Images

Images are built by the CI2 pipeline stage and pushed to two registries:

| Registry | Image |
|----------|-------|
| GHCR | `ghcr.io/willeastbury/baremetalweb:<tag>` |
| ACR | `metalclusterregistry.azurecr.io/baremetalweb:<tag>` |

Images use **thin Dockerfiles** (`Dockerfile.prebuilt`) — the AOT binary is compiled in CI and copied into a minimal `runtime-deps` base (no SDK layer). Final images are ~30 MB.

### LoadBalancer Service

The Kubernetes `LoadBalancer` service performs **TCP pass-through only** — it does not terminate TLS. Traffic arrives at Kestrel exactly as sent by the client.

```yaml
ports:
  - name: http
    port: 80
    targetPort: 5232      # Kestrel HTTP
  - name: https
    port: 443
    targetPort: 5233      # Kestrel HTTPS (TLS)
```

---

## TLS Certificates

### Strategy

Kestrel terminates TLS directly (no ingress controller, no sidecar). Certificates are managed by **cert-manager** running in the cluster, using **Let's Encrypt** with **DNS-01** challenges via Azure DNS.

### cert-manager

Installed via Helm in the `cert-manager` namespace:

```bash
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true \
  --set crds.keep=true
```

cert-manager watches `Certificate` resources, requests certs from Let's Encrypt, and stores them as Kubernetes Secrets. Renewal is automatic (default: 30 days before expiry).

### Certificate Flow

```
cert-manager                        Let's Encrypt
     │                                    │
     │  1. ACME order (DNS-01)            │
     ├───────────────────────────────────► │
     │                                    │
     │  2. Create TXT record in           │
     │     Azure DNS zone                 │
     ├──► Azure DNS                       │
     │                                    │
     │  3. Let's Encrypt validates        │
     │     _acme-challenge.metal...       │
     │ ◄──────────────────────────────────┤
     │                                    │
     │  4. Certificate issued             │
     │ ◄──────────────────────────────────┤
     │                                    │
     │  5. Store as K8s Secret            │
     │     (baremetalweb-tls)             │
     ▼                                    │
  Secret mounted at /app/tls/
  in baremetalweb pod
```

### Kubernetes Resources

**ClusterIssuer** — connects cert-manager to Let's Encrypt via Azure DNS:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v2.api.letsencrypt.org/directory
    email: <admin email>
    privateKeySecretRef:
      name: letsencrypt-prod-key
    solvers:
      - dns01:
          azureDNS:
            subscriptionID: <subscription-id>
            resourceGroupName: global-buddy-will-rg
            hostedZoneName: willeastbury.com
```

**Certificate** — requests the cert and writes it to a Secret:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: baremetalweb-tls
  namespace: baremetalweb
spec:
  secretName: baremetalweb-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - metal.willeastbury.com
```

### Secret Mount

The StatefulSet mounts the TLS secret into the container:

```yaml
volumes:
  - name: tls
    secret:
      secretName: baremetalweb-tls
      optional: true          # pod starts even if cert isn't ready yet

volumeMounts:
  - name: tls
    mountPath: /app/tls
    readOnly: true
```

Kestrel reads `tls.crt` and `tls.key` from `/app/tls/` to serve HTTPS on port 5233.

---

## Why No Ingress Controller?

BareMetalWeb is a **single-service deployment** — there is no fan-out to multiple backends. Adding an ingress controller (NGINX, Traefik, etc.) would:

- Add latency (extra network hop + TLS re-encryption or termination)
- Add operational complexity (another component to configure, upgrade, monitor)
- Consume cluster resources for no routing benefit

Kestrel is a production-grade HTTP server that handles TLS termination, HTTP/2, keep-alive, and connection draining natively. Letting it terminate TLS directly is the lowest-latency option.

---

## Port Summary

| Layer | Port | Protocol | Purpose |
|-------|------|----------|---------|
| LoadBalancer | 80 | TCP | HTTP (pass-through to Kestrel) |
| LoadBalancer | 443 | TCP | HTTPS (pass-through to Kestrel) |
| Kestrel | 5232 | HTTP | Application HTTP endpoint |
| Kestrel | 5233 | HTTPS | Application HTTPS endpoint (TLS termination) |
| Pi5 (local dev) | 5000 | HTTP | Local development server |

---

_Status: Created 2026-03-09 — AKS hosting model with Kestrel TLS termination and cert-manager_
