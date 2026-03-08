#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────────
# ensure-infra.sh — Idempotent Azure + Kubernetes infrastructure provisioning
#
# Ensures all Azure resources and Kubernetes prerequisites exist for BareMetalWeb
# on AKS. Safe to re-run — only creates/updates resources that are missing.
#
# Usage:
#   ./infra/ensure-infra.sh                    # Uses defaults
#   CLUSTER=mycluster RG=mygroup ./infra/ensure-infra.sh  # Override via env
#
# Prerequisites:
#   - az CLI authenticated (`az login`)
#   - kubectl installed
#   - helm installed (for NGINX ingress controller)
# ────────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Configuration (override via environment variables) ───────────────────────
LOCATION="${LOCATION:-uksouth}"
RG="${RG:-Personal}"
CLUSTER="${CLUSTER:-metalcluster}"
ACR_NAME="${ACR_NAME:-metalclusterregistry}"
ACR_RG="${ACR_RG:-metalclusterregistry_group}"
ACR_SKU="${ACR_SKU:-Standard}"
K8S_VERSION="${K8S_VERSION:-1.33}"
NODE_COUNT="${NODE_COUNT:-1}"
NODE_VM_SIZE="${NODE_VM_SIZE:-Standard_D2plds_v6}"
NAMESPACE="${NAMESPACE:-baremetalweb}"

# ── Colour helpers ───────────────────────────────────────────────────────────
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
info()   { printf '  %-50s' "$1"; }

check_ok()   { green "✓ $1"; }
check_skip() { yellow "→ $1"; }
check_fail() { red "✗ $1"; }

# ── Prerequisite checks ─────────────────────────────────────────────────────
green "═══════════════════════════════════════════════════════════════"
green " BareMetalWeb — Infrastructure Provisioning"
green "═══════════════════════════════════════════════════════════════"
echo ""

info "Checking az CLI..."
if ! command -v az &>/dev/null; then
    check_fail "az CLI not found — install from https://aka.ms/installazurecli"
    exit 1
fi
check_ok "found"

info "Checking kubectl..."
if ! command -v kubectl &>/dev/null; then
    check_fail "kubectl not found — install via 'az aks install-cli'"
    exit 1
fi
check_ok "found"

info "Checking az login status..."
if ! az account show &>/dev/null; then
    check_fail "Not logged in — run 'az login' first"
    exit 1
fi
check_ok "authenticated"
echo ""

# ── 1. Resource Group ───────────────────────────────────────────────────────
green "── 1. Resource Group ──────────────────────────────────────────"
info "Resource group '${RG}'..."
if az group show --name "${RG}" &>/dev/null; then
    check_ok "exists"
else
    check_skip "creating..."
    az group create --name "${RG}" --location "${LOCATION}" --output none
    check_ok "created"
fi

# ── 2. Azure Container Registry ─────────────────────────────────────────────
green "── 2. Azure Container Registry ────────────────────────────────"
info "ACR '${ACR_NAME}'..."
if az acr show --name "${ACR_NAME}" --resource-group "${ACR_RG}" &>/dev/null; then
    check_ok "exists"
else
    check_skip "creating..."
    az acr create \
        --name "${ACR_NAME}" \
        --resource-group "${ACR_RG}" \
        --location "${LOCATION}" \
        --sku "${ACR_SKU}" \
        --output none
    check_ok "created"
fi

ACR_LOGIN_SERVER=$(az acr show --name "${ACR_NAME}" --resource-group "${ACR_RG}" --query loginServer -o tsv)
echo "  ACR login server: ${ACR_LOGIN_SERVER}"

# ── 3. AKS Cluster ──────────────────────────────────────────────────────────
green "── 3. AKS Cluster ─────────────────────────────────────────────"
info "AKS cluster '${CLUSTER}'..."
if az aks show --name "${CLUSTER}" --resource-group "${RG}" &>/dev/null; then
    check_ok "exists"
else
    check_skip "creating (this may take several minutes)..."
    az aks create \
        --name "${CLUSTER}" \
        --resource-group "${RG}" \
        --location "${LOCATION}" \
        --node-count "${NODE_COUNT}" \
        --node-vm-size "${NODE_VM_SIZE}" \
        --generate-ssh-keys \
        --enable-managed-identity \
        --enable-oidc-issuer \
        --network-plugin azure \
        --network-plugin-mode overlay \
        --output none
    check_ok "created"
fi

# Validate network plugin settings (azure + overlay are immutable after creation)
info "Network plugin config..."
NET_PLUGIN=$(az aks show --name "${CLUSTER}" --resource-group "${RG}" \
    --query "networkProfile.networkPlugin" -o tsv 2>/dev/null)
NET_MODE=$(az aks show --name "${CLUSTER}" --resource-group "${RG}" \
    --query "networkProfile.networkPluginMode" -o tsv 2>/dev/null)

if [[ "${NET_PLUGIN}" == "azure" && "${NET_MODE}" == "overlay" ]]; then
    check_ok "azure + overlay"
else
    check_fail "expected azure/overlay, got ${NET_PLUGIN}/${NET_MODE}"
    red "  The cluster must use --network-plugin azure --network-plugin-mode overlay."
    red "  These settings cannot be changed on an existing cluster — recreate required."
    exit 1
fi

# ── 4. ACR ↔ AKS Attachment ─────────────────────────────────────────────────
green "── 4. ACR ↔ AKS Integration ───────────────────────────────────"
info "ACR attachment to AKS..."

KUBELET_ID=$(az aks show --name "${CLUSTER}" --resource-group "${RG}" \
    --query "identityProfile.kubeletidentity.objectId" -o tsv 2>/dev/null || true)
ACR_ID=$(az acr show --name "${ACR_NAME}" --resource-group "${ACR_RG}" --query id -o tsv)

HAS_PULL=$(az role assignment list \
    --assignee "${KUBELET_ID}" \
    --scope "${ACR_ID}" \
    --role AcrPull \
    --query "[0].id" -o tsv 2>/dev/null || true)

if [[ -n "${HAS_PULL}" ]]; then
    check_ok "already attached"
else
    check_skip "attaching ACR to AKS..."
    az aks update \
        --name "${CLUSTER}" \
        --resource-group "${RG}" \
        --attach-acr "${ACR_NAME}" \
        --output none
    check_ok "attached"
fi

# ── 5. Get kubectl credentials ──────────────────────────────────────────────
green "── 5. kubectl Credentials ─────────────────────────────────────"
info "Fetching AKS credentials..."
az aks get-credentials \
    --name "${CLUSTER}" \
    --resource-group "${RG}" \
    --overwrite-existing \
    --output none 2>/dev/null
check_ok "kubeconfig updated"

info "Cluster connectivity..."
if kubectl cluster-info &>/dev/null; then
    check_ok "connected"
else
    check_fail "cannot reach cluster"
    exit 1
fi

# ── 6. Kubernetes Namespace ──────────────────────────────────────────────────
green "── 6. Kubernetes Namespace ────────────────────────────────────"
info "Namespace '${NAMESPACE}'..."
if kubectl get namespace "${NAMESPACE}" &>/dev/null 2>&1; then
    check_ok "exists"
else
    check_skip "creating..."
    kubectl apply -f kubectl/namespace.yaml
    check_ok "created"
fi

# ── 7. Apply Kubernetes Manifests ────────────────────────────────────────────
green "── 7. Kubernetes Resources ────────────────────────────────────"
info "Applying manifests from kubectl/..."
kubectl apply -f kubectl/ 2>&1 | while IFS= read -r line; do
    echo "  ${line}"
done
check_ok "all resources applied"

# ── 8. Summary ───────────────────────────────────────────────────────────────
echo ""
green "═══════════════════════════════════════════════════════════════"
green " Infrastructure Ready"
green "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Cluster:    ${CLUSTER} (${RG})"
echo "  ACR:        ${ACR_LOGIN_SERVER}"
echo "  Network:    azure CNI + overlay"
echo "  Namespace:  ${NAMESPACE}"
echo "  Image:      ${ACR_LOGIN_SERVER}/baremetalweb:<tag>"
echo ""

# Show LoadBalancer external IP if available
LB_IP=$(kubectl get svc -n "${NAMESPACE}" baremetalweb \
    -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
if [[ -n "${LB_IP}" ]]; then
    echo "  Public IP:  ${LB_IP}"
    echo "  Point your DNS A record to this IP."
else
    yellow "  Public IP:  pending (LoadBalancer provisioning...)"
    echo "  Run: kubectl get svc -n ${NAMESPACE} baremetalweb"
fi

echo ""
echo "  Direct pod access (headless):"
echo "    baremetalweb-0.baremetalweb-headless.${NAMESPACE}.svc.cluster.local"
echo "    baremetalweb-1.baremetalweb-headless.${NAMESPACE}.svc.cluster.local"
echo ""
green "  Next: ./infra/deploy-aks.sh   # Build, push, and deploy"
green "═══════════════════════════════════════════════════════════════"
