#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────────
# deploy-aks.sh — Build, push to ACR, and deploy BareMetalWeb to AKS
#
# Usage:
#   ./infra/deploy-aks.sh                         # Build + deploy latest
#   VERSION=1.20260308.42 ./infra/deploy-aks.sh   # Deploy with specific version tag
#
# Prerequisites:
#   - az CLI authenticated
#   - kubectl configured for metalcluster (run ensure-infra.sh first)
#   - Docker or az acr build available
# ────────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Configuration ────────────────────────────────────────────────────────────
RG="${RG:-Personal}"
CLUSTER="${CLUSTER:-metalcluster}"
ACR_NAME="${ACR_NAME:-metalclusterregistry}"
ACR_RG="${ACR_RG:-metalclusterregistry_group}"
NAMESPACE="${NAMESPACE:-baremetalweb}"

# Version: use env var, or compute from date + git SHA
if [[ -z "${VERSION:-}" ]]; then
    MAJOR="${MAJOR_VERSION:-1}"
    DATE="$(date +%Y%m%d)"
    SHA="$(cd "${REPO_ROOT}" && git rev-parse --short=7 HEAD 2>/dev/null || echo 'local')"
    VERSION="${MAJOR}.${DATE}.${SHA}"
fi

ACR_LOGIN_SERVER=$(az acr show --name "${ACR_NAME}" --resource-group "${ACR_RG}" --query loginServer -o tsv)
IMAGE="${ACR_LOGIN_SERVER}/baremetalweb"

# Detect target platform from AKS node architecture
NODE_ARCH=$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.architecture}' 2>/dev/null || echo "amd64")
case "${NODE_ARCH}" in
    arm64|aarch64) PLATFORM="linux-arm64" ;;
    *)             PLATFORM="linux-amd64" ;;
esac

IMAGE_TAG="${IMAGE}:${VERSION}-${PLATFORM}"

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }

green "═══════════════════════════════════════════════════════════════"
green " BareMetalWeb — Deploy to AKS"
green "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Image:    ${IMAGE_TAG}"
echo "  Platform: ${PLATFORM} (node arch: ${NODE_ARCH})"
echo "  Cluster:  ${CLUSTER} (${RG})"
echo ""

# ── 1. Build and push container image ────────────────────────────────────────
green "── 1. Building container image via ACR ─────────────────────────"

# Convert tag platform format to Docker platform format (linux-arm64 → linux/arm64)
DOCKER_PLATFORM="${PLATFORM//-//}"

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    echo "  Using local Docker build..."
    az acr login --name "${ACR_NAME}" --output none
    docker build \
        -t "${IMAGE_TAG}" \
        --platform "${DOCKER_PLATFORM}" \
        --build-arg "VERSION=${VERSION}" \
        "${REPO_ROOT}"
    docker push "${IMAGE_TAG}"
else
    echo "  Using ACR cloud build..."
    az acr build \
        --registry "${ACR_NAME}" \
        --resource-group "${ACR_RG}" \
        --image "baremetalweb:${VERSION}-${PLATFORM}" \
        --platform "${DOCKER_PLATFORM}" \
        --build-arg "VERSION=${VERSION}" \
        "${REPO_ROOT}"
fi

green "  ✓ Image pushed: ${IMAGE_TAG}"

# ── 2. Ensure kubectl context ───────────────────────────────────────────────
green "── 2. Configuring kubectl ──────────────────────────────────────"
az aks get-credentials \
    --name "${CLUSTER}" \
    --resource-group "${RG}" \
    --overwrite-existing \
    --output none 2>/dev/null
echo "  ✓ kubectl context set to ${CLUSTER}"

# ── 3. Apply Kubernetes manifests ────────────────────────────────────────────
green "── 3. Applying Kubernetes manifests ────────────────────────────"
kubectl apply -f "${REPO_ROOT}/kubectl/" 2>&1 | while IFS= read -r line; do
    echo "  ${line}"
done

# ── 4. Update statefulset image tag ──────────────────────────────────────────
green "── 4. Rolling out new image ────────────────────────────────────"
kubectl set image statefulset/baremetalweb \
    baremetalweb="${IMAGE_TAG}" \
    --namespace "${NAMESPACE}"
echo "  ✓ Image set to ${IMAGE_TAG}"

# ── 5. Wait for rollout ─────────────────────────────────────────────────────
green "── 5. Waiting for rollout ──────────────────────────────────────"
if kubectl rollout status statefulset/baremetalweb \
    --namespace "${NAMESPACE}" \
    --timeout=300s; then
    green "  ✓ Rollout complete"
else
    yellow "  ⚠ Rollout timed out — check: kubectl get pods -n ${NAMESPACE}"
    exit 1
fi

# ── 6. Health check ──────────────────────────────────────────────────────────
green "── 6. Health check ────────────────────────────────────────────"
POD=$(kubectl get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=baremetalweb \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -n "${POD}" ]]; then
    for i in 1 2 3 4 5 6; do
        STATUS=$(kubectl exec -n "${NAMESPACE}" "${POD}" -- \
            cat /proc/1/status 2>/dev/null | head -1 || true)
        if [[ -n "${STATUS}" ]]; then
            green "  ✓ Pod ${POD} is running"
            break
        fi
        echo "  Attempt ${i}/6 — waiting 10s..."
        sleep 10
    done
else
    yellow "  ⚠ No running pod found"
fi

# ── 7. Summary ───────────────────────────────────────────────────────────────
echo ""
green "═══════════════════════════════════════════════════════════════"
green " Deployment Complete"
green "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Version:   ${VERSION}"
echo "  Image:     ${IMAGE_TAG}"
echo "  Namespace: ${NAMESPACE}"
echo ""

kubectl get pods -n "${NAMESPACE}" -o wide 2>/dev/null || true
echo ""

INGRESS_IP=$(kubectl get svc -n "${NAMESPACE}" baremetalweb \
    -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
if [[ -n "${INGRESS_IP}" ]]; then
    echo "  Public IP: http://${INGRESS_IP}"
fi
echo ""
echo "  Direct pod access (headless):"
echo "    baremetalweb-0.baremetalweb-headless.${NAMESPACE}.svc.cluster.local"
echo "    baremetalweb-1.baremetalweb-headless.${NAMESPACE}.svc.cluster.local"
echo ""
