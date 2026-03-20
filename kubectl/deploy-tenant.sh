#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────────
# deploy-tenant.sh — Deploy one or more BareMetalWeb tenants to AKS
#
# Usage:
#   ./kubectl/deploy-tenant.sh <tenant> [image-tag]   Deploy a single tenant
#   ./kubectl/deploy-tenant.sh --all                   Deploy all tenants in tenants.conf
#   ./kubectl/deploy-tenant.sh --all --image-only      Update image tag only (no apply)
#
# Environment overrides (all optional):
#   ACR_LOGIN_SERVER   Container registry  (default: metalclusterregistry.azurecr.io)
#   REPLICAS           Pod count           (default: 1)
#   STORAGE            PVC size            (default: 10Gi)
#   CPU_REQUEST        CPU request         (default: 100m)
#   MEM_REQUEST        Memory request      (default: 128Mi)
#   CPU_LIMIT          CPU limit           (default: 1)
#   MEM_LIMIT          Memory limit        (default: 512Mi)
# ────────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="${SCRIPT_DIR}/template"
TENANTS_FILE="${SCRIPT_DIR}/tenants.conf"

: "${ACR_LOGIN_SERVER:=metalclusterregistry.azurecr.io}"

deploy_tenant() {
    local tenant="$1"
    local image_tag="$2"
    local image_only="${3:-false}"

    export TENANT_NAME="${tenant}"
    export IMAGE_TAG="${image_tag}"
    export ACR_LOGIN_SERVER
    export REPLICAS="${REPLICAS:-1}"
    export STORAGE="${STORAGE:-10Gi}"
    export CPU_REQUEST="${CPU_REQUEST:-100m}"
    export MEM_REQUEST="${MEM_REQUEST:-128Mi}"
    export CPU_LIMIT="${CPU_LIMIT:-1}"
    export MEM_LIMIT="${MEM_LIMIT:-512Mi}"

    echo "══════════════════════════════════════════════════════════════"
    echo "  Deploying tenant: ${tenant}"
    echo "  Image:            ${ACR_LOGIN_SERVER}/baremetalweb:${image_tag}"
    echo "══════════════════════════════════════════════════════════════"

    if [[ "${image_only}" == "true" ]]; then
        echo "→ Updating image only..."
        kubectl set image "statefulset/${tenant}" \
            "${tenant}=${ACR_LOGIN_SERVER}/baremetalweb:${image_tag}" \
            --namespace "${tenant}"
    else
        echo "→ Applying full manifest..."
        for tmpl in namespace configmap service headless-service statefulset; do
            envsubst < "${TEMPLATE_DIR}/${tmpl}.yaml" | kubectl apply -f -
        done
    fi

    echo "→ Waiting for rollout..."
    kubectl rollout status "statefulset/${tenant}" \
        --namespace "${tenant}" \
        --timeout=300s

    echo "→ Health check..."
    local pod
    pod=$(kubectl get pod -n "${tenant}" \
        -l "app.kubernetes.io/name=${tenant}" \
        -o jsonpath='{.items[0].metadata.name}')

    for attempt in 1 2 3 4 5 6; do
        local status
        status=$(kubectl exec -n "${tenant}" "${pod}" -- \
            wget -q -O- --timeout=5 http://localhost:5232/health 2>/dev/null || true)
        if [[ -n "${status}" ]]; then
            echo "✅ ${tenant} healthy (attempt ${attempt})"
            return 0
        fi
        echo "  Attempt ${attempt}/6 — waiting 10s..."
        sleep 10
    done
    echo "❌ ${tenant} health check failed"
    return 1
}

deploy_all() {
    local image_only="${1:-false}"
    local failures=0

    while IFS=' ' read -r tenant tag replicas storage cpu_req mem_req cpu_lim mem_lim; do
        [[ -z "${tenant}" || "${tenant}" == \#* ]] && continue
        export REPLICAS="${replicas:-1}"
        export STORAGE="${storage:-10Gi}"
        export CPU_REQUEST="${cpu_req:-100m}"
        export MEM_REQUEST="${mem_req:-128Mi}"
        export CPU_LIMIT="${cpu_lim:-1}"
        export MEM_LIMIT="${mem_lim:-512Mi}"
        deploy_tenant "${tenant}" "${tag}" "${image_only}" || ((failures++))
    done < "${TENANTS_FILE}"

    if ((failures > 0)); then
        echo "❌ ${failures} tenant(s) failed"
        exit 1
    fi
    echo "✅ All tenants deployed"
}

# ── CLI ──────────────────────────────────────────────────────────────────────
case "${1:-}" in
    --all)
        deploy_all "${2:+true}"
        ;;
    --help|-h|"")
        echo "Usage:"
        echo "  $0 <tenant> [image-tag]    Deploy a single tenant"
        echo "  $0 --all                   Deploy all from tenants.conf"
        echo "  $0 --all --image-only      Update image tag only"
        exit 0
        ;;
    *)
        TENANT="$1"
        TAG="${2:-$(grep "^${TENANT}" "${TENANTS_FILE}" | awk '{print $2}')}"
        if [[ -z "${TAG}" ]]; then
            echo "Error: No image tag provided and tenant '${TENANT}' not in tenants.conf"
            exit 1
        fi
        deploy_tenant "${TENANT}" "${TAG}" "false"
        ;;
esac
