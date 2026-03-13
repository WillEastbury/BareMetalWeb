#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_local-common.sh"

MODE="canary"
IMAGE_TAG="${IMAGE_TAG:-}"
PUBLISH_DIR="${PUBLISH_DIR:-${REPO_ROOT}/artifacts/publish-cd}"
ACR_NAME="${ACR_NAME:-metalclusterregistry}"
ACR_LOGIN_SERVER="${ACR_LOGIN_SERVER:-metalclusterregistry.azurecr.io}"
ACR_IMAGE="${ACR_IMAGE:-baremetalweb}"
AKS_CLUSTER="${AKS_CLUSTER:-metalcluster}"
AKS_RESOURCE_GROUP="${AKS_RESOURCE_GROUP:-Personal}"
AKS_NAMESPACE="${AKS_NAMESPACE:-baremetalweb}"
RUN_TESTS="${RUN_TESTS:-1}"

usage() {
    cat <<'EOF'
Usage:
  ./infra/local-cd.sh --image-tag 1.20260312.149-linux-arm64 [--mode canary|early-access|production]

Modes:
  canary        Deploy to AKS and run setup / upgrade / perf checks locally
  early-access  Deploy local publish package to early-access web apps from deploy-list.json
  production    Deploy to production web apps from deploy-list.json and AKS

Environment:
  RUN_TESTS=0                 Skip canary smoke/integration/perf checks
  PUBLISH_DIR=./artifacts/publish-cd
  CONTROL_PLANE_URL=...
  CONTROL_PLANE_API_KEY=...
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image-tag) IMAGE_TAG="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --publish-dir) PUBLISH_DIR="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[[ -n "${IMAGE_TAG}" ]] || die "--image-tag is required"

require_cmd dotnet
require_cmd jq
require_cmd curl
verify_acr_tag "${ACR_NAME}" "${ACR_IMAGE}" "${IMAGE_TAG}"

VERSION_NUMBER="$(strip_arch_suffix "${IMAGE_TAG}")"
FULL_IMAGE="${ACR_LOGIN_SERVER}/${ACR_IMAGE}:${IMAGE_TAG}"

build_publish_if_missing() {
    if [[ -d "${PUBLISH_DIR}" && -n "$(find "${PUBLISH_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null)" ]]; then
        return
    fi

    ensure_dir "${PUBLISH_DIR}"
    rm -rf "${PUBLISH_DIR:?}/"*
    dotnet publish "${REPO_ROOT}/BareMetalWeb.Host/BareMetalWeb.Host.csproj" \
        --configuration Release \
        --output "${PUBLISH_DIR}" \
        -p:InformationalVersion="${IMAGE_TAG}"
}

deploy_aks_image() {
    require_cmd kubectl
    ensure_azure_login

    az aks get-credentials \
        --name "${AKS_CLUSTER}" \
        --resource-group "${AKS_RESOURCE_GROUP}" \
        --overwrite-existing >/dev/null

    kubectl apply -f "${REPO_ROOT}/kubectl/" >/dev/null
    kubectl set image "statefulset/baremetalweb" "baremetalweb=${FULL_IMAGE}" --namespace "${AKS_NAMESPACE}" >/dev/null
    kubectl rollout status "statefulset/baremetalweb" --namespace "${AKS_NAMESPACE}" --timeout=300s

    local pod=""
    for _ in 1 2 3 4 5 6; do
        pod="$(kubectl get pod -n "${AKS_NAMESPACE}" -l app.kubernetes.io/name=baremetalweb -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
        if [[ -n "${pod}" ]]; then
            ready="$(kubectl get pod -n "${AKS_NAMESPACE}" "${pod}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
            if [[ "${ready}" == "True" ]]; then
                green "AKS deployment ready: ${pod}"
                break
            fi
        fi
        sleep 10
    done

    if [[ -n "${CONTROL_PLANE_URL:-}" && -n "${CONTROL_PLANE_API_KEY:-}" && -n "${pod}" ]]; then
        for _ in $(seq 1 30); do
            response="$(curl -s --max-time 10 \
                -H "ApiKey: ${CONTROL_PLANE_API_KEY}" \
                "${CONTROL_PLANE_URL}/api/_cluster/upgrade-status?instanceId=${pod}&targetVersion=${VERSION_NUMBER}" \
                2>/dev/null || true)"
            if [[ -n "${response}" && "$(json_field "${response}" '.verified // false')" == "true" ]]; then
                green "AKS control-plane verification passed."
                return
            fi
            sleep 10
        done
        die "AKS control-plane verification failed for ${pod}"
    fi
}

run_canary_tests() {
    [[ "${RUN_TESTS}" == "1" ]] || return

    build_publish_if_missing

    "${SCRIPT_DIR}/local-deploy-tenant.sh" \
        --app-name baremetalweb-cireset \
        --resource-group baremetalweb-rg \
        --publish-dir "${PUBLISH_DIR}" \
        --health-check-url "https://baremetalweb-cireset.azurewebsites.net" \
        --version-number "${VERSION_NUMBER}" \
        --reset-data

    if [[ -d "${REPO_ROOT}/tests/playwright" ]]; then
        require_cmd npm
        pushd "${REPO_ROOT}/tests/playwright" >/dev/null
        npm ci
        npx playwright install chromium --with-deps
        BASE_URL="https://baremetalweb-cireset.azurewebsites.net" npx playwright test --grep "@smoke"
        popd >/dev/null
    fi

    "${SCRIPT_DIR}/local-deploy-tenant.sh" \
        --app-name baremetalweb-upgrade \
        --resource-group baremetalweb-rg \
        --publish-dir "${PUBLISH_DIR}" \
        --health-check-url "https://baremetalweb-upgrade.azurewebsites.net" \
        --version-number "${VERSION_NUMBER}"

    dotnet restore "${REPO_ROOT}/BareMetalWeb.IntegrationTests/BareMetalWeb.IntegrationTests.csproj"
    dotnet build "${REPO_ROOT}/BareMetalWeb.IntegrationTests/BareMetalWeb.IntegrationTests.csproj" --configuration Release --no-restore
    dotnet test "${REPO_ROOT}/BareMetalWeb.IntegrationTests/BareMetalWeb.IntegrationTests.csproj" \
        --no-build \
        --configuration Release \
        --verbosity normal \
        --blame-hang-timeout 120s \
        --filter "Category=Integration|FullyQualifiedName~IntegrationTests"

    dotnet restore "${REPO_ROOT}/BareMetalWeb.PerformanceTests/BareMetalWeb.PerformanceTests.csproj"
    dotnet build "${REPO_ROOT}/BareMetalWeb.PerformanceTests/BareMetalWeb.PerformanceTests.csproj" --configuration Release --no-restore
    dotnet run --project "${REPO_ROOT}/BareMetalWeb.PerformanceTests/BareMetalWeb.PerformanceTests.csproj" --configuration Release --no-build -- --addresses 100 --customers 50 --products 25 --units 10
    dotnet run --project "${REPO_ROOT}/BareMetalWeb.PerformanceTests/BareMetalWeb.PerformanceTests.csproj" --configuration Release --no-build -- --addresses 10000 --customers 5000 --products 2500 --units 1000
}

deploy_ring_from_list() {
    local ring="$1"
    build_publish_if_missing

    while IFS= read -r row; do
        local app_name
        local resource_group
        local url
        app_name="$(json_field "${row}" '.app_name')"
        resource_group="$(json_field "${row}" '.resource_group')"
        url="$(json_field "${row}" '.url')"

        "${SCRIPT_DIR}/local-deploy-tenant.sh" \
            --app-name "${app_name}" \
            --resource-group "${resource_group}" \
            --publish-dir "${PUBLISH_DIR}" \
            --health-check-url "${url}" \
            --version-number "${VERSION_NUMBER}"
    done < <(jq -c ".targets[] | select(.ring == \"${ring}\")" "${REPO_ROOT}/deploy-list.json")
}

green "== Local CD =="
printf 'Mode:      %s\n' "${MODE}"
printf 'Image tag: %s\n\n' "${IMAGE_TAG}"

case "${MODE}" in
    canary)
        deploy_aks_image
        run_canary_tests
        ;;
    early-access)
        deploy_ring_from_list "early-access"
        ;;
    production)
        deploy_ring_from_list "production"
        deploy_aks_image
        ;;
    *)
        die "Unsupported mode: ${MODE}"
        ;;
esac

green "Local CD complete."
