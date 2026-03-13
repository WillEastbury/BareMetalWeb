#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_local-common.sh"

APP_NAME=""
RESOURCE_GROUP=""
PUBLISH_DIR=""
HEALTH_CHECK_URL=""
VERSION_NUMBER=""
RESET_DATA=0

usage() {
    cat <<'EOF'
Usage:
  ./infra/local-deploy-tenant.sh \
    --app-name baremetalweb-cireset \
    --resource-group baremetalweb-rg \
    --publish-dir ./artifacts/publish-jit \
    [--health-check-url https://example.azurewebsites.net] \
    [--version-number 1.20260312.149] \
    [--reset-data]

Deploys a local JIT publish folder to one Azure Web App, then health-checks it.

Environment:
  CONTROL_PLANE_URL      Optional control-plane base URL
  CONTROL_PLANE_API_KEY  Optional control-plane API key
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app-name) APP_NAME="$2"; shift 2 ;;
        --resource-group) RESOURCE_GROUP="$2"; shift 2 ;;
        --publish-dir) PUBLISH_DIR="$2"; shift 2 ;;
        --health-check-url) HEALTH_CHECK_URL="$2"; shift 2 ;;
        --version-number) VERSION_NUMBER="$2"; shift 2 ;;
        --reset-data) RESET_DATA=1; shift ;;
        --help) usage; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[[ -n "${APP_NAME}" ]] || die "--app-name is required"
[[ -n "${RESOURCE_GROUP}" ]] || die "--resource-group is required"
[[ -n "${PUBLISH_DIR}" ]] || die "--publish-dir is required"
[[ -d "${PUBLISH_DIR}" ]] || die "Publish directory does not exist: ${PUBLISH_DIR}"

require_cmd az
require_cmd curl
ensure_azure_login

staging_dir="$(mktemp -d)"
zip_path="$(mktemp --suffix=.zip)"
trap 'rm -rf "${staging_dir}" "${zip_path}"' EXIT

cp -a "${PUBLISH_DIR}/." "${staging_dir}/"
if [[ "${RESET_DATA}" == "1" ]]; then
    touch "${staging_dir}/reset-data.flag"
fi

zip_publish_dir "${staging_dir}" "${zip_path}"

green "== Deploy tenant: ${APP_NAME} =="
az webapp stop --name "${APP_NAME}" --resource-group "${RESOURCE_GROUP}" >/dev/null
az webapp config appsettings set \
    --name "${APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --settings WEBSITE_RUN_FROM_PACKAGE=0 \
    --output none
az webapp config set \
    --name "${APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --startup-file "dotnet BareMetalWeb.Host.dll" \
    --output none
az webapp config appsettings set \
    --name "${APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --settings ControlPlane__InstanceId="${APP_NAME}" \
    --output none
az webapp deploy \
    --name "${APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --src-path "${zip_path}" \
    --type zip \
    --clean true >/dev/null
az webapp start --name "${APP_NAME}" --resource-group "${RESOURCE_GROUP}" >/dev/null
sleep 30

if [[ -z "${HEALTH_CHECK_URL}" ]]; then
    HEALTH_CHECK_URL="https://${APP_NAME}.azurewebsites.net/"
fi

for attempt in 1 2 3 4 5 6; do
    status="$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "${HEALTH_CHECK_URL}" || echo 000)"
    if [[ "${status}" == "200" || "${status}" == "302" ]]; then
        green "Health check passed for ${APP_NAME} (${status})."
        break
    fi
    [[ "${attempt}" == "6" ]] && die "Health check failed for ${APP_NAME}"
    sleep 10
done

if [[ -n "${VERSION_NUMBER}" && -n "${CONTROL_PLANE_URL:-}" && -n "${CONTROL_PLANE_API_KEY:-}" ]]; then
    for attempt in $(seq 1 30); do
        response="$(curl -s --max-time 10 \
            -H "ApiKey: ${CONTROL_PLANE_API_KEY}" \
            "${CONTROL_PLANE_URL}/api/_cluster/upgrade-status?instanceId=${APP_NAME}&targetVersion=${VERSION_NUMBER}" \
            2>/dev/null || true)"

        if [[ -n "${response}" && "$(json_field "${response}" '.verified // false')" == "true" ]]; then
            green "Upgrade verified for ${APP_NAME} on ${VERSION_NUMBER}."
            exit 0
        fi
        sleep 10
    done
    die "Control-plane upgrade verification failed for ${APP_NAME}"
fi
