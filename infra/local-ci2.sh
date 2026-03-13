#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_local-common.sh"

ACR_NAME="${ACR_NAME:-metalclusterregistry}"
ACR_LOGIN_SERVER="${ACR_LOGIN_SERVER:-metalclusterregistry.azurecr.io}"
ACR_IMAGE="${ACR_IMAGE:-baremetalweb}"
PLATFORM="${PLATFORM:-linux-arm64}"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/arm64}"
BUILD_CONTAINER="${BUILD_CONTAINER:-1}"
PUSH_IMAGE="${PUSH_IMAGE:-0}"
JIT_OUT="${JIT_OUT:-${REPO_ROOT}/artifacts/publish-jit}"
AOT_OUT="${AOT_OUT:-${REPO_ROOT}/artifacts/publish-aot-linux-arm64}"

usage() {
    cat <<'EOF'
Usage: ./infra/local-ci2.sh

Runs the local equivalent of CI2:
  - compute version metadata
  - JIT publish (AnyCPU)
  - AOT publish (linux-arm64 by default)
  - optional Docker build / push using Dockerfile.prebuilt

Environment:
  VERSION=1.20260312.149      Exact version without arch suffix
  BUILD_NUMBER=149            Used when VERSION is omitted
  PLATFORM=linux-arm64
  BUILD_CONTAINER=0           Skip Docker image build
  PUSH_IMAGE=1                Push to ACR instead of local --load
  ACR_NAME=metalclusterregistry
  ACR_LOGIN_SERVER=metalclusterregistry.azurecr.io
  ACR_IMAGE=baremetalweb
EOF
}

if [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

require_cmd dotnet

VERSION_VALUE="$(compute_local_version)"
INFO_VERSION="$(derive_info_version "${VERSION_VALUE}")"
ASSEMBLY_VERSION="$(derive_assembly_version "${VERSION_VALUE}")"
IMAGE_TAG="${IMAGE_TAG:-${VERSION_VALUE}-${PLATFORM}}"
FULL_IMAGE="${ACR_LOGIN_SERVER}/${ACR_IMAGE}:${IMAGE_TAG}"

ensure_dir "${JIT_OUT}"
ensure_dir "${AOT_OUT}"
rm -rf "${JIT_OUT:?}/"* "${AOT_OUT:?}/"*

green "== Local CI2 =="
printf 'Version:        %s\n' "${VERSION_VALUE}"
printf 'InfoVersion:    %s\n' "${INFO_VERSION}"
printf 'AssemblyVersion:%s\n' "${ASSEMBLY_VERSION}"
printf 'Image:          %s\n\n' "${FULL_IMAGE}"

dotnet publish "${REPO_ROOT}/BareMetalWeb.Host/BareMetalWeb.Host.csproj" \
    --configuration Release \
    --output "${JIT_OUT}" \
    -p:AssemblyVersion="${ASSEMBLY_VERSION}" \
    -p:FileVersion="${ASSEMBLY_VERSION}" \
    -p:InformationalVersion="${INFO_VERSION}"

dotnet publish "${REPO_ROOT}/BareMetalWeb.Host/BareMetalWeb.Host.csproj" \
    --configuration Release \
    --runtime "${PLATFORM}" \
    --self-contained \
    --output "${AOT_OUT}" \
    -p:AssemblyVersion="${ASSEMBLY_VERSION}" \
    -p:FileVersion="${ASSEMBLY_VERSION}" \
    -p:InformationalVersion="${INFO_VERSION}"

if [[ "${BUILD_CONTAINER}" == "1" ]]; then
    require_cmd docker
    if ! docker buildx inspect >/dev/null 2>&1; then
        docker buildx create --use >/dev/null
    fi

    if [[ "${PUSH_IMAGE}" == "1" ]]; then
        ensure_azure_login
        az acr login --name "${ACR_NAME}" >/dev/null
        docker buildx build \
            --platform "${DOCKER_PLATFORM}" \
            --build-arg PUBLISH_DIR=./artifacts/publish-aot-linux-arm64 \
            --file "${REPO_ROOT}/Dockerfile.prebuilt" \
            --tag "${FULL_IMAGE}" \
            --push \
            "${REPO_ROOT}"
    else
        docker buildx build \
            --platform "${DOCKER_PLATFORM}" \
            --build-arg PUBLISH_DIR=./artifacts/publish-aot-linux-arm64 \
            --file "${REPO_ROOT}/Dockerfile.prebuilt" \
            --tag "${FULL_IMAGE}" \
            --load \
            "${REPO_ROOT}"
    fi
fi

green "Local CI2 complete."
printf 'JIT publish: %s\n' "${JIT_OUT}"
printf 'AOT publish: %s\n' "${AOT_OUT}"
printf 'Image tag:   %s\n' "${IMAGE_TAG}"
