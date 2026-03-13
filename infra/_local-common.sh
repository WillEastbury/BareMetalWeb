#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }

die() {
    red "ERROR: $*"
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

ensure_azure_login() {
    require_cmd az
    az account show >/dev/null 2>&1 || die "Azure CLI is not logged in. Run 'az login' first."
}

compute_local_version() {
    if [[ -n "${VERSION:-}" ]]; then
        printf '%s\n' "${VERSION}"
        return
    fi

    local major="${MAJOR_VERSION:-1}"
    local date_part
    local build_part
    date_part="$(date -u +%Y%m%d)"
    build_part="${BUILD_NUMBER:-$(date -u +%H%M%S)}"
    printf '%s\n' "${major}.${date_part}.${build_part}"
}

derive_info_version() {
    local version="$1"
    local sha
    sha="$(git -C "${REPO_ROOT}" rev-parse --short=7 HEAD 2>/dev/null || echo local)"
    printf '%s+%s\n' "${version}" "${sha}"
}

derive_assembly_version() {
    local version="$1"
    local major="${version%%.*}"
    local build="${version##*.}"
    printf '%s.0.0.%s\n' "${major}" "${build}"
}

strip_arch_suffix() {
    local tag="$1"
    tag="${tag%-linux-*}"
    tag="${tag%-windows-*}"
    printf '%s\n' "${tag}"
}

verify_acr_tag() {
    local acr_name="$1"
    local repository="$2"
    local tag="$3"

    ensure_azure_login

    az acr repository show-tags \
        --name "${acr_name}" \
        --repository "${repository}" \
        --query "[?@=='${tag}']" \
        -o tsv | grep -qx "${tag}" \
        || die "Tag '${tag}' not found in ${acr_name}/${repository}"
}

ensure_dir() {
    mkdir -p "$1"
}

zip_publish_dir() {
    local source_dir="$1"
    local zip_path="$2"
    require_cmd zip
    rm -f "${zip_path}"
    (
        cd "${source_dir}"
        zip -qr "${zip_path}" .
    )
}

json_field() {
    local json="$1"
    local expr="$2"
    jq -r "${expr}" <<< "${json}"
}
