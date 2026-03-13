#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_local-common.sh"

CONFIGURATION="${CONFIGURATION:-Debug}"
RESULTS_ROOT="${RESULTS_ROOT:-${REPO_ROOT}/TestResults/local-ci}"
RUN_JEST="${RUN_JEST:-1}"
STRICT_OPTIONAL_TESTS="${STRICT_OPTIONAL_TESTS:-0}"

usage() {
    cat <<'EOF'
Usage: ./infra/local-ci.sh

Runs the local equivalent of CI1:
  - dotnet restore
  - dotnet build (Debug)
  - test shards (sequentially)
  - Jest tests in tests/js-unit

Environment:
  CONFIGURATION=Debug|Release
  RUN_JEST=0                Skip Jest
  STRICT_OPTIONAL_TESTS=1   Fail on Core/API shard failures
EOF
}

if [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

require_cmd dotnet
ensure_dir "${RESULTS_ROOT}"

green "== Local CI (CI1 equivalent) =="
printf 'Configuration: %s\n' "${CONFIGURATION}"
printf 'Results:       %s\n\n' "${RESULTS_ROOT}"

dotnet restore "${REPO_ROOT}/BareMetalWeb.sln"
dotnet build "${REPO_ROOT}/BareMetalWeb.sln" --configuration "${CONFIGURATION}" --no-restore

failures=()

run_dotnet_tests() {
    local name="$1"
    local project="$2"
    local filter="$3"
    local allow_failure="${4:-0}"
    local output_dir="${RESULTS_ROOT}/${name}"

    ensure_dir "${output_dir}"

    printf '\n-- %s --\n' "${name}"
    set +e
    dotnet test "${REPO_ROOT}/${project}" \
        --configuration "${CONFIGURATION}" \
        --no-build \
        --verbosity minimal \
        --blame-hang-timeout 60s \
        ${filter:+--filter "${filter}"} \
        --results-directory "${output_dir}" \
        --logger "trx"
    local rc=$?
    set -e

    if [[ ${rc} -ne 0 ]]; then
        if [[ "${allow_failure}" == "1" && "${STRICT_OPTIONAL_TESTS}" != "1" ]]; then
            yellow "Warning: ${name} failed, but continuing to mirror current workflow behavior."
        else
            failures+=("${name}")
        fi
    fi
}

run_dotnet_tests "data"      "BareMetalWeb.Data.Tests/BareMetalWeb.Data.Tests.csproj"           "FullyQualifiedName!~PerformanceTests&Category!=Integration"
run_dotnet_tests "host"      "BareMetalWeb.Host.Tests/BareMetalWeb.Host.Tests.csproj"           "FullyQualifiedName!~PerformanceTests&Category!=Integration"
run_dotnet_tests "rendering" "BareMetalWeb.Rendering.Tests/BareMetalWeb.Rendering.Tests.csproj" "FullyQualifiedName!~PerformanceTests&Category!=Integration"
run_dotnet_tests "runtime"   "BareMetalWeb.Runtime.Tests/BareMetalWeb.Runtime.Tests.csproj"     "FullyQualifiedName!~PerformanceTests&Category!=Integration"
run_dotnet_tests "core"      "BareMetalWeb.Core.Tests/BareMetalWeb.Core.Tests.csproj"           "" 1
run_dotnet_tests "api"       "BareMetalWeb.API.Tests/BareMetalWeb.API.Tests.csproj"             "" 1

if [[ "${RUN_JEST}" == "1" ]]; then
    require_cmd npm
    printf '\n-- jest --\n'
    pushd "${REPO_ROOT}/tests/js-unit" >/dev/null
    if [[ -f package-lock.json ]]; then
        npm ci
    else
        npm install
    fi
    set +e
    npm test
    jest_rc=$?
    set -e
    popd >/dev/null

    if [[ ${jest_rc} -ne 0 ]]; then
        failures+=("jest")
    fi
fi

if [[ ${#failures[@]} -gt 0 ]]; then
    die "Local CI failed: ${failures[*]}"
fi

green "Local CI passed."
