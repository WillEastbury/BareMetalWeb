#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# guardrails.sh — Scan BareMetalWeb for banned patterns in CHANGED files
#
# Detects in files changed vs the base branch (or HEAD~1):
#   1. Reflection APIs (System.Reflection, Activator.CreateInstance, etc.)
#   2. JSON serializers (JsonSerializer, Newtonsoft, System.Text.Json imports)
#   3. Unauthorised NuGet packages (in ALL .csproj files, not just changed)
#
# Usage:
#   ./guardrails.sh              # scan changes vs origin/main
#   ./guardrails.sh HEAD~3       # scan last 3 commits
#   ./guardrails.sh --all        # scan entire codebase (baseline audit)
#
# Exit code 0 = clean, 1 = violations found
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

VIOLATIONS=0
RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
RST='\033[0m'

banner() { printf "\n${YEL}══ %s${RST}\n" "$1"; }
fail()   { printf "${RED}  VIOLATION: %s${RST}\n" "$1"; VIOLATIONS=$((VIOLATIONS + 1)); }
ok()     { printf "${GRN}  ✔ clean${RST}\n"; }

# ── Determine which files to scan ─────────────────────────────────────────────
SCAN_MODE="diff"
BASE_REF="origin/main"

if [ "${1:-}" = "--all" ]; then
    SCAN_MODE="all"
elif [ -n "${1:-}" ]; then
    BASE_REF="$1"
fi

get_changed_cs_files() {
    if [ "$SCAN_MODE" = "all" ]; then
        find "$REPO_ROOT" -name '*.cs' \
            -not -path '*/obj/*' -not -path '*/bin/*' \
            -not -path '*/node_modules/*' \
            -not -path '*Tests*' -not -path '*Benchmarks*' \
            -not -path '*PerformanceTests*'
    else
        # Files changed vs base ref, filtered to production .cs files
        git diff --name-only --diff-filter=ACMR "$BASE_REF" -- '*.cs' 2>/dev/null | \
            grep -v '/obj/' | grep -v '/bin/' | \
            grep -v 'Tests/' | grep -v 'Benchmarks/' | \
            grep -v 'PerformanceTests/' | \
            while read -r f; do [ -f "$REPO_ROOT/$f" ] && echo "$REPO_ROOT/$f"; done
    fi
}

CHANGED_FILES=()
while IFS= read -r f; do
    CHANGED_FILES+=("$f")
done < <(get_changed_cs_files)

if [ ${#CHANGED_FILES[@]} -eq 0 ] && [ "$SCAN_MODE" != "all" ]; then
    printf "${GRN}No production .cs files changed — guardrails pass${RST}\n"
    # Still check NuGet packages (always)
else
    printf "Scanning %d file(s) [mode=%s]\n" "${#CHANGED_FILES[@]}" "$SCAN_MODE"
fi

# ── Allowed NuGet packages ────────────────────────────────────────────────────
ALLOWED_PROD=(
    "Microsoft.Extensions.AI.Abstractions"
    "Microsoft.Extensions.AI"
    "System.IO.Hashing"
)
ALLOWED_TEST=(
    "Microsoft.NET.Test.Sdk"
    "xunit"
    "xunit.runner.visualstudio"
    "xunit.runner.console"
    "coverlet.collector"
    "BenchmarkDotNet"
)
declare -A ALLOWED_PKG
for p in "${ALLOWED_PROD[@]}" "${ALLOWED_TEST[@]}"; do ALLOWED_PKG["$p"]=1; done

# ── 1. Reflection ─────────────────────────────────────────────────────────────
banner "1. Reflection APIs"

REFLECTION_PATTERNS='(typeof\([^)]+\)\.(GetMethod|GetProperty|GetField|GetMember|GetConstructor)|Type\.GetType\s*\(|Activator\.CreateInstance|Assembly\.Load|Assembly\.GetTypes|BindingFlags\.|\.GetCustomAttribute|\.GetProperties\s*\(|\.GetMethods\s*\(|\.GetFields\s*\(|\.GetMembers\s*\(|\.GetConstructors\s*\(|System\.Reflection\.Emit|DynamicMethod|ILGenerator|Expression\.Lambda|Expression\.Property|Expression\.Call)'

REFLECTION_FOUND=0
if [ ${#CHANGED_FILES[@]} -gt 0 ]; then
    while IFS= read -r match; do
        file=$(echo "$match" | cut -d: -f1)
        relfile="${file#$REPO_ROOT/}"
        lineno=$(echo "$match" | cut -d: -f2)
        content=$(echo "$match" | cut -d: -f3-)
        fail "$relfile:$lineno — $content"
        REFLECTION_FOUND=1
    done < <(grep -nE "$REFLECTION_PATTERNS" "${CHANGED_FILES[@]}" 2>/dev/null || true)
fi
[ "$REFLECTION_FOUND" -eq 0 ] && ok

# ── 2. JSON serializers ───────────────────────────────────────────────────────
banner "2. JSON serializers"

# Ban: importing System.Text.Json, using JsonSerializer.Serialize/Deserialize,
# any Newtonsoft usage. Allow: JsonElement (used for HTTP body parsing in DataScaffold)
JSON_PATTERNS='(using\s+System\.Text\.Json\.Serialization|using\s+Newtonsoft|JsonSerializer\.Serialize|JsonSerializer\.Deserialize|JsonConvert\.|JsonSerializerOptions|JsonSourceGenerationOptions)'

JSON_FOUND=0
if [ ${#CHANGED_FILES[@]} -gt 0 ]; then
    while IFS= read -r match; do
        file=$(echo "$match" | cut -d: -f1)
        relfile="${file#$REPO_ROOT/}"
        lineno=$(echo "$match" | cut -d: -f2)
        content=$(echo "$match" | cut -d: -f3-)
        fail "$relfile:$lineno — $content"
        JSON_FOUND=1
    done < <(grep -nE "$JSON_PATTERNS" "${CHANGED_FILES[@]}" 2>/dev/null || true)
fi
[ "$JSON_FOUND" -eq 0 ] && ok

# ── 3. Banned using directives ────────────────────────────────────────────────
banner "3. Banned using directives"

# System.Reflection is banned in new code — metadata should come from EntitySchema
USING_PATTERNS='(using\s+System\.Reflection;|using\s+System\.Reflection\.Emit;|using\s+System\.Linq\.Expressions;|using\s+Newtonsoft|using\s+System\.Runtime\.Serialization;|using\s+System\.Xml\.Serialization;)'

USING_FOUND=0
if [ ${#CHANGED_FILES[@]} -gt 0 ]; then
    while IFS= read -r match; do
        file=$(echo "$match" | cut -d: -f1)
        relfile="${file#$REPO_ROOT/}"
        lineno=$(echo "$match" | cut -d: -f2)
        content=$(echo "$match" | cut -d: -f3-)
        fail "$relfile:$lineno — $content"
        USING_FOUND=1
    done < <(grep -nE "$USING_PATTERNS" "${CHANGED_FILES[@]}" 2>/dev/null || true)
fi
[ "$USING_FOUND" -eq 0 ] && ok

# ── 4. Unauthorised NuGet packages (always scans ALL .csproj) ────────────────
banner "4. NuGet packages"

PKG_FOUND=0
while IFS= read -r csproj; do
    relproj="${csproj#$REPO_ROOT/}"
    while IFS= read -r pkgline; do
        pkg=$(echo "$pkgline" | grep -oP 'Include="\K[^"]*' || true)
        [ -z "$pkg" ] && continue
        if [ -z "${ALLOWED_PKG[$pkg]+x}" ]; then
            fail "$relproj — unauthorised package: $pkg"
            PKG_FOUND=1
        fi
    done < <(grep -i 'PackageReference' "$csproj" 2>/dev/null || true)
done < <(find "$REPO_ROOT" -name '*.csproj' -not -path '*/node_modules/*' -not -path '*/bin/*' -not -path '*/obj/*')

[ "$PKG_FOUND" -eq 0 ] && ok

# ── Summary ───────────────────────────────────────────────────────────────────
banner "SUMMARY"
if [ "$VIOLATIONS" -gt 0 ]; then
    printf "${RED}  ✘ %d violation(s) found${RST}\n" "$VIOLATIONS"
    printf "\n  Banned in production code:\n"
    printf "    • System.Reflection (use EntitySchema metadata instead)\n"
    printf "    • Activator.CreateInstance (use typed factories)\n"
    printf "    • JsonSerializer / Newtonsoft (use binary wire format)\n"
    printf "    • Expression.Lambda (use ordinal closures)\n"
    printf "    • Any NuGet package not in the allow-list\n\n"
    exit 1
else
    printf "${GRN}  ✔ All guardrails pass — zero violations${RST}\n\n"
    exit 0
fi
