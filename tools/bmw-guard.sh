#!/bin/bash
#
# BMW Guard — forbidden API & dependency scanner for production code.
# Runs as a CI gate to enforce NativeAOT/trimming and architecture constraints.
#
# Hard failures (block merge):
#   - JsonSerializer.Serialize/Deserialize
#   - dynamic keyword
#   - Activator.CreateInstance
#   - Type.MakeGenericType / MethodInfo.MakeGenericMethod
#   - System.Reflection.Emit / ILGenerator / DynamicMethod
#   - Expression.Lambda / Expression.Compile
#   - Runtime GetType() outside startup-time metadata builders
#   - Unauthorised NuGet packages
#
# Counted checks (threshold-gated):
#   - System.Reflection usage count (max allowed: see threshold below)
#   - BindingFlags usage count
#
# Allowed exceptions:
#   - Test projects (*.Tests/) and benchmarks are excluded
#   - Build artifacts (obj/, bin/) are excluded
#   - DataScaffold / MetadataExtractor use startup-time reflection (documented)
#   - Utf8JsonWriter, JsonDocument, JsonElement are allowed (low-level, AOT-safe)

set -e

echo "🔍 BMW Guard: scanning for forbidden APIs in production code..."

FAIL=0

# ── Exclude directories ──────────────────────────────────────────────────────
EXCLUDE_DIRS=(
  --exclude-dir="obj"
  --exclude-dir="bin"
  --exclude-dir="node_modules"
  --exclude-dir="BareMetalWeb.Core.Tests"
  --exclude-dir="BareMetalWeb.Data.Tests"
  --exclude-dir="BareMetalWeb.Host.Tests"
  --exclude-dir="BareMetalWeb.Rendering.Tests"
  --exclude-dir="BareMetalWeb.Runtime.Tests"
  --exclude-dir="BareMetalWeb.Intelligence.Tests"
  --exclude-dir="BareMetalWeb.API.Tests"
  --exclude-dir="BareMetalWeb.IntegrationTests"
  --exclude-dir="BareMetalWeb.Benchmarks"
  --exclude-dir="BareMetalWeb.PerformanceTests"
)

check() {
  PATTERN="$1"
  MESSAGE="$2"

  if grep -r --include="*.cs" -n "$PATTERN" . "${EXCLUDE_DIRS[@]}" \
       > /tmp/grep_result.txt 2>/dev/null; then
    echo ""
    echo "❌ $MESSAGE"
    cat /tmp/grep_result.txt
    FAIL=1
  fi
}

check_with_exclude() {
  PATTERN="$1"
  MESSAGE="$2"
  EXCLUDE_PATTERN="$3"

  if grep -r --include="*.cs" -n "$PATTERN" . "${EXCLUDE_DIRS[@]}" \
       2>/dev/null | grep -v "$EXCLUDE_PATTERN" > /tmp/grep_result.txt 2>/dev/null; then
    if [ -s /tmp/grep_result.txt ]; then
      echo ""
      echo "❌ $MESSAGE"
      cat /tmp/grep_result.txt
      FAIL=1
    fi
  fi
}

# ═══════════════════════════════════════════════════════════════
# 🚫 HARD FAILURES — these must never appear in production code
# ═══════════════════════════════════════════════════════════════

# JSON serializer (always forbidden — use Utf8JsonWriter / BmwJsonWriter)
check "JsonSerializer\.Serialize" "JsonSerializer.Serialize detected (use Utf8JsonWriter)"
check "JsonSerializer\.Deserialize" "JsonSerializer.Deserialize detected (use JsonDocument)"
check "JsonConvert\." "Newtonsoft JsonConvert detected"
check "using Newtonsoft" "Newtonsoft using directive detected"

# dynamic keyword (exclude attributes and comments)
check_with_exclude "dynamic " "dynamic keyword detected" \
  "DynamicallyAccessedMembers\|RequiresDynamicCode\|//\|///\|DynamicDependency"

# Activator.CreateInstance (use typed factories or metadata-driven construction)
check_with_exclude "Activator\.CreateInstance" "Activator.CreateInstance detected" \
  "DataScaffold\.cs\|BinaryObjectSerializer\.cs\|//\|///"

# MakeGenericType / MakeGenericMethod (NativeAOT-incompatible)
check_with_exclude "MakeGenericType" "Type.MakeGenericType detected (NativeAOT incompatible)" \
  "DataScaffold\.cs\|//\|///"
check "MakeGenericMethod" "MethodInfo.MakeGenericMethod detected (NativeAOT incompatible)"

# Reflection.Emit (NativeAOT-incompatible)
check "System\.Reflection\.Emit" "System.Reflection.Emit detected"
check_with_exclude "ILGenerator" "ILGenerator detected" "//\|///"
check_with_exclude "DynamicMethod" "DynamicMethod detected" "//\|///"

# Expression tree compilation (NativeAOT-incompatible at runtime)
check_with_exclude "Expression\.Lambda" "Expression.Lambda detected (use ordinal closures)" \
  "DataScaffold\.cs\|//\|///"
check_with_exclude "\.Compile()" "Expression.Compile() detected" \
  "DataScaffold\.cs\|//\|///"

# Runtime type inspection on hot paths
check_with_exclude "\.GetType()" "Runtime GetType() detected" \
  "DataScaffold\.cs\|MetadataExtractor\.cs\|//\|///"

# ═══════════════════════════════════════════════════════════════
# 📦 NuGet PACKAGE AUDIT — unauthorised dependencies
# ═══════════════════════════════════════════════════════════════

echo ""
echo "📦 Checking NuGet packages..."

# Allowed production packages
ALLOWED_PROD="Microsoft.Extensions.AI.Abstractions|Microsoft.Extensions.AI|System.IO.Hashing"

# Allowed test/benchmark packages
ALLOWED_TEST="Microsoft.NET.Test.Sdk|xunit|xunit.runner.visualstudio|xunit.runner.console|coverlet.collector|BenchmarkDotNet"

ALLOWED_ALL="$ALLOWED_PROD|$ALLOWED_TEST"

PKG_FAIL=0
while IFS= read -r csproj; do
  while IFS= read -r line; do
    pkg=$(echo "$line" | grep -oP 'Include="\K[^"]*' || true)
    [ -z "$pkg" ] && continue
    if ! echo "$pkg" | grep -qE "^($ALLOWED_ALL)$"; then
      echo "❌ Unauthorised package: $pkg  (in $csproj)"
      PKG_FAIL=1
    fi
  done < <(grep -i 'PackageReference' "$csproj" 2>/dev/null || true)
done < <(find . -name '*.csproj' -not -path '*/obj/*' -not -path '*/bin/*' -not -path '*/node_modules/*')

if [ "$PKG_FAIL" -eq 1 ]; then
  FAIL=1
else
  echo "  ✓ All NuGet packages are on the allow-list"
fi

# ═══════════════════════════════════════════════════════════════
# 🔢 COUNTED CHECKS — threshold-gated
# ═══════════════════════════════════════════════════════════════

echo ""
echo "🔢 Threshold checks..."

# System.Reflection usage — max 2 files (DataScaffold.cs, MetadataExtractor.cs)
MAX_REFL_FILES=2
REFL_FILES=$(grep -rl --include="*.cs" "using System\.Reflection" . \
  "${EXCLUDE_DIRS[@]}" 2>/dev/null || true)
REFL_COUNT=$(echo "$REFL_FILES" | grep -c '.' 2>/dev/null || echo 0)

if [ "$REFL_COUNT" -gt "$MAX_REFL_FILES" ]; then
  echo "❌ System.Reflection used in $REFL_COUNT production files (max $MAX_REFL_FILES)"
  echo "$REFL_FILES"
  FAIL=1
else
  echo "  ✓ System.Reflection: $REFL_COUNT file(s) (max $MAX_REFL_FILES)"
fi

# BindingFlags usage — max 2 files
MAX_BF_FILES=2
BF_FILES=$(grep -rl --include="*.cs" "BindingFlags\." . \
  "${EXCLUDE_DIRS[@]}" 2>/dev/null || true)
BF_COUNT=$(echo "$BF_FILES" | grep -c '.' 2>/dev/null || echo 0)

if [ "$BF_COUNT" -gt "$MAX_BF_FILES" ]; then
  echo "❌ BindingFlags used in $BF_COUNT production files (max $MAX_BF_FILES)"
  echo "$BF_FILES"
  FAIL=1
else
  echo "  ✓ BindingFlags: $BF_COUNT file(s) (max $MAX_BF_FILES)"
fi

# ═══════════════════════════════════════════════════════════════
# 🧾 Result
# ═══════════════════════════════════════════════════════════════

if [ $FAIL -eq 1 ]; then
  echo ""
  echo "🚫 BMW Guard FAILED"
  echo ""
  echo "Banned in production code:"
  echo "  • JsonSerializer.Serialize/Deserialize → use Utf8JsonWriter / BmwJsonWriter"
  echo "  • Newtonsoft.Json → not allowed"
  echo "  • Activator.CreateInstance → use typed factory delegates"
  echo "  • MakeGenericType/MakeGenericMethod → use closed generics"
  echo "  • Reflection.Emit / ILGenerator / DynamicMethod → not allowed"
  echo "  • Expression.Lambda → use ordinal-based closures"
  echo "  • dynamic keyword → use static dispatch"
  echo "  • Unauthorised NuGet packages → add to allow-list if justified"
  exit 1
else
  echo ""
  echo "✅ BMW Guard passed"
fi
