#!/bin/bash
#
# BMW Guard — forbidden API scanner for production code.
# Runs as a CI gate to enforce build-enforced constraints.
#
# Allowed exceptions:
#   - Test projects (*.Tests/) are excluded from all checks
#   - Build artifacts (obj/, bin/) are excluded
#   - DataScaffold.BuildEntityMetadata<T>() and MetadataExtractor use
#     startup-time reflection (documented, AOT-annotated)
#   - Utf8JsonWriter, JsonDocument, JsonElement are allowed (low-level, AOT-safe)
#   - JsonSerializer.Serialize/Deserialize are forbidden

set -e

echo "🔍 BMW Guard: scanning for forbidden APIs in production code..."

FAIL=0

# Scan production .cs files only (exclude test projects and build output)
check() {
  PATTERN="$1"
  MESSAGE="$2"

  if grep -r --include="*.cs" -n "$PATTERN" . \
       --exclude-dir="obj" \
       --exclude-dir="bin" \
       --exclude-dir="BareMetalWeb.Core.Tests" \
       --exclude-dir="BareMetalWeb.Data.Tests" \
       --exclude-dir="BareMetalWeb.Host.Tests" \
       --exclude-dir="BareMetalWeb.Rendering.Tests" \
       --exclude-dir="BareMetalWeb.Runtime.Tests" \
       --exclude-dir="BareMetalWeb.Intelligence.Tests" \
       --exclude-dir="BareMetalWeb.API.Tests" \
       > /tmp/grep_result.txt 2>/dev/null; then
    echo ""
    echo "❌ $MESSAGE"
    cat /tmp/grep_result.txt
    FAIL=1
  fi
}

# Check with additional exclusion for known startup-time reflection files
check_with_exclude() {
  PATTERN="$1"
  MESSAGE="$2"
  EXCLUDE_PATTERN="$3"

  if grep -r --include="*.cs" -n "$PATTERN" . \
       --exclude-dir="obj" \
       --exclude-dir="bin" \
       --exclude-dir="BareMetalWeb.Core.Tests" \
       --exclude-dir="BareMetalWeb.Data.Tests" \
       --exclude-dir="BareMetalWeb.Host.Tests" \
       --exclude-dir="BareMetalWeb.Rendering.Tests" \
       --exclude-dir="BareMetalWeb.Runtime.Tests" \
       --exclude-dir="BareMetalWeb.Intelligence.Tests" \
       --exclude-dir="BareMetalWeb.API.Tests" \
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

# Reflection-based serialization (always forbidden)
check "JsonSerializer\.Serialize" "JsonSerializer.Serialize usage detected (use Utf8JsonWriter)"
check "JsonSerializer\.Deserialize" "JsonSerializer.Deserialize usage detected (use JsonDocument)"

# dynamic keyword in actual code (exclude attributes and comments)
check_with_exclude "dynamic " "dynamic keyword detected" "DynamicallyAccessedMembers\|RequiresDynamicCode\|//\|///\|DynamicDependency"

# Runtime type inspection on hot paths — allowed only in DataScaffold and MetadataExtractor (startup)
check_with_exclude "\.GetType()" "Runtime GetType() detected" "DataScaffold\.cs\|MetadataExtractor\.cs\|//\|///"

# ═══════════════════════════════════════════════════════════════
# ⚠️  WARNINGS — flagged but allowed with justification
# ═══════════════════════════════════════════════════════════════

echo ""
echo "⚠️  Checking for items that require justification..."

# Reflection usage — allowed only in DataScaffold.BuildEntityMetadata and MetadataExtractor
REFL_COUNT=$(grep -r --include="*.cs" -c "using System\.Reflection" . \
  --exclude-dir="obj" --exclude-dir="bin" \
  --exclude-dir="BareMetalWeb.Core.Tests" \
  --exclude-dir="BareMetalWeb.Data.Tests" \
  --exclude-dir="BareMetalWeb.Host.Tests" \
  --exclude-dir="BareMetalWeb.Rendering.Tests" \
  --exclude-dir="BareMetalWeb.Runtime.Tests" \
  --exclude-dir="BareMetalWeb.Intelligence.Tests" \
  --exclude-dir="BareMetalWeb.API.Tests" \
  2>/dev/null | awk -F: '{s+=$2} END {print s+0}')

if [ "$REFL_COUNT" -gt 2 ]; then
  echo "❌ System.Reflection used in $REFL_COUNT production files (max 2: DataScaffold.cs, MetadataExtractor.cs)"
  grep -r --include="*.cs" -l "using System\.Reflection" . \
    --exclude-dir="obj" --exclude-dir="bin" \
    --exclude-dir="BareMetalWeb.Core.Tests" \
    --exclude-dir="BareMetalWeb.Data.Tests" \
    --exclude-dir="BareMetalWeb.Host.Tests" \
    --exclude-dir="BareMetalWeb.Rendering.Tests" \
    --exclude-dir="BareMetalWeb.Runtime.Tests" \
    --exclude-dir="BareMetalWeb.Intelligence.Tests" \
    --exclude-dir="BareMetalWeb.API.Tests" \
    2>/dev/null
  FAIL=1
else
  echo "  ✓ System.Reflection: $REFL_COUNT file(s) (allowed: DataScaffold, MetadataExtractor)"
fi

# ═══════════════════════════════════════════════════════════════
# 🧾 Result
# ═══════════════════════════════════════════════════════════════

if [ $FAIL -eq 1 ]; then
  echo ""
  echo "🚫 BMW Guard FAILED"
  exit 1
else
  echo ""
  echo "✅ BMW Guard passed"
fi
