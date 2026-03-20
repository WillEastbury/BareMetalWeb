#!/bin/bash

set -e

echo "🔍 BMW Guard: scanning for forbidden APIs..."

FAIL=0

check() {
  PATTERN="$1"
  MESSAGE="$2"

  if grep -r --include="*.cs" -n "$PATTERN" . > /tmp/grep_result.txt; then
    echo ""
    echo "❌ $MESSAGE"
    cat /tmp/grep_result.txt
    FAIL=1
  fi
}

# 🚫 Forbidden namespaces
check "using System.Reflection" "Reflection usage detected"
check "System.Text.Json" "JSON usage detected"
check "System.Text.Json.Serialization" "JSON serialization detected"

# 🚫 Forbidden patterns
check "dynamic " "dynamic keyword detected"
check "Activator.CreateInstance" "Activator usage detected"
check "JsonSerializer" "JsonSerializer usage detected"
check "GetType(" "Runtime type inspection detected"
check "typeof(" "Type reflection detected"

# 🚫 NuGet creep
if grep -r "<PackageReference" . > /tmp/grep_pkg.txt; then
  echo ""
  echo "⚠️ PackageReference detected:"
  cat /tmp/grep_pkg.txt
  # Not failing by default — change to FAIL=1 if you want hard stop
fi

# 🧾 Result
if [ $FAIL -eq 1 ]; then
  echo ""
  echo "🚫 BMW Guard FAILED"
  exit 1
else
  echo "✅ BMW Guard passed"
fi
