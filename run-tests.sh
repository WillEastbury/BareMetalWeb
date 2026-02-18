#!/bin/bash
# Helper script to run tests with clean, minimal output
# Only shows test failures and errors, suppresses build noise

SKIP_BUILD=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-build)
            SKIP_BUILD=true
            shift
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

# Determine build flag
if [ "$SKIP_BUILD" = true ]; then
    BUILD_FLAG="--no-build"
    echo "Running tests (no build) with quiet output..."
else
    BUILD_FLAG=""
    echo "Running tests with quiet output..."
fi

# Run tests
if [ -z "$TARGET" ]; then
    dotnet test BareMetalWeb.sln -v quiet $BUILD_FLAG
else
    echo "Target: $TARGET"
    dotnet test "$TARGET" -v quiet $BUILD_FLAG
fi

