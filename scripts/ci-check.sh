#!/usr/bin/env bash
# CI Check Script
# Run this locally to verify all CI checks will pass

set -Eeuo pipefail

echo "=========================================="
echo "Running CI Pre-Flight Checks"
echo "=========================================="
echo ""

# Track overall status
OVERALL_STATUS=0

# Function to run a check and report results
run_check() {
    local name="$1"
    local command="$2"
    
    echo "→ Running: $name"
    if eval "$command" 2>&1; then
        echo "  ✓ PASSED"
        return 0
    else
        echo "  ✗ FAILED"
        OVERALL_STATUS=1
        return 1
    fi
}

# Go checks
echo "=== Go Verification ==="
run_check "gofmt" "test -z \"\$(gofmt -l .)\" || (echo '  Files need formatting:'; gofmt -l .; exit 1)"
run_check "go vet" "go vet ./..."
run_check "go test" "go test ./..."
run_check "go test -race" "go test -race ./..."
run_check "go build" "go build ./cmd/solid-sidecar"

echo ""
echo "=== Vulnerability Check ==="
run_check "govulncheck" "govulncheck ./... 2>&1 || true"  # Don't fail on vuln check warnings

echo ""
echo "=== Rust Verification ==="
if [ -d "rust" ]; then
    cd rust
    run_check "cargo fmt" "cargo fmt --all --check"
    run_check "cargo test" "cargo test --workspace --all-targets"
    run_check "cargo clippy" "cargo clippy --workspace --lib -- -D warnings"
    cd ..
fi

echo ""
echo "=========================================="
if [ $OVERALL_STATUS -eq 0 ]; then
    echo "✓ All CI checks PASSED"
    echo "=========================================="
    exit 0
else
    echo "✗ Some CI checks FAILED"
    echo "=========================================="
    exit 1
fi
