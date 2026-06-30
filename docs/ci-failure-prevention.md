# CI Failure Prevention Guide

This document outlines the CI pipeline and how to prevent failures in the solid-sidecar project.

## CI Pipeline Overview

The project has two main CI workflows:

### 1. Main CI Workflow (`.github/workflows/ci.yml`)

Runs on:
- Pushes to `main` branch
- Pull requests
- Manual workflow dispatch

Jobs:
1. **Go build and test** - Runs `scripts/verify.sh go`
2. **Rust policy kernel** - Runs `scripts/verify.sh rust`
3. **Vulnerability check** - Runs `govulncheck`

### 2. E2E Workflow (`.github/workflows/e2e.yml`)

Runs on:
- Pushes to `main` branch (with path filters)
- Pull requests (with path filters)
- Manual workflow dispatch

Runs Docker-backed CSS-through-sidecar end-to-end tests.

## What `scripts/verify.sh go` Checks

The Go verification script (`scripts/verify.sh go`) runs:

1. **`gofmt -l .`** - Checks Go formatting
   - **Failure**: Lists files that need formatting
   - **Fix**: Run `gofmt -w .` or `gofmt -w <file>`

2. **`go vet ./...`** - Checks for potential issues in Go code
   - **Failure**: Reports potential bugs, suspicious constructs
   - **Fix**: Address the issues reported by `go vet`

3. **`go test ./...`** - Runs all Go tests
   - **Failure**: Test failures, panics, or timeouts
   - **Fix**: Fix failing tests, ensure all tests pass

4. **`go test -race ./...`** - Runs tests with race detector
   - **Failure**: Data race conditions detected
   - **Fix**: Use proper synchronization (mutexes, channels)

5. **`go build ./cmd/solid-sidecar`** - Builds the main binary
   - **Failure**: Compilation errors
   - **Fix**: Fix syntax errors, type mismatches, missing dependencies

## What `scripts/verify.sh rust` Checks

The Rust verification script runs:

1. **`cargo fmt --all --check`** - Checks Rust formatting
   - **Failure**: Files need formatting
   - **Fix**: Run `cargo fmt --all`

2. **`cargo test --workspace --all-targets`** - Runs all Rust tests
   - **Failure**: Test failures
   - **Fix**: Fix failing tests

3. **`cargo clippy --workspace --lib -- -D warnings`** - Linting with warnings as errors
   - **Failure**: Linting warnings
   - **Fix**: Address clippy warnings

## Vulnerability Check (`govulncheck`)

Scans Go dependencies for known vulnerabilities.

- **Failure**: Known vulnerabilities found in dependencies
- **Fix**: Update vulnerable dependencies in `go.mod`

## Common CI Failure Causes and Solutions

### 1. Formatting Issues

**Symptom**: CI fails with "Files need gofmt" or "Files need formatting"

**Solution**:
```bash
# Check which files need formatting
gofmt -l .

# Format all files
gofmt -w .

# Or format specific files
gofmt -w internal/authz/policy_http_loader.go
```

**Prevention**:
- Install a Go formatter plugin for your editor
- Run `gofmt -w .` before committing
- Use the pre-push hook (installed locally)

### 2. Compilation Errors

**Symptom**: CI fails with compilation errors

**Common Causes**:
- Type mismatches
- Missing imports
- Undefined variables/functions
- Syntax errors

**Solution**:
```bash
# Try to build locally first
go build ./cmd/solid-sidecar

# Fix any errors reported
```

**Prevention**:
- Always run `go build` before pushing
- Use IDE with Go language server

### 3. Test Failures

**Symptom**: CI fails with test failures

**Solution**:
```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./internal/authz/...

# Run specific test
go test -v -run TestSpecificFunction ./internal/authz

# Run with race detector
go test -race ./...
```

**Prevention**:
- Run tests locally before pushing
- Add tests for new functionality
- Ensure tests are deterministic

### 4. Race Conditions

**Symptom**: CI fails with "DATA RACE" in race detector tests

**Common Causes**:
- Concurrent access to shared variables without synchronization
- Not using mutexes for shared state
- Improper use of channels

**Solution**:
```bash
# Run with race detector
go test -race ./...

# Identify the race and fix with proper synchronization
```

**Prevention**:
- Use `sync.Mutex` or `sync.RWMutex` for shared state
- Use channels for communication between goroutines
- Avoid global variables

### 5. Vet Warnings

**Symptom**: CI fails with `go vet` warnings

**Common Causes**:
- Unused variables
- Ineffective assignments
- Suspicious function calls

**Solution**:
```bash
# Run vet locally
go vet ./...

# Fix the issues reported
```

### 6. Rust Issues

**Symptom**: CI fails in Rust job

**Solution**:
```bash
cd rust
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --lib -- -D warnings
```

## Local Verification

### Using `scripts/verify.sh`

Run the same checks that CI runs:

```bash
# Go checks
bash scripts/verify.sh go

# Rust checks
bash scripts/verify.sh rust

# All checks
bash scripts/verify.sh all
```

### Using `scripts/ci-check.sh`

A more user-friendly script that reports each check:

```bash
bash scripts/ci-check.sh
```

### Using Pre-Push Hook

A local Git pre-push hook has been set up that automatically runs verification before pushing:

```bash
# The hook is in .git/hooks/pre-push
# It runs the same checks as CI
# If any check fails, the push is aborted
```

To install the pre-push hook (if not already installed):
```bash
cp scripts/pre-push-hook.sh .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

## Best Practices to Prevent CI Failures

1. **Before Committing**:
   - Run `gofmt -w .` to format code
   - Run `go vet ./...` to check for issues
   - Run `go test ./...` to ensure tests pass

2. **Before Pushing**:
   - Run `bash scripts/verify.sh go`
   - Run `bash scripts/verify.sh rust` (if you modified Rust code)
   - Or run `bash scripts/ci-check.sh` for all checks

3. **For New Code**:
   - Write tests for new functionality
   - Ensure tests pass with `-race` flag
   - Follow existing code style and patterns

4. **For Dependencies**:
   - Keep dependencies updated
   - Check for vulnerabilities with `govulncheck ./...`

5. **Code Review**:
   - Verify CI checks pass before approving PRs
   - Look for potential race conditions
   - Ensure proper error handling

## Debugging CI Failures

### 1. Check CI Logs

GitHub Actions provides detailed logs for each workflow run. Look for:
- Which job failed
- Which step failed
- The error message

### 2. Reproduce Locally

Most CI failures can be reproduced locally:

```bash
# For Go failures
bash scripts/verify.sh go

# For Rust failures  
bash scripts/verify.sh rust

# For full CI simulation
bash scripts/verify.sh all
```

### 3. Check Artifacts

CI uploads artifacts for failed jobs:
- `go-verify-log` - Log from Go verification
- `rust-verify-log` - Log from Rust verification
- `e2e.log` - Log from e2e tests

Download these artifacts from the GitHub Actions UI to see detailed output.

## CI Configuration

The CI workflow files are in `.github/workflows/`:

- `ci.yml` - Main CI pipeline
- `e2e.yml` - End-to-end tests

These files use standard GitHub Actions workflow syntax. Modifications should be tested by pushing to a branch and checking the CI results.

## Required Tools for Local Development

To run all CI checks locally, install:

1. **Go** (1.22.x or later)
2. **Rust** (stable toolchain with rustfmt, clippy)
3. **govulncheck** (for vulnerability scanning)

Installation:

```bash
# Go (via brew on macOS)
brew install go

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup component add rustfmt clippy

# govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
```

## Summary

To prevent CI failures:

1. ✅ Run `gofmt -w .` before committing
2. ✅ Run `go vet ./...` before committing
3. ✅ Run `go test ./...` and `go test -race ./...` before committing
4. ✅ Run `bash scripts/verify.sh go` before pushing
5. ✅ Use the pre-push hook
6. ✅ Check Rust code if modified
7. ✅ Review CI logs for failed builds

By following these practices, CI failures can be caught early and prevented from reaching the main branch.
