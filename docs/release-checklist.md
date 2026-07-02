# Release Checklist

This document provides the release checklist for the Solid runtime as required by Phase 17.

## Pre-Release Checklist

### Code Quality

- [x] All Go code passes `go vet`
- [x] All Go code passes `gofmt`
- [x] All Go tests pass
- [x] All Go race tests pass
- [x] All Rust code passes `cargo test`
- [x] All Rust code passes `cargo clippy -- -D warnings`
- [x] All Rust code passes `cargo fmt --all --check`
- [x] No `TODO` comments remain (or documented as accepted)
- [x] No `FIXME` comments remain
- [x] No `XXX` comments remain

### Security

- [x] No hardcoded secrets or credentials
- [x] All sensitive operations use constant-time comparisons
- [x] All user inputs are validated
- [x] All memory allocations are bounded
- [x] No sensitive data is logged
- [x] All error messages are privacy-safe
- [x] Rate limiting is configured for all endpoints
- [x] Circuit breakers are configured for critical paths

### Testing

- [x] Unit tests pass for all packages
- [x] Integration tests pass
- [x] Race condition tests pass
- [x] Fuzz tests run without crashes (if applicable)
- [x] E2E tests pass (if applicable)
- [x] Shadow mode tests pass
- [x] CSS compatibility tests pass

### Documentation

- [x] All new features are documented
- [x] All breaking changes are documented
- [x] Configuration schema is documented
- [x] Threat model is updated
- [x] Privacy review is updated
- [x] Rust panic/abort policy is documented
- [x] API documentation is updated

### Configuration

- [x] Default configuration is safe for production
- [x] All configurations have safe defaults
- [x] All configurations are validated on startup
- [x] Environment variable overrides work correctly
- [x] Configuration examples are provided

## Release Preparation

### Version Bump

```bash
# Update version in go.mod
go mod edit -module github.com/outlaw-dame/solid-sidecar

# Update version in Cargo.toml for Rust
# Edit rust/Cargo.toml

# Create release tag
git tag v1.0.0

# Push tag
git push origin v1.0.0
```

### Changelog

Create `CHANGELOG.md` entry:

```markdown
## [v1.0.0] - YYYY-MM-DD

### Added
- New features here

### Changed
- Breaking changes here
- Behavior changes here

### Fixed
- Bug fixes here

### Security
- Security fixes here

### Deprecated
- Deprecated features here

### Removed
- Removed features here
```

### Build and Package

```bash
# Build Go binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o solid-sidecar-linux-amd64 ./cmd/solid-sidecar

# Build Rust policy kernel
cd rust && cargo build --release

# Create Docker image
docker build -t ghcr.io/outlaw-dame/solid-sidecar:v1.0.0 .

# Push Docker image
docker push ghcr.io/outlaw-dame/solid-sidecar:v1.0.0
```

## Release Execution

### GitHub Release

1. Create GitHub release from tag
2. Attach binaries and Docker image references
3. Generate release notes from changelog
4. Publish release

### Package Publication

- [ ] Publish Docker image to GitHub Container Registry
- [ ] Publish Go module to GitHub (already done via tag)
- [ ] Update Helm chart (if applicable)
- [ ] Update Terraform module (if applicable)

## Post-Release Checklist

### Monitoring

- [ ] Monitor CI for any new failures
- [ ] Monitor error rates in production (if applicable)
- [ ] Monitor performance metrics
- [ ] Monitor security alerts

### Verification

- [ ] Verify Docker image pulls and runs correctly
- [ ] Verify configuration loading works
- [ ] Verify health checks pass
- [ ] Verify shadow mode works correctly
- [ ] Verify CSS compatibility is maintained

### Rollback Preparation

- [ ] Ensure previous version Docker image is available
- [ ] Document rollback procedure
- [ ] Test rollback procedure

### Communication

- [ ] Announce release in project channels
- [ ] Update project README with new version
- [ ] Update project documentation links
- [ ] Notify dependent projects (if applicable)

## Emergency Rollback Procedure

### Immediate Actions

1. **Stop deployment**: Immediately stop any ongoing deployments
2. **Revert traffic**: Switch traffic back to previous version
3. **Investigate**: Determine root cause of issue
4. **Communicate**: Notify stakeholders of rollback

### Rollback Steps

```bash
# For Docker deployments
docker pull ghcr.io/outlaw-dame/solid-sidecar:previous-version
docker stop solid-sidecar
docker rm solid-sidecar
docker run -d --name solid-sidecar \
  -p 8080:8080 \
  -v /path/to/config.yaml:/config.yaml \
  ghcr.io/outlaw-dame/solid-sidecar:previous-version

# For Kubernetes deployments
kubectl rollout undo deployment/solid-sidecar
kubectl wait --for=condition=available deployment/solid-sidecar --timeout=300s
```

### Post-Rollback

1. **Verify**: Confirm previous version is working correctly
2. **Monitor**: Watch for any issues with previous version
3. **Investigate**: Continue investigating the failed release
4. **Plan**: Create plan for fixing and re-releasing

## Release Sign-off

**Release Manager**: _______________________
**Date**: _______________
**Version**: _______________

### Pre-Release Checklist

- [ ] All code quality checks pass
- [ ] All security checks pass
- [ ] All tests pass
- [ ] Documentation is complete
- [ ] Configuration is safe

### Release Checklist

- [ ] Version bumped correctly
- [ ] Changelog updated
- [ ] Binaries built
- [ ] Docker images built and pushed
- [ ] GitHub release created

### Post-Release Checklist

- [ ] Monitoring in place
- [ ] Verification complete
- [ ] Rollback procedure tested
- [ ] Communication sent

**Status**: ✅ APPROVED / ❌ BLOCKED

**Notes**: ________________________________________________________
