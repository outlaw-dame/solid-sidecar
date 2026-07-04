# Production Runbook - Solid Sidecar

## Overview

This runbook provides operational procedures for managing the Solid Sidecar in production environments. It covers deployment, monitoring, troubleshooting, and emergency procedures.

## Table of Contents

1. [Deployment Procedures](#deployment-procedures)
2. [Operational Tasks](#operational-tasks)
3. [Monitoring and Observability](#monitoring-and-observability)
4. [Troubleshooting Guide](#troubleshooting-guide)
5. [Emergency Procedures](#emergency-procedures)
6. [Maintenance Windows](#maintenance-windows)
7. [Contact Information](#contact-information)

---

## Deployment Procedures

### Standard Deployment

#### Prerequisites
- All Phase 36 acceptance criteria met
- Production configuration validated
- Monitoring and alerting configured
- On-call team notified
- Rollback procedure tested
- Load testing completed
- Security review completed
- Documentation updated
- Stakeholders notified

#### Deployment Steps

1. **Build and Push Image**
   ```bash
   # Build the Docker image
   docker build -t ghcr.io/outlaw-dame/solid-sidecar:vX.Y.Z .
   
   # Push to container registry
   docker push ghcr.io/outlaw-dame/solid-sidecar:vX.Y.Z
   ```

2. **Update Configuration**
   ```bash
   # Update the version in docker-compose.production.yml
   sed -i 's|image:.*|image: ghcr.io/outlaw-dame/solid-sidecar:vX.Y.Z|' \
       deploy/compose/docker-compose.production.yml
   ```

3. **Deploy to Canary (1% traffic)**
   ```bash
   # Deploy with canary configuration
   cd deploy/compose
   docker compose -f docker-compose.production.yml -f docker-compose.canary.yml up -d
   
   # Monitor for 1 hour
   # Check: Error rate < 0.1%, Latency increase < 10%
   ```

4. **Promote to Limited (5% traffic)**
   ```bash
   # Update traffic split
   docker compose -f docker-compose.production.yml -f docker-compose.limited.yml up -d
   
   # Monitor for 4 hours
   # Check: Error rate < 0.1%, Latency increase < 5%
   ```

5. **Promote to Partial (25% traffic)**
   ```bash
   # Update traffic split
   docker compose -f docker-compose.production.yml -f docker-compose.partial.yml up -d
   
   # Monitor for 24 hours
   # Check: Error rate < 0.1%, No latency increase
   ```

6. **Promote to Majority (50% traffic)**
   ```bash
   # Update traffic split
   docker compose -f docker-compose.production.yml -f docker-compose.majority.yml up -d
   
   # Monitor for 24 hours
   # Check: Error rate < 0.01%, No issues
   ```

7. **Promote to Full (100% traffic)**
   ```bash
   # Full deployment
   docker compose -f docker-compose.production.yml up -d
   
   # Verify all traffic is flowing through sidecar
   ```

### Rollback Deployment

#### Immediate Rollback (Emergency)

1. **Switch to Pass-Through Mode**
   ```bash
   # Update configuration to pass-through mode
   sed -i 's|mode: shadow|mode: pass-through|' configs/sidecar.production.yaml
   
   # Restart containers
   docker compose -f docker-compose.production.yml restart solid-sidecar
   ```

2. **Or: Roll Back to Previous Version**
   ```bash
   # Revert to previous image
   sed -i 's|image:.*|image: ghcr.io/outlaw-dame/solid-sidecar:vPREVIOUS|' \
       deploy/compose/docker-compose.production.yml
   
   # Deploy previous version
   docker compose -f docker-compose.production.yml up -d
   ```

3. **Or: DNS Rollback**
   ```bash
   # Point DNS back to CSS directly
   # This varies by DNS provider
   ```

#### Verification After Rollback
- Verify error rate returns to normal
- Verify latency returns to normal
- Verify no data loss
- Verify rollback is reversible

### Configuration Management

#### Update Configuration
```bash
# Edit configuration file
vim configs/sidecar.production.yaml

# Validate configuration
# Run: go test ./internal/config/...

# Apply configuration (requires restart)
docker compose -f docker-compose.production.yml restart solid-sidecar
```

#### Feature Flags
```bash
# Enable enforcement mode (after validation)
sed -i 's|enforce_authz: false|enforce_authz: true|' configs/sidecar.production.yaml

# Enable SAE support (after Phase 38)
sed -i 's|sae_support: false|sae_support: true|' configs/sidecar.production.yaml

# Apply changes
docker compose -f docker-compose.production.yml restart solid-sidecar
```

---

## Operational Tasks

### Daily Operations

1. **Check Service Health**
   ```bash
   # Check liveness
   curl -f http://localhost:9090/health/live
   
   # Check readiness
   curl -f http://localhost:9090/health/ready
   
   # Check backend connectivity
   curl -f http://localhost:9090/health/startup
   ```

2. **Review Alerts**
   ```bash
   # Check Alertmanager
   curl http://localhost:9093/api/v1/alerts
   
   # Or use Grafana dashboards
   ```

3. **Monitor Metrics**
   ```bash
   # Check Prometheus for errors
   curl http://localhost:9090/api/v1/query?query=rate(http_requests_total{status_code=~"5.."}[5m])
   
   # Check latency
   curl http://localhost:9090/api/v1/query?query=histogram_quantile(0.95,
       sum(rate(http_request_duration_seconds_bucket[5m])) by (le))
   ```

### Weekly Operations

1. **Review Logs**
   ```bash
   # View recent logs
   docker logs --since 1h solid-sidecar-production
   
   # Check for errors
   docker logs --since 1h solid-sidecar-production | grep -i error
   
   # Check for warnings
   docker logs --since 1h solid-sidecar-production | grep -i warn
   ```

2. **Check Resource Usage**
   ```bash
   # Check container stats
   docker stats solid-sidecar-production
   
   # Check memory usage
   docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" solid-sidecar-production
   ```

3. **Test Rollback Procedure**
   ```bash
   # Test rollback in staging first
   cd deploy/compose
   docker compose -f docker-compose.staging.yml exec solid-sidecar /app/solid-sidecar --version
   ```

### Monthly Operations

1. **Review and Update Documentation**
   - Review runbook for accuracy
   - Update contact information
   - Update procedures based on recent incidents

2. **Capacity Planning**
   - Review resource usage trends
   - Plan for scaling needs
   - Update auto-scaling policies

3. **Security Review**
   - Review access controls
   - Rotate secrets if needed
   - Update TLS certificates

---

## Monitoring and Observability

### Key Metrics to Watch

| Metric | Threshold | Action |
|--------|-----------|--------|
| Error Rate | > 1% | Investigate immediately |
| P95 Latency | > 2s | Investigate performance |
| Memory Usage | > 90% | Scale up or investigate leaks |
| CPU Usage | > 80% | Scale up or investigate |
| Cache Hit Rate | < 50% | Investigate cache effectiveness |
| AuthZ Mismatches | > 0 | Investigate comparison harness |
| Fixture Sync Failures | > 0 | Investigate transport layer |

### Dashboards

1. **Overview Dashboard** (`http://grafana:3001/d/overview`)
   - High-level health
   - Request rates
   - Error rates
   - Resource usage

2. **Authorization Dashboard** (`http://grafana:3001/d/authz`)
   - Policy evaluations
   - Decisions (allow/deny/abstain)
   - Cache statistics
   - Mismatch rates

3. **Transport Dashboard** (`http://grafana:3001/d/transport`)
   - Fixture distribution
   - Transport-specific metrics
   - Sync times
   - Error rates by transport

4. **Performance Dashboard** (`http://grafana:3001/d/performance`)
   - Latency percentiles
   - Throughput
   - Resource usage trends

5. **Safety Dashboard** (`http://grafana:3001/d/safety`)
   - Circuit breaker state
   - Rate limiting
   - Panic recovery

### Alerts

#### Critical Alerts (Page 24/7)
- **SidecarDown**: Sidecar is down
- **CSSDown**: Backend CSS is down
- **HighErrorRate**: Error rate > 10%
- **HighLatency**: P95 latency > 2s
- **PrometheusDown**: Monitoring is down
- **AlertmanagerDown**: Alerting is down

#### Warning Alerts (Ticket)
- **MemoryHigh**: Memory > 90%
- **CPUHigh**: CPU > 80%
- **AuthZMismatchDetected**: AuthZ mismatches found
- **FixtureSyncFailure**: Fixture sync failures
- **LowCacheHitRate**: Cache hit rate < 50%
- **CircuitBreakerOpen**: Circuit breaker tripped
- **RateLimitTriggered**: Rate limiting active

#### Info Alerts (Awareness)
- **SidecarRestart**: Container restarted
- **HighRequestVolume**: Request volume > 1000 req/s
- **NewClient**: New clients detected

---

## Troubleshooting Guide

### Common Issues

#### Issue: Sidecar Not Starting

**Symptoms:**
- Container exits immediately
- `docker ps` doesn't show solid-sidecar

**Diagnosis:**
```bash
# Check container logs
docker logs solid-sidecar-production

# Check exit code
docker inspect solid-sidecar-production --format='{{.State.ExitCode}}'

# Check configuration
docker exec -it solid-sidecar-production cat /etc/solid/config.yaml
```

**Common Causes:**
1. Invalid configuration file
2. Missing TLS certificates
3. Port already in use
4. Permission issues

**Solutions:**
1. Validate configuration: `go test ./internal/config/...`
2. Check TLS files exist and are readable
3. Check port availability: `netstat -tuln | grep 443`
4. Check file permissions on mounted volumes


#### Issue: High Error Rate

**Symptoms:**
- Error rate > 1%
- 5xx responses increasing

**Diagnosis:**
```bash
# Check error rate by status code
curl "http://prometheus:9090/api/v1/query?query=rate(http_requests_total[5m])" | jq

# Check recent errors
docker logs --since 5m solid-sidecar-production | grep -i error

# Check backend health
curl -f http://localhost:9090/health/ready
```

**Common Causes:**
1. Backend CSS down
2. Policy evaluation failures
3. Authentication failures
4. Transport failures

**Solutions:**
1. Check CSS health: `curl -f http://css-production:3000/`
2. Check policy cache: Review authz metrics
3. Check authentication: Review authn logs
4. Check transport: Review fixture distribution logs


#### Issue: High Latency

**Symptoms:**
- P95 latency > 2s
- Slow responses

**Diagnosis:**
```bash
# Check latency metrics
curl "http://prometheus:9090/api/v1/query?query=histogram_quantile(0.95,
  sum(rate(http_request_duration_seconds_bucket[5m])) by (le))" | jq

# Check resource usage
docker stats --no-stream solid-sidecar-production

# Check for goroutine leaks
# (Requires pprof enabled)
curl http://localhost:6060/debug/pprof/goroutine?debug=2
```

**Common Causes:**
1. Resource exhaustion (CPU/Memory)
2. Backend CSS slow
3. Policy evaluation slow
4. Fixture sync slow
5. Database queries slow

**Solutions:**
1. Scale up resources
2. Check CSS performance
3. Check policy cache hit rate
4. Check fixture distribution performance
5. Profile with pprof


#### Issue: Authorization Mismatches

**Symptoms:**
- AuthZ mismatch alerts firing
- Comparison harness reports mismatches

**Diagnosis:**
```bash
# Check mismatch metrics
curl "http://prometheus:9090/api/v1/query?query=increase(solid_sidecar_authz_mismatches_total[5m])" | jq

# Check comparison logs
docker logs --since 5m solid-sidecar-production | grep -i mismatch

# Run comparison manually
# (Requires comparison harness)
```

**Common Causes:**
1. Policy changes not synced
2. Bug in policy evaluation
3. Different policy interpretation
4. Cache inconsistency

**Solutions:**
1. Check policy cache invalidation
2. Compare with CSS directly
3. Review policy evaluation logic
4. Clear cache and retry


#### Issue: Fixture Sync Failures

**Symptoms:**
- Fixture sync failure alerts
- Transport errors in logs

**Diagnosis:**
```bash
# Check sync failure metrics
curl "http://prometheus:9090/api/v1/query?query=increase(solid_sidecar_fixture_sync_failures_total[5m])" | jq

# Check transport logs
docker logs --since 5m solid-sidecar-production | grep -i "transport\|fixture\|sync"

# Test transport connectivity
curl -v https://fixture-dist.example.org
```

**Common Causes:**
1. Network connectivity issues
2. Authentication failures
3. Permission issues
4. Backend service down

**Solutions:**
1. Check network connectivity
2. Check transport credentials
3. Check backend service health
4. Test transport manually


#### Issue: Memory Leak

**Symptoms:**
- Memory usage steadily increasing
- OOM kills

**Diagnosis:**
```bash
# Check memory usage over time
curl "http://prometheus:9090/api/v1/query?query=container_memory_working_set_bytes{container=\"solid-sidecar-production\"}[1h]" | jq

# Check for goroutine growth
# (Requires pprof enabled)
curl http://localhost:6060/debug/pprof/goroutine | grep "goroutines"

# Check heap profile
curl http://localhost:6060/debug/pprof/heap -o heap.prof
go tool pprof heap.prof
```

**Common Causes:**
1. Unbounded cache growth
2. Goroutine leaks
3. Memory retention in data structures

**Solutions:**
1. Check cache size limits
2. Check for goroutine leaks with pprof
3. Profile memory with pprof
4. Restart container to reclaim memory

---

## Emergency Procedures

### SEV-1: Complete Outage

**Symptoms:**
- Sidecar completely unavailable
- All requests failing
- Container not running

**Immediate Actions:**
1. **Check container status**
   ```bash
   docker ps -a | grep solid-sidecar
   ```

2. **Check logs**
   ```bash
   docker logs solid-sidecar-production
   ```

3. **Restart container**
   ```bash
   docker compose -f docker-compose.production.yml restart solid-sidecar
   ```

4. **If restart fails, switch to pass-through mode**
   ```bash
   sed -i 's|mode: .*|mode: pass-through|' configs/sidecar.production.yaml
   docker compose -f docker-compose.production.yml restart solid-sidecar
   ```

5. **If pass-through fails, roll back to previous version**
   ```bash
   sed -i 's|image:.*|image: ghcr.io/outlaw-dame/solid-sidecar:vPREVIOUS|' \
       deploy/compose/docker-compose.production.yml
   docker compose -f docker-compose.production.yml up -d
   ```

6. **If all else fails, bypass sidecar at load balancer**
   ```bash
   # Point load balancer directly to CSS
   # This varies by load balancer implementation
   ```

**Escalation:**
- Page on-call engineer
- If no response in 15 minutes, escalate to engineering manager

**Communication:**
- Post incident in `#solid-sidecar-incidents`
- Update status page


### SEV-2: Partial Outage

**Symptoms:**
- High error rate (>10%)
- Significant performance degradation
- Partial functionality broken

**Immediate Actions:**
1. **Check error rate**
   ```bash
   curl "http://prometheus:9090/api/v1/query?query=rate(http_requests_total{status_code=~\"5..\"}[5m])/rate(http_requests_total[5m])" | jq
   ```

2. **Check recent deployments**
   ```bash
   git log --oneline --since="1 hour ago" --until=now
   ```

3. **Check backend health**
   ```bash
   curl -f http://css-production:3000/
   ```

4. **Enable debug logging**
   ```bash
   sed -i 's|SIDECARE_LOG_LEVEL=.*|SIDECARE_LOG_LEVEL=debug|' deploy/compose/docker-compose.production.yml
   docker compose -f docker-compose.production.yml restart solid-sidecar
   ```

5. **Check specific error patterns**
   ```bash
   docker logs --since 5m solid-sidecar-production | grep -i error | sort | uniq -c | sort -nr
   ```

6. **Roll back if needed**
   ```bash
   # Use previous working version
   sed -i 's|image:.*|image: ghcr.io/outlaw-dame/solid-sidecar:vPREVIOUS|' \
       deploy/compose/docker-compose.production.yml
   docker compose -f docker-compose.production.yml up -d
   ```

**Escalation:**
- Page on-call engineer (business hours)
- Ticket otherwise

**Communication:**
- Post in `#solid-sidecar-incidents`
- Notify affected stakeholders


### SEV-3: Degraded Performance

**Symptoms:**
- Performance degradation but still functional
- Low error rates (1-10%)
- Some functionality issues

**Immediate Actions:**
1. **Check latency**
   ```bash
   curl "http://prometheus:9090/api/v1/query?query=histogram_quantile(0.95,
     sum(rate(http_request_duration_seconds_bucket[5m])) by (le))" | jq
   ```

2. **Check resource usage**
   ```bash
   docker stats --no-stream solid-sidecar-production
   ```

3. **Check for garbage collection pressure**
   ```bash
   # Check GC metrics
   curl "http://prometheus:9090/api/v1/query?query=rate(go_gc_duration_seconds_sum[5m])" | jq
   ```

4. **Scale up if needed**
   ```bash
   # Increase replicas in Kubernetes
   kubectl scale deployment solid-sidecar --replicas=5
   
   # Or increase resources in Docker Compose
   # Edit deploy/compose/docker-compose.production.yml
   ```

5. **Check for specific slow operations**
   ```bash
   # Check slowest endpoints
   curl "http://prometheus:9090/api/v1/query?query=topk(5,
     rate(http_request_duration_seconds_sum[5m]) by (path))" | jq
   ```

**Escalation:**
- Ticket during business hours

**Communication:**
- Post in team channel
- Notify if affecting users


### SEV-4: Minor Issues

**Symptoms:**
- Cosmetic issues
- Non-critical features broken
- Minor functionality issues

**Actions:**
- Investigate during next business day
- Fix in next regular deployment
- Monitor for escalation

---

## Maintenance Windows

### Scheduled Maintenance

1. **Weekly Maintenance Window**
   - When: Every Sunday, 02:00-04:00 UTC
   - Purpose: Regular updates, restarts, maintenance
   - Impact: Minimal, rolling updates

2. **Monthly Maintenance Window**
   - When: First Saturday of each month, 00:00-04:00 UTC
   - Purpose: Major updates, configuration changes
   - Impact: May require brief downtime

3. **Emergency Maintenance**
   - When: As needed for SEV-1/SEV-2 incidents
   - Purpose: Critical fixes, security patches
   - Impact: Varies, communication required

### Maintenance Procedures

1. **Announce Maintenance**
   - Post in `#solid-sidecar-announcements` 24 hours before
   - Update status page
   - Notify stakeholders

2. **Prepare Rollback Plan**
   - Identify previous working version
   - Test rollback procedure
   - Prepare emergency contacts

3. **Execute Maintenance**
   - Follow deployment procedures
   - Monitor closely
   - Be prepared to roll back

4. **Verify Success**
   - Check all health checks pass
   - Verify metrics are normal
   - Confirm with stakeholders

5. **Communicate Completion**
   - Post in `#solid-sidecar-announcements`
   - Update status page
   - Notify stakeholders

---

## Contact Information

### On-Call Rotation

| Role | Name | Email | Phone | Time Zone |
|------|------|-------|-------|----------|
| Primary | On-Call Engineer | oncall@solid-sidecar.example.org | +1-XXX-XXX-XXXX | UTC |
| Secondary | Backup Engineer | backup@solid-sidecar.example.org | +1-XXX-XXX-XXXX | UTC |
| Escalation | Engineering Manager | manager@solid-sidecar.example.org | +1-XXX-XXX-XXXX | UTC |

### Teams

| Team | Channel | Email |
|------|---------|-------|
| Platform | `#solid-sidecar-platform` | platform@solid-sidecar.example.org |
| AuthZ | `#solid-sidecar-authz` | authz@solid-sidecar.example.org |
| AuthN | `#solid-sidecar-authn` | authn@solid-sidecar.example.org |

### External Contacts

| Service | Contact | Notes |
|---------|---------|-------|
| CSS Support | css-support@example.org | Community Solid Server |
| Infrastructure | infra@example.org | Hosting provider |
| Security | security@example.org | Security incidents |

---

## Appendix

### Common Commands

```bash
# Check all services
docker compose -f docker-compose.production.yml ps

# View logs
docker compose -f docker-compose.production.yml logs -f

# View specific service logs
docker compose -f docker-compose.production.yml logs -f solid-sidecar

# Check resource usage
docker stats

# Restart all services
docker compose -f docker-compose.production.yml restart

# Update all services
docker compose -f docker-compose.production.yml pull && \
  docker compose -f docker-compose.production.yml up -d

# Check version
docker exec solid-sidecar-production /app/solid-sidecar --version

# Check health
curl -f http://localhost:9090/health/live
curl -f http://localhost:9090/health/ready

# Check metrics
curl http://localhost:9090/metrics
```

### Configuration Reference

```yaml
# Main configuration file
configs/sidecar.production.yaml

# Docker Compose
deploy/compose/docker-compose.production.yml

# Monitoring configuration
configs/monitoring/prometheus.yml
configs/monitoring/alert-rules.yaml
configs/monitoring/alertmanager.yml
```

### Runbook History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-07-04 | Mistral Vibe | Initial production runbook |
