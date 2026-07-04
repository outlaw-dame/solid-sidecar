# Rollback Procedure for solid-sidecar

## Overview

This document describes the rollback procedures for the solid-sidecar in various scenarios. Rollback is the process of reverting from the sidecar to direct CSS access when issues are detected.

**Last Updated:** 2026-07-03  
**Owner:** solid-sidecar Operations Team  

---

## Rollback Objectives

1. **Safety First**: Ensure no data loss or corruption during rollback
2. **Speed**: Complete rollback within 5 minutes
3. **Reliability**: Guarantee rollback doesn't lose in-flight requests
4. **Reversibility**: Rollback must be reversible (can roll forward again)
5. **Observability**: Maintain visibility during rollback process

---

## Rollback Triggers

Rollback should be initiated when any of the following conditions are met:

### Critical Triggers (Immediate Rollback)

- **Sidecar errors exceed threshold**: > 1% error rate for 5 consecutive minutes
- **Response time degradation**: > 2x CSS baseline latency
- **Security incident**: Any security breach or vulnerability exploitation
- **Data corruption**: Any indication of data integrity issues
- **Authorization errors**: Incorrect authorization decisions affecting production users
- **Sidecar readiness flaps**: Frequent readiness state changes (> 3 in 5 minutes)

### Warning Triggers (Consider Rollback)

- Sidecar errors approach threshold: > 0.5% error rate
- Response time approaching degradation: > 1.5x CSS baseline
- Memory leaks detected
- Goroutine leaks detected
- Disk space running low (< 10% free)
- High CPU usage (> 80% for 10 minutes)

---

## Rollback Mechanisms

### 1. Configuration Rollback (Recommended)

Switch the sidecar to pass-through mode, where it proxies to CSS without processing requests.

#### Steps:

1. **Update configuration**:
   ```yaml
   authz:
     shadow_enabled: false
     evaluator: "local"
   enforcement:
     mode: "shadow"
   ```

2. **Reload configuration**:
   - Send SIGHUP to sidecar process (if supported)
   - Or restart sidecar service

3. **Verify pass-through mode**:
   ```bash
   # Check that sidecar is proxying without processing
   curl -v https://solid-sidecar.example.org/healthz
   curl -v https://solid-sidecar.example.org/readyz
   
   # Verify requests are passed through to CSS
   curl -i https://solid-sidecar.example.org/
   ```

#### Expected Behavior:
- Sidecar proxies all requests to CSS
- No authorization checks performed by sidecar
- No policy loading or evaluation
- Minimal overhead (just reverse proxy)

#### Rollback Time: < 30 seconds

---

### 2. DNS/Load Balancer Rollback

Route traffic directly back to CSS, bypassing the sidecar entirely.

#### Steps:

1. **Identify current routing**:
   - Check DNS records
   - Check load balancer configuration

2. **Update DNS** (if using DNS-based routing):
   ```bash
   # Update DNS A/AAAA or CNAME record to point to CSS directly
   # Example using AWS Route 53:
   aws route53 change-resource-record-sets \
     --hosted-zone-id ZONE_ID \
     --change-batch '{
       "Changes": [{
         "Action": "UPSERT",
         "ResourceRecordSet": {
           "Name": "solid.example.org",
           "Type": "A",
           "TTL": 300,
           "ResourceRecords": [{"Value": "CSS_IP_ADDRESS"}]
         }
       }]
     }'
   ```

3. **Update Load Balancer** (if using LB-based routing):
   ```bash
   # Example using AWS ALB:
   aws elbv2 modify-target-group-attributes \
     --target-group-arn TARGET_GROUP_ARN \
     --attributes Key=deregistration_delay.timeout_seconds,Value=0
   
   # Remove sidecar from target group
   aws elbv2 deregister-targets \
     --target-group-arn TARGET_GROUP_ARN \
     --targets Id=SIDECAR_INSTANCE_ID,Port=8443
   ```

4. **Wait for propagation**:
   - DNS: Up to TTL (typically 5-300 seconds)
   - Load Balancer: Immediate (after deregitration delay)

#### Expected Behavior:
- All traffic flows directly to CSS
- Sidecar is no longer in the request path
- No sidecar processing overhead

#### Rollback Time: DNS TTL dependent (typically 1-5 minutes)

---

### 3. Service Rollback

Stop the sidecar service entirely.

#### Steps:

1. **Stop sidecar service**:
   ```bash
   # Systemd
   sudo systemctl stop solid-sidecar
   
   # Docker
   docker stop solid-sidecar
   
   # Kubernetes
   kubectl scale deployment solid-sidecar --replicas=0
   ```

2. **Ensure traffic routes to CSS**:
   - Verify CSS is directly accessible
   - Check that DNS or load balancer is not pointing to sidecar

3. **Monitor CSS directly**:
   ```bash
   curl -v https://css.example.org:3000/healthz
   ```

#### Expected Behavior:
- Sidecar is stopped
- All traffic must be routed directly to CSS (via DNS or LB)
- No sidecar processing

#### Rollback Time: < 1 minute

---

### 4. Emergency Bypass

Enable emergency bypass mode in sidecar configuration.

#### Steps:

1. **Set emergency bypass environment variable**:
   ```bash
   export SOLID_SIDECAR_EMERGENCY_BYPASS=true
   export SOLID_SIDECAR_BYPASS_TOKEN=emergency-token
   ```

2. **Or update configuration file**:
   ```yaml
enforcement:
  mode: "shadow"
  bypass:
    enabled: true
    tokens:
      - "emergency-token"
      - "rollback-token"
    auto_revert_after: "5m"
   ```

3. **Send bypass request**:
   ```bash
   curl -X POST https://solid-sidecar.example.org/emergency-bypass \
     -H "Authorization: Bearer emergency-token"
   ```

4. **Verify bypass is active**:
   ```bash
   curl -v https://solid-sidecar.example.org/healthz
   # Check logs for "Emergency bypass activated"
   ```

#### Expected Behavior:
- Sidecar enters bypass mode
- All requests are proxied to CSS without processing
- Bypass can be reversed by removing the token or waiting for auto-revert

#### Rollback Time: < 10 seconds

---

## Rollback Procedures by Environment

### Staging Environment Rollback

1. **Primary method**: Configuration rollback
2. **Secondary method**: Service rollback
3. **Emergency method**: Emergency bypass

**Steps:**
```bash
# 1. Update configuration
kubectl edit configmap solid-sidecar-config -n solid-staging
# Set authz.shadow_enabled: false

# 2. Rollout restart
kubectl rollout restart deployment solid-sidecar -n solid-staging

# 3. Verify
kubectl get pods -n solid-staging
kubectl logs -f deployment/solid-sidecar -n solid-staging

# 4. Test
curl -v https://staging.solid.example.org/
```

**Rollback Time:** < 2 minutes

### Production Environment Rollback

1. **Primary method**: DNS/Load Balancer rollback
2. **Secondary method**: Configuration rollback
3. **Emergency method**: Emergency bypass

**Steps:**
```bash
# 1. Update DNS (if using DNS-based routing)
# Switch DNS from sidecar to CSS

# 2. Monitor traffic shift
grafana-cli --dashboard solid-traffic

# 3. Verify CSS health
curl -v https://css-production.example.org:3000/healthz

# 4. Verify sidecar is bypassed
curl -v https://solid.example.org/  # Should hit CSS directly
```

**Rollback Time:** < 5 minutes (DNS TTL dependent)

---

## Rollback Verification Checklist

After performing any rollback, verify the following:

### 1. Health Checks
- [ ] CSS health endpoint returns 200
- [ ] If sidecar is still running, its health endpoint returns 200
- [ ] No 5xx errors in last 5 minutes

### 2. Traffic Verification
- [ ] Requests are reaching CSS directly (or via sidecar in pass-through mode)
- [ ] Response times are back to baseline
- [ ] Error rates are back to baseline

### 3. Data Integrity
- [ ] No data loss during rollback
- [ ] No corrupted resources
- [ ] All recent writes are visible

### 4. Observability
- [ ] Logs show successful rollback
- [ ] Metrics show traffic shift
- [ ] Alerts are resolved

### 5. Reversibility
- [ ] Can roll forward again if needed
- [ ] Configuration can be reverted
- [ ] DNS can be switched back

---

## Rollback Runbook

### Scenario 1: High Error Rate

**Symptoms:**
- Error rate > 1% for 5 consecutive minutes
- Increasing error rate trend
- Client complaints about failed requests

**Actions:**
1. Check sidecar logs for error patterns
2. Check CSS logs for issues
3. If sidecar is the source of errors, initiate configuration rollback
4. Monitor for 5 minutes after rollback
5. If errors persist, initiate DNS/LB rollback

### Scenario 2: High Latency

**Symptoms:**
- P99 latency > 2x baseline
- Increasing latency trend
- Client complaints about slow responses

**Actions:**
1. Check sidecar metrics for latency sources
2. Check CSS metrics for latency
3. Check infrastructure (CPU, memory, disk, network)
4. If sidecar is the source, initiate configuration rollback
5. Monitor for improvement

### Scenario 3: Authorization Issues

**Symptoms:**
- Users report access denied when they should have access
- Users report access granted when they should be denied
- Mismatch between sidecar and CSS authorization decisions

**Actions:**
1. Immediately initiate emergency bypass
2. Investigate authorization logs
3. Check policy evaluation
4. Do NOT wait for investigation - rollback immediately
5. Restore from known-good configuration

---

## Rollback Communication

### Who to Notify

| Severity | Who to Notify | Method | Timeframe |
|----------|---------------|--------|-----------|
| Critical | All stakeholders | Phone, PagerDuty | Immediate |
| High | Operations team, Engineering | Slack, Email | < 5 minutes |
| Medium | Engineering team | Slack, Email | < 15 minutes |
| Low | Engineering team | Email | < 1 hour |

### Communication Templates

#### Critical Rollback Notification

```
Subject: URGENT: solid-sidecar rollback initiated

A rollback of solid-sidecar has been initiated due to:
[REASON]

Rollback method: [CONFIG/DNS/LB/SERVICE]
Rollback time: [TIME]
Expected completion: [ETR]

Impact: [DESCRIPTION]

Please stand by for updates.
```

#### Rollback Completion Notification

```
Subject: RESOLVED: solid-sidecar rollback complete

The rollback of solid-sidecar has been completed successfully.

Rollback method: [CONFIG/DNS/LB/SERVICE]
Rollback completed: [TIME]
Rollback duration: [DURATION]

Current status:
- CSS: Healthy
- Sidecar: [STOPPED/PASSTHROUGH]
- Error rate: [X]%
- Latency: [Y]ms

Next steps: [INVESTIGATION/PLAN]
```

---

## Post-Rollback Procedures

### 1. Incident Investigation
- [ ] Identify root cause of rollback trigger
- [ ] Document findings in incident report
- [ ] Identify preventative measures
- [ ] Create action items

### 2. Rollback Review
- [ ] Review rollback process
- [ ] Identify improvements
- [ ] Update runbooks and procedures
- [ ] Conduct blameless post-mortem

### 3. Roll Forward Planning
- [ ] Identify required fixes
- [ ] Create roll forward plan
- [ ] Test fixes in staging
- [ ] Schedule roll forward deployment

### 4. Testing
- [ ] Verify fixes address root cause
- [ ] Run full test suite
- [ ] Conduct performance testing
- [ ] Conduct security review

---

## Rollback Testing

### Regular Rollback Tests

Rollback procedures should be tested regularly:

- **Monthly**: Configuration rollback test in staging
- **Quarterly**: DNS/LB rollback test in staging
- **Annually**: Full rollback test in production (during maintenance window)

### Test Cases

1. **Configuration Rollback Test**
   - Switch from enforcement to shadow mode
   - Verify requests still work
   - Switch back to enforcement mode
   - Verify requests still work

2. **Service Rollback Test**
   - Stop sidecar service
   - Verify traffic routes to CSS
   - Start sidecar service
   - Verify traffic routes through sidecar

3. **DNS Rollback Test**
   - Switch DNS from sidecar to CSS
   - Wait for TTL
   - Verify traffic routes to CSS
   - Switch DNS back to sidecar
   - Wait for TTL
   - Verify traffic routes through sidecar

---

## Rollback Metrics

Track the following metrics for rollback procedures:

| Metric | Target | Measurement |
|--------|--------|-------------|
| Rollback time | < 5 minutes | Time from decision to completion |
| Error rate during rollback | < 0.1% | Percentage of failed requests |
| Latency during rollback | < 2x baseline | P99 latency |
| Data loss | 0 | Number of lost/corrupted resources |
| Downtime | 0 | Time when service is unavailable |

---

## Rollback History

| Date | Environment | Trigger | Method | Duration | Success |
|------|-------------|---------|--------|----------|---------|
| 2026-07-03 | Staging | Test | Configuration | 30s | Yes |

---

## Appendices

### Appendix A: Emergency Bypass Configuration

```yaml
enforcement:
  mode: "shadow"
  bypass:
    enabled: true
    tokens:
      - "emergency-token-1"
      - "emergency-token-2"
    auto_revert_after: "10m"
    max_duration: "1h"
    audit_log: true
```

### Appendix B: Pass-Through Configuration

```yaml
authz:
  shadow_enabled: false
  evaluator: "local"
  policy_discovery:
    enabled: false

enforcement:
  mode: "shadow"
  canary:
    enabled: false
```

### Appendix C: DNS Configuration Examples

**Cloudflare:**
```
api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records
{
  "type": "A",
  "name": "solid.example.org",
  "content": "CSS_IP",
  "ttl": 300,
  "proxied": false
}
```

**AWS Route 53:**
```json
{
  "Comment": "Rollback to CSS",
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "solid.example.org",
      "Type": "A",
      "TTL": 300,
      "ResourceRecords": [{"Value": "CSS_IP"}]
    }
  }]
}
```

---

*This document was created as part of Phase 36: Staging Deployment and Traffic Comparison.*
