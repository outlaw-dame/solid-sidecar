# Incident Response - Solid Sidecar

## Overview

This document defines the incident response process for the Solid Sidecar project. It establishes severity levels, response times, communication protocols, and post-mortem procedures to ensure consistent and effective incident management.

## Incident Classification

### Severity Levels

| Severity | Name | Description | Response Time | Resolution Time |
|----------|------|-------------|---------------|------------------|
| SEV-1 | Critical | Complete outage, data loss, security breach | 15 minutes (24/7) | 4 hours |
| SEV-2 | High | Partial outage, significant degradation, high error rates | 1 hour (business) / 4 hours (off) | 8 hours |
| SEV-3 | Medium | Minor functionality issues, performance degradation | 4 hours (business) | 24 hours |
| SEV-4 | Low | Cosmetic issues, non-critical features | Next business day | 72 hours |

### Severity Definition

#### SEV-1 (Critical)
- **Impact**: Complete service unavailable
- **Examples**:
  - Sidecar completely down, all requests failing
  - Data loss or corruption
  - Security breach (confirmed compromise)
  - Authentication completely broken (no users can log in)
  - Authorization completely broken (all requests denied)
  - Backend CSS completely unavailable

#### SEV-2 (High)
- **Impact**: Significant service degradation or partial outage
- **Examples**:
  - Error rate > 10% for sustained period (>5 minutes)
  - P95 latency > 5 seconds for sustained period
  - Major functionality broken (e.g., all write operations failing)
  - Authentication broken for subset of users
  - Authorization broken for subset of users
  - Fixture distribution completely failing

#### SEV-3 (Medium)
- **Impact**: Minor functionality issues, some users affected
- **Examples**:
  - Error rate 1-10%
  - P95 latency 2-5 seconds
  - Minor features broken (e.g., caching not working)
  - Performance degradation but service still functional
  - Individual transport failing

#### SEV-4 (Low)
- **Impact**: Minimal impact, cosmetic issues
- **Examples**:
  - Cosmetic UI issues
  - Non-critical features broken
  - Documentation errors
  - Logging issues

## Incident Response Process

### 1. Detection and Triage

#### Detection Sources
- **Alerting**: Prometheus Alertmanager (primary)
- **Monitoring**: Grafana dashboards
- **Logging**: ELK/Loki logs
- **User Reports**: Issue tracker, support channels
- **Automated Tests**: CI/CD pipeline failures

#### Triage Procedure

1. **Acknowledge Alert**
   - First responder acknowledges the alert in Alertmanager
   - This stops additional notifications for the same alert

2. **Assess Severity**
   - Use the severity matrix above
   - Consider: Impact, scope, duration
   - When in doubt, escalate to higher severity

3. **Gather Information**
   ```bash
   # Check alert details
   curl http://alertmanager:9093/api/v1/alerts | jq
   
   # Check metrics
   curl "http://prometheus:9090/api/v1/query?query=up" | jq
   
   # Check service health
   curl -f http://localhost:9090/health/live
   curl -f http://localhost:9090/health/ready
   
   # Check logs
   docker logs --since 5m solid-sidecar-production
   ```

4. **Create Incident Record**
   - Open incident in incident tracking system
   - Or create GitHub issue with `incident` label
   - Document: Time, severity, symptoms, initial assessment

5. **Determine if Incident is New**
   - Check for existing incidents with same symptoms
   - If related to existing incident, update that incident
   - If new, create new incident record


### 2. Initial Response

#### For SEV-1 Incidents

1. **Page On-Call Engineer**
   - Use primary contact method (phone)
   - If no response in 15 minutes, page secondary
   - If no response in 30 minutes, escalate to manager

2. **Activate Incident Response Team**
   - Notify all on-call team members
   - Create incident channel: `#solid-sidecar-incident-YYYYMMDD`
   - Invite relevant stakeholders

3. **Begin Immediate Mitigation**
   - Follow playbooks in [runbook-production.md](./runbook-production.md)
   - Prioritize: Restore service > Preserve data > Investigate root cause

4. **Communicate Externally**
   - Update status page within 30 minutes
   - Post in user-facing channels
   - Prepare customer communication if needed


#### For SEV-2 Incidents

1. **Page On-Call Engineer** (business hours)
   - Or ticket (off-hours)

2. **Create Incident Channel**
   - `#solid-sidecar-incident-YYYYMMDD`

3. **Begin Investigation**
   - Follow playbooks
   - Document all findings

4. **Communicate**
   - Update status page within 1 hour
   - Notify affected stakeholders


#### For SEV-3 Incidents

1. **Ticket**
   - Create issue in GitHub with `incident` label

2. **Investigate**
   - Follow playbooks
   - Document findings

3. **Communicate**
   - Update internal stakeholders


#### For SEV-4 Incidents

1. **Document**
   - Create issue in GitHub

2. **Schedule**
   - Address in next sprint


### 3. Investigation and Diagnosis

#### Incident Commander
- **Role**: Coordinate incident response
- **Responsibilities**:
  - Maintain timeline of events
  - Assign tasks to team members
  - Ensure communication flows
  - Make go/no-go decisions

#### Investigation Steps

1. **Reproduce the Issue**
   - Identify steps to reproduce
   - Determine scope (affected users, endpoints, etc.)

2. **Gather Evidence**
   ```bash
   # Save metrics snapshot
   curl "http://prometheus:9090/api/v1/query?query=up" > incident-metrics-$(date +%s).json
   
   # Save logs
   docker logs --since 1h solid-sidecar-production > incident-logs-$(date +%s).txt
   
   # Save configuration
   docker exec solid-sidecar-production cat /etc/solid/config.yaml > incident-config-$(date +%s).yaml
   ```

3. **Identify Root Cause**
   - Use structured debugging approach
   - Check recent changes (deployments, configuration, code)
   - Check dependencies (CSS, databases, external services)
   - Check infrastructure (network, compute, storage)

4. **Document Findings**
   - Record all observations
   - Note what was tried and results
   - Identify contributing factors


### 4. Mitigation and Resolution

#### Mitigation Strategies

1. **Rollback**
   - Revert to previous working version
   - Follow procedures in [runbook-production.md](./runbook-production.md)

2. **Workaround**
   - Implement temporary fix
   - Disable affected feature
   - Route around issue

3. **Hotfix**
   - Apply emergency code change
   - Requires: Approval from incident commander
   - Must be: Minimal change, well-tested

4. **Scale Up**
   - Add more resources
   - Increase replicas
   - Scale horizontally


#### Resolution Criteria

- **Service Restored**: All functionality working as expected
- **Metrics Normal**: Error rate < 1%, latency < 2s, no alerts firing
- **Root Cause Identified**: Clear understanding of what caused the incident
- **Mitigation in Place**: Temporary or permanent fix applied
- **No Regression**: No new issues introduced by fix


### 5. Communication

#### Internal Communication

| Severity | Channel | Frequency |
|----------|---------|-----------|
| SEV-1 | `#solid-sidecar-incidents` + Dedicated channel | Continuous updates |
| SEV-2 | `#solid-sidecar-incidents` | Hourly updates |
| SEV-3 | Team channel | As needed |
| SEV-4 | GitHub issue | As needed |

#### External Communication

| Severity | Channel | Frequency |
|----------|---------|-----------|
| SEV-1 | Status page, Email, User channels | 30 min, then hourly |
| SEV-2 | Status page, User channels | 1 hour, then as needed |
| SEV-3 | Status page | Next business day |
| SEV-4 | None (unless requested) | None |

#### Communication Templates

**SEV-1 Initial Communication**
```
Subject: [SEV-1] Solid Sidecar Service Outage

We are currently investigating a service outage affecting Solid Sidecar.

Status: Investigating
Impact: All users
Start Time: [TIME]

We will provide updates every 30 minutes or as new information becomes available.

Next Update: [TIME + 30min]
```

**SEV-1 Update Communication**
```
Subject: [SEV-1 Update] Solid Sidecar Service Outage

We are continuing to investigate the service outage.

Status: [Investigating/Mitigating/Resolved]
Root Cause: [If identified]
Mitigation: [If applied]
ETA: [If available]

Previous Update: [TIME]
Next Update: [TIME + 30min]
```

**SEV-1 Resolution Communication**
```
Subject: [SEV-1 Resolved] Solid Sidecar Service Outage

The service outage has been resolved.

Status: Resolved
Root Cause: [Detailed explanation]
Resolution: [What was done]
Resolution Time: [TIME]
Duration: [DURATION]

A post-mortem will be published within 5 business days.
```


### 6. Post-Mortem

#### Post-Mortem Timeline

| Severity | Post-Mortem Due |
|----------|-----------------|
| SEV-1 | 5 business days |
| SEV-2 | 10 business days |
| SEV-3 | 15 business days |
| SEV-4 | Optional |

#### Post-Mortem Structure

```markdown
# Post-Mortem: [Incident Title]

## Incident Summary
- **Incident ID**: [ID]
- **Severity**: [SEV-X]
- **Start Time**: [TIME]
- **End Time**: [TIME]
- **Duration**: [DURATION]
- **Impact**: [Description]
- **Affected Users**: [Number/Percentage]

## Timeline
| Time | Event | Owner |
|------|-------|-------|
| [TIME] | [Event] | [Owner] |
| [TIME] | [Event] | [Owner] |

## Root Cause Analysis
[Detailed explanation of what caused the incident]

## Impact Assessment
- **User Impact**: [Description]
- **Business Impact**: [Description]
- **SLA Impact**: [Missed SLAs]

## Detection and Response
- **Detection**: [How was it detected]
- **Initial Response**: [Who responded and when]
- **Escalation**: [Escalation path]
- **Time to Detect**: [Duration]
- **Time to Acknowledge**: [Duration]
- **Time to Mitigate**: [Duration]
- **Time to Resolve**: [Duration]

## Lessons Learned
### What Went Well
- [Item 1]
- [Item 2]

### What Went Wrong
- [Item 1]
- [Item 2]

### Action Items
| ID | Action | Owner | Due Date | Status |
|----|--------|-------|----------|--------|
| 1 | [Action] | [Owner] | [Date] | Open |
| 2 | [Action] | [Owner] | [Date] | Open |

## Follow-Up
- [Follow-up items]
```

#### Post-Mortem Review Meeting

1. **Attendees**
   - Incident commander
   - All responders
   - Engineering manager
   - Relevant stakeholders

2. **Agenda**
   - Review timeline
   - Discuss root cause
   - Review action items
   - Assign owners and due dates

3. **Outcomes**
   - Approved action items
   - Assigned owners
   - Set due dates
   - Document decisions


## Incident Response Team

### On-Call Rotation

The on-call rotation ensures 24/7 coverage for SEV-1 incidents.

#### Rotation Schedule

| Week | Primary | Secondary | Manager |
|------|---------|----------|---------|
| Week 1 | Engineer A | Engineer B | Manager A |
| Week 2 | Engineer C | Engineer D | Manager A |
| Week 3 | Engineer E | Engineer F | Manager B |
| Week 4 | Engineer G | Engineer H | Manager B |

#### Contact Methods

| Role | Primary | Secondary | Escalation |
|------|---------|----------|------------|
| On-Call Engineer | Phone | Email | Slack |
| Backup Engineer | Phone | Email | Slack |
| Engineering Manager | Phone | Email | Slack |


### Escalation Path

```
User Report / Alert
    ↓
Triage (First Responder)
    ↓
SEV-1? → Page Primary On-Call
    ↓
No Response in 15min? → Page Secondary On-Call
    ↓
No Response in 30min? → Page Engineering Manager
    ↓
No Response in 45min? → Page Director
    ↓
No Response in 60min? → Page VP Engineering
```


## Incident Response Playbooks

### Playbook: Service Down

**Severity**: SEV-1

**Symptoms**:
- Sidecar not responding to requests
- All requests failing
- Container not running

**Immediate Actions**:
1. Check container status: `docker ps -a | grep solid-sidecar`
2. Check logs: `docker logs solid-sidecar-production`
3. Restart container: `docker compose -f docker-compose.production.yml restart solid-sidecar`
4. If restart fails, switch to pass-through mode
5. If pass-through fails, roll back to previous version
6. If all else fails, bypass sidecar at load balancer

**Escalation**: Page on-call engineer, then manager

**Communication**: Update status page within 30 minutes


### Playbook: High Error Rate

**Severity**: SEV-1 or SEV-2 (depending on rate)

**Symptoms**:
- Error rate > 10%
- 5xx responses increasing

**Immediate Actions**:
1. Check error rate by status code
2. Check recent deployments: `git log --oneline --since="1 hour ago"`
3. Check backend health: `curl -f http://css-production:3000/`
4. Enable debug logging
5. Check specific error patterns
6. Roll back if needed

**Escalation**: Page on-call engineer

**Communication**: Update status page within 1 hour


### Playbook: High Latency

**Severity**: SEV-2

**Symptoms**:
- P95 latency > 2s
- Slow responses

**Immediate Actions**:
1. Check latency metrics
2. Check resource usage: `docker stats`
3. Check for garbage collection pressure
4. Scale up if needed
5. Check for slow operations
6. Profile with pprof if needed

**Escalation**: Ticket during business hours

**Communication**: Update stakeholders


### Playbook: Authorization Mismatches

**Severity**: SEV-2 or SEV-3

**Symptoms**:
- AuthZ mismatch alerts firing
- Comparison harness reports mismatches

**Immediate Actions**:
1. Check mismatch metrics
2. Check comparison logs
3. Check policy cache invalidation
4. Compare with CSS directly
5. Review policy evaluation logic
6. Clear cache if needed

**Escalation**: Notify authz team

**Communication**: Internal notification


### Playbook: Fixture Sync Failures

**Severity**: SEV-2 or SEV-3

**Symptoms**:
- Fixture sync failure alerts
- Transport errors in logs

**Immediate Actions**:
1. Check sync failure metrics
2. Check transport logs
3. Test transport connectivity
4. Check network connectivity
5. Check authentication/permissions

**Escalation**: Notify platform team

**Communication**: Internal notification


### Playbook: Memory Leak

**Severity**: SEV-2

**Symptoms**:
- Memory usage steadily increasing
- OOM kills

**Immediate Actions**:
1. Check memory usage over time
2. Check for goroutine growth
3. Profile memory with pprof
4. Check cache size limits
5. Restart container to reclaim memory

**Escalation**: Notify platform team

**Communication**: Internal notification


## Incident Response Tools

### Monitoring
- **Prometheus**: `http://prometheus:9090`
- **Grafana**: `http://grafana:3001`
- **Alertmanager**: `http://alertmanager:9093`

### Logging
- **Logs**: `docker logs solid-sidecar-production`
- **ELK**: (If configured)
- **Loki**: (If configured)

### Tracing
- **Jaeger**: `http://jaeger:16686`

### Debugging
- **pprof**: `http://localhost:6060/debug/pprof` (If enabled)

### Configuration
- **Config File**: `configs/sidecar.production.yaml`
- **Docker Compose**: `deploy/compose/docker-compose.production.yml`


## Incident Metrics

### Key Metrics to Track

| Metric | Target | Description |
|--------|--------|-------------|
| Time to Detect (TTD) | < 5 min | Time from incident start to detection |
| Time to Acknowledge (TTA) | < 15 min | Time from detection to first response |
| Time to Mitigate (TTM) | < 1 hour | Time from detection to mitigation |
| Time to Resolve (TTR) | < 4 hours (SEV-1) | Time from detection to resolution |
| Mean Time Between Failures (MTBF) | Maximize | Average time between incidents |
| Mean Time To Recovery (MTTR) | Minimize | Average time to resolve incidents |

### Incident Classification Metrics

| Classification | Count | Percentage |
|---------------|-------|------------|
| SEV-1 | X | Y% |
| SEV-2 | X | Y% |
| SEV-3 | X | Y% |
| SEV-4 | X | Y% |


## Training and Exercises

### Incident Response Training

1. **Onboarding**
   - Review this document
   - Review runbook procedures
   - Shadow on-call engineer for 1 week

2. **Regular Training**
   - Quarterly incident response exercises
   - Annual tabletop exercises
   - Post-mortem review participation

3. **Certification**
   - Complete incident response training
   - Pass incident response quiz
   - Demonstrate proficiency in playbooks


### Incident Response Exercises

1. **Tabletop Exercises**
   - Scenario-based discussions
   - Test decision-making processes
   - Identify gaps in procedures

2. **Simulated Incidents**
   - Inject failures in staging
   - Practice response procedures
   - Test communication protocols

3. **Chaos Engineering**
   - Controlled failure injection
   - Test system resilience
   - Validate monitoring and alerting


## Incident Response Checklist

### SEV-1 Incident Checklist

- [ ] Acknowledge alert in Alertmanager
- [ ] Assess severity as SEV-1
- [ ] Page on-call engineer
- [ ] Create incident channel
- [ ] Create incident record
- [ ] Begin immediate mitigation
- [ ] Notify stakeholders
- [ ] Update status page (within 30 min)
- [ ] Assign incident commander
- [ ] Document all actions
- [ ] Identify root cause
- [ ] Apply mitigation
- [ ] Verify resolution
- [ ] Communicate resolution
- [ ] Schedule post-mortem
- [ ] Complete post-mortem (within 5 days)


### SEV-2 Incident Checklist

- [ ] Acknowledge alert
- [ ] Assess severity as SEV-2
- [ ] Page on-call engineer (business hours) or ticket
- [ ] Create incident channel
- [ ] Create incident record
- [ ] Begin investigation
- [ ] Notify stakeholders
- [ ] Update status page (within 1 hour)
- [ ] Document all actions
- [ ] Identify root cause
- [ ] Apply mitigation
- [ ] Verify resolution
- [ ] Communicate resolution
- [ ] Schedule post-mortem
- [ ] Complete post-mortem (within 10 days)


## Incident Response Documentation

### Related Documents

- [Production Runbook](./runbook-production.md) - Operational procedures
- [Phase 37: Production Deployment and Monitoring](../phase-37-production-deployment.md) - Phase documentation
- [Phase Implementation Roadmap](../phase-implementation-roadmap.md) - Project roadmap

### Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-07-04 | Mistral Vibe | Initial incident response documentation |
