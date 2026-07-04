# Phase 37: Production Deployment and Monitoring

## Overview

Phase 37 focuses on deploying solid-sidecar to production with full monitoring, alerting, and incident response capabilities. This phase builds upon Phase 36 (Staging Deployment) and ensures that the sidecar can be safely and reliably deployed to production environments.

This phase addresses the repository audit requirement for "production deployment planning" and "full monitoring implementation."

## Goals

1. **Production Deployment Planning**: Create comprehensive deployment plan for production
2. **Full Monitoring Implementation**: Deploy complete monitoring stack with metrics, logs, and traces
3. **Alerting and Incident Response**: Set up alerting rules and incident response procedures
4. **Production Rollout**: Execute controlled production rollout with canary and gradual rollout

## Implementation Scope

### 1. Production Deployment Planning

#### Deployment Strategy
- **Blue/Green Deployment**: Zero-downtime deployment with instant rollback capability
- **Canary Deployment**: Gradual traffic shift to new versions (1%, 5%, 25%, 50%, 100%)
- **Rolling Updates**: In-place updates with health checks
- **Feature Flags**: Enable/disable features without deployment

#### Production Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                        Load Balancer                          │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────────────────┐  │
│  │  Canary (5%) │  │  Stable     │  │  Legacy CSS Direct      │  │
│  │  Sidecar    │  │  Sidecar    │  │  (Gradual Migration)    │  │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬───────────┘  │
└─────────┼──────────────────┼─────────────────────────┼─────────────┘
          │                  │                         │
          ▼                  ▼                         ▼
┌─────────────────────────────────────────────────────────────┐
│                     Community Solid Server                     │
│  ┌─────────────────────────┐                                  │
│  │       Pod/Container      │                                  │
│  └─────────────────────────┘                                  │
└─────────────────────────────────────────────────────────────┘
```

#### Production Configuration
Production configuration with all features enabled and hardened:

```yaml
# configs/sidecar.production.yaml
gateway:
  listen_addr: ":443"
  backend_url: "http://css-production:3000"
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/solid-sidecar.crt"
    key_file: "/etc/ssl/private/solid-sidecar.key"
    client_auth: optional  # For mutual TLS if needed

authz:
  mode: shadow  # Start in shadow mode, transition to enforce after validation
  cache:
    enabled: true
    ttl: 5m
    max_size: 10000

authn:
  enabled: true
  allowed_issuers:
    - "https://production-issuer.example.org"
    - "https://backup-issuer.example.org"
  required_assurance: high

transport:
  fixture_distribution:
    enabled: true
    transports:
      http:
        enabled: true
        base_url: "https://fixture-dist.example.org"
        timeout: 30s
        retries: 3
      s3:
        enabled: true
        bucket: "solid-fixtures-production"
        region: "us-east-1"
        ssrf_protection: true
      ssh:
        enabled: true
        host: "fixture-server.example.org"
        port: 22
        username: "fixture-user"
        strict_host_key_checking: true
        known_hosts_file: "/etc/solid/ssh_known_hosts"
      local:
        enabled: false  # Disabled in production

observability:
  metrics:
    enabled: true
    endpoint: "http://prometheus-production:9090/api/v1/write"
    interval: 15s
    include_defaults: true
    custom:
      - name: sidecar_request_duration_seconds
        type: histogram
        buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
      - name: sidecar_requests_total
        type: counter
        labels: [method, path, status_code, authz_decision]
      - name: sidecar_authz_decisions_total
        type: counter
        labels: [decision, policy_type, transport_type]
  logging:
    level: info
    format: json
    output: stdout
    include:
      - request_id
      - correlation_id
      - agent_identity_hash  # Privacy-safe, no PII
  tracing:
    enabled: true
    sample_rate: 0.1  # 10% of requests
    endpoint: "http://jaeger-production:14268/api/traces"

rate_limit:
  enabled: true
  global:
    requests_per_second: 1000
    burst_size: 100
  per_ip:
    requests_per_second: 100
    burst_size: 20

safety:
  circuit_breaker:
    enabled: true
    error_threshold: 0.5  # 50% error rate
    reset_timeout: 30s
  panic_recovery:
    enabled: true
    stack_trace_logging: true

feature_flags:
  enforce_authz: false  # Will be enabled after validation
  sae_support: false    # Will be enabled after Phase 38
```

#### Kubernetes Deployment (Optional)
If deploying to Kubernetes:

```yaml
# deploy/k8s/sidecar-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: solid-sidecar
  labels:
    app: solid-sidecar
    version: v1.0.0
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 15%
  selector:
    matchLabels:
      app: solid-sidecar
  template:
    metadata:
      labels:
        app: solid-sidecar
        version: v1.0.0
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      containers:
      - name: solid-sidecar
        image: ghcr.io/outlaw-dame/solid-sidecar:v1.0.0
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 443
          name: https
        - containerPort: 9090
          name: metrics
        env:
        - name: SIDECARE_CONFIG
          value: "/etc/solid/config.yaml"
        - name: SIDECARE_LOG_LEVEL
          value: "info"
        volumeMounts:
        - name: config
          mountPath: /etc/solid
          readOnly: true
        - name: tls
          mountPath: /etc/ssl
          readOnly: true
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 9090
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: solid-sidecar-config
      - name: tls
        secret:
          secretName: solid-sidecar-tls
```

### 2. Full Monitoring Implementation

#### Metrics Collection
Build upon Phase 35 monitoring to add production-specific metrics:

```go
// internal/observability/metrics.go additions
package observability

// Production-specific metrics
var (
    // Business metrics
    ActiveSessions = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "solid_sidecar_active_sessions",
            Help: "Number of active authenticated sessions",
        },
        []string{"assurance_level"},
    )

    SessionDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "solid_sidecar_session_duration_seconds",
            Help:    "Duration of authenticated sessions",
            Buckets: prometheus.ExponentialBuckets(60, 2, 10), // 1min to ~17hrs
        },
        []string{"assurance_level"},
    )

    PolicyEvaluationTime = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "solid_sidecar_policy_evaluation_seconds",
            Help:    "Time to evaluate authorization policies",
            Buckets: prometheus.DefBuckets,
        },
        []string{"policy_type", "decision"},
    )

    FixtureSyncTime = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "solid_sidecar_fixture_sync_seconds",
            Help:    "Time to sync fixtures from distribution transports",
            Buckets: prometheus.ExponentialBuckets(0.1, 2, 8), // 100ms to ~12s
        },
        []string{"transport_type", "status"},
    )
)

func init() {
    prometheus.MustRegister(
        ActiveSessions,
        SessionDuration,
        PolicyEvaluationTime,
        FixtureSyncTime,
    )
}
```

#### Alerting Rules
Production alerting rules for Prometheus Alertmanager:

```yaml
# configs/monitoring/alert-rules.yaml
groups:
- name: solid-sidecar-alerts
  rules:

  # Critical Alerts - Page on-call
  - alert: SidecarDown
    expr: up{job="solid-sidecar"} == 0
    for: 5m
    labels:
      severity: critical
      category: availability
    annotations:
      summary: "Solid Sidecar is down"
      description: "{{ $labels.instance }} has been down for more than 5 minutes"

  - alert: HighErrorRate
    expr: rate(http_requests_total{job="solid-sidecar", status_code=~"5.."}[5m]) / rate(http_requests_total{job="solid-sidecar"}[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
      category: errors
    annotations:
      summary: "High error rate for Solid Sidecar"
      description: "{{ $labels.instance }} has error rate of {{ $value }}%

  - alert: HighLatency
    expr: histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{job="solid-sidecar"}[5m])) by (le)) > 2
    for: 10m
    labels:
      severity: critical
      category: performance
    annotations:
      summary: "High latency for Solid Sidecar"
      description: "{{ $labels.instance }} has 95th percentile latency of {{ $value }}s"

  - alert: MemoryHigh
    expr: (node_memory_working_set_bytes{job="node-exporter"} / node_memory_total_bytes{job="node-exporter"}) * 100 > 90
    for: 10m
    labels:
      severity: warning
      category: resources
    annotations:
      summary: "High memory usage"
      description: "{{ $labels.instance }} has memory usage of {{ $value }}%"

  # Warning Alerts - Ticket
  - alert: AuthZMismatchDetected
    expr: increase(solid_sidecar_authz_mismatches_total[5m]) > 0
    labels:
      severity: warning
      category: correctness
    annotations:
      summary: "Authorization mismatch detected"
      description: "{{ $labels.instance }} detected {{ $value }} authz mismatches in last 5m"

  - alert: FixtureSyncFailure
    expr: increase(solid_sidecar_fixture_sync_failures_total[5m]) > 0
    labels:
      severity: warning
      category: data
    annotations:
      summary: "Fixture sync failure"
      description: "{{ $labels.instance }} had {{ $value }} fixture sync failures"

  - alert: LowCacheHitRate
    expr: rate(solid_sidecar_cache_hits_total[5m]) / rate(solid_sidecar_cache_requests_total[5m]) < 0.5
    for: 15m
    labels:
      severity: warning
      category: performance
    annotations:
      summary: "Low cache hit rate"
      description: "{{ $labels.instance }} cache hit rate is {{ $value }}"
```

#### Dashboards
Production dashboards for Grafana:

1. **Overview Dashboard**: High-level health, request rates, error rates
2. **Authorization Dashboard**: Policy evaluations, decisions, cache stats
3. **Transport Dashboard**: Fixture distribution, transport-specific metrics
4. **Performance Dashboard**: Latency, throughput, resource usage
5. **Safety Dashboard**: Circuit breakers, rate limits, panic recovery

#### Logging
Structured logging with correlation IDs:

```go
// internal/observability/logging.go
package observability

import (
    "context"
    "github.com/sirupsen/logrus"
)

type contextKey string

const (
    correlationIDKey contextKey = "correlation_id"
    requestIDKey     contextKey = "request_id"
)

func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
    return context.WithValue(ctx, correlationIDKey, correlationID)
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
    return context.WithValue(ctx, requestIDKey, requestID)
}

func GetLogger(ctx context.Context) *logrus.Entry {
    logger := logrus.New()
    
    if correlationID, ok := ctx.Value(correlationIDKey).(string); ok {
        logger = logger.WithField("correlation_id", correlationID)
    }
    if requestID, ok := ctx.Value(requestIDKey).(string); ok {
        logger = logger.WithField("request_id", requestID)
    }
    
    return logger
}

// Middleware to add request ID and correlation ID
func LoggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        requestID := r.Header.Get("X-Request-ID")
        if requestID == "" {
            requestID = uuid.New().String()
        }
        
        correlationID := r.Header.Get("X-Correlation-ID")
        if correlationID == "" {
            correlationID = requestID
        }
        
        ctx := context.WithValue(r.Context(), requestIDKey, requestID)
        ctx = context.WithValue(ctx, correlationIDKey, correlationID)
        
        logger := GetLogger(ctx)
        logger.Info("Request started")
        
        next.ServeHTTP(w, r.WithContext(ctx))
        
        logger.Info("Request completed")
    })
}
```

#### Distributed Tracing
OpenTelemetry tracing integration:

```go
// internal/observability/tracing.go
package observability

import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/jaeger"
    "go.opentelemetry.io/otel/sdk/resource"
    "go.opentelemetry.io/otel/sdk/trace"
    semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

func InitTracer(serviceName, endpoint string) (*trace.TracerProvider, error) {
    exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(endpoint)))
    if err != nil {
        return nil, err
    }
    
    tp := trace.NewTracerProvider(
        trace.WithBatcher(exp),
        trace.WithResource(resource.NewWithAttributes(
            semconv.SchemaURL,
            semconv.ServiceName(serviceName),
            semconv.ServiceVersion("1.0.0"),
        )),
        trace.WithSampler(trace.ParentBased(trace.TraceIDRatioBased(0.1))),
    )
    
    otel.SetTracerProvider(tp)
    return tp, nil
}
```

### 3. Alerting and Incident Response

#### Incident Response Procedures

```markdown
# Solid Sidecar Incident Response Runbook

## Severity Levels

### SEV-1 (Critical)
- Sidecar completely unavailable
- Data loss or corruption
- Security breach
- Response time: 15 minutes (24/7)

### SEV-2 (High)
- Significant performance degradation
- Partial outage affecting major functionality
- High error rates (>10%)
- Response time: 1 hour (business hours) / 4 hours (off-hours)

### SEV-3 (Medium)
- Minor functionality issues
- Performance degradation but still functional
- Low error rates (1-10%)
- Response time: 4 hours (business hours)

### SEV-4 (Low)
- Cosmetic issues
- Non-critical features broken
- Response time: Next business day

## Incident Response Playbooks

### Playbook: Sidecar Down
1. Check health endpoints: `/health/live`, `/health/ready`
2. Check container logs: `kubectl logs -l app=solid-sidecar`
3. Check resource usage: CPU, memory, disk
4. Restart containers if needed
5. Escalate to engineering if issue persists

### Playbook: High Error Rate
1. Check error metrics in Prometheus/Grafana
2. Check recent deployments/changes
3. Check for upstream CSS issues
4. Check fixture distribution health
5. Enable debug logging if needed
6. Roll back to previous version if needed

### Playbook: Authorization Mismatch
1. Check authz mismatch metrics
2. Review recent policy changes
3. Compare with CSS directly
4. Check comparison harness logs
5. Escalate to authz team if needed

### Playbook: Performance Degradation
1. Check latency metrics (P50, P95, P99)
2. Check resource usage (CPU, memory)
3. Check for garbage collection pressure
4. Check database/query performance
5. Scale up replicas if needed
```

#### On-Call Rotation
- Primary on-call: 24/7 rotation
- Secondary on-call: Business hours backup
- Escalation path: Engineering manager -> Director

#### Incident Communication
- Incident channel: `#solid-sidecar-incidents`
- Status page: Updates for major incidents
- Post-mortem: Within 5 business days for SEV-1/2

### 4. Production Rollout

#### Rollout Plan

**Phase 1: Canary (1% of traffic)**
- Duration: 1 hour
- Monitoring: Real-time metrics, error rates, latency
- Criteria to proceed: <0.1% error rate, <10% latency increase

**Phase 2: Limited (5% of traffic)**
- Duration: 4 hours
- Monitoring: All metrics, alerts configured
- Criteria to proceed: <0.1% error rate, <5% latency increase

**Phase 3: Partial (25% of traffic)**
- Duration: 1 day
- Monitoring: Full observability
- Criteria to proceed: <0.1% error rate, no latency increase

**Phase 4: Majority (50% of traffic)**
- Duration: 1 day
- Monitoring: Full observability
- Criteria to proceed: <0.01% error rate, no issues

**Phase 5: Full (100% of traffic)**
- Duration: Permanent
- Monitoring: Full observability
- Rollback: Always available within 5 minutes

#### Rollout Checklist
- [ ] All Phase 36 acceptance criteria met
- [ ] Production configuration validated
- [ ] Monitoring and alerting configured
- [ ] On-call team notified
- [ ] Rollback procedure tested
- [ ] Feature flags configured (shadow mode initially)
- [ ] Load testing completed
- [ ] Security review completed
- [ ] Documentation updated
- [ ] Stakeholders notified

#### Enforcement Mode Transition
Transition from shadow mode to enforcement mode:

1. **Shadow Mode**: Sidecar processes requests but doesn't enforce (Phase 36)
2. **Audit Mode**: Sidecar enforces but logs all decisions for comparison
3. **Enforce Mode**: Sidecar fully enforces authorization decisions

Transition criteria:
- Shadow to Audit: 100% match rate for 24 hours
- Audit to Enforce: 100% match rate for 7 days, no SEV-2+ incidents

## Files to Create/Modify

1. [ ] `configs/sidecar.production.yaml` - Production configuration
2. [ ] `deploy/k8s/sidecar-deployment.yaml` - Kubernetes deployment (if applicable)
3. [ ] `deploy/compose/docker-compose.production.yml` - Production Docker Compose
4. [ ] `configs/monitoring/alert-rules.yaml` - Alerting rules
5. [ ] `docs/runbook-production.md` - Production runbook
6. [ ] `docs/incident-response.md` - Incident response procedures
7. [ ] `internal/observability/metrics.go` - Additional production metrics
8. [ ] `internal/observability/logging.go` - Structured logging with correlation
9. [ ] `internal/observability/tracing.go` - Distributed tracing
10. [ ] `internal/observability/health.go` - Enhanced health checks

## Dependencies

- Phase 36: Staging Deployment and Traffic Comparison (COMPLETE)
- Phase 35: Performance Testing, Security Hardening, and Monitoring (COMPLETE)
- Kubernetes cluster (if using K8s)
- Prometheus/Grafana for metrics
- Jaeger/Zipkin for tracing
- ELK/Loki for logging
- Alertmanager for alerting
- Production CSS instance
- Load balancer or ingress controller

## Acceptance Criteria for Phase 37 Completion

### Must Have
- [ ] Production deployment plan documented
- [ ] Production configuration created and validated
- [ ] Full monitoring stack deployed (metrics, logs, traces)
- [ ] Alerting rules configured with appropriate thresholds
- [ ] Incident response procedures documented
- [ ] Canary deployment mechanism working
- [ ] Rollback procedures tested in production
- [ ] On-call rotation established
- [ ] All production tests passing

### Should Have
- [ ] Kubernetes deployment manifests (if applicable)
- [ ] Production dashboards in Grafana
- [ ] SLOs and error budgets defined
- [ ] Capacity planning completed
- [ ] Disaster recovery procedures documented

### Nice to Have
- [ ] Blue/green deployment setup
- [ ] Automated rollback detection
- [ ] Performance regression alerts
- [ ] Automated canary analysis
- [ ] SLO-based alerting

## Stop Conditions

Pause implementation if any of these occur:
- Production deployment plan cannot be finalized
- Monitoring stack cannot be deployed
- Alerting rules cannot be agreed upon
- Incident response procedures cannot be established
- Canary deployment fails acceptance criteria
- Rollback testing fails

## Next Phase

After Phase 37 completes, proceed to Phase 38: Security Audit and Formal Hardening

## Related Documents

- `docs/phase-36-staging-deployment.md` - Previous phase
- `docs/phase-35-performance-and-hardening.md` - Performance and hardening
- `docs/rollback-procedure.md` - Rollback procedures
- `docs/runbook-staging.md` - Staging runbook
- `docs/solid-platform-maturity-phases.md` - Platform maturity phases
