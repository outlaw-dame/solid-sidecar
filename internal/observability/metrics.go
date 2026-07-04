// Package observability provides production metrics for Solid Sidecar
package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics initialization
func init() {
	// Ensure all metrics are registered
	_ = RequestDuration
	_ = RequestsTotal
	_ = AuthZDecisionsTotal
	_ = AuthZMismatchesTotal
	_ = PolicyEvaluationTime
	_ = CacheHitsTotal
	_ = CacheRequestsTotal
	_ = CacheHitRate
	_ = FixtureSyncTime
	_ = FixtureSyncFailuresTotal
	_ = TransportRequestsTotal
	_ = TransportFailuresTotal
	_ = ActiveSessions
	_ = SessionDuration
	_ = RateLimitRejectedTotal
	_ = CircuitBreakerState
	_ = PanicRecoveryTotal
	_ = GoroutinesCount
	_ = MemoryUsageBytes
	_ = GCDurationSeconds
}

// Request metrics
var (
	// RequestDuration tracks the duration of HTTP requests
	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "solid_sidecar",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "Duration of HTTP requests in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "path", "status_code", "authz_decision"},
	)

	// RequestsTotal counts the total number of HTTP requests
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status_code", "authz_decision"},
	)
)

// Authorization metrics
var (
	// AuthZDecisionsTotal counts authorization decisions
	AuthZDecisionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "authz",
			Name:      "decisions_total",
			Help:      "Total number of authorization decisions",
		},
		[]string{"decision", "policy_type", "transport_type"},
	)

	// AuthZMismatchesTotal counts authorization mismatches with CSS
	AuthZMismatchesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "authz",
			Name:      "mismatches_total",
			Help:      "Total number of authorization mismatches with CSS",
		},
		[]string{"mismatch_type", "policy_type"},
	)

	// PolicyEvaluationTime tracks the time to evaluate policies
	PolicyEvaluationTime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "solid_sidecar",
			Subsystem: "authz",
			Name:      "policy_evaluation_seconds",
			Help:      "Time to evaluate authorization policies in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
		},
		[]string{"policy_type", "decision"},
	)
)

// Cache metrics
var (
	// CacheHitsTotal counts cache hits
	CacheHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "cache",
			Name:      "hits_total",
			Help:      "Total number of cache hits",
		},
		[]string{"cache_type"},
	)

	// CacheRequestsTotal counts cache requests
	CacheRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "cache",
			Name:      "requests_total",
			Help:      "Total number of cache requests",
		},
		[]string{"cache_type"},
	)

	// CacheHitRate is the calculated cache hit rate (gauge)
	CacheHitRate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "solid_sidecar",
			Subsystem: "cache",
			Name:      "hit_rate",
			Help:      "Cache hit rate (0-1)",
		},
		[]string{"cache_type"},
	)
)

// Fixture distribution metrics
var (
	// FixtureSyncTime tracks the time to sync fixtures
	FixtureSyncTime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "solid_sidecar",
			Subsystem: "transport",
			Name:      "fixture_sync_seconds",
			Help:      "Time to sync fixtures from distribution transports in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.1, 2, 8), // 100ms to ~12s
		},
		[]string{"transport_type", "status"},
	)

	// FixtureSyncFailuresTotal counts fixture sync failures
	FixtureSyncFailuresTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "transport",
			Name:      "fixture_sync_failures_total",
			Help:      "Total number of fixture sync failures",
		},
		[]string{"transport_type", "failure_reason"},
	)

	// TransportRequestsTotal counts transport requests
	TransportRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "transport",
			Name:      "requests_total",
			Help:      "Total number of transport requests",
		},
		[]string{"transport_type", "operation", "status"},
	)

	// TransportFailuresTotal counts transport failures
	TransportFailuresTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "transport",
			Name:      "failures_total",
			Help:      "Total number of transport failures",
		},
		[]string{"transport_type", "operation", "failure_reason"},
	)
)

// Session metrics
var (
	// ActiveSessions tracks the number of active authenticated sessions
	ActiveSessions = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "solid_sidecar",
			Subsystem: "session",
			Name:      "active_sessions",
			Help:      "Number of active authenticated sessions",
		},
		[]string{"assurance_level"},
	)

	// SessionDuration tracks the duration of authenticated sessions
	SessionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "solid_sidecar",
			Subsystem: "session",
			Name:      "duration_seconds",
			Help:      "Duration of authenticated sessions in seconds",
			Buckets:   prometheus.ExponentialBuckets(60, 2, 10), // 1min to ~17hrs
		},
		[]string{"assurance_level"},
	)
)

// Safety metrics
var (
	// RateLimitRejectedTotal counts requests rejected by rate limiting
	RateLimitRejectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "safety",
			Name:      "rate_limit_rejected_total",
			Help:      "Total number of requests rejected by rate limiting",
		},
		[]string{"limit_type", "client_id"},
	)

	// CircuitBreakerState tracks the state of circuit breakers
	CircuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "solid_sidecar",
			Subsystem: "safety",
			Name:      "circuit_breaker_state",
			Help:      "State of circuit breaker (0=closed, 1=open, 2=half_open)",
		},
		[]string{"service", "circuit_breaker"},
	)

	// PanicRecoveryTotal counts the number of panic recoveries
	PanicRecoveryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "safety",
			Name:      "panic_recovery_total",
			Help:      "Total number of panic recoveries",
		},
		[]string{"component"},
	)
)

// Runtime metrics
var (
	// GoroutinesCount tracks the number of goroutines
	GoroutinesCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "solid_sidecar",
			Subsystem: "runtime",
			Name:      "goroutines",
			Help:      "Number of goroutines",
		},
	)

	// MemoryUsageBytes tracks memory usage
	MemoryUsageBytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "solid_sidecar",
			Subsystem: "runtime",
			Name:      "memory_usage_bytes",
			Help:      "Memory usage in bytes",
		},
		[]string{"memory_type"}, // heap, stack, total, etc.
	)

	// GCDurationSeconds tracks garbage collection duration
	GCDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "solid_sidecar",
			Subsystem: "runtime",
			Name:      "gc_duration_seconds",
			Help:      "Garbage collection duration in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 8), // 1ms to ~128ms
		},
		[]string{},
	)
)

// Metric recording helper functions

// RecordRequestDuration records the duration of an HTTP request
func RecordRequestDuration(method, path, statusCode, authzDecision string, durationSeconds float64) {
	RequestDuration.WithLabelValues(method, path, statusCode, authzDecision).Observe(durationSeconds)
}

// RecordRequest counts an HTTP request
func RecordRequest(method, path, statusCode, authzDecision string) {
	RequestsTotal.WithLabelValues(method, path, statusCode, authzDecision).Inc()
}

// RecordAuthZDecision records an authorization decision
func RecordAuthZDecision(decision, policyType, transportType string) {
	AuthZDecisionsTotal.WithLabelValues(decision, policyType, transportType).Inc()
}

// RecordAuthZMismatch records an authorization mismatch
func RecordAuthZMismatch(mismatchType, policyType string) {
	AuthZMismatchesTotal.WithLabelValues(mismatchType, policyType).Inc()
}

// RecordPolicyEvaluationTime records policy evaluation time
func RecordPolicyEvaluationTime(policyType, decision string, durationSeconds float64) {
	PolicyEvaluationTime.WithLabelValues(policyType, decision).Observe(durationSeconds)
}

// RecordCacheHit records a cache hit
func RecordCacheHit(cacheType string) {
	CacheHitsTotal.WithLabelValues(cacheType).Inc()
}

// RecordCacheRequest records a cache request
func RecordCacheRequest(cacheType string) {
	CacheRequestsTotal.WithLabelValues(cacheType).Inc()
}

// UpdateCacheHitRate updates the cache hit rate gauge
func UpdateCacheHitRate(cacheType string, hitRate float64) {
	CacheHitRate.WithLabelValues(cacheType).Set(hitRate)
}

// RecordFixtureSync records a fixture sync operation
func RecordFixtureSync(transportType, status string, durationSeconds float64) {
	FixtureSyncTime.WithLabelValues(transportType, status).Observe(durationSeconds)
}

// RecordFixtureSyncFailure records a fixture sync failure
func RecordFixtureSyncFailure(transportType, failureReason string) {
	FixtureSyncFailuresTotal.WithLabelValues(transportType, failureReason).Inc()
}

// RecordTransportRequest records a transport request
func RecordTransportRequest(transportType, operation, status string) {
	TransportRequestsTotal.WithLabelValues(transportType, operation, status).Inc()
}

// RecordTransportFailure records a transport failure
func RecordTransportFailure(transportType, operation, failureReason string) {
	TransportFailuresTotal.WithLabelValues(transportType, operation, failureReason).Inc()
}

// IncrementActiveSessions increments the active sessions count
func IncrementActiveSessions(assuranceLevel string) {
	ActiveSessions.WithLabelValues(assuranceLevel).Inc()
}

// DecrementActiveSessions decrements the active sessions count
func DecrementActiveSessions(assuranceLevel string) {
	ActiveSessions.WithLabelValues(assuranceLevel).Dec()
}

// RecordSessionDuration records a session duration
func RecordSessionDuration(assuranceLevel string, durationSeconds float64) {
	SessionDuration.WithLabelValues(assuranceLevel).Observe(durationSeconds)
}

// RecordRateLimitRejected records a rate-limited request
func RecordRateLimitRejected(limitType, clientID string) {
	RateLimitRejectedTotal.WithLabelValues(limitType, clientID).Inc()
}

// UpdateCircuitBreakerState updates the circuit breaker state
func UpdateCircuitBreakerState(service, circuitBreaker string, state int) {
	CircuitBreakerState.WithLabelValues(service, circuitBreaker).Set(float64(state))
}

// RecordPanicRecovery records a panic recovery
func RecordPanicRecovery(component string) {
	PanicRecoveryTotal.WithLabelValues(component).Inc()
}

// UpdateGoroutinesCount updates the goroutines count
func UpdateGoroutinesCount(count int) {
	GoroutinesCount.Set(float64(count))
}

// UpdateMemoryUsage updates memory usage metrics
func UpdateMemoryUsage(memoryType string, bytes uint64) {
	MemoryUsageBytes.WithLabelValues(memoryType).Set(float64(bytes))
}

// RecordGCDuration records garbage collection duration
func RecordGCDuration(durationSeconds float64) {
	GCDurationSeconds.WithLabelValues().Observe(durationSeconds)
}

// MetricsHandler returns the HTTP handler for metrics endpoint
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// RegisterCustomMetrics registers additional custom metrics
func RegisterCustomMetrics(collectors ...prometheus.Collector) error {
	for _, collector := range collectors {
		if err := prometheus.Register(collector); err != nil {
			return err
		}
	}
	return nil
}

// UnregisterMetrics unregisters all metrics (useful for testing)
func UnregisterMetrics() {
	prometheus.Unregister(RequestDuration)
	prometheus.Unregister(RequestsTotal)
	prometheus.Unregister(AuthZDecisionsTotal)
	prometheus.Unregister(AuthZMismatchesTotal)
	prometheus.Unregister(PolicyEvaluationTime)
	prometheus.Unregister(CacheHitsTotal)
	prometheus.Unregister(CacheRequestsTotal)
	prometheus.Unregister(CacheHitRate)
	prometheus.Unregister(FixtureSyncTime)
	prometheus.Unregister(FixtureSyncFailuresTotal)
	prometheus.Unregister(TransportRequestsTotal)
	prometheus.Unregister(TransportFailuresTotal)
	prometheus.Unregister(ActiveSessions)
	prometheus.Unregister(SessionDuration)
	prometheus.Unregister(RateLimitRejectedTotal)
	prometheus.Unregister(CircuitBreakerState)
	prometheus.Unregister(PanicRecoveryTotal)
	prometheus.Unregister(GoroutinesCount)
	prometheus.Unregister(MemoryUsageBytes)
	prometheus.Unregister(GCDurationSeconds)
}
