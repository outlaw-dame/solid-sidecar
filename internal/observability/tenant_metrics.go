// Package observability provides production metrics for Solid Sidecar
// This file implements privacy-safe tenant metrics with cardinality controls for Phase 21.
package observability

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Privacy-safe tenant metrics that avoid exposing sensitive information
// These metrics use only safe, low-cardinality labels

// TenantRequestTotal counts requests per tenant with privacy-safe labels
var TenantRequestTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "requests_total",
		Help:      "Total number of requests per tenant",
	},
	[]string{"tenant_id"}, // Tenant ID is safe for operators to see
)

// TenantRequestDuration tracks request duration per tenant
var TenantRequestDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "request_duration_seconds",
		Help:      "Duration of requests per tenant in seconds",
		Buckets:   prometheus.DefBuckets,
	},
	[]string{"tenant_id"},
)

// TenantRequestErrors counts request errors per tenant with categorized error types
var TenantRequestErrors = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "request_errors_total",
		Help:      "Total number of request errors per tenant with categorized error types",
	},
	[]string{"tenant_id", "error_category"}, // error_category is safe (not raw error messages)
)

// TenantStorageUsage tracks storage usage per tenant
var TenantStorageUsage = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "storage_usage_bytes",
		Help:      "Storage usage per tenant in bytes",
	},
	[]string{"tenant_id"},
)

// TenantResourceCount tracks resource count per tenant with categorized resource types
var TenantResourceCount = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "resource_count",
		Help:      "Number of resources per tenant with categorized resource types",
	},
	[]string{"tenant_id", "resource_category"}, // resource_category is safe (not raw URIs)
)

// TenantActiveConnections tracks active connections per tenant
var TenantActiveConnections = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "active_connections",
		Help:      "Number of active connections per tenant",
	},
	[]string{"tenant_id"},
)

// TenantAuthEvents tracks authentication events per tenant
var TenantAuthEvents = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "auth_events_total",
		Help:      "Total number of authentication events per tenant with categorized event types",
	},
	[]string{"tenant_id", "auth_event_category", "status"}, // auth_event_category is safe
)

// TenantHealthStatus tracks health status per tenant
var TenantHealthStatus = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "health_status",
		Help:      "Health status per tenant (1 = healthy, 0 = unhealthy)",
	},
	[]string{"tenant_id"},
)

// TenantConfigReloads tracks configuration reloads per tenant
var TenantConfigReloads = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "config_reloads_total",
		Help:      "Total number of configuration reloads per tenant",
	},
	[]string{"tenant_id", "status"},
)

// TenantAuditLogs tracks audit log entries per tenant
var TenantAuditLogs = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "audit_logs_total",
		Help:      "Total number of audit log entries per tenant with categorized log levels and actions",
	},
	[]string{"tenant_id", "log_level", "action_category"}, // action_category is safe
)

// LabelCardinality tracks the cardinality of metric labels for monitoring
var LabelCardinality = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: "solid_sidecar",
		Subsystem: "tenant",
		Name:      "label_cardinality",
		Help:      "Current cardinality of metric labels",
	},
	[]string{"metric_name", "label_name"},
)

// CardinalityController manages label cardinality to prevent metrics explosion
type CardinalityController struct {
	mu sync.RWMutex

	// labelCounts tracks the number of unique values per label
	labelCounts map[string]map[string]bool

	// maxCardinality is the maximum allowed cardinality per label
	maxCardinality map[string]int

	// fallbackValues maps label names to fallback values when cardinality is exceeded
	fallbackValues map[string]string
}

// DefaultCardinalityController creates a new cardinality controller with safe defaults
func DefaultCardinalityController() *CardinalityController {
	return &CardinalityController{
		labelCounts:    make(map[string]map[string]bool),
		maxCardinality: make(map[string]int),
		fallbackValues: map[string]string{
			"tenant_id":           "other_tenant",
			"error_category":      "other_error",
			"resource_category":   "other_resource",
			"auth_event_category": "other_auth",
			"action_category":     "other_action",
			"status":              "unknown",
			"log_level":           "unknown",
		},
	}
}

// NewCardinalityController creates a new cardinality controller with specified limits
func NewCardinalityController(maxTenantLabels int) *CardinalityController {
	cc := DefaultCardinalityController()
	cc.maxCardinality["tenant_id"] = maxTenantLabels
	cc.maxCardinality["error_category"] = 20
	cc.maxCardinality["resource_category"] = 20
	cc.maxCardinality["auth_event_category"] = 15
	cc.maxCardinality["action_category"] = 15
	cc.maxCardinality["status"] = 5
	cc.maxCardinality["log_level"] = 6

	return cc
}

// SafeLabelValue returns a safe label value that respects cardinality limits
// If the cardinality limit for the label is exceeded, it returns the fallback value
func (cc *CardinalityController) SafeLabelValue(labelName string, value string) string {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Get the max cardinality for this label
	max, exists := cc.maxCardinality[labelName]
	if !exists {
		// If no limit is set, allow all values
		return value
	}

	// Initialize label tracking if needed
	if _, exists := cc.labelCounts[labelName]; !exists {
		cc.labelCounts[labelName] = make(map[string]bool)
	}

	labelValues := cc.labelCounts[labelName]

	// If we're at or over the limit and this is a new value, use fallback
	if len(labelValues) >= max {
		if _, exists := labelValues[value]; !exists {
			// New value would exceed limit, use fallback
			return cc.getFallbackValue(labelName)
		}
	}

	// Track this value
	labelValues[value] = true
	return value
}

// getFallbackValue returns the fallback value for a label
func (cc *CardinalityController) getFallbackValue(labelName string) string {
	if fallback, exists := cc.fallbackValues[labelName]; exists {
		return fallback
	}
	return "other"
}

// GetLabelCount returns the current number of unique values for a label
func (cc *CardinalityController) GetLabelCount(labelName string) int {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	if counts, exists := cc.labelCounts[labelName]; exists {
		return len(counts)
	}
	return 0
}

// ResetLabel resets the tracking for a specific label
func (cc *CardinalityController) ResetLabel(labelName string) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if _, exists := cc.labelCounts[labelName]; exists {
		cc.labelCounts[labelName] = make(map[string]bool)
	}
}

// ResetAll resets all label tracking
func (cc *CardinalityController) ResetAll() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.labelCounts = make(map[string]map[string]bool)
}

// Global cardinality controller
var globalCardinalityController = DefaultCardinalityController()

// SafeTenantID returns a safe tenant ID for use in metrics, respecting cardinality limits
func SafeTenantID(tenantID string) string {
	return globalCardinalityController.SafeLabelValue("tenant_id", tenantID)
}

// SafeErrorCategory maps raw error types to safe categories for metrics
func SafeErrorCategory(errorType string) string {
	return globalCardinalityController.SafeLabelValue("error_category", mapErrorTypeToCategory(errorType))
}

// SafeResourceCategory maps raw resource types to safe categories for metrics
func SafeResourceCategory(resourceType string) string {
	return globalCardinalityController.SafeLabelValue("resource_category", mapResourceTypeToCategory(resourceType))
}

// SafeAuthEventCategory maps raw auth event types to safe categories for metrics
func SafeAuthEventCategory(eventType string) string {
	return globalCardinalityController.SafeLabelValue("auth_event_category", mapAuthEventTypeToCategory(eventType))
}

// SafeActionCategory maps raw actions to safe categories for metrics
func SafeActionCategory(action string) string {
	return globalCardinalityController.SafeLabelValue("action_category", mapActionToCategory(action))
}

// SafeLogLevel maps raw log levels to safe categories for metrics
func SafeLogLevel(level string) string {
	return globalCardinalityController.SafeLabelValue("log_level", mapLogLevelToCategory(level))
}

// SafeStatus maps raw status values to safe categories for metrics
func SafeStatus(status string) string {
	return globalCardinalityController.SafeLabelValue("status", mapStatusToCategory(status))
}

// mapErrorTypeToCategory maps error types to safe categories
func mapErrorTypeToCategory(errorType string) string {
	lowerError := strings.ToLower(errorType)
	switch {
	case strings.Contains(lowerError, "not_found"), strings.Contains(lowerError, "404"):
		return "not_found"
	case strings.Contains(lowerError, "unauthorized"), strings.Contains(lowerError, "401"):
		return "unauthorized"
	case strings.Contains(lowerError, "forbidden"), strings.Contains(lowerError, "403"):
		return "forbidden"
	case strings.Contains(lowerError, "timeout"), strings.Contains(lowerError, "408"):
		return "timeout"
	case strings.Contains(lowerError, "rate_limit"), strings.Contains(lowerError, "429"):
		return "rate_limit"
	case strings.Contains(lowerError, "validation"), strings.Contains(lowerError, "400"):
		return "validation_error"
	case strings.Contains(lowerError, "server"), strings.Contains(lowerError, "5xx"):
		return "server_error"
	default:
		return "other_error"
	}
}

// mapAuthEventTypeToCategory maps auth event types to safe categories
func mapAuthEventTypeToCategory(eventType string) string {
	lowerEvent := strings.ToLower(eventType)
	switch {
	case strings.Contains(lowerEvent, "login"), strings.Contains(lowerEvent, "authenticate"):
		return "login"
	case strings.Contains(lowerEvent, "logout"):
		return "logout"
	case strings.Contains(lowerEvent, "token_refresh"), strings.Contains(lowerEvent, "refresh"):
		return "token_refresh"
	case strings.Contains(lowerEvent, "token_revoke"), strings.Contains(lowerEvent, "revoke"):
		return "token_revoke"
	case strings.Contains(lowerEvent, "dpop"):
		return "dpop_event"
	case strings.Contains(lowerEvent, "webid"):
		return "webid_event"
	case strings.Contains(lowerEvent, "sai"):
		return "sai_event"
	default:
		return "other_auth"
	}
}

// mapStatusToCategory maps status values to safe categories
func mapStatusToCategory(status string) string {
	switch strings.ToLower(status) {
	case "success", "200", "ok":
		return "success"
	case "failure", "error", "failed":
		return "failure"
	case "partial", "warning":
		return "partial"
	default:
		return "unknown"
	}
}

// mapLogLevelToCategory maps log levels to safe categories
func mapLogLevelToCategory(level string) string {
	switch strings.ToLower(level) {
	case "debug":
		return "debug"
	case "info":
		return "info"
	case "warn", "warning":
		return "warn"
	case "error":
		return "error"
	case "fatal":
		return "fatal"
	default:
		return "unknown"
	}
}

// mapResourceTypeToCategory maps resource types to safe categories
func mapResourceTypeToCategory(resourceType string) string {
	switch strings.ToLower(resourceType) {
	case "profile", "webid-profile":
		return "profile"
	case "container":
		return "container"
	case "resource":
		return "resource"
	case "acl":
		return "acl"
	case "policy":
		return "policy"
	case "storage":
		return "storage"
	case "config":
		return "config"
	case "audit":
		return "audit"
	default:
		return "other"
	}
}

// mapActionToCategory maps actions to safe categories
func mapActionToCategory(action string) string {
	switch strings.ToLower(action) {
	case "create", "post", "put":
		return "create"
	case "read", "get", "head":
		return "read"
	case "update", "patch":
		return "update"
	case "delete":
		return "delete"
	case "list":
		return "list"
	case "search":
		return "search"
	default:
		return "other"
	}
}

// SetMaxTenantLabels sets the maximum number of tenant labels allowed
func SetMaxTenantLabels(max int) {
	globalCardinalityController.mu.Lock()
	defer globalCardinalityController.mu.Unlock()
	globalCardinalityController.maxCardinality["tenant_id"] = max
}

// GetTenantLabelCount returns the current number of unique tenant labels
func GetTenantLabelCount() int {
	return globalCardinalityController.GetLabelCount("tenant_id")
}

// ResetGlobalCardinalityController resets the global cardinality controller
func ResetGlobalCardinalityController() {
	globalCardinalityController = DefaultCardinalityController()
}

// TenantMetrics provides a convenient interface for recording tenant metrics
// This wraps the global metrics with privacy-safe label handling
type TenantMetrics struct {
	// Cardinality controller for this instance
	cardinalityController *CardinalityController
}

// NewTenantMetrics creates a new tenant metrics instance
func NewTenantMetrics(maxTenantLabels int) *TenantMetrics {
	return &TenantMetrics{
		cardinalityController: NewCardinalityController(maxTenantLabels),
	}
}

// RecordRequest records a request metric for a tenant
func (tm *TenantMetrics) RecordRequest(tenantID string, duration float64, success bool, errorType string) {
	safeTenantID := tm.cardinalityController.SafeLabelValue("tenant_id", tenantID)
	TenantRequestTotal.WithLabelValues(safeTenantID).Inc()
	TenantRequestDuration.WithLabelValues(safeTenantID).Observe(duration)

	if !success {
		safeErrorCategory := tm.cardinalityController.SafeLabelValue("error_category", mapErrorTypeToCategory(errorType))
		TenantRequestErrors.WithLabelValues(safeTenantID, safeErrorCategory).Inc()
	}
}

// RecordStorageUsage records storage usage for a tenant
func (tm *TenantMetrics) RecordStorageUsage(tenantID string, bytesUsed float64) {
	safeTenantID := tm.cardinalityController.SafeLabelValue("tenant_id", tenantID)
	TenantStorageUsage.WithLabelValues(safeTenantID).Set(bytesUsed)
}

// RecordResourceCount records resource count for a tenant
func (tm *TenantMetrics) RecordResourceCount(tenantID string, resourceType string, count float64) {
	safeTenantID := tm.cardinalityController.SafeLabelValue("tenant_id", tenantID)
	safeResourceCategory := tm.cardinalityController.SafeLabelValue("resource_category", mapResourceTypeToCategory(resourceType))
	TenantResourceCount.WithLabelValues(safeTenantID, safeResourceCategory).Set(count)
}

// RecordConnectionCount records active connection count for a tenant
func (tm *TenantMetrics) RecordConnectionCount(tenantID string, count float64) {
	safeTenantID := tm.cardinalityController.SafeLabelValue("tenant_id", tenantID)
	TenantActiveConnections.WithLabelValues(safeTenantID).Set(count)
}

// RecordAuthEvent records an authentication event for a tenant
func (tm *TenantMetrics) RecordAuthEvent(tenantID string, eventType string, status string) {
	safeTenantID := tm.cardinalityController.SafeLabelValue("tenant_id", tenantID)
	safeEventCategory := tm.cardinalityController.SafeLabelValue("auth_event_category", mapAuthEventTypeToCategory(eventType))
	safeStatus := tm.cardinalityController.SafeLabelValue("status", mapStatusToCategory(status))
	TenantAuthEvents.WithLabelValues(safeTenantID, safeEventCategory, safeStatus).Inc()
}

// RecordHealthStatus records health status for a tenant
func (tm *TenantMetrics) RecordHealthStatus(tenantID string, healthy bool) {
	safeTenantID := tm.cardinalityController.SafeLabelValue("tenant_id", tenantID)
	statusValue := 1.0
	if !healthy {
		statusValue = 0.0
	}
	TenantHealthStatus.WithLabelValues(safeTenantID).Set(statusValue)
}

// RecordConfigReload records a configuration reload for a tenant
func (tm *TenantMetrics) RecordConfigReload(tenantID string, success bool) {
	safeTenantID := tm.cardinalityController.SafeLabelValue("tenant_id", tenantID)
	status := "success"
	if !success {
		status = "failure"
	}
	TenantConfigReloads.WithLabelValues(safeTenantID, status).Inc()
}

// RecordAuditLog records an audit log entry for a tenant
func (tm *TenantMetrics) RecordAuditLog(tenantID string, level string, action string) {
	safeTenantID := tm.cardinalityController.SafeLabelValue("tenant_id", tenantID)
	safeLevel := tm.cardinalityController.SafeLabelValue("log_level", mapLogLevelToCategory(level))
	safeAction := tm.cardinalityController.SafeLabelValue("action_category", mapActionToCategory(action))
	TenantAuditLogs.WithLabelValues(safeTenantID, safeLevel, safeAction).Inc()
}

// UpdateLabelCardinalityMetrics updates cardinality monitoring metrics
func (tm *TenantMetrics) UpdateLabelCardinalityMetrics() {
	// Update cardinality metrics for monitoring
	for labelName := range tm.cardinalityController.maxCardinality {
		count := tm.cardinalityController.GetLabelCount(labelName)
		LabelCardinality.WithLabelValues("tenant_metrics", labelName).Set(float64(count))
	}
}

// GetCardinalityWarning returns a warning if cardinality is approaching limits
func (tm *TenantMetrics) GetCardinalityWarning() string {
	for labelName, maxLimit := range tm.cardinalityController.maxCardinality {
		count := tm.cardinalityController.GetLabelCount(labelName)
		threshold := maxLimit * 8 / 10 // 80% threshold
		if count >= threshold {
			return "WARNING: Metric label cardinality approaching limit"
		}
	}
	return ""
}

// Global tenant metrics instance
var GlobalTenantMetrics *TenantMetrics

// InitGlobalTenantMetrics initializes the global tenant metrics
func InitGlobalTenantMetrics(maxTenantLabels int) {
	GlobalTenantMetrics = NewTenantMetrics(maxTenantLabels)
}

// GetGlobalTenantMetrics returns the global tenant metrics instance
func GetGlobalTenantMetrics() *TenantMetrics {
	return GlobalTenantMetrics
}

// NoOpTenantMetrics is a no-op implementation for when metrics are disabled
type NoOpTenantMetrics struct{}

func (n *NoOpTenantMetrics) RecordRequest(tenantID string, duration float64, success bool, errorType string) {
}
func (n *NoOpTenantMetrics) RecordStorageUsage(tenantID string, bytesUsed float64) {}
func (n *NoOpTenantMetrics) RecordResourceCount(tenantID string, resourceType string, count float64) {
}
func (n *NoOpTenantMetrics) RecordConnectionCount(tenantID string, count float64)             {}
func (n *NoOpTenantMetrics) RecordAuthEvent(tenantID string, eventType string, status string) {}
func (n *NoOpTenantMetrics) RecordHealthStatus(tenantID string, healthy bool)                 {}
func (n *NoOpTenantMetrics) RecordConfigReload(tenantID string, success bool)                 {}
func (n *NoOpTenantMetrics) RecordAuditLog(tenantID string, level string, action string)      {}
func (n *NoOpTenantMetrics) UpdateLabelCardinalityMetrics()                                   {}
func (n *NoOpTenantMetrics) GetCardinalityWarning() string                                    { return "" }

// NewNoOpTenantMetrics creates a new no-op tenant metrics instance
func NewNoOpTenantMetrics() *NoOpTenantMetrics {
	return &NoOpTenantMetrics{}
}
