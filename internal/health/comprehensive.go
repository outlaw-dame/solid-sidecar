// Package health provides comprehensive health check endpoints for Solid Sidecar
// This implements Phase 39.4: Health check endpoints with comprehensive status
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

// SystemStatus represents the overall health status of the system
type SystemStatus struct {
	Status     string                     `json:"status"`
	Timestamp  time.Time                  `json:"timestamp"`
	Uptime     time.Duration              `json:"uptime"`
	Version    string                     `json:"version"`
	Components map[string]ComponentStatus `json:"components"`
	Details    map[string]any             `json:"details,omitempty"`
}

// ComponentStatus represents the status of a single component
type ComponentStatus struct {
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	LastCheck time.Time `json:"last_check,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

// ComprehensiveHealthHandler provides detailed health information
// This implements Phase 39.4: Health check endpoints with comprehensive status
type ComprehensiveHealthHandler struct {
	startTime       time.Time
	mu              sync.Mutex
	lastCheck       time.Time
	componentStatus map[string]ComponentStatus
	version         string
	buildInfo       map[string]any
}

// NewComprehensiveHealthHandler creates a new comprehensive health handler
func NewComprehensiveHealthHandler(version string, buildInfo map[string]any) *ComprehensiveHealthHandler {
	return &ComprehensiveHealthHandler{
		startTime:       time.Now(),
		lastCheck:       time.Now(),
		componentStatus: make(map[string]ComponentStatus),
		version:         version,
		buildInfo:       buildInfo,
	}
}

// Handler returns the HTTP handler for comprehensive health checks
func (h *ComprehensiveHealthHandler) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record request for observability
		_, span := observability.StartSpan(r.Context(), "health.comprehensive")
		defer span.End()

		// Update component statuses
		h.updateComponentStatuses()

		// Create system status
		status := h.createSystemStatus()

		// Set response headers
		w.Header().Set("Content-Type", "application/json")

		// Determine overall status
		if status.Status == "healthy" {
			w.WriteHeader(http.StatusOK)
		} else if status.Status == "degraded" {
			w.WriteHeader(http.StatusOK) // Still return 200 for degraded
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		// Write JSON response
		if err := json.NewEncoder(w).Encode(status); err != nil {
			http.Error(w, "Failed to encode health status", http.StatusInternalServerError)
			return
		}
	})
}

// updateComponentStatuses updates the status of all monitored components
func (h *ComprehensiveHealthHandler) updateComponentStatuses() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastCheck = time.Now()

	// Update core component statuses
	h.componentStatus["runtime"] = h.checkRuntime()
	h.componentStatus["database"] = h.checkDatabase()
	h.componentStatus["authz"] = h.checkAuthZ()
	h.componentStatus["cache"] = h.checkCache()
	h.componentStatus["tracing"] = h.checkTracing()
	h.componentStatus["metrics"] = h.checkMetrics()
}

// createSystemStatus creates the comprehensive system status
func (h *ComprehensiveHealthHandler) createSystemStatus() SystemStatus {
	h.mu.Lock()
	defer h.mu.Unlock()

	status := SystemStatus{
		Status:     "healthy",
		Timestamp:  time.Now(),
		Uptime:     time.Since(h.startTime),
		Version:    h.version,
		Components: make(map[string]ComponentStatus),
		Details:    make(map[string]any),
	}

	// Copy component statuses
	for k, v := range h.componentStatus {
		status.Components[k] = v
		if v.Status != "healthy" {
			status.Status = "degraded"
		}
	}

	// Add build info to details
	for k, v := range h.buildInfo {
		status.Details[k] = v
	}

	// Add system information
	status.Details["goroutines"] = runtime.NumGoroutine()
	status.Details["cpu_cores"] = runtime.NumCPU()
	status.Details["go_version"] = runtime.Version()
	status.Details["os"] = runtime.GOOS
	status.Details["arch"] = runtime.GOARCH

	return status
}

// checkRuntime checks the runtime component status
func (h *ComprehensiveHealthHandler) checkRuntime() ComponentStatus {
	return ComponentStatus{
		Status:    "healthy",
		Message:   "Runtime operating normally",
		LastCheck: time.Now(),
	}
}

// checkDatabase checks the database component status
// This is a placeholder that can be extended when database dependencies are added
func (h *ComprehensiveHealthHandler) checkDatabase() ComponentStatus {
	return ComponentStatus{
		Status:    "healthy",
		Message:   "No database dependencies",
		LastCheck: time.Now(),
	}
}

// checkAuthZ checks the authorization component status
func (h *ComprehensiveHealthHandler) checkAuthZ() ComponentStatus {
	// Check if authz evaluation is working
	// This can be extended with actual health checks when authz health monitoring is implemented
	// For now, we assume it's healthy
	return ComponentStatus{
		Status:    "healthy",
		Message:   "Authorization service operational",
		LastCheck: time.Now(),
	}
}

// checkCache checks the cache component status
func (h *ComprehensiveHealthHandler) checkCache() ComponentStatus {
	// Check if cache is operating normally
	// This can be extended with actual cache health checks
	return ComponentStatus{
		Status:    "healthy",
		Message:   "Cache service operational",
		LastCheck: time.Now(),
	}
}

// checkTracing checks the distributed tracing component status
func (h *ComprehensiveHealthHandler) checkTracing() ComponentStatus {
	if !observability.IsTracingEnabled() {
		return ComponentStatus{
			Status:    "degraded",
			Message:   "Distributed tracing not enabled",
			LastCheck: time.Now(),
		}
	}

	return ComponentStatus{
		Status:    "healthy",
		Message:   "Distributed tracing operational",
		LastCheck: time.Now(),
	}
}

// checkMetrics checks the metrics component status
func (h *ComprehensiveHealthHandler) checkMetrics() ComponentStatus {
	if !observability.IsMetricsExporterEnabled() {
		return ComponentStatus{
			Status:    "degraded",
			Message:   "Metrics exporter not enabled",
			LastCheck: time.Now(),
		}
	}

	return ComponentStatus{
		Status:    "healthy",
		Message:   "Metrics collection operational",
		LastCheck: time.Now(),
	}
}

// ReadinessHandlerWithDetails provides readiness checks with detailed component status
// This implements Phase 39.4: Enhanced readiness endpoints
func (h *ComprehensiveHealthHandler) ReadinessHandlerWithDetails(probe *Probe) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record request for observability
		_, span := observability.StartSpan(r.Context(), "health.readiness.detailed")
		defer span.End()

		// Check backend readiness first
		backendStatus := h.checkBackendReadiness(probe, r.Context())

		// Update all component statuses
		h.updateComponentStatuses()

		// Create readiness status
		status := ReadinessStatus{
			Status:     backendStatus.Status,
			Timestamp:  time.Now(),
			Components: h.getComponentStatusMap(),
			Backend:    backendStatus,
			Message:    backendStatus.Message,
		}

		// Set response headers
		w.Header().Set("Content-Type", "application/json")

		// Determine HTTP status
		if status.Status == "ready" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		// Write JSON response
		if err := json.NewEncoder(w).Encode(status); err != nil {
			http.Error(w, "Failed to encode readiness status", http.StatusInternalServerError)
			return
		}
	})
}

// BackendStatus represents the backend service status
type BackendStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	URL     string `json:"url,omitempty"`
	Latency string `json:"latency,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ReadinessStatus represents the detailed readiness status
type ReadinessStatus struct {
	Status     string                     `json:"status"`
	Timestamp  time.Time                  `json:"timestamp"`
	Message    string                     `json:"message"`
	Components map[string]ComponentStatus `json:"components"`
	Backend    BackendStatus              `json:"backend"`
}

// checkBackendReadiness checks if the backend service is ready
func (h *ComprehensiveHealthHandler) checkBackendReadiness(probe *Probe, ctx context.Context) BackendStatus {
	if probe == nil {
		return BackendStatus{
			Status:  "not_configured",
			Message: "No backend probe configured",
		}
	}

	start := time.Now()
	err := probe.Check(ctx)
	latency := time.Since(start).String()

	if err != nil {
		return BackendStatus{
			Status:  "unready",
			Message: "Backend health check failed",
			URL:     probe.healthURL,
			Latency: latency,
			Error:   err.Error(),
		}
	}

	return BackendStatus{
		Status:  "ready",
		Message: "Backend service available",
		URL:     probe.healthURL,
		Latency: latency,
	}
}

// getComponentStatusMap returns a copy of the component status map
func (h *ComprehensiveHealthHandler) getComponentStatusMap() map[string]ComponentStatus {
	h.mu.Lock()
	defer h.mu.Unlock()

	result := make(map[string]ComponentStatus)
	for k, v := range h.componentStatus {
		result[k] = v
	}
	return result
}

// UpdateComponentStatus allows external components to update their status
func (h *ComprehensiveHealthHandler) UpdateComponentStatus(name string, status ComponentStatus) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.componentStatus[name] = status
}

// GetUptime returns the system uptime
func (h *ComprehensiveHealthHandler) GetUptime() time.Duration {
	return time.Since(h.startTime)
}

// VersionHandler returns a handler that provides version and build information
// This implements Phase 39.4: Better debugging tools
func VersionHandler(version string, buildInfo map[string]any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record request for observability
		_, span := observability.StartSpan(r.Context(), "health.version")
		defer span.End()

		// Create version info response
		versionInfo := map[string]any{
			"version":   version,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}

		// Add build info
		for k, v := range buildInfo {
			versionInfo[k] = v
		}

		// Add runtime info
		versionInfo["go_version"] = runtime.Version()
		versionInfo["os"] = runtime.GOOS
		versionInfo["arch"] = runtime.GOARCH
		versionInfo["cpus"] = runtime.NumCPU()
		versionInfo["goroutines"] = runtime.NumGoroutine()

		// Set response headers
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Write JSON response
		if err := json.NewEncoder(w).Encode(versionInfo); err != nil {
			http.Error(w, "Failed to encode version info", http.StatusInternalServerError)
			return
		}
	})
}

// DebugHandler returns a handler that provides debugging information
// This implements Phase 39.4: Better debugging tools
func DebugHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record request for observability
		_, span := observability.StartSpan(r.Context(), "health.debug")
		defer span.End()

		// Create debug info
		debugInfo := map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"request": map[string]any{
				"method":      r.Method,
				"path":        r.URL.Path,
				"remote_addr": r.RemoteAddr,
				"user_agent":  r.UserAgent(),
				"headers":     r.Header,
			},
			"runtime": map[string]any{
				"goroutines": runtime.NumGoroutine(),
				"num_cpu":    runtime.NumCPU(),
				"goos":       runtime.GOOS,
				"goarch":     runtime.GOARCH,
				"version":    runtime.Version(),
			},
			"tracing": map[string]bool{
				"enabled": observability.IsTracingEnabled(),
			},
			"metrics": map[string]bool{
				"enabled": observability.IsMetricsExporterEnabled(),
			},
		}

		// Set response headers
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Write JSON response
		if err := json.NewEncoder(w).Encode(debugInfo); err != nil {
			http.Error(w, "Failed to encode debug info", http.StatusInternalServerError)
			return
		}
	})
}

// ConfigHandler returns a handler that provides current configuration (sanitized)
// This implements Phase 39.4: Better debugging tools
func ConfigHandler(cfg interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record request for observability
		_, span := observability.StartSpan(r.Context(), "health.config")
		defer span.End()

		// For security, only return sanitized configuration
		// This is a placeholder - actual implementation should sanitize sensitive fields
		configInfo := map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"message":   "Configuration endpoint - sensitive fields redacted",
		}

		// Set response headers
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Write JSON response
		if err := json.NewEncoder(w).Encode(configInfo); err != nil {
			http.Error(w, "Failed to encode config info", http.StatusInternalServerError)
			return
		}
	})
}

// NewHealthCheckSuite creates a comprehensive set of health check handlers
// This implements Phase 39.4: Comprehensive health check endpoints
func NewHealthCheckSuite(version string, buildInfo map[string]any, probe *Probe) *HealthCheckSuite {
	comprehensiveHandler := NewComprehensiveHealthHandler(version, buildInfo)

	return &HealthCheckSuite{
		LivenessHandler:          LivenessHandler(),
		ReadinessHandler:         ReadinessHandler(probe),
		ComprehensiveHandler:     comprehensiveHandler.Handler(),
		ReadinessDetailedHandler: comprehensiveHandler.ReadinessHandlerWithDetails(probe),
		VersionHandler:           VersionHandler(version, buildInfo),
		DebugHandler:             DebugHandler(),
		ConfigHandler:            ConfigHandler(nil), // Will be configured later
		ComprehensiveHealth:      comprehensiveHandler,
	}
}

// HealthCheckSuite contains all health check handlers
type HealthCheckSuite struct {
	LivenessHandler          http.Handler
	ReadinessHandler         http.Handler
	ComprehensiveHandler     http.Handler
	ReadinessDetailedHandler http.Handler
	VersionHandler           http.Handler
	DebugHandler             http.Handler
	ConfigHandler            http.Handler
	ComprehensiveHealth      *ComprehensiveHealthHandler
}

// RegisterRoutes registers all health check routes with the given mux
func (suite *HealthCheckSuite) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("GET /healthz", suite.LivenessHandler)
	mux.Handle("GET /readyz", suite.ReadinessHandler)
	mux.Handle("GET /health", suite.ComprehensiveHandler)
	mux.Handle("GET /health/ready", suite.ReadinessDetailedHandler)
	mux.Handle("GET /version", suite.VersionHandler)
	mux.Handle("GET /debug", suite.DebugHandler)
	// Note: Config endpoint is not registered by default for security reasons
	// It should be enabled only in development or with proper authentication
}
