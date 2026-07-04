// Package observability provides health check utilities for Solid Sidecar
package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HealthStatus represents the health status of a component
type HealthStatus struct {
	Status      string            `json:"status"`
	Components map[string]ComponentHealth `json:"components,omitempty"`
	Checks     map[string]CheckResult `json:"checks,omitempty"`
}

// ComponentHealth represents the health of a single component
type ComponentHealth struct {
	Status    string `json:"status"`
	Details   string `json:"details,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// CheckResult represents the result of a health check
type CheckResult struct {
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	Duration  string `json:"duration,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// HealthChecker defines the interface for health checks
type HealthChecker interface {
	Name() string
	Check(ctx context.Context) (status string, message string, err error)
}

// HealthCheckRegistry manages a collection of health checks
type HealthCheckRegistry struct {
	mu          sync.RWMutex
	checkers   map[string]HealthChecker
	checkStatus map[string]CheckResult
	lastChecked time.Time
}

// NewHealthCheckRegistry creates a new health check registry
func NewHealthCheckRegistry() *HealthCheckRegistry {
	return &HealthCheckRegistry{
		checkers:   make(map[string]HealthChecker),
		checkStatus: make(map[string]CheckResult),
		lastChecked: time.Now(),
	}
}

// Register adds a health checker to the registry
func (r *HealthCheckRegistry) Register(checker HealthChecker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checkers[checker.Name()] = checker
}

// Unregister removes a health checker from the registry
func (r *HealthCheckRegistry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.checkers, name)
}

// RunAll runs all registered health checks and returns the results
func (r *HealthCheckRegistry) RunAll(ctx context.Context) HealthStatus {
	r.mu.RLock()
	checkers := make(map[string]HealthChecker)
	for name, checker := range r.checkers {
		checkers[name] = checker
	}
	r.mu.RUnlock()

	status := HealthStatus{
		Status:      "healthy",
		Components: make(map[string]ComponentHealth),
		Checks:     make(map[string]CheckResult),
	}

	for name, checker := range checkers {
		start := time.Now()
		checkStatus, message, err := checker.Check(ctx)
		duration := time.Since(start)

		checkResult := CheckResult{
			Status:    checkStatus,
			Message:   message,
			Duration:  duration.String(),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}

		if err != nil {
			checkResult.Status = "unhealthy"
			checkResult.Message = err.Error()
			status.Status = "unhealthy"
		}

		status.Checks[name] = checkResult

		if checkResult.Status == "unhealthy" {
			status.Status = "unhealthy"
		} else if checkResult.Status == "degraded" && status.Status != "unhealthy" {
			status.Status = "degraded"
		}
	}

	return status
}

// GetStatus returns the current status without running checks
func (r *HealthCheckRegistry) GetStatus() HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	status := HealthStatus{
		Status:      "healthy",
		Checks:     make(map[string]CheckResult),
	}

	for name, result := range r.checkStatus {
		status.Checks[name] = result
	}

	for _, check := range status.Checks {
		if check.Status == "unhealthy" {
			status.Status = "unhealthy"
			break
		}
		if check.Status == "degraded" {
			status.Status = "degraded"
		}
	}

	return status
}

// Refresh refreshes all health check results
func (r *HealthCheckRegistry) Refresh(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for name, checker := range r.checkers {
		start := time.Now()
		checkStatus, message, err := checker.Check(ctx)
		duration := time.Since(start)

		checkResult := CheckResult{
			Status:    checkStatus,
			Message:   message,
			Duration:  duration.String(),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}

		if err != nil {
			checkResult.Status = "unhealthy"
			checkResult.Message = err.Error()
		}

		r.checkStatus[name] = checkResult
	}

	r.lastChecked = time.Now()
}

// LivenessHandler returns a handler for liveness checks
func (r *HealthCheckRegistry) LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}

// ReadinessHandler returns a handler for readiness checks
func (r *HealthCheckRegistry) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
		defer cancel()

		status := r.RunAll(ctx)

		w.Header().Set("Content-Type", "application/json")

		if status.Status == "healthy" {
			w.WriteHeader(http.StatusOK)
		} else if status.Status == "degraded" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		jsonBytes, _ := json.Marshal(status)
		_, _ = w.Write(jsonBytes)
	})
}

// StartupHandler returns a handler for startup checks
func (r *HealthCheckRegistry) StartupHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
		defer cancel()

		status := r.RunAll(ctx)

		w.Header().Set("Content-Type", "application/json")

		if status.Status == "healthy" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		jsonBytes, _ := json.Marshal(status)
		_, _ = w.Write(jsonBytes)
	})
}

// LivenessCheck is a simple liveness check that always returns healthy
type simpleHealthChecker struct {
	name    string
	status  string
	message string
}

func LivenessCheck() HealthChecker {
	return &simpleHealthChecker{
		name:   "liveness",
		status: "healthy",
		message: "server is running",
	}
}

func (s *simpleHealthChecker) Name() string {
	return s.name
}

func (s *simpleHealthChecker) Check(ctx context.Context) (status string, message string, err error) {
	return s.status, s.message, nil
}

// DependencyHealthChecker checks the health of a dependency
type DependencyHealthChecker struct {
	name       string
	checkFunc  func(ctx context.Context) error
	degradedOn func(err error) bool
}

func NewDependencyHealthChecker(name string, checkFunc func(ctx context.Context) error) *DependencyHealthChecker {
	return &DependencyHealthChecker{
		name:      name,
		checkFunc: checkFunc,
		degradedOn: func(err error) bool {
			return false
		},
	}
}

func (d *DependencyHealthChecker) Name() string {
	return d.name
}

func (d *DependencyHealthChecker) Check(ctx context.Context) (status string, message string, err error) {
	if err := d.checkFunc(ctx); err != nil {
		if d.degradedOn != nil && d.degradedOn(err) {
			return "degraded", err.Error(), nil
		}
		return "unhealthy", err.Error(), err
	}
	return "healthy", "", nil
}

// HTTPHealthChecker checks the health of an HTTP endpoint
type HTTPHealthChecker struct {
	name     string
	url      string
	client   *http.Client
	timeout  time.Duration
	expected int
}

func NewHTTPHealthChecker(name, url string, expectedStatus int) *HTTPHealthChecker {
	return &HTTPHealthChecker{
		name:     name,
		url:      url,
		client:   &http.Client{Timeout: 5 * time.Second},
		timeout:  5 * time.Second,
		expected: expectedStatus,
	}
}

func (h *HTTPHealthChecker) Name() string {
	return h.name
}

func (h *HTTPHealthChecker) Check(ctx context.Context) (status string, message string, err error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return "unhealthy", err.Error(), err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return "unhealthy", err.Error(), err
	}
	defer resp.Body.Close()

	if resp.StatusCode != h.expected {
		return "unhealthy", fmt.Sprintf("expected status %d, got %d", h.expected, resp.StatusCode), nil
	}

	return "healthy", "", nil
}

// Global health check registry
var globalHealthRegistry *HealthCheckRegistry
var globalHealthRegistryOnce sync.Once

func GlobalHealthCheckRegistry() *HealthCheckRegistry {
	globalHealthRegistryOnce.Do(func() {
		globalHealthRegistry = NewHealthCheckRegistry()
		globalHealthRegistry.Register(LivenessCheck())
	})
	return globalHealthRegistry
}

func RegisterHealthCheck(checker HealthChecker) {
	GlobalHealthCheckRegistry().Register(checker)
}

func LivenessHandler() http.Handler {
	return GlobalHealthCheckRegistry().LivenessHandler()
}

func ReadinessHandler() http.Handler {
	return GlobalHealthCheckRegistry().ReadinessHandler()
}

func StartupHandler() http.Handler {
	return GlobalHealthCheckRegistry().StartupHandler()
}
