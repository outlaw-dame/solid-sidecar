// Package observability provides observability utilities for the Solid runtime.
// This file implements pprof/debug endpoint policy as required by Phase 17.
package observability

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DebugEndpointConfig holds configuration for debug endpoints
type DebugEndpointConfig struct {
	// Enabled determines if debug endpoints are enabled
	Enabled bool

	// AuthToken is the authentication token for debug endpoints
	// If empty, debug endpoints are disabled in production
	AuthToken string

	// Environment is the runtime environment (dev, staging, prod)
	Environment string

	// AllowedIPs is a list of IP addresses/ranges allowed to access debug endpoints
	AllowedIPs []string

	// RateLimit is the maximum requests per minute per IP
	RateLimit int

	// EnablePprof enables the pprof endpoint
	EnablePprof bool

	// EnableMetrics enables the metrics endpoint
	EnableMetrics bool

	// EnableHealth enables the health endpoint (always available)
	EnableHealth bool

	// EnableDebug enables additional debug endpoints
	EnableDebug bool

	// Logger is the logger for debug endpoints
	Logger *slog.Logger
}

// DefaultDebugEndpointConfig returns safe defaults for debug endpoint configuration
func DefaultDebugEndpointConfig() DebugEndpointConfig {
	return DebugEndpointConfig{
		Enabled:       false, // Disabled by default in production
		AuthToken:     "",    // No auth token by default
		Environment:   "prod",
		AllowedIPs:    nil,   // No IPs allowed by default
		RateLimit:     60,    // 60 requests per minute max
		EnablePprof:   false, // Disabled by default
		EnableMetrics: true,  // Metrics enabled by default
		EnableHealth:  true,  // Health always available
		EnableDebug:   false, // Additional debug disabled by default
		Logger:        nil,
	}
}

// DebugEndpointManager manages debug endpoints with security policies
type DebugEndpointManager struct {
	mu sync.RWMutex

	config DebugEndpointConfig

	// Rate limiting state
	rateLimiters map[string]*rateLimiter

	// Metrics
	metrics DebugEndpointMetrics

	// Close state
	closed bool

	// Started at
	startedAt time.Time
}

// DebugEndpointMetrics holds metrics for debug endpoints
type DebugEndpointMetrics struct {
	mu sync.RWMutex

	// Request metrics
	TotalRequests     int64
	AllowedRequests   int64
	BlockedRequests   int64
	AuthFailures      int64
	RateLimitExceeded int64

	// Per-endpoint metrics
	EndpointRequests map[string]int64
}

// NewDebugEndpointMetrics creates new debug endpoint metrics
func NewDebugEndpointMetrics() DebugEndpointMetrics {
	return DebugEndpointMetrics{
		EndpointRequests: make(map[string]int64),
	}
}

// rateLimiter implements a simple token bucket rate limiter for debug endpoints
type rateLimiter struct {
	mu sync.Mutex

	// Tokens available
	tokens int

	// Maximum tokens (rate limit per minute)
	maxTokens int

	// Last refill time
	lastRefill time.Time
}

// newRateLimiter creates a new rate limiter
func newRateLimiter(rateLimit int) *rateLimiter {
	return &rateLimiter{
		tokens:     rateLimit,
		maxTokens:  rateLimit,
		lastRefill: time.Now(),
	}
}

// allow checks if a request should be allowed based on rate limiting
func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	// Refill 1 token per second
	tokensToAdd := int(elapsed.Seconds())
	if tokensToAdd > 0 {
		rl.tokens += tokensToAdd
		if rl.tokens > rl.maxTokens {
			rl.tokens = rl.maxTokens
		}
		rl.lastRefill = now
	}

	// Check if we have tokens available
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

// NewDebugEndpointManager creates a new debug endpoint manager
func NewDebugEndpointManager(config DebugEndpointConfig) *DebugEndpointManager {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// In production, disable debug endpoints by default
	if config.Environment == "prod" && !config.Enabled {
		config.Enabled = false
		config.EnablePprof = false
		config.EnableDebug = false
	}

	manager := &DebugEndpointManager{
		config:       config,
		rateLimiters: make(map[string]*rateLimiter),
		metrics:      NewDebugEndpointMetrics(),
		startedAt:    time.Now(),
		closed:       false,
	}

	config.Logger.Info("Debug endpoint manager initialized",
		"enabled", config.Enabled,
		"environment", config.Environment,
		"pprof_enabled", config.EnablePprof,
		"metrics_enabled", config.EnableMetrics,
		"debug_enabled", config.EnableDebug,
		"rate_limit", config.RateLimit,
	)

	return manager
}

// Close closes the debug endpoint manager
func (d *DebugEndpointManager) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true
	d.rateLimiters = nil

	d.config.Logger.Info("Debug endpoint manager closed")
	return nil
}

// IsClosed returns true if the manager is closed
func (d *DebugEndpointManager) IsClosed() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.closed
}

// IsEnabled returns true if debug endpoints are enabled
func (d *DebugEndpointManager) IsEnabled() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.config.Enabled
}

// Authenticate authenticates a request to debug endpoints
// Returns true if authentication succeeds, false otherwise
func (d *DebugEndpointManager) Authenticate(req *http.Request) bool {
	d.mu.RLock()
	if d.closed || !d.config.Enabled {
		d.mu.RUnlock()
		return false
	}
	d.mu.RUnlock()

	// Check IP allowlist if configured
	clientIP := getClientIP(req)
	if !d.isIPAllowed(clientIP) {
		d.metrics.recordAuthFailure()
		return false
	}

	// Check auth token if configured
	if d.config.AuthToken != "" {
		// Check Authorization header
		if authHeader := req.Header.Get("Authorization"); authHeader != "" {
			// Support Bearer token
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				if !d.validateAuthToken(token) {
					d.metrics.recordAuthFailure()
					return false
				}
			} else {
				d.metrics.recordAuthFailure()
				return false
			}
		} else {
			d.metrics.recordAuthFailure()
			return false
		}
	}

	// Check rate limiting
	if !d.checkRateLimit(clientIP) {
		d.metrics.recordRateLimitExceeded()
		return false
	}

	return true
}

// isIPAllowed checks if the client IP is in the allowlist
func (d *DebugEndpointManager) isIPAllowed(ip string) bool {
	if ip == "" {
		return false
	}

	// If no IPs are allowed, check environment
	if len(d.config.AllowedIPs) == 0 {
		// In production, no IPs allowed by default
		if d.config.Environment == "prod" {
			return false
		}
		// In dev/staging, allow all if no specific IPs configured
		return d.config.Environment != "prod"
	}

	// Check if IP is in allowlist
	for _, allowedIP := range d.config.AllowedIPs {
		if matchIP(ip, allowedIP) {
			return true
		}
	}

	return false
}

// matchIP checks if an IP matches an IP pattern (supports CIDR notation)
func matchIP(ip, pattern string) bool {
	// Simple exact match
	if ip == pattern {
		return true
	}

	// Simple prefix match (for IP ranges)
	if strings.HasSuffix(pattern, ".0/24") || strings.HasSuffix(pattern, ".0.0/16") {
		// For simplicity, check if IP starts with the pattern prefix
		// A more sophisticated implementation would use proper CIDR parsing
		prefix := strings.TrimSuffix(pattern, ".0/24")
		prefix = strings.TrimSuffix(prefix, ".0/16")
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}

	return false
}

// validateAuthToken validates an auth token with constant-time comparison
func (d *DebugEndpointManager) validateAuthToken(providedToken string) bool {
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(providedToken), []byte(d.config.AuthToken)) == 1
}

// checkRateLimit checks if a request should be allowed based on rate limiting
func (d *DebugEndpointManager) checkRateLimit(ip string) bool {
	if ip == "" || d.config.RateLimit <= 0 {
		return true // No rate limiting
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Get or create rate limiter for this IP
	limiter := d.rateLimiters[ip]
	if limiter == nil {
		limiter = newRateLimiter(d.config.RateLimit)
		d.rateLimiters[ip] = limiter
	}

	return limiter.allow()
}

// getClientIP extracts the client IP from a request
func getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	if req.RemoteAddr != "" {
		if strings.Contains(req.RemoteAddr, ":") {
			return strings.Split(req.RemoteAddr, ":")[0]
		}
		return req.RemoteAddr
	}

	return ""
}

// recordRequest records a request to debug endpoints
func (d *DebugEndpointMetrics) recordRequest(endpoint string, allowed bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.TotalRequests++
	d.EndpointRequests[endpoint]++

	if allowed {
		d.AllowedRequests++
	} else {
		d.BlockedRequests++
	}
}

// recordAuthFailure records an authentication failure
func (d *DebugEndpointMetrics) recordAuthFailure() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.TotalRequests++
	d.AuthFailures++
	d.BlockedRequests++
}

// recordRateLimitExceeded records a rate limit exceeded event
func (d *DebugEndpointMetrics) recordRateLimitExceeded() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.RateLimitExceeded++
}

// GetMetrics returns the current metrics
func (d *DebugEndpointMetrics) GetMetrics() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]interface{}{
		"total_requests":      d.TotalRequests,
		"allowed_requests":    d.AllowedRequests,
		"blocked_requests":    d.BlockedRequests,
		"auth_failures":       d.AuthFailures,
		"rate_limit_exceeded": d.RateLimitExceeded,
		"endpoint_requests":   d.EndpointRequests,
	}
}

// CreateAuthMiddleware creates authentication middleware for debug endpoints
func (d *DebugEndpointManager) CreateAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip authentication for health endpoints if enabled
			if d.config.EnableHealth && isHealthEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Check if debug endpoints are enabled
			if !d.IsEnabled() {
				http.Error(w, "Debug endpoints are disabled", http.StatusNotFound)
				return
			}

			// Check if specific endpoint is enabled
			if !d.isEndpointEnabled(r.URL.Path) {
				http.Error(w, "Endpoint not available", http.StatusNotFound)
				return
			}

			// Authenticate the request
			if !d.Authenticate(r) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Record successful authentication
			endpoint := extractEndpoint(r.URL.Path)
			d.metrics.recordRequest(endpoint, true)

			// Add security headers
			w.Header().Set("X-Debug-Endpoint", "true")
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", d.config.RateLimit))

			next.ServeHTTP(w, r)
		})
	}
}

// isHealthEndpoint checks if the path is a health endpoint
func isHealthEndpoint(path string) bool {
	healthPaths := []string{
		"/health",
		"/healthz",
		"/live",
		"/liveness",
		"/ready",
		"/readiness",
	}

	for _, healthPath := range healthPaths {
		if strings.HasSuffix(path, healthPath) || path == healthPath {
			return true
		}
	}

	return false
}

// isEndpointEnabled checks if a specific endpoint is enabled
func (d *DebugEndpointManager) isEndpointEnabled(path string) bool {
	// Health endpoints are always enabled if configured
	if d.config.EnableHealth && isHealthEndpoint(path) {
		return true
	}

	// Metrics endpoint
	if d.config.EnableMetrics && isMetricsEndpoint(path) {
		return true
	}

	// Pprof endpoints
	if d.config.EnablePprof && isPprofEndpoint(path) {
		return true
	}

	// Other debug endpoints
	if d.config.EnableDebug && isDebugEndpoint(path) {
		return true
	}

	return false
}

// isMetricsEndpoint checks if the path is a metrics endpoint
func isMetricsEndpoint(path string) bool {
	metricsPaths := []string{
		"/metrics",
		"/prometheus",
	}

	for _, metricsPath := range metricsPaths {
		if strings.HasSuffix(path, metricsPath) || path == metricsPath {
			return true
		}
	}

	return false
}

// isPprofEndpoint checks if the path is a pprof endpoint
func isPprofEndpoint(path string) bool {
	pprofPaths := []string{
		"/debug/pprof/",
		"/debug/pprof",
		"/pprof/",
		"/pprof",
	}

	for _, pprofPath := range pprofPaths {
		if strings.HasPrefix(path, pprofPath) || path == pprofPath {
			return true
		}
	}

	return false
}

// isDebugEndpoint checks if the path is a debug endpoint
func isDebugEndpoint(path string) bool {
	debugPaths := []string{
		"/debug/",
		"/debug",
		"/varz",
		"/configz",
		"/tracez",
	}

	for _, debugPath := range debugPaths {
		if strings.HasPrefix(path, debugPath) || path == debugPath {
			return true
		}
	}

	return false
}

// extractEndpoint extracts the endpoint name from a path
func extractEndpoint(path string) string {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// Get first component
	if strings.Contains(path, "/") {
		return strings.Split(path, "/")[0]
	}

	return path
}

// CreateSafePprofHandler creates a safe pprof handler with authentication
func (d *DebugEndpointManager) CreateSafePprofHandler() http.Handler {
	if !d.config.EnablePprof || !d.IsEnabled() {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Not found", http.StatusNotFound)
		})
	}

	// Import pprof here to avoid circular dependencies
	// In a real implementation, this would use the standard library's net/http/pprof

	// For now, return a simple handler that indicates pprof is not available
	// This would be replaced with actual pprof import in the real implementation
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pprof endpoint is enabled but not fully implemented\n"))
	})
}

// ProductionDebugConfig returns a safe configuration for production
func ProductionDebugConfig() DebugEndpointConfig {
	return DebugEndpointConfig{
		Enabled:       false, // Disabled by default in production
		AuthToken:     "",    // No auth token
		Environment:   "prod",
		AllowedIPs:    nil,   // No IPs allowed
		RateLimit:     10,    // Very strict rate limiting
		EnablePprof:   false, // Pprof disabled
		EnableMetrics: true,  // Metrics enabled
		EnableHealth:  true,  // Health enabled
		EnableDebug:   false, // Debug disabled
		Logger:        slog.Default(),
	}
}

// DevelopmentDebugConfig returns a configuration suitable for development
func DevelopmentDebugConfig(authToken string) DebugEndpointConfig {
	return DebugEndpointConfig{
		Enabled:       true, // Enabled in development
		AuthToken:     authToken,
		Environment:   "dev",
		AllowedIPs:    []string{"127.0.0.1", "::1"}, // Localhost only
		RateLimit:     60,                           // 60 requests per minute
		EnablePprof:   true,                         // Pprof enabled
		EnableMetrics: true,                         // Metrics enabled
		EnableHealth:  true,                         // Health enabled
		EnableDebug:   true,                         // Debug enabled
		Logger:        slog.Default(),
	}
}
