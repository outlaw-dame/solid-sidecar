package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter implements a token bucket rate limiter for DoS protection
type RateLimiter struct {
	// Tokens available
	tokens float64
	// Maximum tokens (bucket size)
	maxTokens float64
	// Tokens added per second
	rate float64
	// Last update time
	lastUpdate time.Time
	// Mutex for thread safety
	mu sync.Mutex
}

// NewRateLimiter creates a new rate limiter with the specified rate (tokens/second) and bucket size
func NewRateLimiter(rate float64, bucketSize int) *RateLimiter {
	return &RateLimiter{
		tokens:     float64(bucketSize),
		maxTokens:  float64(bucketSize),
		rate:       rate,
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request should be allowed based on rate limiting
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.lastUpdate = now

	// Add tokens based on elapsed time
	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.maxTokens {
		rl.tokens = rl.maxTokens
	}

	// Check if we have tokens available
	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}

// Wait blocks until a token is available or timeout occurs
func (rl *RateLimiter) Wait(timeout time.Duration) bool {
	start := time.Now()
	for {
		if rl.Allow() {
			return true
		}
		if time.Since(start) >= timeout {
			return false
		}
		time.Sleep(time.Millisecond * 10) // Small sleep to prevent busy waiting
	}
}

// Global rate limiter for overall request rate limiting
var globalRateLimiter *RateLimiter

// RequestCounter tracks request counts per IP/agent for DoS protection
type RequestCounter struct {
	count     int64
	lastReset time.Time
}

// GatewayCompatibilityLayer implements Layer 1: Gateway compatibility layer
// This layer ensures that the native runtime maintains CSS compatibility
// by comparing responses and behavior between the native path and CSS
type GatewayCompatibilityLayer struct {
	mu sync.RWMutex

	config GatewayCompatibilityConfig

	// CSS client for making comparison requests
	cssClient *http.Client

	// CSS base URL
	cssBaseURL string

	// Comparison results cache
	comparisonCache map[string]*ComparisonResult

	// Metrics
	metrics GatewayCompatibilityMetrics

	// Logger
	logger *slog.Logger

	// Rate limiter for DoS protection
	rateLimiter *RateLimiter

	// Per-IP rate limiting (for global DoS protection)
	perIPRateLimiters map[string]*RateLimiter

	// Global request counter for monitoring
	globalRequestCount int64

	// Close channel
	closeChan chan struct{}
	closed    bool
}

// GatewayCompatibilityConfig holds configuration for the gateway compatibility layer
type GatewayCompatibilityConfig struct {
	// CSSBaseURL is the base URL of the CSS server for comparison
	CSSBaseURL string

	// EnableComparison enables CSS comparison (required for safety)
	EnableComparison bool

	// ComparisonTimeout is the timeout for CSS comparison requests
	ComparisonTimeout time.Duration

	// CacheSize is the maximum number of comparison results to cache
	CacheSize int

	// EnableRateLimiting enables rate limiting for DoS protection
	EnableRateLimiting bool

	// RequestsPerSecond is the global rate limit (requests per second)
	RequestsPerSecond float64

	// BurstLimit is the maximum burst size allowed
	BurstLimit int

	// EnablePerIPRateLimiting enables per-IP rate limiting
	EnablePerIPRateLimiting bool

	// PerIPRequestsPerSecond is the rate limit per IP
	PerIPRequestsPerSecond float64

	// MaxRequestsPerMinute is the maximum requests per minute per IP (0 = unlimited)
	MaxRequestsPerMinute int

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultGatewayCompatibilityConfig returns a safe default configuration
func DefaultGatewayCompatibilityConfig() GatewayCompatibilityConfig {
	return GatewayCompatibilityConfig{
		CSSBaseURL:              "http://localhost:3000",
		EnableComparison:        true,
		ComparisonTimeout:       5 * time.Second,
		CacheSize:               1000,
		EnableRateLimiting:      true,  // Enable rate limiting by default for security
		RequestsPerSecond:       100.0, // Default global rate limit
		BurstLimit:              200,   // Allow bursts up to 200 requests
		EnablePerIPRateLimiting: true,  // Enable per-IP rate limiting
		PerIPRequestsPerSecond:  10.0,  // 10 requests per second per IP
		MaxRequestsPerMinute:    600,   // 600 requests per minute per IP (10 RPS)
		Logger:                  nil,
	}
}

// GatewayCompatibilityMetrics holds metrics for the gateway compatibility layer
type GatewayCompatibilityMetrics struct {
	mu sync.RWMutex

	// Total requests processed
	TotalRequests int64

	// Requests that matched CSS behavior
	CSSMatches int64

	// Requests that diverged from CSS behavior
	CSSDivergences int64

	// Comparison requests made to CSS
	CSSComparisonRequests int64

	// Comparison cache hits
	CacheHits int64

	// Comparison cache misses
	CacheMisses int64

	// Last comparison time
	LastComparisonTime time.Time
}

// RecordRequest records a request being processed
func (m *GatewayCompatibilityMetrics) RecordRequest() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalRequests++
	m.LastComparisonTime = time.Now()
}

// RecordCSSMatch records a CSS match
func (m *GatewayCompatibilityMetrics) RecordCSSMatch() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CSSMatches++
}

// RecordCSSDivergence records a CSS divergence
func (m *GatewayCompatibilityMetrics) RecordCSSDivergence() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CSSDivergences++
}

// RecordCSSComparisonRequest records a CSS comparison request
func (m *GatewayCompatibilityMetrics) RecordCSSComparisonRequest() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CSSComparisonRequests++
}

// RecordCacheHit records a cache hit
func (m *GatewayCompatibilityMetrics) RecordCacheHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheHits++
}

// RecordCacheMiss records a cache miss
func (m *GatewayCompatibilityMetrics) RecordCacheMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheMisses++
}

// GetMismatchRate returns the current mismatch rate
func (m *GatewayCompatibilityMetrics) GetMismatchRate() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := m.TotalRequests
	if total == 0 {
		return 0
	}

	return float64(m.CSSDivergences) / float64(total) * 100
}

// ComparisonResult holds the result of a CSS comparison
type ComparisonResult struct {
	// Request hash (used as cache key)
	RequestHash string

	// Native response
	NativeStatusCode int
	NativeHeaders    http.Header
	NativeBodyHash   string

	// CSS response
	CSSStatusCode int
	CSSHeaders    http.Header
	CSSBodyHash   string

	// Whether the responses match
	Match bool

	// Divergence details (if any)
	Divergences []Divergence

	// Timestamp
	Timestamp time.Time
}

// Divergence represents a difference between native and CSS responses
type Divergence struct {
	// Type of divergence
	Type DivergenceType

	// Field or aspect that diverged
	Field string

	// Native value
	NativeValue string

	// CSS value
	CSSValue string

	// Severity (low, medium, high)
	Severity DivergenceSeverity
}

// DivergenceType represents the type of divergence
type DivergenceType string

const (
	DivergenceTypeStatusCode DivergenceType = "status_code"
	DivergenceTypeHeader     DivergenceType = "header"
	DivergenceTypeBody       DivergenceType = "body"
	DivergenceTypeMissing    DivergenceType = "missing"
	DivergenceTypeExtra      DivergenceType = "extra"
)

// DivergenceSeverity represents the severity of a divergence
type DivergenceSeverity string

const (
	SeverityLow    DivergenceSeverity = "low"
	SeverityMedium DivergenceSeverity = "medium"
	SeverityHigh   DivergenceSeverity = "high"
)

// NewGatewayCompatibilityLayer creates a new gateway compatibility layer
func NewGatewayCompatibilityLayer(config GatewayCompatibilityConfig) (*GatewayCompatibilityLayer, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Use default CSS base URL if not provided
	if config.CSSBaseURL == "" {
		config.CSSBaseURL = "http://localhost:3000"
	}

	// Validate CSS base URL
	if err := ValidateURI(config.CSSBaseURL); err != nil {
		return nil, fmt.Errorf("invalid CSS base URL: %w", err)
	}

	// Validate cache size
	if config.CacheSize <= 0 {
		config.CacheSize = 1000 // Default cache size
	}
	if config.CacheSize > 10000 {
		return nil, errors.New("cache size exceeds maximum allowed")
	}

	layer := &GatewayCompatibilityLayer{
		config:            config,
		cssBaseURL:        config.CSSBaseURL,
		comparisonCache:   make(map[string]*ComparisonResult),
		logger:            config.Logger,
		closeChan:         make(chan struct{}),
		closed:            false,
		perIPRateLimiters: make(map[string]*RateLimiter),
	}

	// Initialize global rate limiter if rate limiting is enabled
	if config.EnableRateLimiting && config.RequestsPerSecond > 0 {
		layer.rateLimiter = NewRateLimiter(config.RequestsPerSecond, config.BurstLimit)
		layer.logger.Info("Global rate limiting enabled",
			"requests_per_second", config.RequestsPerSecond,
			"burst_limit", config.BurstLimit,
		)
	}

	// Initialize per-IP rate limiting if enabled
	if config.EnablePerIPRateLimiting && config.PerIPRequestsPerSecond > 0 {
		layer.logger.Info("Per-IP rate limiting enabled",
			"per_ip_requests_per_second", config.PerIPRequestsPerSecond,
			"max_requests_per_minute", config.MaxRequestsPerMinute,
		)
	}

	// Create CSS client with timeout
	layer.cssClient = &http.Client{
		Timeout: config.ComparisonTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	config.Logger.Info("Gateway compatibility layer initialized",
		"css_base_url", config.CSSBaseURL,
		"enable_comparison", config.EnableComparison,
		"comparison_timeout", config.ComparisonTimeout,
		"cache_size", config.CacheSize,
	)

	return layer, nil
}

// Close cleans up the layer
func (g *GatewayCompatibilityLayer) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return nil
	}

	g.closed = true
	close(g.closeChan)
	g.cssClient.CloseIdleConnections()

	g.logger.Info("Gateway compatibility layer closed")
	return nil
}

// IsClosed returns true if the layer is closed
func (g *GatewayCompatibilityLayer) IsClosed() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.closed
}

// AllowRequest checks if a request should be allowed based on rate limiting
// Returns true if allowed, false if rate limited
func (g *GatewayCompatibilityLayer) AllowRequest(clientIP string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.closed {
		return false
	}

	// Check global rate limiting first
	if g.rateLimiter != nil && !g.rateLimiter.Allow() {
		g.logger.Warn("Global rate limit exceeded")
		atomic.AddInt64(&g.globalRequestCount, 1)
		return false
	}

	// Check per-IP rate limiting
	if g.config.EnablePerIPRateLimiting && clientIP != "" {
		ipLimiter := g.getIPRateLimiter(clientIP)
		if ipLimiter != nil && !ipLimiter.Allow() {
			g.logger.Warn("Per-IP rate limit exceeded", "ip", clientIP)
			return false
		}
	}

	// Increment global request counter
	atomic.AddInt64(&g.globalRequestCount, 1)
	return true
}

// getIPRateLimiter gets or creates a rate limiter for a specific IP
func (g *GatewayCompatibilityLayer) getIPRateLimiter(ip string) *RateLimiter {
	g.mu.RLock()
	if limiter, exists := g.perIPRateLimiters[ip]; exists {
		g.mu.RUnlock()
		return limiter
	}
	g.mu.RUnlock()

	// Create new rate limiter for this IP
	g.mu.Lock()
	defer g.mu.Unlock()

	// Double-check in case another goroutine created it
	if limiter, exists := g.perIPRateLimiters[ip]; exists {
		return limiter
	}

	limiter := NewRateLimiter(g.config.PerIPRequestsPerSecond, g.config.BurstLimit)
	g.perIPRateLimiters[ip] = limiter

	// Clean up old rate limiters periodically to prevent memory leaks
	go g.cleanupOldRateLimiters()

	return limiter
}

// cleanupOldRateLimiters removes old rate limiters to prevent memory leaks
func (g *GatewayCompatibilityLayer) cleanupOldRateLimiters() {
	// Clean up every 5 minutes
	time.Sleep(5 * time.Minute)

	g.mu.Lock()
	defer g.mu.Unlock()

	// Remove rate limiters that haven't been used recently
	// We consider an IP inactive if it hasn't been seen in 1 hour
	for ip, limiter := range g.perIPRateLimiters {
		// Check if the limiter's last update was more than 1 hour ago
		limiter.mu.Lock()
		lastUpdate := limiter.lastUpdate
		limiter.mu.Unlock()

		if time.Since(lastUpdate) > time.Hour {
			delete(g.perIPRateLimiters, ip)
			g.logger.Debug("Cleaned up rate limiter for inactive IP", "ip", ip)
		}
	}
}

// GetRequestCount returns the current global request count
func (g *GatewayCompatibilityLayer) GetRequestCount() int64 {
	return atomic.LoadInt64(&g.globalRequestCount)
}

// ResetRequestCount resets the global request counter (useful for testing/monitoring)
func (g *GatewayCompatibilityLayer) ResetRequestCount() {
	atomic.StoreInt64(&g.globalRequestCount, 0)
}

// CompareWithCSS compares a native response with what CSS would return
// This is the core compatibility check
func (g *GatewayCompatibilityLayer) CompareWithCSS(
	req *http.Request,
	nativeResp *http.Response,
	nativeBody []byte,
) (*ComparisonResult, error) {
	g.mu.RLock()
	if g.closed {
		g.mu.RUnlock()
		return nil, errors.New("gateway compatibility layer is closed")
	}
	g.mu.RUnlock()

	// Validate request to prevent injection attacks
	if req == nil || req.URL == nil {
		return nil, errors.New("invalid request: nil request or URL")
	}

	// Validate request URI
	if err := ValidateURI(req.URL.String()); err != nil {
		return nil, fmt.Errorf("invalid request URI: %w", err)
	}

	// Validate request method
	if req.Method == "" {
		return nil, errors.New("invalid request: empty method")
	}

	// Validate request method characters
	for _, r := range req.Method {
		if r < 0x20 || r == 0x7f {
			return nil, errors.New("invalid request: method contains control characters")
		}
	}

	// Check rate limiting (DoS protection)
	clientIP := getClientIP(req)
	if !g.AllowRequest(clientIP) {
		return nil, errors.New("rate limit exceeded - request rejected for DoS protection")
	}

	if !g.config.EnableComparison {
		// If comparison is disabled, assume it matches
		g.metrics.RecordRequest()
		g.metrics.RecordCSSMatch()
		return &ComparisonResult{
			RequestHash:      hashRequest(req),
			NativeStatusCode: nativeResp.StatusCode,
			NativeHeaders:    nativeResp.Header.Clone(),
			NativeBodyHash:   hashBody(nativeBody),
			Match:            true,
			Timestamp:        time.Now(),
		}, nil
	}

	// Check cache first
	requestHash := hashRequest(req)
	if cached, ok := g.getCachedComparison(requestHash); ok {
		g.metrics.RecordRequest()
		g.metrics.RecordCacheHit()
		return cached, nil
	}

	g.metrics.RecordRequest()
	g.metrics.RecordCacheMiss()

	// Make request to CSS for comparison
	cssReq, err := g.createCSSRequest(req)
	if err != nil {
		return nil, fmt.Errorf("create CSS request: %w", err)
	}

	cssResp, cssBody, err := g.makeCSSRequest(cssReq)
	if err != nil {
		// If CSS request fails, we can't compare, so we must fail safe
		g.logger.Error("CSS comparison request failed",
			"error", err,
			"request_hash", requestHash,
		)
		// Mark as divergence since we can't verify compatibility
		g.metrics.RecordCSSDivergence()
		return nil, fmt.Errorf("CSS comparison failed: %w", err)
	}
	defer cssResp.Body.Close()

	g.metrics.RecordCSSComparisonRequest()

	// Compare responses
	result := g.compareResponses(req, nativeResp, nativeBody, cssResp, cssBody)

	// Cache the result
	g.cacheComparisonResult(result)

	// Clean up cache if it's too large
	if len(g.comparisonCache) > g.config.CacheSize {
		g.cleanupCache()
	}

	return result, nil
}

// createCSSRequest creates a request suitable for sending to CSS
func (g *GatewayCompatibilityLayer) createCSSRequest(req *http.Request) (*http.Request, error) {
	// Clone the request
	cssReq := req.Clone(req.Context())

	// Update the URL to point to CSS
	url := *cssReq.URL
	url.Scheme = "http"
	url.Host = g.cssBaseURL
	cssReq.URL = &url

	// Remove hop-by-hop headers
	cssReq.Header.Del("Connection")
	cssReq.Header.Del("Keep-Alive")
	cssReq.Header.Del("Proxy-Authenticate")
	cssReq.Header.Del("Proxy-Authorization")
	cssReq.Header.Del("Te")
	cssReq.Header.Del("Trailer")
	cssReq.Header.Del("Transfer-Encoding")
	cssReq.Header.Del("Upgrade")

	return cssReq, nil
}

// makeCSSRequest makes a request to CSS and returns the response
func (g *GatewayCompatibilityLayer) makeCSSRequest(req *http.Request) (*http.Response, []byte, error) {
	resp, err := g.cssClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("CSS request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read the body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read CSS response body: %w", err)
	}

	// Return a copy of the response with the body restored
	respCopy := &http.Response{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Proto:      resp.Proto,
		ProtoMajor: resp.ProtoMajor,
		ProtoMinor: resp.ProtoMinor,
		Header:     resp.Header.Clone(),
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}

	return respCopy, body, nil
}

// compareResponses compares a native response with a CSS response
func (g *GatewayCompatibilityLayer) compareResponses(
	req *http.Request,
	nativeResp *http.Response,
	nativeBody []byte,
	cssResp *http.Response,
	cssBody []byte,
) *ComparisonResult {
	result := &ComparisonResult{
		RequestHash:      hashRequest(req),
		NativeStatusCode: nativeResp.StatusCode,
		NativeHeaders:    nativeResp.Header.Clone(),
		NativeBodyHash:   hashBody(nativeBody),
		CSSStatusCode:    cssResp.StatusCode,
		CSSHeaders:       cssResp.Header.Clone(),
		CSSBodyHash:      hashBody(cssBody),
		Match:            true,
		Timestamp:        time.Now(),
		Divergences:      []Divergence{},
	}

	// Compare status codes
	if nativeResp.StatusCode != cssResp.StatusCode {
		result.Match = false
		result.Divergences = append(result.Divergences, Divergence{
			Type:        DivergenceTypeStatusCode,
			Field:       "status_code",
			NativeValue: fmt.Sprintf("%d", nativeResp.StatusCode),
			CSSValue:    fmt.Sprintf("%d", cssResp.StatusCode),
			Severity:    SeverityHigh,
		})
	}

	// Compare headers
	g.compareHeaders(nativeResp.Header, cssResp.Header, &result.Divergences, &result.Match)

	// Compare body hashes
	if result.NativeBodyHash != result.CSSBodyHash {
		result.Match = false
		result.Divergences = append(result.Divergences, Divergence{
			Type:        DivergenceTypeBody,
			Field:       "body",
			NativeValue: result.NativeBodyHash,
			CSSValue:    result.CSSBodyHash,
			Severity:    SeverityHigh,
		})
	}

	// Log divergences if any
	if !result.Match {
		g.logger.Warn("CSS divergence detected",
			"request_hash", result.RequestHash,
			"divergence_count", len(result.Divergences),
		)
		g.metrics.RecordCSSDivergence()
	} else {
		g.metrics.RecordCSSMatch()
	}

	return result
}

// compareHeaders compares headers between two responses
func (g *GatewayCompatibilityLayer) compareHeaders(
	nativeHeaders, cssHeaders http.Header,
	divergences *[]Divergence,
	match *bool,
) {
	// Get all header names from both responses
	nativeKeys := make(map[string]bool)
	cssKeys := make(map[string]bool)

	for k := range nativeHeaders {
		nativeKeys[k] = true
	}
	for k := range cssHeaders {
		cssKeys[k] = true
	}

	// Find missing and extra headers
	for k := range nativeKeys {
		if !cssKeys[k] {
			*match = false
			*divergences = append(*divergences, Divergence{
				Type:        DivergenceTypeMissing,
				Field:       k,
				NativeValue: nativeHeaders.Get(k),
				CSSValue:    "",
				Severity:    SeverityMedium,
			})
		}
	}

	for k := range cssKeys {
		if !nativeKeys[k] {
			*match = false
			*divergences = append(*divergences, Divergence{
				Type:        DivergenceTypeExtra,
				Field:       k,
				NativeValue: "",
				CSSValue:    cssHeaders.Get(k),
				Severity:    SeverityMedium,
			})
		}
	}

	// Compare header values for common headers
	for k := range nativeKeys {
		if cssKeys[k] {
			nativeVal := nativeHeaders.Get(k)
			cssVal := cssHeaders.Get(k)
			if nativeVal != cssVal {
				*match = false
				*divergences = append(*divergences, Divergence{
					Type:        DivergenceTypeHeader,
					Field:       k,
					NativeValue: nativeVal,
					CSSValue:    cssVal,
					Severity:    SeverityLow,
				})
			}
		}
	}
}

// getClientIP extracts the client IP from a request, checking common headers
func getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header (common for proxies/load balancers)
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header (used by nginx)
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	if req.RemoteAddr != "" {
		// RemoteAddr is in the form "IP:port", so we need to extract just the IP
		if strings.Contains(req.RemoteAddr, ":") {
			return strings.Split(req.RemoteAddr, ":")[0]
		}
		return req.RemoteAddr
	}

	return ""
}

// getCachedComparison retrieves a cached comparison result
func (g *GatewayCompatibilityLayer) getCachedComparison(requestHash string) (*ComparisonResult, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result, ok := g.comparisonCache[requestHash]
	return result, ok
}

// cacheComparisonResult caches a comparison result
func (g *GatewayCompatibilityLayer) cacheComparisonResult(result *ComparisonResult) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.comparisonCache[result.RequestHash] = result
}

// cleanupCache removes oldest entries from the cache
func (g *GatewayCompatibilityLayer) cleanupCache() {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Simple cleanup: remove half the entries
	toRemove := g.config.CacheSize / 2
	for hash := range g.comparisonCache {
		delete(g.comparisonCache, hash)
		toRemove--
		if toRemove <= 0 {
			break
		}
	}
}

// hashRequest creates a hash of a request for use as a cache key
func hashRequest(req *http.Request) string {
	h := sha256.New()
	h.Write([]byte(req.Method))
	h.Write([]byte("|"))
	h.Write([]byte(req.URL.EscapedPath()))
	h.Write([]byte("|"))
	h.Write([]byte(req.URL.RawQuery))
	return hex.EncodeToString(h.Sum(nil))
}

// hashBody creates a hash of a response body
func hashBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	h := sha256.New()
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)[:16]) // Use first 16 bytes for brevity
}

// VerifyCSSCompatibility verifies that a native response is compatible with CSS
// Returns true if compatible, false if there are divergences
func (g *GatewayCompatibilityLayer) VerifyCSSCompatibility(
	req *http.Request,
	nativeResp *http.Response,
	nativeBody []byte,
) (bool, error) {
	result, err := g.CompareWithCSS(req, nativeResp, nativeBody)
	if err != nil {
		return false, err
	}
	return result.Match, nil
}

// GetMetrics returns the current metrics
func (g *GatewayCompatibilityLayer) GetMetrics() *GatewayCompatibilityMetrics {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return &g.metrics
}

// CreateTestCSSServer creates a test CSS server for testing compatibility
func CreateTestCSSServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Echo back the request details
		w.Header().Set("X-CSS-Response", "true")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS Response: " + r.URL.EscapedPath()))
	})
	return httptest.NewServer(mux)
}
