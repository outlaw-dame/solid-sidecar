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
	"sync"
	"time"
)

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

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultGatewayCompatibilityConfig returns a safe default configuration
func DefaultGatewayCompatibilityConfig() GatewayCompatibilityConfig {
	return GatewayCompatibilityConfig{
		CSSBaseURL:        "http://localhost:3000",
		EnableComparison:  true,
		ComparisonTimeout: 5 * time.Second,
		CacheSize:         1000,
		Logger:            nil,
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

	layer := &GatewayCompatibilityLayer{
		config:          config,
		cssBaseURL:      config.CSSBaseURL,
		comparisonCache: make(map[string]*ComparisonResult),
		logger:          config.Logger,
		closeChan:       make(chan struct{}),
		closed:          false,
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
