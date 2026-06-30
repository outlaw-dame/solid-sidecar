// Package authz provides authorization policy handling for Solid.
package authz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CSSComparisonResult represents the result of comparing CSS and sidecar responses
type CSSComparisonResult struct {
	// Request identifies the request that was compared
	RequestID string `json:"request_id"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Timestamp int64  `json:"timestamp"`

	// CSS response
	CSSStatus   int         `json:"css_status"`
	CSSHeaders  http.Header `json:"css_headers,omitempty"`
	CSSBodyHash string      `json:"css_body_hash,omitempty"`
	CSSBodySize int64       `json:"css_body_size"`

	// Sidecar response
	SidecarStatus   int         `json:"sidecar_status"`
	SidecarHeaders  http.Header `json:"sidecar_headers,omitempty"`
	SidecarBodyHash string      `json:"sidecar_body_hash,omitempty"`
	SidecarBodySize int64       `json:"sidecar_body_size"`

	// Comparison result
	StatusMatch    bool   `json:"status_match"`
	HeadersMatch   bool   `json:"headers_match"`
	BodyMatch      bool   `json:"body_match"`
	IsMismatch     bool   `json:"is_mismatch"`
	MismatchReason string `json:"mismatch_reason,omitempty"`
}

// CSSComparisonMetrics tracks aggregate comparison statistics
type CSSComparisonMetrics struct {
	mu sync.RWMutex

	// Counters
	TotalComparisons int64
	Matching         int64
	Mismatched       int64

	// Status code mismatches
	StatusMismatches int64

	// Header mismatches
	HeaderMismatches int64

	// Body mismatches
	BodyMismatches int64

	// Error counts
	CSSErrors     int64
	SidecarErrors int64

	// Timing
	TotalDuration time.Duration
	MinDuration   time.Duration
	MaxDuration   time.Duration
}

// CSSComparisonHarness compares sidecar behavior against CSS
type CSSComparisonHarness struct {
	options CSSComparisonHarnessOptions
	cssURL  *url.URL
	client  *http.Client
	metrics *CSSComparisonMetrics
	logger  *slog.Logger
}

// CSSComparisonHarnessOptions configures the comparison harness
type CSSComparisonHarnessOptions struct {
	// CSSURL is the base URL of the CSS server
	CSSURL string

	// SidecarURL is the base URL of the sidecar
	SidecarURL string

	// Timeout for comparison requests
	Timeout time.Duration

	// MaxBodySize is the maximum body size to compare
	MaxBodySize int64

	// Logger for harness operations
	Logger *slog.Logger
}

// DefaultCSSComparisonHarnessOptions returns options with sensible defaults
func DefaultCSSComparisonHarnessOptions() CSSComparisonHarnessOptions {
	return CSSComparisonHarnessOptions{
		Timeout:     30 * time.Second,
		MaxBodySize: 10 * 1024 * 1024, // 10 MB
		Logger:      nil,
	}
}

// NewCSSComparisonHarness creates a new CSS comparison harness
func NewCSSComparisonHarness(options CSSComparisonHarnessOptions) (*CSSComparisonHarness, error) {
	if options.CSSURL == "" {
		return nil, fmt.Errorf("CSSURL is required")
	}
	if options.SidecarURL == "" {
		return nil, fmt.Errorf("SidecarURL is required")
	}

	cssURL, err := url.Parse(options.CSSURL)
	if err != nil {
		return nil, fmt.Errorf("invalid CSSURL: %w", err)
	}

	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	if options.MaxBodySize == 0 {
		options.MaxBodySize = 10 * 1024 * 1024
	}

	return &CSSComparisonHarness{
		options: options,
		cssURL:  cssURL,
		client: &http.Client{
			Timeout: options.Timeout,
		},
		metrics: &CSSComparisonMetrics{
			MinDuration: time.Duration(1<<63 - 1), // Max duration initially
		},
		logger: options.Logger,
	}, nil
}

// Compare performs a comparison between CSS and sidecar responses
func (h *CSSComparisonHarness) Compare(ctx context.Context, method, path string, body []byte, headers http.Header) (*CSSComparisonResult, error) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		h.recordMetrics(duration)
	}()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Build CSS URL
	cssURL := *h.cssURL
	cssURL.Path = path

	// Build sidecar URL
	sidecarURL, err := url.Parse(h.options.SidecarURL)
	if err != nil {
		return nil, fmt.Errorf("invalid sidecar URL: %w", err)
	}
	sidecarURL.Path = path

	// Make request to CSS
	cssResp, cssBody, cssErr := h.doRequest(ctx, method, cssURL.String(), body, headers)

	// Make request to sidecar
	sidecarResp, sidecarBody, sidecarErr := h.doRequest(ctx, method, sidecarURL.String(), body, headers)

	// Build comparison result
	result := &CSSComparisonResult{
		RequestID:    fmt.Sprintf("%s:%s", method, path),
		Method:       method,
		Path:         path,
		Timestamp:    time.Now().Unix(),
		StatusMatch:  true,
		HeadersMatch: true,
		BodyMatch:    true,
	}

	// Handle CSS response
	if cssErr != nil {
		h.logCSSError(ctx, cssErr)
		result.CSSStatus = 0
		result.CSSBodyHash = ""
		result.CSSBodySize = 0
		h.metrics.mu.Lock()
		h.metrics.CSSErrors++
		h.metrics.mu.Unlock()
	} else {
		if cssResp != nil {
			result.CSSStatus = cssResp.StatusCode
			result.CSSHeaders = cssResp.Header.Clone()
			result.CSSBodySize = int64(len(cssBody))
			if len(cssBody) > 0 {
				result.CSSBodyHash = h.hashBody(cssBody)
			}
		}
	}

	// Handle sidecar response
	if sidecarErr != nil {
		h.logSidecarError(ctx, sidecarErr)
		result.SidecarStatus = 0
		result.SidecarBodyHash = ""
		result.SidecarBodySize = 0
		h.metrics.mu.Lock()
		h.metrics.SidecarErrors++
		h.metrics.mu.Unlock()
	} else {
		if sidecarResp != nil {
			result.SidecarStatus = sidecarResp.StatusCode
			result.SidecarHeaders = sidecarResp.Header.Clone()
			result.SidecarBodySize = int64(len(sidecarBody))
			if len(sidecarBody) > 0 {
				result.SidecarBodyHash = h.hashBody(sidecarBody)
			}
		}
	}

	// Compare status codes
	if result.CSSStatus != result.SidecarStatus {
		result.StatusMatch = false
		result.IsMismatch = true
		result.MismatchReason = fmt.Sprintf("status mismatch: CSS=%d, Sidecar=%d", result.CSSStatus, result.SidecarStatus)
		h.metrics.mu.Lock()
		h.metrics.StatusMismatches++
		h.metrics.mu.Unlock()
	}

	// Compare headers (filtering out sidecar-added headers)
	if !h.headersMatch(result.CSSHeaders, result.SidecarHeaders) {
		result.HeadersMatch = false
		result.IsMismatch = true
		if result.MismatchReason != "" {
			result.MismatchReason += "; "
		}
		result.MismatchReason += "headers differ"
		h.metrics.mu.Lock()
		h.metrics.HeaderMismatches++
		h.metrics.mu.Unlock()
	}

	// Compare bodies
	if result.CSSBodyHash != result.SidecarBodyHash {
		result.BodyMatch = false
		result.IsMismatch = true
		if result.MismatchReason != "" {
			result.MismatchReason += "; "
		}
		result.MismatchReason += "body differs"
		h.metrics.mu.Lock()
		h.metrics.BodyMismatches++
		h.metrics.mu.Unlock()
	}

	// Update metrics
	h.metrics.mu.Lock()
	h.metrics.TotalComparisons++
	if result.IsMismatch {
		h.metrics.Mismatched++
	} else {
		h.metrics.Matching++
	}
	h.metrics.mu.Unlock()

	return result, nil
}

// doRequest makes an HTTP request and returns response, body, and error
func (h *CSSComparisonHarness) doRequest(ctx context.Context, method, url string, body []byte, headers http.Header) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}

	// Copy headers
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// Read body with size limit
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, h.options.MaxBodySize+1))
	if err != nil {
		return resp, nil, err
	}

	// Check if body was truncated
	if int64(len(bodyBytes)) > h.options.MaxBodySize {
		return resp, bodyBytes[:h.options.MaxBodySize], fmt.Errorf("body truncated to %d bytes", h.options.MaxBodySize)
	}

	return resp, bodyBytes, nil
}

// headersMatch compares headers, ignoring sidecar-added headers
func (h *CSSComparisonHarness) headersMatch(cssHeaders, sidecarHeaders http.Header) bool {
	// Headers that the sidecar is expected to add/modify
	sidecarAddedHeaders := map[string]bool{
		"x-sidecar":          true,
		"x-sidecar-proxy":    true,
		"x-request-id":       true,
		"via":                true,
		"x-forwarded-for":    true,
		"x-forwarded-host":   true,
		"x-forwarded-proto":  true,
		"x-forwarded-port":   true,
		"x-forwarded-uri":    true,
		"x-forwarded-prefix": true,
		"x-enforce-policies": true,
	}

	// Compare each CSS header
	for key, cssValues := range cssHeaders {
		// Skip sidecar-added headers
		if sidecarAddedHeaders[strings.ToLower(key)] {
			continue
		}

		// Get sidecar values for this header
		sidecarValues := sidecarHeaders.Values(key)

		// If header is missing in sidecar, it's a mismatch
		if len(sidecarValues) == 0 {
			return false
		}

		// Compare values (case-insensitive)
		cssValuesLower := make([]string, len(cssValues))
		for i, v := range cssValues {
			cssValuesLower[i] = strings.ToLower(v)
		}
		sidecarValuesLower := make([]string, len(sidecarValues))
		for i, v := range sidecarValues {
			sidecarValuesLower[i] = strings.ToLower(v)
		}

		// Check if all CSS values are present in sidecar values
		for _, cssVal := range cssValuesLower {
			found := false
			for _, sidecarVal := range sidecarValuesLower {
				if cssVal == sidecarVal {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	// Check for extra headers in sidecar (that aren't sidecar-added)
	for key := range sidecarHeaders {
		if sidecarAddedHeaders[strings.ToLower(key)] {
			continue
		}
		if _, exists := cssHeaders[key]; !exists {
			// Extra header in sidecar - this might be okay depending on configuration
			// For now, we'll consider it a mismatch
			return false
		}
	}

	return true
}

// hashBody creates a SHA256 hash of the body
func (h *CSSComparisonHarness) hashBody(body []byte) string {
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

// recordMetrics records timing metrics
func (h *CSSComparisonHarness) recordMetrics(duration time.Duration) {
	h.metrics.mu.Lock()
	defer h.metrics.mu.Unlock()

	h.metrics.TotalDuration += duration
	if duration < h.metrics.MinDuration {
		h.metrics.MinDuration = duration
	}
	if duration > h.metrics.MaxDuration {
		h.metrics.MaxDuration = duration
	}
}

// GetMetrics returns the current comparison metrics
func (h *CSSComparisonHarness) GetMetrics() CSSComparisonMetrics {
	h.metrics.mu.RLock()
	defer h.metrics.mu.RUnlock()

	// Return a copy
	return CSSComparisonMetrics{
		TotalComparisons: h.metrics.TotalComparisons,
		Matching:         h.metrics.Matching,
		Mismatched:       h.metrics.Mismatched,
		StatusMismatches: h.metrics.StatusMismatches,
		HeaderMismatches: h.metrics.HeaderMismatches,
		BodyMismatches:   h.metrics.BodyMismatches,
		CSSErrors:        h.metrics.CSSErrors,
		SidecarErrors:    h.metrics.SidecarErrors,
		TotalDuration:    h.metrics.TotalDuration,
		MinDuration:      h.metrics.MinDuration,
		MaxDuration:      h.metrics.MaxDuration,
	}
}

// ResetMetrics resets the comparison metrics
func (h *CSSComparisonHarness) ResetMetrics() {
	h.metrics.mu.Lock()
	defer h.metrics.mu.Unlock()

	h.metrics.TotalComparisons = 0
	h.metrics.Matching = 0
	h.metrics.Mismatched = 0
	h.metrics.StatusMismatches = 0
	h.metrics.HeaderMismatches = 0
	h.metrics.BodyMismatches = 0
	h.metrics.CSSErrors = 0
	h.metrics.SidecarErrors = 0
	h.metrics.TotalDuration = 0
	h.metrics.MinDuration = time.Duration(1<<63 - 1)
	h.metrics.MaxDuration = 0
}

// MismatchRate returns the current mismatch rate
func (h *CSSComparisonHarness) MismatchRate() float64 {
	h.metrics.mu.RLock()
	defer h.metrics.mu.RUnlock()

	if h.metrics.TotalComparisons == 0 {
		return 0.0
	}
	return float64(h.metrics.Mismatched) / float64(h.metrics.TotalComparisons)
}

// CompareBatch performs multiple comparisons
func (h *CSSComparisonHarness) CompareBatch(ctx context.Context, requests []struct {
	Method  string
	Path    string
	Body    []byte
	Headers http.Header
}) ([]CSSComparisonResult, error) {
	results := make([]CSSComparisonResult, 0, len(requests))

	for _, req := range requests {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
			result, err := h.Compare(ctx, req.Method, req.Path, req.Body, req.Headers)
			if err != nil {
				return results, err
			}
			results = append(results, *result)
		}
	}

	return results, nil
}

// Log helpers

func (h *CSSComparisonHarness) logCSSError(ctx context.Context, err error) {
	if h.logger == nil {
		return
	}
	h.logger.Warn("CSS request failed",
		"error", err,
	)
}

func (h *CSSComparisonHarness) logSidecarError(ctx context.Context, err error) {
	if h.logger == nil {
		return
	}
	h.logger.Warn("Sidecar request failed",
		"error", err,
	)
}

// Summary returns a human-readable summary of the comparison metrics
func (h *CSSComparisonHarness) Summary() string {
	metrics := h.GetMetrics()
	total := metrics.TotalComparisons
	if total == 0 {
		return "No comparisons performed"
	}

	mismatchRate := h.MismatchRate() * 100
	avgDuration := metrics.TotalDuration / time.Duration(total)

	return fmt.Sprintf(
		"CSS Comparison Summary: %d comparisons, %d matches, %d mismatches (%.2f%% mismatch rate), "+
			"avg duration: %v, status mismatches: %d, header mismatches: %d, body mismatches: %d",
		total, metrics.Matching, metrics.Mismatched, mismatchRate,
		avgDuration, metrics.StatusMismatches, metrics.HeaderMismatches, metrics.BodyMismatches,
	)
}

// CSSComparisonMetricsJSON is a JSON-safe version of CSSComparisonMetrics without the mutex
type CSSComparisonMetricsJSON struct {
	TotalComparisons int64   `json:"total_comparisons"`
	Matching         int64   `json:"matching"`
	Mismatched       int64   `json:"mismatched"`
	StatusMismatches int64   `json:"status_mismatches"`
	HeaderMismatches int64   `json:"header_mismatches"`
	BodyMismatches   int64   `json:"body_mismatches"`
	CSSErrors        int64   `json:"css_errors"`
	SidecarErrors    int64   `json:"sidecar_errors"`
	TotalDuration    string  `json:"total_duration"`
	MinDuration      string  `json:"min_duration"`
	MaxDuration      string  `json:"max_duration"`
	MismatchRate     float64 `json:"mismatch_rate"`
	AvgDuration      string  `json:"avg_duration"`
}

// ExportMetrics exports metrics as JSON
func (h *CSSComparisonHarness) ExportMetrics() ([]byte, error) {
	metrics := h.GetMetrics()
	total := metrics.TotalComparisons
	var avgDuration string
	if total > 0 {
		avgDuration = (metrics.TotalDuration / time.Duration(total)).String()
	} else {
		avgDuration = "0"
	}
	metricsJSON := CSSComparisonMetricsJSON{
		TotalComparisons: metrics.TotalComparisons,
		Matching:         metrics.Matching,
		Mismatched:       metrics.Mismatched,
		StatusMismatches: metrics.StatusMismatches,
		HeaderMismatches: metrics.HeaderMismatches,
		BodyMismatches:   metrics.BodyMismatches,
		CSSErrors:        metrics.CSSErrors,
		SidecarErrors:    metrics.SidecarErrors,
		TotalDuration:    metrics.TotalDuration.String(),
		MinDuration:      metrics.MinDuration.String(),
		MaxDuration:      metrics.MaxDuration.String(),
		MismatchRate:     h.MismatchRate(),
		AvgDuration:      avgDuration,
	}
	return json.Marshal(metricsJSON)
}
