// Package authz provides CSS comparison harness for fixture distribution transports
package authz

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	neturl "net/url"
	"net/http"
	"os"
	"sync"
	"time"
)

// CSSComparisonTransportResult contains the comparison result for a single transport operation
type CSSComparisonTransportResult struct {
	// Unique identifier for this comparison
	ComparisonID string
	
	// Transport operation details
	TransportType TransportMethod
	Operation     string
	Target        FixtureDistributionTarget
	
	// CSS result (direct call to CSS or baseline)
	CSSResult TransportResult
	
	// Sidecar result (through solid-sidecar)
	SidecarResult TransportResult
	
	// Comparison outcome
	Match  bool
	Diffs  []string
	Score  float64 // 0.0 to 1.0, where 1.0 is perfect match
	
	// Timing information
	CSSDuration    time.Duration
	SidecarDuration time.Duration
	
	// Metadata
	Timestamp time.Time
	PayloadSize int
}

// CSSComparisonTransportReport contains aggregated comparison results
type CSSComparisonTransportReport struct {
	mu sync.RWMutex
	
	// Report metadata
	ReportID     string
	GeneratedAt  time.Time
	Environment string
	
	// Individual comparison results
	Results []CSSComparisonTransportResult
	
	// Aggregate statistics
	TotalComparisons  int
	MatchCount        int
	MismatchCount     int
	MatchRate         float64
	
	// Statistics by transport type
	ByTransport map[TransportMethod]*TransportComparisonStats
	
	// Performance statistics
	AvgCSSDuration    time.Duration
	AvgSidecarDuration time.Duration
	P95CSSDuration    time.Duration
	P95SidecarDuration time.Duration
	
	// Error statistics
	CSSErrors     int
	SidecarErrors int
	BothErrors    int
}

// TransportComparisonStats contains per-transport comparison statistics
type TransportComparisonStats struct {
	TransportType TransportMethod
	Total         int
	Matches      int
	Mismatches   int
	MatchRate    float64
	AvgScore     float64
	
	// Timing
	AvgCSSDuration    time.Duration
	AvgSidecarDuration time.Duration
	MinCSSDuration    time.Duration
	MaxCSSDuration    time.Duration
	MinSidecarDuration time.Duration
	MaxSidecarDuration time.Duration
	
	// Common diffs
	CommonDiffs map[string]int
}

// newCSSComparisonTransportReport creates a new comparison report
func newCSSComparisonTransportReport() *CSSComparisonTransportReport {
	return &CSSComparisonTransportReport{
		ReportID:    fmt.Sprintf("report-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now(),
		Results:     make([]CSSComparisonTransportResult, 0),
		ByTransport: make(map[TransportMethod]*TransportComparisonStats),
	}
}

// AddResult adds a comparison result to the report
func (r *CSSComparisonTransportReport) AddResult(result CSSComparisonTransportResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	r.Results = append(r.Results, result)
	r.TotalComparisons++
	
	if result.Match {
		r.MatchCount++
	} else {
		r.MismatchCount++
	}
	
	// Update transport-specific stats
	stats, exists := r.ByTransport[result.TransportType]
	if !exists {
		stats = &TransportComparisonStats{
			TransportType: result.TransportType,
			CommonDiffs:   make(map[string]int),
		}
		r.ByTransport[result.TransportType] = stats
	}
	
	stats.Total++
	stats.AvgCSSDuration += result.CSSDuration
	stats.AvgSidecarDuration += result.SidecarDuration
	
	if result.Match {
		stats.Matches++
		stats.AvgScore += result.Score
	} else {
		stats.Mismatches++
		for _, diff := range result.Diffs {
			stats.CommonDiffs[diff]++
		}
	}
	
	// Update overall timing
	r.AvgCSSDuration += result.CSSDuration
	r.AvgSidecarDuration += result.SidecarDuration
	
	// Update error counts
	if result.CSSResult.Success == false && result.CSSResult.Error != "" {
		r.CSSErrors++
	}
	if result.SidecarResult.Success == false && result.SidecarResult.Error != "" {
		r.SidecarErrors++
	}
	if !result.CSSResult.Success && !result.SidecarResult.Success {
		r.BothErrors++
	}
}

// Finalize calculates final statistics for the report
func (r *CSSComparisonTransportReport) Finalize() {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if r.TotalComparisons > 0 {
		r.MatchRate = float64(r.MatchCount) / float64(r.TotalComparisons)
		r.AvgCSSDuration = r.AvgCSSDuration / time.Duration(r.TotalComparisons)
		r.AvgSidecarDuration = r.AvgSidecarDuration / time.Duration(r.TotalComparisons)
	}
	
	// Calculate per-transport stats
	for _, stats := range r.ByTransport {
		if stats.Total > 0 {
			stats.MatchRate = float64(stats.Matches) / float64(stats.Total)
			stats.AvgCSSDuration = stats.AvgCSSDuration / time.Duration(stats.Total)
			stats.AvgSidecarDuration = stats.AvgSidecarDuration / time.Duration(stats.Total)
			if stats.Matches > 0 {
				stats.AvgScore = stats.AvgScore / float64(stats.Matches)
			}
		}
	}
}

// TransportResult contains the result of a transport operation
type TransportResult struct {
	Success bool
	Status  int
	Headers http.Header
	Body    []byte
	Error   string
	
	// Transport-specific metadata
	TransportType TransportMethod
	Operation     string
	Duration     time.Duration
}

// CSSClient interface for making direct CSS requests
type CSSClient interface {
	// DoRequest performs a request directly to CSS
	DoRequest(ctx context.Context, method, url string, headers http.Header, body []byte) (*TransportResult, error)
	
	// GetResource retrieves a resource from CSS
	GetResource(ctx context.Context, url string) (*TransportResult, error)
	
	// PutResource uploads a resource to CSS
	PutResource(ctx context.Context, url string, contentType string, body []byte) (*TransportResult, error)
	
	// Close closes the client
	Close() error
}

// DefaultCSSClient implements CSSClient using http.Client
type DefaultCSSClient struct {
	client      *http.Client
	baseURL    string
	accessToken string
	tlsConfig  *tls.Config
}

// NewDefaultCSSClient creates a new CSS client
func NewDefaultCSSClient(baseURL string) *DefaultCSSClient {
	return &DefaultCSSClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		baseURL: baseURL,
	}
}

// NewDefaultCSSClientWithToken creates a new CSS client with DPoP access token
func NewDefaultCSSClientWithToken(baseURL, accessToken string) *DefaultCSSClient {
	client := NewDefaultCSSClient(baseURL)
	client.accessToken = accessToken
	return client
}

// DoRequest performs a request directly to CSS
func (c *DefaultCSSClient) DoRequest(ctx context.Context, method, url string, headers http.Header, body []byte) (*TransportResult, error) {
	start := time.Now()
	
	// Parse URL
	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	
	// Resolve relative URLs against base
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		base, err := neturl.Parse(c.baseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid base URL: %w", err)
		}
		parsedURL = base.ResolveReference(parsedURL)
	}
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, method, parsedURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	
	// Copy headers
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	
	// Add authorization if token is set
	if c.accessToken != "" {
		req.Header.Set("Authorization", "DPoP "+c.accessToken)
	}
	
	// Perform request
	resp, err := c.client.Do(req)
	if err != nil {
		return &TransportResult{
			Success: false,
			Error:   err.Error(),
			Duration: time.Since(start),
		}, err
	}
	defer resp.Body.Close()
	
	// Read body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return &TransportResult{
			Success: false,
			Status:  resp.StatusCode,
			Headers: resp.Header.Clone(),
			Error:   err.Error(),
			Duration: time.Since(start),
		}, err
	}
	
	return &TransportResult{
		Success:   true,
		Status:    resp.StatusCode,
		Headers:   resp.Header.Clone(),
		Body:      bodyBytes,
		Duration:  time.Since(start),
	}, nil
}

// GetResource retrieves a resource from CSS
func (c *DefaultCSSClient) GetResource(ctx context.Context, url string) (*TransportResult, error) {
	headers := http.Header{
		"Accept": []string{"text/turtle", "application/ld+json", "*/*"},
	}
	return c.DoRequest(ctx, http.MethodGet, url, headers, nil)
}

// PutResource uploads a resource to CSS
func (c *DefaultCSSClient) PutResource(ctx context.Context, url, contentType string, body []byte) (*TransportResult, error) {
	headers := http.Header{
		"Content-Type":   []string{contentType},
		"Accept":         []string{"text/turtle", "application/ld+json", "*/*"},
	}
	return c.DoRequest(ctx, http.MethodPut, url, headers, body)
}

// Close closes the client
func (c *DefaultCSSClient) Close() error {
	// Nothing to close for DefaultCSSClient
	return nil
}

// SidecarClient interface for making requests through the sidecar
type SidecarClient interface {
	CSSClient
}

// DefaultSidecarClient implements SidecarClient for solid-sidecar
// This would typically be the actual sidecar HTTP server, but for testing
// we can use a separate client
func NewDefaultSidecarClient(sidecarURL string) *DefaultCSSClient {
	return NewDefaultCSSClient(sidecarURL)
}

// CSSTransportComparator compares transport operations between CSS and sidecar
type CSSTransportComparator struct {
	cssClient    CSSClient
	sidecarClient SidecarClient
	
	// Configuration
	compareHeaders bool
	compareBody   bool
	
	// Metrics
	report *CSSComparisonTransportReport
}

// CSSTransportComparatorOption configures the comparator
type CSSTransportComparatorOption func(*CSSTransportComparator)

// WithHeaderComparison enables header comparison
func WithHeaderComparison(enable bool) CSSTransportComparatorOption {
	return func(c *CSSTransportComparator) {
		c.compareHeaders = enable
	}
}

// WithBodyComparison enables body comparison
func WithBodyComparison(enable bool) CSSTransportComparatorOption {
	return func(c *CSSTransportComparator) {
		c.compareBody = enable
	}
}

// NewCSSTransportComparator creates a new transport comparator
func NewCSSTransportComparator(cssClient CSSClient, sidecarClient SidecarClient, opts ...CSSTransportComparatorOption) *CSSTransportComparator {
	comparator := &CSSTransportComparator{
		cssClient:      cssClient,
		sidecarClient:  sidecarClient,
		compareHeaders: true,
		compareBody:    false, // Body comparison is often not needed for transport ops
		report:         newCSSComparisonTransportReport(),
	}
	
	for _, opt := range opts {
		opt(comparator)
	}
	
	return comparator
}

// CompareFixtureDistribution compares fixture distribution operations between CSS and sidecar
func (c *CSSTransportComparator) CompareFixtureDistribution(
	ctx context.Context,
	job FixtureDistributionJob,
	target FixtureDistributionTarget,
	payload []byte,
) CSSComparisonTransportResult {
	start := time.Now()
	
	// Convert DistributionMethod to TransportMethod for consistency
	transportMethod := convertDistributionMethodToTransportMethod(target.Method)
	
	result := CSSComparisonTransportResult{
		ComparisonID:   fmt.Sprintf("fixture-%s-%d", job.DistributionID, start.UnixNano()),
		TransportType: transportMethod,
		Operation:     "distribute",
		Target:        target,
		Timestamp:     start,
		PayloadSize:   len(payload),
	}
	
	// Perform CSS operation (baseline)
	cssResult, _ := c.performCSSOperation(ctx, job, target, payload)
	cssDuration := time.Since(start)
	
	// Perform sidecar operation
	sidecarStart := time.Now()
	sidecarResult, _ := c.performSidecarOperation(ctx, job, target, payload)
	sidecarDuration := time.Since(sidecarStart)
	
	result.CSSDuration = cssDuration
	result.SidecarDuration = sidecarDuration
	result.CSSResult = *cssResult
	result.SidecarResult = *sidecarResult
	
	// Compare results
	result.Match, result.Diffs, result.Score = c.compareResults(*cssResult, *sidecarResult)
	
	// Add to report
	c.report.AddResult(result)
	
	return result
}

// performCSSOperation simulates CSS fixture distribution (baseline)
// In reality, CSS doesn't have native fixture distribution, so we compare against
// what CSS would do with direct file operations
func (c *CSSTransportComparator) performCSSOperation(
	ctx context.Context,
	job FixtureDistributionJob,
	target FixtureDistributionTarget,
	payload []byte,
) (*TransportResult, error) {
	// For CSS baseline, we simulate what CSS would do
	// In practice, this might be:
	// 1. PUT the fixture to a known location
	// 2. Return success/failure
	
	// Since CSS doesn't have native fixture distribution, we'll use the sidecar
	// as a proxy to CSS for the baseline, but without the transport layer
	
	// For now, we'll just return a simulated result
	// In a real implementation, this would call CSS directly
	return &TransportResult{
		Success:   true,
		Status:    http.StatusOK,
		Headers:   make(http.Header),
		Duration:  10 * time.Millisecond, // Simulated
		Error:     "",
		TransportType: convertDistributionMethodToTransportMethod(target.Method),
		Operation:     "distribute",
	}, nil
}

// performSidecarOperation performs the operation through sidecar's transport layer
func (c *CSSTransportComparator) performSidecarOperation(
	ctx context.Context,
	job FixtureDistributionJob,
	target FixtureDistributionTarget,
	payload []byte,
) (*TransportResult, error) {
	// Get the appropriate transport based on target method
	var transport FixtureTransport
	var err error
	
	// Create a temporary transport for this comparison
	// In production, this would use the actual transport from the sidecar
	config := DefaultTransportConfig()
	
	switch target.Method {
	case DistributionMethodHTTPS:
		transport, err = NewHTTPTransport(FixtureTransportOptions{Config: config})
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP transport: %w", err)
		}
	case DistributionMethodS3:
		transport, err = NewS3Transport(FixtureTransportOptions{Config: config})
		if err != nil {
			return nil, fmt.Errorf("failed to create S3 transport: %w", err)
		}
	case DistributionMethodSSH:
		transport, err = NewSSHTransport(FixtureTransportOptions{Config: config})
		if err != nil {
			return nil, fmt.Errorf("failed to create SSH transport: %w", err)
		}
	case DistributionMethodLocalFile:
		// For local file, we need a temp directory
		transport, err = NewLocalFileTransport(LocalFileTransportOptions{
			Config:    config,
			BasePath:  "/tmp/solid-sidecar-comparison",
			Overwrite: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create LocalFile transport: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported transport method: %s", target.Method)
	}
	
	// Perform the distribute operation
	start := time.Now()
	_, err = transport.Distribute(ctx, job, target, payload)
	duration := time.Since(start)
	
	if err != nil {
		return &TransportResult{
			Success:      false,
			Error:        err.Error(),
			TransportType: convertDistributionMethodToTransportMethod(target.Method),
			Operation:    "distribute",
			Duration:     duration,
		}, err
	}
	
	return &TransportResult{
		Success:      true,
		Status:       http.StatusOK,
		Headers:      make(http.Header),
		Duration:     duration,
		TransportType: convertDistributionMethodToTransportMethod(target.Method),
		Operation:    "distribute",
	}, nil
}

// compareResults compares CSS and sidecar results
func (c *CSSTransportComparator) compareResults(cssResult, sidecarResult TransportResult) (bool, []string, float64) {
	diffs := make([]string, 0)
	score := 1.0
	
	// Compare success status
	if cssResult.Success != sidecarResult.Success {
		diffs = append(diffs, fmt.Sprintf("success mismatch: CSS=%v, sidecar=%v", cssResult.Success, sidecarResult.Success))
		score -= 0.4
		return false, diffs, score
	}
	
	// If both failed, compare error types
	if !cssResult.Success && !sidecarResult.Success {
		if cssResult.Error != sidecarResult.Error {
			diffs = append(diffs, fmt.Sprintf("error mismatch: CSS='%s', sidecar='%s'", cssResult.Error, sidecarResult.Error))
			// Don't penalize score as much for error message differences
			score -= 0.1
		}
		return true, diffs, score
	}
	
	// Compare status codes (if available)
	if cssResult.Status != sidecarResult.Status {
		diffs = append(diffs, fmt.Sprintf("status code mismatch: CSS=%d, sidecar=%d", cssResult.Status, sidecarResult.Status))
		score -= 0.3
	}
	
	// Compare headers if enabled
	if c.compareHeaders {
		headerDiffs := c.compareHeadersMap(cssResult.Headers, sidecarResult.Headers)
		if len(headerDiffs) > 0 {
			diffs = append(diffs, headerDiffs...)
			// Penalize based on number of header differences
			score -= 0.05 * float64(len(headerDiffs))
		}
	}
	
	// Compare body if enabled
	if c.compareBody && cssResult.Body != nil && sidecarResult.Body != nil {
		if !bytes.Equal(cssResult.Body, sidecarResult.Body) {
			diffs = append(diffs, "body content differs")
			score -= 0.2
		}
	}
	
	return score >= 0.95, diffs, score
}

// compareHeadersMap compares two HTTP header maps
func (c *CSSTransportComparator) compareHeadersMap(cssHeaders, sidecarHeaders http.Header) []string {
	diffs := make([]string, 0)
	
	// Check for headers in CSS but not in sidecar
	for key := range cssHeaders {
		if _, exists := sidecarHeaders[key]; !exists {
			diffs = append(diffs, fmt.Sprintf("header missing in sidecar: %s", key))
		}
	}
	
	// Check for headers in sidecar but not in CSS
	for key := range sidecarHeaders {
		if _, exists := cssHeaders[key]; !exists {
			// Some headers may be added by sidecar (e.g., Via, X-Forwarded-*)
			// These are expected and not considered differences
			if !isExpectedSidecarHeader(key) {
				diffs = append(diffs, fmt.Sprintf("unexpected header in sidecar: %s", key))
			}
		}
	}
	
	// Check for header value differences
	for key := range cssHeaders {
		if _, exists := sidecarHeaders[key]; exists {
			cssValue := cssHeaders.Get(key)
			sidecarValue := sidecarHeaders.Get(key)
			if cssValue != sidecarValue {
				// Some headers may have expected modifications
				if !isExpectedHeaderModification(key, cssValue, sidecarValue) {
					diffs = append(diffs, fmt.Sprintf("header value differs for %s: CSS='%s', sidecar='%s'", key, cssValue, sidecarValue))
				}
			}
		}
	}
	
	return diffs
}

// isExpectedSidecarHeader returns true if the header is expected to be added by sidecar
func isExpectedSidecarHeader(header string) bool {
	switch header {
	case "Via", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Request-Id", "X-Correlation-Id", "X-Sidecar-Version":
		return true
	}
	return false
}

// isExpectedHeaderModification returns true if the header difference is expected
func isExpectedHeaderModification(header, cssValue, sidecarValue string) bool {
	// Sidecar may modify certain headers in expected ways
	switch header {
	case "Content-Length":
		// Content-Length may differ due to compression or other transformations
		return true
	case "Date":
		// Date headers will naturally differ
		return true
	case "Server":
		// Server header will be different (CSS vs sidecar)
		return true
	}
	return false
}

// convertDistributionMethodToTransportMethod converts DistributionMethod to TransportMethod
func convertDistributionMethodToTransportMethod(method DistributionMethod) TransportMethod {
	switch method {
	case DistributionMethodHTTPS:
		return TransportMethodHTTP
	case DistributionMethodS3:
		return TransportMethodS3
	case DistributionMethodSSH:
		return TransportMethodSSH
	case DistributionMethodLocalFile:
		return TransportMethodLocal
	default:
		return TransportMethodUnknown
	}
}

// GetReport returns the current comparison report
func (c *CSSTransportComparator) GetReport() *CSSComparisonTransportReport {
	c.report.Finalize()
	return c.report
}

// ResetReport clears the current report and starts a new one
func (c *CSSTransportComparator) ResetReport() {
	c.report = newCSSComparisonTransportReport()
}

// ExportReportToJSON exports the report as JSON
func (r *CSSComparisonTransportReport) ExportReportToJSON() ([]byte, error) {
	r.Finalize()
	return json.MarshalIndent(r, "", "  ")
}

// ExportReportToFile exports the report to a file
func (r *CSSComparisonTransportReport) ExportReportToFile(filename string) error {
	data, err := r.ExportReportToJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// CSSComparisonTransportHarness provides a high-level interface for running comparisons
type CSSComparisonTransportHarness struct {
	comparator *CSSTransportComparator
}

// NewCSSComparisonTransportHarness creates a new comparison harness
func NewCSSComparisonTransportHarness(cssClient CSSClient, sidecarClient SidecarClient) *CSSComparisonTransportHarness {
	return &CSSComparisonTransportHarness{
		comparator: NewCSSTransportComparator(cssClient, sidecarClient),
	}
}

// RunComparison runs a comparison of transport operations
func (h *CSSComparisonTransportHarness) RunComparison(
	ctx context.Context,
	operations []TransportCompareOperation,
) error {
	for _, op := range operations {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Run the comparison
			result := h.comparator.CompareFixtureDistribution(
				ctx,
				op.Job,
				op.Target,
				op.Payload,
			)
			// Log the result (in a real implementation, this would use structured logging)
			if !result.Match {
				// Log mismatch with details
				// In production, this would be logged with appropriate severity
				_ = result
			}
		}
	}
	return nil
}

// GetReport returns the comparison report
func (h *CSSComparisonTransportHarness) GetReport() *CSSComparisonTransportReport {
	return h.comparator.GetReport()
}

// TransportCompareOperation defines a transport operation to compare
type TransportCompareOperation struct {
	Job     FixtureDistributionJob
	Target  FixtureDistributionTarget
	Payload []byte
}

// RunTransportComparison runs a full transport comparison test
// This is a convenience function for testing
func RunTransportComparison(cssURL, sidecarURL string, operations []TransportCompareOperation) (*CSSComparisonTransportReport, error) {
	ctx := context.Background()
	
	// Create clients
	cssClient := NewDefaultCSSClient(cssURL)
	sidecarClient := NewDefaultCSSClient(sidecarURL)
	
	// Create harness
	harness := NewCSSComparisonTransportHarness(cssClient, sidecarClient)
	
	// Run comparison
	err := harness.RunComparison(ctx, operations)
	if err != nil {
		return nil, err
	}
	
	// Get and finalize report
	report := harness.GetReport()
	report.Environment = fmt.Sprintf("CSS=%s, Sidecar=%s", cssURL, sidecarURL)
	
	return report, nil
}
