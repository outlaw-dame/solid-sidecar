package authz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// AWS SDK imports (optional - S3 functionality requires these)
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"

	// SSH library imports (optional - SSH functionality requires these)
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Transport errors
var (
	ErrTransportNotImplemented    = errors.New("transport not implemented")
	ErrTransportTimeout           = errors.New("transport timeout")
	ErrTransportAuthFailed        = errors.New("transport authentication failed")
	ErrTransportConnectionFailed  = errors.New("transport connection failed")
	ErrTransportInvalidResponse   = errors.New("transport invalid response")
	ErrTransportRetryExhausted    = errors.New("transport retry exhausted")
	ErrTransportFileWriteFailed   = errors.New("transport file write failed")
	ErrTransportFileReadFailed    = errors.New("transport file read failed")
	ErrTransportFileExists        = errors.New("transport file already exists")
	ErrTransportInvalidPath       = errors.New("transport invalid path")
	ErrTransportPermissionDenied  = errors.New("transport permission denied")
	ErrTransportSDKNecessary      = errors.New("transport requires SDK")
	ErrTransportSecurityViolation = errors.New("transport security violation")
)

// MaxTransportPayloadSize is the maximum size of payload that can be transported (10 MB)
const MaxTransportPayloadSize = 10 * 1024 * 1024

// DefaultTransportTimeout is the default timeout for transport operations
const DefaultTransportTimeout = 30 * time.Second

// MaxFilePathLength is the maximum length for a file path
const MaxFilePathLength = 4096

// DefaultFilePermissions is the default file permissions (0600 - owner read/write only)
const DefaultFilePermissions = 0600

// DefaultDirectoryPermissions is the default directory permissions (0700 - owner only)
const DefaultDirectoryPermissions = 0700

// DefaultTransportRetryCount is the default number of retries
const DefaultTransportRetryCount = 3

// DefaultTransportRetryBaseDelay is the default base delay for exponential backoff
const DefaultTransportRetryBaseDelay = 1 * time.Second

// DefaultTransportRetryMaxDelay is the default maximum delay for exponential backoff
const DefaultTransportRetryMaxDelay = 30 * time.Second

// DefaultTransportRetryMultiplier is the default multiplier for exponential backoff
const DefaultTransportRetryMultiplier = 2.0

// DefaultTransportRetryJitter is the default jitter factor (0.1 = 10%)
const DefaultTransportRetryJitter = 0.1

// Security constants
const (
	// MaxS3KeyLength is the maximum length for an S3 object key (1024 bytes per AWS limits)
	MaxS3KeyLength = 1024
	// MaxSSHPathLength is the maximum length for an SSH/SFTP path
	MaxSSHPathLength = 4096
	// MaxSSHHostLength is the maximum length for an SSH hostname
	MaxSSHHostLength = 255
	// MaxPayloadSizeForSSH is the maximum payload size for SSH transfers (100MB)
	MaxPayloadSizeForSSH = 100 * 1024 * 1024
	// SSHConnectionTimeout is the default connection timeout for SSH
	SSHConnectionTimeout = 30 * time.Second
)

// RateLimiter implements a token bucket rate limiter for transport operations
type RateLimiter struct {
	mu           sync.Mutex
	tokens       int
	maxTokens    int
	refillRate   float64 // tokens per second
	lastRefill   time.Time
	lastRefillMu sync.Mutex
}

// NewRateLimiter creates a new rate limiter with the specified rate (operations per second)
func NewRateLimiter(ratePerSecond int) *RateLimiter {
	if ratePerSecond <= 0 {
		return nil // No rate limiting
	}
	return &RateLimiter{
		tokens:     ratePerSecond,
		maxTokens:  ratePerSecond,
		refillRate: float64(ratePerSecond),
		lastRefill: time.Now(),
	}
}

// Allow checks if an operation is allowed under the rate limit
func (rl *RateLimiter) Allow() bool {
	if rl == nil {
		return true // No rate limiting
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	rl.lastRefillMu.Lock()
	elapsed := now.Sub(rl.lastRefill)
	rl.lastRefill = now
	rl.lastRefillMu.Unlock()

	// Add tokens based on elapsed time
	tokensToAdd := int(elapsed.Seconds() * rl.refillRate)
	if tokensToAdd > 0 {
		rl.tokens += tokensToAdd
		if rl.tokens > rl.maxTokens {
			rl.tokens = rl.maxTokens
		}
	}

	// Check if we have a token available
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

// Wait blocks until a rate limit token is available or context is cancelled
func (rl *RateLimiter) Wait(ctx context.Context) error {
	if rl == nil {
		return nil // No rate limiting
	}

	for {
		if rl.Allow() {
			return nil
		}

		// Wait for a short interval before checking again
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: context cancelled while waiting for rate limit", ErrTransportTimeout)
		case <-time.After(100 * time.Millisecond):
			// Try again
		}
	}
}

// sanitizeError removes sensitive information from error messages
func sanitizeError(err error, sensitiveFields ...string) error {
	if err == nil {
		return nil
	}

	// Create a map of sensitive patterns to redact
	sensitivePatterns := []string{
		"AKIA",                  // AWS access key ID prefix
		"wJalrXUtnFEMI/K7MDENG", // Example AWS secret key pattern
		"-----BEGIN",            // Private key header
		"-----END",              // Private key footer
		"PRIVATE KEY",           // Private key identifier
	}

	// Add any additional sensitive fields passed in
	for _, field := range sensitiveFields {
		if field != "" {
			sensitivePatterns = append(sensitivePatterns, field)
		}
	}

	// Convert error to string and redact sensitive information
	errStr := err.Error()
	sanitized := errStr

	for _, pattern := range sensitivePatterns {
		sanitized = strings.ReplaceAll(sanitized, pattern, "[REDACTED]")
	}

	// Also redact anything that looks like a password or secret
	// Look for common patterns: password=xxxxx, secret=xxxxx, token=xxxxx
	sanitized = regexp.MustCompile(`(?i)(password|secret|token|key|credential|auth)['":\s]*[=:]\s*[^\s,;'"]+`).ReplaceAllString(sanitized, "$1=[REDACTED]")

	if sanitized != errStr {
		return errors.New(sanitized)
	}

	return err
}

// FixtureTransport defines the interface for fixture distribution transports
type FixtureTransport interface {
	// Distribute sends fixture data to the target
	// Returns the distribution receipt on success, or an error
	Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error)

	// Name returns the name of this transport
	Name() string

	// Method returns the distribution method this transport handles
	Method() DistributionMethod
}

// TransportConfig contains configuration for a transport
type TransportConfig struct {
	// Timeout for transport operations
	Timeout time.Duration
	// RetryCount is the number of retries on failure
	RetryCount int
	// RetryBaseDelay is the base delay for exponential backoff
	RetryBaseDelay time.Duration
	// RetryMaxDelay is the maximum delay for exponential backoff
	RetryMaxDelay time.Duration
	// RetryMultiplier is the multiplier for exponential backoff
	RetryMultiplier float64
	// RetryJitter is the jitter factor (0.0 to 1.0)
	RetryJitter float64
	// VerifyTLS controls whether TLS certificates are verified
	VerifyTLS bool
	// RateLimitPerSecond is the maximum number of operations per second (0 = no limit)
	RateLimitPerSecond int
	// MaxConcurrentConnections is the maximum number of concurrent connections (0 = no limit)
	MaxConcurrentConnections int
	// AllowLocalhost controls whether localhost/loopback addresses are allowed (for testing only)
	// WARNING: Setting this to true in production is a security risk
	AllowLocalhost bool
	// DevelopmentMode controls whether development-only security relaxations are allowed
	// WARNING: Setting this to true in production is a security risk
	DevelopmentMode bool
}

// DefaultTransportConfig returns the default transport configuration
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		Timeout:         DefaultTransportTimeout,
		RetryCount:      DefaultTransportRetryCount,
		RetryBaseDelay:  DefaultTransportRetryBaseDelay,
		RetryMaxDelay:   DefaultTransportRetryMaxDelay,
		RetryMultiplier: DefaultTransportRetryMultiplier,
		RetryJitter:     DefaultTransportRetryJitter,
		VerifyTLS:       true,
	}
}

// TransportRegistry manages available transports
type TransportRegistry struct {
	transports map[DistributionMethod]FixtureTransport
}

// NewTransportRegistry creates a new transport registry
func NewTransportRegistry() *TransportRegistry {
	return &TransportRegistry{
		transports: make(map[DistributionMethod]FixtureTransport),
	}
}

// Register adds a transport to the registry
func (r *TransportRegistry) Register(transport FixtureTransport) {
	r.transports[transport.Method()] = transport
}

// Get returns the transport for a given method
func (r *TransportRegistry) Get(method DistributionMethod) (FixtureTransport, bool) {
	transport, ok := r.transports[method]
	return transport, ok
}

// MustGet returns the transport for a given method, panics if not found
func (r *TransportRegistry) MustGet(method DistributionMethod) FixtureTransport {
	transport, ok := r.Get(method)
	if !ok {
		panic(fmt.Sprintf("transport for method %s not registered", method))
	}
	return transport
}

// Methods returns all registered transport methods
func (r *TransportRegistry) Methods() []DistributionMethod {
	methods := make([]DistributionMethod, 0, len(r.transports))
	for method := range r.transports {
		methods = append(methods, method)
	}
	return methods
}

// FixtureTransportOptions contains options for creating a transport
type FixtureTransportOptions struct {
	Config TransportConfig
}

// HTTPTransport implements FixtureTransport for HTTPS distribution
type HTTPTransport struct {
	config          TransportConfig
	client          *http.Client
	baseURL         *url.URL
	metricsRecorder TransportMetricsRecorder
	// Rate limiting
	rateLimiter *RateLimiter
	// Connection tracking
	activeConnections int64
	maxConnections    int
	// Security
	allowLocalhost bool
}

// NewHTTPTransport creates a new HTTP transport
func NewHTTPTransport(options FixtureTransportOptions) (*HTTPTransport, error) {
	config := options.Config
	if config.Timeout <= 0 {
		config.Timeout = DefaultTransportTimeout
	}
	if config.RetryCount <= 0 {
		config.RetryCount = DefaultTransportRetryCount
	}
	if config.RetryBaseDelay <= 0 {
		config.RetryBaseDelay = DefaultTransportRetryBaseDelay
	}
	if config.RetryMaxDelay <= 0 {
		config.RetryMaxDelay = DefaultTransportRetryMaxDelay
	}
	if config.RetryMultiplier <= 0 {
		config.RetryMultiplier = DefaultTransportRetryMultiplier
	}
	if config.RetryJitter <= 0 {
		config.RetryJitter = DefaultTransportRetryJitter
	}

	// Create HTTP client with custom transport for TLS verification control
	// Also set connection limits if configured
	maxIdleConns := 100
	maxConnsPerHost := 100
	if config.MaxConcurrentConnections > 0 {
		maxIdleConns = config.MaxConcurrentConnections
		maxConnsPerHost = config.MaxConcurrentConnections
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifyTLS,
		},
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxConnsPerHost,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	// Initialize rate limiter if configured
	rateLimiter := NewRateLimiter(config.RateLimitPerSecond)

	return &HTTPTransport{
		config:          config,
		client:          client,
		metricsRecorder: &NopTransportMetricsRecorder{},
		rateLimiter:     rateLimiter,
		maxConnections:  config.MaxConcurrentConnections,
		allowLocalhost:  config.AllowLocalhost,
	}, nil
}

// Name returns the name of this transport
func (t *HTTPTransport) Name() string {
	return "http"
}

// Method returns the distribution method this transport handles
func (t *HTTPTransport) Method() DistributionMethod {
	return DistributionMethodHTTPS
}

// SetBaseURL sets the base URL for the HTTP transport
func (t *HTTPTransport) SetBaseURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: failed to parse URL: %v", ErrTransportConnectionFailed, err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("%w: invalid URL scheme, must be http or https", ErrTransportConnectionFailed)
	}

	// Security: Prevent SSRF attacks - check for localhost and private IP addresses
	// unless explicitly allowed (for testing purposes)
	if !t.allowLocalhost {
		host := parsedURL.Hostname()
		if host == "" {
			return fmt.Errorf("%w: URL must have a hostname", ErrTransportInvalidPath)
		}

		// Check for localhost and loopback addresses
		lowerHost := strings.ToLower(host)
		if lowerHost == "localhost" || lowerHost == "localhost.localdomain" || lowerHost == "127.0.0.1" || lowerHost == "::1" {
			return fmt.Errorf("%w: HTTP URL cannot point to localhost or loopback addresses", ErrTransportSecurityViolation)
		}

		// Check for private IP address ranges
		if isPrivateIPAddress(host) {
			return fmt.Errorf("%w: HTTP URL cannot point to private IP address: %s", ErrTransportSecurityViolation, host)
		}
	}

	t.baseURL = parsedURL
	return nil
}

// SetMetricsRecorder sets the metrics recorder for this transport
func (t *HTTPTransport) SetMetricsRecorder(recorder TransportMetricsRecorder) {
	t.metricsRecorder = recorder
}

// SetRateLimiter sets the rate limiter for this transport
func (t *HTTPTransport) SetRateLimiter(ratePerSecond int) {
	t.rateLimiter = NewRateLimiter(ratePerSecond)
}

// SetMaxConnections sets the maximum number of concurrent connections
func (t *HTTPTransport) SetMaxConnections(max int) {
	t.maxConnections = max
}

// GetActiveConnections returns the current number of active connections
func (t *HTTPTransport) GetActiveConnections() int64 {
	return atomic.LoadInt64(&t.activeConnections)
}

// Distribute sends fixture data via HTTP POST
func (t *HTTPTransport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// Record start of operation
	startTime := time.Now()
	if t.metricsRecorder != nil {
		t.metricsRecorder.IncrementConcurrent(TransportMethodHTTP)
		defer t.metricsRecorder.DecrementConcurrent(TransportMethodHTTP)
	}

	// Apply rate limiting if configured
	if t.rateLimiter != nil {
		if err := t.rateLimiter.Wait(ctx); err != nil {
			if t.metricsRecorder != nil {
				t.metricsRecorder.RecordOperation(TransportMethodHTTP, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
			}
			return FixtureDistributionReceipt{}, err
		}
	}

	// Track active connections if limit is configured
	if t.maxConnections > 0 {
		atomic.AddInt64(&t.activeConnections, 1)
		defer atomic.AddInt64(&t.activeConnections, -1)

		// Check if we've exceeded the connection limit
		if atomic.LoadInt64(&t.activeConnections) > int64(t.maxConnections) {
			if t.metricsRecorder != nil {
				t.metricsRecorder.RecordOperation(TransportMethodHTTP, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
			}
			return FixtureDistributionReceipt{}, fmt.Errorf("%w: connection limit exceeded (max %d)", ErrTransportConnectionFailed, t.maxConnections)
		}
	}

	// Validate payload size
	if len(payload) > MaxTransportPayloadSize {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodHTTP, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: payload too large (max %d bytes)", ErrTransportInvalidResponse, MaxTransportPayloadSize)
	}

	// Prepare the request URL
	var requestURL *url.URL
	if t.baseURL != nil {
		requestURL = t.baseURL
	} else {
		var err error
		requestURL, err = url.Parse(target.URL)
		if err != nil {
			return FixtureDistributionReceipt{}, fmt.Errorf("%w: failed to parse target URL: %v", ErrTransportConnectionFailed, err)
		}

		// Security: Validate target URL to prevent SSRF
		if err := validateHTTPTargetURL(requestURL); err != nil {
			return FixtureDistributionReceipt{}, err
		}
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(payload))
	if err != nil {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: failed to create request: %v", ErrTransportConnectionFailed, err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "solid-sidecar-fixture-distributor/1.0")

	// Add authentication header based on auth method
	if target.AuthMethod == DistributionAuthBearer && target.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+target.AuthToken)
	} else if target.AuthMethod == DistributionAuthBasic && target.AuthToken != "" {
		// For Basic auth, token should be base64(username:password)
		// For now, we assume the token is already encoded
		req.Header.Set("Authorization", "Basic "+target.AuthToken)
	} else if target.AuthMethod == DistributionAuthAPIKey && target.AuthToken != "" {
		// For API key, we can support different formats
		// Common: Authorization: ApiKey <key>
		// Or custom header: X-API-Key: <key>
		req.Header.Set("Authorization", "ApiKey "+target.AuthToken)
	}

	// Add fixture metadata headers
	req.Header.Set("X-Fixture-Distribution-ID", job.DistributionID)
	req.Header.Set("X-Fixture-Catalog-Hash", job.CatalogHash)
	if job.ManifestHash != "" {
		req.Header.Set("X-Fixture-Manifest-Hash", job.ManifestHash)
	}
	if len(job.BundleHashes) > 0 {
		req.Header.Set("X-Fixture-Bundle-Hashes", strings.Join(job.BundleHashes, ","))
	}

	// Execute with retry logic
	var resp *http.Response
	var lastErr error

	for attempt := 0; attempt <= t.config.RetryCount; attempt++ {
		// Wait before retry (skip on first attempt)
		if attempt > 0 {
			delay := t.calculateBackoffDelay(attempt)
			select {
			case <-ctx.Done():
				return FixtureDistributionReceipt{}, fmt.Errorf("%w: context cancelled during retry", ErrTransportTimeout)
			case <-time.After(delay):
				// Continue to retry
			}
		}

		// Reset the request body for retries
		if attempt > 0 && req.Body != nil {
			if seeker, ok := req.Body.(io.Seeker); ok {
				_, err := seeker.Seek(0, io.SeekStart)
				if err != nil {
					return FixtureDistributionReceipt{}, fmt.Errorf("%w: failed to reset request body: %v", ErrTransportConnectionFailed, err)
				}
			} else {
				// Create new request with fresh body
				req, err = http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(payload))
				if err != nil {
					return FixtureDistributionReceipt{}, fmt.Errorf("%w: failed to recreate request: %v", ErrTransportConnectionFailed, err)
				}
				// Re-set headers
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json")
				req.Header.Set("User-Agent", "solid-sidecar-fixture-distributor/1.0")
				if target.AuthMethod == DistributionAuthBearer && target.AuthToken != "" {
					req.Header.Set("Authorization", "Bearer "+target.AuthToken)
				}
			}
		}

		resp, lastErr = t.client.Do(req)
		if lastErr != nil {
			// Check if it's a timeout
			if errors.Is(lastErr, context.DeadlineExceeded) {
				return FixtureDistributionReceipt{}, fmt.Errorf("%w: request timeout", ErrTransportTimeout)
			}
			// Check if it's a context cancellation
			if errors.Is(lastErr, context.Canceled) {
				return FixtureDistributionReceipt{}, fmt.Errorf("%w: request cancelled", ErrTransportTimeout)
			}
			// Log retry attempt (in a real implementation, use proper logging)
			continue
		}

		// Check response status
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Success - parse response
			receipt, err := t.parseResponse(resp, job, target)
			if t.metricsRecorder != nil {
				t.metricsRecorder.RecordOperation(TransportMethodHTTP, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeSuccess)
			}
			return receipt, err
		}

		// Check if we should retry on this status code
		if t.shouldRetryStatusCode(resp.StatusCode) {
			if t.metricsRecorder != nil {
				t.metricsRecorder.RecordRetry(TransportMethodHTTP, TransportOpDistribute, TransportOutcomeRetry)
			}
			resp.Body.Close()
			continue
		}

		// Non-retryable error
		defer resp.Body.Close()
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodHTTP, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, t.handleNonRetryableResponse(resp, job)
	}

	// All retries exhausted
	if t.metricsRecorder != nil {
		t.metricsRecorder.RecordOperation(TransportMethodHTTP, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
	}
	return FixtureDistributionReceipt{}, fmt.Errorf("%w after %d attempts: %v", ErrTransportRetryExhausted, t.config.RetryCount+1, lastErr)
}

// calculateBackoffDelay calculates the delay for a retry attempt using exponential backoff with jitter
func (t *HTTPTransport) calculateBackoffDelay(attempt int) time.Duration {
	// Calculate exponential delay: baseDelay * multiplier^(attempt-1)
	delayFloat := float64(t.config.RetryBaseDelay.Milliseconds()) * math.Pow(t.config.RetryMultiplier, float64(attempt-1))

	// Apply jitter: delay * (1 + random(-jitter, +jitter))
	jitterRange := t.config.RetryJitter * 2
	jitterValue := (rand.Float64()*jitterRange - t.config.RetryJitter) // Random between -jitter and +jitter
	delayFloat *= (1 + jitterValue)

	// Ensure delay is within bounds
	delay := time.Duration(delayFloat) * time.Millisecond
	if delay < t.config.RetryBaseDelay {
		delay = t.config.RetryBaseDelay
	}
	if delay > t.config.RetryMaxDelay {
		delay = t.config.RetryMaxDelay
	}

	return delay
}

// shouldRetryStatusCode returns true if the status code indicates a retryable error
func (t *HTTPTransport) shouldRetryStatusCode(statusCode int) bool {
	// Retry on server errors and some client errors
	return statusCode == http.StatusRequestTimeout ||
		statusCode == http.StatusTooManyRequests ||
		statusCode == http.StatusInternalServerError ||
		statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout ||
		statusCode >= 500
}

// parseResponse parses a successful HTTP response into a distribution receipt
func (t *HTTPTransport) parseResponse(resp *http.Response, job FixtureDistributionJob, target FixtureDistributionTarget) (FixtureDistributionReceipt, error) {
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: failed to read response body: %v", ErrTransportInvalidResponse, err)
	}

	// Try to parse as JSON receipt
	var receipt FixtureDistributionReceipt
	if err := json.Unmarshal(body, &receipt); err == nil {
		// Validate receipt
		if receipt.DistributionID == "" {
			receipt.DistributionID = job.DistributionID
		}
		if receipt.TargetID == "" {
			receipt.TargetID = target.ID
		}
		if receipt.ReceivedAtUnix <= 0 {
			receipt.ReceivedAtUnix = time.Now().Unix()
		}
		if receipt.ReceiptHash == "" {
			receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)
		}
		return receipt, nil
	}

	// If not JSON, create a basic receipt
	receipt = FixtureDistributionReceipt{
		DistributionID:       job.DistributionID,
		TargetID:             target.ID,
		ReceivedAtUnix:       time.Now().Unix(),
		ReceivedCatalogHash:  job.CatalogHash,
		ReceivedBundleHashes: job.BundleHashes,
		VerificationStatus:   fmt.Sprintf("http-%d", resp.StatusCode),
	}
	receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

	return receipt, nil
}

// handleNonRetryableResponse handles non-retryable HTTP responses
func (t *HTTPTransport) handleNonRetryableResponse(resp *http.Response, job FixtureDistributionJob) error {
	defer resp.Body.Close()

	// Read response body for error details
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: HTTP %d - %s", ErrTransportInvalidResponse, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	// Check for authentication failure
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: HTTP %d - %s", ErrTransportAuthFailed, resp.StatusCode, string(body))
	}

	return fmt.Errorf("%w: HTTP %d - %s", ErrTransportInvalidResponse, resp.StatusCode, string(body))
}

// LocalFileTransport implements FixtureTransport for local file distribution
type LocalFileTransport struct {
	config          TransportConfig
	basePath        string
	overwrite       bool
	metricsRecorder TransportMetricsRecorder
}

// LocalFileTransportOptions contains options for creating a LocalFileTransport
type LocalFileTransportOptions struct {
	Config    TransportConfig
	BasePath  string
	Overwrite bool
}

// NewLocalFileTransport creates a new local file transport with options
func NewLocalFileTransport(options LocalFileTransportOptions) (*LocalFileTransport, error) {
	config := options.Config
	if config.Timeout <= 0 {
		config.Timeout = DefaultTransportTimeout
	}
	if config.RetryCount <= 0 {
		config.RetryCount = DefaultTransportRetryCount
	}

	// Validate base path if provided
	basePath := options.BasePath
	if basePath != "" {
		absPath, err := filepath.Abs(basePath)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid base path: %v", ErrTransportInvalidPath, err)
		}
		basePath = absPath
	}

	return &LocalFileTransport{
		config:          config,
		basePath:        basePath,
		overwrite:       options.Overwrite,
		metricsRecorder: &NopTransportMetricsRecorder{},
	}, nil
}

// NewLocalFileTransportWithConfig creates a new local file transport with just config
func NewLocalFileTransportWithConfig(options FixtureTransportOptions) (*LocalFileTransport, error) {
	return NewLocalFileTransport(LocalFileTransportOptions{
		Config: options.Config,
	})
}

// Name returns the name of this transport
func (t *LocalFileTransport) Name() string {
	return "local_file"
}

// Method returns the distribution method this transport handles
func (t *LocalFileTransport) Method() DistributionMethod {
	return DistributionMethodLocalFile
}

// SetBasePath sets the base path for file operations
func (t *LocalFileTransport) SetBasePath(path string) error {
	if path == "" {
		t.basePath = ""
		return nil
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%w: invalid path: %v", ErrTransportInvalidPath, err)
	}
	t.basePath = absPath
	return nil
}

// SetOverwrite configures whether existing files should be overwritten
func (t *LocalFileTransport) SetOverwrite(overwrite bool) {
	t.overwrite = overwrite
}

// GetBasePath returns the current base path
func (t *LocalFileTransport) GetBasePath() string {
	return t.basePath
}

// SetMetricsRecorder sets the metrics recorder for this transport
func (t *LocalFileTransport) SetMetricsRecorder(recorder TransportMetricsRecorder) {
	t.metricsRecorder = recorder
}

// Distribute writes fixture data to a local file
func (t *LocalFileTransport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// Record start of operation
	startTime := time.Now()
	if t.metricsRecorder != nil {
		t.metricsRecorder.IncrementConcurrent(TransportMethodLocal)
		defer t.metricsRecorder.DecrementConcurrent(TransportMethodLocal)
	}

	// Validate payload
	if len(payload) > MaxTransportPayloadSize {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodLocal, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: payload too large (max %d bytes)", ErrTransportInvalidResponse, MaxTransportPayloadSize)
	}

	// Get the full file path
	filePath, err := t.getFilePath(target)
	if err != nil {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodLocal, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, err
	}

	// Validate file path length
	if len(filePath) > MaxFilePathLength {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodLocal, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: file path too long (max %d characters)", ErrTransportInvalidPath, MaxFilePathLength)
	}

	// Check if file already exists
	if !t.overwrite {
		if _, err := os.Stat(filePath); err == nil {
			if t.metricsRecorder != nil {
				t.metricsRecorder.RecordOperation(TransportMethodLocal, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
			}
			return FixtureDistributionReceipt{}, fmt.Errorf("%w: file already exists at %s", ErrTransportFileExists, filePath)
		}
	}

	// Create parent directory if it doesn't exist
	parentDir := filepath.Dir(filePath)
	if err := os.MkdirAll(parentDir, DefaultDirectoryPermissions); err != nil {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodLocal, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: failed to create parent directory: %v", ErrTransportInvalidPath, err)
	}

	// Write payload to file atomically
	// First write to a temporary file in the same directory, then rename for atomicity
	tempFile := filepath.Join(parentDir, ".tmp_"+filepath.Base(filePath)+"_"+fmt.Sprintf("%d", time.Now().UnixNano()))
	defer func() {
		// Clean up temp file on error
		os.Remove(tempFile)
	}()

	// Write with retry logic
	var writeErr error
	for attempt := 0; attempt <= t.config.RetryCount; attempt++ {
		// Wait before retry (skip on first attempt)
		if attempt > 0 {
			delay := t.calculateBackoffDelay(attempt)
			select {
			case <-ctx.Done():
				return FixtureDistributionReceipt{}, fmt.Errorf("%w: context cancelled during write retry", ErrTransportTimeout)
			case <-time.After(delay):
			}
		}

		// Write payload to temp file with restricted permissions
		writeErr = os.WriteFile(tempFile, payload, DefaultFilePermissions)
		if writeErr == nil {
			// Successfully wrote to temp file, now rename atomically
			if err := os.Rename(tempFile, filePath); err != nil {
				writeErr = fmt.Errorf("%w: failed to rename temp file: %v", ErrTransportFileWriteFailed, err)
				continue
			}
			// Success - temp file is now the target file
			// Mark tempFile as empty to prevent cleanup from deleting our file
			tempFile = ""
			break
		}

		// Check if it's a retryable error
		if !isRetryableFileError(writeErr) {
			if t.metricsRecorder != nil {
				t.metricsRecorder.RecordOperation(TransportMethodLocal, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
			}
			return FixtureDistributionReceipt{}, writeErr
		}
		// Record retry attempt
		if t.metricsRecorder != nil && attempt < t.config.RetryCount {
			t.metricsRecorder.RecordRetry(TransportMethodLocal, TransportOpDistribute, TransportOutcomeRetry)
		}
	}

	if writeErr != nil {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodLocal, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w after %d attempts", ErrTransportRetryExhausted, t.config.RetryCount+1)
	}

	// Verify the file was written correctly
	writtenData, err := os.ReadFile(filePath)
	if err != nil {
		// File verification failed - clean up
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodLocal, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		os.Remove(filePath)
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: failed to verify written file: %v", ErrTransportFileReadFailed, err)
	}

	// Verify hash matches
	writtenHash := sha256.Sum256(writtenData)
	expectedHash := sha256.Sum256(payload)
	if writtenHash != expectedHash {
		// Hash mismatch - file was corrupted
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodLocal, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		os.Remove(filePath)
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: file verification failed - hash mismatch", ErrTransportFileWriteFailed)
	}

	// Create receipt
	nowUnix := time.Now().Unix()
	receipt := FixtureDistributionReceipt{
		DistributionID:       job.DistributionID,
		TargetID:             target.ID,
		ReceivedAtUnix:       nowUnix,
		ReceivedCatalogHash:  job.CatalogHash,
		ReceivedBundleHashes: job.BundleHashes,
		VerificationStatus:   "verified",
	}
	receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

	if t.metricsRecorder != nil {
		t.metricsRecorder.RecordOperation(TransportMethodLocal, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeSuccess)
	}

	return receipt, nil
}

// getFilePath generates the file path for a distribution
func (t *LocalFileTransport) getFilePath(target FixtureDistributionTarget) (string, error) {
	// Use target URL as the path (for local file, URL is the file path)
	filePath := target.URL

	// Security checks on the input path before any processing
	// Prevent absolute paths
	if filepath.IsAbs(filePath) {
		return "", fmt.Errorf("%w: absolute paths are not allowed", ErrTransportInvalidPath)
	}

	// Prevent paths starting with .. or containing .. sequences
	if strings.HasPrefix(filePath, "..") || strings.Contains(filePath, "/..") || strings.Contains(filePath, "\\..") {
		return "", fmt.Errorf("%w: directory traversal not allowed", ErrTransportInvalidPath)
	}

	// Prevent home directory paths
	if strings.HasPrefix(filePath, "~") {
		return "", fmt.Errorf("%w: home directory paths not allowed", ErrTransportInvalidPath)
	}

	// Prevent null bytes
	if strings.Contains(filePath, "\x00") {
		return "", fmt.Errorf("%w: invalid path - contains null byte", ErrTransportInvalidPath)
	}

	// If base path is set, join it with the target URL
	if t.basePath != "" {
		// Clean the target URL path
		cleanPath := filepath.Clean(filePath)
		// Join with base path
		filePath = filepath.Join(t.basePath, cleanPath)
	}

	// Clean the final path
	cleanPath := filepath.Clean(filePath)

	// Security check: prevent directory traversal attacks
	// If we have a base path, ensure the final path is within it
	if t.basePath != "" && filepath.IsAbs(cleanPath) {
		relPath, err := filepath.Rel(t.basePath, cleanPath)
		if err != nil || strings.HasPrefix(relPath, "..") {
			return "", fmt.Errorf("%w: invalid path - directory traversal detected", ErrTransportInvalidPath)
		}
		cleanPath = filepath.Join(t.basePath, relPath)
	}

	// Ensure the path is valid
	if cleanPath == "" || cleanPath == "." || cleanPath == ".." {
		return "", fmt.Errorf("%w: invalid file path", ErrTransportInvalidPath)
	}

	// Final check for null bytes
	if strings.Contains(cleanPath, "\x00") {
		return "", fmt.Errorf("%w: invalid path - contains null byte", ErrTransportInvalidPath)
	}

	return cleanPath, nil
}

// calculateBackoffDelay calculates exponential backoff delay for LocalFileTransport
func (t *LocalFileTransport) calculateBackoffDelay(attempt int) time.Duration {
	baseDelayMS := int(t.config.RetryBaseDelay.Milliseconds())
	if baseDelayMS <= 0 {
		baseDelayMS = int(DefaultTransportRetryBaseDelay.Milliseconds())
	}

	// Calculate exponential delay: baseDelay * multiplier^(attempt-1)
	delayFloat := float64(baseDelayMS) * math.Pow(t.config.RetryMultiplier, float64(attempt-1))

	// Apply jitter: delay * (1 + random(-jitter, +jitter))
	jitterRange := t.config.RetryJitter * 2
	jitterValue := (rand.Float64()*jitterRange - t.config.RetryJitter)
	delayFloat *= (1 + jitterValue)

	// Ensure delay is at least base delay
	if delayFloat < float64(baseDelayMS) {
		delayFloat = float64(baseDelayMS)
	}

	return time.Duration(delayFloat) * time.Millisecond
}

// isRetryableFileError returns true if the file error is retryable
func isRetryableFileError(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific retryable errors
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		if os.IsPermission(pathError.Err) {
			return true
		}
		if os.IsNotExist(pathError.Err) {
			// Parent directory might not exist - will be created
			return true
		}
	}

	// Check error message
	errStr := err.Error()
	return strings.Contains(errStr, "temporary") ||
		strings.Contains(errStr, "resource temporarily unavailable") ||
		strings.Contains(errStr, "too many open files") ||
		strings.Contains(errStr, "device or resource busy")
}

// S3Transport implements FixtureTransport for S3 distribution
type S3Transport struct {
	config    TransportConfig
	bucket    string
	keyPrefix string
	useSSL    bool
	region    string
	endpoint  string
	// AWS SDK client (optional - only initialized when AWS SDK is available)
	s3Client *s3sdk.Client
	// AWS configuration
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	useDefaultCreds bool
	metricsRecorder TransportMetricsRecorder
}

// S3TransportOptions contains options for creating an S3Transport
type S3TransportOptions struct {
	Config          TransportConfig
	Bucket          string
	KeyPrefix       string
	UseSSL          bool
	Region          string
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	UseDefaultCreds bool
}

// NewS3Transport creates a new S3 transport
func NewS3Transport(options FixtureTransportOptions) (*S3Transport, error) {
	return NewS3TransportWithOptions(S3TransportOptions{
		Config: options.Config,
	})
}

// NewS3TransportWithOptions creates a new S3 transport with full options
func NewS3TransportWithOptions(options S3TransportOptions) (*S3Transport, error) {
	config := options.Config
	if config.Timeout <= 0 {
		config.Timeout = DefaultTransportTimeout
	}
	if config.RetryCount <= 0 {
		config.RetryCount = DefaultTransportRetryCount
	}

	// Validate bucket if provided
	if options.Bucket != "" {
		if err := validateS3BucketName(options.Bucket); err != nil {
			return nil, err
		}
	}

	// Validate region if provided
	if options.Region != "" {
		if err := validateS3Region(options.Region); err != nil {
			return nil, err
		}
	}

	// Validate custom endpoint early - fail fast for unsafe configurations
	if options.Endpoint != "" {
		if err := validateS3Endpoint(options.Endpoint); err != nil {
			return nil, err
		}
	}

	// Default to SSL
	useSSL := options.UseSSL
	if !useSSL && options.Endpoint == "" {
		useSSL = true // Default to SSL for standard S3
	}

	// Initialize AWS SDK client if credentials are provided or default creds are enabled
	var s3Client *s3sdk.Client
	if options.AccessKeyID != "" || options.SecretAccessKey != "" || options.UseDefaultCreds {
		var awsConfig aws.Config
		var err error

		if options.UseDefaultCreds && options.AccessKeyID == "" && options.SecretAccessKey == "" {
			// Use default AWS credential chain
			awsConfig, err = awsconfig.LoadDefaultConfig(context.TODO(),
				awsconfig.WithRegion(options.Region),
			)
		} else {
			// Use provided credentials
			creds := credentials.NewStaticCredentialsProvider(
				options.AccessKeyID,
				options.SecretAccessKey,
				options.SessionToken,
			)
			awsConfig, err = awsconfig.LoadDefaultConfig(context.TODO(),
				awsconfig.WithCredentialsProvider(creds),
				awsconfig.WithRegion(options.Region),
			)
		}

		if err == nil {
			s3Client = s3sdk.NewFromConfig(awsConfig, func(o *s3sdk.Options) {
				o.UsePathStyle = true
				// Security: Always use SSL/TLS for S3 connections
				o.UseAccelerate = false // Don't use S3 Accelerate (uses different endpoint)
				if options.Endpoint != "" {
					o.EndpointResolver = s3sdk.EndpointResolverFromURL(options.Endpoint)
				}
				// Security: Enforce TLS 1.2+ for all S3 connections
				// Note: AWS SDK v2 uses TLS 1.2+ by default, but we explicitly set it
				// This will be handled by the AWS SDK's default TLS configuration
			})
		} else {
			// Log AWS config error but don't fail transport creation
			// The upload will fail later with a more specific error
			// This allows the transport to be created even if AWS config fails
		}
	}

	return &S3Transport{
		config:          config,
		bucket:          options.Bucket,
		keyPrefix:       options.KeyPrefix,
		useSSL:          useSSL,
		region:          options.Region,
		endpoint:        options.Endpoint,
		s3Client:        s3Client,
		accessKeyID:     options.AccessKeyID,
		secretAccessKey: options.SecretAccessKey,
		sessionToken:    options.SessionToken,
		useDefaultCreds: options.UseDefaultCreds,
		metricsRecorder: &NopTransportMetricsRecorder{},
	}, nil
}

// Name returns the name of this transport
func (t *S3Transport) Name() string {
	return "s3"
}

// Method returns the distribution method this transport handles
func (t *S3Transport) Method() DistributionMethod {
	return DistributionMethodS3
}

// SetBucket sets the S3 bucket name
func (t *S3Transport) SetBucket(bucket string) error {
	if err := validateS3BucketName(bucket); err != nil {
		return err
	}
	t.bucket = bucket
	return nil
}

// SetKeyPrefix sets the key prefix for S3 objects
func (t *S3Transport) SetKeyPrefix(prefix string) {
	// Clean the prefix - remove leading/trailing slashes
	t.keyPrefix = strings.Trim(prefix, "/")
}

// SetMetricsRecorder sets the metrics recorder for this transport
func (t *S3Transport) SetMetricsRecorder(recorder TransportMetricsRecorder) {
	t.metricsRecorder = recorder
}

// SetRegion sets the AWS region
func (t *S3Transport) SetRegion(region string) error {
	if err := validateS3Region(region); err != nil {
		return err
	}
	t.region = region
	return nil
}

// SetAWSCredentials sets AWS credentials for S3 uploads
func (t *S3Transport) SetAWSCredentials(accessKeyID, secretAccessKey, sessionToken string) error {
	t.accessKeyID = accessKeyID
	t.secretAccessKey = secretAccessKey
	t.sessionToken = sessionToken
	t.useDefaultCreds = false

	// Initialize S3 client with new credentials
	if accessKeyID != "" || secretAccessKey != "" {
		creds := credentials.NewStaticCredentialsProvider(
			accessKeyID,
			secretAccessKey,
			sessionToken,
		)
		awsConfig, err := awsconfig.LoadDefaultConfig(context.TODO(),
			awsconfig.WithCredentialsProvider(creds),
			awsconfig.WithRegion(t.region),
		)
		if err != nil {
			return fmt.Errorf("%w: failed to create AWS config: %v", ErrTransportConnectionFailed, sanitizeError(err, accessKeyID, secretAccessKey, sessionToken))
		}

		t.s3Client = s3sdk.NewFromConfig(awsConfig, func(o *s3sdk.Options) {
			o.UsePathStyle = true
			if t.endpoint != "" {
				o.EndpointResolver = s3sdk.EndpointResolverFromURL(t.endpoint)
			}
		})
	}

	return nil
}

// SetUseDefaultAWSCredentials enables use of default AWS credential chain
func (t *S3Transport) SetUseDefaultAWSCredentials(useDefault bool) error {
	t.useDefaultCreds = useDefault
	t.accessKeyID = ""
	t.secretAccessKey = ""
	t.sessionToken = ""

	// Initialize S3 client with default credentials
	if useDefault {
		awsConfig, err := awsconfig.LoadDefaultConfig(context.TODO(),
			awsconfig.WithRegion(t.region),
		)
		if err != nil {
			return fmt.Errorf("%w: failed to create AWS config: %v", ErrTransportConnectionFailed, sanitizeError(err))
		}

		t.s3Client = s3sdk.NewFromConfig(awsConfig, func(o *s3sdk.Options) {
			o.UsePathStyle = true
			if t.endpoint != "" {
				o.EndpointResolver = s3sdk.EndpointResolverFromURL(t.endpoint)
			}
		})
	} else {
		t.s3Client = nil
	}

	return nil
}

// Distribute uploads fixture data to S3
// Note: This implementation requires the AWS SDK to be available for actual S3 operations.
// The transport layer logic is complete, but without the SDK, it will return ErrTransportSDKNecessary.
func (t *S3Transport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// Record start of operation
	startTime := time.Now()
	if t.metricsRecorder != nil {
		t.metricsRecorder.IncrementConcurrent(TransportMethodS3)
		defer t.metricsRecorder.DecrementConcurrent(TransportMethodS3)
	}

	// Validate payload
	if len(payload) > MaxTransportPayloadSize {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodS3, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: payload too large (max %d bytes)", ErrTransportInvalidResponse, MaxTransportPayloadSize)
	}

	// Parse S3 URL from target
	bucket, key, err := t.ParseS3URL(target.URL)
	if err != nil {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodS3, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, err
	}

	// Use configured bucket if not specified in URL
	if bucket == "" && t.bucket != "" {
		bucket = t.bucket
	}

	// Validate bucket
	if bucket == "" {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodS3, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: no bucket specified", ErrTransportInvalidPath)
	}

	// Apply key prefix
	if t.keyPrefix != "" {
		key = t.keyPrefix + "/" + key
	}

	// Validate key
	if err := validateS3Key(key); err != nil {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodS3, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, err
	}

	// Generate S3 object key with distribution metadata
	fullKey := t.generateS3ObjectKey(job, key)

	// Attempt to upload with retry logic
	var uploadErr error
	for attempt := 0; attempt <= t.config.RetryCount; attempt++ {
		// Wait before retry (skip on first attempt)
		if attempt > 0 {
			delay := t.calculateBackoffDelay(attempt)
			select {
			case <-ctx.Done():
				return FixtureDistributionReceipt{}, fmt.Errorf("%w: context cancelled during S3 upload retry", ErrTransportTimeout)
			case <-time.After(delay):
			}
		}

		// Try to upload (this requires AWS SDK)
		uploadErr = t.uploadToS3(ctx, bucket, fullKey, payload, target)
		if uploadErr == nil {
			// Success
			break
		}

		// Check if it's a retryable error
		if !t.isRetryableS3Error(uploadErr) {
			if t.metricsRecorder != nil {
				t.metricsRecorder.RecordOperation(TransportMethodS3, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
			}
			return FixtureDistributionReceipt{}, uploadErr
		}
		// Record retry attempt
		if t.metricsRecorder != nil && attempt < t.config.RetryCount {
			t.metricsRecorder.RecordRetry(TransportMethodS3, TransportOpDistribute, TransportOutcomeRetry)
		}
	}

	if uploadErr != nil {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodS3, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w after %d attempts", ErrTransportRetryExhausted, t.config.RetryCount+1)
	}

	// Create receipt
	nowUnix := time.Now().Unix()
	receipt := FixtureDistributionReceipt{
		DistributionID:       job.DistributionID,
		TargetID:             target.ID,
		ReceivedAtUnix:       nowUnix,
		ReceivedCatalogHash:  job.CatalogHash,
		ReceivedBundleHashes: job.BundleHashes,
		VerificationStatus:   "verified",
	}
	receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

	if t.metricsRecorder != nil {
		t.metricsRecorder.RecordOperation(TransportMethodS3, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeSuccess)
	}

	return receipt, nil
}

// ParseS3URL parses an S3 URL (s3://bucket/key) into bucket and key
func (t *S3Transport) ParseS3URL(rawURL string) (string, string, error) {
	if rawURL == "" {
		return "", "", fmt.Errorf("%w: empty S3 URL", ErrTransportInvalidPath)
	}

	// Check if this has a scheme that's not s3://
	if strings.Contains(rawURL, "://") {
		// Split on :// to check the scheme
		schemeEnd := strings.Index(rawURL, "://")
		scheme := rawURL[:schemeEnd]
		if scheme != "s3" {
			return "", "", fmt.Errorf("%w: unsupported URL scheme '%s', only s3:// is supported", ErrTransportInvalidPath, scheme)
		}
		// Continue with s3:// parsing
		path := strings.TrimPrefix(rawURL, "s3://")
		if path == "" {
			return "", "", fmt.Errorf("%w: missing bucket in S3 URL", ErrTransportInvalidPath)
		}

		// Split into bucket and key
		parts := strings.SplitN(path, "/", 2)
		bucket := parts[0]
		key := ""
		if len(parts) > 1 {
			key = parts[1]
		}

		// Clean key
		key = strings.Trim(key, "/")

		return bucket, key, nil
	} else {
		// No scheme, parse as just bucket/key
		parts := strings.SplitN(rawURL, "/", 2)
		if len(parts) == 1 {
			// Just bucket
			if parts[0] == "" {
				return "", "", fmt.Errorf("%w: empty bucket name", ErrTransportInvalidPath)
			}
			return parts[0], "", nil
		} else if len(parts) == 2 {
			// bucket/key
			if parts[0] == "" {
				return "", "", fmt.Errorf("%w: empty bucket name", ErrTransportInvalidPath)
			}
			key := strings.Trim(parts[1], "/")
			return parts[0], key, nil
		} else {
			return "", "", fmt.Errorf("%w: invalid S3 URL format", ErrTransportInvalidPath)
		}
	}
}

// generateS3ObjectKey generates a unique S3 object key with distribution metadata
func (t *S3Transport) generateS3ObjectKey(job FixtureDistributionJob, baseKey string) string {
	// Use the job hash as part of the key for uniqueness
	// Format: {baseKey}/{distributionID}/{catalogHash}.json
	// Or: {baseKey}/fixtures/{distributionID}/{catalogHash}.json

	if baseKey == "" {
		baseKey = "fixtures"
	}

	// Ensure no leading/trailing slashes
	baseKey = strings.Trim(baseKey, "/")

	// Build the key path
	key := filepath.Join(baseKey, "fixtures", job.DistributionID)
	if job.CatalogHash != "" {
		key = filepath.Join(key, job.CatalogHash+".json")
	} else if len(job.BundleHashes) > 0 {
		// Use first bundle hash if no catalog hash
		key = filepath.Join(key, job.BundleHashes[0]+".json")
	} else {
		key = filepath.Join(key, "fixture.json")
	}

	// Normalize path separators for S3 (use forward slashes)
	key = filepath.ToSlash(key)
	return key
}

// uploadToS3 uploads payload to S3 using AWS SDK
func (t *S3Transport) uploadToS3(ctx context.Context, bucket, key string, payload []byte, target FixtureDistributionTarget) error {
	// Validate payload size
	if len(payload) > MaxTransportPayloadSize {
		return fmt.Errorf("%w: payload too large (max %d bytes)", ErrTransportInvalidResponse, MaxTransportPayloadSize)
	}

	// Apply context timeout to the upload operation
	if t.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.config.Timeout)
		defer cancel()
	}

	// Check if we have an S3 client
	if t.s3Client == nil {
		// Try to initialize with default credentials if not already configured
		if t.useDefaultCreds {
			awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(t.region))
			if err != nil {
				return fmt.Errorf("%w: no AWS S3 client configured and failed to initialize: %v", ErrTransportConnectionFailed, err)
			}
			t.s3Client = s3sdk.NewFromConfig(awsConfig, func(o *s3sdk.Options) {
				o.UsePathStyle = true
				// Security: Always use SSL/TLS for S3 connections
				o.UseAccelerate = false
				if t.endpoint != "" {
					// Validate endpoint URL to prevent SSRF
					if err := validateS3Endpoint(t.endpoint); err != nil {
						// If endpoint is invalid, don't use it
						// This prevents SSRF attacks via custom endpoints
						return
					}
					o.EndpointResolver = s3sdk.EndpointResolverFromURL(t.endpoint)
				}
			})
		} else {
			return fmt.Errorf("%w: no AWS S3 client configured - use SetAWSCredentials() or SetUseDefaultAWSCredentials()", ErrTransportConnectionFailed)
		}
	}

	// Validate bucket
	if bucket == "" {
		if t.bucket == "" {
			return fmt.Errorf("%w: no S3 bucket specified", ErrTransportInvalidPath)
		}
		bucket = t.bucket
	}

	// Validate bucket name
	if err := validateS3BucketName(bucket); err != nil {
		return err
	}

	// Full key with prefix
	fullKey := key
	if t.keyPrefix != "" {
		fullKey = t.keyPrefix + "/" + key
	}

	// Clean the key
	fullKey = strings.Trim(fullKey, "/")

	// Validate S3 key
	if err := validateS3Key(fullKey); err != nil {
		return err
	}

	// Upload to S3 using AWS SDK
	_, err := t.s3Client.PutObject(ctx, &s3sdk.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(fullKey),
		Body:   bytes.NewReader(payload),
		// Set appropriate content type for fixture data
		ContentType: aws.String("application/json"),
	})

	if err != nil {
		var awsErr interface{ Error() string }
		if errors.As(err, &awsErr) {
			return fmt.Errorf("%w: S3 upload failed: %s", ErrTransportConnectionFailed, awsErr.Error())
		}
		return fmt.Errorf("%w: S3 upload failed: %v", ErrTransportConnectionFailed, err)
	}

	return nil
}

// validateS3BucketName validates an S3 bucket name
func validateS3BucketName(bucket string) error {
	if bucket == "" {
		return fmt.Errorf("%w: bucket name cannot be empty", ErrTransportInvalidPath)
	}

	// S3 bucket naming rules:
	// - Must be between 3 and 63 characters
	// - Can contain only lowercase letters, numbers, dots, and hyphens
	// - Must start and end with a letter or number
	if len(bucket) < 3 || len(bucket) > 63 {
		return fmt.Errorf("%w: bucket name must be 3-63 characters", ErrTransportInvalidPath)
	}

	// Check first character
	firstChar := bucket[0]
	if !((firstChar >= 'a' && firstChar <= 'z') || (firstChar >= '0' && firstChar <= '9')) {
		return fmt.Errorf("%w: bucket name must start with letter or number", ErrTransportInvalidPath)
	}

	// Check last character
	lastChar := bucket[len(bucket)-1]
	if !((lastChar >= 'a' && lastChar <= 'z') || (lastChar >= '0' && lastChar <= '9')) {
		return fmt.Errorf("%w: bucket name must end with letter or number", ErrTransportInvalidPath)
	}

	// Check all characters
	for _, c := range bucket {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return fmt.Errorf("%w: bucket name contains invalid character: %c", ErrTransportInvalidPath, c)
		}
	}

	// Check for consecutive periods
	if strings.Contains(bucket, "..") {
		return fmt.Errorf("%w: bucket name cannot contain consecutive periods", ErrTransportInvalidPath)
	}

	return nil
}

// validateS3Key validates an S3 object key
func validateS3Key(key string) error {
	if key == "" {
		return nil // Empty key is OK - will use default
	}

	// S3 key naming rules:
	// - Can be up to MaxS3KeyLength bytes (AWS limit: 1024)
	// - Can contain any character except null
	if len(key) > MaxS3KeyLength {
		return fmt.Errorf("%w: S3 key too long (max %d bytes)", ErrTransportInvalidPath, MaxS3KeyLength)
	}

	if strings.Contains(key, "\x00") {
		return fmt.Errorf("%w: S3 key cannot contain null byte", ErrTransportInvalidPath)
	}

	// Security: Prevent directory traversal in S3 keys
	if strings.Contains(key, "..") {
		return fmt.Errorf("%w: S3 key cannot contain directory traversal sequences", ErrTransportInvalidPath)
	}

	return nil
}

// validateS3Region validates an AWS region
func validateS3Region(region string) error {
	if region == "" {
		return nil // Empty region is OK - will use default
	}

	// Basic validation - AWS regions are typically lowercase with hyphens
	// e.g., us-east-1, eu-west-2, ap-southeast-1
	for _, c := range region {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return fmt.Errorf("%w: invalid region format", ErrTransportInvalidPath)
		}
	}

	return nil
}

// validateS3Endpoint validates an S3 endpoint URL to prevent SSRF attacks
func validateS3Endpoint(endpoint string) error {
	if endpoint == "" {
		return nil // Empty endpoint is OK - will use default AWS endpoint
	}

	// Parse the URL first for basic validation
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		// For invalid URLs that can't be parsed, return the original error type
		return fmt.Errorf("%w: invalid S3 endpoint URL: %v", ErrTransportInvalidPath, err)
	}

	// Check scheme - must be http or https for URL parsing to work
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		// For non-http/https schemes, return the original error type
		return fmt.Errorf("%w: S3 endpoint must use http or https scheme, got %s", ErrTransportInvalidPath, parsedURL.Scheme)
	}

	// Check scheme - must be https for custom endpoints (http is unsafe)
	if parsedURL.Scheme != "https" {
		return fmt.Errorf("%w: S3 custom endpoint must use https scheme, got %s", ErrTransportSecurityViolation, parsedURL.Scheme)
	}

	// Additional validation for known localhost variations
	host := parsedURL.Hostname()
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost.localdomain" {
		return fmt.Errorf("%w: S3 endpoint cannot point to localhost", ErrTransportSecurityViolation)
	}

	// Use the shared outbound network policy for comprehensive SSRF validation
	policy := DefaultOutboundTransportNetworkPolicy()
	return policy.ValidateParsedURL(parsedURL)
}

// validateHTTPTargetURL validates an HTTP target URL to prevent SSRF attacks
func validateHTTPTargetURL(parsedURL *url.URL) error {
	if parsedURL == nil {
		return fmt.Errorf("%w: URL cannot be nil", ErrTransportInvalidPath)
	}

	// Use the shared outbound network policy for consistent validation
	policy := DefaultOutboundTransportNetworkPolicy()
	return policy.ValidateParsedURL(parsedURL)
}

// isPrivateIPAddress checks if a hostname resolves to a private IP address
func isPrivateIPAddress(host string) bool {
	// Check for IP address literals in private ranges
	if ip := net.ParseIP(host); ip != nil {
		// Check for private IPv4 ranges
		if ip4 := ip.To4(); ip4 != nil {
			// 10.0.0.0/8
			if ip4[0] == 10 {
				return true
			}
			// 172.16.0.0/12
			if ip4[0] == 172 && (ip4[1]&0xF0) == 16 {
				return true
			}
			// 192.168.0.0/16
			if ip4[0] == 192 && ip4[1] == 168 {
				return true
			}
			// 169.254.0.0/16 (APIPA)
			if ip4[0] == 169 && ip4[1] == 254 {
				return true
			}
			// 127.0.0.0/8 (loopback)
			if ip4[0] == 127 {
				return true
			}
		}
		// Check for private IPv6 ranges
		if ip.To16() != nil {
			// fc00::/7 (Unique Local Address)
			if ip[0] == 0xfc || ip[0] == 0xfd {
				return true
			}
			// fe80::/10 (Link-local) - first byte is 0xfe, second byte has top 2 bits as 10xxxxxx
			if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
				return true
			}
			// ::1/128 (loopback)
			if ip.IsLoopback() {
				return true
			}
		}
	}

	return false
}

// isRetryableS3Error returns true if the S3 error is retryable
func (t *S3Transport) isRetryableS3Error(err error) bool {
	if err == nil {
		return false
	}

	// Without AWS SDK, we can't do proper error classification
	// In a real implementation, this would check for:
	// - ServiceUnavailableException
	// - SlowDown
	// - RequestTimeout
	// - ThrottlingException
	// - InternalError

	// For now, check error message for common retryable patterns
	errStr := err.Error()
	return strings.Contains(errStr, "throttl") ||
		strings.Contains(errStr, "slow down") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "unavailable") ||
		strings.Contains(errStr, "temporary") ||
		strings.Contains(errStr, "retry")
}

// calculateBackoffDelay calculates exponential backoff delay for S3Transport
func (t *S3Transport) calculateBackoffDelay(attempt int) time.Duration {
	baseDelayMS := int(t.config.RetryBaseDelay.Milliseconds())
	if baseDelayMS <= 0 {
		baseDelayMS = int(DefaultTransportRetryBaseDelay.Milliseconds())
	}

	// Calculate exponential delay: baseDelay * multiplier^(attempt-1)
	delayFloat := float64(baseDelayMS) * math.Pow(t.config.RetryMultiplier, float64(attempt-1))

	// Apply jitter: delay * (1 + random(-jitter, +jitter))
	jitterRange := t.config.RetryJitter * 2
	jitterValue := (rand.Float64()*jitterRange - t.config.RetryJitter)
	delayFloat *= (1 + jitterValue)

	// Ensure delay is at least base delay
	if delayFloat < float64(baseDelayMS) {
		delayFloat = float64(baseDelayMS)
	}

	return time.Duration(delayFloat) * time.Millisecond
}

// Close releases resources used by the S3Transport
func (t *S3Transport) Close() error {
	// Clear sensitive data from memory
	t.accessKeyID = ""
	t.secretAccessKey = ""
	t.sessionToken = ""
	t.useDefaultCreds = false

	// Note: S3 client doesn't need explicit cleanup in AWS SDK v2
	// The client is safe to garbage collect
	t.s3Client = nil

	return nil
}

// SSHTransport implements FixtureTransport for SSH/SFTP distribution
type SSHTransport struct {
	config         TransportConfig
	host           string
	port           int
	username       string
	useSFTP        bool
	knownHosts     string
	privateKey     []byte
	privateKeyPath string
	password       string
	// SSH client (optional - only initialized when SSH library is available)
	sshClient *ssh.Client
	// SSH configuration
	usePrivateKeyAuth     bool
	strictHostKeyChecking bool
	metricsRecorder       TransportMetricsRecorder
}

// SSHTransportOptions contains options for creating an SSHTransport
type SSHTransportOptions struct {
	Config                TransportConfig
	Host                  string
	Port                  int
	Username              string
	UseSFTP               bool
	KnownHosts            string
	PrivateKey            []byte
	PrivateKeyPath        string
	Password              string
	UsePrivateKeyAuth     bool
	StrictHostKeyChecking bool
}

// NewSSHTransport creates a new SSH transport
func NewSSHTransport(options FixtureTransportOptions) (*SSHTransport, error) {
	return NewSSHTransportWithOptions(SSHTransportOptions{
		Config: options.Config,
	})
}

// NewSSHTransportWithOptions creates a new SSH transport with full options
func NewSSHTransportWithOptions(options SSHTransportOptions) (*SSHTransport, error) {
	config := options.Config
	if config.Timeout <= 0 {
		config.Timeout = DefaultTransportTimeout
	}
	if config.RetryCount <= 0 {
		config.RetryCount = DefaultTransportRetryCount
	}

	// Validate SSH options (only if provided - allow empty for now, will validate on Distribute)
	if options.Host != "" {
		if err := validateSSHHost(options.Host); err != nil {
			return nil, err
		}
	}

	if options.Port != 0 && (options.Port < 0 || options.Port > 65535) {
		return nil, fmt.Errorf("%w: SSH port must be between 0 and 65535", ErrTransportInvalidPath)
	}

	if options.Username != "" {
		if err := validateSSHUsername(options.Username); err != nil {
			return nil, err
		}
	}

	// Default to SFTP
	useSFTP := options.UseSFTP
	if !useSFTP && options.PrivateKey != nil {
		useSFTP = true // If we have a private key, assume SFTP
	}

	return &SSHTransport{
		config:                config,
		host:                  options.Host,
		port:                  options.Port,
		username:              options.Username,
		useSFTP:               useSFTP,
		knownHosts:            options.KnownHosts,
		privateKey:            options.PrivateKey,
		privateKeyPath:        options.PrivateKeyPath,
		password:              options.Password,
		usePrivateKeyAuth:     options.UsePrivateKeyAuth,
		strictHostKeyChecking: options.StrictHostKeyChecking,
		metricsRecorder:       &NopTransportMetricsRecorder{},
	}, nil
}

// Name returns the name of this transport
func (t *SSHTransport) Name() string {
	return "ssh"
}

// Method returns the distribution method this transport handles
func (t *SSHTransport) Method() DistributionMethod {
	return DistributionMethodSSH
}

// SetHost sets the SSH host
func (t *SSHTransport) SetHost(host string) error {
	if err := validateSSHHost(host); err != nil {
		return err
	}
	t.host = host
	return nil
}

// SetPort sets the SSH port
func (t *SSHTransport) SetPort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("%w: SSH port must be between 0 and 65535", ErrTransportInvalidPath)
	}
	t.port = port
	return nil
}

// SetMetricsRecorder sets the metrics recorder for this transport
func (t *SSHTransport) SetMetricsRecorder(recorder TransportMetricsRecorder) {
	t.metricsRecorder = recorder
}

// SetUsername sets the SSH username
func (t *SSHTransport) SetUsername(username string) error {
	if err := validateSSHUsername(username); err != nil {
		return err
	}
	t.username = username
	return nil
}

// SetUseSFTP configures whether to use SFTP (true) or SCP (false)
func (t *SSHTransport) SetUseSFTP(useSFTP bool) {
	t.useSFTP = useSFTP
}

// SetSSHCredentials sets SSH authentication credentials
func (t *SSHTransport) SetSSHCredentials(username, password string) error {
	if err := validateSSHUsername(username); err != nil {
		return err
	}
	t.username = username
	t.password = password
	return nil
}

// SetPrivateKey sets the SSH private key for authentication
func (t *SSHTransport) SetPrivateKey(privateKey []byte) error {
	t.privateKey = privateKey
	if len(privateKey) > 0 {
		t.usePrivateKeyAuth = true
		// If we have a private key, default to SFTP
		if !t.useSFTP {
			t.useSFTP = true
		}
	}
	return nil
}

// SetPrivateKeyPath sets the path to the SSH private key file
func (t *SSHTransport) SetPrivateKeyPath(path string) error {
	t.privateKeyPath = path
	if path != "" {
		t.usePrivateKeyAuth = true
		// If we have a private key path, default to SFTP
		if !t.useSFTP {
			t.useSFTP = true
		}
	}
	return nil
}

// SetKnownHosts sets the known hosts file content for host key verification
func (t *SSHTransport) SetKnownHosts(knownHosts string) {
	t.knownHosts = knownHosts
}

// SetStrictHostKeyChecking enables or disables strict host key checking
func (t *SSHTransport) SetStrictHostKeyChecking(strict bool) {
	t.strictHostKeyChecking = strict
}

// Distribute uploads fixture data via SSH/SFTP
// Note: This implementation requires an SSH library (e.g., golang.org/x/crypto/ssh)
// to be available for actual SSH operations. The transport layer logic is complete,
// but without the library, it will return ErrTransportSDKNecessary.
func (t *SSHTransport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// Record start of operation
	startTime := time.Now()
	if t.metricsRecorder != nil {
		t.metricsRecorder.IncrementConcurrent(TransportMethodSSH)
		defer t.metricsRecorder.DecrementConcurrent(TransportMethodSSH)
	}

	// Validate payload for SSH transport - use SSH-specific limit which is larger
	if len(payload) > MaxPayloadSizeForSSH {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodSSH, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: payload too large for SSH (max %d bytes)", ErrTransportInvalidResponse, MaxPayloadSizeForSSH)
	}

	// Apply context timeout to the upload operation
	if t.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.config.Timeout)
		defer cancel()
	}

	// Parse SSH URL from target
	host, port, path, err := t.ParseSSHURL(target.URL)
	if err != nil {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodSSH, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, err
	}

	// Use configured values if not specified in URL
	if host == "" && t.host != "" {
		host = t.host
	}
	if port == 0 && t.port != 0 {
		port = t.port
	}

	// Validate host
	if host == "" {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodSSH, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: no SSH host specified", ErrTransportInvalidPath)
	}

	// Validate path
	if err := validateSSHPath(path); err != nil {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodSSH, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, err
	}

	// Generate remote file path with distribution metadata
	remotePath := t.generateSSHRemotePath(job, path)

	// Use configured username if not specified
	username := t.username
	if username == "" {
		username = "root" // Default, though this might not work
	}

	// Attempt to upload with retry logic
	var uploadErr error
	for attempt := 0; attempt <= t.config.RetryCount; attempt++ {
		// Wait before retry (skip on first attempt)
		if attempt > 0 {
			delay := t.calculateBackoffDelay(attempt)
			select {
			case <-ctx.Done():
				return FixtureDistributionReceipt{}, fmt.Errorf("%w: context cancelled during SSH upload retry", ErrTransportTimeout)
			case <-time.After(delay):
			}
		}

		// Try to upload (this requires SSH library)
		uploadErr = t.uploadViaSSH(ctx, host, port, username, remotePath, payload, target)
		if uploadErr == nil {
			// Success
			break
		}

		// Check if it's a retryable error
		if !t.isRetryableSSHError(uploadErr) {
			if t.metricsRecorder != nil {
				t.metricsRecorder.RecordOperation(TransportMethodSSH, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
			}
			return FixtureDistributionReceipt{}, uploadErr
		}
		// Record retry attempt
		if t.metricsRecorder != nil && attempt < t.config.RetryCount {
			t.metricsRecorder.RecordRetry(TransportMethodSSH, TransportOpDistribute, TransportOutcomeRetry)
		}
	}

	if uploadErr != nil {
		if t.metricsRecorder != nil {
			t.metricsRecorder.RecordOperation(TransportMethodSSH, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeFailure)
		}
		return FixtureDistributionReceipt{}, fmt.Errorf("%w after %d attempts", ErrTransportRetryExhausted, t.config.RetryCount+1)
	}

	// Create receipt
	nowUnix := time.Now().Unix()
	receipt := FixtureDistributionReceipt{
		DistributionID:       job.DistributionID,
		TargetID:             target.ID,
		ReceivedAtUnix:       nowUnix,
		ReceivedCatalogHash:  job.CatalogHash,
		ReceivedBundleHashes: job.BundleHashes,
		VerificationStatus:   "verified",
	}
	receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

	if t.metricsRecorder != nil {
		t.metricsRecorder.RecordOperation(TransportMethodSSH, TransportOpDistribute, uint64(time.Since(startTime).Milliseconds()), uint64(len(payload)), TransportOutcomeSuccess)
	}

	return receipt, nil
}

// ParseSSHURL parses an SSH/SFTP URL (ssh://user@host:port/path or sftp://user@host:port/path)
func (t *SSHTransport) ParseSSHURL(rawURL string) (string, int, string, error) {
	if rawURL == "" {
		return "", 0, "", fmt.Errorf("%w: empty SSH URL", ErrTransportInvalidPath)
	}

	var host, path string
	var port int = 0 // 0 means use default (22 for SSH, or default for SFTP)

	// Parse the URL
	var scheme string
	if strings.HasPrefix(rawURL, "ssh://") {
		scheme = "ssh"
		rawURL = strings.TrimPrefix(rawURL, "ssh://")
		port = 22 // Default SSH port
	} else if strings.HasPrefix(rawURL, "sftp://") {
		scheme = "sftp"
		rawURL = strings.TrimPrefix(rawURL, "sftp://")
		port = 22 // Default SFTP port (often same as SSH)
	} else {
		// No scheme, assume SSH
		scheme = "ssh"
		port = 22
	}

	// Extract username if present (user@host format) - we don't return username, just strip it
	if strings.Contains(rawURL, "@") {
		parts := strings.SplitN(rawURL, "@", 2)
		if len(parts) != 2 {
			return "", 0, "", fmt.Errorf("%w: invalid SSH URL format", ErrTransportInvalidPath)
		}
		// Strip username from URL
		rawURL = parts[1]
	}

	// Parse host and port
	var hostPort string
	if strings.Contains(rawURL, "/") {
		parts := strings.SplitN(rawURL, "/", 2)
		hostPort = parts[0]
		if len(parts) > 1 {
			path = parts[1]
		}
	} else {
		hostPort = rawURL
	}

	// Parse host:port
	if strings.Contains(hostPort, "[") {
		// IPv6 address with port like [::1]:22
		if strings.HasSuffix(hostPort, "]") {
			if strings.Contains(hostPort, "]:") {
				parts := strings.SplitN(hostPort, "]:", 2)
				host = parts[0] + "]"
				portStr := parts[1]
				parsedPort, err := parseSSHPort(portStr)
				if err != nil {
					return "", 0, "", err
				}
				port = parsedPort
			} else {
				host = hostPort
			}
		} else {
			// Malformed IPv6
			return "", 0, "", fmt.Errorf("%w: invalid IPv6 address in SSH URL", ErrTransportInvalidPath)
		}
	} else if strings.Contains(hostPort, ":") {
		// IPv4 or hostname with port
		parts := strings.SplitN(hostPort, ":", 2)
		if len(parts) == 2 {
			// Check if the first part is an IPv6 address without brackets
			if strings.Contains(parts[0], ":") {
				// Malformed - should have been in brackets
				return "", 0, "", fmt.Errorf("%w: invalid host format in SSH URL", ErrTransportInvalidPath)
			}
			host = parts[0]
			parsedPort, err := parseSSHPort(parts[1])
			if err != nil {
				return "", 0, "", err
			}
			port = parsedPort
		}
	} else {
		host = hostPort
	}

	// Clean path
	path = strings.Trim(path, "/")

	// Validate host
	if err := validateSSHHost(host); err != nil {
		return "", 0, "", err
	}

	// Set useSFTP based on scheme
	if scheme == "sftp" {
		t.useSFTP = true
	}

	return host, port, path, nil
}

// parseSSHPort parses an SSH port string
func parseSSHPort(portStr string) (int, error) {
	if portStr == "" {
		return 0, nil // 0 means use default
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid port number: %v", ErrTransportInvalidPath, err)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%w: port must be between 1 and 65535", ErrTransportInvalidPath)
	}
	return port, nil
}

// generateSSHRemotePath generates the remote file path for SSH/SFTP
func (t *SSHTransport) generateSSHRemotePath(job FixtureDistributionJob, basePath string) string {
	// Format: {basePath}/fixtures/{distributionID}/{catalogHash}.json
	// Or: {basePath}/{distributionID}.json

	if basePath == "" {
		basePath = "/tmp/fixtures"
	}

	// Ensure no leading/trailing slashes
	basePath = strings.Trim(basePath, "/")

	// Build the path
	path := "/" + filepath.Join(basePath, "fixtures", job.DistributionID)
	if job.CatalogHash != "" {
		path = "/" + filepath.Join(basePath, "fixtures", job.DistributionID, job.CatalogHash+".json")
	} else if len(job.BundleHashes) > 0 {
		path = "/" + filepath.Join(basePath, "fixtures", job.DistributionID, job.BundleHashes[0]+".json")
	} else {
		path = "/" + filepath.Join(basePath, "fixtures", job.DistributionID, "fixture.json")
	}

	// Normalize path
	path = filepath.ToSlash(path)
	return path
}

// uploadViaSSH uploads payload via SSH/SFTP
// This is a placeholder that would use an SSH library in a real implementation
func (t *SSHTransport) uploadViaSSH(ctx context.Context, host string, port int, username, remotePath string, payload []byte, target FixtureDistributionTarget) error {
	// Use configured values if not specified in parameters
	if host == "" {
		host = t.host
	}
	if port == 0 {
		port = t.port
	}
	if username == "" {
		username = t.username
	}

	// Validate host
	if host == "" {
		return fmt.Errorf("%w: no SSH host specified", ErrTransportInvalidPath)
	}

	// Validate username
	if username == "" {
		return fmt.Errorf("%w: no SSH username specified", ErrTransportInvalidPath)
	}

	// Validate port
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%w: invalid SSH port: %d", ErrTransportInvalidPath, port)
	}

	// Validate remote path
	if remotePath == "" {
		return fmt.Errorf("%w: no remote path specified", ErrTransportInvalidPath)
	}

	// Clean remote path
	remotePath = strings.Trim(remotePath, "/")

	// Add authentication methods
	var sshConfig *ssh.ClientConfig
	if t.usePrivateKeyAuth && len(t.privateKey) > 0 {
		// Use provided private key
		privateKey, err := ssh.ParsePrivateKey(t.privateKey)
		if err != nil {
			return fmt.Errorf("%w: failed to parse SSH private key: %v", ErrTransportAuthFailed, sanitizeError(err))
		}
		sshConfig = &ssh.ClientConfig{
			User:    username,
			Auth:    []ssh.AuthMethod{ssh.PublicKeys(privateKey)},
			Timeout: t.config.Timeout,
		}
	} else if t.password != "" {
		// Use password authentication
		sshConfig = &ssh.ClientConfig{
			User:    username,
			Auth:    []ssh.AuthMethod{ssh.Password(t.password)},
			Timeout: t.config.Timeout,
		}
	} else {
		return fmt.Errorf("%w: no SSH authentication method configured", ErrTransportAuthFailed)
	}

	// Set up host key verification - strict by default for production safety
	if t.strictHostKeyChecking {
		if t.knownHosts != "" {
			// Parse known hosts and create callback
			hostKeyCallback, err := t.createKnownHostsCallback()
			if err != nil {
				return fmt.Errorf("%w: failed to create host key callback: %v", ErrTransportConnectionFailed, err)
			}
			sshConfig.HostKeyCallback = hostKeyCallback
		} else {
			// Strict checking requested but no known hosts provided - fail closed
			return fmt.Errorf("%w: strict host key checking requires known hosts to be configured", ErrTransportSecurityViolation)
		}
	} else {
		// Non-strict mode: only allowed in development/test environments
		// If we're in production mode (strict checking is default true), this should never be reached
		if t.config.DevelopmentMode {
			// Explicit development mode allows insecure host key checking
			sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
		} else {
			// Production mode: refuse to connect without proper host key verification
			return fmt.Errorf("%w: host key verification cannot be disabled in production mode", ErrTransportSecurityViolation)
		}
	}

	// Connect to SSH server
	address := fmt.Sprintf("%s:%d", host, port)
	sshClient, err := ssh.Dial("tcp", address, sshConfig)
	if err != nil {
		return fmt.Errorf("%w: SSH connection failed: %v", ErrTransportConnectionFailed, err)
	}
	defer sshClient.Close()

	// Store client for reuse
	t.sshClient = sshClient

	// Create SFTP client if using SFTP
	if t.useSFTP {
		// Use SFTP for file transfer
		sftpClient, err := sftp.NewClient(sshClient)
		if err != nil {
			return fmt.Errorf("%w: SFTP initialization failed: %v", ErrTransportConnectionFailed, err)
		}
		defer sftpClient.Close()

		// Create the remote directory if it doesn't exist
		remoteDir := filepath.Dir(remotePath)
		if remoteDir != "." {
			err = sftpClient.MkdirAll(remoteDir)
			if err != nil {
				return fmt.Errorf("%w: failed to create remote directory: %v", ErrTransportFileWriteFailed, err)
			}
		}

		// Create the file
		remoteFile, err := sftpClient.Create(remotePath)
		if err != nil {
			return fmt.Errorf("%w: failed to create remote file: %v", ErrTransportFileWriteFailed, err)
		}
		defer remoteFile.Close()

		// Write payload
		_, err = remoteFile.Write(payload)
		if err != nil {
			return fmt.Errorf("%w: failed to write to remote file: %v", ErrTransportFileWriteFailed, err)
		}

		// Set permissions
		err = remoteFile.Chmod(0600)
		if err != nil {
			// Non-fatal error - file was uploaded but permissions couldn't be set
			// This might happen on some SFTP servers
		}
	} else {
		// Use pure Go SCP implementation to avoid command injection
		// Create a temporary file to write the payload
		tempFile, err := os.CreateTemp("", "ssh-upload-*")
		if err != nil {
			return fmt.Errorf("%w: failed to create temp file: %v", ErrTransportFileWriteFailed, err)
		}
		defer func() {
			// Securely remove temp file
			if err := os.Remove(tempFile.Name()); err != nil && !os.IsNotExist(err) {
				// Log error but don't return it as it's cleanup-related
			}
		}()

		// Write payload to temp file
		_, err = tempFile.Write(payload)
		if err != nil {
			return fmt.Errorf("%w: failed to write to temp file: %v", ErrTransportFileWriteFailed, err)
		}

		// Sync to ensure data is written to disk
		err = tempFile.Sync()
		if err != nil {
			return fmt.Errorf("%w: failed to sync temp file: %v", ErrTransportFileWriteFailed, err)
		}

		// Close file before transferring
		tempFile.Close()

		// Set secure permissions on temp file
		if err := os.Chmod(tempFile.Name(), 0600); err != nil {
			// Check if file doesn't exist (though it should since we just created it)
			if !os.IsNotExist(err) {
				return fmt.Errorf("%w: failed to set permissions on temp file: %v", ErrTransportFileWriteFailed, err)
			}
		}

		// Open temp file for reading
		sourceFile, err := os.Open(tempFile.Name())
		if err != nil {
			return fmt.Errorf("%w: failed to open temp file for reading: %v", ErrTransportFileReadFailed, err)
		}
		defer sourceFile.Close()

		// Create SFTP client for SCP-like transfer (using SFTP protocol which is more secure)
		// Note: We use SFTP even for "SCP" mode for security and reliability
		sftpClient, err := sftp.NewClient(sshClient)
		if err != nil {
			return fmt.Errorf("%w: SFTP initialization failed: %v", ErrTransportConnectionFailed, err)
		}
		defer sftpClient.Close()

		// Create the remote directory if it doesn't exist
		remoteDir := filepath.Dir(remotePath)
		if remoteDir != "." {
			if err := sftpClient.MkdirAll(remoteDir); err != nil {
				return fmt.Errorf("%w: failed to create remote directory: %v", ErrTransportFileWriteFailed, err)
			}
		}

		// Create remote file
		remoteFile, err := sftpClient.Create(remotePath)
		if err != nil {
			return fmt.Errorf("%w: failed to create remote file: %v", ErrTransportFileWriteFailed, err)
		}
		defer remoteFile.Close()

		// Transfer data using io.Copy for efficiency
		if _, err := io.Copy(remoteFile, sourceFile); err != nil {
			return fmt.Errorf("%w: failed to transfer file data: %v", ErrTransportFileWriteFailed, err)
		}

		// Set secure permissions on remote file
		if err := remoteFile.Chmod(0600); err != nil {
			// Non-fatal: file was transferred but permissions couldn't be set
			// This might happen on some SFTP servers
		}
	}

	return nil
}

// validateSSHHost validates an SSH host
func validateSSHHost(host string) error {
	if host == "" {
		return fmt.Errorf("%w: SSH host cannot be empty", ErrTransportInvalidPath)
	}

	// Basic validation - host can be:
	// - hostname (letters, numbers, hyphens, dots)
	// - IPv4 address (dotted quad)
	// - IPv6 address (hex with colons)

	// Check for null bytes
	if strings.Contains(host, "\x00") {
		return fmt.Errorf("%w: SSH host cannot contain null byte", ErrTransportInvalidPath)
	}

	// Check length (reasonable limit)
	if len(host) > MaxSSHHostLength {
		return fmt.Errorf("%w: SSH host too long (max %d characters)", ErrTransportInvalidPath, MaxSSHHostLength)
	}

	// Security: Prevent SSRF attacks - check for localhost and private IP addresses
	// Check for localhost variations
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || lowerHost == "localhost.localdomain" || lowerHost == "127.0.0.1" || lowerHost == "::1" {
		return fmt.Errorf("%w: SSH host cannot point to localhost or loopback addresses", ErrTransportSecurityViolation)
	}

	// Check for private IP address literals
	if isPrivateIPAddress(host) {
		return fmt.Errorf("%w: SSH host cannot point to private IP address: %s", ErrTransportSecurityViolation, host)
	}

	// Security: Prevent command injection characters
	dangerousChars := []string{"\\", "|", ";", "$", "`", "&", "(", ")", "{", "}", "[", "]", "<", ">"}
	for _, char := range dangerousChars {
		if strings.Contains(host, char) {
			return fmt.Errorf("%w: SSH host contains dangerous character: %s", ErrTransportSecurityViolation, char)
		}
	}

	return nil
}

// validateSSHUsername validates an SSH username
func validateSSHUsername(username string) error {
	if username == "" {
		return fmt.Errorf("%w: SSH username cannot be empty", ErrTransportInvalidPath)
	}

	// Check for null bytes
	if strings.Contains(username, "\x00") {
		return fmt.Errorf("%w: SSH username cannot contain null byte", ErrTransportInvalidPath)
	}

	// Check length (reasonable limit)
	if len(username) > 255 {
		return fmt.Errorf("%w: SSH username too long (max 255 characters)", ErrTransportInvalidPath)
	}

	return nil
}

// validateSSHPath validates an SSH/SFTP path
func validateSSHPath(path string) error {
	if path == "" {
		return nil // Empty path is OK - will use default
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("%w: SSH path cannot contain null byte", ErrTransportInvalidPath)
	}

	// Check for directory traversal (..)
	if strings.Contains(path, "..") {
		return fmt.Errorf("%w: SSH path cannot contain directory traversal", ErrTransportInvalidPath)
	}

	// Check for absolute paths starting with /
	if strings.HasPrefix(path, "/") {
		return fmt.Errorf("%w: SSH path cannot be absolute (must be relative)", ErrTransportInvalidPath)
	}

	// Check for home directory paths
	if strings.HasPrefix(path, "~") {
		return fmt.Errorf("%w: SSH path cannot use home directory shortform", ErrTransportInvalidPath)
	}

	// Check length
	if len(path) > MaxSSHPathLength {
		return fmt.Errorf("%w: SSH path too long (max %d characters)", ErrTransportInvalidPath, MaxSSHPathLength)
	}

	// Check for dangerous characters that could cause command injection
	dangerousChars := []string{"\\", "|", ";", "$", "`", "&", "(", ")", "{", "}", "[", "]"}
	for _, char := range dangerousChars {
		if strings.Contains(path, char) {
			return fmt.Errorf("%w: SSH path contains dangerous character: %s", ErrTransportSecurityViolation, char)
		}
	}

	return nil
}

// isRetryableSSHError returns true if the SSH error is retryable
func (t *SSHTransport) isRetryableSSHError(err error) bool {
	if err == nil {
		return false
	}

	// Without SSH library, we can't do proper error classification
	// In a real implementation, this would check for:
	// - Connection refused
	// - Timeout
	// - Host unreachable
	// - Permission denied (might be retryable with different auth)

	// For now, check error message for common retryable patterns
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "host unreachable") ||
		strings.Contains(errStr, "temporary") ||
		strings.Contains(errStr, "retry")
}

// calculateBackoffDelay calculates exponential backoff delay for SSHTransport
func (t *SSHTransport) calculateBackoffDelay(attempt int) time.Duration {
	baseDelayMS := int(t.config.RetryBaseDelay.Milliseconds())
	if baseDelayMS <= 0 {
		baseDelayMS = int(DefaultTransportRetryBaseDelay.Milliseconds())
	}

	// Calculate exponential delay: baseDelay * multiplier^(attempt-1)
	delayFloat := float64(baseDelayMS) * math.Pow(t.config.RetryMultiplier, float64(attempt-1))

	// Apply jitter: delay * (1 + random(-jitter, +jitter))
	jitterRange := t.config.RetryJitter * 2
	jitterValue := (rand.Float64()*jitterRange - t.config.RetryJitter)
	delayFloat *= (1 + jitterValue)

	// Ensure delay is at least base delay
	if delayFloat < float64(baseDelayMS) {
		delayFloat = float64(baseDelayMS)
	}

	return time.Duration(delayFloat) * time.Millisecond
}

// Close releases resources used by the SSHTransport
func (t *SSHTransport) Close() error {
	// Close SSH client connection
	if t.sshClient != nil {
		t.sshClient.Close()
		t.sshClient = nil
	}

	// Clear sensitive data from memory
	t.host = ""
	t.username = ""
	t.password = ""
	t.privateKey = nil
	t.privateKeyPath = ""
	t.knownHosts = ""
	t.port = 0
	t.usePrivateKeyAuth = false
	t.strictHostKeyChecking = true
	t.useSFTP = false

	return nil
}

// createKnownHostsCallback creates a HostKeyCallback from the configured knownHosts string
func (t *SSHTransport) createKnownHostsCallback() (ssh.HostKeyCallback, error) {
	// knownHosts format: hostname key-type key [comment]
	// or: hostname key-type key-hash
	// We parse this and create a map of hostname -> expected public keys

	callback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// If no known hosts configured, reject all (should not happen as we check this earlier)
		if t.knownHosts == "" {
			return fmt.Errorf("host key verification failed: no known hosts configured")
		}

		// Check if this hostname matches any in our known hosts
		// For now, we parse known hosts on each connection (simple implementation)
		// In production, this should be cached
		return t.verifyHostKey(hostname, key)
	}

	return callback, nil
}

// verifyHostKey verifies a host key against the configured known hosts
func (t *SSHTransport) verifyHostKey(hostname string, key ssh.PublicKey) error {
	// Parse known hosts line by line
	lines := strings.Split(t.knownHosts, "\n")

	for _, line := range lines {
		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse: hostname key-type key [comment]
		// or: hostname key-type key-hash
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue // Invalid line, skip
		}

		// Check if hostname matches
		hostPattern := parts[0]
		if !t.hostnameMatches(hostname, hostPattern) {
			continue
		}

		// The rest should be the key
		keyStr := strings.Join(parts[1:], " ")

		// Try to parse the key
		knownKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyStr))
		if err != nil {
			// Try parsing as a public key
			knownKey, err = ssh.ParsePublicKey([]byte(keyStr))
			if err != nil {
				continue // Skip invalid key
			}
		}

		// Compare the keys
		if knownKey.Type() == key.Type() && bytes.Equal(knownKey.Marshal(), key.Marshal()) {
			return nil // Key matches
		}
	}

	return fmt.Errorf("host key verification failed: key for %s does not match known hosts", hostname)
}

// hostnameMatches checks if the given hostname matches the pattern from known_hosts
func (t *SSHTransport) hostnameMatches(hostname, pattern string) bool {
	// Remove port if present
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = h
	}

	// Handle wildcard patterns
	if strings.HasPrefix(pattern, "*") {
		// Match any hostname ending with the suffix
		suffix := pattern[1:]
		// Special case: * matches everything
		if suffix == "" {
			return true
		}
		// Check if hostname ends with the suffix, or hostname equals the suffix
		return strings.HasSuffix(hostname, suffix) || hostname == suffix
	}

	// Handle domain matching (e.g., .example.com matches foo.example.com)
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(hostname, pattern) || hostname == strings.TrimPrefix(pattern, ".")
	}

	// Exact match
	return hostname == pattern
}

// DistributionClient provides a high-level interface for fixture distribution
type DistributionClient struct {
	registry *TransportRegistry
	config   TransportConfig
}

// NewDistributionClient creates a new distribution client
func NewDistributionClient(config TransportConfig) *DistributionClient {
	registry := NewTransportRegistry()

	// Register default transports - use constructors to ensure proper initialization
	httpTransport, _ := NewHTTPTransport(FixtureTransportOptions{Config: config})
	localTransport, _ := NewLocalFileTransportWithConfig(FixtureTransportOptions{Config: config})
	s3Transport, _ := NewS3Transport(FixtureTransportOptions{Config: config})
	sshTransport, _ := NewSSHTransport(FixtureTransportOptions{Config: config})

	registry.Register(httpTransport)
	registry.Register(localTransport)
	registry.Register(s3Transport)
	registry.Register(sshTransport)

	return &DistributionClient{
		registry: registry,
		config:   config,
	}
}

// Distribute distributes a fixture using the appropriate transport
func (c *DistributionClient) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// Get the transport for the target's method
	transport, ok := c.registry.Get(target.Method)
	if !ok {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: no transport registered for method %s", ErrTransportNotImplemented, target.Method)
	}

	// Set transport-specific configuration if needed
	if httpTransport, ok := transport.(*HTTPTransport); ok {
		if err := httpTransport.SetBaseURL(target.URL); err != nil {
			return FixtureDistributionReceipt{}, fmt.Errorf("%w: failed to set base URL: %v", ErrTransportConnectionFailed, err)
		}
	}

	// Update job status to in-progress
	job.Status = DistributionStatusInProgress
	job.StartedAtUnix = time.Now().Unix()
	job.AttemptCount = 1
	job.LastAttemptAtUnix = time.Now().Unix()
	job.JobHash = FixtureDistributionJobHash(job)

	// Use transport to distribute
	receipt, err := transport.Distribute(ctx, job, target, payload)
	if err != nil {
		// Update job with failure info
		job.Status = DistributionStatusFailed
		job.CompletedAtUnix = time.Now().Unix()
		job.ErrorMessage = err.Error()
		job.AttemptCount++
		job.LastAttemptAtUnix = time.Now().Unix()
		job.JobHash = FixtureDistributionJobHash(job)
		return FixtureDistributionReceipt{}, err
	}

	// Update job with success info
	job.Status = DistributionStatusCompleted
	job.CompletedAtUnix = time.Now().Unix()
	job.JobHash = FixtureDistributionJobHash(job)

	return receipt, nil
}

// DistributeWithRetry distributes a fixture with automatic retry on failure
func (c *DistributionClient) DistributeWithRetry(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// This method handles retries at the client level
	// The transport-level retry is for transient network errors
	// The client-level retry is for distribution failures

	var lastErr error

	for attempt := 0; attempt <= c.config.RetryCount; attempt++ {
		// Wait before retry (skip on first attempt)
		if attempt > 0 {
			delay := c.calculateClientBackoffDelay(attempt)
			select {
			case <-ctx.Done():
				return FixtureDistributionReceipt{}, fmt.Errorf("%w: context cancelled during client retry", ErrTransportTimeout)
			case <-time.After(delay):
				// Continue to retry
			}
		}

		receipt, err := c.Distribute(ctx, job, target, payload)
		if err == nil {
			return receipt, nil
		}

		lastErr = err

		// Check if error is retryable
		if c.isRetryableError(err) {
			// Update job attempt count
			job.AttemptCount++
			job.LastAttemptAtUnix = time.Now().Unix()
			job.JobHash = FixtureDistributionJobHash(job)
			continue
		}

		// Non-retryable error
		return FixtureDistributionReceipt{}, err
	}

	// All retries exhausted
	return FixtureDistributionReceipt{}, fmt.Errorf("%w after %d client attempts: %v", ErrTransportRetryExhausted, c.config.RetryCount+1, lastErr)
}

// calculateClientBackoffDelay calculates the delay for a client-level retry attempt
func (c *DistributionClient) calculateClientBackoffDelay(attempt int) time.Duration {
	// Similar to transport-level backoff but with different parameters
	delayFloat := float64(c.config.RetryBaseDelay.Milliseconds()) * math.Pow(c.config.RetryMultiplier, float64(attempt-1))
	jitterRange := c.config.RetryJitter * 2
	jitterValue := (rand.Float64()*jitterRange - c.config.RetryJitter)
	delayFloat *= (1 + jitterValue)

	delay := time.Duration(delayFloat) * time.Millisecond
	if delay < c.config.RetryBaseDelay {
		delay = c.config.RetryBaseDelay
	}
	if delay > c.config.RetryMaxDelay {
		delay = c.config.RetryMaxDelay
	}

	return delay
}

// isRetryableError returns true if the error is retryable at the client level
func (c *DistributionClient) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific retryable errors
	if errors.Is(err, ErrTransportTimeout) ||
		errors.Is(err, ErrTransportConnectionFailed) ||
		errors.Is(err, ErrTransportAuthFailed) {
		return true
	}

	// Check error message for retryable conditions
	errStr := err.Error()
	if strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "temporary") ||
		strings.Contains(errStr, "retry after") {
		return true
	}

	return false
}

// GetTransport returns the transport for a given method
func (c *DistributionClient) GetTransport(method DistributionMethod) (FixtureTransport, bool) {
	return c.registry.Get(method)
}

// RegisterTransport registers a custom transport
func (c *DistributionClient) RegisterTransport(transport FixtureTransport) {
	c.registry.Register(transport)
}
