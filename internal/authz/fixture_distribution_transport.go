package authz

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Transport errors
var (
	ErrTransportNotImplemented   = errors.New("transport not implemented")
	ErrTransportTimeout          = errors.New("transport timeout")
	ErrTransportAuthFailed       = errors.New("transport authentication failed")
	ErrTransportConnectionFailed = errors.New("transport connection failed")
	ErrTransportInvalidResponse  = errors.New("transport invalid response")
	ErrTransportRetryExhausted   = errors.New("transport retry exhausted")
)

// MaxTransportPayloadSize is the maximum size of payload that can be transported (10 MB)
const MaxTransportPayloadSize = 10 * 1024 * 1024

// DefaultTransportTimeout is the default timeout for transport operations
const DefaultTransportTimeout = 30 * time.Second

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
	config  TransportConfig
	client  *http.Client
	baseURL *url.URL
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
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifyTLS,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return &HTTPTransport{
		config: config,
		client: client,
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
	t.baseURL = parsedURL
	return nil
}

// Distribute sends fixture data via HTTP POST
func (t *HTTPTransport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// Validate payload size
	if len(payload) > MaxTransportPayloadSize {
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
			return t.parseResponse(resp, job, target)
		}

		// Check if we should retry on this status code
		if t.shouldRetryStatusCode(resp.StatusCode) {
			resp.Body.Close()
			continue
		}

		// Non-retryable error
		defer resp.Body.Close()
		return FixtureDistributionReceipt{}, t.handleNonRetryableResponse(resp, job)
	}

	// All retries exhausted
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
	config TransportConfig
}

// NewLocalFileTransport creates a new local file transport
func NewLocalFileTransport(options FixtureTransportOptions) (*LocalFileTransport, error) {
	config := options.Config
	if config.Timeout <= 0 {
		config.Timeout = DefaultTransportTimeout
	}
	if config.RetryCount <= 0 {
		config.RetryCount = DefaultTransportRetryCount
	}

	return &LocalFileTransport{
		config: config,
	}, nil
}

// Name returns the name of this transport
func (t *LocalFileTransport) Name() string {
	return "local_file"
}

// Method returns the distribution method this transport handles
func (t *LocalFileTransport) Method() DistributionMethod {
	return DistributionMethodLocalFile
}

// Distribute writes fixture data to a local file
func (t *LocalFileTransport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// Local file transport is a stub for now
	// In a real implementation, this would write to the local filesystem
	return FixtureDistributionReceipt{}, ErrTransportNotImplemented
}

// S3Transport implements FixtureTransport for S3 distribution
type S3Transport struct {
	config TransportConfig
}

// NewS3Transport creates a new S3 transport
func NewS3Transport(options FixtureTransportOptions) (*S3Transport, error) {
	config := options.Config
	if config.Timeout <= 0 {
		config.Timeout = DefaultTransportTimeout
	}
	if config.RetryCount <= 0 {
		config.RetryCount = DefaultTransportRetryCount
	}

	return &S3Transport{
		config: config,
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

// Distribute uploads fixture data to S3
func (t *S3Transport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// S3 transport is a stub for now
	// In a real implementation, this would use the AWS SDK to upload to S3
	return FixtureDistributionReceipt{}, ErrTransportNotImplemented
}

// SSHTransport implements FixtureTransport for SSH/SFTP distribution
type SSHTransport struct {
	config TransportConfig
}

// NewSSHTransport creates a new SSH transport
func NewSSHTransport(options FixtureTransportOptions) (*SSHTransport, error) {
	config := options.Config
	if config.Timeout <= 0 {
		config.Timeout = DefaultTransportTimeout
	}
	if config.RetryCount <= 0 {
		config.RetryCount = DefaultTransportRetryCount
	}

	return &SSHTransport{
		config: config,
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

// Distribute uploads fixture data via SSH/SFTP
func (t *SSHTransport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// SSH transport is a stub for now
	// In a real implementation, this would use an SSH/SFTP client
	return FixtureDistributionReceipt{}, ErrTransportNotImplemented
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
	localTransport, _ := NewLocalFileTransport(FixtureTransportOptions{Config: config})
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
