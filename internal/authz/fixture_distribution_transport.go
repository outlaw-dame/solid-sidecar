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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	ErrTransportFileWriteFailed  = errors.New("transport file write failed")
	ErrTransportFileReadFailed   = errors.New("transport file read failed")
	ErrTransportFileExists       = errors.New("transport file already exists")
	ErrTransportInvalidPath      = errors.New("transport invalid path")
	ErrTransportPermissionDenied = errors.New("transport permission denied")
	ErrTransportSDKNecessary     = errors.New("transport requires SDK")
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
	config    TransportConfig
	basePath  string
	overwrite bool
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
		config:    config,
		basePath:  basePath,
		overwrite: options.Overwrite,
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

// Distribute writes fixture data to a local file
func (t *LocalFileTransport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// Validate payload
	if len(payload) > MaxTransportPayloadSize {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: payload too large (max %d bytes)", ErrTransportInvalidResponse, MaxTransportPayloadSize)
	}

	// Get the full file path
	filePath, err := t.getFilePath(target)
	if err != nil {
		return FixtureDistributionReceipt{}, err
	}

	// Validate file path length
	if len(filePath) > MaxFilePathLength {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: file path too long (max %d characters)", ErrTransportInvalidPath, MaxFilePathLength)
	}

	// Check if file already exists
	if !t.overwrite {
		if _, err := os.Stat(filePath); err == nil {
			return FixtureDistributionReceipt{}, fmt.Errorf("%w: file already exists at %s", ErrTransportFileExists, filePath)
		}
	}

	// Create parent directory if it doesn't exist
	parentDir := filepath.Dir(filePath)
	if err := os.MkdirAll(parentDir, DefaultDirectoryPermissions); err != nil {
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
			return FixtureDistributionReceipt{}, writeErr
		}
	}

	if writeErr != nil {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w after %d attempts", ErrTransportRetryExhausted, t.config.RetryCount+1)
	}

	// Verify the file was written correctly
	writtenData, err := os.ReadFile(filePath)
	if err != nil {
		// File verification failed - clean up
		os.Remove(filePath)
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: failed to verify written file: %v", ErrTransportFileReadFailed, err)
	}

	// Verify hash matches
	writtenHash := sha256.Sum256(writtenData)
	expectedHash := sha256.Sum256(payload)
	if writtenHash != expectedHash {
		// Hash mismatch - file was corrupted
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
}

// S3TransportOptions contains options for creating an S3Transport
type S3TransportOptions struct {
	Config    TransportConfig
	Bucket    string
	KeyPrefix string
	UseSSL    bool
	Region    string
	Endpoint  string
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

	// Default to SSL
	useSSL := options.UseSSL
	if !useSSL && options.Endpoint == "" {
		useSSL = true // Default to SSL for standard S3
	}

	return &S3Transport{
		config:    config,
		bucket:    options.Bucket,
		keyPrefix: options.KeyPrefix,
		useSSL:    useSSL,
		region:    options.Region,
		endpoint:  options.Endpoint,
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

// SetRegion sets the AWS region
func (t *S3Transport) SetRegion(region string) error {
	if err := validateS3Region(region); err != nil {
		return err
	}
	t.region = region
	return nil
}

// Distribute uploads fixture data to S3
// Note: This implementation requires the AWS SDK to be available for actual S3 operations.
// The transport layer logic is complete, but without the SDK, it will return ErrTransportSDKNecessary.
func (t *S3Transport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// Validate payload
	if len(payload) > MaxTransportPayloadSize {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: payload too large (max %d bytes)", ErrTransportInvalidResponse, MaxTransportPayloadSize)
	}

	// Parse S3 URL from target
	bucket, key, err := t.ParseS3URL(target.URL)
	if err != nil {
		return FixtureDistributionReceipt{}, err
	}

	// Use configured bucket if not specified in URL
	if bucket == "" && t.bucket != "" {
		bucket = t.bucket
	}

	// Validate bucket
	if bucket == "" {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: no bucket specified", ErrTransportInvalidPath)
	}

	// Apply key prefix
	if t.keyPrefix != "" {
		key = t.keyPrefix + "/" + key
	}

	// Validate key
	if err := validateS3Key(key); err != nil {
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
			return FixtureDistributionReceipt{}, uploadErr
		}
	}

	if uploadErr != nil {
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

// uploadToS3 uploads payload to S3
// This is a placeholder that would use the AWS SDK in a real implementation
func (t *S3Transport) uploadToS3(ctx context.Context, bucket, key string, payload []byte, target FixtureDistributionTarget) error {
	// This is where AWS SDK integration would go
	// For now, return an error indicating SDK is needed
	return fmt.Errorf("%w: S3 upload requires AWS SDK - install 'github.com/aws/aws-sdk-go-v2' for S3 support", ErrTransportSDKNecessary)
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
	// - Can be up to 1024 bytes
	// - Can contain any character except null
	if len(key) > 1024 {
		return fmt.Errorf("%w: S3 key too long (max 1024 bytes)", ErrTransportInvalidPath)
	}

	if strings.Contains(key, "\x00") {
		return fmt.Errorf("%w: S3 key cannot contain null byte", ErrTransportInvalidPath)
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
}

// SSHTransportOptions contains options for creating an SSHTransport
type SSHTransportOptions struct {
	Config         TransportConfig
	Host           string
	Port           int
	Username       string
	UseSFTP        bool
	KnownHosts     string
	PrivateKey     []byte
	PrivateKeyPath string
	Password       string
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
		config:         config,
		host:           options.Host,
		port:           options.Port,
		username:       options.Username,
		useSFTP:        useSFTP,
		knownHosts:     options.KnownHosts,
		privateKey:     options.PrivateKey,
		privateKeyPath: options.PrivateKeyPath,
		password:       options.Password,
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

// Distribute uploads fixture data via SSH/SFTP
// Note: This implementation requires an SSH library (e.g., golang.org/x/crypto/ssh)
// to be available for actual SSH operations. The transport layer logic is complete,
// but without the library, it will return ErrTransportSDKNecessary.
func (t *SSHTransport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	// Validate payload
	if len(payload) > MaxTransportPayloadSize {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: payload too large (max %d bytes)", ErrTransportInvalidResponse, MaxTransportPayloadSize)
	}

	// Parse SSH URL from target
	host, port, path, err := t.ParseSSHURL(target.URL)
	if err != nil {
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
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: no SSH host specified", ErrTransportInvalidPath)
	}

	// Validate path
	if err := validateSSHPath(path); err != nil {
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
			return FixtureDistributionReceipt{}, uploadErr
		}
	}

	if uploadErr != nil {
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
	// This is where SSH library integration would go
	// For now, return an error indicating library is needed
	return fmt.Errorf("%w: SSH upload requires SSH library - install 'golang.org/x/crypto/ssh' for SSH/SFTP support", ErrTransportSDKNecessary)
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
	if len(host) > 253 {
		return fmt.Errorf("%w: SSH host too long (max 253 characters)", ErrTransportInvalidPath)
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

	// Check length
	if len(path) > 4096 {
		return fmt.Errorf("%w: SSH path too long (max 4096 characters)", ErrTransportInvalidPath)
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
