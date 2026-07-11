// Package utils provides HTTP client utilities for the Solid Sidecar Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready
package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/types"
)

// Default configuration constants
const (
	DefaultTimeout       = 30 * time.Second
	DefaultMaxRetries    = 3
	DefaultRetryDelay    = 1 * time.Second
	DefaultMaxRetryDelay = 30 * time.Second
	DefaultMaxBodySize   = 10 * 1024 * 1024 // 10MB
)

// normalizeHeaderKey normalizes an HTTP header key to canonical form.
// This is necessary because httptest.ResponseRecorder doesn't use canonical case.
func normalizeHeaderKey(key string) string {
	// For common headers that we know the canonical form of, return it directly
	switch strings.ToLower(key) {
	case "etag":
		return "ETag"
	case "content-type":
		return "Content-Type"
	case "content-length":
		return "Content-Length"
	case "last-modified":
		return "Last-Modified"
	case "location":
		return "Location"
	case "authorization":
		return "Authorization"
	case "dpop":
		return "DPoP"
	case "accept":
		return "Accept"
	case "user-agent":
		return "User-Agent"
	case "if-match":
		return "If-Match"
	case "if-none-match":
		return "If-None-Match"
	case "link":
		return "Link"
	default:
		// For unknown headers, use textproto's canonicalization
		return textproto.CanonicalMIMEHeaderKey(key)
	}
}

// ErrNetwork represents a network error
var ErrNetwork = errors.New("network error")

// ErrAuthentication represents an authentication error
var ErrAuthentication = errors.New("authentication error")

// ErrAuthorization represents an authorization error
var ErrAuthorization = errors.New("authorization error")

// ErrNotFound represents a not found error
var ErrNotFound = errors.New("resource not found")

// ErrConflict represents a conflict error
var ErrConflict = errors.New("conflict")

// ErrPreconditionFailed represents a precondition failed error
var ErrPreconditionFailed = errors.New("precondition failed")

// ErrRateLimited represents a rate limit error
var ErrRateLimited = errors.New("rate limited")

// ErrValidation represents a validation error
var ErrValidation = errors.New("validation error")

// ErrSecurity represents a security error
var ErrSecurity = errors.New("security error")

// HTTPClient is the main HTTP client for the SDK.
type HTTPClient struct {
	// client is the underlying HTTP client
	client *http.Client

	// baseURL is the base URL for the Solid Sidecar instance
	baseURL string

	// defaultOptions contains default request options
	defaultOptions types.RequestOptions

	// accessToken is the current access token
	accessToken string

	// dpopProofFunc is a function that generates DPoP proofs
	dpopProofFunc func(method, url string) (string, error)
}

// NewHTTPClient creates a new HTTPClient.
//
// Parameters:
//   - baseURL: The base URL of the Solid Sidecar instance (e.g., "https://sidecar.example.com")
//   - options: Optional request options (can be nil for defaults)
//
// Returns:
//   - A new HTTPClient instance
//   - Error if baseURL is invalid
func NewHTTPClient(baseURL string, options *types.RequestOptions) (*HTTPClient, error) {
	// Validate and normalize base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base URL: %v", ErrValidation, err)
	}

	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	if parsedURL.Host == "" {
		return nil, fmt.Errorf("%w: base URL must include host", ErrValidation)
	}

	// Create transport with security settings
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}

	// For localhost, allow insecure connections (development only)
	if strings.Contains(parsedURL.Host, "localhost") || strings.Contains(parsedURL.Host, "127.0.0.1") {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
	}

	// Set default options
	defaultOpts := types.RequestOptions{
		Timeout:       DefaultTimeout,
		MaxRetries:    DefaultMaxRetries,
		RetryDelay:    DefaultRetryDelay,
		MaxRetryDelay: DefaultMaxRetryDelay,
	}

	if options != nil {
		if options.Timeout > 0 {
			defaultOpts.Timeout = options.Timeout
		}
		if options.MaxRetries > 0 {
			defaultOpts.MaxRetries = options.MaxRetries
		}
		if options.RetryDelay > 0 {
			defaultOpts.RetryDelay = options.RetryDelay
		}
		if options.MaxRetryDelay > 0 {
			defaultOpts.MaxRetryDelay = options.MaxRetryDelay
		}
		defaultOpts.FollowRedirects = options.FollowRedirects
		// Merge headers
		if len(options.Headers) > 0 {
			if defaultOpts.Headers == nil {
				defaultOpts.Headers = make(types.HTTPHeaders)
			}
			for k, v := range options.Headers {
				defaultOpts.Headers[k] = v
			}
		}
	}

	return &HTTPClient{
		client:         client,
		baseURL:        parsedURL.String(),
		defaultOptions: defaultOpts,
	}, nil
}

// SetAccessToken sets the access token for authentication.
func (c *HTTPClient) SetAccessToken(token string) {
	c.accessToken = token
}

// SetDPoPProofFunc sets the function to generate DPoP proofs.
// The function should return a DPoP proof JWT for the given method and URL.
func (c *HTTPClient) SetDPoPProofFunc(fn func(method, url string) (string, error)) {
	c.dpopProofFunc = fn
}

// GetAccessToken returns the current access token.
func (c *HTTPClient) GetAccessToken() string {
	return c.accessToken
}

// Do performs an HTTP request with the given parameters.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - method: HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD)
//   - path: URL path (relative or absolute)
//   - body: Request body (can be nil)
//   - headers: Additional headers (can be nil)
//   - options: Request options (can be nil, will use defaults)
//
// Returns:
//   - Response body as []byte
//   - HTTP status code
//   - Headers from the response
//   - Error if the request failed
func (c *HTTPClient) Do(
	ctx context.Context,
	method string,
	path string,
	body []byte,
	headers types.HTTPHeaders,
	options *types.RequestOptions,
) ([]byte, int, types.HTTPHeaders, error) {
	// Validate method
	method = strings.ToUpper(method)
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		// Valid
	default:
		return nil, 0, nil, fmt.Errorf("%w: unsupported HTTP method: %s", ErrValidation, method)
	}

	// Merge options with defaults
	opts := c.mergeOptions(options)

	// Validate body size
	if len(body) > DefaultMaxBodySize {
		return nil, 0, nil, fmt.Errorf("%w: body size exceeds maximum: %d > %d", ErrValidation, len(body), DefaultMaxBodySize)
	}

	// Build URL
	fullURL, err := c.buildURL(path)
	if err != nil {
		return nil, 0, nil, err
	}

	// Validate URL for SSRF prevention
	if err := validateURLForSSRF(fullURL); err != nil {
		return nil, 0, nil, err
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("%w: failed to create request: %v", ErrNetwork, err)
	}

	// Set headers
	c.setHeaders(req, headers, method, fullURL)

	// Execute request with retries
	return c.doWithRetry(ctx, req, body, opts)
}

// mergeOptions merges provided options with defaults.
func (c *HTTPClient) mergeOptions(options *types.RequestOptions) types.RequestOptions {
	opts := c.defaultOptions

	if options == nil {
		return opts
	}

	if options.Timeout > 0 {
		opts.Timeout = options.Timeout
	}
	if options.MaxRetries > 0 {
		opts.MaxRetries = options.MaxRetries
	}
	if options.RetryDelay > 0 {
		opts.RetryDelay = options.RetryDelay
	}
	if options.MaxRetryDelay > 0 {
		opts.MaxRetryDelay = options.MaxRetryDelay
	}
	if options.FollowRedirects {
		opts.FollowRedirects = true
	}

	// Merge headers
	if len(options.Headers) > 0 {
		if opts.Headers == nil {
			opts.Headers = make(types.HTTPHeaders)
		}
		for k, v := range options.Headers {
			opts.Headers[k] = v
		}
	}

	return opts
}

// buildURL builds the full URL from a path.
func (c *HTTPClient) buildURL(path string) (string, error) {
	// If path is already a full URL, use it as-is
	if strings.Contains(path, "://") {
		parsed, err := url.Parse(path)
		if err != nil {
			return "", fmt.Errorf("%w: invalid URL: %v", ErrValidation, err)
		}
		return parsed.String(), nil
	}

	// Parse base URL
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("%w: invalid base URL: %v", ErrValidation, err)
	}

	// Parse path
	pathURL, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("%w: invalid path: %v", ErrValidation, err)
	}

	// Resolve reference
	resolved := base.ResolveReference(pathURL)

	return resolved.String(), nil
}

// setHeaders sets request headers.
func (c *HTTPClient) setHeaders(req *http.Request, headers types.HTTPHeaders, method, url string) {
	// Set default headers
	req.Header.Set("Accept", "text/turtle, application/ld+json, */*")
	req.Header.Set("User-Agent", "SolidSidecar-Go-SDK/1.0.0")

	// Set authorization if access token is available
	if c.accessToken != "" {
		req.Header.Set("Authorization", "DPoP "+c.accessToken)
	}

	// Set DPoP proof if function is available
	if c.dpopProofFunc != nil {
		proof, err := c.dpopProofFunc(method, url)
		if err == nil && proof != "" {
			req.Header.Set("DPoP", proof)
		}
	}

	// Set custom headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

// doWithRetry executes the request with retry logic and exponential backoff.
func (c *HTTPClient) doWithRetry(
	ctx context.Context,
	req *http.Request,
	body []byte,
	opts types.RequestOptions,
) ([]byte, int, types.HTTPHeaders, error) {
	var lastErr error
	var lastStatusCode int
	var responseHeaders types.HTTPHeaders

	for attempt := 0; attempt <= opts.MaxRetries; attempt++ {
		// Reset body for retries
		if body != nil && attempt > 0 {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		// Set timeout for this attempt
		if opts.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
			defer cancel()
		}

		// Execute request
		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err

			// Check if error is retryable
			if isRetryableError(err) {
				if attempt < opts.MaxRetries {
					delay := calculateBackoff(attempt, opts)
					select {
					case <-ctx.Done():
						return nil, 0, nil, ctx.Err()
					case <-time.After(delay):
						continue
					}
				}
			} else {
				return nil, 0, nil, fmt.Errorf("%w: %v", ErrNetwork, err)
			}
			continue
		}

		// Read response body
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, DefaultMaxBodySize+1))
		if err != nil {
			return nil, resp.StatusCode, nil, fmt.Errorf("%w: failed to read response body: %v", ErrNetwork, err)
		}

		// Check for body size limit
		if len(bodyBytes) > DefaultMaxBodySize {
			return nil, resp.StatusCode, nil, fmt.Errorf("%w: response body exceeds maximum size", ErrValidation)
		}

		// Store headers (normalize to canonical case for consistent access)
		responseHeaders = make(types.HTTPHeaders)
		for k, v := range resp.Header {
			// Normalize header name to canonical case for consistent access
			// httptest.ResponseRecorder doesn't use canonical case, so we normalize here
			canonicalKey := normalizeHeaderKey(k)
			responseHeaders[canonicalKey] = strings.Join(v, ", ")
		}

		lastStatusCode = resp.StatusCode

		// Check if we need to retry
		if shouldRetry(resp.StatusCode, bodyBytes) {
			if attempt < opts.MaxRetries {
				delay := calculateBackoff(attempt, opts)
				select {
				case <-ctx.Done():
					return nil, resp.StatusCode, responseHeaders, ctx.Err()
				case <-time.After(delay):
					continue
				}
			}
		}

		// Return successful response
		return bodyBytes, resp.StatusCode, responseHeaders, nil
	}

	// All retries exhausted
	if lastErr != nil {
		return nil, lastStatusCode, responseHeaders, lastErr
	}

	return nil, lastStatusCode, responseHeaders, fmt.Errorf("request failed after %d attempts", opts.MaxRetries+1)
}

// calculateBackoff calculates the backoff delay with jitter.
func calculateBackoff(attempt int, opts types.RequestOptions) time.Duration {
	// Exponential backoff: baseDelay * 2^attempt
	baseDelay := opts.RetryDelay
	backoff := baseDelay * (1 << uint(attempt))

	// Add jitter (±25% of baseDelay)
	jitter := time.Duration(rand.Int63n(int64(baseDelay / 4)))
	if rand.Intn(2) == 0 {
		backoff += jitter
	} else {
		backoff -= jitter
		if backoff < 0 {
			backoff = 0
		}
	}

	// Cap at max delay
	if backoff > opts.MaxRetryDelay {
		backoff = opts.MaxRetryDelay
	}

	return backoff
}

// isRetryableError checks if an error is retryable.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common retryable errors
	errStr := err.Error()
	retryableStrings := []string{
		"Connection refused",
		"Connection timed out",
		"Temporary failure",
		"timeout",
		"reset by peer",
		"broken pipe",
	}

	for _, s := range retryableStrings {
		if strings.Contains(errStr, s) {
			return true
		}
	}

	// Check for network-level errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout() || netErr.Temporary()
	}

	return false
}

// shouldRetry determines if a request should be retried based on status code.
func shouldRetry(statusCode int, body []byte) bool {
	switch {
	case statusCode >= 500 && statusCode < 600:
		// Server errors are retryable
		return true
	case statusCode == 429:
		// Rate limited - always retry
		return true
	case statusCode == 408:
		// Request timeout
		return true
	case statusCode == 0:
		// No response (connection reset, etc.)
		return true
	default:
		return false
	}
}

// validateURLForSSRF validates a URL to prevent SSRF attacks.
func validateURLForSSRF(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: invalid URL: %v", ErrValidation, err)
	}

	// Check scheme
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: unsupported URL scheme: %s", ErrSecurity, parsed.Scheme)
	}

	// Check for credentials in URL
	if parsed.User != nil {
		return fmt.Errorf("%w: URLs with credentials are not allowed", ErrSecurity)
	}

	// Check for localhost/private IP addresses in production
	// (Allowed for development)
	host := parsed.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil // Allowed for development
	}

	// Check for private IP ranges
	if isPrivateIP(host) {
		return fmt.Errorf("%w: private IP addresses are not allowed", ErrSecurity)
	}

	return nil
}

// isPrivateIP checks if a hostname resolves to a private IP address.
func isPrivateIP(host string) bool {
	// Try to parse as IP address
	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP, try to resolve
		ips, err := net.LookupIP(host)
		if err != nil {
			return false
		}
		for _, ip := range ips {
			if isPrivateIPAddress(ip) {
				return true
			}
		}
		return false
	}

	return isPrivateIPAddress(ip)
}

// isPrivateIPAddress checks if an IP address is in a private range.
func isPrivateIPAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 || // 10.0.0.0/8
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || // 172.16.0.0/12
			(ip4[0] == 192 && ip4[1] == 168) || // 192.168.0.0/16
			(ip4[0] == 169 && ip4[1] == 254) || // 169.254.0.0/16 (link-local)
			ip4[0] == 127 || // 127.0.0.0/8
			(ip4[0] == 0 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 0) // 0.0.0.0
	}

	// IPv6 private ranges
	if ip.To16() != nil {
		return ip.IsLoopback() ||
			ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() ||
			ip.IsPrivate() // IPv6 unique local addresses (fc00::/7)
	}

	return false
}

// ParseErrorResponse parses an error response from the server.
func ParseErrorResponse(statusCode int, body []byte) *types.ErrorResponse {
	// Try to parse as JSON
	var errResp types.ErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil {
		errResp.StatusCode = statusCode
		return &errResp
	}

	// Fallback to basic error
	return &types.ErrorResponse{
		Code:       fmt.Sprintf("HTTP_%d", statusCode),
		Message:    string(body),
		StatusCode: statusCode,
	}
}

// CheckHTTPError checks if a response status code indicates an error and returns an appropriate error.
func CheckHTTPError(statusCode int, body []byte) error {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return nil
	case statusCode == 401:
		return ErrAuthentication
	case statusCode == 403:
		return ErrAuthorization
	case statusCode == 404:
		return ErrNotFound
	case statusCode == 409:
		return ErrConflict
	case statusCode == 412:
		return ErrPreconditionFailed
	case statusCode == 429:
		return ErrRateLimited
	case statusCode >= 400 && statusCode < 500:
		return fmt.Errorf("%w: client error %d", ErrValidation, statusCode)
	case statusCode >= 500:
		return fmt.Errorf("%w: server error %d", ErrNetwork, statusCode)
	default:
		return nil
	}
}
