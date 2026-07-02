// Package compression implements HTTP compression and decompression middleware
// for the Solid sidecar, following the compatibility requirements defined in
// docs/compression-compatibility.md.
package compression

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Response compression constants
const (
	// DefaultMinBytes is the minimum response size to compress (1 KB)
	DefaultMinBytes = 1024
	// Gzip encoding string
	EncodingGzip = "gzip"
	// Zstd encoding string
	EncodingZstd = "zstd"
)

// Sensitive request headers that trigger sensitive response detection
var sensitiveRequestHeaders = []string{
	"authorization",
	"cookie",
}

// Sensitive response headers that indicate sensitive content
var sensitiveResponseHeaders = []string{
	"set-cookie",
	"www-authenticate",
}

// Sensitive cache control directives
var sensitiveCacheControlDirectives = []string{
	"private",
	"no-store",
}

// errorResponseStatuses contains HTTP status codes that should skip compression
var errorResponseStatuses = map[int]bool{
	100: true, // Continue
	101: true, // Switching Protocols
	204: true, // No Content
	205: true, // Reset Content
	304: true, // Not Modified
	400: true, // Bad Request
	401: true, // Unauthorized
	403: true, // Forbidden
	405: true, // Method Not Allowed
	408: true, // Request Timeout
	410: true, // Gone
	413: true, // Payload Too Large
	414: true, // URI Too Long
	415: true, // Unsupported Media Type
	422: true, // Unprocessable Entity
	426: true, // Upgrade Required
	429: true, // Too Many Requests
	500: true, // Internal Server Error
	501: true, // Not Implemented
	502: true, // Bad Gateway
	503: true, // Service Unavailable
	504: true, // Gateway Timeout
}

// eligibleMethods contains HTTP methods that may be compressed.
// Following the spec: GET may be compressed, write responses should remain uncompressed initially.
var eligibleMethods = map[string]bool{
	"GET": true,
}

// skippedMethods contains HTTP methods that should always skip compression
var skippedMethods = map[string]bool{
	"HEAD":    true,
	"OPTIONS": true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"PATCH":   true,
	"CONNECT": true,
	"TRACE":   true,
}

// Config holds the compression middleware configuration
type Config struct {
	// Responses configuration
	Responses ResponsesConfig
	// Requests configuration
	Requests RequestsConfig
	// Metrics for observing compression behavior (optional)
	Metrics *Metrics
}

// ResponsesConfig holds response compression configuration
type ResponsesConfig struct {
	// Enabled controls whether response compression is active
	Enabled bool
	// Gzip configuration
	Gzip GzipConfig
	// Zstd configuration
	Zstd ZstdConfig
	// Prefer indicates which compression to prefer when both are acceptable
	Prefer string
	// SkipContentTypes is a list of content type prefixes to skip
	SkipContentTypes []string
	// SkipSensitiveResponses controls whether to skip compression for sensitive responses
	SkipSensitiveResponses bool
	// SkipErrorResponses controls whether to skip compression for error responses
	SkipErrorResponses bool
	// SkipRanges controls whether to skip compression for range requests
	SkipRanges bool
	// MinBytes is the minimum response size to compress
	MinBytes int64
}

// GzipConfig holds Gzip-specific configuration
type GzipConfig struct {
	// Enabled controls whether Gzip compression is active
	Enabled bool
	// Level controls the compression level (0 = default, 1-9)
	Level int
}

// ZstdConfig holds Zstd-specific configuration
type ZstdConfig struct {
	// Enabled controls whether Zstd compression is active
	Enabled bool
	// Level controls the compression level (0 = default, 1-22)
	Level int
}

// RequestsConfig holds request decompression configuration
type RequestsConfig struct {
	// Enabled controls whether request decompression is active
	Enabled bool
	// AllowedEncodings is a list of allowed encodings for decompression
	AllowedEncodings []string
	// MaxDecompressedBytes is the maximum size of decompressed request body
	MaxDecompressedBytes int64
	// ZstdEnabled controls whether Zstd decompression is active
	ZstdEnabled bool
}

// DefaultConfig returns a safe default configuration
type DefaultConfig struct{}

func (DefaultConfig) Responses() ResponsesConfig {
	return ResponsesConfig{
		// Must default to false until e2e compatibility tests exist
		Enabled: false,
		Gzip: GzipConfig{
			Enabled: true,
			Level:   0, // default
		},
		Zstd: ZstdConfig{
			// Must default to false even after Gzip support lands
			Enabled: false,
			Level:   0, // default
		},
		Prefer:                 "gzip",
		SkipContentTypes:       []string{"image/", "audio/", "video/", "application/zip", "application/gzip", "application/zstd", "application/octet-stream"},
		SkipSensitiveResponses: true,
		SkipErrorResponses:     true,
		SkipRanges:             true,
		MinBytes:               DefaultMinBytes,
	}
}

func (DefaultConfig) Requests() RequestsConfig {
	return RequestsConfig{
		// Must default to false until limits, threat model, and CSS compatibility are proven
		Enabled:              false,
		AllowedEncodings:     []string{"gzip"},
		MaxDecompressedBytes: 10485760, // 10 MiB
		ZstdEnabled:          false,
	}
}

// compressionResponseWriter wraps the response writer to capture the response
// for potential compression
type compressionResponseWriter struct {
	http.ResponseWriter
	body        *bytes.Buffer
	status      int
	headers     http.Header
	wroteHeader bool
	compression *compressionContext
}

type compressionContext struct {
	encoding string
	config   ResponsesConfig
	request  *http.Request
}

// WriteHeader implements http.ResponseWriter
func (crw *compressionResponseWriter) WriteHeader(statusCode int) {
	// Always update status and mark as wrote header
	crw.status = statusCode
	crw.wroteHeader = true
	// Copy headers at the time of WriteHeader
	crw.headers = make(http.Header)
	for k, v := range crw.ResponseWriter.Header() {
		crw.headers[k] = v
	}
	// Don't write headers to the original writer yet
}

// Write implements http.ResponseWriter
func (crw *compressionResponseWriter) Write(b []byte) (int, error) {
	if !crw.wroteHeader {
		crw.WriteHeader(http.StatusOK)
	}
	if crw.body == nil {
		crw.body = &bytes.Buffer{}
	}
	return crw.body.Write(b)
}

// shouldSkipResponseCompression determines if response compression should be skipped
// Returns (shouldSkip, skipReason) for metrics recording
func shouldSkipResponseCompression(req *http.Request, cfg ResponsesConfig, statusCode int, headers http.Header, bodySize int64, metrics *Metrics) (bool, string) {
	// Skip if compression is not enabled
	if !cfg.Enabled {
		return true, "compression_disabled"
	}

	method := strings.ToUpper(req.Method)

	// Check if method is eligible for compression
	// Following spec: GET may be compressed, write responses remain uncompressed initially
	if !eligibleMethods[method] {
		return true, "method_not_eligible"
	}

	// Skip for methods that should always skip
	if skippedMethods[method] {
		return true, "method_skipped"
	}

	// Skip for error responses if configured
	if cfg.SkipErrorResponses {
		// Check for error status codes (4xx and 5xx)
		if statusCode >= 400 || errorResponseStatuses[statusCode] {
			return true, "error_response"
		}
	}

	// Skip for sensitive responses if configured
	if cfg.SkipSensitiveResponses && isSensitiveResponse(req, headers) {
		return true, "sensitive_response"
	}

	// Skip for range requests if configured
	if cfg.SkipRanges && req.Header.Get("Range") != "" {
		return true, "range_request"
	}

	// Skip if response already has Content-Encoding
	if headers.Get("Content-Encoding") != "" {
		return true, "already_encoded"
	}

	// Skip if body is too small
	if bodySize < cfg.MinBytes {
		return true, "too_small"
	}

	// Skip if content type matches skip list
	contentType := headers.Get("Content-Type")
	for _, prefix := range cfg.SkipContentTypes {
		if strings.HasPrefix(contentType, prefix) {
			return true, "content_type_skipped"
		}
	}

	return false, ""
}

// isSensitiveResponse determines if a response is sensitive based on request/response headers
func isSensitiveResponse(req *http.Request, respHeaders http.Header) bool {
	// Check request headers
	for _, header := range sensitiveRequestHeaders {
		if req.Header.Get(header) != "" {
			return true
		}
	}

	// Check response headers
	for _, header := range sensitiveResponseHeaders {
		if respHeaders.Get(header) != "" {
			return true
		}
	}

	// Check Cache-Control for sensitive directives
	cacheControl := respHeaders.Get("Cache-Control")
	if cacheControl != "" {
		cacheControlLower := strings.ToLower(cacheControl)
		for _, directive := range sensitiveCacheControlDirectives {
			if strings.Contains(cacheControlLower, directive) {
				return true
			}
		}
	}

	return false
}

// getAcceptedEncodings parses Accept-Encoding header and returns accepted encodings
func getAcceptedEncodings(req *http.Request) []string {
	acceptEncoding := req.Header.Get("Accept-Encoding")
	if acceptEncoding == "" {
		return nil
	}

	encodings := strings.Split(acceptEncoding, ",")
	var accepted []string
	for _, enc := range encodings {
		enc = strings.TrimSpace(enc)
		// Handle quality values (e.g., "gzip;q=1.0")
		if idx := strings.Index(enc, ";"); idx != -1 {
			enc = strings.TrimSpace(enc[:idx])
		}
		if enc != "" {
			accepted = append(accepted, strings.ToLower(enc))
		}
	}

	return accepted
}

// selectEncoding selects the best encoding based on accepted encodings and configuration
func selectEncoding(accepted []string, cfg ResponsesConfig) string {
	if len(accepted) == 0 {
		return ""
	}

	// Check for explicit preference
	prefer := strings.ToLower(cfg.Prefer)
	if prefer != "" {
		// Check if preferred encoding is accepted and enabled
		if prefers(accepted, prefer) && isEncodingEnabled(prefer, cfg) {
			return prefer
		}
	}

	// Fall back to first accepted encoding that is enabled
	for _, enc := range accepted {
		if isEncodingEnabled(enc, cfg) {
			return enc
		}
	}

	return ""
}

// prefers checks if the preferred encoding is in the accepted list
func prefers(accepted []string, prefer string) bool {
	for _, enc := range accepted {
		if enc == prefer {
			return true
		}
	}
	return false
}

// isEncodingEnabled checks if an encoding is enabled in the configuration
func isEncodingEnabled(encoding string, cfg ResponsesConfig) bool {
	switch strings.ToLower(encoding) {
	case EncodingGzip:
		return cfg.Gzip.Enabled
	case EncodingZstd:
		return cfg.Zstd.Enabled
	default:
		return false
	}
}

// addVaryHeader adds or merges Vary: Accept-Encoding header
func addVaryHeader(headers http.Header) {
	// Check if Vary header already exists
	vary := headers.Get("Vary")
	if vary == "" {
		// No Vary header, add it
		headers.Set("Vary", "Accept-Encoding")
	} else {
		// Vary header exists, check if Accept-Encoding is already present
		varyLower := strings.ToLower(vary)
		if !strings.Contains(varyLower, "accept-encoding") {
			// Add Accept-Encoding to existing Vary header
			headers.Set("Vary", vary+", Accept-Encoding")
		}
	}
}

// handleETag modifies ETag header for compressed responses
func handleETag(headers http.Header) {
	etag := headers.Get("ETag")
	if etag == "" {
		return
	}

	// Check if it's a strong ETag (not starting with W/)
	if !strings.HasPrefix(etag, "W/") {
		// Convert strong ETag to weak by prefixing with W/
		// This is the safe policy: don't describe two different byte representations
		// with the same strong validator
		headers.Set("ETag", "W/"+etag)
	}
	// Weak ETags can be preserved as they represent semantic equivalence
}

// handleContentLength removes Content-Length for compressed responses
// since the compressed length is different from the original
func handleContentLength(headers http.Header) {
	headers.Del("Content-Length")
}

// CompressResponse compresses the response body with the specified encoding
func CompressResponse(body []byte, encoding string, cfg ResponsesConfig) ([]byte, error) {
	switch encoding {
	case EncodingGzip:
		return compressGzip(body, cfg.Gzip.Level)
	case EncodingZstd:
		return compressZstd(body, cfg.Zstd.Level)
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// compressGzip compresses data with Gzip
func compressGzip(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	gzWriter, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip writer: %w", err)
	}

	if _, err := gzWriter.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write compressed data: %w", err)
	}

	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return buf.Bytes(), nil
}

// compressZstd compresses data with Zstd (placeholder - would use actual zstd library)
func compressZstd(data []byte, level int) ([]byte, error) {
	// Placeholder: In a real implementation, this would use the zstd library
	// For now, return an error indicating zstd is not implemented
	return nil, errors.New("zstd compression not implemented - enable with explicit feature flag")
}

// decompressRequestBody decompresses the request body if it's compressed
func decompressRequestBody(req *http.Request, cfg RequestsConfig) (io.ReadCloser, error) {
	// Check Content-Encoding header
	contentEncoding := req.Header.Get("Content-Encoding")
	if contentEncoding == "" {
		// No compression, return original body
		return req.Body, nil
	}

	// Check if encoding is allowed
	contentEncodingLower := strings.ToLower(contentEncoding)
	if !isEncodingAllowed(contentEncodingLower, cfg) {
		// Not an allowed encoding, return original body
		// This preserves CSS behavior for unsupported encodings
		return req.Body, nil
	}

	// Decompress the body
	switch contentEncodingLower {
	case EncodingGzip:
		return decompressGzip(req.Body, cfg.MaxDecompressedBytes)
	case EncodingZstd:
		if cfg.ZstdEnabled {
			return nil, errors.New("zstd decompression not implemented")
		}
		// Zstd not enabled, return original body
		return req.Body, nil
	default:
		return req.Body, nil
	}
}

// isEncodingAllowed checks if an encoding is in the allowed list
func isEncodingAllowed(encoding string, cfg RequestsConfig) bool {
	for _, allowed := range cfg.AllowedEncodings {
		if strings.ToLower(allowed) == encoding {
			return true
		}
	}
	return false
}

// decompressGzip decompresses a gzip-compressed body
func decompressGzip(body io.ReadCloser, maxDecompressedBytes int64) (io.ReadCloser, error) {
	// Create a limited reader to prevent decompression bombs
	// We need to limit both the compressed and decompressed sizes
	gzReader, err := gzip.NewReader(body)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}

	// Create a limited reader for the decompressed data
	limitedReader := &io.LimitedReader{
		R: gzReader,
		N: maxDecompressedBytes + 1, // +1 to detect overflow
	}

	// Create a pipe to handle the streaming decompression
	pr, pw := io.Pipe()

	go func() {
		defer gzReader.Close()
		defer pw.Close()

		// Use a buffered reader for efficiency
		bufReader := bufio.NewReader(limitedReader)
		if _, err := io.Copy(pw, bufReader); err != nil {
			pw.CloseWithError(err)
			return
		}

		// Check if we exceeded the limit
		if limitedReader.N == 0 {
			pw.CloseWithError(fmt.Errorf("decompressed body exceeds maximum size of %d bytes", maxDecompressedBytes))
		}
	}()

	return &decompressReadCloser{
		Reader: pr,
		body:   body,
		gz:     gzReader,
	}, nil
}

// decompressReadCloser wraps an io.ReadCloser to properly clean up resources
type decompressReadCloser struct {
	io.Reader
	body io.ReadCloser
	gz   *gzip.Reader
}

// Close implements io.ReadCloser
func (d *decompressReadCloser) Close() error {
	if d.gz != nil {
		d.gz.Close()
	}
	if d.body != nil {
		return d.body.Close()
	}
	return nil
}

// ValidateConfig validates the compression configuration
func ValidateConfig(cfg Config) error {
	// Validate response compression
	if cfg.Responses.Enabled {
		// Validate Gzip config
		if cfg.Responses.Gzip.Enabled {
			if cfg.Responses.Gzip.Level < 0 || cfg.Responses.Gzip.Level > 9 {
				return errors.New("compression.responses.gzip.level must be between 0 and 9")
			}
		}

		// Validate Zstd config
		if cfg.Responses.Zstd.Enabled {
			if cfg.Responses.Zstd.Level < 0 || cfg.Responses.Zstd.Level > 22 {
				return errors.New("compression.responses.zstd.level must be between 0 and 22")
			}
		}

		// Validate prefer value
		if cfg.Responses.Prefer != "" && cfg.Responses.Prefer != "gzip" && cfg.Responses.Prefer != "zstd" {
			return errors.New("compression.responses.prefer must be empty, 'gzip', or 'zstd'")
		}

		// Validate min_bytes
		if cfg.Responses.MinBytes < 0 {
			return errors.New("compression.responses.min_bytes must be non-negative")
		}
	}

	// Validate request decompression
	if cfg.Requests.Enabled {
		if cfg.Requests.MaxDecompressedBytes <= 0 {
			return errors.New("compression.requests.max_decompressed_bytes must be positive when decompression is enabled")
		}
	}

	return nil
}

// Metrics holds aggregate counters for compression operations.
// All metrics are privacy-safe: no WebIDs, resource URLs, query strings,
// request bodies, response bodies, or policy bodies are included in metrics labels.
type Metrics struct {
	mu sync.RWMutex

	// Response compression metrics
	ResponseCandidates    int64 // Total candidates for response compression
	CompressedGzip        int64 // Responses compressed with gzip
	CompressedZstd        int64 // Responses compressed with zstd
	SkippedNoClientAccept int64 // Skipped: client did not accept encoding
	SkippedAlreadyEncoded int64 // Skipped: already encoded
	SkippedRangeRequest   int64 // Skipped: range request
	SkippedSensitive      int64 // Skipped: sensitive response
	SkippedContentType    int64 // Skipped: content type
	SkippedTooSmall       int64 // Skipped: body too small
	SkippedStatusMethod   int64 // Skipped: status code or HTTP method
	SkippedMethod         int64 // Skipped: HTTP method not eligible
	CompressionErrors     int64 // Errors during compression

	// Request decompression metrics
	RequestDecompressionAttempts  int64 // Request decompression attempts
	RequestDecompressionRejected  int64 // Request decompression rejected
	DecompressedByteLimitFailures int64 // Decompression byte limit failures
}

// NewMetrics creates a new Metrics instance with all counters initialized to zero.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// RecordResponseCandidate increments the response candidate counter.
func (m *Metrics) RecordResponseCandidate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ResponseCandidates++
}

// RecordCompressedGzip increments the gzip compression counter.
func (m *Metrics) RecordCompressedGzip() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CompressedGzip++
}

// RecordCompressedZstd increments the zstd compression counter.
func (m *Metrics) RecordCompressedZstd() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CompressedZstd++
}

// RecordSkipNoClientAccept increments the skip counter for no client accept.
func (m *Metrics) RecordSkipNoClientAccept() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SkippedNoClientAccept++
}

// RecordSkipAlreadyEncoded increments the skip counter for already encoded.
func (m *Metrics) RecordSkipAlreadyEncoded() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SkippedAlreadyEncoded++
}

// RecordSkipRangeRequest increments the skip counter for range requests.
func (m *Metrics) RecordSkipRangeRequest() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SkippedRangeRequest++
}

// RecordSkipSensitive increments the skip counter for sensitive responses.
func (m *Metrics) RecordSkipSensitive() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SkippedSensitive++
}

// RecordSkipContentType increments the skip counter for content types.
func (m *Metrics) RecordSkipContentType() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SkippedContentType++
}

// RecordSkipTooSmall increments the skip counter for small bodies.
func (m *Metrics) RecordSkipTooSmall() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SkippedTooSmall++
}

// RecordSkipStatusMethod increments the skip counter for status/method.
func (m *Metrics) RecordSkipStatusMethod() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SkippedStatusMethod++
}

// RecordSkipMethod increments the skip counter for ineligible methods.
func (m *Metrics) RecordSkipMethod() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SkippedMethod++
}

// RecordCompressionError increments the compression error counter.
func (m *Metrics) RecordCompressionError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CompressionErrors++
}

// RecordRequestDecompressionAttempt increments the request decompression attempt counter.
func (m *Metrics) RecordRequestDecompressionAttempt() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RequestDecompressionAttempts++
}

// RecordRequestDecompressionRejected increments the request decompression rejected counter.
func (m *Metrics) RecordRequestDecompressionRejected() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RequestDecompressionRejected++
}

// RecordDecompressedByteLimitFailure increments the byte limit failure counter.
func (m *Metrics) RecordDecompressedByteLimitFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DecompressedByteLimitFailures++
}

// Snapshot returns a copy of the current metrics values for testing.
type MetricsSnapshot struct {
	ResponseCandidates            int64
	CompressedGzip                int64
	CompressedZstd                int64
	SkippedNoClientAccept         int64
	SkippedAlreadyEncoded         int64
	SkippedRangeRequest           int64
	SkippedSensitive              int64
	SkippedContentType            int64
	SkippedTooSmall               int64
	SkippedStatusMethod           int64
	SkippedMethod                 int64
	CompressionErrors             int64
	RequestDecompressionAttempts  int64
	RequestDecompressionRejected  int64
	DecompressedByteLimitFailures int64
}

// Snapshot returns a snapshot of the current metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return MetricsSnapshot{
		ResponseCandidates:            m.ResponseCandidates,
		CompressedGzip:                m.CompressedGzip,
		CompressedZstd:                m.CompressedZstd,
		SkippedNoClientAccept:         m.SkippedNoClientAccept,
		SkippedAlreadyEncoded:         m.SkippedAlreadyEncoded,
		SkippedRangeRequest:           m.SkippedRangeRequest,
		SkippedSensitive:              m.SkippedSensitive,
		SkippedContentType:            m.SkippedContentType,
		SkippedTooSmall:               m.SkippedTooSmall,
		SkippedStatusMethod:           m.SkippedStatusMethod,
		SkippedMethod:                 m.SkippedMethod,
		CompressionErrors:             m.CompressionErrors,
		RequestDecompressionAttempts:  m.RequestDecompressionAttempts,
		RequestDecompressionRejected:  m.RequestDecompressionRejected,
		DecompressedByteLimitFailures: m.DecompressedByteLimitFailures,
	}
}

// Middleware creates a compression middleware with the given configuration
func Middleware(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle request decompression first
			if cfg.Requests.Enabled {
				var err error
				r.Body, err = decompressRequestBody(r, cfg.Requests)
				if err != nil {
					// In production, this would use proper logging
					// For now, just pass through to next handler
					if cfg.Metrics != nil {
						cfg.Metrics.RecordDecompressedByteLimitFailure()
					}
					next.ServeHTTP(w, r)
					return
				}
				// Record request decompression attempt
				if cfg.Metrics != nil {
					cfg.Metrics.RecordRequestDecompressionAttempt()
				}
			}

			// Create a response writer that can capture the response
			crw := &compressionResponseWriter{
				ResponseWriter: w,
				body:           &bytes.Buffer{},
				status:         http.StatusOK,
				headers:        make(http.Header),
				wroteHeader:    false,
				compression: &compressionContext{
					config:  cfg.Responses,
					request: r,
				},
			}

			// Serve the request with our custom writer
			next.ServeHTTP(crw, r)

			// After the handler has completed, decide whether to compress
			bodyBytes := []byte{}
			if crw.body != nil {
				bodyBytes = crw.body.Bytes()
			}

			// Record that this is a compression candidate if it has a body
			if len(bodyBytes) > 0 && cfg.Metrics != nil {
				cfg.Metrics.RecordResponseCandidate()
			}

			// Check if we should compress
			shouldSkip := true
			var skipReason string
			if len(bodyBytes) > 0 {
				shouldSkip, skipReason = shouldSkipResponseCompression(
					r, cfg.Responses, crw.status, crw.headers, int64(len(bodyBytes)), cfg.Metrics,
				)
			}

			if !shouldSkip {
				// Get accepted encodings
				accepted := getAcceptedEncodings(r)
				encoding := selectEncoding(accepted, cfg.Responses)

				if encoding != "" {
					// Compress the response
					compressed, err := CompressResponse(bodyBytes, encoding, cfg.Responses)
					if err == nil {
						// Record successful compression
						if cfg.Metrics != nil {
							if encoding == EncodingGzip {
								cfg.Metrics.RecordCompressedGzip()
							} else if encoding == EncodingZstd {
								cfg.Metrics.RecordCompressedZstd()
							}
						}

						// Set compression headers
						w.Header().Set("Content-Encoding", encoding)
						addVaryHeader(w.Header())

						// Handle ETag and Content-Length
						handleETag(w.Header())
						w.Header().Del("Content-Length")

						// Copy other headers from the captured response
						for k, v := range crw.headers {
							// Don't overwrite headers we just set
							if k != "Content-Encoding" && k != "Vary" && k != "ETag" && k != "Content-Length" {
								w.Header()[k] = v
							}
						}

						// Write the compressed response
						w.WriteHeader(crw.status)
						w.Write(compressed)
						return
					}
					// If compression failed, record error and fall back to original response
					if cfg.Metrics != nil {
						cfg.Metrics.RecordCompressionError()
					}
				}
			} else if cfg.Metrics != nil && skipReason != "" && len(bodyBytes) > 0 {
				// Record the skip reason
				switch skipReason {
				case "no_client_accept":
					cfg.Metrics.RecordSkipNoClientAccept()
				case "already_encoded":
					cfg.Metrics.RecordSkipAlreadyEncoded()
				case "range_request":
					cfg.Metrics.RecordSkipRangeRequest()
				case "sensitive_response":
					cfg.Metrics.RecordSkipSensitive()
				case "content_type_skipped":
					cfg.Metrics.RecordSkipContentType()
				case "too_small":
					cfg.Metrics.RecordSkipTooSmall()
				case "error_response", "method_not_eligible", "method_skipped", "compression_disabled":
					cfg.Metrics.RecordSkipStatusMethod()
				}
			}

			// If we didn't compress or compression failed, write the original response
			if crw.wroteHeader {
				// Headers were written, write them now
				for k, v := range crw.headers {
					w.Header()[k] = v
				}
				w.WriteHeader(crw.status)
			} else {
				w.WriteHeader(crw.status)
			}
			if len(bodyBytes) > 0 {
				w.Write(bodyBytes)
			}
		})
	}
}
