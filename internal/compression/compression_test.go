package compression

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =============================================================================
// Configuration Tests
// =============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig{}

	// Test response defaults
	resp := cfg.Responses()
	if resp.Enabled != false {
		t.Error("Expected responses.enabled to default to false")
	}
	if resp.Gzip.Enabled != true {
		t.Error("Expected gzip.enabled to default to true")
	}
	if resp.Gzip.Level != 0 {
		t.Error("Expected gzip.level to default to 0")
	}
	if resp.Zstd.Enabled != false {
		t.Error("Expected zstd.enabled to default to false")
	}
	if resp.Prefer != "gzip" {
		t.Errorf("Expected prefer to default to gzip, got %q", resp.Prefer)
	}
	if resp.SkipSensitiveResponses != true {
		t.Error("Expected skip_sensitive_responses to default to true")
	}
	if resp.SkipErrorResponses != true {
		t.Error("Expected skip_error_responses to default to true")
	}
	if resp.SkipRanges != true {
		t.Error("Expected skip_ranges to default to true")
	}
	if resp.MinBytes != DefaultMinBytes {
		t.Errorf("Expected min_bytes to default to %d, got %d", DefaultMinBytes, resp.MinBytes)
	}

	// Test request defaults
	req := cfg.Requests()
	if req.Enabled != false {
		t.Error("Expected requests.enabled to default to false")
	}
	if req.ZstdEnabled != false {
		t.Error("Expected requests.zstd_enabled to default to false")
	}
	if req.MaxDecompressedBytes != 10485760 {
		t.Errorf("Expected max_decompressed_bytes to default to 10485760, got %d", req.MaxDecompressedBytes)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Responses: ResponsesConfig{
					Enabled:                true,
					Gzip:                   GzipConfig{Enabled: true, Level: 5},
					Zstd:                   ZstdConfig{Enabled: false, Level: 0},
					Prefer:                 "gzip",
					SkipSensitiveResponses: true,
					SkipErrorResponses:     true,
					SkipRanges:             true,
					MinBytes:               1024,
				},
				Requests: RequestsConfig{
					Enabled:              false,
					MaxDecompressedBytes: 10485760,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid gzip level",
			cfg: Config{
				Responses: ResponsesConfig{
					Enabled: true,
					Gzip:    GzipConfig{Enabled: true, Level: 10},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid zstd level",
			cfg: Config{
				Responses: ResponsesConfig{
					Enabled: true,
					Zstd:    ZstdConfig{Enabled: true, Level: 23},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid prefer value",
			cfg: Config{
				Responses: ResponsesConfig{
					Enabled: true,
					Prefer:  "invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "negative min_bytes",
			cfg: Config{
				Responses: ResponsesConfig{
					Enabled:  true,
					MinBytes: -1,
				},
			},
			wantErr: true,
		},
		{
			name: "request decompression with zero max bytes",
			cfg: Config{
				Requests: RequestsConfig{
					Enabled:              true,
					MaxDecompressedBytes: 0,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Accept-Encoding Parsing Tests
// =============================================================================

func TestGetAcceptedEncodings(t *testing.T) {
	tests := []struct {
		name           string
		acceptEncoding string
		want           []string
	}{
		{
			name:           "no accept encoding",
			acceptEncoding: "",
			want:           nil,
		},
		{
			name:           "gzip only",
			acceptEncoding: "gzip",
			want:           []string{"gzip"},
		},
		{
			name:           "gzip with quality",
			acceptEncoding: "gzip;q=1.0",
			want:           []string{"gzip"},
		},
		{
			name:           "multiple encodings",
			acceptEncoding: "gzip, deflate",
			want:           []string{"gzip", "deflate"},
		},
		{
			name:           "gzip and zstd",
			acceptEncoding: "gzip, zstd",
			want:           []string{"gzip", "zstd"},
		},
		{
			name:           "gzip and zstd with quality",
			acceptEncoding: "gzip;q=1.0, zstd;q=0.8",
			want:           []string{"gzip", "zstd"},
		},
		{
			name:           "case insensitive",
			acceptEncoding: "GZIP, ZSTD",
			want:           []string{"gzip", "zstd"},
		},
		{
			name:           "with spaces",
			acceptEncoding: " gzip , zstd ",
			want:           []string{"gzip", "zstd"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}

			got := getAcceptedEncodings(req)
			if !slicesEqual(got, tt.want) {
				t.Errorf("getAcceptedEncodings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSelectEncoding(t *testing.T) {
	tests := []struct {
		name     string
		accepted []string
		cfg      ResponsesConfig
		want     string
	}{
		{
			name:     "gzip accepted and enabled",
			accepted: []string{"gzip", "deflate"},
			cfg: ResponsesConfig{
				Gzip:   GzipConfig{Enabled: true},
				Prefer: "gzip",
			},
			want: "gzip",
		},
		{
			name:     "gzip not accepted",
			accepted: []string{"deflate"},
			cfg: ResponsesConfig{
				Gzip:   GzipConfig{Enabled: true},
				Prefer: "gzip",
			},
			want: "",
		},
		{
			name:     "gzip not enabled",
			accepted: []string{"gzip"},
			cfg: ResponsesConfig{
				Gzip:   GzipConfig{Enabled: false},
				Prefer: "gzip",
			},
			want: "",
		},
		{
			name:     "zstd preferred but not enabled",
			accepted: []string{"gzip", "zstd"},
			cfg: ResponsesConfig{
				Gzip:   GzipConfig{Enabled: true},
				Zstd:   ZstdConfig{Enabled: false},
				Prefer: "zstd",
			},
			want: "gzip",
		},
		{
			name:     "zstd accepted and enabled",
			accepted: []string{"gzip", "zstd"},
			cfg: ResponsesConfig{
				Gzip:   GzipConfig{Enabled: true},
				Zstd:   ZstdConfig{Enabled: true},
				Prefer: "zstd",
			},
			want: "zstd",
		},
		{
			name:     "no accepted encodings",
			accepted: []string{},
			cfg:      ResponsesConfig{Gzip: GzipConfig{Enabled: true}},
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectEncoding(tt.accepted, tt.cfg)
			if got != tt.want {
				t.Errorf("selectEncoding() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// Sensitive Response Detection Tests
// =============================================================================

func TestIsSensitiveResponse(t *testing.T) {
	tests := []struct {
		name       string
		reqHeader  map[string]string
		respHeader map[string]string
		want       bool
	}{
		{
			name:       "authorization header",
			reqHeader:  map[string]string{"Authorization": "Bearer token"},
			respHeader: map[string]string{},
			want:       true,
		},
		{
			name:       "cookie header",
			reqHeader:  map[string]string{"Cookie": "session=id"},
			respHeader: map[string]string{},
			want:       true,
		},
		{
			name:       "set-cookie response header",
			reqHeader:  map[string]string{},
			respHeader: map[string]string{"Set-Cookie": "session=id"},
			want:       true,
		},
		{
			name:       "www-authenticate response header",
			reqHeader:  map[string]string{},
			respHeader: map[string]string{"WWW-Authenticate": "Basic"},
			want:       true,
		},
		{
			name:       "cache-control private",
			reqHeader:  map[string]string{},
			respHeader: map[string]string{"Cache-Control": "private"},
			want:       true,
		},
		{
			name:       "cache-control no-store",
			reqHeader:  map[string]string{},
			respHeader: map[string]string{"Cache-Control": "no-store"},
			want:       true,
		},
		{
			name:       "cache-control no-cache (not sensitive)",
			reqHeader:  map[string]string{},
			respHeader: map[string]string{"Cache-Control": "no-cache"},
			want:       false,
		},
		{
			name:       "not sensitive",
			reqHeader:  map[string]string{},
			respHeader: map[string]string{"Content-Type": "text/html"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.reqHeader {
				req.Header.Set(k, v)
			}

			respHeaders := http.Header{}
			for k, v := range tt.respHeader {
				respHeaders.Set(k, v)
			}

			got := isSensitiveResponse(req, respHeaders)
			if got != tt.want {
				t.Errorf("isSensitiveResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// Skip Compression Logic Tests
// =============================================================================

func TestShouldSkipResponseCompression(t *testing.T) {
	baseCfg := ResponsesConfig{
		Enabled:                true,
		Gzip:                   GzipConfig{Enabled: true},
		SkipSensitiveResponses: true,
		SkipErrorResponses:     true,
		SkipRanges:             true,
		MinBytes:               1024,
		SkipContentTypes:       []string{"image/", "audio/"},
	}

	tests := []struct {
		name       string
		method     string
		statusCode int
		reqHeader  map[string]string
		respHeader map[string]string
		bodySize   int64
		cfg        ResponsesConfig
		want       bool
	}{
		{
			name:       "compression disabled",
			method:     http.MethodGet,
			statusCode: http.StatusOK,
			cfg:        ResponsesConfig{Enabled: false, Gzip: GzipConfig{Enabled: true}, MinBytes: 1024, SkipSensitiveResponses: true, SkipErrorResponses: true, SkipRanges: true, SkipContentTypes: []string{"image/", "audio/"}},
			want:       true,
		},
		{
			name:       "HEAD method always skipped",
			method:     http.MethodHead,
			statusCode: http.StatusOK,
			bodySize:   2048,
			cfg:        baseCfg,
			want:       true,
		},
		{
			name:       "OPTIONS method always skipped",
			method:     http.MethodOptions,
			statusCode: http.StatusOK,
			bodySize:   2048,
			cfg:        baseCfg,
			want:       true,
		},
		{
			name:       "error response skipped",
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
			bodySize:   2048,
			cfg:        baseCfg,
			want:       true,
		},
		{
			name:       "sensitive response skipped",
			method:     http.MethodGet,
			statusCode: http.StatusOK,
			reqHeader:  map[string]string{"Authorization": "Bearer token"},
			bodySize:   2048,
			cfg:        baseCfg,
			want:       true,
		},
		{
			name:       "range request skipped",
			method:     http.MethodGet,
			statusCode: http.StatusOK,
			reqHeader:  map[string]string{"Range": "bytes=0-499"},
			bodySize:   2048,
			cfg:        baseCfg,
			want:       true,
		},
		{
			name:       "already compressed skipped",
			method:     http.MethodGet,
			statusCode: http.StatusOK,
			respHeader: map[string]string{"Content-Encoding": "gzip"},
			bodySize:   2048,
			cfg:        baseCfg,
			want:       true,
		},
		{
			name:       "body too small skipped",
			method:     http.MethodGet,
			statusCode: http.StatusOK,
			bodySize:   512,
			cfg:        baseCfg,
			want:       true,
		},
		{
			name:       "skipped content type",
			method:     http.MethodGet,
			statusCode: http.StatusOK,
			respHeader: map[string]string{"Content-Type": "image/png"},
			bodySize:   2048,
			cfg:        baseCfg,
			want:       true,
		},
		{
			name:       "should compress",
			method:     http.MethodGet,
			statusCode: http.StatusOK,
			respHeader: map[string]string{"Content-Type": "text/html"},
			bodySize:   2048,
			cfg:        baseCfg,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", nil)
			for k, v := range tt.reqHeader {
				req.Header.Set(k, v)
			}

			respHeaders := http.Header{}
			for k, v := range tt.respHeader {
				respHeaders.Set(k, v)
			}

			// Call with nil metrics since we're just testing the logic
			got, _ := shouldSkipResponseCompression(req, tt.cfg, tt.statusCode, respHeaders, tt.bodySize, nil)
			if got != tt.want {
				t.Errorf("shouldSkipResponseCompression() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// Gzip Compression Tests
// =============================================================================

func TestCompressGzip(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		level   int
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			level:   gzip.DefaultCompression,
			wantErr: false,
		},
		{
			name:    "small data",
			data:    []byte("hello world"),
			level:   gzip.DefaultCompression,
			wantErr: false,
		},
		{
			name:    "large data",
			data:    bytes.Repeat([]byte("test data "), 1000),
			level:   gzip.DefaultCompression,
			wantErr: false,
		},
		{
			name:    "invalid compression level",
			data:    []byte("test"),
			level:   10,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compressGzip(tt.data, tt.level)
			if (err != nil) != tt.wantErr {
				t.Errorf("compressGzip() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) == 0 {
				t.Error("compressGzip() returned empty bytes for valid input")
			}

			// Verify we can decompress it back
			if !tt.wantErr && len(tt.data) > 0 {
				gr, err := gzip.NewReader(bytes.NewReader(got))
				if err != nil {
					t.Errorf("failed to create gzip reader: %v", err)
					return
				}
				decompressed, err := io.ReadAll(gr)
				if err != nil {
					t.Errorf("failed to decompress: %v", err)
					return
				}
				if !bytes.Equal(decompressed, tt.data) {
					t.Errorf("decompressed data doesn't match original: got %q, want %q", decompressed, tt.data)
				}
			}
		})
	}
}

// =============================================================================
// Header Handling Tests
// =============================================================================

func TestAddVaryHeader(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
	}{
		{
			name:    "no vary header",
			headers: http.Header{},
			want:    "Accept-Encoding",
		},
		{
			name:    "existing vary header",
			headers: http.Header{"Vary": []string{"Accept"}},
			want:    "Accept, Accept-Encoding",
		},
		{
			name:    "vary with accept-encoding already present",
			headers: http.Header{"Vary": []string{"Accept, Accept-Encoding"}},
			want:    "Accept, Accept-Encoding",
		},
		{
			name:    "vary case insensitive",
			headers: http.Header{"Vary": []string{"accept-encoding"}},
			want:    "accept-encoding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			for k, v := range tt.headers {
				headers[k] = v
			}

			addVaryHeader(headers)

			got := headers.Get("Vary")
			if got != tt.want {
				t.Errorf("addVaryHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleETag(t *testing.T) {
	tests := []struct {
		name  string
		setup func(http.Header)
		want  string
	}{
		{
			name: "strong etag converted to weak",
			setup: func(h http.Header) {
				h.Set("ETag", "\"abc123\"")
			},
			want: "W/\"abc123\"",
		},
		{
			name: "weak etag preserved",
			setup: func(h http.Header) {
				h.Set("ETag", "W/\"abc123\"")
			},
			want: "W/\"abc123\"",
		},
		{
			name:  "no etag",
			setup: func(h http.Header) {},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			tt.setup(headers)

			handleETag(headers)

			got := headers.Get("ETag")
			if got != tt.want {
				t.Errorf("handleETag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleContentLength(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
	}{
		{
			name:    "remove content-length",
			headers: http.Header{"Content-Length": []string{"1024"}},
			want:    "",
		},
		{
			name:    "no content-length",
			headers: http.Header{},
			want:    "",
		},
		{
			name:    "other headers preserved",
			headers: http.Header{"Content-Length": []string{"1024"}, "Content-Type": []string{"text/html"}},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			for k, v := range tt.headers {
				headers[k] = v
			}

			handleContentLength(headers)

			got := headers.Get("Content-Length")
			if got != tt.want {
				t.Errorf("handleContentLength() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// Middleware Integration Tests
// =============================================================================

func TestMiddleware_CompressionEnabled(t *testing.T) {
	// Create a handler that returns a large enough response
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("test", 300))) // > 1024 bytes
	})

	cfg := Config{
		Responses: ResponsesConfig{
			Enabled:  true,
			Gzip:     GzipConfig{Enabled: true, Level: gzip.DefaultCompression},
			MinBytes: 1024,
			Prefer:   "gzip",
		},
		Requests: RequestsConfig{Enabled: false},
	}

	middleware := Middleware(cfg)
	wrapped := middleware(handler)

	// Test with Accept-Encoding: gzip
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Check that response is compressed
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("Expected Content-Encoding: gzip, got %q", w.Header().Get("Content-Encoding"))
	}

	// Check Vary header
	if !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") {
		t.Errorf("Expected Vary header to contain Accept-Encoding")
	}

	// Verify we can decompress the body
	gr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("Failed to decompress body: %v", err)
	}

	expectedBody := strings.Repeat("test", 300)
	if !bytes.Equal(decompressed, []byte(expectedBody)) {
		t.Errorf("Decompressed body doesn't match expected")
	}
}

func TestMiddleware_CompressionDisabled(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	cfg := Config{
		Responses: ResponsesConfig{
			Enabled: false, // Compression disabled
			Gzip:    GzipConfig{Enabled: true},
		},
		Requests: RequestsConfig{Enabled: false},
	}

	middleware := Middleware(cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Check that response is NOT compressed
	if w.Header().Get("Content-Encoding") != "" {
		t.Errorf("Expected no Content-Encoding, got %q", w.Header().Get("Content-Encoding"))
	}

	// Check body is not compressed
	if w.Body.String() != "test response" {
		t.Errorf("Expected uncompressed body, got %q", w.Body.String())
	}
}

func TestMiddleware_SensitiveResponseSkipped(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("test", 300)))
	})

	cfg := Config{
		Responses: ResponsesConfig{
			Enabled:                true,
			Gzip:                   GzipConfig{Enabled: true},
			SkipSensitiveResponses: true,
			MinBytes:               1024,
		},
		Requests: RequestsConfig{Enabled: false},
	}

	middleware := Middleware(cfg)
	wrapped := middleware(handler)

	// Test with Authorization header
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Check that response is NOT compressed due to sensitive request
	if w.Header().Get("Content-Encoding") != "" {
		t.Errorf("Expected no Content-Encoding for sensitive request, got %q", w.Header().Get("Content-Encoding"))
	}
}

func TestMiddleware_ErrorResponseSkipped(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	cfg := Config{
		Responses: ResponsesConfig{
			Enabled:            true,
			Gzip:               GzipConfig{Enabled: true},
			SkipErrorResponses: true,
		},
		Requests: RequestsConfig{Enabled: false},
	}

	middleware := Middleware(cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Check that response is NOT compressed due to error status
	if w.Header().Get("Content-Encoding") != "" {
		t.Errorf("Expected no Content-Encoding for error response, got %q", w.Header().Get("Content-Encoding"))
	}
}

func TestMiddleware_SmallBodySkipped(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("small")) // < 1024 bytes
	})

	cfg := Config{
		Responses: ResponsesConfig{
			Enabled:  true,
			Gzip:     GzipConfig{Enabled: true},
			MinBytes: 1024,
		},
		Requests: RequestsConfig{Enabled: false},
	}

	middleware := Middleware(cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Check that response is NOT compressed due to small body
	if w.Header().Get("Content-Encoding") != "" {
		t.Errorf("Expected no Content-Encoding for small body, got %q", w.Header().Get("Content-Encoding"))
	}
}

func TestMiddleware_AlreadyCompressedSkipped(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("test", 300)))
	})

	cfg := Config{
		Responses: ResponsesConfig{
			Enabled:  true,
			Gzip:     GzipConfig{Enabled: true},
			MinBytes: 1024,
		},
		Requests: RequestsConfig{Enabled: false},
	}

	middleware := Middleware(cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Check that response is NOT double-compressed
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("Expected Content-Encoding to remain gzip, got %q", w.Header().Get("Content-Encoding"))
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
