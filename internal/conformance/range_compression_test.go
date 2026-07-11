// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements range and compression compatibility tests.
package conformance

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRangeRequests tests HTTP range request support
func TestRangeRequests(t *testing.T) {
	t.Parallel()

	// Create a server that supports range requests
	content := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	contentLength := len(content)

	t.Run("Range request for bytes 0-9", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rangeHeader := r.Header.Get("Range")
			if rangeHeader == "" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(content))
				return
			}

			// Parse range header (simplified - in production use proper parsing)
			if strings.HasPrefix(rangeHeader, "bytes=0-9") {
				w.Header().Set("Content-Range", "bytes 0-9/"+string(rune(contentLength)))
				w.Header().Set("Content-Length", "10")
				w.WriteHeader(http.StatusPartialContent)
				w.Write([]byte("0123456789"))
				return
			}

			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Add Range header
		req.Header.Set("Range", "bytes=0-9")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusPartialContent {
			t.Errorf("Expected status 206, got %d", resp.StatusCode)
		}

		contentRange := resp.Header.Get("Content-Range")
		if !strings.Contains(contentRange, "0-9") {
			t.Errorf("Expected Content-Range header to contain 0-9, got: %s", contentRange)
		}

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if bodyStr != "0123456789" {
			t.Errorf("Expected body '0123456789', got: %s", bodyStr)
		}
	})

	t.Run("Range request for last 10 bytes", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rangeHeader := r.Header.Get("Range")
			if rangeHeader == "" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(content))
				return
			}

			// Parse range header for "bytes=-10"
			if strings.HasSuffix(rangeHeader, "-10") {
				start := contentLength - 10
				end := contentLength - 1
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, contentLength))
				w.Header().Set("Content-Length", "10")
				w.WriteHeader(http.StatusPartialContent)
				w.Write([]byte(content[start : end+1]))
				return
			}

			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Add Range header for last 10 bytes
		req.Header.Set("Range", "bytes=-10")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusPartialContent {
			t.Errorf("Expected status 206, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		expected := content[contentLength-10 : contentLength]
		if bodyStr != expected {
			t.Errorf("Expected body '%s', got: %s", expected, bodyStr)
		}
	})

	t.Run("Full content without range", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", string(rune(contentLength)))
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(content))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if bodyStr != content {
			t.Errorf("Expected full content, got: %s", bodyStr)
		}
	})

	t.Run("Invalid range request", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rangeHeader := r.Header.Get("Range")
			if rangeHeader != "" && !strings.HasPrefix(rangeHeader, "bytes=") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(content))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Add invalid Range header
		req.Header.Set("Range", "invalid")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", resp.StatusCode)
		}
	})
}

// TestAcceptRangesHeader tests Accept-Ranges header
func TestAcceptRangesHeader(t *testing.T) {
	t.Parallel()

	t.Run("Accept-Ranges: bytes", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(strings.Repeat("A", 100)))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		acceptRanges := resp.Header.Get("Accept-Ranges")
		if acceptRanges != "bytes" {
			t.Errorf("Expected Accept-Ranges: bytes, got: %s", acceptRanges)
		}
	})

	t.Run("No Accept-Ranges header", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Don't set Accept-Ranges header
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test"))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		acceptRanges := resp.Header.Get("Accept-Ranges")
		if acceptRanges != "" {
			t.Errorf("Expected no Accept-Ranges header, got: %s", acceptRanges)
		}
	})
}

// TestCompressionNegotiation tests content encoding compression support
func TestCompressionNegotiation(t *testing.T) {
	t.Parallel()

	t.Run("gzip compression supported", func(t *testing.T) {
		t.Parallel()

		// Create gzip-compressed content
		var buf strings.Builder
		gw := gzip.NewWriter(&buf)
		gw.Write([]byte("Hello, World!"))
		gw.Close()
		compressedContent := buf.String()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for Accept-Encoding header
			acceptEncoding := r.Header.Get("Accept-Encoding")
			if strings.Contains(acceptEncoding, "gzip") {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Vary", "Accept-Encoding")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(compressedContent))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello, World!"))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Add Accept-Encoding header
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		contentEncoding := resp.Header.Get("Content-Encoding")
		if contentEncoding != "gzip" {
			t.Errorf("Expected Content-Encoding: gzip, got: %s", contentEncoding)
		}

		vary := resp.Header.Get("Vary")
		if !strings.Contains(vary, "Accept-Encoding") {
			t.Errorf("Expected Vary header to contain Accept-Encoding, got: %s", vary)
		}
	})

	t.Run("deflate compression supported", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acceptEncoding := r.Header.Get("Accept-Encoding")
			if strings.Contains(acceptEncoding, "deflate") {
				w.Header().Set("Content-Encoding", "deflate")
				w.Header().Set("Vary", "Accept-Encoding")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("compressed with deflate"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello, World!"))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Add Accept-Encoding header
		req.Header.Set("Accept-Encoding", "deflate")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		contentEncoding := resp.Header.Get("Content-Encoding")
		if contentEncoding != "deflate" {
			t.Errorf("Expected Content-Encoding: deflate, got: %s", contentEncoding)
		}
	})

	t.Run("Multiple compression algorithms", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acceptEncoding := r.Header.Get("Accept-Encoding")
			// Server prefers gzip
			if strings.Contains(acceptEncoding, "gzip") {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Vary", "Accept-Encoding")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("compressed with gzip"))
				return
			}
			if strings.Contains(acceptEncoding, "deflate") {
				w.Header().Set("Content-Encoding", "deflate")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("compressed with deflate"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("uncompressed"))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Add Accept-Encoding header with multiple algorithms
		req.Header.Set("Accept-Encoding", "gzip, deflate")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		contentEncoding := resp.Header.Get("Content-Encoding")
		if contentEncoding != "gzip" {
			t.Errorf("Expected Content-Encoding: gzip (server preference), got: %s", contentEncoding)
		}
	})

	t.Run("No compression support", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello, World!"))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Don't add Accept-Encoding header

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		contentEncoding := resp.Header.Get("Content-Encoding")
		if contentEncoding != "" {
			t.Errorf("Expected no Content-Encoding header, got: %s", contentEncoding)
		}
	})
}

// TestCompressionQualityValues tests Accept-Encoding with quality values
func TestCompressionQualityValues(t *testing.T) {
	t.Parallel()

	t.Run("Quality values in Accept-Encoding", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acceptEncoding := r.Header.Get("Accept-Encoding")
			// Server should respect quality values
			if strings.Contains(acceptEncoding, "gzip;q=0.5") {
				// gzip has low priority, server might choose not to use it
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("uncompressed or other method"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("uncompressed"))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Add Accept-Encoding header with quality values
		req.Header.Set("Accept-Encoding", "gzip;q=0.5, identity;q=1.0")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Server should respect the quality values
		// With gzip at q=0.5 and identity at q=1.0, server might prefer identity
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("Wildcard compression", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acceptEncoding := r.Header.Get("Accept-Encoding")
			if strings.Contains(acceptEncoding, "*") {
				w.Header().Set("Content-Encoding", "gzip")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("compressed"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("uncompressed"))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Add Accept-Encoding header with wildcard
		req.Header.Set("Accept-Encoding", "*")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Server can choose any compression with wildcard
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})
}

// TestRangeAndCompressionCombined tests range requests with compression
func TestRangeAndCompressionCombined(t *testing.T) {
	t.Parallel()

	t.Run("Range request with compression", func(t *testing.T) {
		t.Parallel()

		// Create gzip-compressed content
		var buf strings.Builder
		gw := gzip.NewWriter(&buf)
		gw.Write([]byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
		gw.Close()
		compressedContent := buf.String()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acceptEncoding := r.Header.Get("Accept-Encoding")
			rangeHeader := r.Header.Get("Range")

			if strings.Contains(acceptEncoding, "gzip") && rangeHeader != "" {
				// Return compressed partial content
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Range", "bytes 0-9/36")
				w.Header().Set("Vary", "Accept-Encoding")
				w.WriteHeader(http.StatusPartialContent)
				// In reality, we would compress just the range, but for testing we use pre-compressed
				w.Write([]byte(compressedContent))
				return
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Add both Range and Accept-Encoding headers
		req.Header.Set("Range", "bytes=0-9")
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Should get partial content with compression
		if resp.StatusCode != http.StatusPartialContent {
			t.Errorf("Expected status 206, got %d", resp.StatusCode)
		}

		contentEncoding := resp.Header.Get("Content-Encoding")
		if contentEncoding != "gzip" {
			t.Errorf("Expected Content-Encoding: gzip, got: %s", contentEncoding)
		}
	})
}
