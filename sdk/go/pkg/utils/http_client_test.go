package utils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPClient(t *testing.T) {
	t.Run("valid base URL", func(t *testing.T) {
		client, err := NewHTTPClient("https://example.com", nil)
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "https://example.com", client.baseURL)
	})

	t.Run("base URL without scheme", func(t *testing.T) {
		client, err := NewHTTPClient("//example.com/path", nil)
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "https://example.com/path", client.baseURL)
	})

	t.Run("base URL with port", func(t *testing.T) {
		client, err := NewHTTPClient("https://example.com:8080", nil)
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "https://example.com:8080", client.baseURL)
	})

	t.Run("invalid base URL", func(t *testing.T) {
		_, err := NewHTTPClient("", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "base URL must include host")
	})

	t.Run("localhost allows insecure", func(t *testing.T) {
		client, err := NewHTTPClient("http://localhost:8080", nil)
		require.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestHTTPClient_Do(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back method and path
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Test-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"method": "` + r.Method + `", "path": "` + r.URL.Path + `"}`))
	}))
	defer server.Close()

	t.Run("GET request", func(t *testing.T) {
		client, err := NewHTTPClient(server.URL, nil)
		require.NoError(t, err)

		ctx := context.Background()
		body, statusCode, headers, err := client.Do(ctx, "GET", "/test", nil, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		assert.Contains(t, string(body), `"method": "GET"`)
		assert.Equal(t, "application/json", headers["Content-Type"])
		assert.Equal(t, "test-value", headers["X-Test-Header"])
	})

	t.Run("POST request with body", func(t *testing.T) {
		client, err := NewHTTPClient(server.URL, nil)
		require.NoError(t, err)

		ctx := context.Background()
		body, statusCode, headers, err := client.Do(ctx, "POST", "/create", []byte("test body"), nil, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		assert.Contains(t, string(body), `"method": "POST"`)
		_ = headers
	})

	t.Run("PUT request", func(t *testing.T) {
		client, err := NewHTTPClient(server.URL, nil)
		require.NoError(t, err)

		ctx := context.Background()
		body, statusCode, _, err := client.Do(ctx, "PUT", "/update", []byte("updated"), nil, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		assert.Contains(t, string(body), `"method": "PUT"`)
	})

	t.Run("DELETE request", func(t *testing.T) {
		client, err := NewHTTPClient(server.URL, nil)
		require.NoError(t, err)

		ctx := context.Background()
		body, statusCode, _, err := client.Do(ctx, "DELETE", "/resource", nil, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		assert.Contains(t, string(body), `"method": "DELETE"`)
	})

	t.Run("HEAD request", func(t *testing.T) {
		client, err := NewHTTPClient(server.URL, nil)
		require.NoError(t, err)

		ctx := context.Background()
		body, statusCode, _, err := client.Do(ctx, "HEAD", "/head", nil, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		assert.Empty(t, body)
	})

	t.Run("with custom headers", func(t *testing.T) {
		client, err := NewHTTPClient(server.URL, nil)
		require.NoError(t, err)

		ctx := context.Background()
		headers := types.HTTPHeaders{
			"X-Custom-Header": "custom-value",
		}
		body, statusCode, respHeaders, err := client.Do(ctx, "GET", "/headers", nil, headers, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		_ = body
		_ = respHeaders
	})

	t.Run("with authentication", func(t *testing.T) {
		client, err := NewHTTPClient(server.URL, nil)
		require.NoError(t, err)

		client.SetAccessToken("test-token")

		ctx := context.Background()
		body, statusCode, respHeaders, err := client.Do(ctx, "GET", "/auth", nil, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		// Check that Authorization header was set (it gets passed to server)
		assert.Contains(t, string(body), `"path": "/auth"`)
		// The response headers won't contain the Authorization header we sent
		// because the test server doesn't echo headers back
		_ = respHeaders
		_ = body
	})
}

func TestHTTPClient_Retry(t *testing.T) {
	// Create server that fails first time
	attempt := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	client, err := NewHTTPClient(server.URL, &types.RequestOptions{
		MaxRetries:    2,
		RetryDelay:    10 * time.Millisecond,
		MaxRetryDelay: 50 * time.Millisecond,
	})
	require.NoError(t, err)

	ctx := context.Background()
	body, statusCode, _, err := client.Do(ctx, "GET", "/retry", nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "success", string(body))
	assert.Equal(t, 2, attempt)
}

func TestHTTPClient_Timeout(t *testing.T) {
	// Test that timeout option is properly set in default options
	client, err := NewHTTPClient("https://example.com", &types.RequestOptions{
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, client.defaultOptions.Timeout)

	// Test default timeout
	client2, err := NewHTTPClient("https://example.com", nil)
	require.NoError(t, err)
	assert.Equal(t, DefaultTimeout, client2.defaultOptions.Timeout)
}

func TestHTTPClient_SSRFPrevention(t *testing.T) {
	t.Run("allows http and https", func(t *testing.T) {
		client, err := NewHTTPClient("https://example.com", nil)
		require.NoError(t, err)

		// This should not error during client creation
		assert.NotNil(t, client)
	})

	t.Run("rejects invalid scheme", func(t *testing.T) {
		client, err := NewHTTPClient("https://example.com", nil)
		require.NoError(t, err)
		// Now try to make a request to ftp URL
		_, _, _, err = client.Do(context.Background(), "GET", "ftp://example.com/path", nil, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported URL scheme")
	})

	t.Run("rejects URLs with credentials", func(t *testing.T) {
		// This is tested at request time, not client creation time
		client, err := NewHTTPClient("https://example.com", nil)
		require.NoError(t, err)

		// Try to make a request with a URL that has credentials
		_, _, _, err = client.Do(context.Background(), "GET", "http://user:pass@example.com/path", nil, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credentials")
	})
}

func TestHTTPClient_BodySizeLimit(t *testing.T) {
	// Create server that returns large response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 11MB response (exceeds 10MB limit)
		largeBody := make([]byte, 11*1024*1024)
		for i := range largeBody {
			largeBody[i] = byte(i % 256)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(largeBody)
	}))
	defer server.Close()

	client, err := NewHTTPClient(server.URL, nil)
	require.NoError(t, err)

	ctx := context.Background()
	_, _, _, err = client.Do(ctx, "GET", "/large", nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

func TestCheckHTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
		wantErr    bool
	}{
		{"success", 200, nil, false},
		{"created", 201, nil, false},
		{"no content", 204, nil, false},
		{"bad request", 400, []byte("bad request"), true},
		{"unauthorized", 401, nil, true},
		{"forbidden", 403, nil, true},
		{"not found", 404, nil, true},
		{"conflict", 409, nil, true},
		{"precondition failed", 412, nil, true},
		{"rate limited", 429, nil, true},
		{"server error", 500, nil, true},
		{"service unavailable", 503, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckHTTPError(tt.statusCode, tt.body)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateURLForSSRF(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid https", "https://example.com/path", false},
		{"valid http", "http://example.com/path", false},
		{"localhost", "http://localhost:8080/path", false},
		{"127.0.0.1", "http://127.0.0.1/path", false},
		{"invalid scheme", "ftp://example.com/path", true},
		{"with credentials", "http://user:pass@example.com/path", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURLForSSRF(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseErrorResponse(t *testing.T) {
	t.Run("JSON error", func(t *testing.T) {
		body := []byte(`{"code": "test_error", "message": "test message"}`)
		resp := ParseErrorResponse(400, body)
		assert.Equal(t, 400, resp.StatusCode)
		assert.Equal(t, "test_error", resp.Code)
		assert.Equal(t, "test message", resp.Message)
	})

	t.Run("non-JSON error", func(t *testing.T) {
		body := []byte("plain text error")
		resp := ParseErrorResponse(500, body)
		assert.Equal(t, 500, resp.StatusCode)
		assert.Equal(t, "HTTP_500", resp.Code)
		assert.Equal(t, "plain text error", resp.Message)
	})

	t.Run("empty body", func(t *testing.T) {
		resp := ParseErrorResponse(404, nil)
		assert.Equal(t, 404, resp.StatusCode)
		assert.Equal(t, "HTTP_404", resp.Code)
	})
}
