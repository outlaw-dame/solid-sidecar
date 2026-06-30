package authn

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/config"
)

func TestMiddlewareAllowsUnauthenticatedRequestThrough(t *testing.T) {
	called := false
	handler := Middleware(defaultAuthConfig(), testLogger(), NewReplayCache(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/resource", nil))
	if !called {
		t.Fatal("expected next handler to be called")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestMiddlewareRejectsDPoPAuthorizationWithoutProof(t *testing.T) {
	handler := Middleware(defaultAuthConfig(), testLogger(), NewReplayCache(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "DPoP token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestMiddlewareRejectsBearerWithDPoPProof(t *testing.T) {
	handler := Middleware(defaultAuthConfig(), testLogger(), NewReplayCache(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("DPoP", "proof")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddlewareAcceptsValidDPoPAuthorization(t *testing.T) {
	privateKey := mustP256Key(t)
	accessToken := "access-token"
	now := time.Now().UTC()
	proof := mustDPoPProof(t, privateKey, ProofClaims{
		HTM: "GET",
		HTU: "https://pod.example/resource",
		JTI: "middleware-proof-1",
		IAT: now.Unix(),
		ATH: accessTokenHash(accessToken),
	})
	cfg := defaultAuthConfig()
	cfg.PublicBaseURL = "https://pod.example"
	cache := NewReplayCache()
	called := false
	handler := Middleware(cfg, testLogger(), cache, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://internal/resource", nil)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", proof)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if !called {
		t.Fatal("expected next handler to be called")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func defaultAuthConfig() config.AuthConfig {
	return config.AuthConfig{
		PreflightEnabled:                true,
		RequireDPoPForDPoPAuthorization: true,
		ValidateDPoPSignature:           true,
		MaxClockSkew:                    time.Minute,
		ReplayWindow:                    10 * time.Minute,
	}
}

func TestMiddlewareDoesNotLeakTokenInLogs(t *testing.T) {
	// Create a logger that captures log output
	var logBuffer strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuffer, nil))

	cfg := defaultAuthConfig()
	cfg.RequireDPoPForDPoPAuthorization = true
	cfg.ValidateDPoPSignature = true

	handler := Middleware(cfg, logger, NewReplayCache(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This should not be called for invalid auth
		t.Fatal("expected request to be rejected")
	}))

	// Make a request with DPoP authorization but no DPoP proof - should be rejected
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "DPoP secret-token-material")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	// Check that the token material is not in the logs
	logOutput := logBuffer.String()
	if strings.Contains(logOutput, "secret-token-material") {
		t.Fatal("token material found in logs: " + logOutput)
	}
	// Note: Generic terms like "DPoP" in error messages are acceptable
	// We're only checking for actual token leakage
	if strings.Contains(logOutput, "Authorization") {
		t.Fatal("authorization header found in logs: " + logOutput)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
