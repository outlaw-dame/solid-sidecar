package authn

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	now := time.Unix(1_700_000_000, 0)
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
	cache.now = func() time.Time { return now }
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
		PreflightEnabled:                 true,
		RequireDPoPForDPoPAuthorization: true,
		ValidateDPoPSignature:           true,
		MaxClockSkew:                    time.Minute,
		ReplayWindow:                    10 * time.Minute,
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
