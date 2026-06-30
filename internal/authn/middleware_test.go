package authn

import (
	"encoding/json"
	"fmt"
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

func TestMiddlewareValidatesBearerTokenWithIdentityValidation(t *testing.T) {
	// Create a valid JWT token
	privateKey := mustRSAKey(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			// Use the server's URL as the issuer
			issuerURL := "https://" + r.Host
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuerURL, issuerURL+"/jwks")
		case "/jwks":
			jwks := jwksForRSAKey(t, "key-1", &privateKey.PublicKey)
			encoded, err := json.Marshal(jwks)
			if err != nil {
				t.Fatalf("Marshal jwks returned error: %v", err)
			}
			w.Write(encoded)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	issuerURL := server.URL
	claims := map[string]any{
		"iss": issuerURL,
		"sub": "https://alice.example/profile/card#me",
		"aud": "solid-sidecar",
		"iat": 90,
		"exp": 200,
	}
	token := signTestJWT(t, privateKey, "key-1", "RS256", claims)

	// Configure auth with identity validation enabled
	cfg := config.AuthConfig{
		PreflightEnabled:                true,
		RequireDPoPForDPoPAuthorization: true,
		ValidateDPoPSignature:           true,
		MaxClockSkew:                    time.Minute,
		ReplayWindow:                    10 * time.Minute,
		IdentityValidationEnabled:       true,
		AllowedIdentityIssuers:          []string{issuerURL},
		ExpectedIdentityAudience:        "solid-sidecar",
	}

	// Create a custom identity verifier that can reach our test server
	// Use a fixed time that matches the token's timestamps (iat: 90, exp: 200)
	now := time.Unix(100, 0)
	identityVerifier := NewIdentityVerifier(NewIssuerDiscoveryClient(server.Client()), IdentityValidationOptions{
		AllowedIssuers:   []string{issuerURL},
		ExpectedAudience: "solid-sidecar",
		Now:              now,
		ClockSkew:        time.Minute,
	})
	// Set the verifier's discovery client's Now function
	if discClient := identityVerifier.Discovery; discClient != nil {
		discClient.Now = func() time.Time { return now }
	}

	handler := MiddlewareWithVerifier(cfg, testLogger(), NewReplayCache(), identityVerifier, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that the identity was stored in context
		identity := IdentityFromContext(r.Context())
		if identity.WebID != "https://alice.example/profile/card#me" {
			t.Fatalf("expected WebID to be set in context, got: %s", identity.WebID)
		}
		if identity.Issuer != issuerURL {
			t.Fatalf("expected Issuer to be set in context, got: %s", identity.Issuer)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestMiddlewareRejectsInvalidBearerTokenWithIdentityValidation(t *testing.T) {
	// Configure auth with identity validation enabled but no valid token
	cfg := config.AuthConfig{
		PreflightEnabled:                true,
		RequireDPoPForDPoPAuthorization: true,
		ValidateDPoPSignature:           true,
		MaxClockSkew:                    time.Minute,
		ReplayWindow:                    10 * time.Minute,
		IdentityValidationEnabled:       true,
		AllowedIdentityIssuers:          []string{"https://issuer.example/"},
		ExpectedIdentityAudience:        "solid-sidecar",
	}

	handler := Middleware(cfg, testLogger(), NewReplayCache(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("expected request to be rejected")
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddlewareAllowsBearerTokenWithoutIdentityValidation(t *testing.T) {
	cfg := config.AuthConfig{
		PreflightEnabled:                true,
		RequireDPoPForDPoPAuthorization: true,
		ValidateDPoPSignature:           true,
		MaxClockSkew:                    time.Minute,
		ReplayWindow:                    10 * time.Minute,
		IdentityValidationEnabled:       false, // Disabled
		AllowedIdentityIssuers:          []string{"https://issuer.example/"},
		ExpectedIdentityAudience:        "solid-sidecar",
	}

	called := false
	handler := Middleware(cfg, testLogger(), NewReplayCache(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Check that no identity was set in context
		identity := IdentityFromContext(r.Context())
		if identity.WebID != "" {
			t.Fatalf("expected no identity in context when validation is disabled, got: %s", identity.WebID)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected handler to be called")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
