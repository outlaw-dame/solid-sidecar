package authn

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIdentityVerifierVerifiesTokenThroughIssuerDiscovery(t *testing.T) {
	privateKey := mustRSAKey(t)
	server := newTestIssuerServer(t, privateKey, "key-1")
	defer server.Close()
	token := signTestJWT(t, privateKey, "key-1", "RS256", map[string]any{
		"iss": server.URL,
		"sub": "https://alice.example/profile/card#me",
		"aud": "solid-sidecar",
		"iat": 90,
		"exp": 200,
	})
	verifier := NewIdentityVerifier(NewIssuerDiscoveryClient(server.Client()), IdentityValidationOptions{AllowedIssuers: []string{server.URL}, ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0), ClockSkew: time.Second})
	identity, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if identity.Issuer != server.URL || identity.WebID != "https://alice.example/profile/card#me" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestIdentityVerifierRefreshesJWKSForRotatedKey(t *testing.T) {
	oldKey := mustRSAKey(t)
	newKey := mustRSAKey(t)
	server := newRotatingTestIssuerServer(t, oldKey, newKey, "key-1")
	defer server.Close()
	token := signTestJWT(t, newKey, "key-1", "RS256", map[string]any{
		"iss": server.URL,
		"sub": "https://alice.example/profile/card#me",
		"aud": "solid-sidecar",
		"iat": 90,
		"exp": 200,
	})
	discovery := NewIssuerDiscoveryClient(server.Client())
	discovery.JWKSRefreshCooldown = time.Minute
	verifier := NewIdentityVerifier(discovery, IdentityValidationOptions{AllowedIssuers: []string{server.URL}, ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0), ClockSkew: time.Second})
	identity, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify returned error after refresh: %v", err)
	}
	if identity.Issuer != server.URL {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestIdentityVerifierRequiresAllowedIssuers(t *testing.T) {
	privateKey := mustRSAKey(t)
	token := signTestJWT(t, privateKey, "key-1", "RS256", validJWTClaims())
	verifier := NewIdentityVerifier(nil, IdentityValidationOptions{ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0)})
	_, err := verifier.Verify(context.Background(), token)
	if !errors.Is(err, ErrInvalidIdentityVerification) {
		t.Fatalf("error = %v, want ErrInvalidIdentityVerification", err)
	}
}

func TestIdentityVerifierRejectsIssuerBeforeDiscovery(t *testing.T) {
	privateKey := mustRSAKey(t)
	server := newTestIssuerServer(t, privateKey, "key-1")
	defer server.Close()
	token := signTestJWT(t, privateKey, "key-1", "RS256", map[string]any{
		"iss": server.URL,
		"sub": "https://alice.example/profile/card#me",
		"aud": "solid-sidecar",
		"iat": 90,
		"exp": 200,
	})
	verifier := NewIdentityVerifier(NewIssuerDiscoveryClient(server.Client()), IdentityValidationOptions{AllowedIssuers: []string{"https://other.example/"}, ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0)})
	_, err := verifier.Verify(context.Background(), token)
	if !errors.Is(err, ErrInvalidIdentityVerification) {
		t.Fatalf("error = %v, want ErrInvalidIdentityVerification", err)
	}
}

func TestIdentityVerifierRejectsBadSignature(t *testing.T) {
	privateKey := mustRSAKey(t)
	otherKey := mustRSAKey(t)
	server := newTestIssuerServer(t, privateKey, "key-1")
	defer server.Close()
	token := signTestJWT(t, otherKey, "key-1", "RS256", map[string]any{
		"iss": server.URL,
		"sub": "https://alice.example/profile/card#me",
		"aud": "solid-sidecar",
		"iat": 90,
		"exp": 200,
	})
	verifier := NewIdentityVerifier(NewIssuerDiscoveryClient(server.Client()), IdentityValidationOptions{AllowedIssuers: []string{server.URL}, ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0)})
	_, err := verifier.Verify(context.Background(), token)
	if !errors.Is(err, ErrInvalidJWT) {
		t.Fatalf("error = %v, want ErrInvalidJWT", err)
	}
}

func newTestIssuerServer(t *testing.T, privateKey *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	jwks := jwksForRSAKey(t, kid, &privateKey.PublicKey)
	return newTestIssuerServerWithJWKS(t, func() JWKS { return jwks })
}

func newRotatingTestIssuerServer(t *testing.T, oldKey *rsa.PrivateKey, newKey *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	oldJWKS := jwksForRSAKey(t, kid, &oldKey.PublicKey)
	newJWKS := jwksForRSAKey(t, kid, &newKey.PublicKey)
	jwksHits := 0
	return newTestIssuerServerWithJWKS(t, func() JWKS {
		jwksHits++
		if jwksHits == 1 {
			return oldJWKS
		}
		return newJWKS
	})
}

func newTestIssuerServerWithJWKS(t *testing.T, jwksForRequest func() JWKS) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, server.URL, server.URL+"/jwks")
		case "/jwks":
			if err := json.NewEncoder(w).Encode(jwksForRequest()); err != nil {
				t.Fatalf("Encode returned error: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}
