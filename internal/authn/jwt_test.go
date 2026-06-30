package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyIdentityJWTWithDiscovery(t *testing.T) {
	privateKey := mustRSAKey(t)
	var issuerURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuerURL, issuerURL+"/jwks")
		case "/jwks":
			jwks := jwksForRSAKey(t, "key-1", &privateKey.PublicKey)
			encoded, err := json.Marshal(jwks)
			if err != nil {
				t.Fatalf("Marshal JWKS returned error: %v", err)
			}
			_, _ = w.Write(encoded)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	issuerURL = server.URL

	token := signTestJWT(t, privateKey, "key-1", "RS256", map[string]any{
		"iss": issuerURL,
		"sub": "https://alice.example/profile/card#me",
		"aud": "solid-sidecar",
		"iat": 90,
		"exp": 200,
	})
	client := NewIssuerDiscoveryClient(server.Client())
	identity, err := VerifyIdentityJWTWithDiscovery(context.Background(), token, client, IdentityValidationOptions{AllowedIssuers: []string{issuerURL}, ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0), ClockSkew: time.Second})
	if err != nil {
		t.Fatalf("VerifyIdentityJWTWithDiscovery returned error: %v", err)
	}
	if identity.Issuer != issuerURL || identity.WebID != "https://alice.example/profile/card#me" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestVerifyIdentityJWTWithDiscoveryRequiresAllowedIssuer(t *testing.T) {
	privateKey := mustRSAKey(t)
	token := signTestJWT(t, privateKey, "key-1", "RS256", validJWTClaims())
	_, err := VerifyIdentityJWTWithDiscovery(context.Background(), token, NewIssuerDiscoveryClient(nil), IdentityValidationOptions{ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0), ClockSkew: time.Second})
	if !errors.Is(err, ErrInvalidJWT) {
		t.Fatalf("error = %v, want ErrInvalidJWT", err)
	}
}

func TestVerifyIdentityJWTAcceptsValidRS256Token(t *testing.T) {
	privateKey := mustRSAKey(t)
	jwks := jwksForRSAKey(t, "key-1", &privateKey.PublicKey)
	token := signTestJWT(t, privateKey, "key-1", "RS256", map[string]any{
		"iss":       "https://issuer.example/",
		"sub":       "https://alice.example/profile/card#me",
		"aud":       "solid-sidecar",
		"client_id": "client-1",
		"iat":       90,
		"exp":       200,
	})
	identity, err := VerifyIdentityJWT(token, jwks, IdentityValidationOptions{AllowedIssuers: []string{"https://issuer.example/"}, ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0), ClockSkew: time.Second})
	if err != nil {
		t.Fatalf("VerifyIdentityJWT returned error: %v", err)
	}
	if identity.Issuer != "https://issuer.example/" || identity.WebID != "https://alice.example/profile/card#me" || identity.ClientID != "client-1" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestVerifyIdentityJWTRejectsBadSignature(t *testing.T) {
	privateKey := mustRSAKey(t)
	otherKey := mustRSAKey(t)
	jwks := jwksForRSAKey(t, "key-1", &privateKey.PublicKey)
	token := signTestJWT(t, otherKey, "key-1", "RS256", validJWTClaims())
	_, err := VerifyIdentityJWT(token, jwks, validJWTOptions())
	if !errors.Is(err, ErrInvalidJWT) {
		t.Fatalf("error = %v, want ErrInvalidJWT", err)
	}
}

func TestVerifyIdentityJWTRejectsUnknownKeyID(t *testing.T) {
	privateKey := mustRSAKey(t)
	jwks := jwksForRSAKey(t, "key-2", &privateKey.PublicKey)
	token := signTestJWT(t, privateKey, "key-1", "RS256", validJWTClaims())
	_, err := VerifyIdentityJWT(token, jwks, validJWTOptions())
	if !errors.Is(err, ErrInvalidJWT) {
		t.Fatalf("error = %v, want ErrInvalidJWT", err)
	}
}

func TestVerifyIdentityJWTRejectsUnsupportedAlgorithm(t *testing.T) {
	privateKey := mustRSAKey(t)
	jwks := jwksForRSAKey(t, "key-1", &privateKey.PublicKey)
	token := signTestJWT(t, privateKey, "key-1", "none", validJWTClaims())
	_, err := VerifyIdentityJWT(token, jwks, validJWTOptions())
	if !errors.Is(err, ErrInvalidJWT) {
		t.Fatalf("error = %v, want ErrInvalidJWT", err)
	}
}

func TestVerifyIdentityJWTRejectsInvalidClaims(t *testing.T) {
	privateKey := mustRSAKey(t)
	jwks := jwksForRSAKey(t, "key-1", &privateKey.PublicKey)
	claims := validJWTClaims()
	claims["aud"] = "other"
	token := signTestJWT(t, privateKey, "key-1", "RS256", claims)
	_, err := VerifyIdentityJWT(token, jwks, validJWTOptions())
	if !errors.Is(err, ErrInvalidIdentityToken) {
		t.Fatalf("error = %v, want ErrInvalidIdentityToken", err)
	}
}

func validJWTClaims() map[string]any {
	return map[string]any{
		"iss": "https://issuer.example/",
		"sub": "https://alice.example/profile/card#me",
		"aud": "solid-sidecar",
		"iat": 90,
		"exp": 200,
	}
}

func validJWTOptions() IdentityValidationOptions {
	return IdentityValidationOptions{AllowedIssuers: []string{"https://issuer.example/"}, ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0), ClockSkew: time.Second}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	return key
}

func jwksForRSAKey(t *testing.T, kid string, publicKey *rsa.PublicKey) JWKS {
	t.Helper()
	jwk := map[string]string{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}
	encoded, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	return JWKS{Keys: []json.RawMessage{encoded}}
}

func signTestJWT(t *testing.T, privateKey *rsa.PrivateKey, kid string, alg string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatalf("Marshal header returned error: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal claims returned error: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15 returned error: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
