package authn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestVerifyIDTokenWithJWKSetAcceptsSignedToken(t *testing.T) {
	key, set := mustRSAJWKSet(t, "key-1")
	token := mustSignedIDToken(t, key, "key-1", IdentityClaims{Issuer: "https://issuer.example/", Subject: "https://alice.example/profile/card#me", Audience: []string{"solid-sidecar"}, ClientID: "client-1", IssuedAt: 90, ExpiresAt: 200})
	identity, err := VerifyIDTokenWithJWKSet(token, set, IdentityValidationOptions{AllowedIssuers: []string{"https://issuer.example/"}, ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0), ClockSkew: time.Second})
	if err != nil {
		t.Fatalf("VerifyIDTokenWithJWKSet returned error: %v", err)
	}
	if identity.WebID != "https://alice.example/profile/card#me" || identity.Issuer != "https://issuer.example/" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestVerifyIDTokenWithJWKSetRejectsTamperedToken(t *testing.T) {
	key, set := mustRSAJWKSet(t, "key-1")
	token := mustSignedIDToken(t, key, "key-1", IdentityClaims{Issuer: "https://issuer.example/", Subject: "https://alice.example/profile/card#me", Audience: []string{"solid-sidecar"}, IssuedAt: 90, ExpiresAt: 200})
	parts := stringsSplitToken(t, token)
	parts[1] = base64RawURL.EncodeToString([]byte(`{"iss":"https://issuer.example/","sub":"https://mallory.example/#me","aud":"solid-sidecar","exp":200}`))
	_, err := VerifyIDTokenWithJWKSet(parts[0]+"."+parts[1]+"."+parts[2], set, IdentityValidationOptions{AllowedIssuers: []string{"https://issuer.example/"}, ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0), ClockSkew: time.Second})
	if !errors.Is(err, ErrInvalidIdentityToken) {
		t.Fatalf("error = %v, want ErrInvalidIdentityToken", err)
	}
}

func TestVerifyIDTokenWithJWKSetRejectsUnknownKid(t *testing.T) {
	key, set := mustRSAJWKSet(t, "key-1")
	token := mustSignedIDToken(t, key, "key-2", IdentityClaims{Issuer: "https://issuer.example/", Subject: "https://alice.example/profile/card#me", Audience: []string{"solid-sidecar"}, IssuedAt: 90, ExpiresAt: 200})
	_, err := VerifyIDTokenWithJWKSet(token, set, IdentityValidationOptions{AllowedIssuers: []string{"https://issuer.example/"}, ExpectedAudience: "solid-sidecar", Now: time.Unix(100, 0), ClockSkew: time.Second})
	if !errors.Is(err, ErrInvalidIdentityToken) {
		t.Fatalf("error = %v, want ErrInvalidIdentityToken", err)
	}
}

func mustRSAJWKSet(t *testing.T, kid string) (*rsa.PrivateKey, JWKSet) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]string{"kid": kid, "kty": "RSA", "use": "sig", "alg": "RS256", "n": base64RawURL.EncodeToString(key.PublicKey.N.Bytes()), "e": base64RawURL.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	return key, JWKSet{Keys: []json.RawMessage{raw}}
}

func mustSignedIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims IdentityClaims) string {
	t.Helper()
	headerBytes, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64RawURL.EncodeToString(headerBytes) + "." + base64RawURL.EncodeToString(claimsBytes)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64RawURL.EncodeToString(signature)
}

func TestVerifyIDTokenWithJWKSetHandlesKeyRotation(t *testing.T) {
	// Generate two different keys
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create JWKS with only key1
	jwk1 := map[string]string{"kid": "key-1", "kty": "RSA", "use": "sig", "alg": "RS256", "n": base64RawURL.EncodeToString(key1.PublicKey.N.Bytes()), "e": base64RawURL.EncodeToString(big.NewInt(int64(key1.PublicKey.E)).Bytes())}
	raw1, err := json.Marshal(jwk1)
	if err != nil {
		t.Fatal(err)
	}
	setWithKey1 := JWKSet{Keys: []json.RawMessage{raw1}}

	// Create JWKS with only key2 (key1 rotated out)
	jwk2 := map[string]string{"kid": "key-2", "kty": "RSA", "use": "sig", "alg": "RS256", "n": base64RawURL.EncodeToString(key2.PublicKey.N.Bytes()), "e": base64RawURL.EncodeToString(big.NewInt(int64(key2.PublicKey.E)).Bytes())}
	raw2, err := json.Marshal(jwk2)
	if err != nil {
		t.Fatal(err)
	}
	setWithKey2 := JWKSet{Keys: []json.RawMessage{raw2}}

	// Create JWKS with both keys (transition period)
	setWithBothKeys := JWKSet{Keys: []json.RawMessage{raw1, raw2}}

	claims := IdentityClaims{Issuer: "https://issuer.example/", Subject: "https://alice.example/profile/card#me", Audience: []string{"solid-sidecar"}, IssuedAt: 90, ExpiresAt: 200}
	now := time.Unix(100, 0)

	// Token signed with key1 should work with JWKS containing key1
	token1 := mustSignedIDTokenWithKey(t, key1, "key-1", claims)
	_, err = VerifyIDTokenWithJWKSet(token1, setWithKey1, IdentityValidationOptions{AllowedIssuers: []string{"https://issuer.example/"}, ExpectedAudience: "solid-sidecar", Now: now, ClockSkew: time.Second})
	if err != nil {
		t.Fatalf("token signed with key1 should work with JWKS containing key1: %v", err)
	}

	// Token signed with key2 should work with JWKS containing key2
	token2 := mustSignedIDTokenWithKey(t, key2, "key-2", claims)
	_, err = VerifyIDTokenWithJWKSet(token2, setWithKey2, IdentityValidationOptions{AllowedIssuers: []string{"https://issuer.example/"}, ExpectedAudience: "solid-sidecar", Now: now, ClockSkew: time.Second})
	if err != nil {
		t.Fatalf("token signed with key2 should work with JWKS containing key2: %v", err)
	}

	// Token signed with key1 should fail with JWKS containing only key2 (key rotation)
	_, err = VerifyIDTokenWithJWKSet(token1, setWithKey2, IdentityValidationOptions{AllowedIssuers: []string{"https://issuer.example/"}, ExpectedAudience: "solid-sidecar", Now: now, ClockSkew: time.Second})
	if !errors.Is(err, ErrInvalidIdentityToken) {
		t.Fatalf("token signed with key1 should fail with JWKS containing only key2: got %v, want ErrInvalidIdentityToken", err)
	}

	// Token signed with key1 should work with JWKS containing both keys (transition period)
	_, err = VerifyIDTokenWithJWKSet(token1, setWithBothKeys, IdentityValidationOptions{AllowedIssuers: []string{"https://issuer.example/"}, ExpectedAudience: "solid-sidecar", Now: now, ClockSkew: time.Second})
	if err != nil {
		t.Fatalf("token signed with key1 should work with JWKS containing both keys: %v", err)
	}

	// Token signed with key2 should work with JWKS containing both keys
	_, err = VerifyIDTokenWithJWKSet(token2, setWithBothKeys, IdentityValidationOptions{AllowedIssuers: []string{"https://issuer.example/"}, ExpectedAudience: "solid-sidecar", Now: now, ClockSkew: time.Second})
	if err != nil {
		t.Fatalf("token signed with key2 should work with JWKS containing both keys: %v", err)
	}
}

func mustSignedIDTokenWithKey(t *testing.T, key *rsa.PrivateKey, kid string, claims IdentityClaims) string {
	t.Helper()
	headerBytes, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64RawURL.EncodeToString(headerBytes) + "." + base64RawURL.EncodeToString(claimsBytes)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64RawURL.EncodeToString(signature)
}

func stringsSplitToken(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("bad token parts: %d", len(parts))
	}
	return parts
}
