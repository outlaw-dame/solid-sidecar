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

func stringsSplitToken(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("bad token parts: %d", len(parts))
	}
	return parts
}
