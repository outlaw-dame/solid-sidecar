package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/config"
)

func TestDPoPVerifierAcceptsValidES256Proof(t *testing.T) {
	privateKey := mustP256Key(t)
	accessToken := "access-token"
	now := time.Unix(1_700_000_000, 0)
	proof := mustDPoPProof(t, privateKey, ProofClaims{
		HTM: "GET",
		HTU: "https://pod.example/alice/card",
		JTI: "proof-1",
		IAT: now.Unix(),
		ATH: accessTokenHash(accessToken),
	})
	verifier := NewDPoPVerifier(config.AuthConfig{
		PreflightEnabled:       true,
		ValidateDPoPSignature: true,
		MaxClockSkew:          time.Minute,
		ReplayWindow:          10 * time.Minute,
		PublicBaseURL:         "https://pod.example",
	}, NewReplayCache())
	verifier.now = func() time.Time { return now }
	req := httptest.NewRequest(http.MethodGet, "http://internal/alice/card?ignored=true", nil)
	if err := verifier.VerifyRequest(req, accessToken, proof); err != nil {
		t.Fatalf("expected proof to verify: %v", err)
	}
}

func TestDPoPVerifierRejectsWrongATH(t *testing.T) {
	privateKey := mustP256Key(t)
	now := time.Unix(1_700_000_000, 0)
	proof := mustDPoPProof(t, privateKey, ProofClaims{
		HTM: "GET",
		HTU: "https://pod.example/alice/card",
		JTI: "proof-2",
		IAT: now.Unix(),
		ATH: accessTokenHash("different-token"),
	})
	verifier := NewDPoPVerifier(config.AuthConfig{
		PreflightEnabled:       true,
		ValidateDPoPSignature: true,
		MaxClockSkew:          time.Minute,
		ReplayWindow:          10 * time.Minute,
		PublicBaseURL:         "https://pod.example",
	}, NewReplayCache())
	verifier.now = func() time.Time { return now }
	req := httptest.NewRequest(http.MethodGet, "http://internal/alice/card", nil)
	if err := verifier.VerifyRequest(req, "access-token", proof); err == nil {
		t.Fatal("expected ath mismatch to be rejected")
	}
}

func TestDPoPVerifierRejectsReplay(t *testing.T) {
	privateKey := mustP256Key(t)
	accessToken := "access-token"
	now := time.Unix(1_700_000_000, 0)
	proof := mustDPoPProof(t, privateKey, ProofClaims{
		HTM: "GET",
		HTU: "https://pod.example/alice/card",
		JTI: "proof-3",
		IAT: now.Unix(),
		ATH: accessTokenHash(accessToken),
	})
	verifier := NewDPoPVerifier(config.AuthConfig{
		PreflightEnabled:       true,
		ValidateDPoPSignature: true,
		MaxClockSkew:          time.Minute,
		ReplayWindow:          10 * time.Minute,
		PublicBaseURL:         "https://pod.example",
	}, NewReplayCache())
	verifier.now = func() time.Time { return now }
	req := httptest.NewRequest(http.MethodGet, "http://internal/alice/card", nil)
	if err := verifier.VerifyRequest(req, accessToken, proof); err != nil {
		t.Fatalf("first proof should verify: %v", err)
	}
	if err := verifier.VerifyRequest(req, accessToken, proof); err == nil {
		t.Fatal("expected replay to be rejected")
	}
}

func TestExpectedHTUIgnoresQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://pod.example/alice/card?query=ignored", nil)
	if got := expectedHTU(req, ""); got != "https://pod.example/alice/card" {
		t.Fatalf("unexpected htu: %q", got)
	}
}

func mustP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustDPoPProof(t *testing.T, key *ecdsa.PrivateKey, claims ProofClaims) string {
	t.Helper()
	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64RawURL.EncodeToString(padCurveCoordinate(key.PublicKey.X.Bytes())),
			"y":   base64RawURL.EncodeToString(padCurveCoordinate(key.PublicKey.Y.Bytes())),
		},
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64RawURL.EncodeToString(headerBytes) + "." + base64RawURL.EncodeToString(claimsBytes)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(padCurveCoordinate(r.Bytes()), padCurveCoordinate(s.Bytes())...)
	return signingInput + "." + base64RawURL.EncodeToString(signature)
}

func padCurveCoordinate(value []byte) []byte {
	if len(value) >= 32 {
		return value
	}
	padded := make([]byte, 32)
	copy(padded[32-len(value):], value)
	return padded
}
