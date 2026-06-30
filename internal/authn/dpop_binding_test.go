package authn

import (
	"encoding/json"
	"testing"
	"time"
)

func TestConfirmDPoPTokenBindingAcceptsMatchingJKT(t *testing.T) {
	privateKey := mustP256Key(t)
	proof := mustDPoPProof(t, privateKey, ProofClaims{
		HTM: "GET",
		HTU: "https://pod.example/alice/card",
		JTI: "binding-1",
		IAT: time.Unix(1_700_000_000, 0).Unix(),
		ATH: accessTokenHash("placeholder"),
	})
	jkt := mustProofThumbprint(t, proof)
	accessToken := mustCompactJWT(t, map[string]any{
		"iss": "https://issuer.example/",
		"sub": "https://pod.example/profile/card#me",
		"cnf": map[string]string{"jkt": jkt},
	})
	if err := ConfirmDPoPTokenBinding(accessToken, proof); err != nil {
		t.Fatalf("expected binding to verify: %v", err)
	}
}

func TestConfirmDPoPTokenBindingRejectsMismatchedJKT(t *testing.T) {
	firstProof := mustDPoPProof(t, mustP256Key(t), ProofClaims{
		HTM: "GET",
		HTU: "https://pod.example/alice/card",
		JTI: "binding-2a",
		IAT: time.Unix(1_700_000_000, 0).Unix(),
	})
	secondProof := mustDPoPProof(t, mustP256Key(t), ProofClaims{
		HTM: "GET",
		HTU: "https://pod.example/alice/card",
		JTI: "binding-2b",
		IAT: time.Unix(1_700_000_000, 0).Unix(),
	})
	accessToken := mustCompactJWT(t, map[string]any{
		"cnf": map[string]string{"jkt": mustProofThumbprint(t, firstProof)},
	})
	if err := ConfirmDPoPTokenBinding(accessToken, secondProof); err == nil {
		t.Fatal("expected mismatched cnf.jkt to be rejected")
	}
}

func TestConfirmDPoPTokenBindingIgnoresOpaqueToken(t *testing.T) {
	proof := mustDPoPProof(t, mustP256Key(t), ProofClaims{
		HTM: "GET",
		HTU: "https://pod.example/alice/card",
		JTI: "binding-3",
		IAT: time.Unix(1_700_000_000, 0).Unix(),
	})
	if err := ConfirmDPoPTokenBinding("opaque-token", proof); err != nil {
		t.Fatalf("opaque tokens should be left to issuer verification: %v", err)
	}
}

func TestConfirmDPoPTokenBindingIgnoresDottedOpaqueToken(t *testing.T) {
	proof := mustDPoPProof(t, mustP256Key(t), ProofClaims{
		HTM: "GET",
		HTU: "https://pod.example/alice/card",
		JTI: "binding-opaque-dotted",
		IAT: time.Unix(1_700_000_000, 0).Unix(),
	})
	if err := ConfirmDPoPTokenBinding("some.opaque.token", proof); err != nil {
		t.Fatalf("dotted opaque tokens should not be treated as malformed JWTs: %v", err)
	}
}

func TestDPoPConfirmationThumbprintIgnoresEmptyToken(t *testing.T) {
	jkt, ok, err := DPoPConfirmationThumbprint("   ")
	if err != nil {
		t.Fatalf("empty tokens should be ignored: %v", err)
	}
	if ok || jkt != "" {
		t.Fatalf("expected no confirmation thumbprint, got ok=%v jkt=%q", ok, jkt)
	}
}

func TestConfirmDPoPTokenBindingIgnoresJWTWithoutCNF(t *testing.T) {
	proof := mustDPoPProof(t, mustP256Key(t), ProofClaims{
		HTM: "GET",
		HTU: "https://pod.example/alice/card",
		JTI: "binding-4",
		IAT: time.Unix(1_700_000_000, 0).Unix(),
	})
	accessToken := mustCompactJWT(t, map[string]any{"sub": "https://pod.example/profile/card#me"})
	if err := ConfirmDPoPTokenBinding(accessToken, proof); err != nil {
		t.Fatalf("JWTs without cnf.jkt should be left to issuer verification: %v", err)
	}
}

func TestDPoPConfirmationThumbprintRejectsMalformedJWTClaims(t *testing.T) {
	token := base64RawURL.EncodeToString([]byte(`{"typ":"JWT"}`)) + ".not-base64.ignored"
	if _, _, err := DPoPConfirmationThumbprint(token); err == nil {
		t.Fatal("expected malformed compact JWT claims to be rejected")
	}
}

func mustProofThumbprint(t *testing.T, proof string) string {
	t.Helper()
	header, _, _, _, err := parseProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := proofJWKThumbprint(header.JWK)
	if err != nil {
		t.Fatal(err)
	}
	return thumbprint
}

func mustCompactJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	headerBytes, err := json.Marshal(map[string]string{"typ": "JWT", "alg": "none"})
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64RawURL.EncodeToString(headerBytes) + "." + base64RawURL.EncodeToString(claimsBytes) + ".ignored"
}
