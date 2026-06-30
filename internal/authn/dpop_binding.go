package authn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const maxDPoPThumbprintLength = 128

var ErrDPoPTokenBinding = errors.New("invalid DPoP token binding")

// ConfirmDPoPTokenBinding verifies the optional JWT cnf.jkt confirmation claim
// against the public JWK embedded in the DPoP proof header. Request-path code
// should prefer DPoPVerifier.VerifyRequest so the proof is parsed once and the
// signature is verified before binding. This helper remains for focused tests
// and non-request callers.
func ConfirmDPoPTokenBinding(accessToken, proof string) error {
	expected, ok, err := DPoPConfirmationThumbprint(accessToken)
	if err != nil || !ok {
		return err
	}
	header, _, _, _, err := parseProof(proof)
	if err != nil {
		return err
	}
	return confirmDPoPTokenBinding(header, expected)
}

func confirmDPoPTokenBinding(header proofHeader, expected string) error {
	actual, err := proofJWKThumbprint(header.JWK)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) != 1 {
		return fmt.Errorf("%w: cnf.jkt does not match DPoP proof key", ErrDPoPTokenBinding)
	}
	return nil
}

// DPoPConfirmationThumbprint extracts cnf.jkt from a compact JWT access token.
// It does not validate token signatures or identity claims and must not be used
// as trusted identity input. Its only purpose is proof-key confirmation binding.
// Empty tokens and opaque tokens return ok=false so issuer/token validation can
// handle them without false-positive JWT parsing failures.
func DPoPConfirmationThumbprint(accessToken string) (string, bool, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return "", false, nil
	}
	if len(accessToken) > 32768 || strings.ContainsAny(accessToken, "\r\n\x00") {
		return "", false, fmt.Errorf("%w: token size or characters invalid", ErrDPoPTokenBinding)
	}
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return "", false, nil
	}
	if !looksLikeJWTHeader(parts[0]) {
		return "", false, nil
	}
	claimsBytes, err := base64RawURL.DecodeString(parts[1])
	if err != nil {
		return "", false, fmt.Errorf("%w: token claims are not base64url", ErrDPoPTokenBinding)
	}
	var claims struct {
		Confirmation struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return "", false, fmt.Errorf("%w: token claims are not valid JSON", ErrDPoPTokenBinding)
	}
	jkt := strings.TrimSpace(claims.Confirmation.JKT)
	if jkt == "" {
		return "", false, nil
	}
	if len(jkt) > maxDPoPThumbprintLength || strings.ContainsAny(jkt, "\r\n\x00") {
		return "", false, fmt.Errorf("%w: cnf.jkt is invalid", ErrDPoPTokenBinding)
	}
	return jkt, true, nil
}

func looksLikeJWTHeader(encodedHeader string) bool {
	headerBytes, err := base64RawURL.DecodeString(encodedHeader)
	if err != nil {
		return false
	}
	var header struct {
		Type string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(header.Type), "JWT")
}

func proofJWKThumbprint(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || len(raw) > 16384 {
		return "", fmt.Errorf("%w: DPoP proof header must include bounded jwk", ErrDPoPTokenBinding)
	}
	var key jwk
	if err := json.Unmarshal(raw, &key); err != nil {
		return "", fmt.Errorf("%w: DPoP jwk is not valid JSON", ErrDPoPTokenBinding)
	}
	var canonical map[string]string
	switch key.KTY {
	case "EC":
		if key.CRV == "" || key.X == "" || key.Y == "" {
			return "", fmt.Errorf("%w: EC jwk is missing public members", ErrDPoPTokenBinding)
		}
		canonical = map[string]string{"crv": key.CRV, "kty": key.KTY, "x": key.X, "y": key.Y}
	case "RSA":
		if key.N == "" || key.E == "" {
			return "", fmt.Errorf("%w: RSA jwk is missing public members", ErrDPoPTokenBinding)
		}
		canonical = map[string]string{"e": key.E, "kty": key.KTY, "n": key.N}
	default:
		return "", fmt.Errorf("%w: unsupported DPoP jwk type", ErrDPoPTokenBinding)
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("%w: cannot canonicalize jwk", ErrDPoPTokenBinding)
	}
	digest := sha256.Sum256(encoded)
	return base64RawURL.EncodeToString(digest[:]), nil
}
