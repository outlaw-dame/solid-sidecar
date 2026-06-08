package authn

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

type idTokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

func VerifyIDTokenWithJWKSet(token string, set JWKSet, opts IdentityValidationOptions) (TrustedIdentity, error) {
	if err := ValidateJWKSet(set); err != nil {
		return TrustedIdentity{}, err
	}
	header, claimsBytes, signingInput, signature, err := parseIDToken(token)
	if err != nil {
		return TrustedIdentity{}, err
	}
	if err := verifyIDTokenSignature(header, set, signingInput, signature); err != nil {
		return TrustedIdentity{}, err
	}
	claims, err := ParseIdentityClaimsJSON(claimsBytes)
	if err != nil {
		return TrustedIdentity{}, err
	}
	return ValidateIdentityClaims(claims, opts)
}

func parseIDToken(token string) (idTokenHeader, []byte, []byte, []byte, error) {
	if token == "" || len(token) > 32768 || strings.ContainsAny(token, "\r\n\x00") {
		return idTokenHeader{}, nil, nil, nil, fmt.Errorf("%w: token size out of bounds", ErrInvalidIdentityToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return idTokenHeader{}, nil, nil, nil, fmt.Errorf("%w: token is not a compact JWT", ErrInvalidIdentityToken)
	}
	headerBytes, err := base64RawURL.DecodeString(parts[0])
	if err != nil {
		return idTokenHeader{}, nil, nil, nil, fmt.Errorf("%w: invalid token header encoding", ErrInvalidIdentityToken)
	}
	claimsBytes, err := base64RawURL.DecodeString(parts[1])
	if err != nil {
		return idTokenHeader{}, nil, nil, nil, fmt.Errorf("%w: invalid token claims encoding", ErrInvalidIdentityToken)
	}
	signature, err := base64RawURL.DecodeString(parts[2])
	if err != nil {
		return idTokenHeader{}, nil, nil, nil, fmt.Errorf("%w: invalid token signature encoding", ErrInvalidIdentityToken)
	}
	var header idTokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return idTokenHeader{}, nil, nil, nil, fmt.Errorf("%w: token header is not JSON", ErrInvalidIdentityToken)
	}
	return header, claimsBytes, []byte(parts[0] + "." + parts[1]), signature, nil
}

func verifyIDTokenSignature(header idTokenHeader, set JWKSet, signingInput []byte, signature []byte) error {
	if header.Alg != "RS256" && header.Alg != "ES256" {
		return fmt.Errorf("%w: unsupported token alg", ErrInvalidIdentityToken)
	}
	keys := set.Keys
	if strings.TrimSpace(header.Kid) != "" {
		key, ok, err := set.KeyByID(header.Kid)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: token kid not found", ErrInvalidIdentityToken)
		}
		keys = []json.RawMessage{key}
	}
	for _, raw := range keys {
		proofHeader := proofHeader{Alg: header.Alg, JWK: raw}
		if err := verifySignature(proofHeader, signingInput, signature); err == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: token signature verification failed", ErrInvalidIdentityToken)
}

func jwkThumbprintForIDTokenKey(raw json.RawMessage) string {
	digest := sha256.Sum256(raw)
	return base64RawURL.EncodeToString(digest[:])
}
