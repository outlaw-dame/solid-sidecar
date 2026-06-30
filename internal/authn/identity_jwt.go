package authn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type identityJWTHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

func ValidateSignedIdentityToken(token string, keys JWKSet, opts IdentityValidationOptions) (TrustedIdentity, error) {
	header, claims, signingInput, signature, err := parseIdentityJWT(token)
	if err != nil {
		return TrustedIdentity{}, err
	}
	if header.Type != "" && !strings.EqualFold(header.Type, "JWT") {
		return TrustedIdentity{}, fmt.Errorf("%w: unsupported token typ", ErrInvalidIdentityToken)
	}
	if header.KeyID == "" {
		return TrustedIdentity{}, fmt.Errorf("%w: missing token kid", ErrInvalidIdentityToken)
	}
	key, ok, err := keys.KeyByID(header.KeyID)
	if err != nil {
		return TrustedIdentity{}, err
	}
	if !ok {
		return TrustedIdentity{}, fmt.Errorf("%w: token signing key not found", ErrInvalidIdentityToken)
	}
	if err := verifySignature(proofHeader{Alg: header.Algorithm, JWK: key}, signingInput, signature); err != nil {
		return TrustedIdentity{}, fmt.Errorf("%w: token signature invalid", ErrInvalidIdentityToken)
	}
	return ValidateIdentityClaims(claims, opts)
}

func parseIdentityJWT(token string) (identityJWTHeader, IdentityClaims, []byte, []byte, error) {
	if token == "" || len(token) > 32768 || strings.ContainsAny(token, "\r\n\x00") {
		return identityJWTHeader{}, IdentityClaims{}, nil, nil, fmt.Errorf("%w: token size or characters invalid", ErrInvalidIdentityToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return identityJWTHeader{}, IdentityClaims{}, nil, nil, fmt.Errorf("%w: token must be compact JWT", ErrInvalidIdentityToken)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return identityJWTHeader{}, IdentityClaims{}, nil, nil, fmt.Errorf("%w: token header is not base64url", ErrInvalidIdentityToken)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return identityJWTHeader{}, IdentityClaims{}, nil, nil, fmt.Errorf("%w: token claims are not base64url", ErrInvalidIdentityToken)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return identityJWTHeader{}, IdentityClaims{}, nil, nil, fmt.Errorf("%w: token signature is not base64url", ErrInvalidIdentityToken)
	}
	var header identityJWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return identityJWTHeader{}, IdentityClaims{}, nil, nil, fmt.Errorf("%w: token header is not JSON", ErrInvalidIdentityToken)
	}
	claims, err := ParseIdentityClaimsJSON(claimsBytes)
	if err != nil {
		return identityJWTHeader{}, IdentityClaims{}, nil, nil, err
	}
	return header, claims, []byte(parts[0] + "." + parts[1]), signature, nil
}
