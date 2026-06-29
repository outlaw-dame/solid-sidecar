package authn

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const maxCompactJWTLength = 32768

var ErrInvalidJWT = errors.New("invalid jwt")

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ,omitempty"`
}

type rsaJWK struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg,omitempty"`
	Use       string `json:"use,omitempty"`
	N         string `json:"n"`
	E         string `json:"e"`
}

func VerifyIdentityJWTWithDiscovery(ctx context.Context, token string, discovery *IssuerDiscoveryClient, opts IdentityValidationOptions) (TrustedIdentity, error) {
	if discovery == nil {
		return TrustedIdentity{}, fmt.Errorf("%w: nil discovery client", ErrInvalidJWT)
	}
	_, payload, _, _, err := parseCompactJWT(token)
	if err != nil {
		return TrustedIdentity{}, err
	}
	claims, err := ParseIdentityClaimsJSON(payload)
	if err != nil {
		return TrustedIdentity{}, err
	}
	issuer, err := canonicalIssuerURI(claims.Issuer)
	if err != nil {
		return TrustedIdentity{}, fmt.Errorf("%w: invalid issuer", ErrInvalidJWT)
	}
	if len(opts.AllowedIssuers) == 0 || !issuerAllowed(issuer, opts.AllowedIssuers) {
		return TrustedIdentity{}, fmt.Errorf("%w: issuer is not allowed for discovery", ErrInvalidJWT)
	}
	metadata, err := discovery.Discover(ctx, issuer)
	if err != nil {
		return TrustedIdentity{}, err
	}
	jwks, err := discovery.FetchJWKS(ctx, metadata)
	if err != nil {
		return TrustedIdentity{}, err
	}
	return VerifyIdentityJWT(token, jwks, opts)
}

func VerifyIdentityJWT(token string, jwks JWKS, opts IdentityValidationOptions) (TrustedIdentity, error) {
	header, payload, signingInput, signature, err := parseCompactJWT(token)
	if err != nil {
		return TrustedIdentity{}, err
	}
	if header.Algorithm != "RS256" {
		return TrustedIdentity{}, fmt.Errorf("%w: unsupported algorithm", ErrInvalidJWT)
	}
	if header.KeyID == "" {
		return TrustedIdentity{}, fmt.Errorf("%w: missing key id", ErrInvalidJWT)
	}
	publicKey, err := rsaPublicKeyForJWT(jwks, header.KeyID, header.Algorithm)
	if err != nil {
		return TrustedIdentity{}, err
	}
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return TrustedIdentity{}, fmt.Errorf("%w: signature verification failed", ErrInvalidJWT)
	}
	claims, err := ParseIdentityClaimsJSON(payload)
	if err != nil {
		return TrustedIdentity{}, err
	}
	identity, err := ValidateIdentityClaims(claims, opts)
	if err != nil {
		return TrustedIdentity{}, err
	}
	return identity, nil
}

func parseCompactJWT(token string) (jwtHeader, []byte, string, []byte, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > maxCompactJWTLength || strings.ContainsAny(token, "\r\n\x00") {
		return jwtHeader{}, nil, "", nil, fmt.Errorf("%w: invalid token length", ErrInvalidJWT)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return jwtHeader{}, nil, "", nil, fmt.Errorf("%w: compact token must have three parts", ErrInvalidJWT)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(headerBytes) == 0 || len(headerBytes) > 4096 {
		return jwtHeader{}, nil, "", nil, fmt.Errorf("%w: invalid header", ErrInvalidJWT)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 32768 {
		return jwtHeader{}, nil, "", nil, fmt.Errorf("%w: invalid payload", ErrInvalidJWT)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) == 0 || len(signature) > 8192 {
		return jwtHeader{}, nil, "", nil, fmt.Errorf("%w: invalid signature", ErrInvalidJWT)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return jwtHeader{}, nil, "", nil, fmt.Errorf("%w: invalid header json", ErrInvalidJWT)
	}
	return header, payload, parts[0] + "." + parts[1], signature, nil
}

func rsaPublicKeyForJWT(jwks JWKS, kid string, alg string) (*rsa.PublicKey, error) {
	if kid == "" || alg != "RS256" {
		return nil, fmt.Errorf("%w: invalid key selector", ErrInvalidJWT)
	}
	if len(jwks.Keys) == 0 || len(jwks.Keys) > 32 {
		return nil, fmt.Errorf("%w: invalid jwks", ErrInvalidJWT)
	}
	for _, raw := range jwks.Keys {
		var key rsaJWK
		if err := json.Unmarshal(raw, &key); err != nil {
			return nil, fmt.Errorf("%w: invalid jwk", ErrInvalidJWT)
		}
		if key.KeyID != kid {
			continue
		}
		if key.KeyType != "RSA" || key.N == "" || key.E == "" {
			return nil, fmt.Errorf("%w: invalid rsa jwk", ErrInvalidJWT)
		}
		if key.Algorithm != "" && key.Algorithm != alg {
			return nil, fmt.Errorf("%w: jwk algorithm mismatch", ErrInvalidJWT)
		}
		if key.Use != "" && key.Use != "sig" {
			return nil, fmt.Errorf("%w: jwk use mismatch", ErrInvalidJWT)
		}
		return rsaPublicKeyFromJWK(key)
	}
	return nil, fmt.Errorf("%w: key not found", ErrInvalidJWT)
}

func rsaPublicKeyFromJWK(key rsaJWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil || len(nBytes) == 0 || len(nBytes) > 8192 {
		return nil, fmt.Errorf("%w: invalid rsa modulus", ErrInvalidJWT)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, fmt.Errorf("%w: invalid rsa exponent", ErrInvalidJWT)
	}
	exponent := new(big.Int).SetBytes(eBytes)
	if !exponent.IsInt64() || exponent.Sign() <= 0 || exponent.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("%w: invalid rsa exponent", ErrInvalidJWT)
	}
	modulus := new(big.Int).SetBytes(nBytes)
	if modulus.BitLen() < 2048 {
		return nil, fmt.Errorf("%w: rsa key too small", ErrInvalidJWT)
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}
