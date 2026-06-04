package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/config"
)

var base64RawURL = base64.RawURLEncoding

type DPoPVerifier struct {
	cfg   config.AuthConfig
	cache *ReplayCache
	now   func() time.Time
}

type ProofClaims struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	JTI string `json:"jti"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath"`
}

type proofHeader struct {
	Typ string          `json:"typ"`
	Alg string          `json:"alg"`
	JWK json.RawMessage `json:"jwk"`
}

type jwk struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func NewDPoPVerifier(cfg config.AuthConfig, cache *ReplayCache) *DPoPVerifier {
	if cache == nil {
		cache = NewReplayCache()
	}
	return &DPoPVerifier{cfg: cfg, cache: cache, now: time.Now}
}

func (v *DPoPVerifier) VerifyRequest(r *http.Request, accessToken string, proof string) error {
	header, claims, signingInput, signature, err := parseProof(proof)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(header.Typ), "dpop+jwt") {
		return errors.New("DPoP proof typ must be dpop+jwt")
	}
	if v.cfg.ValidateDPoPSignature {
		if err := verifySignature(header, signingInput, signature); err != nil {
			return err
		}
	}
	if strings.ToUpper(claims.HTM) != r.Method {
		return errors.New("DPoP htm does not match request method")
	}
	expectedHTU := expectedHTU(r, v.cfg.PublicBaseURL)
	if normalizeHTU(claims.HTU) != normalizeHTU(expectedHTU) {
		return fmt.Errorf("DPoP htu does not match request target")
	}
	if claims.JTI == "" || len(claims.JTI) > 512 {
		return errors.New("DPoP jti is required and must be bounded")
	}
	issuedAt := time.Unix(claims.IAT, 0)
	now := v.now()
	if issuedAt.After(now.Add(v.cfg.MaxClockSkew)) {
		return errors.New("DPoP iat is in the future")
	}
	if issuedAt.Before(now.Add(-v.cfg.ReplayWindow - v.cfg.MaxClockSkew)) {
		return errors.New("DPoP proof is too old")
	}
	if accessToken != "" {
		expectedATH := accessTokenHash(accessToken)
		if claims.ATH == "" {
			return errors.New("DPoP ath is required when an access token is present")
		}
		if subtle.ConstantTimeCompare([]byte(claims.ATH), []byte(expectedATH)) != 1 {
			return errors.New("DPoP ath does not match access token")
		}
	}
	cacheKey := replayKey(header, claims)
	if ok := v.cache.Store(cacheKey, issuedAt.Add(v.cfg.ReplayWindow)); !ok {
		return errors.New("DPoP proof replay detected")
	}
	return nil
}

func parseProof(proof string) (proofHeader, ProofClaims, []byte, []byte, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return proofHeader{}, ProofClaims{}, nil, nil, errors.New("DPoP proof must be a compact JWT")
	}
	headerBytes, err := base64RawURL.DecodeString(parts[0])
	if err != nil {
		return proofHeader{}, ProofClaims{}, nil, nil, errors.New("DPoP header is not valid base64url")
	}
	claimsBytes, err := base64RawURL.DecodeString(parts[1])
	if err != nil {
		return proofHeader{}, ProofClaims{}, nil, nil, errors.New("DPoP claims are not valid base64url")
	}
	signature, err := base64RawURL.DecodeString(parts[2])
	if err != nil {
		return proofHeader{}, ProofClaims{}, nil, nil, errors.New("DPoP signature is not valid base64url")
	}
	var header proofHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return proofHeader{}, ProofClaims{}, nil, nil, errors.New("DPoP header is not valid JSON")
	}
	var claims ProofClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return proofHeader{}, ProofClaims{}, nil, nil, errors.New("DPoP claims are not valid JSON")
	}
	return header, claims, []byte(parts[0] + "." + parts[1]), signature, nil
}

func verifySignature(header proofHeader, signingInput, signature []byte) error {
	if len(header.JWK) == 0 {
		return errors.New("DPoP proof header must include jwk")
	}
	var key jwk
	if err := json.Unmarshal(header.JWK, &key); err != nil {
		return errors.New("DPoP jwk is not valid JSON")
	}
	digest := sha256.Sum256(signingInput)
	switch header.Alg {
	case "ES256":
		publicKey, err := ecdsaPublicKey(key)
		if err != nil {
			return err
		}
		if len(signature) != 64 {
			return errors.New("ES256 DPoP signature must be 64 bytes")
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(publicKey, digest[:], r, s) {
			return errors.New("ES256 DPoP signature verification failed")
		}
		return nil
	case "RS256":
		publicKey, err := rsaPublicKey(key)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
			return errors.New("RS256 DPoP signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported DPoP alg %q", header.Alg)
	}
}

func ecdsaPublicKey(key jwk) (*ecdsa.PublicKey, error) {
	if key.KTY != "EC" || key.CRV != "P-256" {
		return nil, errors.New("ES256 DPoP jwk must be EC P-256")
	}
	xBytes, err := base64RawURL.DecodeString(key.X)
	if err != nil {
		return nil, errors.New("EC jwk x is invalid")
	}
	yBytes, err := base64RawURL.DecodeString(key.Y)
	if err != nil {
		return nil, errors.New("EC jwk y is invalid")
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("EC jwk point is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func rsaPublicKey(key jwk) (*rsa.PublicKey, error) {
	if key.KTY != "RSA" {
		return nil, errors.New("RS256 DPoP jwk must be RSA")
	}
	nBytes, err := base64RawURL.DecodeString(key.N)
	if err != nil {
		return nil, errors.New("RSA jwk n is invalid")
	}
	eBytes, err := base64RawURL.DecodeString(key.E)
	if err != nil {
		return nil, errors.New("RSA jwk e is invalid")
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes).Int64()
	if n.Sign() <= 0 || e < 3 || e > (1<<31)-1 {
		return nil, errors.New("RSA jwk parameters are invalid")
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

func accessTokenHash(accessToken string) string {
	digest := sha256.Sum256([]byte(accessToken))
	return base64RawURL.EncodeToString(digest[:])
}

func replayKey(header proofHeader, claims ProofClaims) string {
	digest := sha256.Sum256(header.JWK)
	return base64RawURL.EncodeToString(digest[:]) + ":" + claims.JTI
}

func expectedHTU(r *http.Request, publicBaseURL string) string {
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if publicBaseURL != "" {
		base, err := url.Parse(publicBaseURL)
		if err == nil {
			base.Path = strings.TrimRight(base.Path, "/") + path
			base.RawQuery = ""
			base.Fragment = ""
			return base.String()
		}
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + path
}

func normalizeHTU(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return value
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
