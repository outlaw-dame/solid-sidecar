package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultOIDCTimeout = 5 * time.Second
const defaultOIDCMaxResponseBytes = 256 * 1024
const maxJWKSKeys = 64

var ErrInvalidOIDCDiscovery = errors.New("invalid oidc discovery")

type OIDCDiscoveryConfig struct {
	HTTPClient       *http.Client
	Timeout          time.Duration
	MaxResponseBytes int64
	AllowHTTPForTest bool
}

type OIDCDiscoveryClient struct {
	httpClient       *http.Client
	timeout          time.Duration
	maxResponseBytes int64
	allowHTTPForTest bool
}

type OIDCIssuerMetadata struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type JWKSet struct {
	Keys []json.RawMessage `json:"keys"`
}

type jwksKeyHeader struct {
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
}

func NewOIDCDiscoveryClient(cfg OIDCDiscoveryConfig) *OIDCDiscoveryClient {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultOIDCTimeout
	}
	maxResponseBytes := cfg.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = defaultOIDCMaxResponseBytes
	}
	return &OIDCDiscoveryClient{httpClient: client, timeout: timeout, maxResponseBytes: maxResponseBytes, allowHTTPForTest: cfg.AllowHTTPForTest}
}

func (c *OIDCDiscoveryClient) DiscoverIssuer(ctx context.Context, issuer string) (OIDCIssuerMetadata, error) {
	wellKnown, canonicalIssuer, err := oidcWellKnownURL(issuer, c.allowHTTPForTest)
	if err != nil {
		return OIDCIssuerMetadata{}, err
	}
	var metadata OIDCIssuerMetadata
	if err := c.getJSON(ctx, wellKnown, &metadata); err != nil {
		return OIDCIssuerMetadata{}, err
	}
	metadataIssuer, err := canonicalIssuerForDiscovery(metadata.Issuer, c.allowHTTPForTest)
	if err != nil {
		return OIDCIssuerMetadata{}, fmt.Errorf("%w: invalid metadata issuer", ErrInvalidOIDCDiscovery)
	}
	if metadataIssuer != canonicalIssuer {
		return OIDCIssuerMetadata{}, fmt.Errorf("%w: issuer mismatch", ErrInvalidOIDCDiscovery)
	}
	jwksURI, err := canonicalIssuerForDiscovery(metadata.JWKSURI, c.allowHTTPForTest)
	if err != nil {
		return OIDCIssuerMetadata{}, fmt.Errorf("%w: invalid jwks uri", ErrInvalidOIDCDiscovery)
	}
	metadata.Issuer = metadataIssuer
	metadata.JWKSURI = jwksURI
	return metadata, nil
}

func (c *OIDCDiscoveryClient) FetchJWKS(ctx context.Context, jwksURI string) (JWKSet, error) {
	canonical, err := canonicalIssuerForDiscovery(jwksURI, c.allowHTTPForTest)
	if err != nil {
		return JWKSet{}, fmt.Errorf("%w: invalid jwks uri", ErrInvalidOIDCDiscovery)
	}
	var set JWKSet
	if err := c.getJSON(ctx, canonical, &set); err != nil {
		return JWKSet{}, err
	}
	if err := ValidateJWKSet(set); err != nil {
		return JWKSet{}, err
	}
	return set, nil
}

func ValidateJWKSet(set JWKSet) error {
	if len(set.Keys) == 0 || len(set.Keys) > maxJWKSKeys {
		return fmt.Errorf("%w: invalid jwks key count", ErrInvalidOIDCDiscovery)
	}
	seen := map[string]struct{}{}
	for _, raw := range set.Keys {
		if len(raw) == 0 || len(raw) > 16384 {
			return fmt.Errorf("%w: invalid jwk size", ErrInvalidOIDCDiscovery)
		}
		var header jwksKeyHeader
		if err := json.Unmarshal(raw, &header); err != nil {
			return fmt.Errorf("%w: invalid jwk json", ErrInvalidOIDCDiscovery)
		}
		if strings.TrimSpace(header.KeyID) == "" || strings.ContainsAny(header.KeyID, "\r\n\x00") || len(header.KeyID) > 512 {
			return fmt.Errorf("%w: invalid jwk kid", ErrInvalidOIDCDiscovery)
		}
		if header.KeyType != "RSA" && header.KeyType != "EC" {
			return fmt.Errorf("%w: unsupported jwk kty", ErrInvalidOIDCDiscovery)
		}
		if header.Use != "" && header.Use != "sig" {
			return fmt.Errorf("%w: unsupported jwk use", ErrInvalidOIDCDiscovery)
		}
		if _, ok := seen[header.KeyID]; ok {
			return fmt.Errorf("%w: duplicate jwk kid", ErrInvalidOIDCDiscovery)
		}
		seen[header.KeyID] = struct{}{}
	}
	return nil
}

func (set JWKSet) KeyByID(keyID string) (json.RawMessage, bool, error) {
	if strings.TrimSpace(keyID) == "" || strings.ContainsAny(keyID, "\r\n\x00") || len(keyID) > 512 {
		return nil, false, fmt.Errorf("%w: invalid jwk kid", ErrInvalidOIDCDiscovery)
	}
	var found json.RawMessage
	for _, raw := range set.Keys {
		var header jwksKeyHeader
		if err := json.Unmarshal(raw, &header); err != nil {
			return nil, false, fmt.Errorf("%w: invalid jwk json", ErrInvalidOIDCDiscovery)
		}
		if header.KeyID == keyID {
			if found != nil {
				return nil, false, fmt.Errorf("%w: duplicate jwk kid", ErrInvalidOIDCDiscovery)
			}
			found = append(json.RawMessage(nil), raw...)
		}
	}
	return found, found != nil, nil
}

func (c *OIDCDiscoveryClient) getJSON(ctx context.Context, target string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("%w: invalid request", ErrInvalidOIDCDiscovery)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: request failed", ErrInvalidOIDCDiscovery)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: unexpected status", ErrInvalidOIDCDiscovery)
	}
	if resp.ContentLength > c.maxResponseBytes {
		return fmt.Errorf("%w: response too large", ErrInvalidOIDCDiscovery)
	}
	limited := io.LimitReader(resp.Body, c.maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("%w: response read failed", ErrInvalidOIDCDiscovery)
	}
	if int64(len(body)) > c.maxResponseBytes {
		return fmt.Errorf("%w: response too large", ErrInvalidOIDCDiscovery)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: response is not JSON", ErrInvalidOIDCDiscovery)
	}
	return nil
}

func oidcWellKnownURL(issuer string, allowHTTP bool) (string, string, error) {
	canonical, err := canonicalIssuerForDiscovery(issuer, allowHTTP)
	if err != nil {
		return "", "", err
	}
	parsed, _ := url.Parse(canonical)
	issuerPath := strings.TrimRight(parsed.EscapedPath(), "/")
	wellKnown := &url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: "/.well-known/openid-configuration"}
	if issuerPath != "" {
		wellKnown.Path += issuerPath
	}
	return wellKnown.String(), canonical, nil
}

func canonicalIssuerForDiscovery(value string, allowHTTP bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxIdentityIssuerLength || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("%w: invalid uri", ErrInvalidOIDCDiscovery)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: invalid uri", ErrInvalidOIDCDiscovery)
	}
	if parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http") {
		return "", fmt.Errorf("%w: insecure uri", ErrInvalidOIDCDiscovery)
	}
	return parsed.String(), nil
}
