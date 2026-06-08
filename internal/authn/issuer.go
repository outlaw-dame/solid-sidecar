package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const defaultIssuerHTTPTimeout = 5 * time.Second
const defaultIssuerMaxBodyBytes int64 = 1 << 20
const defaultIssuerCacheTTL = 10 * time.Minute

var ErrInvalidIssuerMetadata = errors.New("invalid issuer metadata")

type IssuerDiscoveryClient struct {
	HTTPClient *http.Client
	MaxBodyBytes int64
	CacheTTL time.Duration
	Now func() time.Time
	cache *IssuerMetadataCache
}

type IssuerMetadata struct {
	Issuer string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
	FetchedAt time.Time `json:"-"`
	ExpiresAt time.Time `json:"-"`
}

type JWKS struct {
	Keys []json.RawMessage `json:"keys"`
	FetchedAt time.Time `json:"-"`
	ExpiresAt time.Time `json:"-"`
}

type IssuerMetadataCache struct {
	mu sync.Mutex
	entries map[string]IssuerMetadata
	sets map[string]JWKS
}

func NewIssuerMetadataCache() *IssuerMetadataCache {
	return &IssuerMetadataCache{entries: map[string]IssuerMetadata{}, sets: map[string]JWKS{}}
}

func NewIssuerDiscoveryClient(httpClient *http.Client) *IssuerDiscoveryClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultIssuerHTTPTimeout}
	}
	return &IssuerDiscoveryClient{HTTPClient: httpClient, MaxBodyBytes: defaultIssuerMaxBodyBytes, CacheTTL: defaultIssuerCacheTTL, Now: time.Now, cache: NewIssuerMetadataCache()}
}

func (c *IssuerDiscoveryClient) Discover(ctx context.Context, issuer string) (IssuerMetadata, error) {
	if c == nil {
		return IssuerMetadata{}, fmt.Errorf("%w: nil discovery client", ErrInvalidIssuerMetadata)
	}
	canonicalIssuer, err := canonicalIssuerURI(issuer)
	if err != nil {
		return IssuerMetadata{}, fmt.Errorf("%w: invalid issuer", ErrInvalidIssuerMetadata)
	}
	now := c.now()
	if c.cache != nil {
		if cached, ok := c.cache.GetIssuer(canonicalIssuer, now); ok {
			return cached, nil
		}
	}
	discoveryURL, err := issuerDiscoveryURL(canonicalIssuer)
	if err != nil {
		return IssuerMetadata{}, err
	}
	body, err := c.getBounded(ctx, discoveryURL)
	if err != nil {
		return IssuerMetadata{}, err
	}
	var metadata IssuerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return IssuerMetadata{}, fmt.Errorf("%w: discovery JSON is invalid", ErrInvalidIssuerMetadata)
	}
	metadata, err = c.normalizeMetadata(canonicalIssuer, metadata, now)
	if err != nil {
		return IssuerMetadata{}, err
	}
	if c.cache != nil {
		c.cache.StoreIssuer(metadata)
	}
	return metadata, nil
}

func (c *IssuerDiscoveryClient) FetchJWKS(ctx context.Context, metadata IssuerMetadata) (JWKS, error) {
	if c == nil {
		return JWKS{}, fmt.Errorf("%w: nil discovery client", ErrInvalidIssuerMetadata)
	}
	now := c.now()
	if c.cache != nil {
		if cached, ok := c.cache.GetJWKS(metadata.JWKSURI, now); ok {
			return cached, nil
		}
	}
	if _, err := canonicalIssuerURI(metadata.Issuer); err != nil {
		return JWKS{}, fmt.Errorf("%w: invalid issuer", ErrInvalidIssuerMetadata)
	}
	jwksURI, err := canonicalJWKSURI(metadata.JWKSURI)
	if err != nil {
		return JWKS{}, err
	}
	body, err := c.getBounded(ctx, jwksURI)
	if err != nil {
		return JWKS{}, err
	}
	var set JWKS
	if err := json.Unmarshal(body, &set); err != nil {
		return JWKS{}, fmt.Errorf("%w: jwks JSON is invalid", ErrInvalidIssuerMetadata)
	}
	if len(set.Keys) == 0 || len(set.Keys) > 32 {
		return JWKS{}, fmt.Errorf("%w: jwks key count is invalid", ErrInvalidIssuerMetadata)
	}
	set.FetchedAt = now
	set.ExpiresAt = now.Add(c.cacheTTL())
	if c.cache != nil {
		c.cache.StoreJWKS(jwksURI, set)
	}
	return copyJWKS(set), nil
}

func (c *IssuerDiscoveryClient) getBounded(ctx context.Context, target string) ([]byte, error) {
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultIssuerHTTPTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid request", ErrInvalidIssuerMetadata)
	}
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed", ErrInvalidIssuerMetadata)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status", ErrInvalidIssuerMetadata)
	}
	limit := c.MaxBodyBytes
	if limit <= 0 || limit > defaultIssuerMaxBodyBytes {
		limit = defaultIssuerMaxBodyBytes
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read failed", ErrInvalidIssuerMetadata)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: response too large", ErrInvalidIssuerMetadata)
	}
	return body, nil
}

func (c *IssuerDiscoveryClient) normalizeMetadata(expectedIssuer string, metadata IssuerMetadata, now time.Time) (IssuerMetadata, error) {
	issuer, err := canonicalIssuerURI(metadata.Issuer)
	if err != nil {
		return IssuerMetadata{}, fmt.Errorf("%w: metadata issuer is invalid", ErrInvalidIssuerMetadata)
	}
	if issuer != expectedIssuer {
		return IssuerMetadata{}, fmt.Errorf("%w: metadata issuer mismatch", ErrInvalidIssuerMetadata)
	}
	jwksURI, err := canonicalJWKSURI(metadata.JWKSURI)
	if err != nil {
		return IssuerMetadata{}, err
	}
	metadata.Issuer = issuer
	metadata.JWKSURI = jwksURI
	metadata.FetchedAt = now
	metadata.ExpiresAt = now.Add(c.cacheTTL())
	return metadata, nil
}

func (c *IssuerDiscoveryClient) cacheTTL() time.Duration {
	if c.CacheTTL <= 0 || c.CacheTTL > time.Hour {
		return defaultIssuerCacheTTL
	}
	return c.CacheTTL
}

func (c *IssuerDiscoveryClient) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func issuerDiscoveryURL(issuer string) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", fmt.Errorf("%w: invalid issuer", ErrInvalidIssuerMetadata)
	}
	parsed.Path = stringsTrimRightSlash(parsed.Path) + "/.well-known/openid-configuration"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func canonicalJWKSURI(value string) (string, error) {
	parsed, err := parseHTTPSIdentityURI(value, 2048)
	if err != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: invalid jwks uri", ErrInvalidIssuerMetadata)
	}
	parsed.RawQuery = ""
	return parsed.String(), nil
}

func stringsTrimRightSlash(value string) string {
	for len(value) > 1 && value[len(value)-1] == '/' {
		value = value[:len(value)-1]
	}
	if value == "" {
		return ""
	}
	return value
}

func (c *IssuerMetadataCache) GetIssuer(issuer string, now time.Time) (IssuerMetadata, bool) {
	if c == nil {
		return IssuerMetadata{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[issuer]
	if !ok || !now.Before(entry.ExpiresAt) {
		return IssuerMetadata{}, false
	}
	return entry, true
}

func (c *IssuerMetadataCache) StoreIssuer(metadata IssuerMetadata) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[metadata.Issuer] = metadata
}

func (c *IssuerMetadataCache) GetJWKS(uri string, now time.Time) (JWKS, bool) {
	if c == nil {
		return JWKS{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	set, ok := c.sets[uri]
	if !ok || !now.Before(set.ExpiresAt) {
		return JWKS{}, false
	}
	return copyJWKS(set), true
}

func (c *IssuerMetadataCache) StoreJWKS(uri string, set JWKS) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets[uri] = copyJWKS(set)
}

func copyJWKS(input JWKS) JWKS {
	out := input
	out.Keys = append([]json.RawMessage(nil), input.Keys...)
	for i := range out.Keys {
		out.Keys[i] = append(json.RawMessage(nil), out.Keys[i]...)
	}
	return out
}
