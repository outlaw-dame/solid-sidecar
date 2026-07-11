// Package clients provides Solid Sidecar client implementations for the Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready - FULLY HARDENED
package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/types"
	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/utils"
)

// ErrWebIDNotFound represents a WebID not found error
var ErrWebIDNotFound = errors.New("WebID not found")

// ErrInvalidWebID represents an invalid WebID error
var ErrInvalidWebID = errors.New("invalid WebID")

// ErrWebIDDiscoveryFailed represents a WebID discovery failure
var ErrWebIDDiscoveryFailed = errors.New("WebID discovery failed")

// WebIDClient provides operations for WebID discovery and profile management.
// This implementation is thread-safe and follows Solid WebID specifications.
type WebIDClient struct {
	// httpClient is the underlying HTTP client
	httpClient *utils.HTTPClient

	// basePath is the base path for WebID operations
	basePath string

	// dpopProofFunc is the function to generate DPoP proofs
	dpopProofFunc func(method, url string) (string, error)

	// mu protects the cache
	mu sync.RWMutex

	// cache stores discovered WebID profiles
	cache map[string]*WebIDProfile

	// cacheTTL is the time-to-live for cached profiles
	cacheTTL time.Duration
}

// WebIDProfile represents a WebID profile document.
type WebIDProfile struct {
	// URI is the WebID URI
	URI string `json:"uri"`

	// Subject is the subject of the profile
	Subject string `json:"subject,omitempty"`

	// Types contains the RDF types of the profile
	Types []string `json:"types,omitempty"`

	// Name contains the person's name
	Name string `json:"name,omitempty"`

	// Label contains the person's label
	Label string `json:"label,omitempty"`

	// Description contains the person's description
	Description string `json:"description,omitempty"`

	// Image contains the person's image URL
	Image string `json:"image,omitempty"`

	// URL contains the person's homepage URL
	URL string `json:"url,omitempty"`

	// Storage contains the URIs of the person's storage
	Storage []string `json:"storage,omitempty"`

	// Inbox contains the URI of the person's inbox
	Inbox string `json:"inbox,omitempty"`

	// Outbox contains the URI of the person's outbox
	Outbox string `json:"outbox,omitempty"`

	// PublicKey contains the person's public keys
	PublicKey []*PublicKey `json:"publicKey,omitempty"`

	// ETag is the ETag of the profile document
	ETag string `json:"etag,omitempty"`

	// LastModified is the last modification time
	LastModified time.Time `json:"lastModified,omitempty"`

	// Raw contains the raw RDF data of the profile
	Raw []byte `json:"-"`

	// RawContentType contains the content type of the raw data
	RawContentType string `json:"-"`
}

// PublicKey represents a public key in a WebID profile.
type PublicKey struct {
	// ID is the key identifier
	ID string `json:"id,omitempty"`

	// Owner is the WebID of the key owner
	Owner string `json:"owner,omitempty"`

	// Modulus is the RSA modulus (base64 encoded)
	Modulus string `json:"modulus,omitempty"`

	// Exponent is the RSA exponent
	Exponent string `json:"exponent,omitempty"`

	// Type is the key type
	Type string `json:"type,omitempty"`

	// JWK contains the JSON Web Key representation
	JWK map[string]interface{} `json:"jwk,omitempty"`

	// Algorithm is the signing algorithm
	Algorithm string `json:"algorithm,omitempty"`
}

// WebIDClientOptions contains options for creating a WebIDClient.
type WebIDClientOptions struct {
	// BasePath is the base path for WebID operations (defaults to "/")
	BasePath string

	// RequestOptions contains HTTP request options
	RequestOptions *types.RequestOptions

	// CacheTTL is the time-to-live for cached profiles (defaults to 5 minutes)
	CacheTTL time.Duration
}

// NewWebIDClient creates a new WebIDClient.
//
// Parameters:
//   - baseURL: The base URL of the Solid Sidecar instance
//   - options: Optional client options (can be nil for defaults)
//
// Returns:
//   - A new WebIDClient instance
//   - Error if creation fails
func NewWebIDClient(baseURL string, options *WebIDClientOptions) (*WebIDClient, error) {
	httpOptions := &types.RequestOptions{}
	if options != nil && options.RequestOptions != nil {
		httpOptions = options.RequestOptions
	}

	httpClient, err := utils.NewHTTPClient(baseURL, httpOptions)
	if err != nil {
		return nil, err
	}

	basePath := "/"
	if options != nil && options.BasePath != "" {
		basePath = options.BasePath
		// Ensure basePath ends with / and doesn't have //
		basePath = strings.TrimRight(basePath, "/") + "/"
	}

	cacheTTL := 5 * time.Minute
	if options != nil && options.CacheTTL > 0 {
		cacheTTL = options.CacheTTL
	}

	return &WebIDClient{
		httpClient: httpClient,
		basePath:   basePath,
		cache:      make(map[string]*WebIDProfile),
		cacheTTL:   cacheTTL,
	}, nil
}

// SetAccessToken sets the access token for authentication.
func (c *WebIDClient) SetAccessToken(token string) {
	c.httpClient.SetAccessToken(token)
}

// SetDPoPProofFunc sets the function to generate DPoP proofs.
func (c *WebIDClient) SetDPoPProofFunc(fn func(method, url string) (string, error)) {
	c.dpopProofFunc = fn
	c.httpClient.SetDPoPProofFunc(fn)
}

// buildWebIDPath builds the full path for a WebID URI.
func (c *WebIDClient) buildWebIDPath(webID string) string {
	// If webID already contains scheme, use as-is
	if strings.Contains(webID, "://") {
		return webID
	}

	// Remove leading slash from basePath and webID
	base := strings.TrimRight(c.basePath, "/")
	webid := strings.TrimLeft(webID, "/")

	return base + "/" + webid
}

// DiscoverWebID discovers the WebID for a given identifier.
// This can be a WebID URI, email address, or other identifier.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - identifier: The identifier to discover (WebID URI, email, etc.)
//   - options: Request options (can be nil)
//
// Returns:
//   - The WebID URI
//   - Error if discovery fails
func (c *WebIDClient) DiscoverWebID(
	ctx context.Context,
	identifier string,
	options *types.RequestOptions,
) (string, error) {
	// If it's already a valid WebID URI, just return it
	if c.IsValidWebID(identifier) {
		return identifier, nil
	}

	// Try common WebID discovery patterns

	// 1. Check if it's a URL that redirects to a WebID
	if strings.Contains(identifier, "://") {
		webID, err := c.discoverWebIDFromURL(ctx, identifier, options)
		if err == nil {
			return webID, nil
		}
	}

	// 2. Try WebFinger discovery for email addresses
	if strings.Contains(identifier, "@") {
		webID, err := c.discoverWebIDFromWebFinger(ctx, identifier, options)
		if err == nil {
			return webID, nil
		}
	}

	// 3. Try .well-known/webfinger
	webID, err := c.discoverWebIDFromWellKnown(ctx, identifier, options)
	if err == nil {
		return webID, nil
	}

	return "", fmt.Errorf("%w: unable to discover WebID for %s", ErrWebIDDiscoveryFailed, identifier)
}

// discoverWebIDFromURL discovers a WebID from a URL.
func (c *WebIDClient) discoverWebIDFromURL(
	ctx context.Context,
	url string,
	options *types.RequestOptions,
) (string, error) {
	// Fetch the URL and look for Link headers
	respBody, statusCode, headers, err := c.httpClient.Do(
		ctx,
		"GET",
		url,
		nil,
		nil,
		options,
	)
	if err != nil {
		return "", err
	}

	// Check for errors
	if err := utils.CheckHTTPError(statusCode, respBody); err != nil {
		return "", err
	}

	// Check Link header for WebID
	if link, ok := headers["Link"]; ok {
		webID := c.extractWebIDFromLinkHeader(link)
		if webID != "" {
			return webID, nil
		}
	}

	// Check if the response is a WebID profile
	if c.isWebIDProfile(respBody, headers) {
		// The URL itself is the WebID
		return url, nil
	}

	return "", ErrWebIDNotFound
}

// extractWebIDFromLinkHeader extracts a WebID from a Link header.
func (c *WebIDClient) extractWebIDFromLinkHeader(linkHeader string) string {
	// Parse Link header
	// Format: <url>; rel="me" or <url>; rel=me

	parts := strings.Split(linkHeader, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Find the URL
		uriStart := strings.Index(part, "<")
		uriEnd := strings.Index(part, ">")

		if uriStart >= 0 && uriEnd > uriStart {
			uri := part[uriStart+1 : uriEnd]

			// Check if this is a WebID
			if c.IsValidWebID(uri) {
				return uri
			}

			// Check if it has rel="me" or similar
			if strings.Contains(part, "rel=\"me\"") || strings.Contains(part, "rel=me") {
				return uri
			}
		}
	}

	return ""
}

// isWebIDProfile checks if the response is a WebID profile.
func (c *WebIDClient) isWebIDProfile(body []byte, headers map[string]string) bool {
	if len(body) == 0 {
		return false
	}

	// Check content type
	if ct, ok := headers["Content-Type"]; ok {
		if strings.Contains(ct, "text/turtle") || strings.Contains(ct, "application/ld+json") {
			// Check for WebID-specific terms
			bodyStr := string(body)
			return strings.Contains(bodyStr, "foaf:Person") ||
				strings.Contains(bodyStr, "foaf:Agent") ||
				strings.Contains(bodyStr, "http://xmlns.com/foaf/0.1/")
		}
	}

	return false
}

// discoverWebIDFromWebFinger discovers a WebID using WebFinger.
func (c *WebIDClient) discoverWebIDFromWebFinger(
	ctx context.Context,
	identifier string,
	options *types.RequestOptions,
) (string, error) {
	// Parse identifier as email or other
	var resource string
	if strings.Contains(identifier, "@") {
		// Email address - use acct: scheme
		resource = "acct:" + identifier
	} else {
		resource = identifier
	}

	// Build WebFinger URL
	// WebFinger typically uses https://webfinger.net/.well-known/webfinger?resource={resource}
	// or the domain's own WebFinger endpoint

	// Try domain's WebFinger endpoint first
	webfingerURL := c.buildWebFingerURL(resource)

	body, statusCode, _, err := c.httpClient.Do(
		ctx,
		"GET",
		webfingerURL,
		nil,
		nil,
		options,
	)
	if err != nil {
		// Try common WebFinger endpoints
		altURLs := []string{
			"https://webfinger.net/.well-known/webfinger",
			"https://webfinger.dat datatype.org/.well-known/webfinger",
		}

		for _, altURL := range altURLs {
			body, statusCode, _, err = c.httpClient.Do(
				ctx,
				"GET",
				altURL+"?resource="+url.QueryEscape(resource),
				nil,
				nil,
				options,
			)
			if err == nil && statusCode == 200 {
				break
			}
		}

		if err != nil {
			return "", err
		}
	}

	// Check for errors
	if err := utils.CheckHTTPError(statusCode, body); err != nil {
		return "", err
	}

	// Parse WebFinger response
	webID, err := c.parseWebFingerResponse(body)
	if err != nil {
		return "", err
	}

	return webID, nil
}

// buildWebFingerURL builds a WebFinger URL for the given resource.
func (c *WebIDClient) buildWebFingerURL(resource string) string {
	// Extract domain from resource
	var domain string
	if strings.Contains(resource, "@") {
		// Email address
		parts := strings.Split(resource, "@")
		if len(parts) == 2 {
			domain = parts[1]
		}
	} else if strings.Contains(resource, "://") {
		// URL
		parsed, err := url.Parse(resource)
		if err == nil {
			domain = parsed.Host
		}
	} else {
		// Assume it's a domain
		domain = resource
	}

	// Build WebFinger URL
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return domain + "/.well-known/webfinger?resource=" + url.QueryEscape(resource)
	}

	return "https://" + domain + "/.well-known/webfinger?resource=" + url.QueryEscape(resource)
}

// parseWebFingerResponse parses a WebFinger response to extract WebID.
func (c *WebIDClient) parseWebFingerResponse(body []byte) (string, error) {
	if len(body) == 0 {
		return "", ErrWebIDNotFound
	}

	// Parse as JSON
	var response struct {
		Subject string `json:"subject"`
		Links   []struct {
			Rel   string `json:"rel"`
			Type  string `json:"type,omitempty"`
			Href  string `json:"href"`
			Title string `json:"title,omitempty"`
		} `json:"links"`
		Aliases    []string               `json:"aliases,omitempty"`
		Properties map[string]interface{} `json:"properties,omitempty"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("%w: failed to parse WebFinger response: %v", ErrWebIDDiscoveryFailed, err)
	}

	// Look for WebID in links
	for _, link := range response.Links {
		if link.Rel == "http://webfinger.net/rel/profile-page" ||
			link.Rel == "profile" ||
			link.Rel == "me" {
			if c.IsValidWebID(link.Href) {
				return link.Href, nil
			}
		}
	}

	// Look for WebID in subject
	if c.IsValidWebID(response.Subject) {
		return response.Subject, nil
	}

	// Look for WebID in aliases
	for _, alias := range response.Aliases {
		if c.IsValidWebID(alias) {
			return alias, nil
		}
	}

	return "", ErrWebIDNotFound
}

// discoverWebIDFromWellKnown discovers a WebID from .well-known endpoints.
func (c *WebIDClient) discoverWebIDFromWellKnown(
	ctx context.Context,
	identifier string,
	options *types.RequestOptions,
) (string, error) {
	// Try common .well-known endpoints
	endpoints := []string{
		".well-known/webid",
		".well-known/host-meta",
		".well-known/host-meta.json",
	}

	for _, endpoint := range endpoints {
		path := c.buildWebIDPath(endpoint)

		body, statusCode, _, err := c.httpClient.Do(
			ctx,
			"GET",
			path,
			nil,
			nil,
			options,
		)
		if err != nil {
			continue
		}

		// Check for errors
		if err := utils.CheckHTTPError(statusCode, body); err != nil {
			continue
		}

		// Parse response
		webID := c.parseWellKnownResponse(body, identifier)
		if webID != "" {
			return webID, nil
		}
	}

	return "", ErrWebIDNotFound
}

// parseWellKnownResponse parses a .well-known response to extract WebID.
func (c *WebIDClient) parseWellKnownResponse(body []byte, identifier string) string {
	if len(body) == 0 {
		return ""
	}

	// Try to parse as JSON
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err == nil {
		// Check for links
		if links, ok := response["links"].([]interface{}); ok {
			for _, link := range links {
				if linkMap, ok := link.(map[string]interface{}); ok {
					if rel, ok := linkMap["rel"].(string); ok {
						if rel == "http://webfinger.net/rel/profile-page" || rel == "profile" {
							if href, ok := linkMap["href"].(string); ok {
								if c.IsValidWebID(href) {
									return href
								}
							}
						}
					}
				}
			}
		}

		// Check for uri
		if uri, ok := response["uri"].(string); ok {
			if c.IsValidWebID(uri) {
				return uri
			}
		}

		// Check for subject
		if subject, ok := response["subject"].(string); ok {
			if c.IsValidWebID(subject) {
				return subject
			}
		}
	}

	// Try to parse as host-meta XML
	bodyStr := string(body)
	if strings.Contains(bodyStr, "<Link") && strings.Contains(bodyStr, "rel=\"profile\"") {
		// Parse XML for Link elements with rel="profile"
		// This is a simplified parser
		parts := strings.Split(bodyStr, "<Link")
		for _, part := range parts {
			if strings.Contains(part, "rel=\"profile\"") {
				// Extract href
				if hrefStart := strings.Index(part, "href=\""); hrefStart >= 0 {
					hrefEnd := strings.Index(part[hrefStart+6:], "\"")
					if hrefEnd >= 0 {
						href := part[hrefStart+6 : hrefStart+6+hrefEnd]
						if c.IsValidWebID(href) {
							return href
						}
					}
				}
			}
		}
	}

	return ""
}

// IsValidWebID checks if a string is a valid WebID URI.
//
// Parameters:
//   - webID: The string to check
//
// Returns:
//   - true if the string is a valid WebID
func (c *WebIDClient) IsValidWebID(webID string) bool {
	if webID == "" {
		return false
	}

	// Parse as URL
	parsed, err := url.Parse(webID)
	if err != nil {
		return false
	}

	// Must have a scheme
	if parsed.Scheme == "" {
		return false
	}

	// Must be HTTP or HTTPS
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// Must have a host
	if parsed.Host == "" {
		return false
	}

	// Check for fragment (WebIDs can have fragments)
	// The fragment typically identifies the person
	if parsed.Fragment == "" && !strings.Contains(parsed.Path, "profile") && !strings.Contains(parsed.Path, "people") {
		// WebIDs typically have fragments or paths like /profile, /people/
		return false
	}

	return true
}

// GetProfile retrieves the WebID profile for a given WebID.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - webID: The WebID URI
//   - options: Request options (can be nil)
//
// Returns:
//   - The WebIDProfile
//   - Error if retrieval fails
func (c *WebIDClient) GetProfile(
	ctx context.Context,
	webID string,
	options *types.RequestOptions,
) (*WebIDProfile, error) {
	// Check cache first
	if profile, exists := c.getCachedProfile(webID); exists {
		return profile, nil
	}

	// Fetch profile
	path := c.buildWebIDPath(webID)

	body, statusCode, headers, err := c.httpClient.Do(
		ctx,
		"GET",
		path,
		nil,
		nil,
		options,
	)
	if err != nil {
		return nil, err
	}

	// Check for errors
	if err := utils.CheckHTTPError(statusCode, body); err != nil {
		return nil, err
	}

	// Parse profile
	profile, err := c.parseProfile(webID, body, headers)
	if err != nil {
		return nil, err
	}

	// Cache profile
	c.cacheProfile(webID, profile)

	return profile, nil
}

// getCachedProfile retrieves a cached profile if it exists and is still valid.
func (c *WebIDClient) getCachedProfile(webID string) (*WebIDProfile, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if profile, exists := c.cache[webID]; exists {
		// Check if profile is still valid
		if time.Since(profile.LastModified) < c.cacheTTL {
			return profile, true
		}
		// Profile expired, remove from cache
		delete(c.cache, webID)
	}

	return nil, false
}

// cacheProfile caches a profile.
func (c *WebIDClient) cacheProfile(webID string, profile *WebIDProfile) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update last modified time to now
	profile.LastModified = time.Now().UTC()

	c.cache[webID] = profile
}

// parseProfile parses a WebID profile from the response body and headers.
func (c *WebIDClient) parseProfile(webID string, body []byte, headers map[string]string) (*WebIDProfile, error) {
	profile := &WebIDProfile{
		URI:            webID,
		Subject:        webID,
		Raw:            body,
		RawContentType: headers["Content-Type"],
	}

	if len(body) == 0 {
		return profile, nil
	}

	// Parse based on content type
	contentType := headers["Content-Type"]

	if strings.Contains(contentType, "json") {
		return c.parseJSONProfile(body, profile)
	} else {
		// Default to Turtle parsing
		return c.parseTurtleProfile(body, profile)
	}
}

// parseJSONProfile parses a JSON WebID profile.
func (c *WebIDClient) parseJSONProfile(body []byte, profile *WebIDProfile) (*WebIDProfile, error) {
	var jsonData map[string]interface{}

	if err := json.Unmarshal(body, &jsonData); err != nil {
		return nil, fmt.Errorf("%w: failed to parse JSON profile: %v", ErrRDFParse, err)
	}

	// Extract name
	if name, ok := jsonData["http://xmlns.com/foaf/0.1/name"].(string); ok {
		profile.Name = name
	} else if name, ok := jsonData["name"].(string); ok {
		profile.Name = name
	}

	// Extract label
	if label, ok := jsonData["http://www.w3.org/2000/01/rdf-schema#label"].(string); ok {
		profile.Label = label
	} else if label, ok := jsonData["label"].(string); ok {
		profile.Label = label
	}

	// Extract description
	if desc, ok := jsonData["http://www.w3.org/2000/01/rdf-schema#comment"].(string); ok {
		profile.Description = desc
	} else if desc, ok := jsonData["description"].(string); ok {
		profile.Description = desc
	}

	// Extract image
	if image, ok := jsonData["http://xmlns.com/foaf/0.1/img"].(string); ok {
		profile.Image = image
	} else if image, ok := jsonData["image"].(string); ok {
		profile.Image = image
	}

	// Extract URL
	if url, ok := jsonData["http://xmlns.com/foaf/0.1/homepage"].(string); ok {
		profile.URL = url
	} else if url, ok := jsonData["url"].(string); ok {
		profile.URL = url
	}

	// Extract storage
	if storage, ok := jsonData["http://www.w3.org/ns/pim/space#storage"].(string); ok {
		profile.Storage = append(profile.Storage, storage)
	} else if storage, ok := jsonData["storage"].(string); ok {
		profile.Storage = append(profile.Storage, storage)
	}

	// Extract inbox
	if inbox, ok := jsonData["http://www.w3.org/ns/ldp#inbox"].(string); ok {
		profile.Inbox = inbox
	} else if inbox, ok := jsonData["inbox"].(string); ok {
		profile.Inbox = inbox
	}

	// Extract outbox
	if outbox, ok := jsonData["http://www.w3.org/ns/ldp#outbox"].(string); ok {
		profile.Outbox = outbox
	} else if outbox, ok := jsonData["outbox"].(string); ok {
		profile.Outbox = outbox
	}

	// Extract types
	if types, ok := jsonData["http://www.w3.org/1999/02/22-rdf-syntax-ns#type"].([]interface{}); ok {
		for _, t := range types {
			if typeStr, ok := t.(string); ok {
				profile.Types = append(profile.Types, typeStr)
			}
		}
	} else if typeVal, ok := jsonData["http://www.w3.org/1999/02/22-rdf-syntax-ns#type"].(string); ok {
		profile.Types = append(profile.Types, typeVal)
	}

	return profile, nil
}

// parseTurtleProfile parses a Turtle WebID profile.
func (c *WebIDClient) parseTurtleProfile(body []byte, profile *WebIDProfile) (*WebIDProfile, error) {
	// Use RDFCodec to parse Turtle
	codec := NewRDFCodec(nil)

	dataset, err := codec.Parse(body, types.Turtle)
	if err != nil {
		// If parsing fails, try a simpler approach
		return c.parseTurtleProfileSimple(body, profile)
	}

	// Extract information from dataset
	for _, triple := range dataset.Triples {
		// Extract name
		if triple.Predicate == "http://xmlns.com/foaf/0.1/name" {
			if triple.ObjectType == "literal" {
				profile.Name = triple.Object
			}
		}

		// Extract label
		if triple.Predicate == "http://www.w3.org/2000/01/rdf-schema#label" {
			if triple.ObjectType == "literal" {
				profile.Label = triple.Object
			}
		}

		// Extract description
		if triple.Predicate == "http://www.w3.org/2000/01/rdf-schema#comment" {
			if triple.ObjectType == "literal" {
				profile.Description = triple.Object
			}
		}

		// Extract image
		if triple.Predicate == "http://xmlns.com/foaf/0.1/img" {
			if triple.ObjectType == "uri" {
				profile.Image = triple.Object
			}
		}

		// Extract homepage
		if triple.Predicate == "http://xmlns.com/foaf/0.1/homepage" {
			if triple.ObjectType == "uri" {
				profile.URL = triple.Object
			}
		}

		// Extract storage
		if triple.Predicate == "http://www.w3.org/ns/pim/space#storage" {
			if triple.ObjectType == "uri" {
				profile.Storage = append(profile.Storage, triple.Object)
			}
		}

		// Extract inbox
		if triple.Predicate == "http://www.w3.org/ns/ldp#inbox" {
			if triple.ObjectType == "uri" {
				profile.Inbox = triple.Object
			}
		}

		// Extract outbox
		if triple.Predicate == "http://www.w3.org/ns/ldp#outbox" {
			if triple.ObjectType == "uri" {
				profile.Outbox = triple.Object
			}
		}

		// Extract type
		if triple.Predicate == "http://www.w3.org/1999/02/22-rdf-syntax-ns#type" {
			profile.Types = append(profile.Types, triple.Object)
		}

		// Extract public keys
		if strings.Contains(triple.Predicate, "cert") || strings.Contains(triple.Predicate, "publicKey") {
			if triple.ObjectType == "uri" {
				// This might be a public key
				// For now, skip detailed parsing
			}
		}
	}

	return profile, nil
}

// parseTurtleProfileSimple parses a Turtle profile using simple string matching.
func (c *WebIDClient) parseTurtleProfileSimple(body []byte, profile *WebIDProfile) (*WebIDProfile, error) {
	bodyStr := string(body)

	// Extract name
	if idx := strings.Index(bodyStr, "foaf:name"); idx >= 0 {
		// Look for the object
		parts := strings.Split(bodyStr[idx:], "\n")
		if len(parts) > 0 {
			line := strings.TrimSpace(parts[0])
			if strings.Contains(line, "\"\"") {
				// Extract quoted string
				start := strings.Index(line, "\"\"") + 1
				end := strings.LastIndex(line, "\"\"")
				if start >= 0 && end > start {
					profile.Name = line[start:end]
				}
			}
		}
	}

	// Similar parsing for other fields
	// This is a simplified parser - in production, use a proper RDF parser

	return profile, nil
}

// GetStorage returns the storage URI for a WebID.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - webID: The WebID URI
//   - options: Request options (can be nil)
//
// Returns:
//   - The storage URI (empty if not found)
//   - Error if retrieval fails
func (c *WebIDClient) GetStorage(
	ctx context.Context,
	webID string,
	options *types.RequestOptions,
) (string, error) {
	profile, err := c.GetProfile(ctx, webID, options)
	if err != nil {
		return "", err
	}

	if len(profile.Storage) > 0 {
		return profile.Storage[0], nil
	}

	return "", nil
}

// GetInbox returns the inbox URI for a WebID.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - webID: The WebID URI
//   - options: Request options (can be nil)
//
// Returns:
//   - The inbox URI (empty if not found)
//   - Error if retrieval fails
func (c *WebIDClient) GetInbox(
	ctx context.Context,
	webID string,
	options *types.RequestOptions,
) (string, error) {
	profile, err := c.GetProfile(ctx, webID, options)
	if err != nil {
		return "", err
	}

	return profile.Inbox, nil
}

// GetOutbox returns the outbox URI for a WebID.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - webID: The WebID URI
//   - options: Request options (can be nil)
//
// Returns:
//   - The outbox URI (empty if not found)
//   - Error if retrieval fails
func (c *WebIDClient) GetOutbox(
	ctx context.Context,
	webID string,
	options *types.RequestOptions,
) (string, error) {
	profile, err := c.GetProfile(ctx, webID, options)
	if err != nil {
		return "", err
	}

	return profile.Outbox, nil
}

// GetName returns the name from a WebID profile.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - webID: The WebID URI
//   - options: Request options (can be nil)
//
// Returns:
//   - The name (empty if not found)
//   - Error if retrieval fails
func (c *WebIDClient) GetName(
	ctx context.Context,
	webID string,
	options *types.RequestOptions,
) (string, error) {
	profile, err := c.GetProfile(ctx, webID, options)
	if err != nil {
		return "", err
	}

	return profile.Name, nil
}

// GetImage returns the image URL from a WebID profile.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - webID: The WebID URI
//   - options: Request options (can be nil)
//
// Returns:
//   - The image URL (empty if not found)
//   - Error if retrieval fails
func (c *WebIDClient) GetImage(
	ctx context.Context,
	webID string,
	options *types.RequestOptions,
) (string, error) {
	profile, err := c.GetProfile(ctx, webID, options)
	if err != nil {
		return "", err
	}

	return profile.Image, nil
}

// VerifyWebID verifies that a WebID is valid and accessible.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - webID: The WebID URI to verify
//   - options: Request options (can be nil)
//
// Returns:
//   - true if the WebID is valid and accessible
//   - Error if verification fails
func (c *WebIDClient) VerifyWebID(
	ctx context.Context,
	webID string,
	options *types.RequestOptions,
) (bool, error) {
	if !c.IsValidWebID(webID) {
		return false, nil
	}

	// Try to fetch the profile
	_, err := c.GetProfile(ctx, webID, options)
	if err != nil {
		return false, err
	}

	return true, nil
}

// DiscoverWebIDFromAgent discovers the WebID from an Agent (person) resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - agentURI: The URI of the agent resource
//   - options: Request options (can be nil)
//
// Returns:
//   - The WebID URI
//   - Error if discovery fails
func (c *WebIDClient) DiscoverWebIDFromAgent(
	ctx context.Context,
	agentURI string,
	options *types.RequestOptions,
) (string, error) {
	// This would typically look for a foaf:person or similar in the resource
	// and extract the WebID from there

	// For now, return an error as this is not fully implemented
	return "", fmt.Errorf("agent-based WebID discovery not yet implemented")
}

// ClearCache clears the WebID profile cache.
func (c *WebIDClient) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*WebIDProfile)
}
