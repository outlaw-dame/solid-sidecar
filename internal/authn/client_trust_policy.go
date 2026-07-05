package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrClientNotTrusted is returned when a client identifier is not trusted
var ErrClientNotTrusted = errors.New("client identifier not trusted")

// ErrClientRegistrationRequired is returned when client registration is required
var ErrClientRegistrationRequired = errors.New("client registration required")

// ClientTrustPolicy defines trust and registration policies for client identifiers
type ClientTrustPolicy struct {
	mu sync.RWMutex

	// trustedClients is a set of pre-trusted client identifiers
	trustedClients map[string]*ClientRegistration

	// allowedClientPatterns is a list of URL patterns that are allowed without explicit registration
	allowedClientPatterns []string

	// requireRegistration enforces that all clients must be explicitly registered
	requireRegistration bool

	// allowPublicClients allows public clients (without client secret) to be used
	allowPublicClients bool

	// clientTimeout is the timeout for client metadata fetching
	clientTimeout time.Duration

	// logger is used for policy operations logging
	logger *slog.Logger

	// httpClient is used for fetching client metadata
	httpClient *http.Client
}

// ClientRegistration holds registration information for a client
type ClientRegistration struct {
	// ClientID is the client identifier
	ClientID string

	// ClientName is the human-readable name
	ClientName string

	// RedirectURIs are the allowed redirect URIs
	RedirectURIs []string

	// GrantTypes are the allowed grant types
	GrantTypes []string

	// ResponseTypes are the allowed response types
	ResponseTypes []string

	// Scopes are the allowed scopes
	Scopes []string

	// PublicClient indicates if this is a public client (no secret)
	PublicClient bool

	// Trusted indicates if this client is trusted
	Trusted bool

	// RegisteredAt is when the client was registered
	RegisteredAt time.Time

	// ExpiresAt is when the registration expires (optional)
	ExpiresAt *time.Time

	// Metadata contains additional client metadata
	Metadata map[string]string
}

// ClientTrustPolicyOptions configures the client trust policy
type ClientTrustPolicyOptions struct {
	// RequireRegistration enforces explicit client registration
	RequireRegistration bool

	// AllowPublicClients allows public clients
	AllowPublicClients bool

	// ClientTimeout is the timeout for client operations
	ClientTimeout time.Duration

	// Logger is the logger to use
	Logger *slog.Logger

	// HTTPClient is the HTTP client to use for fetching metadata
	HTTPClient *http.Client
}

// DefaultClientTrustPolicyOptions returns safe default options
func DefaultClientTrustPolicyOptions() ClientTrustPolicyOptions {
	return ClientTrustPolicyOptions{
		RequireRegistration: false,
		AllowPublicClients:  true,
		ClientTimeout:       10 * time.Second,
		Logger:              nil,
		HTTPClient:          nil,
	}
}

// NewClientTrustPolicy creates a new client trust policy
func NewClientTrustPolicy(options ClientTrustPolicyOptions) *ClientTrustPolicy {
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{Timeout: options.ClientTimeout}
	}

	return &ClientTrustPolicy{
		trustedClients:        make(map[string]*ClientRegistration),
		allowedClientPatterns: []string{"https://solidproject.org/", "https://inrupt.com/"},
		requireRegistration:   options.RequireRegistration,
		allowPublicClients:    options.AllowPublicClients,
		clientTimeout:         options.ClientTimeout,
		logger:                options.Logger,
		httpClient:            options.HTTPClient,
	}
}

// RegisterClient registers a new client
func (p *ClientTrustPolicy) RegisterClient(registration *ClientRegistration) error {
	if registration == nil {
		return errors.New("registration cannot be nil")
	}
	if registration.ClientID == "" {
		return errors.New("client ID is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Normalize client ID
	clientID := p.normalizeClientID(registration.ClientID)

	// Set registration timestamp
	now := time.Now()
	registration.RegisteredAt = now

	// Set default values
	if registration.GrantTypes == nil {
		registration.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if registration.ResponseTypes == nil {
		registration.ResponseTypes = []string{"code"}
	}

	p.trustedClients[clientID] = registration
	p.logger.Info("Client registered", "client_id", clientID, "name", registration.ClientName)

	return nil
}

// UnregisterClient removes a client registration
func (p *ClientTrustPolicy) UnregisterClient(clientID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	clientID = p.normalizeClientID(clientID)

	if _, exists := p.trustedClients[clientID]; !exists {
		return fmt.Errorf("client %s not found", clientID)
	}

	delete(p.trustedClients, clientID)
	p.logger.Info("Client unregistered", "client_id", clientID)

	return nil
}

// GetClient returns the registration for a client
func (p *ClientTrustPolicy) GetClient(clientID string) (*ClientRegistration, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	clientID = p.normalizeClientID(clientID)
	registration, exists := p.trustedClients[clientID]

	return registration, exists
}

// IsClientTrusted checks if a client identifier is trusted
func (p *ClientTrustPolicy) IsClientTrusted(clientID string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	clientID = p.normalizeClientID(clientID)

	// Check if explicitly registered
	if _, exists := p.trustedClients[clientID]; exists {
		return true
	}

	// Check if matches an allowed pattern
	if p.matchesAllowedPattern(clientID) {
		return true
	}

	// If registration is required, return false
	if p.requireRegistration {
		return false
	}

	// Default: allow if it's a valid HTTPS URL
	return p.isValidHTTPSClientID(clientID)
}

// VerifyClientInToken verifies the client identifier in a token
func (p *ClientTrustPolicy) VerifyClientInToken(ctx context.Context, token IdentityClaims) error {
	if token.ClientID == "" {
		// No client ID in token - may be acceptable depending on flow
		p.logger.Debug("Token has no client_id claim")
		return nil
	}

	// Check if client is trusted
	if !p.IsClientTrusted(token.ClientID) {
		if p.requireRegistration {
			p.logger.Warn("Client verification failed: client not registered", "client_id", token.ClientID)
			return fmt.Errorf("%w: %s", ErrClientRegistrationRequired, token.ClientID)
		}

		p.logger.Warn("Client verification failed: client not trusted", "client_id", token.ClientID)
		return fmt.Errorf("%w: %s", ErrClientNotTrusted, token.ClientID)
	}

	// Additional verification: check client metadata if available
	if err := p.verifyClientMetadata(ctx, token.ClientID, token.Issuer); err != nil {
		p.logger.Warn("Client metadata verification failed", "client_id", token.ClientID, "error", err)
		return fmt.Errorf("client metadata verification failed: %w", err)
	}

	return nil
}

// verifyClientMetadata verifies client metadata from the issuer
func (p *ClientTrustPolicy) verifyClientMetadata(ctx context.Context, clientID, issuer string) error {
	// If we have explicit registration, skip metadata verification
	if _, exists := p.GetClient(clientID); exists {
		return nil
	}

	// Parse client ID
	clientURL, err := url.Parse(clientID)
	if err != nil {
		return fmt.Errorf("invalid client ID: %w", err)
	}

	// Must be HTTPS
	if clientURL.Scheme != "https" {
		return fmt.Errorf("client ID must use HTTPS")
	}

	// For now, we trust any valid HTTPS client ID
	// In production, this would fetch and verify client metadata from the issuer
	p.logger.Debug("Client metadata verification skipped (not implemented)", "client_id", clientID)

	return nil
}

// AddAllowedPattern adds a client ID pattern to the allowed list
func (p *ClientTrustPolicy) AddAllowedPattern(pattern string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.allowedClientPatterns = append(p.allowedClientPatterns, pattern)
	p.logger.Info("Client pattern added", "pattern", pattern)
}

// RemoveAllowedPattern removes a client ID pattern from the allowed list
func (p *ClientTrustPolicy) RemoveAllowedPattern(pattern string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, pat := range p.allowedClientPatterns {
		if pat == pattern {
			p.allowedClientPatterns = append(p.allowedClientPatterns[:i], p.allowedClientPatterns[i+1:]...)
			p.logger.Info("Client pattern removed", "pattern", pattern)
			return
		}
	}
}

// SetRequireRegistration sets whether client registration is required
func (p *ClientTrustPolicy) SetRequireRegistration(require bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.requireRegistration = require
	p.logger.Info("Client registration requirement updated", "require", require)
}

// SetAllowPublicClients sets whether public clients are allowed
func (p *ClientTrustPolicy) SetAllowPublicClients(allow bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.allowPublicClients = allow
	p.logger.Info("Public clients allowance updated", "allow", allow)
}

// normalizeClientID normalizes a client identifier
func (p *ClientTrustPolicy) normalizeClientID(clientID string) string {
	// Remove trailing slashes
	clientID = strings.TrimSuffix(clientID, "/")
	// Convert to lowercase for comparison
	return strings.ToLower(clientID)
}

// matchesAllowedPattern checks if a client ID matches any allowed pattern
func (p *ClientTrustPolicy) matchesAllowedPattern(clientID string) bool {
	clientURL, err := url.Parse(clientID)
	if err != nil {
		return false
	}

	for _, pattern := range p.allowedClientPatterns {
		// Simple prefix matching for now
		// In production, this would support more complex patterns
		if strings.HasPrefix(clientID, pattern) {
			return true
		}

		// Also check if host matches
		patternURL, err := url.Parse(pattern)
		if err == nil && patternURL.Host != "" && clientURL.Host == patternURL.Host {
			return true
		}
	}

	return false
}

// isValidHTTPSClientID checks if a client ID is a valid HTTPS URL
func (p *ClientTrustPolicy) isValidHTTPSClientID(clientID string) bool {
	clientURL, err := url.Parse(clientID)
	if err != nil {
		return false
	}

	return clientURL.Scheme == "https" && clientURL.Host != ""
}

// ListClients returns a list of all registered client IDs
func (p *ClientTrustPolicy) ListClients() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	clients := make([]string, 0, len(p.trustedClients))
	for clientID := range p.trustedClients {
		clients = append(clients, clientID)
	}

	return clients
}

// ClientTrustResult contains the result of client trust verification
type ClientTrustResult struct {
	// ClientID is the client identifier
	ClientID string

	// IsTrusted indicates if the client is trusted
	IsTrusted bool

	// IsRegistered indicates if the client is explicitly registered
	IsRegistered bool

	// MatchesPattern indicates if the client matches an allowed pattern
	MatchesPattern bool

	// Reason contains the reason for the trust decision
	Reason string
}

// CheckClientTrust performs a comprehensive client trust check
func (p *ClientTrustPolicy) CheckClientTrust(clientID string) ClientTrustResult {
	result := ClientTrustResult{
		ClientID: clientID,
	}

	clientID = p.normalizeClientID(clientID)

	// Check if explicitly registered
	if _, exists := p.GetClient(clientID); exists {
		result.IsTrusted = true
		result.IsRegistered = true
		result.Reason = "client explicitly registered"
		return result
	}

	// Check if matches allowed pattern
	if p.matchesAllowedPattern(clientID) {
		result.IsTrusted = true
		result.MatchesPattern = true
		result.Reason = "client matches allowed pattern"
		return result
	}

	// If registration is required, not trusted
	if p.requireRegistration {
		result.IsTrusted = false
		result.Reason = "client registration required"
		return result
	}

	// Default: trust valid HTTPS client IDs
	if p.isValidHTTPSClientID(clientID) {
		result.IsTrusted = true
		result.Reason = "valid HTTPS client ID"
		return result
	}

	result.IsTrusted = false
	result.Reason = "invalid client ID format"
	return result
}

// ClientMetadata contains metadata about a Solid OIDC client
type ClientMetadata struct {
	// ClientID is the client identifier
	ClientID string `json:"client_id"`

	// ClientName is the human-readable name
	ClientName string `json:"client_name,omitempty"`

	// RedirectURIs are the allowed redirect URIs
	RedirectURIs []string `json:"redirect_uris,omitempty"`

	// GrantTypes are the allowed grant types
	GrantTypes []string `json:"grant_types,omitempty"`

	// ResponseTypes are the allowed response types
	ResponseTypes []string `json:"response_types,omitempty"`

	// Scopes are the allowed scopes
	Scopes []string `json:"scopes,omitempty"`

	// PublicClient indicates if this is a public client
	PublicClient bool `json:"public_client,omitempty"`

	// Trusted indicates if this client is trusted
	Trusted bool `json:"trusted,omitempty"`
}

// FetchClientMetadata fetches client metadata from the issuer
func (p *ClientTrustPolicy) FetchClientMetadata(ctx context.Context, clientID, issuer string) (*ClientMetadata, error) {
	// Parse client ID
	clientURL, err := url.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client ID: %w", err)
	}

	// Construct the client metadata URL
	// Solid OIDC uses the client_id as the URL
	metadataURL := clientID

	// If client_id ends with a path, append .well-known/solid-oidc-client
	if !strings.HasSuffix(clientID, "/") && strings.Contains(clientID, "/") {
		metadataURL += "/.well-known/solid-oidc-client"
	} else if !strings.Contains(clientID, "/") {
		// If it's just a host, use https://host/.well-known/solid-oidc-client
		metadataURL = fmt.Sprintf("https://%s/.well-known/solid-oidc-client", clientURL.Host)
	} else {
		// If it's a path, append .well-known/solid-oidc-client
		metadataURL = fmt.Sprintf("%s/.well-known/solid-oidc-client", clientID)
	}

	// Try to fetch metadata
	metadata, err := p.fetchMetadata(ctx, metadataURL)
	if err != nil {
		// Metadata fetch failed - may be acceptable
		p.logger.Debug("Failed to fetch client metadata", "url", metadataURL, "error", err)
		return nil, nil
	}

	return metadata, nil
}

// fetchMetadata fetches client metadata from a URL
func (p *ClientTrustPolicy) fetchMetadata(ctx context.Context, url string) (*ClientMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "solid-sidecar/1.0")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var metadata ClientMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

// SolidOIDCClientRegistry is an interface for client registration with Solid OIDC issuers
type SolidOIDCClientRegistry interface {
	// RegisterClient registers a client with a Solid OIDC issuer
	RegisterClient(ctx context.Context, issuer string, clientID string, redirectURI string) error

	// GetClientInfo retrieves client information from the issuer
	GetClientInfo(ctx context.Context, issuer string, clientID string) (*ClientRegistration, error)

	// VerifyClient verifies a client's registration with an issuer
	VerifyClient(ctx context.Context, issuer string, clientID string) error
}
