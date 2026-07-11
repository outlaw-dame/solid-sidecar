// Package auth provides authentication utilities for the Solid Sidecar Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready
package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/types"
)

// ErrAuthenticationFailed represents an authentication failure
var ErrAuthenticationFailed = errors.New("authentication failed")

// ErrTokenExpired represents an expired token
var ErrTokenExpired = errors.New("token expired")

// ErrNoToken represents missing token
var ErrNoToken = errors.New("no token available")

// ErrInvalidIssuer represents an invalid issuer
var ErrInvalidIssuer = errors.New("invalid issuer")

// AuthManager provides OAuth2/DPoP authentication management.
type AuthManager struct {
	mu sync.RWMutex

	// tokenManager manages access tokens
	tokenManager *TokenManager

	// keyStore manages DPoP keys
	keyStore *DPoPKeyStore

	// httpClient is the underlying HTTP client for token exchange
	httpClient *http.Client

	// issuer is the OAuth2 issuer URL
	issuer string

	// clientID is the OAuth2 client ID
	clientID string

	// clientSecret is the OAuth2 client secret (optional for confidential clients)
	clientSecret string

	// redirectURI is the OAuth2 redirect URI
	redirectURI string

	// scope is the requested scope
	scope string

	// currentKeyID is the current DPoP key ID
	currentKeyID string

	// autoRefresh indicates if tokens should be auto-refreshed
	autoRefresh bool

	// onTokenRefresh is called when a token is refreshed
	onTokenRefresh func(token string)
}

// AuthManagerOptions contains options for creating an AuthManager.
type AuthManagerOptions struct {
	// Issuer is the OAuth2 issuer URL
	Issuer string

	// ClientID is the OAuth2 client ID
	ClientID string

	// ClientSecret is the OAuth2 client secret
	ClientSecret string

	// RedirectURI is the OAuth2 redirect URI
	RedirectURI string

	// Scope is the requested scope
	Scope string

	// KeyStore is an existing DPoP key store (optional)
	KeyStore *DPoPKeyStore

	// TokenManager is an existing token manager (optional)
	TokenManager *TokenManager

	// HTTPClient is an existing HTTP client (optional)
	HTTPClient *http.Client

	// AutoRefresh indicates if tokens should be auto-refreshed
	AutoRefresh bool
}

// NewAuthManager creates a new AuthManager.
//
// Parameters:
//   - options: AuthManager options
//
// Returns:
//   - A new AuthManager instance
//   - Error if options are invalid
func NewAuthManager(options *AuthManagerOptions) (*AuthManager, error) {
	if options == nil {
		options = &AuthManagerOptions{}
	}

	// Validate issuer
	if options.Issuer == "" {
		return nil, ErrInvalidIssuer
	}

	// Parse issuer URL
	parsedIssuer, err := url.Parse(options.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid issuer URL: %v", ErrInvalidIssuer, err)
	}

	if parsedIssuer.Scheme == "" {
		parsedIssuer.Scheme = "https"
	}

	// Create HTTP client if not provided
	httpClient := options.HTTPClient
	if httpClient == nil {
		transport := &http.Transport{
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
		}

		// Allow insecure for localhost
		if strings.Contains(parsedIssuer.Host, "localhost") || strings.Contains(parsedIssuer.Host, "127.0.0.1") {
			transport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		} else {
			transport.TLSClientConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}

		httpClient = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
	}

	// Create key store if not provided
	keyStore := options.KeyStore
	if keyStore == nil {
		keyStore = NewDPoPKeyStore(&DPoPKeyStoreOptions{
			Algorithm: RS256,
			KeySize:   2048,
		})
	}

	// Create token manager if not provided
	tokenManager := options.TokenManager
	if tokenManager == nil {
		tokenManager = NewTokenManager()
	}

	return &AuthManager{
		tokenManager: tokenManager,
		keyStore:     keyStore,
		httpClient:   httpClient,
		issuer:       parsedIssuer.String(),
		clientID:     options.ClientID,
		clientSecret: options.ClientSecret,
		redirectURI:  options.RedirectURI,
		scope:        options.Scope,
		autoRefresh:  options.AutoRefresh,
	}, nil
}

// SetToken sets the access token directly.
//
// Parameters:
//   - token: The access token
//   - expiresIn: The lifetime in seconds
func (am *AuthManager) SetToken(token string, expiresIn int64) {
	am.tokenManager.SetToken(&types.TokenResponse{
		AccessToken: token,
		TokenType:   "DPoP",
		ExpiresIn:   expiresIn,
		IssuedAt:    time.Now().UTC(),
	}, expiresIn)
}

// GetAccessToken returns the current access token.
// If auto-refresh is enabled and the token is expired, it will attempt to refresh.
//
// Returns:
//   - The access token
//   - Error if no token or refresh fails
func (am *AuthManager) GetAccessToken() (string, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Check if token exists and is valid
	if token := am.tokenManager.GetAccessToken(); token != "" {
		if !am.tokenManager.IsExpired() {
			return token, nil
		}

		// Token is expired - try to refresh if auto-refresh is enabled
		if am.autoRefresh && am.clientSecret != "" {
			if err := am.refreshToken(); err == nil {
				return am.tokenManager.GetAccessToken(), nil
			}
		}
	}

	return "", ErrNoToken
}

// GetDPoPKeyStore returns the DPoP key store.
func (am *AuthManager) GetDPoPKeyStore() *DPoPKeyStore {
	return am.keyStore
}

// GenerateDPoPProof generates a DPoP proof for the given method and URL.
//
// Parameters:
//   - method: The HTTP method
//   - url: The request URL
//
// Returns:
//   - The DPoP proof JWT
//   - Error if proof generation fails
func (am *AuthManager) GenerateDPoPProof(method, url string) (string, error) {
	// Get current key
	keyID := am.currentKeyID
	if keyID == "" {
		// Try to get current key from store
		currentKey, err := am.keyStore.GetCurrentKey()
		if err != nil {
			// Generate a new key
			key, err := am.keyStore.GenerateKey(RS256, "")
			if err != nil {
				return "", err
			}
			keyID = key.ID
			am.currentKeyID = keyID
		} else {
			keyID = currentKey.ID
			am.currentKeyID = keyID
		}
	}

	// Get access token
	accessToken, err := am.GetAccessToken()
	if err != nil {
		return "", err
	}

	return am.keyStore.GenerateProof(keyID, method, url, accessToken)
}

// GetDPoPProofFunc returns a function that generates DPoP proofs.
//
// Returns:
//   - A function that generates DPoP proofs
func (am *AuthManager) GetDPoPProofFunc() func(method, url string) (string, error) {
	return func(method, url string) (string, error) {
		return am.GenerateDPoPProof(method, url)
	}
}

// DiscoverIssuer discovers the OAuth2 issuer configuration.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//
// Returns:
//   - The issuer configuration
//   - Error if discovery fails
func (am *AuthManager) DiscoverIssuer(ctx context.Context) (*IssuerConfig, error) {
	// Build issuer metadata URL
	issuerURL, err := url.Parse(am.issuer)
	if err != nil {
		return nil, err
	}

	// Add .well-known/openid-configuration
	issuerURL.Path = ".well-known/openid-configuration"

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", issuerURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SolidSidecar-Go-SDK/1.0.0")

	// Execute request
	resp, err := am.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check status
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("issuer discovery failed with status: %d", resp.StatusCode)
	}

	// Parse response
	var config IssuerConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	// Validate required fields
	if config.Issuer == "" {
		return nil, ErrInvalidIssuer
	}

	return &config, nil
}

// ExchangeCode exchanges an authorization code for an access token.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - code: The authorization code
//   - verifier: The PKCE code verifier
//
// Returns:
//   - The token response
//   - Error if exchange fails
func (am *AuthManager) ExchangeCode(ctx context.Context, code, verifier string) (*types.TokenResponse, error) {
	// Discover issuer config
	config, err := am.DiscoverIssuer(ctx)
	if err != nil {
		return nil, err
	}

	if config.TokenEndpoint == "" {
		return nil, ErrInvalidIssuer
	}

	// Prepare request body
	body := url.Values{}
	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("redirect_uri", am.redirectURI)
	body.Set("client_id", am.clientID)

	if am.clientSecret != "" {
		body.Set("client_secret", am.clientSecret)
	}

	if verifier != "" {
		body.Set("code_verifier", verifier)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", config.TokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SolidSidecar-Go-SDK/1.0.0")

	// Execute request
	resp, err := am.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check status
	if resp.StatusCode != 200 {
		// Try to parse error response
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description,omitempty"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			if errResp.Error != "" {
				return nil, fmt.Errorf("token exchange failed: %s - %s", errResp.Error, errResp.ErrorDescription)
			}
		}
		return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	// Parse response
	var tokenResp types.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	// Set token in manager
	am.tokenManager.SetToken(&tokenResp, tokenResp.ExpiresIn)

	// Set issuer
	am.tokenManager.SetIssuer(am.issuer)
	am.tokenManager.SetClientID(am.clientID)
	am.tokenManager.SetScope(am.scope)

	return &tokenResp, nil
}

// RefreshToken refreshes the access token.
//
// Returns:
//   - Error if refresh fails
func (am *AuthManager) refreshToken() error {
	// Discover issuer config
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	config, err := am.DiscoverIssuer(ctx)
	if err != nil {
		return err
	}

	if config.TokenEndpoint == "" {
		return ErrInvalidIssuer
	}

	// Get current refresh token
	refreshToken := am.tokenManager.GetRefreshToken()
	if refreshToken == "" {
		return errors.New("no refresh token available")
	}

	// Prepare request body
	body := url.Values{}
	body.Set("grant_type", "refresh_token")
	body.Set("refresh_token", refreshToken)
	body.Set("client_id", am.clientID)

	if am.clientSecret != "" {
		body.Set("client_secret", am.clientSecret)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", config.TokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SolidSidecar-Go-SDK/1.0.0")

	// Execute request
	resp, err := am.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check status
	if resp.StatusCode != 200 {
		// Try to parse error response
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description,omitempty"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			if errResp.Error != "" {
				return fmt.Errorf("token refresh failed: %s - %s", errResp.Error, errResp.ErrorDescription)
			}
		}
		return fmt.Errorf("token refresh failed with status: %d", resp.StatusCode)
	}

	// Parse response
	var tokenResp types.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}

	// Set token in manager
	am.tokenManager.SetToken(&tokenResp, tokenResp.ExpiresIn)

	// Call refresh callback if set
	if am.onTokenRefresh != nil {
		am.onTokenRefresh(tokenResp.AccessToken)
	}

	return nil
}

// RevokeToken revokes an access token.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - token: The token to revoke (if empty, uses current access token)
//
// Returns:
//   - Error if revocation fails
func (am *AuthManager) RevokeToken(ctx context.Context, token string) error {
	if token == "" {
		var err error
		token, err = am.GetAccessToken()
		if err != nil {
			return err
		}
	}

	// Discover issuer config
	config, err := am.DiscoverIssuer(ctx)
	if err != nil {
		return err
	}

	if config.RevocationEndpoint == "" {
		// If no revocation endpoint, just clear local token
		am.tokenManager.Clear()
		return nil
	}

	// Prepare request body
	body := url.Values{}
	body.Set("token", token)
	body.Set("client_id", am.clientID)

	if am.clientSecret != "" {
		body.Set("client_secret", am.clientSecret)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", config.RevocationEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SolidSidecar-Go-SDK/1.0.0")

	// Execute request
	resp, err := am.httpClient.Do(req)
	if err != nil {
		// Clear local token even if server call fails
		am.tokenManager.Clear()
		return err
	}
	defer resp.Body.Close()

	// Check status
	if resp.StatusCode != 200 {
		// Clear local token
		am.tokenManager.Clear()
		return fmt.Errorf("token revocation failed with status: %d", resp.StatusCode)
	}

	// Clear local token
	am.tokenManager.Clear()
	return nil
}

// ClearSession clears the current session.
func (am *AuthManager) ClearSession() {
	am.tokenManager.Clear()
	am.currentKeyID = ""
}

// SetOnTokenRefresh sets the callback for token refresh.
//
// Parameters:
//   - callback: The callback function
func (am *AuthManager) SetOnTokenRefresh(callback func(token string)) {
	am.onTokenRefresh = callback
}

// EnableAutoRefresh enables automatic token refresh.
//
// Parameters:
//   - enabled: Whether to enable auto-refresh
func (am *AuthManager) EnableAutoRefresh(enabled bool) {
	am.autoRefresh = enabled
}

// IssuerConfig represents OAuth2 issuer configuration.
type IssuerConfig struct {
	// Issuer is the issuer URL
	Issuer string `json:"issuer"`

	// AuthorizationEndpoint is the authorization endpoint
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// TokenEndpoint is the token endpoint
	TokenEndpoint string `json:"token_endpoint"`

	// RevocationEndpoint is the revocation endpoint (optional)
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// JWKSURI is the JWKS endpoint
	JWKSURI string `json:"jwks_uri"`

	// ScopesSupported are the supported scopes
	ScopesSupported []string `json:"scopes_supported"`

	// ResponseTypesSupported are the supported response types
	ResponseTypesSupported []string `json:"response_types_supported"`

	// SubjectTypesSupported are the supported subject types
	SubjectTypesSupported []string `json:"subject_types_supported"`

	// IDTokenSigningAlgValuesSupported are the supported signing algorithms
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// DPoPSigningAlgValuesSupported are the supported DPoP signing algorithms
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

// ValidateDPoPSupport checks if the issuer supports DPoP.
//
// Parameters:
//   - config: The issuer configuration
//
// Returns:
//   - true if DPoP is supported
func ValidateDPoPSupport(config *IssuerConfig) bool {
	// Check for DPoP-specific endpoints or algorithms
	if config == nil {
		return false
	}

	// Check if DPoP signing algorithms are specified
	if len(config.DPoPSigningAlgValuesSupported) > 0 {
		return true
	}

	// Check common DPoP signing algorithms in regular signing algs
	for _, alg := range config.IDTokenSigningAlgValuesSupported {
		switch alg {
		case string(RS256), string(ES256), string(ES384), string(ES512), string(EdDSA):
			return true
		}
	}

	return false
}

// import "crypto/tls" is needed for the AuthManager
