// Package auth provides authentication utilities for the Solid Sidecar Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready - FULLY HARDENED
package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockOIDCServer provides a mock OAuth2/OIDC server for testing AuthManager
// This server simulates issuer discovery, token exchange, and token revocation endpoints
type MockOIDCServer struct {
	mu sync.RWMutex

	// issuerConfig is the OIDC issuer configuration
	issuerConfig *IssuerConfig

	// tokenEndpointHandler handles token requests
	tokenEndpointHandler func(w http.ResponseWriter, r *http.Request)

	// revocationEndpointHandler handles revocation requests
	revocationEndpointHandler func(w http.ResponseWriter, r *http.Request)

	// lastRequest stores the last request received for inspection
	lastRequest *http.Request

	// lastRequestBody stores the last request body
	lastRequestBody []byte

	// simulateError indicates if the server should simulate errors
	simulateError bool

	// errorStatusCode is the status code to return on error
	errorStatusCode int

	// errorResponse is the error response to return
	errorResponse map[string]interface{}

	// tokenResponse is the token response to return
	tokenResponse *types.TokenResponse

	// authCodeToToken maps auth codes to token responses for testing
	authCodeToToken map[string]*types.TokenResponse

	// requireDPoP indicates if DPoP proof is required
	requireDPoP bool

	// validDPoPProof is the expected DPoP proof for validation
	validDPoPProof string
}

// NewMockOIDCServer creates a new mock OIDC server with default configuration
func NewMockOIDCServer() *MockOIDCServer {
	return &MockOIDCServer{
		issuerConfig: &IssuerConfig{
			Issuer:                           "https://example.com",
			AuthorizationEndpoint:            "https://example.com/oauth2/authorize",
			TokenEndpoint:                    "https://example.com/oauth2/token",
			RevocationEndpoint:               "https://example.com/oauth2/revoke",
			JWKSURI:                          "https://example.com/.well-known/jwks.json",
			ScopesSupported:                  []string{"openid", "profile", "email", "webid"},
			ResponseTypesSupported:           []string{"code"},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
			DPoPSigningAlgValuesSupported:    []string{"RS256", "ES256"},
		},
		authCodeToToken: make(map[string]*types.TokenResponse),
		errorStatusCode: http.StatusBadRequest,
	}
}

// Handler returns the HTTP handler for the mock OIDC server
func (s *MockOIDCServer) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()

		// Store request information
		s.lastRequest = r
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			s.lastRequestBody = body
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		// Handle error simulation
		if s.simulateError {
			if s.errorResponse != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(s.errorStatusCode)
				json.NewEncoder(w).Encode(s.errorResponse)
			} else {
				w.WriteHeader(s.errorStatusCode)
			}
			return
		}

		// Route requests
		path := r.URL.Path
		if strings.HasSuffix(path, ".well-known/openid-configuration") {
			s.handleIssuerDiscovery(w, r)
		} else if strings.HasSuffix(path, "/token") {
			s.handleTokenEndpoint(w, r)
		} else if strings.HasSuffix(path, "/revoke") {
			s.handleRevocationEndpoint(w, r)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// handleIssuerDiscovery handles OIDC issuer discovery requests
func (s *MockOIDCServer) handleIssuerDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(s.issuerConfig)
}

// handleTokenEndpoint handles token exchange requests
func (s *MockOIDCServer) handleTokenEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// If custom handler is set, use it
	if s.tokenEndpointHandler != nil {
		s.tokenEndpointHandler(w, r)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	grantType := r.Form.Get("grant_type")

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r)
	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "unsupported_grant_type",
		})
	}
}

// handleAuthorizationCodeGrant handles authorization code grant type
func (s *MockOIDCServer) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "Missing authorization code",
		})
		return
	}

	// Check if code exists in our mapping
	if tokenResp, exists := s.authCodeToToken[code]; exists {
		// Check client_id if provided (not stored in TokenResponse in this implementation)
		if clientID := r.Form.Get("client_id"); clientID != "" {
			_ = clientID
		}

		// Check PKCE verifier if provided
		if codeVerifier := r.Form.Get("code_verifier"); codeVerifier != "" {
			// In a real server, we'd verify the verifier matches the challenge
			// For testing, we just check it's present
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tokenResp)
	} else {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		})
	}
}

// handleRefreshTokenGrant handles refresh token grant type
func (s *MockOIDCServer) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Form.Get("refresh_token")
	if refreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "Missing refresh token",
		})
		return
	}

	// Check client_id if provided
	clientID := r.Form.Get("client_id")

	// For testing, we'll return a new token
	newToken := &types.TokenResponse{
		AccessToken:  "new-access-token-" + refreshToken,
		TokenType:    "DPoP",
		ExpiresIn:    3600,
		RefreshToken: "new-refresh-token-" + refreshToken,
		Scope:        "openid profile webid",
		IssuedAt:     time.Now().UTC(),
	}

	// clientID is not stored in TokenResponse in this implementation
	_ = clientID

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(newToken)
}

// handleRevocationEndpoint handles token revocation requests
func (s *MockOIDCServer) handleRevocationEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// If custom handler is set, use it
	if s.revocationEndpointHandler != nil {
		s.revocationEndpointHandler(w, r)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "Missing token",
		})
		return
	}

	// For testing, we always return success for revocation
	w.WriteHeader(http.StatusOK)
}

// SetIssuerConfig sets the issuer configuration
func (s *MockOIDCServer) SetIssuerConfig(config *IssuerConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issuerConfig = config
}

// SetTokenResponse sets the token response to return
func (s *MockOIDCServer) SetTokenResponse(response *types.TokenResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenResponse = response
}

// AddAuthCodeToToken adds a mapping from auth code to token response
func (s *MockOIDCServer) AddAuthCodeToToken(code string, token *types.TokenResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodeToToken[code] = token
}

// SetTokenEndpointHandler sets a custom handler for the token endpoint
func (s *MockOIDCServer) SetTokenEndpointHandler(handler func(w http.ResponseWriter, r *http.Request)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenEndpointHandler = handler
}

// SetRevocationEndpointHandler sets a custom handler for the revocation endpoint
func (s *MockOIDCServer) SetRevocationEndpointHandler(handler func(w http.ResponseWriter, r *http.Request)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revocationEndpointHandler = handler
}

// SetError configures the server to return an error
func (s *MockOIDCServer) SetError(statusCode int, errorResponse map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.simulateError = true
	s.errorStatusCode = statusCode
	s.errorResponse = errorResponse
}

// ResetError clears the error simulation
func (s *MockOIDCServer) ResetError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.simulateError = false
	s.errorStatusCode = http.StatusBadRequest
	s.errorResponse = nil
}

// GetLastRequest returns the last request received
func (s *MockOIDCServer) GetLastRequest() *http.Request {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRequest
}

// GetLastRequestBody returns the last request body
func (s *MockOIDCServer) GetLastRequestBody() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRequestBody
}

// -----------------------------------------------------------------------------
// AuthManager Tests
// -----------------------------------------------------------------------------

func TestAuthManager_NewAuthManager(t *testing.T) {
	t.Run("valid issuer", func(t *testing.T) {
		options := &AuthManagerOptions{
			Issuer:   "https://example.com",
			ClientID: "test-client",
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)
		require.NotNil(t, am)
		assert.Equal(t, "https://example.com", am.issuer)
		assert.Equal(t, "test-client", am.clientID)
	})

	t.Run("empty issuer", func(t *testing.T) {
		options := &AuthManagerOptions{
			Issuer: "",
		}
		am, err := NewAuthManager(options)
		require.Error(t, err)
		assert.Equal(t, ErrInvalidIssuer, err)
		assert.Nil(t, am)
	})

	t.Run("nil options", func(t *testing.T) {
		am, err := NewAuthManager(nil)
		require.Error(t, err)
		assert.Equal(t, ErrInvalidIssuer, err)
		assert.Nil(t, am)
	})

	t.Run("invalid issuer URL", func(t *testing.T) {
		// Use an actually invalid URL that url.Parse will reject
		options := &AuthManagerOptions{
			Issuer: "://invalid-url",
		}
		am, err := NewAuthManager(options)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer URL")
		assert.Nil(t, am)
	})

	t.Run("localhost issuer", func(t *testing.T) {
		options := &AuthManagerOptions{
			Issuer: "http://localhost:8080",
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)
		require.NotNil(t, am)
	})

	t.Run("with custom http client", func(t *testing.T) {
		customClient := &http.Client{Timeout: 5 * time.Second}
		options := &AuthManagerOptions{
			Issuer:     "https://example.com",
			HTTPClient: customClient,
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)
		require.NotNil(t, am)
		assert.Equal(t, customClient, am.httpClient)
	})

	t.Run("with custom key store", func(t *testing.T) {
		keyStore := NewDPoPKeyStore(&DPoPKeyStoreOptions{
			Algorithm: ES256,
		})
		options := &AuthManagerOptions{
			Issuer:   "https://example.com",
			KeyStore: keyStore,
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)
		require.NotNil(t, am)
		assert.Equal(t, keyStore, am.keyStore)
	})
}

func TestAuthManager_DiscoverIssuer(t *testing.T) {
	// Create mock server
	mockServer := NewMockOIDCServer()
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Update issuer config to use our test server URL
	mockServer.SetIssuerConfig(&IssuerConfig{
		Issuer:                           server.URL,
		AuthorizationEndpoint:            server.URL + "/oauth2/authorize",
		TokenEndpoint:                    server.URL + "/oauth2/token",
		RevocationEndpoint:               server.URL + "/oauth2/revoke",
		JWKSURI:                          server.URL + "/.well-known/jwks.json",
		ScopesSupported:                  []string{"openid", "profile"},
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	})

	t.Run("successful discovery", func(t *testing.T) {
		options := &AuthManagerOptions{
			Issuer: server.URL,
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		config, err := am.DiscoverIssuer(context.Background())
		require.NoError(t, err)
		require.NotNil(t, config)
		assert.Equal(t, server.URL, config.Issuer)
		assert.Equal(t, server.URL+"/oauth2/authorize", config.AuthorizationEndpoint)
		assert.Equal(t, server.URL+"/oauth2/token", config.TokenEndpoint)
	})

	t.Run("server returns error", func(t *testing.T) {
		mockServer.SetError(http.StatusInternalServerError, map[string]interface{}{
			"error": "server_error",
		})

		options := &AuthManagerOptions{
			Issuer: server.URL,
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		config, err := am.DiscoverIssuer(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer discovery failed with status: 500")
		assert.Nil(t, config)

		// Reset error
		mockServer.ResetError()
	})

	t.Run("invalid issuer URL in config", func(t *testing.T) {
		mockServer.SetTokenResponse(&types.TokenResponse{})
		mockServer.SetIssuerConfig(&IssuerConfig{
			Issuer: "", // Empty issuer should fail
		})

		options := &AuthManagerOptions{
			Issuer: server.URL,
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		config, err := am.DiscoverIssuer(context.Background())
		require.Error(t, err)
		assert.Equal(t, ErrInvalidIssuer, err)
		assert.Nil(t, config)
	})
}

func TestAuthManager_ExchangeCode(t *testing.T) {
	// Create mock server
	mockServer := NewMockOIDCServer()
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Add a token response for a specific auth code
	mockServer.AddAuthCodeToToken("test-code", &types.TokenResponse{
		AccessToken:  "test-access-token",
		TokenType:    "DPoP",
		ExpiresIn:    3600,
		RefreshToken: "test-refresh-token",
		Scope:        "openid profile webid",
		IssuedAt:     time.Now().UTC(),
	})

	// Update issuer config
	mockServer.SetIssuerConfig(&IssuerConfig{
		Issuer:                           server.URL,
		AuthorizationEndpoint:            server.URL + "/oauth2/authorize",
		TokenEndpoint:                    server.URL + "/oauth2/token",
		RevocationEndpoint:               server.URL + "/oauth2/revoke",
		JWKSURI:                          server.URL + "/.well-known/jwks.json",
		ScopesSupported:                  []string{"openid", "profile", "webid"},
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	})

	t.Run("successful code exchange", func(t *testing.T) {
		options := &AuthManagerOptions{
			Issuer:       server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURI:  "https://example.com/callback",
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		tokenResp, err := am.ExchangeCode(context.Background(), "test-code", "test-verifier")
		require.NoError(t, err)
		require.NotNil(t, tokenResp)
		assert.Equal(t, "test-access-token", tokenResp.AccessToken)
		assert.Equal(t, "DPoP", tokenResp.TokenType)
		assert.Equal(t, int64(3600), tokenResp.ExpiresIn)
		assert.Equal(t, "test-refresh-token", tokenResp.RefreshToken)
	})

	t.Run("invalid code", func(t *testing.T) {
		options := &AuthManagerOptions{
			Issuer:   server.URL,
			ClientID: "test-client",
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		tokenResp, err := am.ExchangeCode(context.Background(), "invalid-code", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
		assert.Nil(t, tokenResp)
	})

	t.Run("server returns error", func(t *testing.T) {
		// Set a custom handler for the token endpoint that returns an error
		mockServer.SetTokenEndpointHandler(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "test error",
			})
		})

		options := &AuthManagerOptions{
			Issuer:   server.URL,
			ClientID: "test-client",
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		tokenResp, err := am.ExchangeCode(context.Background(), "test-code", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token exchange failed: invalid_request")
		assert.Nil(t, tokenResp)
		// Reset the custom handler
		mockServer.SetTokenEndpointHandler(nil)
	})

	t.Run("issuer without token endpoint", func(t *testing.T) {
		// Create a mock server without token endpoint
		mockServerNoToken := NewMockOIDCServer()
		mockServerNoToken.SetIssuerConfig(&IssuerConfig{
			Issuer:                server.URL,
			TokenEndpoint:         "", // No token endpoint
			AuthorizationEndpoint: server.URL + "/oauth2/authorize",
		})

		// Create a new server for this test
		serverNoToken := httptest.NewServer(mockServerNoToken.Handler())
		defer serverNoToken.Close()

		options := &AuthManagerOptions{
			Issuer:   serverNoToken.URL,
			ClientID: "test-client",
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		tokenResp, err := am.ExchangeCode(context.Background(), "test-code", "")
		require.Error(t, err)
		assert.Equal(t, ErrInvalidIssuer, err)
		assert.Nil(t, tokenResp)
	})
}

func TestAuthManager_SetToken_And_GetAccessToken(t *testing.T) {
	options := &AuthManagerOptions{
		Issuer: "https://example.com",
	}
	am, err := NewAuthManager(options)
	require.NoError(t, err)

	t.Run("get token without setting", func(t *testing.T) {
		token, err := am.GetAccessToken()
		require.Error(t, err)
		assert.Equal(t, ErrNoToken, err)
		assert.Equal(t, "", token)
	})

	t.Run("set and get token", func(t *testing.T) {
		am.SetToken("test-token", 3600)
		token, err := am.GetAccessToken()
		require.NoError(t, err)
		assert.Equal(t, "test-token", token)
	})

	t.Run("expired token without auto refresh", func(t *testing.T) {
		// Set token with IssuedAt in the past using TokenManager directly
		am.tokenManager.SetToken(&types.TokenResponse{
			AccessToken: "expired-token",
			TokenType:   "DPoP",
			IssuedAt:    time.Now().Add(-2 * time.Hour),
		}, 0)
		token, err := am.GetAccessToken()
		require.Error(t, err)
		assert.Equal(t, ErrNoToken, err)
		assert.Equal(t, "", token)
	})

	t.Run("expired token with auto refresh but no client secret", func(t *testing.T) {
		am2, _ := NewAuthManager(&AuthManagerOptions{
			Issuer: "https://example.com",
		})
		am2.EnableAutoRefresh(true)
		// Set token with IssuedAt in the past using TokenManager directly
		am2.tokenManager.SetToken(&types.TokenResponse{
			AccessToken: "expired-token",
			TokenType:   "DPoP",
			IssuedAt:    time.Now().Add(-2 * time.Hour),
		}, 0)

		token, err := am2.GetAccessToken()
		require.Error(t, err)
		assert.Equal(t, ErrNoToken, err)
		assert.Equal(t, "", token)
	})
}

func TestAuthManager_SetOnTokenRefresh(t *testing.T) {
	options := &AuthManagerOptions{
		Issuer: "https://example.com",
	}
	am, err := NewAuthManager(options)
	require.NoError(t, err)

	// Test that callback is initially nil
	assert.Nil(t, am.onTokenRefresh)

	// Set a callback
	am.SetOnTokenRefresh(func(token string) {
		// Callback is set - we can verify it's not nil
	})

	assert.NotNil(t, am.onTokenRefresh)

	// The callback should be called during token refresh
	// We can't easily test the callback without mocking the entire refresh flow,
	// but we can verify it's set correctly
}

func TestAuthManager_ClearSession(t *testing.T) {
	options := &AuthManagerOptions{
		Issuer: "https://example.com",
	}
	am, err := NewAuthManager(options)
	require.NoError(t, err)

	// Set a token
	am.SetToken("test-token", 3600)

	// Verify token is set
	token, err := am.GetAccessToken()
	require.NoError(t, err)
	assert.Equal(t, "test-token", token)

	// Clear session
	am.ClearSession()

	// Verify token is cleared
	token, err = am.GetAccessToken()
	require.Error(t, err)
	assert.Equal(t, ErrNoToken, err)
	assert.Equal(t, "", token)
}

func TestAuthManager_EnableAutoRefresh(t *testing.T) {
	options := &AuthManagerOptions{
		Issuer: "https://example.com",
	}
	am, err := NewAuthManager(options)
	require.NoError(t, err)

	// Default should be false
	assert.False(t, am.autoRefresh)

	// Enable auto refresh
	am.EnableAutoRefresh(true)
	assert.True(t, am.autoRefresh)

	// Disable auto refresh
	am.EnableAutoRefresh(false)
	assert.False(t, am.autoRefresh)
}

func TestAuthManager_GetDPoPKeyStore(t *testing.T) {
	options := &AuthManagerOptions{
		Issuer: "https://example.com",
	}
	am, err := NewAuthManager(options)
	require.NoError(t, err)

	keyStore := am.GetDPoPKeyStore()
	assert.NotNil(t, keyStore)
	assert.Equal(t, am.keyStore, keyStore)
}

func TestAuthManager_GenerateDPoPProof_Integration(t *testing.T) {
	options := &AuthManagerOptions{
		Issuer: "https://example.com",
	}
	am, err := NewAuthManager(options)
	require.NoError(t, err)

	// Set a token
	am.SetToken("test-access-token", 3600)

	// Generate DPoP proof
	proof, err := am.GenerateDPoPProof("GET", "https://example.com/resource")
	require.NoError(t, err)
	assert.NotEmpty(t, proof)

	// Verify it's a JWT with 3 parts
	parts := strings.Split(proof, ".")
	assert.Len(t, parts, 3)

	// Verify the header contains dpop+jwt type
	headerJSON, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(parts[0])
	require.NoError(t, err)

	var header map[string]interface{}
	json.Unmarshal(headerJSON, &header)
	assert.Equal(t, "dpop+jwt", header["typ"])
}

func TestAuthManager_GetDPoPProofFunc(t *testing.T) {
	options := &AuthManagerOptions{
		Issuer: "https://example.com",
	}
	am, err := NewAuthManager(options)
	require.NoError(t, err)

	am.SetToken("test-token", 3600)

	proofFunc := am.GetDPoPProofFunc()
	assert.NotNil(t, proofFunc)

	// Test the function
	proof, err := proofFunc("GET", "https://example.com/resource")
	require.NoError(t, err)
	assert.NotEmpty(t, proof)
}

func TestAuthManager_RevokeToken(t *testing.T) {
	// Create mock server
	mockServer := NewMockOIDCServer()
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Update issuer config
	mockServer.SetIssuerConfig(&IssuerConfig{
		Issuer:             server.URL,
		TokenEndpoint:      server.URL + "/oauth2/token",
		RevocationEndpoint: server.URL + "/oauth2/revoke",
	})

	t.Run("revoke with current token", func(t *testing.T) {
		options := &AuthManagerOptions{
			Issuer:       server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		// Set a token
		am.SetToken("token-to-revoke", 3600)

		// Revoke the current token
		err = am.RevokeToken(context.Background(), "")
		require.NoError(t, err)

		// Verify token is cleared
		_, err = am.GetAccessToken()
		require.Error(t, err)
		assert.Equal(t, ErrNoToken, err)
	})

	t.Run("revoke specific token", func(t *testing.T) {
		options := &AuthManagerOptions{
			Issuer:       server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		// Set a token
		am.SetToken("token-to-revoke", 3600)

		// Revoke a specific token
		err = am.RevokeToken(context.Background(), "specific-token-to-revoke")
		require.NoError(t, err)

		// The current token should still be cleared because revocation clears local token
		_, err = am.GetAccessToken()
		require.Error(t, err)
		assert.Equal(t, ErrNoToken, err)
	})

	t.Run("revoke without token", func(t *testing.T) {
		options := &AuthManagerOptions{
			Issuer:   server.URL,
			ClientID: "test-client",
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		// Try to revoke without a token
		err = am.RevokeToken(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no token available")
	})

	t.Run("issuer without revocation endpoint", func(t *testing.T) {
		// Create a mock server without revocation endpoint
		mockServerNoRevoke := NewMockOIDCServer()
		mockServerNoRevoke.SetIssuerConfig(&IssuerConfig{
			Issuer:             server.URL,
			TokenEndpoint:      server.URL + "/oauth2/token",
			RevocationEndpoint: "", // No revocation endpoint
		})

		// Create a new server for this test
		serverNoRevoke := httptest.NewServer(mockServerNoRevoke.Handler())
		defer serverNoRevoke.Close()

		options := &AuthManagerOptions{
			Issuer:   serverNoRevoke.URL,
			ClientID: "test-client",
		}
		am, err := NewAuthManager(options)
		require.NoError(t, err)

		// Set a token
		am.SetToken("token-to-revoke", 3600)

		// Revoke should succeed (just clears local token)
		err = am.RevokeToken(context.Background(), "")
		require.NoError(t, err)

		// Verify token is cleared
		_, err = am.GetAccessToken()
		require.Error(t, err)
		assert.Equal(t, ErrNoToken, err)
	})
}

func TestValidateDPoPSupport(t *testing.T) {
	t.Run("supports DPoP with explicit algorithms", func(t *testing.T) {
		config := &IssuerConfig{
			DPoPSigningAlgValuesSupported: []string{"RS256", "ES256"},
		}
		assert.True(t, ValidateDPoPSupport(config))
	})

	t.Run("supports DPoP with standard algorithms", func(t *testing.T) {
		config := &IssuerConfig{
			IDTokenSigningAlgValuesSupported: []string{"RS256", "ES256"},
		}
		assert.True(t, ValidateDPoPSupport(config))
	})

	t.Run("does not support DPoP with weak algorithms only", func(t *testing.T) {
		config := &IssuerConfig{
			IDTokenSigningAlgValuesSupported: []string{"HS256"},
		}
		assert.False(t, ValidateDPoPSupport(config))
	})

	t.Run("nil config", func(t *testing.T) {
		assert.False(t, ValidateDPoPSupport(nil))
	})

	t.Run("empty config", func(t *testing.T) {
		config := &IssuerConfig{}
		assert.False(t, ValidateDPoPSupport(config))
	})
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

// No additional helper functions needed - all imports are already at the top
