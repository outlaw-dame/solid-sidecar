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

// MaxWebIDProfileSize is the maximum size of a WebID profile document we'll fetch
const MaxWebIDProfileSize = 64 * 1024 // 64KB

// WebIDProfile represents a minimal WebID profile document
type WebIDProfile struct {
	// Subject is the WebID URI
	Subject string `json:"@id"`
	// Type should include "Person" or similar
	Type []string `json:"type,omitempty"`
	// SolidOIDCIssuer is the OIDC issuer associated with this WebID
	SolidOIDCIssuer string `json:"http://www.w3.org/ns/solid/terms#oidcIssuer,omitempty"`
	// Claims may contain additional profile information
	Claims map[string]any `json:"-"`
}

// WebIDVerifier verifies WebID ownership
type WebIDVerifier struct {
	client         *http.Client
	maxSize        int
	timeout        time.Duration
	allowedIssuers []string
}

// NewWebIDVerifier creates a new WebID verifier
func NewWebIDVerifier(client *http.Client, allowedIssuers []string) *WebIDVerifier {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}
	return &WebIDVerifier{
		client:         client,
		maxSize:        MaxWebIDProfileSize,
		timeout:        10 * time.Second,
		allowedIssuers: allowedIssuers,
	}
}

// VerifyWebIDOwnership fetches the WebID profile and verifies it's valid
// Returns the profile if valid, or an error
func (v *WebIDVerifier) VerifyWebIDOwnership(ctx context.Context, webID string) (*WebIDProfile, error) {
	if webID == "" {
		return nil, errors.New("WebID is required")
	}

	// Parse the WebID URI
	parsed, err := url.Parse(webID)
	if err != nil {
		return nil, fmt.Errorf("invalid WebID URI: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("WebID must be an HTTPS URI")
	}

	// Fetch the WebID profile
	profile, err := v.fetchWebIDProfile(ctx, webID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch WebID profile: %w", err)
	}

	// Verify the profile subject matches the WebID
	if profile.Subject != webID {
		return nil, fmt.Errorf("WebID profile subject %q does not match requested WebID %q", profile.Subject, webID)
	}

	// Check if the profile has a Solid OIDC issuer that we trust
	if profile.SolidOIDCIssuer != "" {
		if !v.isAllowedIssuer(profile.SolidOIDCIssuer) {
			return nil, fmt.Errorf("WebID profile issuer %q is not trusted", profile.SolidOIDCIssuer)
		}
	}

	return profile, nil
}

// fetchWebIDProfile fetches and parses a WebID profile document
func (v *WebIDVerifier) fetchWebIDProfile(ctx context.Context, webID string) (*WebIDProfile, error) {
	// Handle fragment identifiers in WebID
	// The WebID might have a fragment (e.g., https://example.com/profile/card#me)
	// We need to fetch the document without the fragment
	baseURL := webID
	if idx := strings.IndexByte(webID, '#'); idx >= 0 {
		baseURL = webID[:idx]
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, err
	}

	// Set acceptable headers
	req.Header.Set("Accept", "application/json, application/ld+json")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WebID profile fetch failed with status %d", resp.StatusCode)
	}

	// Limit the response size
	limitedReader := io.LimitReader(resp.Body, int64(v.maxSize)+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}

	if len(body) > v.maxSize {
		return nil, errors.New("WebID profile exceeds maximum size")
	}

	// Parse as JSON-LD (WebID profiles are typically JSON-LD)
	var profile WebIDProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse WebID profile: %w", err)
	}

	return &profile, nil
}

// isAllowedIssuer checks if the issuer is in the allowed list
func (v *WebIDVerifier) isAllowedIssuer(issuer string) bool {
	for _, allowed := range v.allowedIssuers {
		if strings.EqualFold(issuer, allowed) {
			return true
		}
	}
	return false
}

// VerifyWebIDFromToken extracts the WebID from token claims and verifies ownership
func (v *WebIDVerifier) VerifyWebIDFromToken(ctx context.Context, claims IdentityClaims) error {
	if claims.Subject == "" {
		return errors.New("token subject (WebID) is required")
	}

	// Verify the WebID profile
	_, err := v.VerifyWebIDOwnership(ctx, claims.Subject)
	if err != nil {
		return fmt.Errorf("WebID ownership verification failed: %w", err)
	}

	return nil
}
