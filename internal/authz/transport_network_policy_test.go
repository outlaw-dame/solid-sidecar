package authz

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOutboundTransportNetworkPolicyRejectsUnsafeURLs(t *testing.T) {
	t.Parallel()
	policy := DefaultOutboundTransportNetworkPolicy()
	cases := []string{
		"http://example.com/fixtures",
		"https://user@example.com/fixtures",
		"https://localhost/fixtures",
		"https://service.local/fixtures",
		"https://service.localhost/fixtures",
		"https://singlelabel/fixtures",
		"https://127.0.0.1/fixtures",
		"https://[::1]/fixtures",
		"https://10.0.0.1/fixtures",
		"https://172.16.0.1/fixtures",
		"https://192.168.0.1/fixtures",
		"https://169.254.169.254/fixtures",
	}
	for _, rawURL := range cases {
		_, err := policy.ValidateURL(rawURL)
		if !errors.Is(err, ErrTransportSecurityViolation) {
			t.Fatalf("expected ErrTransportSecurityViolation for %s, got %v", rawURL, err)
		}
	}
}

func TestOutboundTransportNetworkPolicyAllowsPublicHTTPSURL(t *testing.T) {
	t.Parallel()
	policy := DefaultOutboundTransportNetworkPolicy()
	parsedURL, err := policy.ValidateURL("https://example.com/fixtures")
	if err != nil {
		t.Fatalf("expected public HTTPS URL to be accepted: %v", err)
	}
	if parsedURL.Hostname() != "example.com" {
		t.Fatalf("unexpected hostname: %s", parsedURL.Hostname())
	}
}

func TestOutboundTransportNetworkPolicyAllowsLocalhostWhenExplicitlyEnabled(t *testing.T) {
	t.Parallel()
	policy := DefaultOutboundTransportNetworkPolicy()
	policy.AllowLocalhost = true
	if _, err := policy.ValidateURL("https://localhost/fixtures"); err != nil {
		t.Fatalf("expected localhost to be allowed by explicit test override: %v", err)
	}
}

func TestOutboundTransportHTTPClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	policy := DefaultOutboundTransportNetworkPolicy()
	client := policy.NewHTTPClient(0)
	redirectReq := httptest.NewRequest(http.MethodGet, "https://example.com/redirect", nil)
	originalReq := httptest.NewRequest(http.MethodGet, "https://example.com/source", nil)
	if err := client.CheckRedirect(redirectReq, []*http.Request{originalReq}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("expected redirects to be disabled, got %v", err)
	}
}

func TestOutboundTransportDialContextRejectsUnsafeResolvedIP(t *testing.T) {
	t.Parallel()
	policy := DefaultOutboundTransportNetworkPolicy()
	dialer := &net.Dialer{}
	_, err := policy.DialContext(context.Background(), dialer, "tcp", "localhost:443")
	if !errors.Is(err, ErrTransportSecurityViolation) {
		t.Fatalf("expected unsafe localhost resolution to be rejected, got %v", err)
	}
}

func TestOutboundTransportDialContextRejectsMissingPort(t *testing.T) {
	t.Parallel()
	policy := DefaultOutboundTransportNetworkPolicy()
	dialer := &net.Dialer{}
	_, err := policy.DialContext(context.Background(), dialer, "tcp", "example.com")
	if !errors.Is(err, ErrTransportInvalidPath) {
		t.Fatalf("expected missing port to be rejected as invalid path, got %v", err)
	}
}

func TestOutboundTransportNetworkPolicyClassifiesSecurityErrors(t *testing.T) {
	t.Parallel()
	policy := DefaultOutboundTransportNetworkPolicy()
	_, err := policy.ValidateURL("https://127.0.0.1/fixtures")
	if !IsTransportSecurityError(err) {
		t.Fatalf("expected transport security error classification for %v", err)
	}
}
