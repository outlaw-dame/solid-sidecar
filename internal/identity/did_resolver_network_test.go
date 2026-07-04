package identity

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestValidateOutboundResolutionURLRejectsUnsafeTargets(t *testing.T) {
	t.Parallel()
	cases := []string{
		"http://example.com/.well-known/did/solid.json",
		"https://localhost/.well-known/did/solid.json",
		"https://service.local/.well-known/did/solid.json",
		"https://127.0.0.1/.well-known/did/solid.json",
		"https://[::1]/.well-known/did/solid.json",
		"https://10.0.0.1/.well-known/did/solid.json",
		"https://172.16.0.1/.well-known/did/solid.json",
		"https://192.168.1.1/.well-known/did/solid.json",
		"https://169.254.169.254/.well-known/did/solid.json",
		"https://user@example.com/.well-known/did/solid.json",
	}
	for _, rawURL := range cases {
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatalf("test URL should parse: %s", rawURL)
		}
		err = validateOutboundResolutionURL(u)
		if !errors.Is(err, ErrUnsafeDID) {
			t.Fatalf("expected ErrUnsafeDID for %s, got %v", rawURL, err)
		}
	}
}

func TestValidateOutboundResolutionURLAllowsPublicHTTPSHost(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("https://example.com/.well-known/did/solid.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOutboundResolutionURL(u); err != nil {
		t.Fatalf("expected public HTTPS host to be accepted: %v", err)
	}
}

func TestResolverHTTPClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	client := newResolverHTTPClient(1)
	redirectReq := httptest.NewRequest(http.MethodGet, "https://example.com/redirect", nil)
	originalReq := httptest.NewRequest(http.MethodGet, "https://example.com/source", nil)
	if err := client.CheckRedirect(redirectReq, []*http.Request{originalReq}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("expected redirects to be disabled, got %v", err)
	}
}

func TestDialValidatedResolutionAddressRejectsUnsafeResolvedIP(t *testing.T) {
	t.Parallel()
	dialer := &net.Dialer{}
	_, err := dialValidatedResolutionAddress(context.Background(), dialer, "tcp", "localhost:443")
	if !errors.Is(err, ErrUnsafeDID) {
		t.Fatalf("expected unsafe localhost resolution to be rejected, got %v", err)
	}
}

func TestDialValidatedResolutionAddressRejectsMissingPort(t *testing.T) {
	t.Parallel()
	dialer := &net.Dialer{}
	_, err := dialValidatedResolutionAddress(context.Background(), dialer, "tcp", "example.com")
	if err == nil {
		t.Fatal("expected missing port to be rejected")
	}
}

func TestAllowedDIDDocumentContentTypeParsesParameters(t *testing.T) {
	t.Parallel()
	allowed := []string{
		"application/did+json",
		"application/did+json; charset=utf-8",
		"application/json",
		"application/json; charset=utf-8",
	}
	for _, contentType := range allowed {
		if !isAllowedDIDDocumentContentType(contentType) {
			t.Fatalf("expected content type %q to be allowed", contentType)
		}
	}

	rejected := []string{"", "text/html", "application/octet-stream", "not a content type"}
	for _, contentType := range rejected {
		if isAllowedDIDDocumentContentType(contentType) {
			t.Fatalf("expected content type %q to be rejected", contentType)
		}
	}
}
