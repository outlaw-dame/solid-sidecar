package authz

import (
	"errors"
	"testing"
)

func TestNewHardenedHTTPTransportUsesPolicyClient(t *testing.T) {
	t.Parallel()
	transport, err := NewHardenedHTTPTransport(FixtureTransportOptions{Config: DefaultTransportConfig()})
	if err != nil {
		t.Fatalf("expected hardened HTTP transport to construct: %v", err)
	}
	if transport.client == nil {
		t.Fatal("expected hardened HTTP transport client to be configured")
	}
	if transport.client.CheckRedirect == nil {
		t.Fatal("expected hardened HTTP transport to disable redirects through policy client")
	}
}

func TestSetHardenedBaseURLRejectsUnsafeTargets(t *testing.T) {
	t.Parallel()
	transport, err := NewHardenedHTTPTransport(FixtureTransportOptions{Config: DefaultTransportConfig()})
	if err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{
		"http://example.com/fixtures",
		"https://localhost/fixtures",
		"https://singlelabel/fixtures",
		"https://127.0.0.1/fixtures",
		"https://user@example.com/fixtures",
	} {
		err := transport.SetHardenedBaseURL(rawURL)
		if !errors.Is(err, ErrTransportSecurityViolation) {
			t.Fatalf("expected security violation for %s, got %v", rawURL, err)
		}
	}
}

func TestSetHardenedBaseURLAllowsPublicHTTPS(t *testing.T) {
	t.Parallel()
	transport, err := NewHardenedHTTPTransport(FixtureTransportOptions{Config: DefaultTransportConfig()})
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.SetHardenedBaseURL("https://example.com/fixtures"); err != nil {
		t.Fatalf("expected public HTTPS base URL to be accepted: %v", err)
	}
	if transport.baseURL == nil || transport.baseURL.Hostname() != "example.com" {
		t.Fatalf("expected base URL to be set to example.com, got %#v", transport.baseURL)
	}
}

func TestNewHardenedS3TransportRejectsUnsafeEndpoint(t *testing.T) {
	t.Parallel()
	_, err := NewHardenedS3TransportWithOptions(S3TransportOptions{
		Config:   DefaultTransportConfig(),
		Endpoint: "http://127.0.0.1:9000",
	})
	if !errors.Is(err, ErrTransportSecurityViolation) {
		t.Fatalf("expected unsafe S3 endpoint to be rejected, got %v", err)
	}
}

func TestSetHardenedS3EndpointRejectsUnsafeEndpoint(t *testing.T) {
	t.Parallel()
	transport, err := NewHardenedS3TransportWithOptions(S3TransportOptions{Config: DefaultTransportConfig()})
	if err != nil {
		t.Fatalf("expected hardened S3 transport without endpoint to construct: %v", err)
	}
	err = transport.SetHardenedS3Endpoint("https://localhost:9000")
	if !errors.Is(err, ErrTransportSecurityViolation) {
		t.Fatalf("expected unsafe S3 endpoint to be rejected, got %v", err)
	}
}

func TestSetHardenedS3EndpointAllowsPublicHTTPSEndpoint(t *testing.T) {
	t.Parallel()
	transport, err := NewHardenedS3TransportWithOptions(S3TransportOptions{Config: DefaultTransportConfig()})
	if err != nil {
		t.Fatalf("expected hardened S3 transport without endpoint to construct: %v", err)
	}
	if err := transport.SetHardenedS3Endpoint("https://s3.example.com"); err != nil {
		t.Fatalf("expected public HTTPS S3 endpoint to be accepted: %v", err)
	}
	if transport.endpoint != "https://s3.example.com" {
		t.Fatalf("expected endpoint to be recorded, got %q", transport.endpoint)
	}
}
