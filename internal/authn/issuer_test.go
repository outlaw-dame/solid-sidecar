package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIssuerDiscoveryClientDiscoversAndCachesMetadata(t *testing.T) {
	now := time.Unix(100, 0)
	discoveryHits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		discoveryHits++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, serverIssuer(r), serverIssuer(r)+"/jwks")
	}))
	defer server.Close()

	client := NewIssuerDiscoveryClient(server.Client())
	client.Now = func() time.Time { return now }
	client.CacheTTL = time.Minute

	metadata, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}
	if metadata.Issuer != server.URL || metadata.JWKSURI != server.URL+"/jwks" || metadata.ExpiresAt.IsZero() {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
	metadata, err = client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover cached returned error: %v", err)
	}
	if discoveryHits != 1 {
		t.Fatalf("discovery hits = %d, want 1", discoveryHits)
	}
}

func TestIssuerDiscoveryClientFetchesAndCopiesJWKS(t *testing.T) {
	now := time.Unix(100, 0)
	jwksHits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		jwksHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"one"}]}`))
	}))
	defer server.Close()

	client := NewIssuerDiscoveryClient(server.Client())
	client.Now = func() time.Time { return now }
	metadata := IssuerMetadata{Issuer: server.URL, JWKSURI: server.URL + "/jwks"}

	set, err := client.FetchJWKS(context.Background(), metadata)
	if err != nil {
		t.Fatalf("FetchJWKS returned error: %v", err)
	}
	set.Keys[0][0] = 'X'
	set, err = client.FetchJWKS(context.Background(), metadata)
	if err != nil {
		t.Fatalf("FetchJWKS cached returned error: %v", err)
	}
	if jwksHits != 1 {
		t.Fatalf("jwks hits = %d, want 1", jwksHits)
	}
	if string(set.Keys[0]) != `{"kty":"RSA","kid":"one"}` {
		t.Fatalf("cached jwks was mutated: %s", set.Keys[0])
	}
}

func TestIssuerDiscoveryClientRejectsInvalidMetadata(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://other.example","jwks_uri":"https://other.example/jwks"}`))
	}))
	defer server.Close()

	client := NewIssuerDiscoveryClient(server.Client())
	_, err := client.Discover(context.Background(), server.URL)
	if !errors.Is(err, ErrInvalidIssuerMetadata) {
		t.Fatalf("error = %v, want ErrInvalidIssuerMetadata", err)
	}
}

func TestIssuerDiscoveryClientRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + serverIssuer(r) + `","jwks_uri":"` + serverIssuer(r) + `/jwks","padding":"1234567890"}`))
	}))
	defer server.Close()

	client := NewIssuerDiscoveryClient(server.Client())
	client.MaxBodyBytes = 20
	_, err := client.Discover(context.Background(), server.URL)
	if !errors.Is(err, ErrInvalidIssuerMetadata) {
		t.Fatalf("error = %v, want ErrInvalidIssuerMetadata", err)
	}
}

func TestIssuerDiscoveryURLForRootIssuer(t *testing.T) {
	got, err := issuerDiscoveryURL("https://issuer.example/")
	if err != nil {
		t.Fatalf("issuerDiscoveryURL returned error: %v", err)
	}
	want := "https://issuer.example/.well-known/openid-configuration"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJWKSURIRejectsQuery(t *testing.T) {
	_, err := canonicalJWKSURI("https://issuer.example/jwks?x=1")
	if !errors.Is(err, ErrInvalidIssuerMetadata) {
		t.Fatalf("error = %v, want ErrInvalidIssuerMetadata", err)
	}
}

func serverIssuer(r *http.Request) string {
	return "https://" + r.Host
}
