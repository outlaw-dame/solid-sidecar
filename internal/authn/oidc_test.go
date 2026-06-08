package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOIDCDiscoveryClientDiscoversIssuerAndJWKS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration/issuer":
			_, _ = w.Write([]byte(`{"issuer":"` + hostURL(r) + `/issuer","jwks_uri":"` + hostURL(r) + `/jwks"}`))
		case "/jwks":
			_, _ = w.Write([]byte(`{"keys":[{"kid":"key-1","kty":"RSA","use":"sig"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewOIDCDiscoveryClient(OIDCDiscoveryConfig{HTTPClient: server.Client(), AllowHTTPForTest: true, Timeout: time.Second})
	issuer := server.URL + "/issuer"
	metadata, err := client.DiscoverIssuer(context.Background(), issuer)
	if err != nil {
		t.Fatalf("DiscoverIssuer returned error: %v", err)
	}
	if metadata.Issuer != issuer || metadata.JWKSURI != server.URL+"/jwks" {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
	set, err := client.FetchJWKS(context.Background(), metadata.JWKSURI)
	if err != nil {
		t.Fatalf("FetchJWKS returned error: %v", err)
	}
	key, ok, err := set.KeyByID("key-1")
	if err != nil || !ok || len(key) == 0 {
		t.Fatalf("KeyByID returned key=%q ok=%v err=%v", string(key), ok, err)
	}
}

func TestOIDCDiscoveryRejectsIssuerMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"http://other.example/issuer","jwks_uri":"` + hostURL(r) + `/jwks"}`))
	}))
	defer server.Close()

	client := NewOIDCDiscoveryClient(OIDCDiscoveryConfig{HTTPClient: server.Client(), AllowHTTPForTest: true, Timeout: time.Second})
	_, err := client.DiscoverIssuer(context.Background(), server.URL+"/issuer")
	if !errors.Is(err, ErrInvalidOIDCDiscovery) {
		t.Fatalf("error = %v, want ErrInvalidOIDCDiscovery", err)
	}
}

func TestOIDCDiscoveryRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + hostURL(r) + `/issuer","jwks_uri":"` + hostURL(r) + `/jwks","padding":"too-large"}`))
	}))
	defer server.Close()

	client := NewOIDCDiscoveryClient(OIDCDiscoveryConfig{HTTPClient: server.Client(), AllowHTTPForTest: true, Timeout: time.Second, MaxResponseBytes: 32})
	_, err := client.DiscoverIssuer(context.Background(), server.URL+"/issuer")
	if !errors.Is(err, ErrInvalidOIDCDiscovery) {
		t.Fatalf("error = %v, want ErrInvalidOIDCDiscovery", err)
	}
}

func TestValidateJWKSetRejectsUnsafeKeys(t *testing.T) {
	tests := []struct {
		name string
		set  JWKSet
	}{
		{name: "empty", set: JWKSet{}},
		{name: "missing kid", set: JWKSet{Keys: []json.RawMessage{json.RawMessage(`{"kty":"RSA"}`)}}},
		{name: "unsupported kty", set: JWKSet{Keys: []json.RawMessage{json.RawMessage(`{"kid":"key-1","kty":"oct"}`)}}},
		{name: "duplicate kid", set: JWKSet{Keys: []json.RawMessage{json.RawMessage(`{"kid":"key-1","kty":"RSA"}`), json.RawMessage(`{"kid":"key-1","kty":"RSA"}`)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateJWKSet(test.set)
			if !errors.Is(err, ErrInvalidOIDCDiscovery) {
				t.Fatalf("error = %v, want ErrInvalidOIDCDiscovery", err)
			}
		})
	}
}

func hostURL(r *http.Request) string {
	return "http://" + r.Host
}
