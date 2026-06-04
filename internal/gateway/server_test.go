package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/outlaw-dame/solid-sidecar/internal/config"
)

func TestGatewayRoutesHealthAndProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "proxied")
	}))
	defer backend.Close()
	cfg := config.Defaults()
	cfg.Backend.URL = backend.URL
	cfg.RateLimit.Enabled = false
	server, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("health status mismatch: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/some/resource", nil))
	if rr.Body.String() != "proxied" {
		t.Fatalf("proxy body mismatch: %q", rr.Body.String())
	}
}

func TestGatewayRejectsUnsafePath(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend should not be called")
	}))
	defer backend.Close()
	cfg := config.Defaults()
	cfg.Backend.URL = backend.URL
	cfg.RateLimit.Enabled = false
	server, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/a/%2e%2e/b", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestGatewayAppliesRateLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	cfg := config.Defaults()
	cfg.Backend.URL = backend.URL
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.RequestsPerWindow = 1
	server, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "192.0.2.44:1111"
	server.http.Handler.ServeHTTP(httptest.NewRecorder(), req)
	rr := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "192.0.2.44:1111"
	server.http.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
}
