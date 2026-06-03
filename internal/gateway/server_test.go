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
