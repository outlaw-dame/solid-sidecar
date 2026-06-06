package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/outlaw-dame/solid-sidecar/internal/authz"
	"github.com/outlaw-dame/solid-sidecar/internal/config"
)

func TestGatewayAuthzShadowModeStillProxies(t *testing.T) {
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		if got := r.Header.Get("X-Request-ID"); got != "req-shadow" {
			t.Fatalf("request id was not forwarded: %q", got)
		}
		_, _ = io.WriteString(w, "shadow-proxied")
	}))
	defer backend.Close()

	cfg := config.Defaults()
	cfg.Backend.URL = backend.URL
	cfg.RateLimit.Enabled = false
	cfg.Authz.ShadowEnabled = true
	cfg.Authz.PublicBaseURL = "https://pod.example"

	server, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/some/resource?x=1", nil)
	req.Header.Set("X-Request-ID", "req-shadow")
	rr := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rr, req)

	if !backendCalled {
		t.Fatal("expected backend to be called")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Body.String() != "shadow-proxied" {
		t.Fatalf("proxy body mismatch: %q", rr.Body.String())
	}
	key := authz.ShadowMetricKey{Event: authz.ShadowMetricDecision, Decision: string(authz.DecisionAbstain), ReasonCode: string(authz.ReasonKernelAbstainShadowMode)}
	if got := server.AuthzMetricsSnapshotForTests().Counters[key]; got != 1 {
		t.Fatalf("authz shadow metric = %d, want 1", got)
	}
}

func TestGatewayAuthzMetricsDisabledWhenShadowDisabled(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	cfg := config.Defaults()
	cfg.Backend.URL = backend.URL
	cfg.RateLimit.Enabled = false
	cfg.Authz.ShadowEnabled = false

	server, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(server.AuthzMetricsSnapshotForTests().Counters); got != 0 {
		t.Fatalf("authz metrics counters = %d, want 0", got)
	}
}
