package gateway

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/outlaw-dame/solid-sidecar/internal/authz"
	"github.com/outlaw-dame/solid-sidecar/internal/config"
)

func TestAuthzMetricsSnapshotIsEmptyWhenShadowDisabled(t *testing.T) {
	cfg := config.Defaults()
	server, err := New(cfg, slog.Default())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if len(server.AuthzMetricsSnapshotForTests().Counters) != 0 {
		t.Fatal("authz metrics should be empty when shadow mode is disabled")
	}
}

func TestAuthzMetricsSnapshotRecordsShadowDecision(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	cfg := config.Defaults()
	cfg.Backend.URL = backend.URL
	cfg.Authz.ShadowEnabled = true
	cfg.Authz.Evaluator = config.DefaultAuthzEvaluatorLocal
	server, err := New(cfg, slog.Default())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/card", nil)
	res := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusNoContent)
	}

	key := authz.ShadowMetricKey{
		Event:      authz.ShadowMetricDecision,
		Decision:   string(authz.DecisionAbstain),
		ReasonCode: string(authz.ReasonKernelAbstainShadowMode),
	}
	if got := server.AuthzMetricsSnapshotForTests().Counters[key]; got != 1 {
		t.Fatalf("authz decision counter = %d, want 1", got)
	}
}
