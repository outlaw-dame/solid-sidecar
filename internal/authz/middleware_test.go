package authz

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

type fakeEvaluator struct {
	decision Decision
	err      error
	seen     bool
}

func (e *fakeEvaluator) Evaluate(_ context.Context, request Request) (Decision, error) {
	e.seen = true
	if e.err != nil {
		return Decision{}, e.err
	}
	e.decision.RequestID = request.RequestID
	return e.decision, nil
}

func TestMiddlewarePassesThroughOnAbstain(t *testing.T) {
	evaluator := &fakeEvaluator{decision: Decision{
		SchemaVersion: SchemaVersion,
		Decision:      DecisionAbstain,
		ReasonCode:    ReasonKernelAbstainShadowMode,
	}}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Middleware(MiddlewareOptions{Evaluator: evaluator, BuildOptions: BuildOptions{Now: fixedNow}}, next)

	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if !evaluator.seen {
		t.Fatal("expected evaluator to be called")
	}
	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if res.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusNoContent)
	}
}

func TestMiddlewarePassesThroughOnBuildError(t *testing.T) {
	evaluator := &fakeEvaluator{}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusAccepted)
	})
	handler := Middleware(MiddlewareOptions{Evaluator: evaluator, BuildOptions: BuildOptions{Now: fixedNow}}, next)

	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if evaluator.seen {
		t.Fatal("evaluator should not be called when request building fails")
	}
	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusAccepted)
	}
}

func TestMiddlewarePassesThroughOnEvaluatorError(t *testing.T) {
	evaluator := &fakeEvaluator{err: errors.New("boom")}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusCreated)
	})
	handler := Middleware(MiddlewareOptions{Evaluator: evaluator, BuildOptions: BuildOptions{Now: fixedNow}}, next)

	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if !evaluator.seen {
		t.Fatal("expected evaluator to be called")
	}
	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if res.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusCreated)
	}
}

func TestMiddlewareLogsShadowDecisionAuditMetadata(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	req := httptest.NewRequest(http.MethodGet, "http://pod.example/alice/card?secret=value", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))

	request, err := BuildRequest(req, BuildOptions{Now: fixedNow})
	if err != nil {
		t.Fatalf("BuildRequest returned error: %v", err)
	}
	decision := Decision{
		SchemaVersion:    SchemaVersion,
		Decision:         DecisionAbstain,
		ReasonCode:       ReasonKernelAbstainShadowMode,
		StatusHint:       0,
		CacheTTLSeconds:  0,
		PolicyVersion:    "policy-v1",
		ResourceVersion:  "resource-v1",
		Audit:            AuditForRequest(request),
	}
	evaluator := &fakeEvaluator{decision: decision}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Middleware(MiddlewareOptions{Evaluator: evaluator, BuildOptions: BuildOptions{Now: fixedNow}, Logger: logger}, next)

	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	logOutput := logs.String()
	for _, expected := range []string{
		`"msg":"authz shadow decision"`,
		`"request_id":"req-1"`,
		`"decision":"abstain"`,
		`"reason_code":"kernel_abstain_shadow_mode"`,
		`"policy_version":"policy-v1"`,
		`"resource_version":"resource-v1"`,
		`"request_hash":"` + decision.Audit.RequestHash + `"`,
		`"policy_hash":"` + decision.Audit.PolicyHash + `"`,
	} {
		if !strings.Contains(logOutput, expected) {
			t.Fatalf("expected log output to contain %s; got %s", expected, logOutput)
		}
	}
	for _, forbidden := range []string{
		"secret=value",
		"https://alice.example/profile#me",
		"https://app.example/id",
	} {
		if strings.Contains(logOutput, forbidden) {
			t.Fatalf("log output leaked %q: %s", forbidden, logOutput)
		}
	}
}
