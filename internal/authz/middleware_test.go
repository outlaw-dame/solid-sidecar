package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
