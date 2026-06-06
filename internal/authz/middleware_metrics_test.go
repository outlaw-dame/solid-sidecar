package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

func TestMiddlewareRecordsDecisionMetric(t *testing.T) {
	metrics := NewShadowMetrics()
	evaluator := &fakeEvaluator{decision: Decision{
		SchemaVersion: SchemaVersion,
		Decision:      DecisionAbstain,
		ReasonCode:    ReasonKernelAbstainShadowMode,
		Audit: AuditFields{
			RequestHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PolicyHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}}
	handler := Middleware(MiddlewareOptions{Evaluator: evaluator, BuildOptions: BuildOptions{Now: fixedNow}, Metrics: metrics}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card?secret=value", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	key := ShadowMetricKey{Event: ShadowMetricDecision, Decision: string(DecisionAbstain), ReasonCode: string(ReasonKernelAbstainShadowMode)}
	if got := metrics.Snapshot().Counters[key]; got != 1 {
		t.Fatalf("decision metric = %d, want 1", got)
	}
}

func TestMiddlewareRecordsWarningAndFallbackMetrics(t *testing.T) {
	metrics := NewShadowMetrics()
	primary := &fakeEvaluator{err: errors.New("boom")}
	fallback := &fakeEvaluator{decision: Decision{
		SchemaVersion: SchemaVersion,
		Decision:      DecisionAbstain,
		ReasonCode:    ReasonKernelAbstainShadowMode,
		Audit: AuditFields{
			RequestHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PolicyHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}}
	handler := Middleware(MiddlewareOptions{
		Evaluator:         primary,
		FallbackEvaluator: fallback,
		BuildOptions:      BuildOptions{Now: fixedNow},
		Metrics:           metrics,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card?secret=value", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	snapshot := metrics.Snapshot()
	warningKey := ShadowMetricKey{Event: ShadowMetricWarning, ErrorReason: ShadowErrorReasonEvaluationFailed}
	fallbackKey := ShadowMetricKey{Event: ShadowMetricFallbackDecision, Decision: string(DecisionAbstain), ReasonCode: string(ReasonKernelAbstainShadowMode)}
	if got := snapshot.Counters[warningKey]; got != 1 {
		t.Fatalf("warning metric = %d, want 1", got)
	}
	if got := snapshot.Counters[fallbackKey]; got != 1 {
		t.Fatalf("fallback metric = %d, want 1", got)
	}
}

func TestMiddlewareRecordsFallbackFailureMetric(t *testing.T) {
	metrics := NewShadowMetrics()
	primary := &fakeEvaluator{err: errors.New("boom")}
	fallback := evaluatorFunc(func(context.Context, Request) (Decision, error) {
		return Decision{}, errors.New("fallback failed")
	})
	handler := Middleware(MiddlewareOptions{
		Evaluator:         primary,
		FallbackEvaluator: fallback,
		BuildOptions:      BuildOptions{Now: fixedNow},
		Metrics:           metrics,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card?secret=value", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	snapshot := metrics.Snapshot()
	warningKey := ShadowMetricKey{Event: ShadowMetricWarning, ErrorReason: ShadowErrorReasonEvaluationFailed}
	failureKey := ShadowMetricKey{Event: ShadowMetricFallbackFailure, ErrorReason: ShadowErrorReasonFallbackFailed}
	if got := snapshot.Counters[warningKey]; got != 1 {
		t.Fatalf("warning metric = %d, want 1", got)
	}
	if got := snapshot.Counters[failureKey]; got != 1 {
		t.Fatalf("fallback failure metric = %d, want 1", got)
	}
}

type evaluatorFunc func(context.Context, Request) (Decision, error)

func (f evaluatorFunc) Evaluate(ctx context.Context, request Request) (Decision, error) {
	return f(ctx, request)
}
