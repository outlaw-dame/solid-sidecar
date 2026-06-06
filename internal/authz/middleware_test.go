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
	if e.decision.RequestID == "" {
		e.decision.RequestID = request.RequestID
	}
	return e.decision, nil
}

func TestMiddlewarePassesThroughOnAbstain(t *testing.T) {
	evaluator := &fakeEvaluator{decision: Decision{
		SchemaVersion: SchemaVersion,
		Decision:      DecisionAbstain,
		ReasonCode:    ReasonKernelAbstainShadowMode,
		Audit: AuditFields{
			RequestHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PolicyHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
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

func TestMiddlewarePassesThroughOnShadowDeny(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator := &fakeEvaluator{decision: Decision{
		SchemaVersion:   SchemaVersion,
		Decision:        DecisionDeny,
		ReasonCode:      ReasonInvalidRequest,
		StatusHint:      httpBadRequestStatus,
		PolicyVersion:   "policy-v1",
		ResourceVersion: "resource-v1",
		Audit: AuditFields{
			RequestHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PolicyHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusAccepted)
	})
	handler := Middleware(MiddlewareOptions{Evaluator: evaluator, BuildOptions: BuildOptions{Now: fixedNow}, Logger: logger}, next)

	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if !evaluator.seen {
		t.Fatal("expected evaluator to be called")
	}
	if !nextCalled {
		t.Fatal("shadow deny decisions must still pass through to CSS")
	}
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusAccepted)
	}
	logOutput := logs.String()
	for _, expected := range []string{
		`"msg":"` + ShadowLogMessageDecision + `"`,
		`"` + ShadowLogFieldRequestID + `":"req-1"`,
		`"` + ShadowLogFieldDecision + `":"deny"`,
		`"` + ShadowLogFieldReasonCode + `":"invalid_request"`,
		`"` + ShadowLogFieldStatusHint + `":400`,
	} {
		if !strings.Contains(logOutput, expected) {
			t.Fatalf("expected log output to contain %s; got %s", expected, logOutput)
		}
	}
}

func TestMiddlewarePassesThroughOnInvalidEvaluatorDecision(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator := &fakeEvaluator{decision: Decision{
		SchemaVersion:   SchemaVersion,
		RequestID:       "bad request",
		Decision:        DecisionDeny,
		ReasonCode:      ReasonInvalidRequest,
		StatusHint:      httpBadRequestStatus,
		CacheTTLSeconds: 0,
		Audit: AuditFields{
			RequestHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PolicyHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusAccepted)
	})
	handler := Middleware(MiddlewareOptions{Evaluator: evaluator, BuildOptions: BuildOptions{Now: fixedNow}, Logger: logger}, next)

	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card?token=secret-token", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if !evaluator.seen {
		t.Fatal("expected evaluator to be called")
	}
	if !nextCalled {
		t.Fatal("invalid evaluator decisions must still pass through to CSS")
	}
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusAccepted)
	}
	logOutput := logs.String()
	assertShadowWarningLog(t, logOutput, ShadowLogMessageInvalidDecision, ShadowErrorReasonInvalidDecision, "req-1", "/card")
	assertNotContainsAny(t, logOutput, `"msg":"`+ShadowLogMessageDecision+`"`, `"error":`, "bad request", "token=secret-token", "secret-token")
}

func TestMiddlewarePassesThroughOnBuildError(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator := &fakeEvaluator{}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusAccepted)
	})
	handler := Middleware(MiddlewareOptions{Evaluator: evaluator, BuildOptions: BuildOptions{Now: fixedNow}, Logger: logger}, next)

	req := httptest.NewRequest(http.MethodTrace, "http://pod.example/card?token=secret-token", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))
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
	logOutput := logs.String()
	assertShadowWarningLog(t, logOutput, ShadowLogMessageRequestBuildFailed, ShadowErrorReasonRequestBuildFailed, "req-1", "/card")
	assertNotContainsAny(t, logOutput, `"msg":"`+ShadowLogMessageDecision+`"`, `"error":`, "unsupported authz method", "token=secret-token", "secret-token")
}

func TestMiddlewarePassesThroughOnEvaluatorError(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator := &fakeEvaluator{err: errors.New("boom")}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusCreated)
	})
	handler := Middleware(MiddlewareOptions{Evaluator: evaluator, BuildOptions: BuildOptions{Now: fixedNow}, Logger: logger}, next)

	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card?token=secret-token", nil)
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
	logOutput := logs.String()
	assertShadowWarningLog(t, logOutput, ShadowLogMessageEvaluationFailed, ShadowErrorReasonEvaluationFailed, "req-1", "/card")
	assertNotContainsAny(t, logOutput, `"msg":"`+ShadowLogMessageDecision+`"`, `"error":`, "boom", "token=secret-token", "secret-token")
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
		SchemaVersion:   SchemaVersion,
		Decision:        DecisionAbstain,
		ReasonCode:      ReasonKernelAbstainShadowMode,
		StatusHint:      0,
		CacheTTLSeconds: 0,
		PolicyVersion:   "policy-v1",
		ResourceVersion: "resource-v1",
		Audit:           AuditForRequest(request),
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
		`"msg":"` + ShadowLogMessageDecision + `"`,
		`"` + ShadowLogFieldRequestID + `":"req-1"`,
		`"` + ShadowLogFieldDecision + `":"abstain"`,
		`"` + ShadowLogFieldReasonCode + `":"kernel_abstain_shadow_mode"`,
		`"` + ShadowLogFieldPolicyVersion + `":"policy-v1"`,
		`"` + ShadowLogFieldResourceVersion + `":"resource-v1"`,
		`"` + ShadowLogFieldRequestHash + `":"` + decision.Audit.RequestHash + `"`,
		`"` + ShadowLogFieldPolicyHash + `":"` + decision.Audit.PolicyHash + `"`,
	} {
		if !strings.Contains(logOutput, expected) {
			t.Fatalf("expected log output to contain %s; got %s", expected, logOutput)
		}
	}
	assertNotContainsAny(t, logOutput, "secret=value", "https://alice.example/profile#me", "https://app.example/id")
}

func assertShadowWarningLog(t *testing.T, logOutput, message, reason, requestID, path string) {
	t.Helper()
	for _, expected := range []string{
		`"msg":"` + message + `"`,
		`"` + ShadowLogFieldRequestID + `":"` + requestID + `"`,
		`"` + ShadowLogFieldErrorReason + `":"` + reason + `"`,
		`"` + ShadowLogFieldPath + `":"` + path + `"`,
	} {
		if !strings.Contains(logOutput, expected) {
			t.Fatalf("expected log output to contain %s; got %s", expected, logOutput)
		}
	}
}

func assertNotContainsAny(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if strings.Contains(output, value) {
			t.Fatalf("log output leaked %q: %s", value, output)
		}
	}
}
