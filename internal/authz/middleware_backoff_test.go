package authz

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

type backoffOnlyEvaluator struct {
	seen bool
}

func (e *backoffOnlyEvaluator) Evaluate(context.Context, Request) (Decision, error) {
	e.seen = true
	return Decision{}, ErrEvaluatorBackoffActive
}

func TestMiddlewareClassifiesBackoffActiveSeparately(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	primary := &backoffOnlyEvaluator{}
	fallback := &fakeEvaluator{decision: Decision{
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
		w.WriteHeader(http.StatusAccepted)
	})
	handler := Middleware(MiddlewareOptions{
		Evaluator:         primary,
		FallbackEvaluator: fallback,
		BuildOptions:      BuildOptions{Now: fixedNow},
		Logger:            logger,
	}, next)

	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card?token=secret-token", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if !primary.seen || !fallback.seen {
		t.Fatalf("expected primary and fallback evaluators to run: primary=%v fallback=%v", primary.seen, fallback.seen)
	}
	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusAccepted)
	}
	logOutput := logs.String()
	assertShadowWarningLog(t, logOutput, ShadowLogMessageEvaluationBackoffActive, ShadowErrorReasonBackoffActive, "req-1", "/card")
	for _, expected := range []string{
		`"msg":"` + ShadowLogMessageDecision + `"`,
		`"` + ShadowLogFieldRequestID + `":"req-1"`,
		`"` + ShadowLogFieldDecision + `":"abstain"`,
	} {
		if !strings.Contains(logOutput, expected) {
			t.Fatalf("expected log output to contain %s; got %s", expected, logOutput)
		}
	}
	assertNotContainsAny(t, logOutput, `"error":`, "token=secret-token", "secret-token")
}
