package authz

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mutableEvaluator struct {
	calls    int
	decision Decision
	err      error
}

func (e *mutableEvaluator) Evaluate(context.Context, Request) (Decision, error) {
	e.calls++
	if e.err != nil {
		return Decision{}, e.err
	}
	return e.decision, nil
}

func TestBackoffEvaluatorSkipsAttemptsDuringBackoff(t *testing.T) {
	now := time.Unix(100, 0)
	primary := &mutableEvaluator{err: errors.New("temporary failure")}
	evaluator, err := NewBackoffEvaluator(BackoffEvaluatorOptions{
		Evaluator: primary,
		BaseDelay: time.Second,
		MaxDelay:  8 * time.Second,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewBackoffEvaluator returned error: %v", err)
	}
	request := validBackoffRequest()

	if _, err := evaluator.Evaluate(context.Background(), request); err == nil {
		t.Fatal("expected primary failure")
	}
	if primary.calls != 1 {
		t.Fatalf("primary calls = %d, want 1", primary.calls)
	}

	if _, err := evaluator.Evaluate(context.Background(), request); !errors.Is(err, ErrEvaluatorBackoffActive) {
		t.Fatalf("error = %v, want ErrEvaluatorBackoffActive", err)
	}
	if primary.calls != 1 {
		t.Fatalf("primary calls = %d, want still 1 during backoff", primary.calls)
	}

	now = now.Add(time.Second)
	if _, err := evaluator.Evaluate(context.Background(), request); err == nil {
		t.Fatal("expected second primary failure after backoff window")
	}
	if primary.calls != 2 {
		t.Fatalf("primary calls = %d, want 2", primary.calls)
	}

	now = now.Add(time.Second)
	if _, err := evaluator.Evaluate(context.Background(), request); !errors.Is(err, ErrEvaluatorBackoffActive) {
		t.Fatalf("error = %v, want ErrEvaluatorBackoffActive after exponential delay", err)
	}
	if primary.calls != 2 {
		t.Fatalf("primary calls = %d, want still 2 during second backoff", primary.calls)
	}
}

func TestBackoffEvaluatorResetsAfterSuccess(t *testing.T) {
	now := time.Unix(100, 0)
	request := validBackoffRequest()
	primary := &mutableEvaluator{err: errors.New("temporary failure")}
	evaluator, err := NewBackoffEvaluator(BackoffEvaluatorOptions{
		Evaluator: primary,
		BaseDelay: time.Second,
		MaxDelay:  8 * time.Second,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewBackoffEvaluator returned error: %v", err)
	}

	if _, err := evaluator.Evaluate(context.Background(), request); err == nil {
		t.Fatal("expected primary failure")
	}
	now = now.Add(time.Second)
	primary.err = nil
	primary.decision = shadowDecision(request, AuditForRequest(request), DecisionAbstain, ReasonKernelAbstainShadowMode, 0)
	if _, err := evaluator.Evaluate(context.Background(), request); err != nil {
		t.Fatalf("expected success after backoff window: %v", err)
	}

	primary.err = errors.New("new failure")
	if _, err := evaluator.Evaluate(context.Background(), request); err == nil {
		t.Fatal("expected new primary failure")
	}
	now = now.Add(time.Second)
	primary.err = nil
	if _, err := evaluator.Evaluate(context.Background(), request); err != nil {
		t.Fatalf("expected retry after reset base delay: %v", err)
	}
}

func TestNewBackoffEvaluatorRejectsInvalidOptions(t *testing.T) {
	primary := &mutableEvaluator{}
	for _, test := range []struct {
		name    string
		options BackoffEvaluatorOptions
	}{
		{name: "missing evaluator", options: BackoffEvaluatorOptions{}},
		{name: "negative base", options: BackoffEvaluatorOptions{Evaluator: primary, BaseDelay: -time.Second, MaxDelay: time.Second}},
		{name: "negative max", options: BackoffEvaluatorOptions{Evaluator: primary, BaseDelay: time.Second, MaxDelay: -time.Second}},
		{name: "base greater than max", options: BackoffEvaluatorOptions{Evaluator: primary, BaseDelay: 2 * time.Second, MaxDelay: time.Second}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewBackoffEvaluator(test.options); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func validBackoffRequest() Request {
	return Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "req-1",
		Method:         "GET",
		ResourceURI:    "https://pod.example/card",
		RequestedModes: []AccessMode{AccessModeRead},
		NowUnix:        fixedNow().Unix(),
	}
}
