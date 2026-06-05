package authz

import (
	"context"
	"errors"
	"testing"
)

func TestShadowEvaluatorAbstains(t *testing.T) {
	request := Request{
		SchemaVersion: SchemaVersion,
		RequestID:     "req-1",
	}

	decision, err := NewShadowEvaluator().Evaluate(context.Background(), request)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if decision.SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected schema version: %q", decision.SchemaVersion)
	}
	if decision.RequestID != "req-1" {
		t.Fatalf("unexpected request id: %q", decision.RequestID)
	}
	if decision.Decision != DecisionAbstain {
		t.Fatalf("unexpected decision: %q", decision.Decision)
	}
	if decision.ReasonCode != ReasonKernelAbstainShadowMode {
		t.Fatalf("unexpected reason: %q", decision.ReasonCode)
	}
	if len(decision.Audit.RequestHash) != 64 || len(decision.Audit.PolicyHash) != 64 {
		t.Fatalf("expected audit hashes, got %+v", decision.Audit)
	}
	if !ShouldContinueToCSS(decision) {
		t.Fatal("abstain decisions must continue to CSS")
	}
}

func TestShadowEvaluatorRejectsEmptyRequest(t *testing.T) {
	_, err := NewShadowEvaluator().Evaluate(context.Background(), Request{})
	if !errors.Is(err, ErrNilRequest) {
		t.Fatalf("expected ErrNilRequest, got %v", err)
	}
}

func TestShadowEvaluatorHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NewShadowEvaluator().Evaluate(ctx, Request{SchemaVersion: SchemaVersion, RequestID: "req-1"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestShouldContinueToCSS(t *testing.T) {
	if !ShouldContinueToCSS(Decision{}) {
		t.Fatal("empty decision should continue to CSS")
	}
	if !ShouldContinueToCSS(Decision{Decision: DecisionAbstain}) {
		t.Fatal("abstain decision should continue to CSS")
	}
	if ShouldContinueToCSS(Decision{Decision: DecisionAllow}) {
		t.Fatal("allow decision must not be treated as implicit CSS continuation")
	}
	if ShouldContinueToCSS(Decision{Decision: DecisionDeny}) {
		t.Fatal("deny decision must not be treated as implicit CSS continuation")
	}
}
