package authz

import (
	"context"
	"errors"
	"testing"
)

func TestShadowEvaluatorAbstainsForValidRequest(t *testing.T) {
	request := readFixture[Request](t, "authz_request.valid.json")

	decision, err := NewShadowEvaluator().Evaluate(context.Background(), request)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if decision.SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected schema version: %q", decision.SchemaVersion)
	}
	if decision.RequestID != request.RequestID {
		t.Fatalf("unexpected request id: %q", decision.RequestID)
	}
	if decision.Decision != DecisionAbstain {
		t.Fatalf("unexpected decision: %q", decision.Decision)
	}
	if decision.ReasonCode != ReasonKernelAbstainShadowMode {
		t.Fatalf("unexpected reason: %q", decision.ReasonCode)
	}
	if decision.StatusHint != 0 {
		t.Fatalf("unexpected status hint: %d", decision.StatusHint)
	}
	if decision.PolicyVersion != request.PolicyVersion || decision.ResourceVersion != request.ResourceVersion {
		t.Fatalf("unexpected versions: %+v", decision)
	}
	if decision.Audit != AuditForRequest(request) {
		t.Fatalf("unexpected audit fields: %+v", decision.Audit)
	}
	if !ShouldContinueToCSS(decision) {
		t.Fatal("abstain decisions must continue to CSS")
	}
}

func TestShadowEvaluatorReturnsStructuredDenyForInvalidRequests(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
		reason ReasonCode
	}{
		{
			name: "unsupported schema",
			mutate: func(request *Request) {
				request.SchemaVersion = "authz.v0"
			},
			reason: ReasonUnsupportedSchema,
		},
		{
			name: "invalid request id",
			mutate: func(request *Request) {
				request.RequestID = "bad request"
			},
			reason: ReasonInvalidRequest,
		},
		{
			name: "unsupported method",
			mutate: func(request *Request) {
				request.Method = "TRACE"
			},
			reason: ReasonInvalidRequest,
		},
		{
			name: "missing modes",
			mutate: func(request *Request) {
				request.RequestedModes = nil
			},
			reason: ReasonMissingRequestedModes,
		},
		{
			name: "unsafe resource uri",
			mutate: func(request *Request) {
				request.ResourceURI = "ftp://pod.example/alice/card"
			},
			reason: ReasonUnsafeResourceURI,
		},
		{
			name: "invalid mode",
			mutate: func(request *Request) {
				request.RequestedModes = []AccessMode{"owner"}
			},
			reason: ReasonInvalidRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := readFixture[Request](t, "authz_request.valid.json")
			test.mutate(&request)

			decision, err := NewShadowEvaluator().Evaluate(context.Background(), request)
			if err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}
			if decision.Decision != DecisionDeny {
				t.Fatalf("decision = %q, want %q", decision.Decision, DecisionDeny)
			}
			if decision.ReasonCode != test.reason {
				t.Fatalf("reason = %q, want %q", decision.ReasonCode, test.reason)
			}
			if decision.StatusHint != httpBadRequestStatus {
				t.Fatalf("status hint = %d, want %d", decision.StatusHint, httpBadRequestStatus)
			}
			if !validToken(decision.RequestID, 128) {
				t.Fatalf("decision request id must be valid, got %q", decision.RequestID)
			}
			if decision.Audit != AuditForRequest(request) {
				t.Fatalf("unexpected audit fields: %+v", decision.Audit)
			}
			if ShouldContinueToCSS(decision) {
				t.Fatal("structured deny decisions must not be implicit CSS continuation decisions")
			}
		})
	}
}

func TestDecisionRequestIDSafelyCorrelatesMalformedRequestID(t *testing.T) {
	request := readFixture[Request](t, "authz_request.valid.json")
	request.RequestID = "bad request"
	audit := AuditForRequest(request)

	got := decisionRequestID(request, audit)
	want := "invalid-request-" + audit.RequestHash[:32]
	if got != want {
		t.Fatalf("decision request id = %q, want %q", got, want)
	}
	if !validToken(got, 128) {
		t.Fatalf("sanitized decision request id must be valid, got %q", got)
	}
}

func TestShadowEvaluatorHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NewShadowEvaluator().Evaluate(ctx, readFixture[Request](t, "authz_request.valid.json"))
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
