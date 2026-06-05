package authz

import (
	"errors"
	"testing"
)

func TestValidateRequestMatchesSharedFixtureManifest(t *testing.T) {
	for _, fixture := range readFixtureManifest(t).Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			request := readFixture[Request](t, fixture.RequestFile)
			err := ValidateRequest(request)
			if fixture.ValidRequest {
				if err != nil {
					t.Fatalf("ValidateRequest returned error: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected ErrInvalidRequest, got %v", err)
			}
		})
	}
}

func TestValidateRequestRejectsInvalidValues(t *testing.T) {
	base := readFixture[Request](t, "authz_request.valid.json")
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "schema", mutate: func(r *Request) { r.SchemaVersion = "authz.v2" }},
		{name: "request id", mutate: func(r *Request) { r.RequestID = "bad request" }},
		{name: "method", mutate: func(r *Request) { r.Method = "TRACE" }},
		{name: "resource uri", mutate: func(r *Request) { r.ResourceURI = "file:///tmp/card" }},
		{name: "resource fragment", mutate: func(r *Request) { r.ResourceURI = "https://pod.example/a#frag" }},
		{name: "mode", mutate: func(r *Request) { r.RequestedModes = []AccessMode{"invalid"} }},
		{name: "duplicate mode", mutate: func(r *Request) { r.RequestedModes = []AccessMode{AccessModeRead, AccessModeRead} }},
		{name: "negative time", mutate: func(r *Request) { r.NowUnix = -1 }},
		{name: "policy uri", mutate: func(r *Request) { r.PolicyDocuments[0].URI = "urn:policy" }},
		{name: "policy hash", mutate: func(r *Request) { r.PolicyDocuments[0].SHA256 = "not-a-hash" }},
		{name: "policy content type", mutate: func(r *Request) { r.PolicyDocuments[0].ContentType = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := base
			request.PolicyDocuments = append([]PolicyDocument(nil), base.PolicyDocuments...)
			tt.mutate(&request)
			if err := ValidateRequest(request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected ErrInvalidRequest, got %v", err)
			}
		})
	}
}

func TestValidateDecisionAcceptsSharedFixtureManifest(t *testing.T) {
	for _, fixture := range readFixtureManifest(t).Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			decision := readFixture[Decision](t, fixture.DecisionFile)
			if err := ValidateDecision(decision); err != nil {
				t.Fatalf("ValidateDecision returned error: %v", err)
			}
		})
	}
}

func TestValidateDecisionRejectsInvalidValues(t *testing.T) {
	base := readFixture[Decision](t, "authz_decision.shadow.json")
	tests := []struct {
		name   string
		mutate func(*Decision)
	}{
		{name: "schema", mutate: func(d *Decision) { d.SchemaVersion = "authz.v2" }},
		{name: "request id", mutate: func(d *Decision) { d.RequestID = "bad request" }},
		{name: "decision", mutate: func(d *Decision) { d.Decision = "invalid" }},
		{name: "reason", mutate: func(d *Decision) { d.ReasonCode = "invalid" }},
		{name: "status", mutate: func(d *Decision) { d.StatusHint = 99 }},
		{name: "ttl", mutate: func(d *Decision) { d.CacheTTLSeconds = -1 }},
		{name: "request hash", mutate: func(d *Decision) { d.Audit.RequestHash = "bad" }},
		{name: "policy hash", mutate: func(d *Decision) { d.Audit.PolicyHash = "bad" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := base
			tt.mutate(&decision)
			if err := ValidateDecision(decision); !errors.Is(err, ErrInvalidDecision) {
				t.Fatalf("expected ErrInvalidDecision, got %v", err)
			}
		})
	}
}
