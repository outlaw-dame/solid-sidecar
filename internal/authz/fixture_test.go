package authz

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestShadowEvaluatorMatchesSharedFixture(t *testing.T) {
	request := readFixture[Request](t, "authz_request.valid.json")
	expected := readFixture[Decision](t, "authz_decision.shadow.json")

	actual, err := NewShadowEvaluator().Evaluate(context.Background(), request)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	assertDecisionEqual(t, actual, expected)
}

func TestShadowEvaluatorMatchesSharedInvalidFixtures(t *testing.T) {
	tests := []struct {
		name         string
		requestFile  string
		decisionFile string
	}{
		{
			name:         "unsupported schema",
			requestFile:  "authz_request.unsupported_schema.json",
			decisionFile: "authz_decision.unsupported_schema.json",
		},
		{
			name:         "unsupported method",
			requestFile:  "authz_request.unsupported_method.json",
			decisionFile: "authz_decision.unsupported_method.json",
		},
		{
			name:         "missing modes",
			requestFile:  "authz_request.missing_modes.json",
			decisionFile: "authz_decision.missing_modes.json",
		},
		{
			name:         "unsafe uri",
			requestFile:  "authz_request.unsafe_uri.json",
			decisionFile: "authz_decision.unsafe_uri.json",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := readFixture[Request](t, test.requestFile)
			expected := readFixture[Decision](t, test.decisionFile)

			actual, err := NewShadowEvaluator().Evaluate(context.Background(), request)
			if err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}

			assertDecisionEqual(t, actual, expected)
		})
	}
}

func TestAuditForRequestMatchesSharedFixture(t *testing.T) {
	request := readFixture[Request](t, "authz_request.valid.json")
	expected := readFixture[Decision](t, "authz_decision.shadow.json")
	actual := AuditForRequest(request)

	if actual != expected.Audit {
		t.Fatalf("audit mismatch: got %+v, want %+v", actual, expected.Audit)
	}
}

func assertDecisionEqual(t *testing.T, actual, expected Decision) {
	t.Helper()
	if actual != expected {
		actualBytes, _ := json.MarshalIndent(actual, "", "  ")
		expectedBytes, _ := json.MarshalIndent(expected, "", "  ")
		t.Fatalf("decision mismatch\nactual:   %s\nexpected: %s", actualBytes, expectedBytes)
	}
}

func readFixture[T any](t *testing.T, name string) T {
	t.Helper()
	path := filepath.Join("..", "..", "contracts", "fixtures", name)
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var out T
	if err := json.Unmarshal(bytes, &out); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return out
}
