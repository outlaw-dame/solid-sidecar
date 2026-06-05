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

	if actual != expected {
		actualBytes, _ := json.MarshalIndent(actual, "", "  ")
		expectedBytes, _ := json.MarshalIndent(expected, "", "  ")
		t.Fatalf("decision mismatch\nactual:   %s\nexpected: %s", actualBytes, expectedBytes)
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
