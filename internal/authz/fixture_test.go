package authz

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fixtureManifest struct {
	SchemaVersion string        `json:"schema_version"`
	Cases         []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	Name         string `json:"name"`
	RequestFile  string `json:"request"`
	DecisionFile string `json:"decision"`
	ValidRequest bool   `json:"valid_request"`
}

func TestShadowEvaluatorMatchesSharedFixtures(t *testing.T) {
	for _, test := range readFixtureManifest(t).Cases {
		t.Run(test.Name, func(t *testing.T) {
			request := readFixture[Request](t, test.RequestFile)
			expected := readFixture[Decision](t, test.DecisionFile)

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

func readFixtureManifest(t *testing.T) fixtureManifest {
	t.Helper()
	manifest := readFixture[fixtureManifest](t, "authz_manifest.json")
	if manifest.SchemaVersion != "authz.fixture-manifest.v1" {
		t.Fatalf("unexpected fixture manifest schema: %q", manifest.SchemaVersion)
	}
	if len(manifest.Cases) == 0 {
		t.Fatal("fixture manifest must contain at least one case")
	}
	seenNames := make(map[string]struct{}, len(manifest.Cases))
	for _, test := range manifest.Cases {
		if test.Name == "" || test.RequestFile == "" || test.DecisionFile == "" {
			t.Fatalf("fixture manifest case must include name, request, and decision: %+v", test)
		}
		if _, ok := seenNames[test.Name]; ok {
			t.Fatalf("duplicate fixture manifest case name: %q", test.Name)
		}
		seenNames[test.Name] = struct{}{}
	}
	return manifest
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
