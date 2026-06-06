package authz

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestFixtureManifestCoversAuthzFixtureFiles(t *testing.T) {
	manifest := readFixtureManifest(t)
	listedRequests := make(map[string]struct{}, len(manifest.Cases))
	listedDecisions := make(map[string]struct{}, len(manifest.Cases))
	for _, test := range manifest.Cases {
		listedRequests[test.RequestFile] = struct{}{}
		listedDecisions[test.DecisionFile] = struct{}{}
	}

	entries, err := os.ReadDir(fixtureDir())
	if err != nil {
		t.Fatalf("read fixture directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, "authz_request.") && strings.HasSuffix(name, ".json"):
			if _, ok := listedRequests[name]; !ok {
				t.Fatalf("request fixture %q is not referenced by authz_manifest.json", name)
			}
		case strings.HasPrefix(name, "authz_decision.") && strings.HasSuffix(name, ".json"):
			if _, ok := listedDecisions[name]; !ok {
				t.Fatalf("decision fixture %q is not referenced by authz_manifest.json", name)
			}
		}
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
	seenRequests := make(map[string]struct{}, len(manifest.Cases))
	seenDecisions := make(map[string]struct{}, len(manifest.Cases))
	for _, test := range manifest.Cases {
		if test.Name == "" || test.RequestFile == "" || test.DecisionFile == "" {
			t.Fatalf("fixture manifest case must include name, request, and decision: %+v", test)
		}
		if !validFixtureName(test.RequestFile, "authz_request.") {
			t.Fatalf("invalid request fixture filename %q", test.RequestFile)
		}
		if !validFixtureName(test.DecisionFile, "authz_decision.") {
			t.Fatalf("invalid decision fixture filename %q", test.DecisionFile)
		}
		if _, ok := seenNames[test.Name]; ok {
			t.Fatalf("duplicate fixture manifest case name: %q", test.Name)
		}
		if _, ok := seenRequests[test.RequestFile]; ok {
			t.Fatalf("duplicate fixture manifest request file: %q", test.RequestFile)
		}
		if _, ok := seenDecisions[test.DecisionFile]; ok {
			t.Fatalf("duplicate fixture manifest decision file: %q", test.DecisionFile)
		}
		seenNames[test.Name] = struct{}{}
		seenRequests[test.RequestFile] = struct{}{}
		seenDecisions[test.DecisionFile] = struct{}{}
	}
	return manifest
}

func validFixtureName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
		return false
	}
	return !strings.ContainsAny(name, `/\\`)
}

func readFixture[T any](t *testing.T, name string) T {
	t.Helper()
	bytes, err := os.ReadFile(filepath.Join(fixtureDir(), name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var out T
	if err := json.Unmarshal(bytes, &out); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return out
}

func fixtureDir() string {
	return filepath.Join("..", "..", "contracts", "fixtures")
}
