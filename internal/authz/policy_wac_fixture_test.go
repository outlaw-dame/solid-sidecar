package authz

import (
	"context"
	"errors"
	"testing"
)

func TestWACFixtureFactsFromParseResult(t *testing.T) {
	results, err := ParsePolicySemanticsFixtures(context.Background(), readPolicySemanticsSuiteFixture(t))
	if err != nil {
		t.Fatalf("ParsePolicySemanticsFixtures returned error: %v", err)
	}
	var wacResult PolicyParseResult
	for _, result := range results {
		if result.Family == PolicySemanticsWAC {
			wacResult = result
			break
		}
	}
	if wacResult.FixtureName == "" {
		t.Fatal("expected WAC parse result")
	}

	facts, ok, err := WACFixtureFactsFromParseResult(wacResult)
	if err != nil {
		t.Fatalf("WACFixtureFactsFromParseResult returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected WAC result to be converted")
	}
	if facts.SchemaVersion != WACFixtureFactsSchemaVersion || !facts.FixtureOnly {
		t.Fatalf("unexpected facts metadata: %#v", facts)
	}
	if facts.TargetURI != facts.PolicyDocuments[0].URI {
		t.Fatalf("target = %q, first policy document = %q", facts.TargetURI, facts.PolicyDocuments[0].URI)
	}
	if len(facts.Modes) != 1 || facts.Modes[0] != AccessModeRead {
		t.Fatalf("modes = %#v, want read", facts.Modes)
	}
}

func TestWACFixtureFactsFromParseResultSkipsOtherFamilies(t *testing.T) {
	result := PolicyParseResult{Family: PolicySemanticsACP}
	facts, ok, err := WACFixtureFactsFromParseResult(result)
	if err != nil {
		t.Fatalf("WACFixtureFactsFromParseResult returned error: %v", err)
	}
	if ok || facts.FixtureName != "" {
		t.Fatalf("expected non-WAC result to be skipped, got ok=%v facts=%#v", ok, facts)
	}
}

func TestParseWACFixtureFacts(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	parser, err := NewFixturePolicySemanticsParser(suite)
	if err != nil {
		t.Fatalf("NewFixturePolicySemanticsParser returned error: %v", err)
	}
	normalized, err := NormalizePolicySemanticsFixtureSuite(suite)
	if err != nil {
		t.Fatalf("NormalizePolicySemanticsFixtureSuite returned error: %v", err)
	}
	for _, fixtureCase := range normalized.Cases {
		facts, ok, err := ParseWACFixtureFacts(context.Background(), parser, fixtureCase.Request)
		if err != nil {
			t.Fatalf("ParseWACFixtureFacts returned error for %q: %v", fixtureCase.Name, err)
		}
		if fixtureCase.Family == PolicySemanticsWAC && !ok {
			t.Fatalf("expected WAC fixture match for %q", fixtureCase.Name)
		}
		if fixtureCase.Family != PolicySemanticsWAC && ok {
			t.Fatalf("unexpected WAC fixture facts for %q: %#v", fixtureCase.Name, facts)
		}
	}
}

func TestWACFixtureFactsFromSuiteIsDeterministic(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	left, err := WACFixtureFactsFromSuite(context.Background(), suite)
	if err != nil {
		t.Fatalf("WACFixtureFactsFromSuite left returned error: %v", err)
	}
	reversed := PolicySemanticsFixtureSuite{SchemaVersion: suite.SchemaVersion}
	for i := len(suite.Cases) - 1; i >= 0; i-- {
		reversed.Cases = append(reversed.Cases, suite.Cases[i])
	}
	right, err := WACFixtureFactsFromSuite(context.Background(), reversed)
	if err != nil {
		t.Fatalf("WACFixtureFactsFromSuite right returned error: %v", err)
	}
	if len(left) != len(right) || len(left) == 0 {
		t.Fatalf("unexpected WAC facts counts: %d vs %d", len(left), len(right))
	}
	for i := range left {
		if left[i].FixtureName != right[i].FixtureName || left[i].RequestHash != right[i].RequestHash {
			t.Fatalf("facts order mismatch at %d: %#v vs %#v", i, left[i], right[i])
		}
	}
}

func TestValidateWACFixtureFactsRejectsInvalidInput(t *testing.T) {
	facts := mustWACFixtureFacts(t)
	for _, test := range []struct {
		name  string
		facts WACFixtureFacts
	}{
		{name: "bad schema", facts: withWACFactsSchema(facts, "bad")},
		{name: "bad hash", facts: withWACFactsRequestHash(facts, "bad")},
		{name: "bad target", facts: withWACFactsTarget(facts, "not-a-uri")},
		{name: "empty modes", facts: withWACFactsModes(facts, nil)},
		{name: "bad reason", facts: withWACFactsReason(facts, ReasonPolicyDeny)},
		{name: "not fixture only", facts: withWACFactsFixtureOnly(facts, false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateWACFixtureFacts(test.facts)
			if !errors.Is(err, ErrInvalidWACFixtureFacts) {
				t.Fatalf("error = %v, want ErrInvalidWACFixtureFacts", err)
			}
		})
	}
}

func TestWACFixtureFactsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := WACFixtureFactsFromSuite(ctx, readPolicySemanticsSuiteFixture(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WACFixtureFactsFromSuite error = %v, want context.Canceled", err)
	}
	_, _, err = ParseWACFixtureFacts(ctx, nil, Request{})
	if !errors.Is(err, ErrInvalidWACFixtureFacts) && !errors.Is(err, context.Canceled) {
		t.Fatalf("ParseWACFixtureFacts error = %v, want cancellation or fixture error", err)
	}
}

func mustWACFixtureFacts(t *testing.T) WACFixtureFacts {
	t.Helper()
	facts, err := WACFixtureFactsFromSuite(context.Background(), readPolicySemanticsSuiteFixture(t))
	if err != nil {
		t.Fatalf("WACFixtureFactsFromSuite returned error: %v", err)
	}
	if len(facts) == 0 {
		t.Fatal("expected WAC facts")
	}
	return facts[0]
}

func withWACFactsSchema(input WACFixtureFacts, schema string) WACFixtureFacts {
	input.SchemaVersion = schema
	return input
}

func withWACFactsRequestHash(input WACFixtureFacts, hash string) WACFixtureFacts {
	input.RequestHash = hash
	return input
}

func withWACFactsTarget(input WACFixtureFacts, target string) WACFixtureFacts {
	input.TargetURI = target
	return input
}

func withWACFactsModes(input WACFixtureFacts, modes []AccessMode) WACFixtureFacts {
	input.Modes = modes
	return input
}

func withWACFactsReason(input WACFixtureFacts, reason ReasonCode) WACFixtureFacts {
	input.ExpectedReason = reason
	return input
}

func withWACFactsFixtureOnly(input WACFixtureFacts, fixtureOnly bool) WACFixtureFacts {
	input.FixtureOnly = fixtureOnly
	return input
}
