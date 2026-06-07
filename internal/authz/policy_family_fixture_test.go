package authz

import (
	"context"
	"errors"
	"testing"
)

func TestPolicyFamilyFixtureFactsFromSuiteCoversACPAndSAI(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	for _, family := range []PolicySemanticsFamily{PolicySemanticsACP, PolicySemanticsSAI} {
		facts, err := PolicyFamilyFixtureFactsFromSuite(context.Background(), suite, family)
		if err != nil {
			t.Fatalf("PolicyFamilyFixtureFactsFromSuite(%q) returned error: %v", family, err)
		}
		if len(facts) != 1 {
			t.Fatalf("facts count for %q = %d, want 1", family, len(facts))
		}
		if facts[0].Family != family || facts[0].SchemaVersion != PolicyFamilyFixtureFactsSchemaVersion || !facts[0].FixtureOnly {
			t.Fatalf("unexpected facts for %q: %#v", family, facts[0])
		}
		if facts[0].TargetURI == "" || len(facts[0].Modes) == 0 || len(facts[0].PolicyDocuments) == 0 {
			t.Fatalf("incomplete facts for %q: %#v", family, facts[0])
		}
	}
}

func TestPolicyFamilyFixtureFactsFromParseResultFiltersFamily(t *testing.T) {
	results, err := ParsePolicySemanticsFixtures(context.Background(), readPolicySemanticsSuiteFixture(t))
	if err != nil {
		t.Fatalf("ParsePolicySemanticsFixtures returned error: %v", err)
	}
	var acpResult PolicyParseResult
	for _, result := range results {
		if result.Family == PolicySemanticsACP {
			acpResult = result
			break
		}
	}
	if acpResult.FixtureName == "" {
		t.Fatal("expected ACP parse result")
	}
	facts, ok, err := PolicyFamilyFixtureFactsFromParseResult(acpResult, PolicySemanticsACP)
	if err != nil {
		t.Fatalf("PolicyFamilyFixtureFactsFromParseResult returned error: %v", err)
	}
	if !ok || facts.Family != PolicySemanticsACP || facts.TargetURI != acpResult.ResourceURI {
		t.Fatalf("unexpected ACP facts: ok=%v facts=%#v", ok, facts)
	}
	facts, ok, err = PolicyFamilyFixtureFactsFromParseResult(acpResult, PolicySemanticsSAI)
	if err != nil {
		t.Fatalf("PolicyFamilyFixtureFactsFromParseResult non-match returned error: %v", err)
	}
	if ok || facts.FixtureName != "" {
		t.Fatalf("expected SAI filter to skip ACP result, got ok=%v facts=%#v", ok, facts)
	}
}

func TestParsePolicyFamilyFixtureFacts(t *testing.T) {
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
		facts, ok, err := ParsePolicyFamilyFixtureFacts(context.Background(), parser, fixtureCase.Request, fixtureCase.Family)
		if err != nil {
			t.Fatalf("ParsePolicyFamilyFixtureFacts returned error for %q: %v", fixtureCase.Name, err)
		}
		if !ok {
			t.Fatalf("expected fixture facts for %q", fixtureCase.Name)
		}
		if facts.Family != fixtureCase.Family || facts.TargetURI != fixtureCase.Request.ResourceURI {
			t.Fatalf("unexpected fixture facts for %q: %#v", fixtureCase.Name, facts)
		}
	}
}

func TestPolicyFamilyFixtureFactsFromSuiteIsDeterministic(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	left, err := PolicyFamilyFixtureFactsFromSuite(context.Background(), suite, PolicySemanticsSAI)
	if err != nil {
		t.Fatalf("left returned error: %v", err)
	}
	reversed := PolicySemanticsFixtureSuite{SchemaVersion: suite.SchemaVersion}
	for i := len(suite.Cases) - 1; i >= 0; i-- {
		reversed.Cases = append(reversed.Cases, suite.Cases[i])
	}
	right, err := PolicyFamilyFixtureFactsFromSuite(context.Background(), reversed, PolicySemanticsSAI)
	if err != nil {
		t.Fatalf("right returned error: %v", err)
	}
	if len(left) != len(right) || len(left) == 0 {
		t.Fatalf("unexpected facts counts: %d vs %d", len(left), len(right))
	}
	for i := range left {
		if left[i].FixtureName != right[i].FixtureName || left[i].RequestHash != right[i].RequestHash {
			t.Fatalf("facts order mismatch at %d: %#v vs %#v", i, left[i], right[i])
		}
	}
}

func TestValidatePolicyFamilyFixtureFactsRejectsInvalidInput(t *testing.T) {
	facts := mustFamilyFixtureFacts(t, PolicySemanticsACP)
	for _, test := range []struct {
		name  string
		facts PolicyFamilyFixtureFacts
	}{
		{name: "bad schema", facts: withFamilyFactsSchema(facts, "bad")},
		{name: "bad family", facts: withFamilyFactsFamily(facts, "bad")},
		{name: "bad hash", facts: withFamilyFactsRequestHash(facts, "bad")},
		{name: "bad target", facts: withFamilyFactsTarget(facts, "not-a-uri")},
		{name: "empty modes", facts: withFamilyFactsModes(facts, nil)},
		{name: "bad reason", facts: withFamilyFactsReason(facts, mismatchedReasonForDecision(facts.ExpectedDecision))},
		{name: "not fixture only", facts: withFamilyFactsFixtureOnly(facts, false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePolicyFamilyFixtureFacts(test.facts)
			if !errors.Is(err, ErrInvalidPolicyFamilyFixtureFacts) {
				t.Fatalf("error = %v, want ErrInvalidPolicyFamilyFixtureFacts", err)
			}
		})
	}
}

func TestPolicyFamilyFixtureFactsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := PolicyFamilyFixtureFactsFromSuite(ctx, readPolicySemanticsSuiteFixture(t), PolicySemanticsACP)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PolicyFamilyFixtureFactsFromSuite error = %v, want context.Canceled", err)
	}
	_, _, err = ParsePolicyFamilyFixtureFacts(ctx, nil, Request{}, PolicySemanticsSAI)
	if !errors.Is(err, ErrInvalidPolicyFamilyFixtureFacts) && !errors.Is(err, context.Canceled) {
		t.Fatalf("ParsePolicyFamilyFixtureFacts error = %v, want cancellation or fixture error", err)
	}
}

func mustFamilyFixtureFacts(t *testing.T, family PolicySemanticsFamily) PolicyFamilyFixtureFacts {
	t.Helper()
	facts, err := PolicyFamilyFixtureFactsFromSuite(context.Background(), readPolicySemanticsSuiteFixture(t), family)
	if err != nil {
		t.Fatalf("PolicyFamilyFixtureFactsFromSuite returned error: %v", err)
	}
	if len(facts) == 0 {
		t.Fatalf("expected facts for %q", family)
	}
	return facts[0]
}

func withFamilyFactsSchema(input PolicyFamilyFixtureFacts, schema string) PolicyFamilyFixtureFacts {
	input.SchemaVersion = schema
	return input
}

func withFamilyFactsFamily(input PolicyFamilyFixtureFacts, family PolicySemanticsFamily) PolicyFamilyFixtureFacts {
	input.Family = family
	return input
}

func withFamilyFactsRequestHash(input PolicyFamilyFixtureFacts, hash string) PolicyFamilyFixtureFacts {
	input.RequestHash = hash
	return input
}

func withFamilyFactsTarget(input PolicyFamilyFixtureFacts, target string) PolicyFamilyFixtureFacts {
	input.TargetURI = target
	return input
}

func withFamilyFactsModes(input PolicyFamilyFixtureFacts, modes []AccessMode) PolicyFamilyFixtureFacts {
	input.Modes = modes
	return input
}

func withFamilyFactsReason(input PolicyFamilyFixtureFacts, reason ReasonCode) PolicyFamilyFixtureFacts {
	input.ExpectedReason = reason
	return input
}

func withFamilyFactsFixtureOnly(input PolicyFamilyFixtureFacts, fixtureOnly bool) PolicyFamilyFixtureFacts {
	input.FixtureOnly = fixtureOnly
	return input
}
