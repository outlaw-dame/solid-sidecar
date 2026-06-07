package authz

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFixturePolicySemanticsParserMatchesFixtureRequests(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	parser, err := NewFixturePolicySemanticsParser(suite)
	if err != nil {
		t.Fatalf("NewFixturePolicySemanticsParser returned error: %v", err)
	}
	results, err := ParsePolicySemanticsFixtures(context.Background(), suite)
	if err != nil {
		t.Fatalf("ParsePolicySemanticsFixtures returned error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected parse results")
	}

	normalized, err := NormalizePolicySemanticsFixtureSuite(suite)
	if err != nil {
		t.Fatalf("NormalizePolicySemanticsFixtureSuite returned error: %v", err)
	}
	for _, fixtureCase := range normalized.Cases {
		result, ok, err := parser.ParsePolicySemantics(context.Background(), fixtureCase.Request)
		if err != nil {
			t.Fatalf("ParsePolicySemantics returned error for %q: %v", fixtureCase.Name, err)
		}
		if !ok {
			t.Fatalf("expected fixture match for %q", fixtureCase.Name)
		}
		if result.FixtureName != fixtureCase.Name || result.Family != fixtureCase.Family {
			t.Fatalf("result = %#v, want fixture %q/%q", result, fixtureCase.Family, fixtureCase.Name)
		}
		if !result.FixtureOnly {
			t.Fatalf("result for %q was not fixture-only", fixtureCase.Name)
		}
	}
}

func TestFixturePolicySemanticsParserNoMatch(t *testing.T) {
	parser, err := NewFixturePolicySemanticsParser(readPolicySemanticsSuiteFixture(t))
	if err != nil {
		t.Fatalf("NewFixturePolicySemanticsParser returned error: %v", err)
	}
	request := validPolicySemanticsRequest("req-no-match", []AccessMode{AccessModeRead})
	request.PolicyDocuments = []PolicyDocument{{URI: "https://pod.example/policies/none.acl", SHA256: policyHashA, ContentType: "text/turtle"}}
	request.PolicyVersion = PolicyVersionForDocuments(request.PolicyDocuments)
	_, ok, err := parser.ParsePolicySemantics(context.Background(), request)
	if err != nil {
		t.Fatalf("ParsePolicySemantics returned error: %v", err)
	}
	if ok {
		t.Fatal("unexpected fixture match")
	}
}

func TestFixturePolicySemanticsParserContextCancellation(t *testing.T) {
	parser, err := NewFixturePolicySemanticsParser(readPolicySemanticsSuiteFixture(t))
	if err != nil {
		t.Fatalf("NewFixturePolicySemanticsParser returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = parser.ParsePolicySemantics(ctx, validPolicySemanticsRequest("req-canceled", []AccessMode{AccessModeRead}))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	_, err = ParsePolicySemanticsFixtures(ctx, readPolicySemanticsSuiteFixture(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("parse all error = %v, want context.Canceled", err)
	}
}

func TestParsePolicySemanticsFixturesIsDeterministic(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	left, err := ParsePolicySemanticsFixtures(context.Background(), suite)
	if err != nil {
		t.Fatalf("ParsePolicySemanticsFixtures left returned error: %v", err)
	}
	reversed := PolicySemanticsFixtureSuite{SchemaVersion: suite.SchemaVersion}
	for i := len(suite.Cases) - 1; i >= 0; i-- {
		reversed.Cases = append(reversed.Cases, suite.Cases[i])
	}
	right, err := ParsePolicySemanticsFixtures(context.Background(), reversed)
	if err != nil {
		t.Fatalf("ParsePolicySemanticsFixtures right returned error: %v", err)
	}
	if len(left) != len(right) {
		t.Fatalf("result count mismatch: %d vs %d", len(left), len(right))
	}
	for i := range left {
		if left[i].RequestHash != right[i].RequestHash || left[i].FixtureName != right[i].FixtureName {
			t.Fatalf("result order mismatch at %d: %#v vs %#v", i, left[i], right[i])
		}
	}
}

func TestValidatePolicyParseResultRejectsInvalidInput(t *testing.T) {
	results, err := ParsePolicySemanticsFixtures(context.Background(), readPolicySemanticsSuiteFixture(t))
	if err != nil {
		t.Fatalf("ParsePolicySemanticsFixtures returned error: %v", err)
	}
	valid := results[0]
	for _, test := range []struct {
		name   string
		result PolicyParseResult
	}{
		{name: "bad schema", result: withParseSchema(valid, "bad")},
		{name: "bad family", result: withParseFamily(valid, "bad")},
		{name: "bad reason", result: withParseReason(valid, mismatchedReasonForDecision(valid.ExpectedDecision))},
		{name: "bad hash", result: withParseRequestHash(valid, "bad")},
		{name: "not fixture only", result: withParseFixtureOnly(valid, false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePolicyParseResult(test.result)
			if !errors.Is(err, ErrInvalidPolicyParser) {
				t.Fatalf("error = %v, want ErrInvalidPolicyParser", err)
			}
		})
	}
}

func mismatchedReasonForDecision(decision DecisionValue) ReasonCode {
	if decision == DecisionDeny {
		return ReasonPolicyAllow
	}
	return ReasonPolicyDeny
}

func readPolicySemanticsSuiteFixture(t *testing.T) PolicySemanticsFixtureSuite {
	t.Helper()
	path := filepath.Join(fixtureDir(), "policy_semantics_manifest.json")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy semantics fixture manifest: %v", err)
	}
	var suite PolicySemanticsFixtureSuite
	if err := json.Unmarshal(bytes, &suite); err != nil {
		t.Fatalf("decode policy semantics fixture manifest: %v", err)
	}
	return suite
}

func withParseSchema(input PolicyParseResult, schema string) PolicyParseResult {
	input.SchemaVersion = schema
	return input
}

func withParseFamily(input PolicyParseResult, family PolicySemanticsFamily) PolicyParseResult {
	input.Family = family
	return input
}

func withParseReason(input PolicyParseResult, reason ReasonCode) PolicyParseResult {
	input.ExpectedReason = reason
	return input
}

func withParseRequestHash(input PolicyParseResult, hash string) PolicyParseResult {
	input.RequestHash = hash
	return input
}

func withParseFixtureOnly(input PolicyParseResult, fixtureOnly bool) PolicyParseResult {
	input.FixtureOnly = fixtureOnly
	return input
}
