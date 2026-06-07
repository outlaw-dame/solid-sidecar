package authz

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizePolicySemanticsFixtureSuite(t *testing.T) {
	suite := PolicySemanticsFixtureSuite{
		SchemaVersion: PolicySemanticsFixtureSchemaVersion,
		Cases: []PolicySemanticsFixtureCase{
			{
				Name:             "allow read",
				Family:           PolicySemanticsWAC,
				Request:          validPolicySemanticsRequest("req-allow", []AccessMode{AccessModeRead}),
				PolicyDocuments:  []PolicyDocument{{URI: "https://pod.example/policies/a.acl", SHA256: policyHashA, ContentType: "TEXT/TURTLE"}},
				ExpectedDecision: DecisionAllow,
				ExpectedReason:   ReasonPolicyAllow,
				ExpectedModes:    []AccessMode{AccessModeWrite, AccessModeRead},
			},
			{
				Name:             "deny write",
				Family:           PolicySemanticsACP,
				Request:          validPolicySemanticsRequest("req-deny", []AccessMode{AccessModeWrite}),
				PolicyDocuments:  []PolicyDocument{{URI: "https://pod.example/policies/b.acp", SHA256: policyHashB, ContentType: "application/ld+json"}},
				ExpectedDecision: DecisionDeny,
				ExpectedReason:   ReasonPolicyDeny,
			},
		},
	}

	normalized, err := NormalizePolicySemanticsFixtureSuite(suite)
	if err != nil {
		t.Fatalf("NormalizePolicySemanticsFixtureSuite returned error: %v", err)
	}
	if len(normalized.Cases) != 2 {
		t.Fatalf("case count = %d, want 2", len(normalized.Cases))
	}
	if normalized.Cases[0].Family != PolicySemanticsACP || normalized.Cases[1].Family != PolicySemanticsWAC {
		t.Fatalf("cases not sorted deterministically: %#v", normalized.Cases)
	}
	wacCase := normalized.Cases[1]
	if wacCase.Request.PolicyVersion == "" {
		t.Fatal("expected derived policy version")
	}
	if len(wacCase.ExpectedModes) != 2 || wacCase.ExpectedModes[0] != AccessModeRead || wacCase.ExpectedModes[1] != AccessModeWrite {
		t.Fatalf("expected modes not normalized: %#v", wacCase.ExpectedModes)
	}
	if err := ValidateRequest(wacCase.Request); err != nil {
		t.Fatalf("normalized request did not validate: %v", err)
	}
}

func TestNormalizePolicySemanticsFixtureSuiteRejectsInvalidInput(t *testing.T) {
	validCase := PolicySemanticsFixtureCase{
		Name:             "valid",
		Family:           PolicySemanticsWAC,
		Request:          validPolicySemanticsRequest("req-valid", []AccessMode{AccessModeRead}),
		PolicyDocuments:  []PolicyDocument{{URI: "https://pod.example/policies/a.acl", SHA256: policyHashA, ContentType: "text/turtle"}},
		ExpectedDecision: DecisionAllow,
		ExpectedReason:   ReasonPolicyAllow,
	}

	for _, test := range []struct {
		name  string
		suite PolicySemanticsFixtureSuite
	}{
		{name: "bad schema", suite: PolicySemanticsFixtureSuite{SchemaVersion: "bad", Cases: []PolicySemanticsFixtureCase{validCase}}},
		{name: "empty cases", suite: PolicySemanticsFixtureSuite{SchemaVersion: PolicySemanticsFixtureSchemaVersion}},
		{name: "bad family", suite: PolicySemanticsFixtureSuite{SchemaVersion: PolicySemanticsFixtureSchemaVersion, Cases: []PolicySemanticsFixtureCase{withFamily(validCase, "unknown")}}},
		{name: "reason mismatch", suite: PolicySemanticsFixtureSuite{SchemaVersion: PolicySemanticsFixtureSchemaVersion, Cases: []PolicySemanticsFixtureCase{withReason(validCase, ReasonPolicyDeny)}}},
		{name: "bad expected mode", suite: PolicySemanticsFixtureSuite{SchemaVersion: PolicySemanticsFixtureSchemaVersion, Cases: []PolicySemanticsFixtureCase{withModes(validCase, []AccessMode{"bad"})}}},
		{name: "duplicate name", suite: PolicySemanticsFixtureSuite{SchemaVersion: PolicySemanticsFixtureSchemaVersion, Cases: []PolicySemanticsFixtureCase{validCase, validCase}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizePolicySemanticsFixtureSuite(test.suite)
			if !errors.Is(err, ErrInvalidPolicySemanticsFixture) {
				t.Fatalf("error = %v, want ErrInvalidPolicySemanticsFixture", err)
			}
		})
	}
}

func TestSharedPolicySemanticsFixturesNormalize(t *testing.T) {
	path := filepath.Join(fixtureDir(), "policy_semantics_manifest.json")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy semantics fixture manifest: %v", err)
	}
	var suite PolicySemanticsFixtureSuite
	if err := json.Unmarshal(bytes, &suite); err != nil {
		t.Fatalf("decode policy semantics fixture manifest: %v", err)
	}
	normalized, err := NormalizePolicySemanticsFixtureSuite(suite)
	if err != nil {
		t.Fatalf("NormalizePolicySemanticsFixtureSuite returned error: %v", err)
	}
	families := map[PolicySemanticsFamily]bool{}
	for _, fixtureCase := range normalized.Cases {
		families[fixtureCase.Family] = true
		if fixtureCase.Request.PolicyVersion == "" {
			t.Fatalf("case %q missing policy version", fixtureCase.Name)
		}
	}
	for _, family := range []PolicySemanticsFamily{PolicySemanticsWAC, PolicySemanticsACP, PolicySemanticsSAI} {
		if !families[family] {
			t.Fatalf("shared fixtures missing family %q", family)
		}
	}
}

func validPolicySemanticsRequest(requestID string, modes []AccessMode) Request {
	return Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      requestID,
		Method:         "GET",
		ResourceURI:    "https://pod.example/alice/card",
		RequestedModes: modes,
		NowUnix:        fixedNow().Unix(),
	}
}

func withFamily(input PolicySemanticsFixtureCase, family PolicySemanticsFamily) PolicySemanticsFixtureCase {
	input.Family = family
	return input
}

func withReason(input PolicySemanticsFixtureCase, reason ReasonCode) PolicySemanticsFixtureCase {
	input.ExpectedReason = reason
	return input
}

func withModes(input PolicySemanticsFixtureCase, modes []AccessMode) PolicySemanticsFixtureCase {
	input.ExpectedModes = modes
	return input
}
