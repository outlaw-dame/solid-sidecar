package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

const PolicyFamilyFixtureFactsSchemaVersion = "policy.family.fixture_facts.v1"

var ErrInvalidPolicyFamilyFixtureFacts = errors.New("invalid authz policy family fixture facts")

type PolicyFamilyFixtureFacts struct {
	SchemaVersion    string                `json:"schema_version"`
	Family           PolicySemanticsFamily `json:"family"`
	FixtureName      string                `json:"fixture_name"`
	RequestHash      string                `json:"request_hash"`
	PolicyHash       string                `json:"policy_hash"`
	TargetURI        string                `json:"target_uri"`
	Modes            []AccessMode          `json:"modes"`
	ExpectedDecision DecisionValue         `json:"expected_decision"`
	ExpectedReason   ReasonCode            `json:"expected_reason_code"`
	PolicyDocuments  []PolicyDocument      `json:"policy_documents"`
	FixtureOnly      bool                  `json:"fixture_only"`
}

func PolicyFamilyFixtureFactsFromParseResult(result PolicyParseResult, family PolicySemanticsFamily) (PolicyFamilyFixtureFacts, bool, error) {
	if !validPolicySemanticsFamily(family) {
		return PolicyFamilyFixtureFacts{}, false, fmt.Errorf("%w: invalid fixture family", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if result.Family != family {
		return PolicyFamilyFixtureFacts{}, false, nil
	}
	if err := ValidatePolicyParseResult(result); err != nil {
		return PolicyFamilyFixtureFacts{}, false, err
	}
	modes, err := normalizePolicySemanticsModes(result.ExpectedModes)
	if err != nil {
		return PolicyFamilyFixtureFacts{}, false, fmt.Errorf("%w: invalid fixture modes", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if len(modes) == 0 {
		return PolicyFamilyFixtureFacts{}, false, fmt.Errorf("%w: fixture modes are required", ErrInvalidPolicyFamilyFixtureFacts)
	}
	documents, err := NormalizePolicyDocuments(result.PolicyDocuments)
	if err != nil {
		return PolicyFamilyFixtureFacts{}, false, err
	}
	if len(documents) == 0 {
		return PolicyFamilyFixtureFacts{}, false, fmt.Errorf("%w: fixture documents are required", ErrInvalidPolicyFamilyFixtureFacts)
	}
	facts := PolicyFamilyFixtureFacts{
		SchemaVersion:    PolicyFamilyFixtureFactsSchemaVersion,
		Family:           family,
		FixtureName:      result.FixtureName,
		RequestHash:      result.RequestHash,
		PolicyHash:       result.PolicyHash,
		TargetURI:        result.ResourceURI,
		Modes:            modes,
		ExpectedDecision: result.ExpectedDecision,
		ExpectedReason:   result.ExpectedReason,
		PolicyDocuments:  documents,
		FixtureOnly:      true,
	}
	if err := ValidatePolicyFamilyFixtureFacts(facts); err != nil {
		return PolicyFamilyFixtureFacts{}, false, err
	}
	return facts, true, nil
}

func ParsePolicyFamilyFixtureFacts(ctx context.Context, parser PolicySemanticsParser, request Request, family PolicySemanticsFamily) (PolicyFamilyFixtureFacts, bool, error) {
	if parser == nil {
		return PolicyFamilyFixtureFacts{}, false, fmt.Errorf("%w: nil policy semantics parser", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if err := ctx.Err(); err != nil {
		return PolicyFamilyFixtureFacts{}, false, err
	}
	result, ok, err := parser.ParsePolicySemantics(ctx, request)
	if err != nil || !ok {
		return PolicyFamilyFixtureFacts{}, false, err
	}
	return PolicyFamilyFixtureFactsFromParseResult(result, family)
}

func PolicyFamilyFixtureFactsFromSuite(ctx context.Context, suite PolicySemanticsFixtureSuite, family PolicySemanticsFamily) ([]PolicyFamilyFixtureFacts, error) {
	if !validPolicySemanticsFamily(family) {
		return nil, fmt.Errorf("%w: invalid fixture family", ErrInvalidPolicyFamilyFixtureFacts)
	}
	results, err := ParsePolicySemanticsFixtures(ctx, suite)
	if err != nil {
		return nil, err
	}
	facts := make([]PolicyFamilyFixtureFacts, 0, len(results))
	for _, result := range results {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		familyFacts, ok, err := PolicyFamilyFixtureFactsFromParseResult(result, family)
		if err != nil {
			return nil, err
		}
		if ok {
			facts = append(facts, familyFacts)
		}
	}
	sortPolicyFamilyFixtureFacts(facts)
	return facts, nil
}

func ValidatePolicyFamilyFixtureFacts(facts PolicyFamilyFixtureFacts) error {
	if facts.SchemaVersion != PolicyFamilyFixtureFactsSchemaVersion {
		return fmt.Errorf("%w: unsupported fixture facts schema version", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if !validPolicySemanticsFamily(facts.Family) {
		return fmt.Errorf("%w: invalid fixture family", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if !validPolicySemanticsFixtureText(facts.FixtureName, 128) {
		return fmt.Errorf("%w: invalid fixture name", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if !validSHA256Hex(facts.RequestHash) || !validSHA256Hex(facts.PolicyHash) {
		return fmt.Errorf("%w: invalid fixture hash", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if !validResourceURI(facts.TargetURI) {
		return fmt.Errorf("%w: invalid fixture target", ErrInvalidPolicyFamilyFixtureFacts)
	}
	modes, err := normalizePolicySemanticsModes(facts.Modes)
	if err != nil {
		return fmt.Errorf("%w: invalid fixture modes", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if len(modes) == 0 {
		return fmt.Errorf("%w: fixture modes are required", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if !validDecisionValue(facts.ExpectedDecision) {
		return fmt.Errorf("%w: invalid fixture expected decision", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if !expectedReasonMatchesDecision(facts.ExpectedDecision, facts.ExpectedReason) {
		return fmt.Errorf("%w: fixture reason does not match decision", ErrInvalidPolicyFamilyFixtureFacts)
	}
	documents, err := NormalizePolicyDocuments(facts.PolicyDocuments)
	if err != nil {
		return err
	}
	if len(documents) == 0 {
		return fmt.Errorf("%w: fixture documents are required", ErrInvalidPolicyFamilyFixtureFacts)
	}
	if !facts.FixtureOnly {
		return fmt.Errorf("%w: fixture facts must be fixture-only", ErrInvalidPolicyFamilyFixtureFacts)
	}
	return nil
}

func sortPolicyFamilyFixtureFacts(facts []PolicyFamilyFixtureFacts) {
	sort.Slice(facts, func(i, j int) bool {
		if facts[i].Family != facts[j].Family {
			return facts[i].Family < facts[j].Family
		}
		if facts[i].FixtureName != facts[j].FixtureName {
			return facts[i].FixtureName < facts[j].FixtureName
		}
		return facts[i].RequestHash < facts[j].RequestHash
	})
}
