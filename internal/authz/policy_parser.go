package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

const PolicyParseResultSchemaVersion = "policy.parse.result.v1"

var ErrInvalidPolicyParser = errors.New("invalid authz policy parser input")

type PolicySemanticsParser interface {
	ParsePolicySemantics(ctx context.Context, request Request) (PolicyParseResult, bool, error)
}

type PolicyParseResult struct {
	SchemaVersion    string                `json:"schema_version"`
	Family           PolicySemanticsFamily `json:"family"`
	FixtureName      string                `json:"fixture_name"`
	ResourceURI      string                `json:"resource_uri"`
	RequestHash      string                `json:"request_hash"`
	PolicyHash       string                `json:"policy_hash"`
	ExpectedDecision DecisionValue         `json:"expected_decision"`
	ExpectedReason   ReasonCode            `json:"expected_reason_code"`
	ExpectedModes    []AccessMode          `json:"expected_modes,omitempty"`
	PolicyDocuments  []PolicyDocument      `json:"policy_documents,omitempty"`
	FixtureOnly      bool                  `json:"fixture_only"`
}

type FixturePolicySemanticsParser struct {
	casesByRequestHash map[string]PolicySemanticsFixtureCase
}

func NewFixturePolicySemanticsParser(suite PolicySemanticsFixtureSuite) (*FixturePolicySemanticsParser, error) {
	normalized, err := NormalizePolicySemanticsFixtureSuite(suite)
	if err != nil {
		return nil, err
	}
	casesByRequestHash := make(map[string]PolicySemanticsFixtureCase, len(normalized.Cases))
	for _, fixtureCase := range normalized.Cases {
		audit := AuditForRequest(fixtureCase.Request)
		if _, exists := casesByRequestHash[audit.RequestHash]; exists {
			return nil, fmt.Errorf("%w: duplicate policy semantics fixture request hash", ErrInvalidPolicyParser)
		}
		casesByRequestHash[audit.RequestHash] = fixtureCase
	}
	return &FixturePolicySemanticsParser{casesByRequestHash: casesByRequestHash}, nil
}

func (p *FixturePolicySemanticsParser) ParsePolicySemantics(ctx context.Context, request Request) (PolicyParseResult, bool, error) {
	if p == nil {
		return PolicyParseResult{}, false, fmt.Errorf("%w: nil policy semantics parser", ErrInvalidPolicyParser)
	}
	if err := ctx.Err(); err != nil {
		return PolicyParseResult{}, false, err
	}
	if err := ValidateRequest(request); err != nil {
		return PolicyParseResult{}, false, err
	}
	audit := AuditForRequest(request)
	fixtureCase, ok := p.casesByRequestHash[audit.RequestHash]
	if !ok {
		return PolicyParseResult{}, false, nil
	}
	result := parseResultForFixtureCase(fixtureCase, audit)
	if err := ValidatePolicyParseResult(result); err != nil {
		return PolicyParseResult{}, false, err
	}
	return result, true, nil
}

func ParsePolicySemanticsFixtures(ctx context.Context, suite PolicySemanticsFixtureSuite) ([]PolicyParseResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	normalized, err := NormalizePolicySemanticsFixtureSuite(suite)
	if err != nil {
		return nil, err
	}
	results := make([]PolicyParseResult, 0, len(normalized.Cases))
	for _, fixtureCase := range normalized.Cases {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result := parseResultForFixtureCase(fixtureCase, AuditForRequest(fixtureCase.Request))
		if err := ValidatePolicyParseResult(result); err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	sortPolicyParseResults(results)
	return results, nil
}

func parseResultForFixtureCase(fixtureCase PolicySemanticsFixtureCase, audit AuditFields) PolicyParseResult {
	return PolicyParseResult{
		SchemaVersion:    PolicyParseResultSchemaVersion,
		Family:           fixtureCase.Family,
		FixtureName:      fixtureCase.Name,
		ResourceURI:      fixtureCase.Request.ResourceURI,
		RequestHash:      audit.RequestHash,
		PolicyHash:       audit.PolicyHash,
		ExpectedDecision: fixtureCase.ExpectedDecision,
		ExpectedReason:   fixtureCase.ExpectedReason,
		ExpectedModes:    append([]AccessMode(nil), fixtureCase.ExpectedModes...),
		PolicyDocuments:  append([]PolicyDocument(nil), fixtureCase.PolicyDocuments...),
		FixtureOnly:      true,
	}
}

func ValidatePolicyParseResult(result PolicyParseResult) error {
	if result.SchemaVersion != PolicyParseResultSchemaVersion {
		return fmt.Errorf("%w: unsupported parse result schema version", ErrInvalidPolicyParser)
	}
	if !validPolicySemanticsFamily(result.Family) {
		return fmt.Errorf("%w: invalid parse result family", ErrInvalidPolicyParser)
	}
	if !validPolicySemanticsFixtureText(result.FixtureName, 128) {
		return fmt.Errorf("%w: invalid parse result fixture name", ErrInvalidPolicyParser)
	}
	if !validResourceURI(result.ResourceURI) {
		return fmt.Errorf("%w: invalid parse result resource uri", ErrInvalidPolicyParser)
	}
	if !validSHA256Hex(result.RequestHash) || !validSHA256Hex(result.PolicyHash) {
		return fmt.Errorf("%w: invalid parse result hash", ErrInvalidPolicyParser)
	}
	if !validDecisionValue(result.ExpectedDecision) {
		return fmt.Errorf("%w: invalid parse result expected decision", ErrInvalidPolicyParser)
	}
	if !expectedReasonMatchesDecision(result.ExpectedDecision, result.ExpectedReason) {
		return fmt.Errorf("%w: parse result reason does not match decision", ErrInvalidPolicyParser)
	}
	if _, err := normalizePolicySemanticsModes(result.ExpectedModes); err != nil {
		return fmt.Errorf("%w: invalid parse result expected modes", ErrInvalidPolicyParser)
	}
	if _, err := NormalizePolicyDocuments(result.PolicyDocuments); err != nil {
		return fmt.Errorf("%w: invalid parse result policy documents", ErrInvalidPolicyParser)
	}
	if !result.FixtureOnly {
		return fmt.Errorf("%w: parse result must be fixture-only", ErrInvalidPolicyParser)
	}
	return nil
}

func sortPolicyParseResults(results []PolicyParseResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Family != results[j].Family {
			return results[i].Family < results[j].Family
		}
		if results[i].FixtureName != results[j].FixtureName {
			return results[i].FixtureName < results[j].FixtureName
		}
		return results[i].RequestHash < results[j].RequestHash
	})
}
