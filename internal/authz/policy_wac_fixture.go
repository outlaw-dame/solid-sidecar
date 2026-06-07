package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

const WACFixtureFactsSchemaVersion = "policy.wac.fixture_facts.v1"

var ErrInvalidWACFixtureFacts = errors.New("invalid authz wac fixture facts")

type WACFixtureFacts struct {
	SchemaVersion   string           `json:"schema_version"`
	FixtureName     string           `json:"fixture_name"`
	RequestHash     string           `json:"request_hash"`
	PolicyHash      string           `json:"policy_hash"`
	TargetURI       string           `json:"target_uri"`
	Modes           []AccessMode     `json:"modes"`
	ExpectedDecision DecisionValue    `json:"expected_decision"`
	ExpectedReason   ReasonCode       `json:"expected_reason_code"`
	PolicyDocuments  []PolicyDocument `json:"policy_documents"`
	FixtureOnly      bool             `json:"fixture_only"`
}

func WACFixtureFactsFromParseResult(result PolicyParseResult) (WACFixtureFacts, bool, error) {
	if result.Family != PolicySemanticsWAC {
		return WACFixtureFacts{}, false, nil
	}
	if err := ValidatePolicyParseResult(result); err != nil {
		return WACFixtureFacts{}, false, err
	}
	modes, err := normalizePolicySemanticsModes(result.ExpectedModes)
	if err != nil {
		return WACFixtureFacts{}, false, fmt.Errorf("%w: invalid wac fixture modes", ErrInvalidWACFixtureFacts)
	}
	if len(modes) == 0 {
		return WACFixtureFacts{}, false, fmt.Errorf("%w: wac fixture modes are required", ErrInvalidWACFixtureFacts)
	}
	documents, err := NormalizePolicyDocuments(result.PolicyDocuments)
	if err != nil {
		return WACFixtureFacts{}, false, err
	}
	if len(documents) == 0 {
		return WACFixtureFacts{}, false, fmt.Errorf("%w: wac fixture policy documents are required", ErrInvalidWACFixtureFacts)
	}
	facts := WACFixtureFacts{
		SchemaVersion:   WACFixtureFactsSchemaVersion,
		FixtureName:     result.FixtureName,
		RequestHash:     result.RequestHash,
		PolicyHash:      result.PolicyHash,
		TargetURI:       documents[0].URI,
		Modes:           modes,
		ExpectedDecision: result.ExpectedDecision,
		ExpectedReason:   result.ExpectedReason,
		PolicyDocuments:  documents,
		FixtureOnly:      true,
	}
	if err := ValidateWACFixtureFacts(facts); err != nil {
		return WACFixtureFacts{}, false, err
	}
	return facts, true, nil
}

func ParseWACFixtureFacts(ctx context.Context, parser PolicySemanticsParser, request Request) (WACFixtureFacts, bool, error) {
	if parser == nil {
		return WACFixtureFacts{}, false, fmt.Errorf("%w: nil policy semantics parser", ErrInvalidWACFixtureFacts)
	}
	if err := ctx.Err(); err != nil {
		return WACFixtureFacts{}, false, err
	}
	result, ok, err := parser.ParsePolicySemantics(ctx, request)
	if err != nil || !ok {
		return WACFixtureFacts{}, false, err
	}
	return WACFixtureFactsFromParseResult(result)
}

func WACFixtureFactsFromSuite(ctx context.Context, suite PolicySemanticsFixtureSuite) ([]WACFixtureFacts, error) {
	results, err := ParsePolicySemanticsFixtures(ctx, suite)
	if err != nil {
		return nil, err
	}
	facts := make([]WACFixtureFacts, 0, len(results))
	for _, result := range results {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		wacFacts, ok, err := WACFixtureFactsFromParseResult(result)
		if err != nil {
			return nil, err
		}
		if ok {
			facts = append(facts, wacFacts)
		}
	}
	sortWACFixtureFacts(facts)
	return facts, nil
}

func ValidateWACFixtureFacts(facts WACFixtureFacts) error {
	if facts.SchemaVersion != WACFixtureFactsSchemaVersion {
		return fmt.Errorf("%w: unsupported wac fixture facts schema version", ErrInvalidWACFixtureFacts)
	}
	if !validPolicySemanticsFixtureText(facts.FixtureName, 128) {
		return fmt.Errorf("%w: invalid wac fixture name", ErrInvalidWACFixtureFacts)
	}
	if !validSHA256Hex(facts.RequestHash) || !validSHA256Hex(facts.PolicyHash) {
		return fmt.Errorf("%w: invalid wac fixture hash", ErrInvalidWACFixtureFacts)
	}
	if !validResourceURI(facts.TargetURI) {
		return fmt.Errorf("%w: invalid wac fixture target", ErrInvalidWACFixtureFacts)
	}
	modes, err := normalizePolicySemanticsModes(facts.Modes)
	if err != nil {
		return fmt.Errorf("%w: invalid wac fixture modes", ErrInvalidWACFixtureFacts)
	}
	if len(modes) == 0 {
		return fmt.Errorf("%w: wac fixture modes are required", ErrInvalidWACFixtureFacts)
	}
	if !validDecisionValue(facts.ExpectedDecision) {
		return fmt.Errorf("%w: invalid wac fixture expected decision", ErrInvalidWACFixtureFacts)
	}
	if !expectedReasonMatchesDecision(facts.ExpectedDecision, facts.ExpectedReason) {
		return fmt.Errorf("%w: wac fixture reason does not match decision", ErrInvalidWACFixtureFacts)
	}
	documents, err := NormalizePolicyDocuments(facts.PolicyDocuments)
	if err != nil {
		return err
	}
	if len(documents) == 0 {
		return fmt.Errorf("%w: wac fixture policy documents are required", ErrInvalidWACFixtureFacts)
	}
	if facts.TargetURI != documents[0].URI {
		return fmt.Errorf("%w: wac fixture target must match first policy document", ErrInvalidWACFixtureFacts)
	}
	if !facts.FixtureOnly {
		return fmt.Errorf("%w: wac fixture facts must be fixture-only", ErrInvalidWACFixtureFacts)
	}
	return nil
}

func sortWACFixtureFacts(facts []WACFixtureFacts) {
	sort.Slice(facts, func(i, j int) bool {
		if facts[i].FixtureName != facts[j].FixtureName {
			return facts[i].FixtureName < facts[j].FixtureName
		}
		return facts[i].RequestHash < facts[j].RequestHash
	})
}
