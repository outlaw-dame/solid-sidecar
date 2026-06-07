package authz

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const PolicySemanticsFixtureSchemaVersion = "policy.semantics.fixtures.v1"

var ErrInvalidPolicySemanticsFixture = errors.New("invalid authz policy semantics fixture")

type PolicySemanticsFamily string

const (
	PolicySemanticsWAC PolicySemanticsFamily = "wac"
	PolicySemanticsACP PolicySemanticsFamily = "acp"
	PolicySemanticsSAI PolicySemanticsFamily = "sai"
)

type PolicySemanticsFixtureSuite struct {
	SchemaVersion string                       `json:"schema_version"`
	Cases         []PolicySemanticsFixtureCase `json:"cases"`
}

type PolicySemanticsFixtureCase struct {
	Name             string                `json:"name"`
	Family           PolicySemanticsFamily `json:"family"`
	Description      string                `json:"description,omitempty"`
	Request          Request               `json:"request"`
	PolicyDocuments  []PolicyDocument      `json:"policy_documents,omitempty"`
	ExpectedDecision DecisionValue         `json:"expected_decision"`
	ExpectedReason   ReasonCode            `json:"expected_reason_code"`
	ExpectedModes    []AccessMode          `json:"expected_modes,omitempty"`
}

func NormalizePolicySemanticsFixtureSuite(input PolicySemanticsFixtureSuite) (PolicySemanticsFixtureSuite, error) {
	if input.SchemaVersion != PolicySemanticsFixtureSchemaVersion {
		return PolicySemanticsFixtureSuite{}, fmt.Errorf("%w: unsupported fixture schema version", ErrInvalidPolicySemanticsFixture)
	}
	if len(input.Cases) == 0 {
		return PolicySemanticsFixtureSuite{}, fmt.Errorf("%w: fixture cases are required", ErrInvalidPolicySemanticsFixture)
	}
	seenNames := make(map[string]struct{}, len(input.Cases))
	cases := make([]PolicySemanticsFixtureCase, 0, len(input.Cases))
	for _, fixtureCase := range input.Cases {
		normalized, err := normalizePolicySemanticsFixtureCase(fixtureCase)
		if err != nil {
			return PolicySemanticsFixtureSuite{}, err
		}
		nameKey := strings.ToLower(normalized.Family.String() + ":" + normalized.Name)
		if _, exists := seenNames[nameKey]; exists {
			return PolicySemanticsFixtureSuite{}, fmt.Errorf("%w: duplicate fixture case name", ErrInvalidPolicySemanticsFixture)
		}
		seenNames[nameKey] = struct{}{}
		cases = append(cases, normalized)
	}
	sort.Slice(cases, func(i, j int) bool {
		if cases[i].Family != cases[j].Family {
			return cases[i].Family < cases[j].Family
		}
		return cases[i].Name < cases[j].Name
	})
	return PolicySemanticsFixtureSuite{SchemaVersion: PolicySemanticsFixtureSchemaVersion, Cases: cases}, nil
}

func normalizePolicySemanticsFixtureCase(input PolicySemanticsFixtureCase) (PolicySemanticsFixtureCase, error) {
	name := strings.TrimSpace(input.Name)
	if !validPolicySemanticsFixtureText(name, 128) {
		return PolicySemanticsFixtureCase{}, fmt.Errorf("%w: invalid fixture case name", ErrInvalidPolicySemanticsFixture)
	}
	family := input.Family
	if !validPolicySemanticsFamily(family) {
		return PolicySemanticsFixtureCase{}, fmt.Errorf("%w: invalid fixture family", ErrInvalidPolicySemanticsFixture)
	}
	description := strings.TrimSpace(input.Description)
	if description != "" && !validPolicySemanticsFixtureText(description, 512) {
		return PolicySemanticsFixtureCase{}, fmt.Errorf("%w: invalid fixture description", ErrInvalidPolicySemanticsFixture)
	}

	request := input.Request
	policyDocuments, err := NormalizePolicyDocuments(append(request.PolicyDocuments, input.PolicyDocuments...))
	if err != nil {
		return PolicySemanticsFixtureCase{}, err
	}
	request.PolicyDocuments = policyDocuments
	if request.PolicyVersion == "" {
		request.PolicyVersion = PolicyVersionForDocuments(policyDocuments)
	}
	if err := ValidateRequest(request); err != nil {
		return PolicySemanticsFixtureCase{}, err
	}
	if !validDecisionValue(input.ExpectedDecision) {
		return PolicySemanticsFixtureCase{}, fmt.Errorf("%w: invalid expected decision", ErrInvalidPolicySemanticsFixture)
	}
	if !expectedReasonMatchesDecision(input.ExpectedDecision, input.ExpectedReason) {
		return PolicySemanticsFixtureCase{}, fmt.Errorf("%w: expected reason does not match decision", ErrInvalidPolicySemanticsFixture)
	}
	modes, err := normalizePolicySemanticsModes(input.ExpectedModes)
	if err != nil {
		return PolicySemanticsFixtureCase{}, err
	}
	return PolicySemanticsFixtureCase{
		Name:             name,
		Family:           family,
		Description:      description,
		Request:          request,
		PolicyDocuments:  policyDocuments,
		ExpectedDecision: input.ExpectedDecision,
		ExpectedReason:   input.ExpectedReason,
		ExpectedModes:    modes,
	}, nil
}

func validPolicySemanticsFamily(family PolicySemanticsFamily) bool {
	switch family {
	case PolicySemanticsWAC, PolicySemanticsACP, PolicySemanticsSAI:
		return true
	default:
		return false
	}
}

func (family PolicySemanticsFamily) String() string {
	return string(family)
}

func expectedReasonMatchesDecision(decision DecisionValue, reason ReasonCode) bool {
	switch decision {
	case DecisionAllow:
		return reason == ReasonPolicyAllow
	case DecisionDeny:
		return reason == ReasonPolicyDeny
	case DecisionAbstain:
		return reason == ReasonKernelAbstainShadowMode || reason == ReasonPolicyNotLoaded
	default:
		return false
	}
}

func normalizePolicySemanticsModes(input []AccessMode) ([]AccessMode, error) {
	if len(input) == 0 {
		return nil, nil
	}
	seen := make(map[AccessMode]struct{}, len(input))
	out := make([]AccessMode, 0, len(input))
	for _, mode := range input {
		if !validAccessMode(mode) {
			return nil, fmt.Errorf("%w: invalid expected mode", ErrInvalidPolicySemanticsFixture)
		}
		if _, exists := seen[mode]; exists {
			return nil, fmt.Errorf("%w: duplicate expected mode", ErrInvalidPolicySemanticsFixture)
		}
		seen[mode] = struct{}{}
		out = append(out, mode)
	}
	sort.Slice(out, func(i, j int) bool {
		return accessModeRank(out[i]) < accessModeRank(out[j])
	})
	return out, nil
}

func validPolicySemanticsFixtureText(value string, maxLen int) bool {
	if value == "" || len(value) > maxLen {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
