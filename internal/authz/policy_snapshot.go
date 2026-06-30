package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const PolicyFixtureSnapshotSchemaVersion = "policy.fixture.snapshot.v1"
const PolicyFixtureSummarySchemaVersion = "policy.fixture.summary.v1"

var ErrInvalidPolicyFixtureSnapshot = errors.New("invalid authz policy fixture snapshot")

type PolicyFixtureSnapshot struct {
	SchemaVersion    string                `json:"schema_version"`
	Family           PolicySemanticsFamily `json:"family"`
	FixtureName      string                `json:"fixture_name"`
	RequestHash      string                `json:"request_hash"`
	PolicyHash       string                `json:"policy_hash"`
	TargetURI        string                `json:"target_uri"`
	Modes            []AccessMode          `json:"modes"`
	ExpectedDecision DecisionValue         `json:"expected_decision"`
	ExpectedReason   ReasonCode            `json:"expected_reason_code"`
	DocumentCount    int                   `json:"document_count"`
	FixtureOnly      bool                  `json:"fixture_only"`
	SnapshotHash     string                `json:"snapshot_hash"`
}

type PolicyFixtureSummary struct {
	SchemaVersion  string                       `json:"schema_version"`
	SnapshotCount  int                          `json:"snapshot_count"`
	FamilyCounts   []PolicyFixtureFamilyCount   `json:"family_counts"`
	DecisionCounts []PolicyFixtureDecisionCount `json:"result_counts"`
	ModeCounts     []PolicyFixtureModeCount     `json:"mode_counts"`
	FixtureOnly    bool                         `json:"fixture_only"`
	SummaryHash    string                       `json:"rollup_hash"`
}

type PolicyFixtureFamilyCount struct {
	Family PolicySemanticsFamily `json:"family"`
	Count  int                   `json:"count"`
}

type PolicyFixtureDecisionCount struct {
	Decision DecisionValue `json:"decision"`
	Count    int           `json:"count"`
}

type PolicyFixtureModeCount struct {
	Mode  AccessMode `json:"mode"`
	Count int        `json:"count"`
}

func PolicyFixtureSnapshotsFromSuite(ctx context.Context, suite PolicySemanticsFixtureSuite) ([]PolicyFixtureSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results, err := ParsePolicySemanticsFixtures(ctx, suite)
	if err != nil {
		return nil, err
	}
	snapshots := make([]PolicyFixtureSnapshot, 0, len(results))
	for _, result := range results {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		snapshot, err := PolicyFixtureSnapshotFromParseResult(result)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	sortPolicyFixtureSnapshots(snapshots)
	return snapshots, nil
}

func PolicyFixtureSnapshotFromParseResult(result PolicyParseResult) (PolicyFixtureSnapshot, error) {
	if err := ValidatePolicyParseResult(result); err != nil {
		return PolicyFixtureSnapshot{}, err
	}
	modes, err := normalizePolicySemanticsModes(result.ExpectedModes)
	if err != nil {
		return PolicyFixtureSnapshot{}, fmt.Errorf("%w: invalid snapshot modes", ErrInvalidPolicyFixtureSnapshot)
	}
	if len(modes) == 0 {
		return PolicyFixtureSnapshot{}, fmt.Errorf("%w: snapshot modes are required", ErrInvalidPolicyFixtureSnapshot)
	}
	documents, err := NormalizePolicyDocuments(result.PolicyDocuments)
	if err != nil {
		return PolicyFixtureSnapshot{}, err
	}
	if len(documents) == 0 {
		return PolicyFixtureSnapshot{}, fmt.Errorf("%w: snapshot documents are required", ErrInvalidPolicyFixtureSnapshot)
	}
	snapshot := PolicyFixtureSnapshot{
		SchemaVersion:    PolicyFixtureSnapshotSchemaVersion,
		Family:           result.Family,
		FixtureName:      result.FixtureName,
		RequestHash:      result.RequestHash,
		PolicyHash:       result.PolicyHash,
		TargetURI:        result.ResourceURI,
		Modes:            modes,
		ExpectedDecision: result.ExpectedDecision,
		ExpectedReason:   result.ExpectedReason,
		DocumentCount:    len(documents),
		FixtureOnly:      true,
	}
	snapshot.SnapshotHash = PolicyFixtureSnapshotHash(snapshot)
	if err := ValidatePolicyFixtureSnapshot(snapshot); err != nil {
		return PolicyFixtureSnapshot{}, err
	}
	return snapshot, nil
}

func ValidatePolicyFixtureSnapshot(snapshot PolicyFixtureSnapshot) error {
	if snapshot.SchemaVersion != PolicyFixtureSnapshotSchemaVersion {
		return fmt.Errorf("%w: unsupported snapshot schema version", ErrInvalidPolicyFixtureSnapshot)
	}
	if !validPolicySemanticsFamily(snapshot.Family) {
		return fmt.Errorf("%w: invalid snapshot family", ErrInvalidPolicyFixtureSnapshot)
	}
	if !validPolicySemanticsFixtureText(snapshot.FixtureName, 128) {
		return fmt.Errorf("%w: invalid snapshot fixture name", ErrInvalidPolicyFixtureSnapshot)
	}
	if !validSHA256Hex(snapshot.RequestHash) || !validSHA256Hex(snapshot.PolicyHash) || !validSHA256Hex(snapshot.SnapshotHash) {
		return fmt.Errorf("%w: invalid snapshot hash", ErrInvalidPolicyFixtureSnapshot)
	}
	if !validResourceURI(snapshot.TargetURI) {
		return fmt.Errorf("%w: invalid snapshot target", ErrInvalidPolicyFixtureSnapshot)
	}
	modes, err := normalizePolicySemanticsModes(snapshot.Modes)
	if err != nil || len(modes) == 0 {
		return fmt.Errorf("%w: invalid snapshot modes", ErrInvalidPolicyFixtureSnapshot)
	}
	if !validDecisionValue(snapshot.ExpectedDecision) {
		return fmt.Errorf("%w: invalid snapshot expected decision", ErrInvalidPolicyFixtureSnapshot)
	}
	if !expectedReasonMatchesDecision(snapshot.ExpectedDecision, snapshot.ExpectedReason) {
		return fmt.Errorf("%w: snapshot reason does not match decision", ErrInvalidPolicyFixtureSnapshot)
	}
	if snapshot.DocumentCount <= 0 {
		return fmt.Errorf("%w: snapshot document count must be positive", ErrInvalidPolicyFixtureSnapshot)
	}
	if !snapshot.FixtureOnly {
		return fmt.Errorf("%w: snapshot must be fixture-only", ErrInvalidPolicyFixtureSnapshot)
	}
	if PolicyFixtureSnapshotHash(snapshot) != snapshot.SnapshotHash {
		return fmt.Errorf("%w: snapshot hash mismatch", ErrInvalidPolicyFixtureSnapshot)
	}
	return nil
}

func PolicyFixtureSnapshotHash(snapshot PolicyFixtureSnapshot) string {
	modes, err := normalizePolicySemanticsModes(snapshot.Modes)
	if err != nil {
		return ""
	}
	parts := []string{
		snapshot.SchemaVersion,
		string(snapshot.Family),
		snapshot.FixtureName,
		snapshot.RequestHash,
		snapshot.PolicyHash,
		snapshot.TargetURI,
		string(snapshot.ExpectedDecision),
		string(snapshot.ExpectedReason),
		fmt.Sprintf("%010d", snapshot.DocumentCount),
	}
	for _, mode := range modes {
		parts = append(parts, string(mode))
	}
	return sha256Hex(strings.Join(parts, "\x1f"))
}

func PolicyFixtureSummaryFromSnapshots(snapshots []PolicyFixtureSnapshot) (PolicyFixtureSummary, error) {
	normalized, err := NormalizePolicyFixtureSnapshots(snapshots)
	if err != nil {
		return PolicyFixtureSummary{}, err
	}
	familyCounts := make(map[PolicySemanticsFamily]int)
	decisionCounts := make(map[DecisionValue]int)
	modeCounts := make(map[AccessMode]int)
	for _, snapshot := range normalized {
		familyCounts[snapshot.Family]++
		decisionCounts[snapshot.ExpectedDecision]++
		for _, mode := range snapshot.Modes {
			modeCounts[mode]++
		}
	}
	summary := PolicyFixtureSummary{
		SchemaVersion:  PolicyFixtureSummarySchemaVersion,
		SnapshotCount:  len(normalized),
		FamilyCounts:   sortedFamilyCounts(familyCounts),
		DecisionCounts: sortedDecisionCounts(decisionCounts),
		ModeCounts:     sortedModeCounts(modeCounts),
		FixtureOnly:    true,
	}
	summary.SummaryHash = PolicyFixtureSummaryHash(summary)
	if err := ValidatePolicyFixtureSummary(summary); err != nil {
		return PolicyFixtureSummary{}, err
	}
	return summary, nil
}

func NormalizePolicyFixtureSnapshots(input []PolicyFixtureSnapshot) ([]PolicyFixtureSnapshot, error) {
	if len(input) == 0 {
		return nil, nil
	}
	seen := make(map[string]PolicyFixtureSnapshot, len(input))
	for _, snapshot := range input {
		if err := ValidatePolicyFixtureSnapshot(snapshot); err != nil {
			return nil, err
		}
		if existing, ok := seen[snapshot.SnapshotHash]; ok {
			if existing.RequestHash != snapshot.RequestHash || existing.PolicyHash != snapshot.PolicyHash {
				return nil, fmt.Errorf("%w: conflicting snapshot hash", ErrInvalidPolicyFixtureSnapshot)
			}
			continue
		}
		seen[snapshot.SnapshotHash] = snapshot
	}
	out := make([]PolicyFixtureSnapshot, 0, len(seen))
	for _, snapshot := range seen {
		out = append(out, snapshot)
	}
	sortPolicyFixtureSnapshots(out)
	return out, nil
}

func ValidatePolicyFixtureSummary(summary PolicyFixtureSummary) error {
	if summary.SchemaVersion != PolicyFixtureSummarySchemaVersion {
		return fmt.Errorf("%w: unsupported summary schema version", ErrInvalidPolicyFixtureSnapshot)
	}
	if summary.SnapshotCount < 0 {
		return fmt.Errorf("%w: negative snapshot count", ErrInvalidPolicyFixtureSnapshot)
	}
	if !summary.FixtureOnly {
		return fmt.Errorf("%w: summary must be fixture-only", ErrInvalidPolicyFixtureSnapshot)
	}
	if !validSHA256Hex(summary.SummaryHash) || PolicyFixtureSummaryHash(summary) != summary.SummaryHash {
		return fmt.Errorf("%w: invalid summary hash", ErrInvalidPolicyFixtureSnapshot)
	}
	return nil
}

func PolicyFixtureSummaryHash(summary PolicyFixtureSummary) string {
	parts := []string{summary.SchemaVersion, fmt.Sprintf("%010d", summary.SnapshotCount)}
	for _, item := range summary.FamilyCounts {
		parts = append(parts, "family", string(item.Family), fmt.Sprintf("%010d", item.Count))
	}
	for _, item := range summary.DecisionCounts {
		parts = append(parts, "decision", string(item.Decision), fmt.Sprintf("%010d", item.Count))
	}
	for _, item := range summary.ModeCounts {
		parts = append(parts, "mode", string(item.Mode), fmt.Sprintf("%010d", item.Count))
	}
	return sha256Hex(strings.Join(parts, "\x1f"))
}

func sortPolicyFixtureSnapshots(snapshots []PolicyFixtureSnapshot) {
	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].Family != snapshots[j].Family {
			return snapshots[i].Family < snapshots[j].Family
		}
		if snapshots[i].FixtureName != snapshots[j].FixtureName {
			return snapshots[i].FixtureName < snapshots[j].FixtureName
		}
		return snapshots[i].SnapshotHash < snapshots[j].SnapshotHash
	})
}

func sortedFamilyCounts(counts map[PolicySemanticsFamily]int) []PolicyFixtureFamilyCount {
	out := make([]PolicyFixtureFamilyCount, 0, len(counts))
	for family, count := range counts {
		out = append(out, PolicyFixtureFamilyCount{Family: family, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}

func sortedDecisionCounts(counts map[DecisionValue]int) []PolicyFixtureDecisionCount {
	out := make([]PolicyFixtureDecisionCount, 0, len(counts))
	for decision, count := range counts {
		out = append(out, PolicyFixtureDecisionCount{Decision: decision, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Decision < out[j].Decision })
	return out
}

func sortedModeCounts(counts map[AccessMode]int) []PolicyFixtureModeCount {
	out := make([]PolicyFixtureModeCount, 0, len(counts))
	for mode, count := range counts {
		out = append(out, PolicyFixtureModeCount{Mode: mode, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return accessModeRank(out[i].Mode) < accessModeRank(out[j].Mode) })
	return out
}
