package authz

import (
	"fmt"
	"sort"
	"strings"
)

const PolicyFixtureReleaseLedgerSchemaVersion = "policy.fixture.release_ledger.v1"

type PolicyFixtureReleaseLedger struct {
	SchemaVersion string                       `json:"schema_version"`
	Records       []PolicyFixtureReleaseRecord `json:"records"`
	FixtureOnly   bool                         `json:"fixture_only"`
	LedgerHash    string                       `json:"ledger_hash"`
}

func PolicyFixtureReleaseLedgerFromRecords(records []PolicyFixtureReleaseRecord) (PolicyFixtureReleaseLedger, error) {
	normalized, err := NormalizePolicyFixtureReleaseRecords(records)
	if err != nil { return PolicyFixtureReleaseLedger{}, err }
	if len(normalized) == 0 { return PolicyFixtureReleaseLedger{}, fmt.Errorf("%w: release records are required", ErrInvalidPolicyFixtureRelease) }
	ledger := PolicyFixtureReleaseLedger{SchemaVersion: PolicyFixtureReleaseLedgerSchemaVersion, Records: normalized, FixtureOnly: true}
	ledger.LedgerHash = PolicyFixtureReleaseLedgerHash(ledger)
	if err := ValidatePolicyFixtureReleaseLedger(ledger); err != nil { return PolicyFixtureReleaseLedger{}, err }
	return ledger, nil
}

func NormalizePolicyFixtureReleaseRecords(records []PolicyFixtureReleaseRecord) ([]PolicyFixtureReleaseRecord, error) {
	seen := map[string]PolicyFixtureReleaseRecord{}
	for _, record := range records {
		if err := ValidatePolicyFixtureReleaseRecord(record); err != nil { return nil, err }
		if existing, ok := seen[record.ReleaseHash]; ok {
			if existing.BundleHash != record.BundleHash || existing.ManifestHash != record.ManifestHash { return nil, fmt.Errorf("%w: conflicting release record", ErrInvalidPolicyFixtureRelease) }
			continue
		}
		seen[record.ReleaseHash] = record
	}
	out := make([]PolicyFixtureReleaseRecord, 0, len(seen))
	for _, record := range seen { out = append(out, record) }
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAtUnix != out[j].CreatedAtUnix { return out[i].CreatedAtUnix < out[j].CreatedAtUnix }
		return out[i].ReleaseHash < out[j].ReleaseHash
	})
	return out, nil
}

func ValidatePolicyFixtureReleaseLedger(ledger PolicyFixtureReleaseLedger) error {
	if ledger.SchemaVersion != PolicyFixtureReleaseLedgerSchemaVersion || !ledger.FixtureOnly { return fmt.Errorf("%w: invalid release ledger metadata", ErrInvalidPolicyFixtureRelease) }
	if len(ledger.Records) == 0 { return fmt.Errorf("%w: release ledger records are required", ErrInvalidPolicyFixtureRelease) }
	if _, err := NormalizePolicyFixtureReleaseRecords(ledger.Records); err != nil { return err }
	if !validSHA256Hex(ledger.LedgerHash) || PolicyFixtureReleaseLedgerHash(ledger) != ledger.LedgerHash { return fmt.Errorf("%w: release ledger hash mismatch", ErrInvalidPolicyFixtureRelease) }
	return nil
}

func PolicyFixtureReleaseLedgerHash(ledger PolicyFixtureReleaseLedger) string {
	records, err := NormalizePolicyFixtureReleaseRecords(ledger.Records)
	if err != nil { return "" }
	parts := []string{ledger.SchemaVersion}
	for _, record := range records { parts = append(parts, record.ReleaseHash) }
	return sha256Hex(strings.Join(parts, "\x1f"))
}
