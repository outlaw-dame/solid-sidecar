package authz

import (
	"fmt"
	"strings"
)

const PolicyFixtureMarkerRecordSchemaVersion = "policy.fixture.marker.v1"

type PolicyFixtureMarkerRecord struct {
	SchemaVersion string `json:"schema_version"`
	ReleaseHash string `json:"release_hash"`
	LedgerHash string `json:"ledger_hash"`
	ReviewHash string `json:"review_hash"`
	Label string `json:"label"`
	CreatedAtUnix int64 `json:"created_at_unix"`
	FixtureOnly bool `json:"fixture_only"`
	MarkerHash string `json:"marker_hash"`
}

func PolicyFixtureMarkerRecordForRelease(release PolicyFixtureReleaseRecord, ledger PolicyFixtureReleaseLedger, review PolicyFixtureReleaseReview, label string, createdAtUnix int64) (PolicyFixtureMarkerRecord, error) {
	if createdAtUnix < 0 {
		return PolicyFixtureMarkerRecord{}, fmt.Errorf("%w: negative marker time", ErrInvalidPolicyFixtureRelease)
	}
	if err := ValidatePolicyFixtureReleaseRecord(release); err != nil {
		return PolicyFixtureMarkerRecord{}, err
	}
	if err := ValidatePolicyFixtureReleaseLedger(ledger); err != nil {
		return PolicyFixtureMarkerRecord{}, err
	}
	if err := ValidatePolicyFixtureReleaseReview(review); err != nil {
		return PolicyFixtureMarkerRecord{}, err
	}
	if review.Status != PolicyFixtureReleaseOK || review.LedgerHash != ledger.LedgerHash || !policyFixtureReleaseLedgerHas(ledger, release.ReleaseHash) {
		return PolicyFixtureMarkerRecord{}, fmt.Errorf("%w: marker input mismatch", ErrInvalidPolicyFixtureRelease)
	}
	label = strings.TrimSpace(label)
	if label == "" {
		label = "fixture-marker"
	}
	record := PolicyFixtureMarkerRecord{SchemaVersion: PolicyFixtureMarkerRecordSchemaVersion, ReleaseHash: release.ReleaseHash, LedgerHash: ledger.LedgerHash, ReviewHash: review.ReviewHash, Label: label, CreatedAtUnix: createdAtUnix, FixtureOnly: true}
	record.MarkerHash = PolicyFixtureMarkerRecordHash(record)
	if err := ValidatePolicyFixtureMarkerRecord(record); err != nil {
		return PolicyFixtureMarkerRecord{}, err
	}
	return record, nil
}

func ValidatePolicyFixtureMarkerRecord(record PolicyFixtureMarkerRecord) error {
	if record.SchemaVersion != PolicyFixtureMarkerRecordSchemaVersion || !record.FixtureOnly {
		return fmt.Errorf("%w: invalid marker metadata", ErrInvalidPolicyFixtureRelease)
	}
	if !validSHA256Hex(record.ReleaseHash) || !validSHA256Hex(record.LedgerHash) || !validSHA256Hex(record.ReviewHash) || !validSHA256Hex(record.MarkerHash) {
		return fmt.Errorf("%w: invalid marker hash", ErrInvalidPolicyFixtureRelease)
	}
	if !validPolicySemanticsFixtureText(record.Label, 128) || record.CreatedAtUnix < 0 {
		return fmt.Errorf("%w: invalid marker values", ErrInvalidPolicyFixtureRelease)
	}
	if PolicyFixtureMarkerRecordHash(record) != record.MarkerHash {
		return fmt.Errorf("%w: marker hash mismatch", ErrInvalidPolicyFixtureRelease)
	}
	return nil
}

func PolicyFixtureMarkerRecordHash(record PolicyFixtureMarkerRecord) string {
	parts := []string{record.SchemaVersion, record.ReleaseHash, record.LedgerHash, record.ReviewHash, record.Label, fmt.Sprintf("%020d", record.CreatedAtUnix)}
	return sha256Hex(strings.Join(parts, "\x1f"))
}

func policyFixtureReleaseLedgerHas(ledger PolicyFixtureReleaseLedger, releaseHash string) bool {
	records, err := NormalizePolicyFixtureReleaseRecords(ledger.Records)
	if err != nil {
		return false
	}
	for _, record := range records {
		if record.ReleaseHash == releaseHash {
			return true
		}
	}
	return false
}
