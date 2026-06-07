package authz

import (
	"fmt"
	"sort"
	"strings"
)

const PolicyFixtureMarkerLogSchemaVersion = "policy.fixture.marker_log.v1"

type PolicyFixtureMarkerLog struct {
	SchemaVersion string `json:"schema_version"`
	Records []PolicyFixtureMarkerRecord `json:"records"`
	FixtureOnly bool `json:"fixture_only"`
	LogHash string `json:"log_hash"`
}

func PolicyFixtureMarkerLogFromRecords(records []PolicyFixtureMarkerRecord) (PolicyFixtureMarkerLog, error) {
	normalized, err := NormalizePolicyFixtureMarkerRecords(records)
	if err != nil { return PolicyFixtureMarkerLog{}, err }
	if len(normalized) == 0 { return PolicyFixtureMarkerLog{}, fmt.Errorf("%w: marker records are required", ErrInvalidPolicyFixtureRelease) }
	log := PolicyFixtureMarkerLog{SchemaVersion: PolicyFixtureMarkerLogSchemaVersion, Records: normalized, FixtureOnly: true}
	log.LogHash = PolicyFixtureMarkerLogHash(log)
	if err := ValidatePolicyFixtureMarkerLog(log); err != nil { return PolicyFixtureMarkerLog{}, err }
	return log, nil
}

func NormalizePolicyFixtureMarkerRecords(records []PolicyFixtureMarkerRecord) ([]PolicyFixtureMarkerRecord, error) {
	seen := map[string]PolicyFixtureMarkerRecord{}
	for _, record := range records {
		if err := ValidatePolicyFixtureMarkerRecord(record); err != nil { return nil, err }
		if existing, ok := seen[record.MarkerHash]; ok {
			if existing.ReleaseHash != record.ReleaseHash || existing.LedgerHash != record.LedgerHash { return nil, fmt.Errorf("%w: conflicting marker record", ErrInvalidPolicyFixtureRelease) }
			continue
		}
		seen[record.MarkerHash] = record
	}
	out := make([]PolicyFixtureMarkerRecord, 0, len(seen))
	for _, record := range seen { out = append(out, record) }
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAtUnix != out[j].CreatedAtUnix { return out[i].CreatedAtUnix < out[j].CreatedAtUnix }
		return out[i].MarkerHash < out[j].MarkerHash
	})
	return out, nil
}

func ValidatePolicyFixtureMarkerLog(log PolicyFixtureMarkerLog) error {
	if log.SchemaVersion != PolicyFixtureMarkerLogSchemaVersion || !log.FixtureOnly { return fmt.Errorf("%w: invalid marker log metadata", ErrInvalidPolicyFixtureRelease) }
	if len(log.Records) == 0 { return fmt.Errorf("%w: marker log records are required", ErrInvalidPolicyFixtureRelease) }
	if _, err := NormalizePolicyFixtureMarkerRecords(log.Records); err != nil { return err }
	if !validSHA256Hex(log.LogHash) || PolicyFixtureMarkerLogHash(log) != log.LogHash { return fmt.Errorf("%w: marker log hash mismatch", ErrInvalidPolicyFixtureRelease) }
	return nil
}

func PolicyFixtureMarkerLogHash(log PolicyFixtureMarkerLog) string {
	records, err := NormalizePolicyFixtureMarkerRecords(log.Records)
	if err != nil { return "" }
	parts := []string{log.SchemaVersion}
	for _, record := range records { parts = append(parts, record.MarkerHash) }
	return sha256Hex(strings.Join(parts, "\x1f"))
}
