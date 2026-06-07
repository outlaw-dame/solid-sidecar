package authz

import (
	"fmt"
	"sort"
	"strings"
)

const PolicyFixtureExportIndexSchemaVersion = "policy.fixture.export_index.v1"

type PolicyFixtureExportIndex struct {
	SchemaVersion string                      `json:"schema_version"`
	Records       []PolicyFixtureExportRecord `json:"records"`
	FixtureOnly   bool                        `json:"fixture_only"`
	IndexHash     string                      `json:"index_hash"`
}

func PolicyFixtureExportIndexFromRecords(records []PolicyFixtureExportRecord) (PolicyFixtureExportIndex, error) {
	normalized, err := NormalizePolicyFixtureExportRecords(records)
	if err != nil {
		return PolicyFixtureExportIndex{}, err
	}
	if len(normalized) == 0 {
		return PolicyFixtureExportIndex{}, fmt.Errorf("%w: export records are required", ErrInvalidPolicyFixtureExport)
	}
	index := PolicyFixtureExportIndex{SchemaVersion: PolicyFixtureExportIndexSchemaVersion, Records: normalized, FixtureOnly: true}
	index.IndexHash = PolicyFixtureExportIndexHash(index)
	if err := ValidatePolicyFixtureExportIndex(index); err != nil {
		return PolicyFixtureExportIndex{}, err
	}
	return index, nil
}

func NormalizePolicyFixtureExportRecords(records []PolicyFixtureExportRecord) ([]PolicyFixtureExportRecord, error) {
	seen := map[string]PolicyFixtureExportRecord{}
	for _, record := range records {
		if err := ValidatePolicyFixtureExportRecord(record); err != nil {
			return nil, err
		}
		key := string(record.Kind) + ":" + record.Name
		if existing, ok := seen[key]; ok {
			if existing.ExportHash != record.ExportHash {
				return nil, fmt.Errorf("%w: conflicting export record", ErrInvalidPolicyFixtureExport)
			}
			continue
		}
		seen[key] = record
	}
	out := make([]PolicyFixtureExportRecord, 0, len(seen))
	for _, record := range seen {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func ValidatePolicyFixtureExportIndex(index PolicyFixtureExportIndex) error {
	if index.SchemaVersion != PolicyFixtureExportIndexSchemaVersion || !index.FixtureOnly {
		return fmt.Errorf("%w: invalid export index metadata", ErrInvalidPolicyFixtureExport)
	}
	if len(index.Records) == 0 {
		return fmt.Errorf("%w: export index records are required", ErrInvalidPolicyFixtureExport)
	}
	if _, err := NormalizePolicyFixtureExportRecords(index.Records); err != nil {
		return err
	}
	if !validSHA256Hex(index.IndexHash) || PolicyFixtureExportIndexHash(index) != index.IndexHash {
		return fmt.Errorf("%w: export index hash mismatch", ErrInvalidPolicyFixtureExport)
	}
	return nil
}

func PolicyFixtureExportIndexHash(index PolicyFixtureExportIndex) string {
	records, err := NormalizePolicyFixtureExportRecords(index.Records)
	if err != nil {
		return ""
	}
	parts := []string{index.SchemaVersion}
	for _, record := range records {
		parts = append(parts, record.ExportHash)
	}
	return sha256Hex(strings.Join(parts, "\x1f"))
}
