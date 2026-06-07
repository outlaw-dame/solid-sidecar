package authz

import (
	"fmt"
	"strings"
)

const PolicyFixtureExportCheckSchemaVersion = "policy.fixture.export_check.v1"

type PolicyFixtureExportStatus string

const (
	PolicyFixtureExportOK     PolicyFixtureExportStatus = "ok"
	PolicyFixtureExportFailed PolicyFixtureExportStatus = "failed"
)

type PolicyFixtureExportCheck struct {
	SchemaVersion string                    `json:"schema_version"`
	Status        PolicyFixtureExportStatus `json:"status"`
	IndexHash     string                    `json:"index_hash"`
	RecordCount   int                       `json:"record_count"`
	CheckedAtUnix int64                     `json:"checked_at_unix"`
	FixtureOnly   bool                      `json:"fixture_only"`
	CheckHash     string                    `json:"check_hash"`
}

func PolicyFixtureExportCheckForIndex(index PolicyFixtureExportIndex, checkedAtUnix int64) (PolicyFixtureExportCheck, error) {
	if checkedAtUnix < 0 {
		return PolicyFixtureExportCheck{}, fmt.Errorf("%w: negative export check time", ErrInvalidPolicyFixtureExport)
	}
	status := PolicyFixtureExportOK
	if ValidatePolicyFixtureExportIndex(index) != nil {
		status = PolicyFixtureExportFailed
	}
	check := PolicyFixtureExportCheck{SchemaVersion: PolicyFixtureExportCheckSchemaVersion, Status: status, IndexHash: index.IndexHash, RecordCount: len(index.Records), CheckedAtUnix: checkedAtUnix, FixtureOnly: true}
	check.CheckHash = PolicyFixtureExportCheckHash(check)
	if err := ValidatePolicyFixtureExportCheck(check); err != nil {
		return PolicyFixtureExportCheck{}, err
	}
	return check, nil
}

func ValidatePolicyFixtureExportCheck(check PolicyFixtureExportCheck) error {
	if check.SchemaVersion != PolicyFixtureExportCheckSchemaVersion || !check.FixtureOnly {
		return fmt.Errorf("%w: invalid export check metadata", ErrInvalidPolicyFixtureExport)
	}
	if check.Status != PolicyFixtureExportOK && check.Status != PolicyFixtureExportFailed {
		return fmt.Errorf("%w: invalid export check status", ErrInvalidPolicyFixtureExport)
	}
	if !validSHA256Hex(check.IndexHash) || !validSHA256Hex(check.CheckHash) || check.RecordCount < 0 || check.CheckedAtUnix < 0 {
		return fmt.Errorf("%w: invalid export check values", ErrInvalidPolicyFixtureExport)
	}
	if PolicyFixtureExportCheckHash(check) != check.CheckHash {
		return fmt.Errorf("%w: export check hash mismatch", ErrInvalidPolicyFixtureExport)
	}
	return nil
}

func PolicyFixtureExportCheckHash(check PolicyFixtureExportCheck) string {
	parts := []string{check.SchemaVersion, string(check.Status), check.IndexHash, fmt.Sprintf("%020d", check.RecordCount), fmt.Sprintf("%020d", check.CheckedAtUnix)}
	return sha256Hex(strings.Join(parts, "\x1f"))
}
