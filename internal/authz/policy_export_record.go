package authz

import (
	"errors"
	"fmt"
	"strings"
)

const PolicyFixtureExportRecordSchemaVersion = "policy.fixture.export.v1"

var ErrInvalidPolicyFixtureExport = errors.New("invalid authz policy fixture export")

type PolicyFixtureExportKind string

const (
	PolicyFixtureExportBundle   PolicyFixtureExportKind = "bundle"
	PolicyFixtureExportManifest PolicyFixtureExportKind = "manifest"
	PolicyFixtureExportCatalog  PolicyFixtureExportKind = "catalog"
)

type PolicyFixtureExportRecord struct {
	SchemaVersion string                  `json:"schema_version"`
	Kind          PolicyFixtureExportKind `json:"kind"`
	Name          string                  `json:"name"`
	SourceHash    string                  `json:"source_hash"`
	CreatedAtUnix int64                   `json:"created_at_unix"`
	ByteCount     int64                   `json:"byte_count"`
	FixtureOnly   bool                    `json:"fixture_only"`
	ExportHash    string                  `json:"export_hash"`
}

func PolicyFixtureExportRecordForBundle(bundle PolicyFixtureBundle, name string, createdAtUnix int64, byteCount int64) (PolicyFixtureExportRecord, error) {
	if err := ValidatePolicyFixtureBundle(bundle); err != nil {
		return PolicyFixtureExportRecord{}, err
	}
	return newPolicyFixtureExportRecord(PolicyFixtureExportBundle, name, bundle.BundleHash, createdAtUnix, byteCount)
}

func PolicyFixtureExportRecordForManifest(manifest PolicyFixtureBundleManifest, name string, createdAtUnix int64, byteCount int64) (PolicyFixtureExportRecord, error) {
	if err := ValidatePolicyFixtureBundleManifest(manifest); err != nil {
		return PolicyFixtureExportRecord{}, err
	}
	return newPolicyFixtureExportRecord(PolicyFixtureExportManifest, name, manifest.ManifestHash, createdAtUnix, byteCount)
}

func PolicyFixtureExportRecordForCatalog(catalog PolicyFixtureArtifactCatalog, name string, createdAtUnix int64, byteCount int64) (PolicyFixtureExportRecord, error) {
	if err := ValidatePolicyFixtureArtifactCatalog(catalog); err != nil {
		return PolicyFixtureExportRecord{}, err
	}
	return newPolicyFixtureExportRecord(PolicyFixtureExportCatalog, name, catalog.CatalogHash, createdAtUnix, byteCount)
}

func newPolicyFixtureExportRecord(kind PolicyFixtureExportKind, name string, sourceHash string, createdAtUnix int64, byteCount int64) (PolicyFixtureExportRecord, error) {
	if createdAtUnix < 0 || byteCount < 0 {
		return PolicyFixtureExportRecord{}, fmt.Errorf("%w: invalid export metadata", ErrInvalidPolicyFixtureExport)
	}
	record := PolicyFixtureExportRecord{SchemaVersion: PolicyFixtureExportRecordSchemaVersion, Kind: kind, Name: strings.TrimSpace(name), SourceHash: sourceHash, CreatedAtUnix: createdAtUnix, ByteCount: byteCount, FixtureOnly: true}
	record.ExportHash = PolicyFixtureExportRecordHash(record)
	if err := ValidatePolicyFixtureExportRecord(record); err != nil {
		return PolicyFixtureExportRecord{}, err
	}
	return record, nil
}

func ValidatePolicyFixtureExportRecord(record PolicyFixtureExportRecord) error {
	if record.SchemaVersion != PolicyFixtureExportRecordSchemaVersion {
		return fmt.Errorf("%w: unsupported export schema", ErrInvalidPolicyFixtureExport)
	}
	if record.Kind != PolicyFixtureExportBundle && record.Kind != PolicyFixtureExportManifest && record.Kind != PolicyFixtureExportCatalog {
		return fmt.Errorf("%w: invalid export kind", ErrInvalidPolicyFixtureExport)
	}
	if !validFixtureExportName(record.Name) || !validSHA256Hex(record.SourceHash) || !validSHA256Hex(record.ExportHash) {
		return fmt.Errorf("%w: invalid export values", ErrInvalidPolicyFixtureExport)
	}
	if record.CreatedAtUnix < 0 || record.ByteCount < 0 || !record.FixtureOnly {
		return fmt.Errorf("%w: invalid export metadata", ErrInvalidPolicyFixtureExport)
	}
	if PolicyFixtureExportRecordHash(record) != record.ExportHash {
		return fmt.Errorf("%w: export hash mismatch", ErrInvalidPolicyFixtureExport)
	}
	return nil
}

func PolicyFixtureExportRecordHash(record PolicyFixtureExportRecord) string {
	parts := []string{record.SchemaVersion, string(record.Kind), record.Name, record.SourceHash, fmt.Sprintf("%020d", record.CreatedAtUnix), fmt.Sprintf("%020d", record.ByteCount)}
	return sha256Hex(strings.Join(parts, "\x1f"))
}

func validFixtureExportName(name string) bool {
	if name == "" || len(name) > 160 || strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
