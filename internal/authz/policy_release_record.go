package authz

import (
	"errors"
	"fmt"
	"strings"
)

const PolicyFixtureReleaseRecordSchemaVersion = "policy.fixture.release.v1"

var ErrInvalidPolicyFixtureRelease = errors.New("invalid authz policy fixture release")

type PolicyFixtureReleaseRecord struct {
	SchemaVersion  string `json:"schema_version"`
	BundleHash     string `json:"bundle_hash"`
	ManifestHash   string `json:"manifest_hash"`
	CatalogHash    string `json:"catalog_hash"`
	ExportIndexHash string `json:"export_index_hash"`
	ExportCheckHash string `json:"export_check_hash"`
	CreatedAtUnix  int64  `json:"created_at_unix"`
	FixtureOnly    bool   `json:"fixture_only"`
	ReleaseHash    string `json:"release_hash"`
}

func PolicyFixtureReleaseRecordForBundle(bundle PolicyFixtureBundle, manifest PolicyFixtureBundleManifest, catalog PolicyFixtureArtifactCatalog, index PolicyFixtureExportIndex, check PolicyFixtureExportCheck, createdAtUnix int64) (PolicyFixtureReleaseRecord, error) {
	if createdAtUnix < 0 {
		return PolicyFixtureReleaseRecord{}, fmt.Errorf("%w: negative release time", ErrInvalidPolicyFixtureRelease)
	}
	if err := ValidatePolicyFixtureBundle(bundle); err != nil { return PolicyFixtureReleaseRecord{}, err }
	if err := ValidatePolicyFixtureBundleManifest(manifest); err != nil { return PolicyFixtureReleaseRecord{}, err }
	if err := ValidatePolicyFixtureArtifactCatalog(catalog); err != nil { return PolicyFixtureReleaseRecord{}, err }
	if err := ValidatePolicyFixtureExportIndex(index); err != nil { return PolicyFixtureReleaseRecord{}, err }
	if err := ValidatePolicyFixtureExportCheck(check); err != nil { return PolicyFixtureReleaseRecord{}, err }
	if manifest.BundleHash != bundle.BundleHash || check.IndexHash != index.IndexHash || check.Status != PolicyFixtureExportOK {
		return PolicyFixtureReleaseRecord{}, fmt.Errorf("%w: release input mismatch", ErrInvalidPolicyFixtureRelease)
	}
	if !policyFixtureArtifactCatalogHas(catalog, PolicyFixtureArtifactBundle, bundle.BundleHash) || !policyFixtureArtifactCatalogHas(catalog, PolicyFixtureArtifactManifest, manifest.ManifestHash) {
		return PolicyFixtureReleaseRecord{}, fmt.Errorf("%w: release catalog missing required artifact", ErrInvalidPolicyFixtureRelease)
	}
	record := PolicyFixtureReleaseRecord{SchemaVersion: PolicyFixtureReleaseRecordSchemaVersion, BundleHash: bundle.BundleHash, ManifestHash: manifest.ManifestHash, CatalogHash: catalog.CatalogHash, ExportIndexHash: index.IndexHash, ExportCheckHash: check.CheckHash, CreatedAtUnix: createdAtUnix, FixtureOnly: true}
	record.ReleaseHash = PolicyFixtureReleaseRecordHash(record)
	if err := ValidatePolicyFixtureReleaseRecord(record); err != nil { return PolicyFixtureReleaseRecord{}, err }
	return record, nil
}

func ValidatePolicyFixtureReleaseRecord(record PolicyFixtureReleaseRecord) error {
	if record.SchemaVersion != PolicyFixtureReleaseRecordSchemaVersion || !record.FixtureOnly {
		return fmt.Errorf("%w: invalid release metadata", ErrInvalidPolicyFixtureRelease)
	}
	if !validSHA256Hex(record.BundleHash) || !validSHA256Hex(record.ManifestHash) || !validSHA256Hex(record.CatalogHash) || !validSHA256Hex(record.ExportIndexHash) || !validSHA256Hex(record.ExportCheckHash) || !validSHA256Hex(record.ReleaseHash) {
		return fmt.Errorf("%w: invalid release hash", ErrInvalidPolicyFixtureRelease)
	}
	if record.CreatedAtUnix < 0 {
		return fmt.Errorf("%w: invalid release time", ErrInvalidPolicyFixtureRelease)
	}
	if PolicyFixtureReleaseRecordHash(record) != record.ReleaseHash {
		return fmt.Errorf("%w: release hash mismatch", ErrInvalidPolicyFixtureRelease)
	}
	return nil
}

func PolicyFixtureReleaseRecordHash(record PolicyFixtureReleaseRecord) string {
	parts := []string{record.SchemaVersion, record.BundleHash, record.ManifestHash, record.CatalogHash, record.ExportIndexHash, record.ExportCheckHash, fmt.Sprintf("%020d", record.CreatedAtUnix)}
	return sha256Hex(strings.Join(parts, "\x1f"))
}
