package authz

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const PolicyFixtureArtifactRecordSchemaVersion = "policy.fixture.artifact.v1"
const PolicyFixtureArtifactCatalogSchemaVersion = "policy.fixture.artifact_catalog.v1"
const PolicyFixtureArtifactCheckSchemaVersion = "policy.fixture.artifact_check.v1"
const maxFixtureArtifactReasonLength = 128

var ErrInvalidPolicyFixtureArtifact = errors.New("invalid authz policy fixture artifact")

type PolicyFixtureArtifactKind string

const (
	PolicyFixtureArtifactBundle   PolicyFixtureArtifactKind = "bundle"
	PolicyFixtureArtifactManifest PolicyFixtureArtifactKind = "manifest"
)

type PolicyFixtureArtifactCheckStatus string

const (
	PolicyFixtureArtifactCheckOK     PolicyFixtureArtifactCheckStatus = "ok"
	PolicyFixtureArtifactCheckFailed PolicyFixtureArtifactCheckStatus = "failed"
)

type PolicyFixtureArtifactRecord struct {
	SchemaVersion string                    `json:"schema_version"`
	Kind          PolicyFixtureArtifactKind `json:"kind"`
	ArtifactHash  string                    `json:"artifact_hash"`
	CreatedAtUnix int64                     `json:"created_at_unix"`
	ExpiresAtUnix int64                     `json:"expires_at_unix,omitempty"`
	KeepReason    string                    `json:"keep_reason"`
	FixtureOnly   bool                      `json:"fixture_only"`
	RecordHash    string                    `json:"record_hash"`
}

type PolicyFixtureArtifactCatalog struct {
	SchemaVersion string                        `json:"schema_version"`
	Records       []PolicyFixtureArtifactRecord `json:"records"`
	FixtureOnly   bool                          `json:"fixture_only"`
	CatalogHash   string                        `json:"catalog_hash"`
}

type PolicyFixtureArtifactCheck struct {
	SchemaVersion string                           `json:"schema_version"`
	Status        PolicyFixtureArtifactCheckStatus `json:"status"`
	BundleHash    string                           `json:"bundle_hash"`
	ManifestHash  string                           `json:"manifest_hash"`
	CatalogHash   string                           `json:"catalog_hash"`
	CheckedAtUnix int64                            `json:"checked_at_unix"`
	FixtureOnly   bool                             `json:"fixture_only"`
	CheckHash     string                           `json:"check_hash"`
}

func PolicyFixtureArtifactRecordForBundle(bundle PolicyFixtureBundle, createdAtUnix int64, ttlSeconds int64, reason string) (PolicyFixtureArtifactRecord, error) {
	if err := ValidatePolicyFixtureBundle(bundle); err != nil {
		return PolicyFixtureArtifactRecord{}, err
	}
	return newPolicyFixtureArtifactRecord(PolicyFixtureArtifactBundle, bundle.BundleHash, createdAtUnix, ttlSeconds, reason)
}

func PolicyFixtureArtifactRecordForManifest(manifest PolicyFixtureBundleManifest, createdAtUnix int64, ttlSeconds int64, reason string) (PolicyFixtureArtifactRecord, error) {
	if err := ValidatePolicyFixtureBundleManifest(manifest); err != nil {
		return PolicyFixtureArtifactRecord{}, err
	}
	return newPolicyFixtureArtifactRecord(PolicyFixtureArtifactManifest, manifest.ManifestHash, createdAtUnix, ttlSeconds, reason)
}

func newPolicyFixtureArtifactRecord(kind PolicyFixtureArtifactKind, artifactHash string, createdAtUnix int64, ttlSeconds int64, reason string) (PolicyFixtureArtifactRecord, error) {
	if createdAtUnix < 0 || ttlSeconds < 0 {
		return PolicyFixtureArtifactRecord{}, fmt.Errorf("%w: negative artifact timing", ErrInvalidPolicyFixtureArtifact)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "fixture-output"
	}
	record := PolicyFixtureArtifactRecord{
		SchemaVersion: PolicyFixtureArtifactRecordSchemaVersion,
		Kind:          kind,
		ArtifactHash:  artifactHash,
		CreatedAtUnix: createdAtUnix,
		KeepReason:    reason,
		FixtureOnly:   true,
	}
	if ttlSeconds > 0 {
		record.ExpiresAtUnix = createdAtUnix + ttlSeconds
	}
	record.RecordHash = PolicyFixtureArtifactRecordHash(record)
	if err := ValidatePolicyFixtureArtifactRecord(record); err != nil {
		return PolicyFixtureArtifactRecord{}, err
	}
	return record, nil
}

func ValidatePolicyFixtureArtifactRecord(record PolicyFixtureArtifactRecord) error {
	if record.SchemaVersion != PolicyFixtureArtifactRecordSchemaVersion {
		return fmt.Errorf("%w: unsupported artifact record schema", ErrInvalidPolicyFixtureArtifact)
	}
	if record.Kind != PolicyFixtureArtifactBundle && record.Kind != PolicyFixtureArtifactManifest {
		return fmt.Errorf("%w: invalid artifact kind", ErrInvalidPolicyFixtureArtifact)
	}
	if !validSHA256Hex(record.ArtifactHash) || !validSHA256Hex(record.RecordHash) {
		return fmt.Errorf("%w: invalid artifact hash", ErrInvalidPolicyFixtureArtifact)
	}
	if record.CreatedAtUnix < 0 || record.ExpiresAtUnix < 0 || (record.ExpiresAtUnix > 0 && record.ExpiresAtUnix < record.CreatedAtUnix) {
		return fmt.Errorf("%w: invalid artifact timing", ErrInvalidPolicyFixtureArtifact)
	}
	if !validPolicySemanticsFixtureText(record.KeepReason, maxFixtureArtifactReasonLength) {
		return fmt.Errorf("%w: invalid artifact reason", ErrInvalidPolicyFixtureArtifact)
	}
	if !record.FixtureOnly {
		return fmt.Errorf("%w: artifact record must be fixture-only", ErrInvalidPolicyFixtureArtifact)
	}
	if PolicyFixtureArtifactRecordHash(record) != record.RecordHash {
		return fmt.Errorf("%w: artifact record hash mismatch", ErrInvalidPolicyFixtureArtifact)
	}
	return nil
}

func PolicyFixtureArtifactCatalogFromRecords(records []PolicyFixtureArtifactRecord) (PolicyFixtureArtifactCatalog, error) {
	normalized, err := NormalizePolicyFixtureArtifactRecords(records)
	if err != nil {
		return PolicyFixtureArtifactCatalog{}, err
	}
	if len(normalized) == 0 {
		return PolicyFixtureArtifactCatalog{}, fmt.Errorf("%w: artifact catalog records are required", ErrInvalidPolicyFixtureArtifact)
	}
	catalog := PolicyFixtureArtifactCatalog{SchemaVersion: PolicyFixtureArtifactCatalogSchemaVersion, Records: normalized, FixtureOnly: true}
	catalog.CatalogHash = PolicyFixtureArtifactCatalogHash(catalog)
	if err := ValidatePolicyFixtureArtifactCatalog(catalog); err != nil {
		return PolicyFixtureArtifactCatalog{}, err
	}
	return catalog, nil
}

func NormalizePolicyFixtureArtifactRecords(records []PolicyFixtureArtifactRecord) ([]PolicyFixtureArtifactRecord, error) {
	seen := map[string]PolicyFixtureArtifactRecord{}
	for _, record := range records {
		if err := ValidatePolicyFixtureArtifactRecord(record); err != nil {
			return nil, err
		}
		key := string(record.Kind) + ":" + record.ArtifactHash
		if existing, ok := seen[key]; ok {
			if existing.RecordHash != record.RecordHash {
				return nil, fmt.Errorf("%w: conflicting artifact record", ErrInvalidPolicyFixtureArtifact)
			}
			continue
		}
		seen[key] = record
	}
	out := make([]PolicyFixtureArtifactRecord, 0, len(seen))
	for _, record := range seen {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ArtifactHash < out[j].ArtifactHash
	})
	return out, nil
}

func ValidatePolicyFixtureArtifactCatalog(catalog PolicyFixtureArtifactCatalog) error {
	if catalog.SchemaVersion != PolicyFixtureArtifactCatalogSchemaVersion {
		return fmt.Errorf("%w: unsupported artifact catalog schema", ErrInvalidPolicyFixtureArtifact)
	}
	if !catalog.FixtureOnly {
		return fmt.Errorf("%w: artifact catalog must be fixture-only", ErrInvalidPolicyFixtureArtifact)
	}
	normalized, err := NormalizePolicyFixtureArtifactRecords(catalog.Records)
	if err != nil {
		return err
	}
	if len(normalized) == 0 {
		return fmt.Errorf("%w: artifact catalog records are required", ErrInvalidPolicyFixtureArtifact)
	}
	if !validSHA256Hex(catalog.CatalogHash) || PolicyFixtureArtifactCatalogHash(catalog) != catalog.CatalogHash {
		return fmt.Errorf("%w: artifact catalog hash mismatch", ErrInvalidPolicyFixtureArtifact)
	}
	return nil
}

func PolicyFixtureArtifactCheckForBundle(bundle PolicyFixtureBundle, manifest PolicyFixtureBundleManifest, catalog PolicyFixtureArtifactCatalog, checkedAtUnix int64) (PolicyFixtureArtifactCheck, error) {
	if checkedAtUnix < 0 {
		return PolicyFixtureArtifactCheck{}, fmt.Errorf("%w: negative check time", ErrInvalidPolicyFixtureArtifact)
	}
	status := PolicyFixtureArtifactCheckOK
	if ValidatePolicyFixtureBundle(bundle) != nil ||
		ValidatePolicyFixtureBundleManifest(manifest) != nil ||
		ValidatePolicyFixtureArtifactCatalog(catalog) != nil ||
		manifest.BundleHash != bundle.BundleHash ||
		!policyFixtureArtifactCatalogHas(catalog, PolicyFixtureArtifactBundle, bundle.BundleHash) ||
		!policyFixtureArtifactCatalogHas(catalog, PolicyFixtureArtifactManifest, manifest.ManifestHash) {
		status = PolicyFixtureArtifactCheckFailed
	}
	check := PolicyFixtureArtifactCheck{
		SchemaVersion: PolicyFixtureArtifactCheckSchemaVersion,
		Status:        status,
		BundleHash:    bundle.BundleHash,
		ManifestHash:  manifest.ManifestHash,
		CatalogHash:   catalog.CatalogHash,
		CheckedAtUnix: checkedAtUnix,
		FixtureOnly:   true,
	}
	check.CheckHash = PolicyFixtureArtifactCheckHash(check)
	if err := ValidatePolicyFixtureArtifactCheck(check); err != nil {
		return PolicyFixtureArtifactCheck{}, err
	}
	return check, nil
}

func ValidatePolicyFixtureArtifactCheck(check PolicyFixtureArtifactCheck) error {
	if check.SchemaVersion != PolicyFixtureArtifactCheckSchemaVersion {
		return fmt.Errorf("%w: unsupported artifact check schema", ErrInvalidPolicyFixtureArtifact)
	}
	if check.Status != PolicyFixtureArtifactCheckOK && check.Status != PolicyFixtureArtifactCheckFailed {
		return fmt.Errorf("%w: invalid artifact check status", ErrInvalidPolicyFixtureArtifact)
	}
	if !validSHA256Hex(check.BundleHash) || !validSHA256Hex(check.ManifestHash) || !validSHA256Hex(check.CatalogHash) || !validSHA256Hex(check.CheckHash) {
		return fmt.Errorf("%w: invalid artifact check hash", ErrInvalidPolicyFixtureArtifact)
	}
	if check.CheckedAtUnix < 0 || !check.FixtureOnly {
		return fmt.Errorf("%w: invalid artifact check metadata", ErrInvalidPolicyFixtureArtifact)
	}
	if PolicyFixtureArtifactCheckHash(check) != check.CheckHash {
		return fmt.Errorf("%w: artifact check hash mismatch", ErrInvalidPolicyFixtureArtifact)
	}
	return nil
}

func policyFixtureArtifactCatalogHas(catalog PolicyFixtureArtifactCatalog, kind PolicyFixtureArtifactKind, artifactHash string) bool {
	records, err := NormalizePolicyFixtureArtifactRecords(catalog.Records)
	if err != nil {
		return false
	}
	for _, record := range records {
		if record.Kind == kind && record.ArtifactHash == artifactHash {
			return true
		}
	}
	return false
}

func PolicyFixtureArtifactRecordHash(record PolicyFixtureArtifactRecord) string {
	parts := []string{record.SchemaVersion, string(record.Kind), record.ArtifactHash, fmt.Sprintf("%020d", record.CreatedAtUnix), fmt.Sprintf("%020d", record.ExpiresAtUnix), record.KeepReason}
	return sha256Hex(strings.Join(parts, "\x1f"))
}

func PolicyFixtureArtifactCatalogHash(catalog PolicyFixtureArtifactCatalog) string {
	records, err := NormalizePolicyFixtureArtifactRecords(catalog.Records)
	if err != nil {
		return ""
	}
	parts := []string{catalog.SchemaVersion}
	for _, record := range records {
		parts = append(parts, record.RecordHash)
	}
	return sha256Hex(strings.Join(parts, "\x1f"))
}

func PolicyFixtureArtifactCheckHash(check PolicyFixtureArtifactCheck) string {
	parts := []string{check.SchemaVersion, string(check.Status), check.BundleHash, check.ManifestHash, check.CatalogHash, fmt.Sprintf("%020d", check.CheckedAtUnix)}
	return sha256Hex(strings.Join(parts, "\x1f"))
}
