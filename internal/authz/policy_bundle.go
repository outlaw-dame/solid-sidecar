package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const PolicyFixtureBundleSchemaVersion = "policy.fixture.bundle.v1"
const PolicyFixtureBundleManifestSchemaVersion = "policy.fixture.bundle_manifest.v1"

var ErrInvalidPolicyFixtureBundle = errors.New("invalid authz policy fixture bundle")

type PolicyFixtureBundle struct {
	SchemaVersion string                  `json:"schema_version"`
	Snapshots     []PolicyFixtureSnapshot `json:"snapshots"`
	Summary       PolicyFixtureSummary    `json:"summary"`
	FixtureOnly   bool                    `json:"fixture_only"`
	BundleHash    string                  `json:"bundle_hash"`
}

type PolicyFixtureBundleManifest struct {
	SchemaVersion  string   `json:"schema_version"`
	BundleHash     string   `json:"bundle_hash"`
	SnapshotHashes []string `json:"snapshot_hashes"`
	SummaryHash    string   `json:"rollup_hash"`
	ManifestHash   string   `json:"manifest_hash"`
	FixtureOnly    bool     `json:"fixture_only"`
}

func PolicyFixtureBundleFromSuite(ctx context.Context, suite PolicySemanticsFixtureSuite) (PolicyFixtureBundle, error) {
	if err := ctx.Err(); err != nil {
		return PolicyFixtureBundle{}, err
	}
	snapshots, err := PolicyFixtureSnapshotsFromSuite(ctx, suite)
	if err != nil {
		return PolicyFixtureBundle{}, err
	}
	summary, err := PolicyFixtureSummaryFromSnapshots(snapshots)
	if err != nil {
		return PolicyFixtureBundle{}, err
	}
	bundle := PolicyFixtureBundle{
		SchemaVersion: PolicyFixtureBundleSchemaVersion,
		Snapshots:     snapshots,
		Summary:       summary,
		FixtureOnly:   true,
	}
	bundle.BundleHash = PolicyFixtureBundleHash(bundle)
	if err := ValidatePolicyFixtureBundle(bundle); err != nil {
		return PolicyFixtureBundle{}, err
	}
	return bundle, nil
}

func ValidatePolicyFixtureBundle(bundle PolicyFixtureBundle) error {
	if bundle.SchemaVersion != PolicyFixtureBundleSchemaVersion {
		return fmt.Errorf("%w: unsupported bundle schema version", ErrInvalidPolicyFixtureBundle)
	}
	if !bundle.FixtureOnly {
		return fmt.Errorf("%w: bundle must be fixture-only", ErrInvalidPolicyFixtureBundle)
	}
	snapshots, err := NormalizePolicyFixtureSnapshots(bundle.Snapshots)
	if err != nil {
		return err
	}
	if len(snapshots) == 0 {
		return fmt.Errorf("%w: bundle snapshots are required", ErrInvalidPolicyFixtureBundle)
	}
	summary, err := PolicyFixtureSummaryFromSnapshots(snapshots)
	if err != nil {
		return err
	}
	if summary.SummaryHash != bundle.Summary.SummaryHash || summary.SnapshotCount != bundle.Summary.SnapshotCount {
		return fmt.Errorf("%w: bundle summary mismatch", ErrInvalidPolicyFixtureBundle)
	}
	if !validSHA256Hex(bundle.BundleHash) || PolicyFixtureBundleHash(bundle) != bundle.BundleHash {
		return fmt.Errorf("%w: bundle hash mismatch", ErrInvalidPolicyFixtureBundle)
	}
	return nil
}

func PolicyFixtureBundleHash(bundle PolicyFixtureBundle) string {
	snapshots, err := NormalizePolicyFixtureSnapshots(bundle.Snapshots)
	if err != nil {
		return ""
	}
	parts := []string{bundle.SchemaVersion, bundle.Summary.SummaryHash}
	for _, snapshot := range snapshots {
		parts = append(parts, snapshot.SnapshotHash)
	}
	return sha256Hex(strings.Join(parts, "\x1f"))
}

func PolicyFixtureBundleManifestForBundle(bundle PolicyFixtureBundle) (PolicyFixtureBundleManifest, error) {
	if err := ValidatePolicyFixtureBundle(bundle); err != nil {
		return PolicyFixtureBundleManifest{}, err
	}
	snapshots, err := NormalizePolicyFixtureSnapshots(bundle.Snapshots)
	if err != nil {
		return PolicyFixtureBundleManifest{}, err
	}
	snapshotHashes := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		snapshotHashes = append(snapshotHashes, snapshot.SnapshotHash)
	}
	sort.Strings(snapshotHashes)
	manifest := PolicyFixtureBundleManifest{
		SchemaVersion:  PolicyFixtureBundleManifestSchemaVersion,
		BundleHash:     bundle.BundleHash,
		SnapshotHashes: snapshotHashes,
		SummaryHash:    bundle.Summary.SummaryHash,
		FixtureOnly:    true,
	}
	manifest.ManifestHash = PolicyFixtureBundleManifestHash(manifest)
	if err := ValidatePolicyFixtureBundleManifest(manifest); err != nil {
		return PolicyFixtureBundleManifest{}, err
	}
	return manifest, nil
}

func ValidatePolicyFixtureBundleManifest(manifest PolicyFixtureBundleManifest) error {
	if manifest.SchemaVersion != PolicyFixtureBundleManifestSchemaVersion {
		return fmt.Errorf("%w: unsupported bundle manifest schema version", ErrInvalidPolicyFixtureBundle)
	}
	if !manifest.FixtureOnly {
		return fmt.Errorf("%w: bundle manifest must be fixture-only", ErrInvalidPolicyFixtureBundle)
	}
	if !validSHA256Hex(manifest.BundleHash) || !validSHA256Hex(manifest.SummaryHash) || !validSHA256Hex(manifest.ManifestHash) {
		return fmt.Errorf("%w: invalid bundle manifest hash", ErrInvalidPolicyFixtureBundle)
	}
	if len(manifest.SnapshotHashes) == 0 {
		return fmt.Errorf("%w: bundle manifest snapshot hashes are required", ErrInvalidPolicyFixtureBundle)
	}
	seen := map[string]struct{}{}
	for _, hash := range manifest.SnapshotHashes {
		if !validSHA256Hex(hash) {
			return fmt.Errorf("%w: invalid bundle manifest snapshot hash", ErrInvalidPolicyFixtureBundle)
		}
		if _, ok := seen[hash]; ok {
			return fmt.Errorf("%w: duplicate bundle manifest snapshot hash", ErrInvalidPolicyFixtureBundle)
		}
		seen[hash] = struct{}{}
	}
	if PolicyFixtureBundleManifestHash(manifest) != manifest.ManifestHash {
		return fmt.Errorf("%w: bundle manifest hash mismatch", ErrInvalidPolicyFixtureBundle)
	}
	return nil
}

func PolicyFixtureBundleManifestHash(manifest PolicyFixtureBundleManifest) string {
	hashes := append([]string(nil), manifest.SnapshotHashes...)
	sort.Strings(hashes)
	parts := []string{manifest.SchemaVersion, manifest.BundleHash, manifest.SummaryHash}
	parts = append(parts, hashes...)
	return sha256Hex(strings.Join(parts, "\x1f"))
}
