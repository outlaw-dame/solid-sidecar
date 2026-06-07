package authz

import (
	"context"
	"testing"
)

func TestPolicyFixtureReleaseBuilds(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	bundle, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil { t.Fatal(err) }
	manifest, err := PolicyFixtureBundleManifestForBundle(bundle)
	if err != nil { t.Fatal(err) }
	bundleArtifact, err := PolicyFixtureArtifactRecordForBundle(bundle, 100, 3600, "release")
	if err != nil { t.Fatal(err) }
	manifestArtifact, err := PolicyFixtureArtifactRecordForManifest(manifest, 100, 3600, "release")
	if err != nil { t.Fatal(err) }
	catalog, err := PolicyFixtureArtifactCatalogFromRecords([]PolicyFixtureArtifactRecord{bundleArtifact, manifestArtifact})
	if err != nil { t.Fatal(err) }
	exportRecord, err := PolicyFixtureExportRecordForBundle(bundle, "bundle.json", 100, 512)
	if err != nil { t.Fatal(err) }
	index, err := PolicyFixtureExportIndexFromRecords([]PolicyFixtureExportRecord{exportRecord})
	if err != nil { t.Fatal(err) }
	check, err := PolicyFixtureExportCheckForIndex(index, 200)
	if err != nil { t.Fatal(err) }
	release, err := PolicyFixtureReleaseRecordForBundle(bundle, manifest, catalog, index, check, 300)
	if err != nil { t.Fatal(err) }
	ledger, err := PolicyFixtureReleaseLedgerFromRecords([]PolicyFixtureReleaseRecord{release, release})
	if err != nil { t.Fatal(err) }
	if len(ledger.Records) != 1 || ledger.LedgerHash == "" { t.Fatal(ledger) }
	review, err := PolicyFixtureReleaseReviewForLedger(ledger, 400)
	if err != nil { t.Fatal(err) }
	if review.Status != PolicyFixtureReleaseOK || review.RecordCount != 1 || review.ReviewHash == "" { t.Fatal(review) }
}

func TestPolicyFixtureReleaseHashIsDeterministic(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	bundle, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil { t.Fatal(err) }
	manifest, err := PolicyFixtureBundleManifestForBundle(bundle)
	if err != nil { t.Fatal(err) }
	bundleArtifact, err := PolicyFixtureArtifactRecordForBundle(bundle, 100, 0, "release")
	if err != nil { t.Fatal(err) }
	manifestArtifact, err := PolicyFixtureArtifactRecordForManifest(manifest, 100, 0, "release")
	if err != nil { t.Fatal(err) }
	catalog, err := PolicyFixtureArtifactCatalogFromRecords([]PolicyFixtureArtifactRecord{bundleArtifact, manifestArtifact})
	if err != nil { t.Fatal(err) }
	exportRecord, err := PolicyFixtureExportRecordForBundle(bundle, "bundle.json", 100, 512)
	if err != nil { t.Fatal(err) }
	index, err := PolicyFixtureExportIndexFromRecords([]PolicyFixtureExportRecord{exportRecord})
	if err != nil { t.Fatal(err) }
	check, err := PolicyFixtureExportCheckForIndex(index, 200)
	if err != nil { t.Fatal(err) }
	left, err := PolicyFixtureReleaseRecordForBundle(bundle, manifest, catalog, index, check, 300)
	if err != nil { t.Fatal(err) }
	right, err := PolicyFixtureReleaseRecordForBundle(bundle, manifest, catalog, index, check, 300)
	if err != nil { t.Fatal(err) }
	if left.ReleaseHash != right.ReleaseHash { t.Fatalf("%s != %s", left.ReleaseHash, right.ReleaseHash) }
}
