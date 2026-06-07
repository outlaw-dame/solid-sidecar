package authz

import (
	"context"
	"testing"
)

func TestPolicyFixtureMarkersBuild(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	bundle, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil { t.Fatal(err) }
	manifest, err := PolicyFixtureBundleManifestForBundle(bundle)
	if err != nil { t.Fatal(err) }
	bundleArtifact, err := PolicyFixtureArtifactRecordForBundle(bundle, 100, 0, "marker")
	if err != nil { t.Fatal(err) }
	manifestArtifact, err := PolicyFixtureArtifactRecordForManifest(manifest, 100, 0, "marker")
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
	ledger, err := PolicyFixtureReleaseLedgerFromRecords([]PolicyFixtureReleaseRecord{release})
	if err != nil { t.Fatal(err) }
	review, err := PolicyFixtureReleaseReviewForLedger(ledger, 400)
	if err != nil { t.Fatal(err) }
	marker, err := PolicyFixtureMarkerRecordForRelease(release, ledger, review, "phase-29", 500)
	if err != nil { t.Fatal(err) }
	log, err := PolicyFixtureMarkerLogFromRecords([]PolicyFixtureMarkerRecord{marker, marker})
	if err != nil { t.Fatal(err) }
	if len(log.Records) != 1 || log.LogHash == "" { t.Fatal(log) }
	markerReview, err := PolicyFixtureMarkerReviewForLog(log, 600)
	if err != nil { t.Fatal(err) }
	if markerReview.Status != PolicyFixtureMarkerOK || markerReview.RecordCount != 1 || markerReview.ReviewHash == "" { t.Fatal(markerReview) }
}

func TestPolicyFixtureMarkerHashIsDeterministic(t *testing.T) {
	record := PolicyFixtureMarkerRecord{SchemaVersion: PolicyFixtureMarkerRecordSchemaVersion, ReleaseHash: fixedHash("a"), LedgerHash: fixedHash("b"), ReviewHash: fixedHash("c"), Label: "phase-29", CreatedAtUnix: 500, FixtureOnly: true}
	record.MarkerHash = PolicyFixtureMarkerRecordHash(record)
	copy := record
	copy.MarkerHash = PolicyFixtureMarkerRecordHash(copy)
	if record.MarkerHash != copy.MarkerHash { t.Fatalf("%s != %s", record.MarkerHash, copy.MarkerHash) }
	if err := ValidatePolicyFixtureMarkerRecord(record); err != nil { t.Fatal(err) }
}

func fixedHash(char string) string {
	out := ""
	for len(out) < 64 { out += char }
	return out[:64]
}
