package authz

import (
	"context"
	"testing"
)

func TestPolicyFixtureExportBuilds(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	bundle, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := PolicyFixtureBundleManifestForBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundleRecord, err := PolicyFixtureExportRecordForBundle(bundle, "bundle.json", 100, 512)
	if err != nil {
		t.Fatal(err)
	}
	manifestRecord, err := PolicyFixtureExportRecordForManifest(manifest, "manifest.json", 100, 256)
	if err != nil {
		t.Fatal(err)
	}
	index, err := PolicyFixtureExportIndexFromRecords([]PolicyFixtureExportRecord{manifestRecord, bundleRecord, bundleRecord})
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Records) != 2 || index.IndexHash == "" || !index.FixtureOnly {
		t.Fatal(index)
	}
	check, err := PolicyFixtureExportCheckForIndex(index, 200)
	if err != nil {
		t.Fatal(err)
	}
	if check.Status != PolicyFixtureExportOK || check.RecordCount != 2 || check.CheckHash == "" {
		t.Fatal(check)
	}
}

func TestPolicyFixtureExportHashesAreDeterministic(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	bundle, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	left, err := PolicyFixtureExportRecordForBundle(bundle, "bundle.json", 100, 512)
	if err != nil {
		t.Fatal(err)
	}
	right, err := PolicyFixtureExportRecordForBundle(bundle, "bundle.json", 100, 512)
	if err != nil {
		t.Fatal(err)
	}
	if left.ExportHash != right.ExportHash {
		t.Fatalf("%s != %s", left.ExportHash, right.ExportHash)
	}
}
