package authz

import (
	"context"
	"testing"
)

func TestPolicyFixtureArtifactsBuild(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	bundle, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := PolicyFixtureBundleManifestForBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundleRecord, err := PolicyFixtureArtifactRecordForBundle(bundle, 100, 3600, "phase-output")
	if err != nil {
		t.Fatal(err)
	}
	manifestRecord, err := PolicyFixtureArtifactRecordForManifest(manifest, 100, 3600, "phase-output")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := PolicyFixtureArtifactCatalogFromRecords([]PolicyFixtureArtifactRecord{manifestRecord, bundleRecord, bundleRecord})
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Records) != 2 || catalog.CatalogHash == "" || !catalog.FixtureOnly {
		t.Fatal(catalog)
	}
	check, err := PolicyFixtureArtifactCheckForBundle(bundle, manifest, catalog, 200)
	if err != nil {
		t.Fatal(err)
	}
	if check.Status != PolicyFixtureArtifactCheckOK || check.CheckHash == "" || !check.FixtureOnly {
		t.Fatal(check)
	}
}

func TestPolicyFixtureArtifactHashesAreDeterministic(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	left, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	right, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	leftRecord, err := PolicyFixtureArtifactRecordForBundle(left, 100, 0, "phase-output")
	if err != nil {
		t.Fatal(err)
	}
	rightRecord, err := PolicyFixtureArtifactRecordForBundle(right, 100, 0, "phase-output")
	if err != nil {
		t.Fatal(err)
	}
	if leftRecord.RecordHash != rightRecord.RecordHash {
		t.Fatalf("%s != %s", leftRecord.RecordHash, rightRecord.RecordHash)
	}
}
