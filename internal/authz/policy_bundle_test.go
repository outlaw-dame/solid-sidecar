package authz

import (
	"context"
	"testing"
)

func TestPolicyFixtureBundleAndManifestBuild(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	bundle, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Snapshots) != 3 || bundle.BundleHash == "" || !bundle.FixtureOnly {
		t.Fatal(bundle)
	}
	if err := ValidatePolicyFixtureBundle(bundle); err != nil {
		t.Fatal(err)
	}
	manifest, err := PolicyFixtureBundleManifestForBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.BundleHash != bundle.BundleHash || len(manifest.SnapshotHashes) != len(bundle.Snapshots) || manifest.ManifestHash == "" {
		t.Fatal(manifest)
	}
	if err := ValidatePolicyFixtureBundleManifest(manifest); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyFixtureBundleHashIsDeterministic(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	left, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	right, err := PolicyFixtureBundleFromSuite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if left.BundleHash != right.BundleHash {
		t.Fatalf("%s != %s", left.BundleHash, right.BundleHash)
	}
}
