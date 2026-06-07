package authz

import (
	"context"
	"testing"
)

func TestFixtureMetaBuilds(t *testing.T) {
	suite := readPolicySemanticsSuiteFixture(t)
	items, err := PolicyFixtureSnapshotsFromSuite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatal(len(items))
	}
	for _, item := range items {
		if err := ValidatePolicyFixtureSnapshot(item); err != nil {
			t.Fatal(err)
		}
	}
	rollup, err := PolicyFixtureSummaryFromSnapshots(items)
	if err != nil {
		t.Fatal(err)
	}
	if rollup.SnapshotCount != len(items) || rollup.SummaryHash == "" || !rollup.FixtureOnly {
		t.Fatal(rollup)
	}
	if err := ValidatePolicyFixtureSummary(rollup); err != nil {
		t.Fatal(err)
	}
}
