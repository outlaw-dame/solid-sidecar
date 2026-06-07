package authz

import (
	"context"
	"errors"
	"testing"
)

func TestInMemoryPolicyCacheStoreStoresListsAndGetsRecords(t *testing.T) {
	source := PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"}
	record := mustCacheRecord(t, source, []byte("policy-a"), 10, 100)
	store, err := NewInMemoryPolicyCacheStore([]PolicySourceCacheRecord{record}, 20)
	if err != nil {
		t.Fatalf("NewInMemoryPolicyCacheStore returned error: %v", err)
	}

	got, ok, err := store.GetPolicyCacheRecord(context.Background(), source)
	if err != nil {
		t.Fatalf("GetPolicyCacheRecord returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected record")
	}
	if got.State != PolicyCacheFresh {
		t.Fatalf("state = %q, want fresh", got.State)
	}

	listed, err := store.ListPolicyCacheRecords(context.Background())
	if err != nil {
		t.Fatalf("ListPolicyCacheRecords returned error: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed count = %d, want 1", len(listed))
	}
	listed[0].Version = "mutated"
	again, ok, err := store.GetPolicyCacheRecord(context.Background(), source)
	if err != nil || !ok {
		t.Fatalf("GetPolicyCacheRecord after list mutation = ok:%v err:%v", ok, err)
	}
	if again.Version == "mutated" {
		t.Fatal("list mutation changed store internals")
	}
}

func TestInMemoryPolicyCacheStorePutAndContextCancellation(t *testing.T) {
	source := PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"}
	record := mustCacheRecord(t, source, []byte("policy-a"), 10, 0)
	store, err := NewInMemoryPolicyCacheStore(nil, 20)
	if err != nil {
		t.Fatalf("NewInMemoryPolicyCacheStore returned error: %v", err)
	}
	if err := store.PutPolicyCacheRecord(context.Background(), record); err != nil {
		t.Fatalf("PutPolicyCacheRecord returned error: %v", err)
	}
	if _, ok, err := store.GetPolicyCacheRecord(context.Background(), source); err != nil || !ok {
		t.Fatalf("GetPolicyCacheRecord = ok:%v err:%v, want record", ok, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.PutPolicyCacheRecord(ctx, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("PutPolicyCacheRecord canceled error = %v, want context.Canceled", err)
	}
	if _, _, err := store.GetPolicyCacheRecord(ctx, source); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetPolicyCacheRecord canceled error = %v, want context.Canceled", err)
	}
	if _, err := store.ListPolicyCacheRecords(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListPolicyCacheRecords canceled error = %v, want context.Canceled", err)
	}
}

func TestBuildPolicyRefreshPlanClassifiesSources(t *testing.T) {
	missing := PolicySource{URI: "https://pod.example/policies/missing.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"}
	expired := PolicySource{URI: "https://pod.example/policies/expired.acl", Kind: PolicySourceExplicit, Priority: 20, ContentType: "text/turtle"}
	stale := PolicySource{URI: "https://pod.example/policies/stale.acl", Kind: PolicySourceExplicit, Priority: 30, ContentType: "text/turtle"}
	soon := PolicySource{URI: "https://pod.example/policies/soon.acl", Kind: PolicySourceExplicit, Priority: 40, ContentType: "text/turtle"}
	fresh := PolicySource{URI: "https://pod.example/policies/fresh.acl", Kind: PolicySourceExplicit, Priority: 50, ContentType: "text/turtle"}

	records := []PolicySourceCacheRecord{
		mustCacheRecord(t, expired, []byte("expired"), 10, 100),
		mustCacheRecord(t, stale, []byte("stale"), 0, 0),
		mustCacheRecord(t, soon, []byte("soon"), 10, 125),
		mustCacheRecord(t, fresh, []byte("fresh"), 10, 1000),
	}
	plan, err := BuildPolicyRefreshPlan(PolicyRefreshPlanOptions{
		Sources:          []PolicySource{fresh, missing, soon, stale, expired},
		Records:          records,
		NowUnix:          120,
		RefreshWindowSec: 10,
	})
	if err != nil {
		t.Fatalf("BuildPolicyRefreshPlan returned error: %v", err)
	}
	if plan.PlanVersion == "" || plan.CreatedAt != 120 {
		t.Fatalf("unexpected plan metadata: %#v", plan)
	}
	if len(plan.Items) != 5 {
		t.Fatalf("item count = %d, want 5", len(plan.Items))
	}

	byKey := make(map[string]PolicyRefreshItem, len(plan.Items))
	for _, item := range plan.Items {
		byKey[item.CacheKey] = item
	}
	assertRefreshItem(t, byKey[PolicySourceCacheKey(missing)], PolicyRefreshNow, PolicyRefreshReasonMissing, 120)
	assertRefreshItem(t, byKey[PolicySourceCacheKey(expired)], PolicyRefreshNow, PolicyRefreshReasonExpired, 120)
	assertRefreshItem(t, byKey[PolicySourceCacheKey(stale)], PolicyRefreshNow, PolicyRefreshReasonStale, 120)
	assertRefreshItem(t, byKey[PolicySourceCacheKey(soon)], PolicyRefreshLater, PolicyRefreshReasonFresh, 125)
	assertRefreshItem(t, byKey[PolicySourceCacheKey(fresh)], PolicyRefreshSkip, PolicyRefreshReasonFresh, 1000)
}

func TestBuildPolicyRefreshPlanIsDeterministic(t *testing.T) {
	sourceA := PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"}
	sourceB := PolicySource{URI: "https://pod.example/policies/b.acl", Kind: PolicySourceExplicit, Priority: 20, ContentType: "text/turtle"}
	recordA := mustCacheRecord(t, sourceA, []byte("a"), 10, 100)
	recordB := mustCacheRecord(t, sourceB, []byte("b"), 10, 100)

	left, err := BuildPolicyRefreshPlan(PolicyRefreshPlanOptions{Sources: []PolicySource{sourceB, sourceA}, Records: []PolicySourceCacheRecord{recordB, recordA}, NowUnix: 50, RefreshWindowSec: 10})
	if err != nil {
		t.Fatalf("BuildPolicyRefreshPlan left returned error: %v", err)
	}
	right, err := BuildPolicyRefreshPlan(PolicyRefreshPlanOptions{Sources: []PolicySource{sourceA, sourceB}, Records: []PolicySourceCacheRecord{recordA, recordB}, NowUnix: 50, RefreshWindowSec: 10})
	if err != nil {
		t.Fatalf("BuildPolicyRefreshPlan right returned error: %v", err)
	}
	if left.PlanVersion != right.PlanVersion {
		t.Fatalf("plan versions differ: %q vs %q", left.PlanVersion, right.PlanVersion)
	}
}

func TestBuildPolicyRefreshPlanRejectsInvalidTiming(t *testing.T) {
	_, err := BuildPolicyRefreshPlan(PolicyRefreshPlanOptions{NowUnix: -1})
	if !errors.Is(err, ErrInvalidPolicyRefresh) {
		t.Fatalf("negative now error = %v, want ErrInvalidPolicyRefresh", err)
	}
	_, err = BuildPolicyRefreshPlan(PolicyRefreshPlanOptions{RefreshWindowSec: -1})
	if !errors.Is(err, ErrInvalidPolicyRefresh) {
		t.Fatalf("negative window error = %v, want ErrInvalidPolicyRefresh", err)
	}
}

func assertRefreshItem(t *testing.T, item PolicyRefreshItem, action PolicyRefreshAction, reason PolicyRefreshReason, next int64) {
	t.Helper()
	if item.Action != action || item.Reason != reason || item.NextCheckAt != next {
		t.Fatalf("item = %#v, want action=%q reason=%q next=%d", item, action, reason, next)
	}
}

func mustCacheRecord(t *testing.T, source PolicySource, content []byte, loadedAt int64, expiresAt int64) PolicySourceCacheRecord {
	t.Helper()
	record, err := PolicyCacheRecordForLoadedSource(LoadedPolicySource{Source: source, Content: content}, loadedAt, expiresAt, "")
	if err != nil {
		t.Fatalf("PolicyCacheRecordForLoadedSource returned error: %v", err)
	}
	return record
}
