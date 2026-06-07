package authz

import (
	"context"
	"errors"
	"testing"
)

func TestInMemoryPolicySourceLoaderLoadsCopyAndMetadata(t *testing.T) {
	source := PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "TEXT/TURTLE"}
	content := []byte("policy document")
	loader, err := NewInMemoryPolicySourceLoader(map[PolicySource]InMemoryPolicySourceEntry{
		source: {Content: content, LoadedAtUnix: 100, ExpiresAtUnix: 200},
	})
	if err != nil {
		t.Fatalf("NewInMemoryPolicySourceLoader returned error: %v", err)
	}
	content[0] = 'X'

	result, err := loader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("LoadPolicySource returned error: %v", err)
	}
	if string(result.Loaded.Content) != "policy document" {
		t.Fatalf("loaded content = %q, want original copy", string(result.Loaded.Content))
	}
	result.Loaded.Content[0] = 'Y'
	again, err := loader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("LoadPolicySource returned error: %v", err)
	}
	if string(again.Loaded.Content) != "policy document" {
		t.Fatalf("loader returned mutable internal content: %q", string(again.Loaded.Content))
	}
	if result.Metadata.CacheKey == "" || result.Metadata.Version == "" {
		t.Fatalf("expected cache key/version: %#v", result.Metadata)
	}
	if result.Metadata.Document.ContentType != "text/turtle" {
		t.Fatalf("document content type = %q", result.Metadata.Document.ContentType)
	}
	if result.Metadata.State != PolicyCacheFresh {
		t.Fatalf("state = %q, want fresh", result.Metadata.State)
	}
}

func TestInMemoryPolicySourceLoaderRejectsUnsafeInput(t *testing.T) {
	loader, err := NewInMemoryPolicySourceLoader(nil)
	if err != nil {
		t.Fatalf("NewInMemoryPolicySourceLoader returned error: %v", err)
	}
	validSource := PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"}
	if err := loader.Store(validSource, InMemoryPolicySourceEntry{}); !errors.Is(err, ErrInvalidPolicyLoad) {
		t.Fatalf("empty content error = %v, want ErrInvalidPolicyLoad", err)
	}
	if _, err := loader.LoadPolicySource(context.Background(), validSource); !errors.Is(err, ErrInvalidPolicyLoad) {
		t.Fatalf("missing source error = %v, want ErrInvalidPolicyLoad", err)
	}
	if _, err := loader.LoadPolicySource(context.Background(), PolicySource{URI: "not-a-url"}); !errors.Is(err, ErrInvalidPolicySource) {
		t.Fatalf("invalid source error = %v, want ErrInvalidPolicySource", err)
	}
}

func TestInMemoryPolicySourceLoaderHonorsContextCancellation(t *testing.T) {
	loader, err := NewInMemoryPolicySourceLoader(nil)
	if err != nil {
		t.Fatalf("NewInMemoryPolicySourceLoader returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = loader.LoadPolicySource(ctx, PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestPolicySourceCacheKeyIsDeterministic(t *testing.T) {
	left := PolicySource{URI: " https://pod.example/policies/a.acl ", Kind: PolicySourceExplicit, Priority: 10, ContentType: "TEXT/TURTLE"}
	right := PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"}
	if PolicySourceCacheKey(left) == "" {
		t.Fatal("expected cache key")
	}
	if PolicySourceCacheKey(left) != PolicySourceCacheKey(right) {
		t.Fatalf("cache keys differ: %q vs %q", PolicySourceCacheKey(left), PolicySourceCacheKey(right))
	}
}

func TestPolicyCacheStateAt(t *testing.T) {
	for _, test := range []struct {
		name    string
		loaded  int64
		expires int64
		now     int64
		want    PolicyCacheState
	}{
		{name: "missing loaded", loaded: 0, expires: 0, now: 100, want: PolicyCacheStale},
		{name: "fresh no expiry", loaded: 10, expires: 0, now: 100, want: PolicyCacheFresh},
		{name: "fresh before expiry", loaded: 10, expires: 200, now: 100, want: PolicyCacheFresh},
		{name: "expired at boundary", loaded: 10, expires: 100, now: 100, want: PolicyCacheExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := PolicyCacheStateAt(test.loaded, test.expires, test.now); got != test.want {
				t.Fatalf("state = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNormalizePolicyCacheRecordsDeduplicatesAndRejectsConflicts(t *testing.T) {
	sourceA := PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"}
	sourceB := PolicySource{URI: "https://pod.example/policies/b.acl", Kind: PolicySourceExplicit, Priority: 20, ContentType: "text/turtle"}
	loadedA := LoadedPolicySource{Source: sourceA, Content: []byte("a")}
	loadedB := LoadedPolicySource{Source: sourceB, Content: []byte("b")}
	recordA, err := PolicyCacheRecordForLoadedSource(loadedA, 10, 20, "")
	if err != nil {
		t.Fatalf("PolicyCacheRecordForLoadedSource returned error: %v", err)
	}
	recordB, err := PolicyCacheRecordForLoadedSource(loadedB, 11, 0, "")
	if err != nil {
		t.Fatalf("PolicyCacheRecordForLoadedSource returned error: %v", err)
	}

	got, err := NormalizePolicyCacheRecords([]PolicySourceCacheRecord{recordB, recordA, recordA}, 21)
	if err != nil {
		t.Fatalf("NormalizePolicyCacheRecords returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("record count = %d, want 2", len(got))
	}
	byKey := make(map[string]PolicySourceCacheRecord, len(got))
	for _, record := range got {
		byKey[record.CacheKey] = record
	}
	if byKey[recordA.CacheKey].State != PolicyCacheExpired {
		t.Fatalf("record A state = %q, want expired", byKey[recordA.CacheKey].State)
	}
	if byKey[recordB.CacheKey].State != PolicyCacheFresh {
		t.Fatalf("record B state = %q, want fresh", byKey[recordB.CacheKey].State)
	}

	conflict := recordA
	conflict.Document.SHA256 = policyHashB
	if _, err := NormalizePolicyCacheRecords([]PolicySourceCacheRecord{recordA, conflict}, 21); !errors.Is(err, ErrInvalidPolicyLoad) {
		t.Fatalf("conflict error = %v, want ErrInvalidPolicyLoad", err)
	}
}
