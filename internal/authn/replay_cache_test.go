package authn

import (
	"testing"
	"time"
)

func TestReplayCacheRejectsDuplicateUntilExpiry(t *testing.T) {
	cache := NewReplayCache()
	now := time.Unix(100, 0)
	cache.now = func() time.Time { return now }
	if !cache.Store("proof", now.Add(time.Minute)) {
		t.Fatal("first store should succeed")
	}
	if cache.Store("proof", now.Add(time.Minute)) {
		t.Fatal("duplicate proof should be rejected")
	}
	now = now.Add(2 * time.Minute)
	if !cache.Store("proof", now.Add(time.Minute)) {
		t.Fatal("expired proof should be accepted again")
	}
}
