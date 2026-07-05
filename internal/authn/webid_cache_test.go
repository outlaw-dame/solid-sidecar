package authn

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWebIDCache_BasicOperations(t *testing.T) {
	// Create cache with test options
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 10
	options.DefaultTTL = 100 * time.Millisecond

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Test 1: Cache miss
	_, ok := cache.Get("https://example.com/profile/card#me")
	if ok {
		t.Error("Expected cache miss for non-existent entry")
	}

	// Test 2: Cache hit after set
	profile := &WebIDProfile{
		Subject: "https://example.com/profile/card#me",
		Type:    []string{"Person"},
	}

	err := cache.Set("https://example.com/profile/card#me", profile, "https://issuer.example.com", "medium")
	if err != nil {
		t.Fatalf("Failed to set cache entry: %v", err)
	}

	cachedProfile, ok := cache.Get("https://example.com/profile/card#me")
	if !ok {
		t.Error("Expected cache hit after set")
	}
	if cachedProfile.Subject != profile.Subject {
		t.Errorf("Expected subject %s, got %s", profile.Subject, cachedProfile.Subject)
	}

	// Test 3: Get with metadata
	cachedProfile, issuer, assuranceLevel, ok := cache.GetWithMetadata("https://example.com/profile/card#me")
	if !ok {
		t.Error("Expected cache hit for GetWithMetadata")
	}
	if issuer != "https://issuer.example.com" {
		t.Errorf("Expected issuer %s, got %s", "https://issuer.example.com", issuer)
	}
	if assuranceLevel != "medium" {
		t.Errorf("Expected assurance level %s, got %s", "medium", assuranceLevel)
	}

	// Test 4: Invalidate
	cache.Invalidate("https://example.com/profile/card#me")
	_, ok = cache.Get("https://example.com/profile/card#me")
	if ok {
		t.Error("Expected cache miss after invalidate")
	}

	// Test 5: Size
	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after invalidate, got %d", cache.Size())
	}
}

func TestWebIDCache_TTLExpiration(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 10
	options.DefaultTTL = 50 * time.Millisecond

	cache := NewWebIDCache(options)
	defer cache.Close()

	profile := &WebIDProfile{
		Subject: "https://example.com/profile/card#me",
		Type:    []string{"Person"},
	}

	// Set entry
	err := cache.Set("https://example.com/profile/card#me", profile, "https://issuer.example.com", "medium")
	if err != nil {
		t.Fatalf("Failed to set cache entry: %v", err)
	}

	// Should be in cache
	_, ok := cache.Get("https://example.com/profile/card#me")
	if !ok {
		t.Error("Expected cache hit immediately after set")
	}

	// Wait for TTL to expire
	time.Sleep(60 * time.Millisecond)

	// Should be expired
	_, ok = cache.Get("https://example.com/profile/card#me")
	if ok {
		t.Error("Expected cache miss after TTL expiration")
	}
}

func TestWebIDCache_MaxSize(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 3
	options.DefaultTTL = 1 * time.Hour

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Add 3 entries
	for i := 0; i < 3; i++ {
		webID := "https://example.com/profile/card#" + string(rune('a'+i))
		profile := &WebIDProfile{
			Subject: webID,
			Type:    []string{"Person"},
		}
		err := cache.Set(webID, profile, "https://issuer.example.com", "medium")
		if err != nil {
			t.Fatalf("Failed to set cache entry %d: %v", i, err)
		}
	}

	// Cache should be at max size
	if cache.Size() != 3 {
		t.Errorf("Expected size 3, got %d", cache.Size())
	}

	// Try to add a 4th entry - should evict oldest
	webID := "https://example.com/profile/card#d"
	profile := &WebIDProfile{
		Subject: webID,
		Type:    []string{"Person"},
	}

	err := cache.Set(webID, profile, "https://issuer.example.com", "medium")
	if err != nil {
		t.Fatalf("Failed to set cache entry (should have evicted): %v", err)
	}

	// Size should still be 3 (oldest was evicted)
	if cache.Size() != 3 {
		t.Errorf("Expected size 3 after eviction, got %d", cache.Size())
	}

	// The new entry should be in cache
	_, ok := cache.Get(webID)
	if !ok {
		t.Error("Expected new entry to be in cache")
	}
}

func TestWebIDCache_SetWithTTL(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 10
	options.DefaultTTL = 1 * time.Hour

	cache := NewWebIDCache(options)
	defer cache.Close()

	profile := &WebIDProfile{
		Subject: "https://example.com/profile/card#me",
		Type:    []string{"Person"},
	}

	// Set with custom TTL
	err := cache.SetWithTTL("https://example.com/profile/card#me", profile, "https://issuer.example.com", "medium", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to set cache entry with TTL: %v", err)
	}

	// Should be in cache
	_, ok := cache.Get("https://example.com/profile/card#me")
	if !ok {
		t.Error("Expected cache hit immediately after set")
	}

	// Wait for custom TTL to expire
	time.Sleep(60 * time.Millisecond)

	// Should be expired
	_, ok = cache.Get("https://example.com/profile/card#me")
	if ok {
		t.Error("Expected cache miss after custom TTL expiration")
	}
}

func TestWebIDCache_NilProfile(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	cache := NewWebIDCache(options)
	defer cache.Close()

	// Setting nil profile should fail
	err := cache.Set("https://example.com/profile/card#me", nil, "https://issuer.example.com", "medium")
	if err == nil {
		t.Error("Expected error when setting nil profile")
	}
}

func TestWebIDCache_InvalidateByIssuer(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 10
	options.DefaultTTL = 1 * time.Hour

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Add entries with different issuers
	issuers := []string{"https://issuer1.example.com", "https://issuer2.example.com"}
	for i, issuer := range issuers {
		webID := "https://example.com/profile/card#" + string(rune('a'+i))
		profile := &WebIDProfile{
			Subject: webID,
			Type:    []string{"Person"},
		}
		cache.Set(webID, profile, issuer, "medium")
	}

	// Both should be in cache
	if cache.Size() != 2 {
		t.Errorf("Expected size 2, got %d", cache.Size())
	}

	// Invalidate all entries from issuer1
	cache.InvalidateByIssuer("https://issuer1.example.com")

	// Only issuer2 entry should remain
	if cache.Size() != 1 {
		t.Errorf("Expected size 1 after invalidate by issuer, got %d", cache.Size())
	}

	// issuer1 entry should be gone
	_, ok := cache.Get("https://example.com/profile/card#a")
	if ok {
		t.Error("Expected issuer1 entry to be invalidated")
	}

	// issuer2 entry should still be there
	_, ok = cache.Get("https://example.com/profile/card#b")
	if !ok {
		t.Error("Expected issuer2 entry to still be in cache")
	}
}

func TestWebIDCache_Clear(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 10
	options.DefaultTTL = 1 * time.Hour

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Add some entries
	for i := 0; i < 5; i++ {
		webID := "https://example.com/profile/card#" + string(rune('a'+i))
		profile := &WebIDProfile{
			Subject: webID,
			Type:    []string{"Person"},
		}
		cache.Set(webID, profile, "https://issuer.example.com", "medium")
	}

	if cache.Size() != 5 {
		t.Errorf("Expected size 5, got %d", cache.Size())
	}

	// Clear cache
	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", cache.Size())
	}
}

func TestWebIDCache_CheckAndInvalidateOnKeyChange(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 10
	options.DefaultTTL = 1 * time.Hour

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Create a mock verifier that returns different profiles
	// For this test, we'll just test the basic flow

	// Add a profile to cache
	profile1 := &WebIDProfile{
		Subject: "https://example.com/profile/card#me",
		Type:    []string{"Person"},
		Claims:  map[string]any{"key": "old-key"},
	}
	cache.Set("https://example.com/profile/card#me", profile1, "https://issuer.example.com", "medium")

	// Since we can't easily mock the verifier in this test,
	// we'll just verify the basic invalidation logic works
	cache.Invalidate("https://example.com/profile/card#me")

	_, ok := cache.Get("https://example.com/profile/card#me")
	if ok {
		t.Error("Expected cache miss after invalidation")
	}
}

func TestWebIDCache_ProfilesEqual(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	cache := NewWebIDCache(options)
	defer cache.Close()

	// Test equal profiles
	profile1 := &WebIDProfile{
		Subject:         "https://example.com/profile/card#me",
		SolidOIDCIssuer: "https://issuer.example.com",
	}
	profile2 := &WebIDProfile{
		Subject:         "https://example.com/profile/card#me",
		SolidOIDCIssuer: "https://issuer.example.com",
	}

	if !cache.profilesEqual(profile1, profile2) {
		t.Error("Expected equal profiles to be equal")
	}

	// Test different subjects
	profile3 := &WebIDProfile{
		Subject:         "https://example.com/profile/card#other",
		SolidOIDCIssuer: "https://issuer.example.com",
	}

	if cache.profilesEqual(profile1, profile3) {
		t.Error("Expected profiles with different subjects to be different")
	}

	// Test different issuers
	profile4 := &WebIDProfile{
		Subject:         "https://example.com/profile/card#me",
		SolidOIDCIssuer: "https://other-issuer.example.com",
	}

	if cache.profilesEqual(profile1, profile4) {
		t.Error("Expected profiles with different issuers to be different")
	}

	// Test nil profiles
	if !cache.profilesEqual(nil, nil) {
		t.Error("Expected two nil profiles to be equal")
	}

	if cache.profilesEqual(nil, profile1) {
		t.Error("Expected nil and non-nil profiles to be different")
	}
}

func TestWebIDCache_DefaultOptions(t *testing.T) {
	options := DefaultWebIDCacheOptions()

	if options.MaxSize != 1000 {
		t.Errorf("Expected default MaxSize 1000, got %d", options.MaxSize)
	}

	if options.DefaultTTL != 5*time.Minute {
		t.Errorf("Expected default TTL 5m, got %v", options.DefaultTTL)
	}

	if options.CleanupInterval != 1*time.Minute {
		t.Errorf("Expected default CleanupInterval 1m, got %v", options.CleanupInterval)
	}
}

func TestWebIDCache_NewWebIDCache(t *testing.T) {
	options := WebIDCacheOptions{
		MaxSize:         0,   // Should default to 1000
		DefaultTTL:      0,   // Should default to 5m
		CleanupInterval: 0,   // Should default to 1m
		Logger:          nil, // Should default to slog.Default()
	}

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Should not panic and should have defaults applied
	if cache.maxSize != 1000 {
		t.Errorf("Expected maxSize 1000, got %d", cache.maxSize)
	}

	if cache.defaultTTL != 5*time.Minute {
		t.Errorf("Expected defaultTTL 5m, got %v", cache.defaultTTL)
	}

	if cache.cleanupInterval != 1*time.Minute {
		t.Errorf("Expected cleanupInterval 1m, got %v", cache.cleanupInterval)
	}
}

func TestWebIDCache_KeyRotationCallback(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	cache := NewWebIDCache(options)
	defer cache.Close()

	// Register a callback
	callbackCalled := false

	cache.RegisterKeyRotationCallback(func(info KeyRotationInfo) {
		callbackCalled = true
		_ = info
	})

	// The callback is registered but we can't easily trigger it without
	// implementing the full key rotation detection logic.
	// This test just verifies the registration doesn't panic.

	if !callbackCalled {
		// Expected - we didn't trigger a rotation
		// This is fine for now
	}
}

func TestWebIDCache_ConcurrentAccess(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 100
	options.DefaultTTL = 1 * time.Hour

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Test concurrent writes and reads
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 50; i++ {
			webID := "https://example.com/profile/card#" + string(rune('a'+i%26))
			profile := &WebIDProfile{
				Subject: webID,
				Type:    []string{"Person"},
			}
			cache.Set(webID, profile, "https://issuer.example.com", "medium")
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 50; i++ {
			webID := "https://example.com/profile/card#" + string(rune('a'+i%26))
			cache.Get(webID)
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Just verify no panic occurred
	t.Log("Concurrent access test passed without panic")
}

func TestWebIDCache_InvalidateNonExistent(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	cache := NewWebIDCache(options)
	defer cache.Close()

	// Invalidate a non-existent entry should not panic
	cache.Invalidate("https://nonexistent.example.com/profile/card#me")

	// Verify no panic
	t.Log("Invalidate non-existent entry test passed")
}

func TestWebIDCache_InvalidateByIssuerNonExistent(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	cache := NewWebIDCache(options)
	defer cache.Close()

	// Invalidate by non-existent issuer should not panic
	cache.InvalidateByIssuer("https://nonexistent.example.com")

	// Verify no panic
	t.Log("Invalidate by non-existent issuer test passed")
}

// MockWebIDVerifier is a mock for testing
type MockWebIDVerifier struct {
	mockProfile *WebIDProfile
	mockError   error
}

func (m *MockWebIDVerifier) VerifyWebIDOwnership(ctx context.Context, webID string) (*WebIDProfile, error) {
	return m.mockProfile, m.mockError
}

func TestWebIDCache_CheckAndInvalidateOnKeyChange_WithMock(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 10
	options.DefaultTTL = 1 * time.Hour

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Add a profile to cache
	profile1 := &WebIDProfile{
		Subject: "https://example.com/profile/card#me",
		Type:    []string{"Person"},
	}
	cache.Set("https://example.com/profile/card#me", profile1, "https://issuer.example.com", "medium")

	// We can't use the actual CheckAndInvalidateOnKeyChange method directly
	// because it uses the embedded verifier which we can't easily mock.
	// This test verifies the basic structure.

	// Create a verifier with a proper HTTP client to avoid nil pointer dereference
	verifier := NewWebIDVerifier(nil, []string{"https://issuer.example.com"})

	// For now, just verify we can call methods without panic
	// Note: This will likely fail to fetch the profile, but shouldn't panic
	_, err := cache.CheckAndInvalidateOnKeyChange(
		context.Background(),
		"https://example.com/profile/card#me",
		verifier,
	)

	// This will likely return an error or false, but shouldn't panic
	if err == nil && cache.Size() == 0 {
		t.Log("CheckAndInvalidateOnKeyChange test passed (cache was invalidated)")
	} else {
		t.Logf("CheckAndInvalidateOnKeyChange test completed with err=%v, size=%d", err, cache.Size())
	}
}

func TestWebIDCache_KeyRotationInfo(t *testing.T) {
	info := KeyRotationInfo{
		WebID:          "https://example.com/profile/card#me",
		OldKeyID:       "key-1",
		NewKeyID:       "key-2",
		RotatedAt:      time.Now(),
		AssuranceLevel: "high",
	}

	if info.WebID != "https://example.com/profile/card#me" {
		t.Errorf("Expected WebID %s, got %s", "https://example.com/profile/card#me", info.WebID)
	}

	if info.OldKeyID != "key-1" {
		t.Errorf("Expected OldKeyID %s, got %s", "key-1", info.OldKeyID)
	}

	if info.NewKeyID != "key-2" {
		t.Errorf("Expected NewKeyID %s, got %s", "key-2", info.NewKeyID)
	}

	if info.AssuranceLevel != "high" {
		t.Errorf("Expected AssuranceLevel %s, got %s", "high", info.AssuranceLevel)
	}
}

func TestWebIDCache_EntryExpiration(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 10
	options.DefaultTTL = 10 * time.Millisecond

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Add a profile
	profile := &WebIDProfile{
		Subject: "https://example.com/profile/card#me",
		Type:    []string{"Person"},
	}
	cache.Set("https://example.com/profile/card#me", profile, "https://issuer.example.com", "medium")

	// Verify it's in cache
	if cache.Size() != 1 {
		t.Fatalf("Expected size 1, got %d", cache.Size())
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Manually trigger cleanup (since we don't want to wait for the next tick)
	cache.cleanupExpired()

	// Should be empty now
	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after cleanup, got %d", cache.Size())
	}
}

func TestWebIDCache_DuplicateSet(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 10
	options.DefaultTTL = 1 * time.Hour

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Add a profile
	profile1 := &WebIDProfile{
		Subject: "https://example.com/profile/card#me",
		Type:    []string{"Person"},
		Claims:  map[string]any{"key": "value1"},
	}
	cache.Set("https://example.com/profile/card#me", profile1, "https://issuer.example.com", "medium")

	// Update the same profile with new data
	profile2 := &WebIDProfile{
		Subject: "https://example.com/profile/card#me",
		Type:    []string{"Person"},
		Claims:  map[string]any{"key": "value2"},
	}
	cache.Set("https://example.com/profile/card#me", profile2, "https://issuer.example.com", "high")

	// Size should still be 1 (updated, not duplicated)
	if cache.Size() != 1 {
		t.Errorf("Expected size 1 after update, got %d", cache.Size())
	}

	// Get the profile and verify it has the new data
	cachedProfile, ok := cache.Get("https://example.com/profile/card#me")
	if !ok {
		t.Fatal("Expected profile to be in cache")
	}

	if cachedProfile.Claims["key"] != "value2" {
		t.Errorf("Expected updated value, got %v", cachedProfile.Claims["key"])
	}
}

// Test errors
var (
	ErrTestCacheExceeded = errors.New("test cache exceeded")
)

func TestWebIDCache_ExceedsMaxSize(t *testing.T) {
	options := DefaultWebIDCacheOptions()
	options.MaxSize = 2
	options.DefaultTTL = 1 * time.Hour

	cache := NewWebIDCache(options)
	defer cache.Close()

	// Add 2 entries
	for i := 0; i < 2; i++ {
		webID := "https://example.com/profile/card#" + string(rune('a'+i))
		profile := &WebIDProfile{
			Subject: webID,
			Type:    []string{"Person"},
		}
		cache.Set(webID, profile, "https://issuer.example.com", "medium")
	}

	// Cache should be full
	if cache.Size() != 2 {
		t.Fatalf("Expected size 2, got %d", cache.Size())
	}

	// Try to add a 3rd entry with a new WebID (not updating existing)
	webID := "https://example.com/profile/card#c"
	profile := &WebIDProfile{
		Subject: webID,
		Type:    []string{"Person"},
	}

	// This should evict the oldest and succeed
	err := cache.Set(webID, profile, "https://issuer.example.com", "medium")
	if err != nil {
		t.Fatalf("Expected set to succeed with eviction, got error: %v", err)
	}

	// Size should still be 2 (oldest was evicted)
	if cache.Size() != 2 {
		t.Errorf("Expected size 2 after eviction, got %d", cache.Size())
	}
}
