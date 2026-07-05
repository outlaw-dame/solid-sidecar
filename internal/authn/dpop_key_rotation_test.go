package authn

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDPoPKeyTracker_RegisterKey tests basic key registration
func TestDPoPKeyTracker_RegisterKey(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	// Generate a test key
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Register the key
	err = tracker.RegisterKey("key-1", publicKey, "Ed25519", "EdDSA")
	require.NoError(t, err)

	// Verify key is registered
	keyInfo, exists := tracker.GetKeyInfo("key-1")
	require.True(t, exists)
	assert.Equal(t, "key-1", keyInfo.KeyID)
	assert.Equal(t, "Ed25519", keyInfo.KeyType)
	assert.Equal(t, "EdDSA", keyInfo.Algorithm)
	assert.True(t, keyInfo.IsActive)
	assert.False(t, keyInfo.FirstSeen.IsZero())
}

// TestDPoPKeyTracker_RegisterKey_EmptyKeyID tests empty key ID rejection
func TestDPoPKeyTracker_RegisterKey_EmptyKeyID(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Empty key ID should fail
	err = tracker.RegisterKey("", publicKey, "Ed25519", "EdDSA")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key ID cannot be empty")
}

// TestDPoPKeyTracker_RegisterKey_Duplicate updates existing key
func TestDPoPKeyTracker_RegisterKey_Duplicate(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Register first key
	err = tracker.RegisterKey("key-1", publicKey1, "Ed25519", "EdDSA")
	require.NoError(t, err)

	firstSeen := time.Now()

	// Small delay to ensure different timestamps
	time.Sleep(10 * time.Millisecond)

	// Register second key with same ID
	err = tracker.RegisterKey("key-1", publicKey2, "Ed25519", "EdDSA")
	require.NoError(t, err)

	// Verify key was updated
	keyInfo, exists := tracker.GetKeyInfo("key-1")
	require.True(t, exists)
	assert.Equal(t, "key-1", keyInfo.KeyID)
	// LastSeen should be updated
	assert.True(t, keyInfo.LastSeen.After(firstSeen))
}

// TestDPoPKeyTracker_RegisterKeyWithWebID tests key registration with WebID
func TestDPoPKeyTracker_RegisterKeyWithWebID(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	webID := "https://example.org/alice#me"

	// Register key with WebID
	err = tracker.RegisterKeyWithWebID("key-1", publicKey, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Verify key is registered
	keyInfo, exists := tracker.GetKeyInfo("key-1")
	require.True(t, exists)
	assert.Equal(t, "key-1", keyInfo.KeyID)

	// Verify WebID association
	retrievedWebID, exists := tracker.GetWebIDForKey("key-1")
	require.True(t, exists)
	assert.Equal(t, webID, retrievedWebID)

	// Verify GetKeysByWebID
	keys := tracker.GetKeysByWebID(webID)
	assert.Len(t, keys, 1)
	assert.Equal(t, "key-1", keys[0].KeyID)
}

// TestDPoPKeyTracker_RecordKeyUsage tests recording key usage
func TestDPoPKeyTracker_RecordKeyUsage(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	webID := "https://example.org/alice#me"

	// Register key with WebID
	err = tracker.RegisterKeyWithWebID("key-1", publicKey, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Record usage
	err = tracker.RecordKeyUsage("key-1", webID)
	require.NoError(t, err)

	// Verify usage was recorded
	keyInfo, exists := tracker.GetKeyInfo("key-1")
	require.True(t, exists)
	assert.Equal(t, int64(1), keyInfo.UseCount)
	assert.False(t, keyInfo.LastUsed.IsZero())
}

// TestDPoPKeyTracker_RecordKeyUsage_NotFound tests recording usage for non-existent key
func TestDPoPKeyTracker_RecordKeyUsage_NotFound(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	// Try to record usage for non-existent key
	err := tracker.RecordKeyUsage("non-existent", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DPoP key not found")
}

// TestDPoPKeyTracker_CheckKeyRotation tests key rotation detection
func TestDPoPKeyTracker_CheckKeyRotation(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	webID := "https://example.org/alice#me"

	// Register old key
	err = tracker.RegisterKeyWithWebID("old-key", publicKey1, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Register new key with same WebID
	err = tracker.RegisterKeyWithWebID("new-key", publicKey2, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Record usage of old key
	err = tracker.RecordKeyUsage("old-key", webID)
	require.NoError(t, err)

	// Check for rotation
	rotated, err := tracker.CheckKeyRotation("old-key", "new-key", webID, "Ed25519", "Ed25519", "basic")
	require.NoError(t, err)
	assert.True(t, rotated)

	// Verify old key is now inactive
	oldKeyInfo, exists := tracker.GetKeyInfo("old-key")
	require.True(t, exists)
	assert.False(t, oldKeyInfo.IsActive)

	// Verify new key is active
	newKeyInfo, exists := tracker.GetKeyInfo("new-key")
	require.True(t, exists)
	assert.True(t, newKeyInfo.IsActive)
}

// TestDPoPKeyTracker_CheckKeyRotation_SameKey tests same key detection
func TestDPoPKeyTracker_CheckKeyRotation_SameKey(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	webID := "https://example.org/alice#me"

	// Register key
	err = tracker.RegisterKeyWithWebID("key-1", publicKey, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Check rotation with same key
	rotated, err := tracker.CheckKeyRotation("key-1", "key-1", webID, "Ed25519", "Ed25519", "basic")
	require.NoError(t, err)
	assert.False(t, rotated)
}

// TestDPoPKeyTracker_CheckKeyRotation_DifferentWebIDs tests different WebID detection
func TestDPoPKeyTracker_CheckKeyRotation_DifferentWebIDs(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Register keys with different WebIDs
	err = tracker.RegisterKeyWithWebID("key-1", publicKey1, "Ed25519", "EdDSA", "https://example.org/alice#me")
	require.NoError(t, err)

	err = tracker.RegisterKeyWithWebID("key-2", publicKey2, "Ed25519", "EdDSA", "https://example.org/bob#me")
	require.NoError(t, err)

	// Check rotation with different WebIDs - should not be rotation
	rotated, err := tracker.CheckKeyRotation("key-1", "key-2", "https://example.org/alice#me", "Ed25519", "Ed25519", "basic")
	require.NoError(t, err)
	assert.False(t, rotated)
}

// TestDPoPKeyTracker_InvalidateKey tests key invalidation
func TestDPoPKeyTracker_InvalidateKey(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Register key
	err = tracker.RegisterKey("key-1", publicKey, "Ed25519", "EdDSA")
	require.NoError(t, err)

	// Verify key is active
	keyInfo, exists := tracker.GetKeyInfo("key-1")
	require.True(t, exists)
	assert.True(t, keyInfo.IsActive)

	// Invalidate key
	tracker.InvalidateKey("key-1")

	// Verify key is now inactive
	keyInfo, exists = tracker.GetKeyInfo("key-1")
	require.True(t, exists)
	assert.False(t, keyInfo.IsActive)
}

// TestDPoPKeyTracker_InvalidateKeysByWebID tests WebID-based key invalidation
func TestDPoPKeyTracker_InvalidateKeysByWebID(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	webID := "https://example.org/alice#me"

	// Register keys with same WebID
	err = tracker.RegisterKeyWithWebID("key-1", publicKey1, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	err = tracker.RegisterKeyWithWebID("key-2", publicKey2, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Verify keys are active
	assert.True(t, tracker.GetActiveKeysByWebID(webID)[0].IsActive)
	assert.True(t, tracker.GetActiveKeysByWebID(webID)[1].IsActive)

	// Invalidate all keys for WebID
	tracker.InvalidateKeysByWebID(webID)

	// Verify all keys are now inactive
	activeKeys := tracker.GetActiveKeysByWebID(webID)
	assert.Len(t, activeKeys, 0)
}

// TestDPoPKeyTracker_GetActiveKeysByWebID tests retrieving active keys
func TestDPoPKeyTracker_GetActiveKeysByWebID(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	webID := "https://example.org/alice#me"

	// Register keys
	err = tracker.RegisterKeyWithWebID("key-1", publicKey1, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	err = tracker.RegisterKeyWithWebID("key-2", publicKey2, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Invalidate one key
	tracker.InvalidateKey("key-1")

	// Get active keys
	activeKeys := tracker.GetActiveKeysByWebID(webID)
	assert.Len(t, activeKeys, 1)
	assert.Equal(t, "key-2", activeKeys[0].KeyID)
}

// TestDPoPKeyTracker_Cleanup tests cleanup of inactive keys
func TestDPoPKeyTracker_Cleanup(t *testing.T) {
	t.Parallel()

	// Use short expiration for testing
	options := DefaultDPoPKeyTrackerOptions()
	options.KeyExpiration = 10 * time.Millisecond

	tracker := NewDPoPKeyTracker(options)

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Register key
	err = tracker.RegisterKey("key-1", publicKey, "Ed25519", "EdDSA")
	require.NoError(t, err)

	// Invalidate key
	tracker.InvalidateKey("key-1")

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Run cleanup
	tracker.Cleanup()

	// Verify key was removed
	_, exists := tracker.GetKeyInfo("key-1")
	assert.False(t, exists)
}

// TestDPoPKeyTracker_Size tests size tracking
func TestDPoPKeyTracker_Size(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	assert.Equal(t, 0, tracker.Size())

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = tracker.RegisterKey("key-1", publicKey, "Ed25519", "EdDSA")
	require.NoError(t, err)

	assert.Equal(t, 1, tracker.Size())

	err = tracker.RegisterKey("key-2", publicKey, "Ed25519", "EdDSA")
	require.NoError(t, err)

	assert.Equal(t, 2, tracker.Size())
}

// TestDPoPKeyTracker_Clear tests clearing all keys
func TestDPoPKeyTracker_Clear(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = tracker.RegisterKey("key-1", publicKey, "Ed25519", "EdDSA")
	require.NoError(t, err)

	assert.Equal(t, 1, tracker.Size())

	tracker.Clear()

	assert.Equal(t, 0, tracker.Size())
}

// TestGenerateKeyFingerprint tests key fingerprint generation
func TestGenerateKeyFingerprint(t *testing.T) {
	t.Parallel()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Generate fingerprint
	fingerprint, err := GenerateKeyFingerprint(publicKey)
	require.NoError(t, err)

	// Verify fingerprint is not empty and is valid hex
	assert.NotEmpty(t, fingerprint)
	assert.Len(t, fingerprint, 64) // SHA-256 hash is 32 bytes = 64 hex chars

	// Verify it's valid hex
	_, err = hex.DecodeString(fingerprint)
	assert.NoError(t, err)
}

// TestGenerateKeyFingerprint_RSA tests RSA key fingerprint generation
func TestGenerateKeyFingerprint_RSA(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey

	fingerprint, err := GenerateKeyFingerprint(publicKey)
	require.NoError(t, err)

	assert.NotEmpty(t, fingerprint)
	assert.Len(t, fingerprint, 64)
}

// TestDPoPKeyTracker_RotationCallback tests rotation callback
func TestDPoPKeyTracker_RotationCallback(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	publicKey1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	webID := "https://example.org/alice#me"

	// Register keys
	err = tracker.RegisterKeyWithWebID("old-key", publicKey1, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	err = tracker.RegisterKeyWithWebID("new-key", publicKey2, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Set up callback
	var callbackCalled bool
	var callbackInfo DPoPKeyRotationInfo
	tracker.RegisterRotationCallback(func(info DPoPKeyRotationInfo) {
		callbackCalled = true
		callbackInfo = info
	})

	// Trigger rotation
	_, err = tracker.CheckKeyRotation("old-key", "new-key", webID, "Ed25519", "Ed25519", "basic")
	require.NoError(t, err)

	// Verify callback was called
	assert.True(t, callbackCalled)
	assert.Equal(t, webID, callbackInfo.WebID)
	assert.Equal(t, "old-key", callbackInfo.OldKeyID)
	assert.Equal(t, "new-key", callbackInfo.NewKeyID)
	assert.Equal(t, "basic", callbackInfo.AssuranceLevel)
}

// TestDPoPKeyRotationDetector tests the detector wrapper
func TestDPoPKeyRotationDetector(t *testing.T) {
	t.Parallel()

	keyTracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())
	replayCache := NewReplayCache()

	detector := NewDPoPKeyRotationDetector(keyTracker, replayCache)

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	webID := "https://example.org/alice#me"

	// Register key
	err = detector.RegisterKey("key-1", publicKey, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Record usage
	err = detector.RecordKeyUsage("key-1", webID)
	require.NoError(t, err)

	// Get active keys
	activeKeys := detector.GetActiveKeysByWebID(webID)
	assert.Len(t, activeKeys, 1)
	assert.Equal(t, "key-1", activeKeys[0].KeyID)

	// Check replay cache integration
	nonce := "test-nonce-12345"
	expiresAt := time.Now().Add(1 * time.Hour)

	// First store should succeed
	stored := detector.StoreReplay(nonce, expiresAt)
	assert.True(t, stored)

	// Second store with same nonce should fail
	stored = detector.StoreReplay(nonce, expiresAt)
	assert.False(t, stored)

	// Check replay should detect the replay
	isReplay := detector.CheckReplay(nonce, expiresAt)
	assert.True(t, isReplay)
}

// TestDPoPKeyTracker_MaxKeys tests max keys limit
func TestDPoPKeyTracker_MaxKeys(t *testing.T) {
	t.Parallel()

	options := DefaultDPoPKeyTrackerOptions()
	options.MaxKeys = 2

	tracker := NewDPoPKeyTracker(options)

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Register 2 keys
	err = tracker.RegisterKey("key-1", publicKey, "Ed25519", "EdDSA")
	require.NoError(t, err)

	err = tracker.RegisterKey("key-2", publicKey, "Ed25519", "EdDSA")
	require.NoError(t, err)

	assert.Equal(t, 2, tracker.Size())

	// Third key should fail
	err = tracker.RegisterKey("key-3", publicKey, "Ed25519", "EdDSA")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum keys limit")
}

// TestDPoPKeyTracker_RapidRotationDetection tests rapid rotation detection
func TestDPoPKeyTracker_RapidRotationDetection(t *testing.T) {
	t.Parallel()

	options := DefaultDPoPKeyTrackerOptions()
	options.RotationThreshold = 1 * time.Second

	tracker := NewDPoPKeyTracker(options)

	publicKey1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	webID := "https://example.org/alice#me"

	// Register old key
	err = tracker.RegisterKeyWithWebID("old-key", publicKey1, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Register new key
	err = tracker.RegisterKeyWithWebID("new-key", publicKey2, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// Record usage of old key
	err = tracker.RecordKeyUsage("old-key", webID)
	require.NoError(t, err)

	// Trigger rotation immediately after usage
	_, err = tracker.CheckKeyRotation("old-key", "new-key", webID, "Ed25519", "Ed25519", "basic")
	require.NoError(t, err)

	// The rotation should have been detected and logged as warning
	// We can't easily verify the log output, but we can verify the keys were updated
	oldKeyInfo, exists := tracker.GetKeyInfo("old-key")
	require.True(t, exists)
	assert.False(t, oldKeyInfo.IsActive)
}

// TestMarshalPublicKey tests the marshalPublicKey function
func TestMarshalPublicKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  crypto.PublicKey
	}{
		{
			name: "Ed25519",
			key: func() crypto.PublicKey {
				_, pub, _ := ed25519.GenerateKey(rand.Reader)
				return ed25519.PublicKey(pub)
			}(),
		},
		{
			name: "RSA",
			key: func() crypto.PublicKey {
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				return &priv.PublicKey
			}(),
		},
		// ECDSA test would need curve setup, skipping for simplicity
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := marshalPublicKey(tt.key)
			require.NoError(t, err)
			assert.NotEmpty(t, data)
		})
	}
}

// TestDPoPKeyTracker_SetLogger tests logger setting
func TestDPoPKeyTracker_SetLogger(t *testing.T) {
	t.Parallel()

	tracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())

	logger := slog.Default()
	tracker.SetLogger(logger)

	// We can't easily verify the logger was set, but at least ensure no panic
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = tracker.RegisterKey("key-1", publicKey, "Ed25519", "EdDSA")
	require.NoError(t, err)
}

// TestDPoPKeyTracker_NilLogger tests nil logger handling
func TestDPoPKeyTracker_NilLogger(t *testing.T) {
	t.Parallel()

	options := DefaultDPoPKeyTrackerOptions()
	options.Logger = nil
	options.AuditLogger = nil

	tracker := NewDPoPKeyTracker(options)

	// Should not panic with nil loggers
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = tracker.RegisterKey("key-1", publicKey, "Ed25519", "EdDSA")
	require.NoError(t, err)
}

// TestDPoPKeyTracker_Context tests context usage
func TestDPoPKeyTracker_Context(t *testing.T) {
	t.Parallel()

	keyTracker := NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())
	replayCache := NewReplayCache()

	detector := NewDPoPKeyRotationDetector(keyTracker, replayCache)

	ctx := context.Background()
	webID := "https://example.org/alice#me"

	// This should not panic with context
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = detector.RegisterKey("key-1", publicKey, "Ed25519", "EdDSA", webID)
	require.NoError(t, err)

	// CheckKeyRotation with context
	_, err = detector.CheckKeyRotation(ctx, "key-1", "key-1", webID, "Ed25519", "Ed25519", "basic")
	require.NoError(t, err)
}
