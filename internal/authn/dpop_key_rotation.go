package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ErrDPoPKeyNotFound is returned when a DPoP key is not found
var ErrDPoPKeyNotFound = errors.New("DPoP key not found")

// ErrDPoPKeyRotationDetected is returned when a DPoP key rotation is detected
var ErrDPoPKeyRotationDetected = errors.New("DPoP key rotation detected")

// DPoPKeyInfo holds information about a DPoP public key
type DPoPKeyInfo struct {
	// KeyID is the unique identifier for the key (e.g., JWT kid)
	KeyID string

	// PublicKey is the raw public key
	PublicKey crypto.PublicKey

	// KeyType is the type of key (e.g., "RSA", "EC", "Ed25519")
	KeyType string

	// Algorithm is the signing algorithm (e.g., "RS256", "ES256", "EdDSA")
	Algorithm string

	// FirstSeen is when the key was first seen
	FirstSeen time.Time

	// LastSeen is when the key was last seen
	LastSeen time.Time

	// LastUsed is when the key was last used in a valid proof
	LastUsed time.Time

	// UseCount is the number of times the key has been used
	UseCount int64

	// WebID is the WebID associated with this key (if known)
	WebID string

	// IsActive indicates if the key is currently active
	IsActive bool
}

// DPoPKeyRotationInfo holds information about a DPoP key rotation event
type DPoPKeyRotationInfo struct {
	// WebID is the WebID whose key was rotated
	WebID string

	// OldKeyID is the previous key identifier
	OldKeyID string

	// NewKeyID is the new key identifier
	NewKeyID string

	// RotatedAt is when the rotation occurred
	RotatedAt time.Time

	// OldKeyType is the type of the old key
	OldKeyType string

	// NewKeyType is the type of the new key
	NewKeyType string

	// AssuranceLevel is the identity assurance level
	AssuranceLevel string
}

// DPoPKeyTracker tracks DPoP public keys and detects rotations
type DPoPKeyTracker struct {
	mu sync.RWMutex

	// keys maps key IDs to key information
	keys map[string]*DPoPKeyInfo

	// webIDToKeys maps WebIDs to their known key IDs
	webIDToKeys map[string]map[string]bool

	// keyToWebID maps key IDs to WebIDs
	keyToWebID map[string]string

	// rotationCallbacks holds callbacks for key rotation events
	rotationCallbacks []func(DPoPKeyRotationInfo)

	// logger is used for tracking operations
	logger *slog.Logger

	// auditLogger is used for audit logging
	auditLogger *slog.Logger

	// options configure the tracker
	options DPoPKeyTrackerOptions
}

// DPoPKeyTrackerOptions configures the DPoP key tracker
type DPoPKeyTrackerOptions struct {
	// MaxKeys is the maximum number of keys to track (0 = unlimited)
	MaxKeys int

	// KeyExpiration is how long to keep inactive keys
	KeyExpiration time.Duration

	// RotationThreshold is the minimum time between rotations to trigger an alert
	RotationThreshold time.Duration

	// Logger is the logger to use
	Logger *slog.Logger

	// AuditLogger is the audit logger to use
	AuditLogger *slog.Logger
}

// DefaultDPoPKeyTrackerOptions returns safe default options
func DefaultDPoPKeyTrackerOptions() DPoPKeyTrackerOptions {
	return DPoPKeyTrackerOptions{
		MaxKeys:           10000,
		KeyExpiration:     24 * time.Hour,
		RotationThreshold: 5 * time.Minute,
		Logger:            nil,
		AuditLogger:       nil,
	}
}

// NewDPoPKeyTracker creates a new DPoP key tracker
func NewDPoPKeyTracker(options DPoPKeyTrackerOptions) *DPoPKeyTracker {
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.AuditLogger == nil {
		options.AuditLogger = options.Logger
	}

	return &DPoPKeyTracker{
		keys:        make(map[string]*DPoPKeyInfo),
		webIDToKeys: make(map[string]map[string]bool),
		keyToWebID:  make(map[string]string),
		logger:      options.Logger,
		auditLogger: options.AuditLogger,
		options:     options,
	}
}

// SetLogger sets the logger for the tracker
func (t *DPoPKeyTracker) SetLogger(logger *slog.Logger) {
	if logger != nil {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.logger = logger
	}
}

// SetAuditLogger sets the audit logger for the tracker
func (t *DPoPKeyTracker) SetAuditLogger(logger *slog.Logger) {
	if logger != nil {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.auditLogger = logger
	}
}

// RegisterKey registers a DPoP public key
func (t *DPoPKeyTracker) RegisterKey(keyID string, publicKey crypto.PublicKey, keyType string, algorithm string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if keyID == "" {
		return errors.New("key ID cannot be empty")
	}

	now := time.Now()

	// Check if key already exists
	if existing, exists := t.keys[keyID]; exists {
		// Update existing key
		existing.PublicKey = publicKey
		existing.KeyType = keyType
		existing.Algorithm = algorithm
		existing.LastSeen = now
		existing.IsActive = true
		return nil
	}

	// Check max keys limit
	if t.options.MaxKeys > 0 && len(t.keys) >= t.options.MaxKeys {
		// Evict inactive keys if we're at capacity
		t.evictInactiveKeys()

		// If still at capacity, reject
		if len(t.keys) >= t.options.MaxKeys {
			return fmt.Errorf("maximum keys limit (%d) reached", t.options.MaxKeys)
		}
	}

	// Create new key info
	keyInfo := &DPoPKeyInfo{
		KeyID:     keyID,
		PublicKey: publicKey,
		KeyType:   keyType,
		Algorithm: algorithm,
		FirstSeen: now,
		LastSeen:  now,
		IsActive:  true,
	}

	t.keys[keyID] = keyInfo
	t.logger.Debug("DPoP key registered", "key_id", keyID, "key_type", keyType)

	return nil
}

// RegisterKeyWithWebID registers a DPoP key with an associated WebID
func (t *DPoPKeyTracker) RegisterKeyWithWebID(keyID string, publicKey crypto.PublicKey, keyType string, algorithm string, webID string) error {
	err := t.RegisterKey(keyID, publicKey, keyType, algorithm)
	if err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Associate key with WebID
	if _, exists := t.webIDToKeys[webID]; !exists {
		t.webIDToKeys[webID] = make(map[string]bool)
	}
	t.webIDToKeys[webID][keyID] = true
	t.keyToWebID[keyID] = webID

	t.logger.Debug("DPoP key associated with WebID", "key_id", keyID, "webid", webID)

	return nil
}

// RecordKeyUsage records that a key was used in a valid proof
func (t *DPoPKeyTracker) RecordKeyUsage(keyID string, webID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	keyInfo, exists := t.keys[keyID]
	if !exists {
		return fmt.Errorf("%w: %s", ErrDPoPKeyNotFound, keyID)
	}

	now := time.Now()
	keyInfo.LastUsed = now
	keyInfo.UseCount++
	keyInfo.IsActive = true

	// Associate with WebID if provided
	if webID != "" {
		if _, exists := t.webIDToKeys[webID]; !exists {
			t.webIDToKeys[webID] = make(map[string]bool)
		}
		t.webIDToKeys[webID][keyID] = true
		t.keyToWebID[keyID] = webID
	}

	return nil
}

// CheckKeyRotation checks if a key rotation has occurred and records it
func (t *DPoPKeyTracker) CheckKeyRotation(oldKeyID, newKeyID, webID, oldKeyType, newKeyType, assuranceLevel string) (bool, error) {
	if oldKeyID == newKeyID {
		// Same key, no rotation
		return false, nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if old key exists and is associated with the WebID
	oldKeyInfo, oldExists := t.keys[oldKeyID]
	if !oldExists {
		// Old key not tracked, can't confirm rotation
		return false, nil
	}

	// Check if new key exists
	newKeyInfo, newExists := t.keys[newKeyID]
	if !newExists {
		// New key not tracked, can't confirm rotation
		// But we should still record the new key
		t.mu.Unlock()
		t.RegisterKeyWithWebID(newKeyID, nil, newKeyType, "", webID)
		t.mu.Lock()
		return false, nil
	}

	// Check if both keys are associated with the same WebID
	oldWebID := t.keyToWebID[oldKeyID]
	newWebID := t.keyToWebID[newKeyID]

	if oldWebID != newWebID {
		// Keys are for different WebIDs, not a rotation
		return false, nil
	}

	// Check time threshold
	now := time.Now()
	if !oldKeyInfo.LastUsed.IsZero() {
		timeSinceLastUse := now.Sub(oldKeyInfo.LastUsed)
		if timeSinceLastUse < t.options.RotationThreshold {
			// Rotation happened too quickly, might be suspicious
			t.auditLogger.Warn("Rapid DPoP key rotation detected",
				"webid", webID,
				"old_key", oldKeyID,
				"new_key", newKeyID,
				"time_since_last_use", timeSinceLastUse)
		}
	}

	// Mark old key as inactive
	oldKeyInfo.IsActive = false
	oldKeyInfo.LastSeen = now

	// Mark new key as active
	newKeyInfo.IsActive = true
	newKeyInfo.LastSeen = now
	newKeyInfo.LastUsed = now

	// Create rotation info
	rotationInfo := DPoPKeyRotationInfo{
		WebID:          webID,
		OldKeyID:       oldKeyID,
		NewKeyID:       newKeyID,
		RotatedAt:      now,
		OldKeyType:     oldKeyType,
		NewKeyType:     newKeyType,
		AssuranceLevel: assuranceLevel,
	}

	// Notify callbacks
	t.notifyRotation(rotationInfo)

	// Log to audit
	t.auditLogger.Info("DPoP key rotation detected",
		"webid", webID,
		"old_key", oldKeyID,
		"new_key", newKeyID,
		"old_key_type", oldKeyType,
		"new_key_type", newKeyType,
		"assurance", assuranceLevel)

	return true, nil
}

// notifyRotation notifies all registered callbacks
func (t *DPoPKeyTracker) notifyRotation(info DPoPKeyRotationInfo) {
	for _, callback := range t.rotationCallbacks {
		callback(info)
	}
}

// RegisterRotationCallback registers a callback for key rotation events
func (t *DPoPKeyTracker) RegisterRotationCallback(callback func(DPoPKeyRotationInfo)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rotationCallbacks = append(t.rotationCallbacks, callback)
}

// GetKeyInfo returns information about a key
func (t *DPoPKeyTracker) GetKeyInfo(keyID string) (*DPoPKeyInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	keyInfo, exists := t.keys[keyID]
	return keyInfo, exists
}

// GetKeysByWebID returns all keys associated with a WebID
func (t *DPoPKeyTracker) GetKeysByWebID(webID string) []*DPoPKeyInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var keys []*DPoPKeyInfo
	if keyIDs, exists := t.webIDToKeys[webID]; exists {
		for keyID := range keyIDs {
			if keyInfo, ok := t.keys[keyID]; ok {
				keys = append(keys, keyInfo)
			}
		}
	}
	return keys
}

// GetActiveKeysByWebID returns all active keys associated with a WebID
func (t *DPoPKeyTracker) GetActiveKeysByWebID(webID string) []*DPoPKeyInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var keys []*DPoPKeyInfo
	if keyIDs, exists := t.webIDToKeys[webID]; exists {
		for keyID := range keyIDs {
			if keyInfo, ok := t.keys[keyID]; ok && keyInfo.IsActive {
				keys = append(keys, keyInfo)
			}
		}
	}
	return keys
}

// GetWebIDForKey returns the WebID associated with a key ID
func (t *DPoPKeyTracker) GetWebIDForKey(keyID string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	webID, exists := t.keyToWebID[keyID]
	return webID, exists
}

// InvalidateKey invalidates a key (e.g., when revoked)
func (t *DPoPKeyTracker) InvalidateKey(keyID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if keyInfo, exists := t.keys[keyID]; exists {
		keyInfo.IsActive = false
		keyInfo.LastSeen = time.Now()
		t.logger.Info("DPoP key invalidated", "key_id", keyID)
	}
}

// InvalidateKeysByWebID invalidates all keys associated with a WebID
func (t *DPoPKeyTracker) InvalidateKeysByWebID(webID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if keyIDs, exists := t.webIDToKeys[webID]; exists {
		for keyID := range keyIDs {
			if keyInfo, ok := t.keys[keyID]; ok {
				keyInfo.IsActive = false
				keyInfo.LastSeen = time.Now()
				t.logger.Info("DPoP key invalidated", "key_id", keyID, "webid", webID)
			}
		}
		delete(t.webIDToKeys, webID)
	}
}

// evictInactiveKeys removes inactive keys to make room for new ones
// Must be called with lock held
func (t *DPoPKeyTracker) evictInactiveKeys() {
	now := time.Now()
	expiration := t.options.KeyExpiration

	for keyID, keyInfo := range t.keys {
		if !keyInfo.IsActive && now.Sub(keyInfo.LastSeen) > expiration {
			delete(t.keys, keyID)

			// Also remove from mappings
			if webID, ok := t.keyToWebID[keyID]; ok {
				if webIDKeys, ok := t.webIDToKeys[webID]; ok {
					delete(webIDKeys, keyID)
					if len(webIDKeys) == 0 {
						delete(t.webIDToKeys, webID)
					}
				}
				delete(t.keyToWebID, keyID)
			}
		}
	}
}

// Cleanup removes expired and inactive keys
func (t *DPoPKeyTracker) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.evictInactiveKeys()
}

// Size returns the number of tracked keys
func (t *DPoPKeyTracker) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.keys)
}

// Clear removes all tracked keys
func (t *DPoPKeyTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.keys = make(map[string]*DPoPKeyInfo)
	t.webIDToKeys = make(map[string]map[string]bool)
	t.keyToWebID = make(map[string]string)
	t.logger.Info("DPoP key tracker cleared")
}

// GenerateKeyFingerprint generates a fingerprint for a public key
func GenerateKeyFingerprint(publicKey crypto.PublicKey) (string, error) {
	// Marshal the public key
	publicKeyBytes, err := marshalPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	// Hash the public key
	hash := sha256.Sum256(publicKeyBytes)

	// Return as hex string
	return hex.EncodeToString(hash[:]), nil
}

// marshalPublicKey marshals a public key to bytes
func marshalPublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return marshalRSAPublicKey(key), nil
	case *ecdsa.PublicKey:
		return marshalECDSAPublicKey(key), nil
	case ed25519.PublicKey:
		return marshalEd25519PublicKey(key), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", publicKey)
	}
}

// marshalRSAPublicKey marshals an RSA public key
func marshalRSAPublicKey(key *rsa.PublicKey) []byte {
	// Simple marshaling - in production, use proper encoding
	return []byte(fmt.Sprintf("rsa:%d:%d", key.Size(), key.E))
}

// marshalECDSAPublicKey marshals an ECDSA public key
func marshalECDSAPublicKey(key *ecdsa.PublicKey) []byte {
	// Simple marshaling - in production, use proper encoding
	return []byte(fmt.Sprintf("ecdsa:%s:%d:%d", key.Curve.Params().Name, key.X.BitLen(), key.Y.BitLen()))
}

// marshalEd25519PublicKey marshals an Ed25519 public key
func marshalEd25519PublicKey(key ed25519.PublicKey) []byte {
	return []byte(key)
}

// KeyRotationTracker is a callback type for key rotation events
type KeyRotationTracker func(info DPoPKeyRotationInfo)

// DPoPKeyAuditLog holds audit information for DPoP key operations
type DPoPKeyAuditLog struct {
	// Timestamp is when the operation occurred
	Timestamp time.Time

	// Operation is the type of operation (register, use, rotate, invalidate)
	Operation string

	// KeyID is the key identifier
	KeyID string

	// WebID is the associated WebID
	WebID string

	// KeyType is the key type
	KeyType string

	// Details contains additional operation-specific details
	Details map[string]string
}

// AuditLogger is an interface for audit logging
type AuditLogger interface {
	LogKeyOperation(ctx context.Context, operation DPoPKeyAuditLog) error
}

// LogKeyOperation logs a key operation to the audit log
func (t *DPoPKeyTracker) LogKeyOperation(ctx context.Context, operation string, keyID string, webID string, keyType string, details map[string]string) {
	t.auditLogger.Info("DPoP key operation",
		"operation", operation,
		"key_id", keyID,
		"webid", webID,
		"key_type", keyType,
		"details", details)
}

// DPoPKeyRotationDetector provides key rotation detection for DPoP proofs
type DPoPKeyRotationDetector struct {
	// keyTracker tracks known DPoP keys
	keyTracker *DPoPKeyTracker

	// replayCache prevents replay attacks
	replayCache *ReplayCache

	// logger is used for detection operations
	logger *slog.Logger
}

// NewDPoPKeyRotationDetector creates a new key rotation detector
func NewDPoPKeyRotationDetector(keyTracker *DPoPKeyTracker, replayCache *ReplayCache) *DPoPKeyRotationDetector {
	if keyTracker == nil {
		keyTracker = NewDPoPKeyTracker(DefaultDPoPKeyTrackerOptions())
	}
	if replayCache == nil {
		replayCache = NewReplayCache()
	}

	return &DPoPKeyRotationDetector{
		keyTracker:  keyTracker,
		replayCache: replayCache,
		logger:      slog.Default(),
	}
}

// SetLogger sets the logger for the detector
func (d *DPoPKeyRotationDetector) SetLogger(logger *slog.Logger) {
	if logger != nil {
		d.logger = logger
	}
}

// CheckKeyRotation checks if a key rotation has occurred between two proofs
func (d *DPoPKeyRotationDetector) CheckKeyRotation(ctx context.Context, oldProofKeyID, newProofKeyID, webID, oldKeyType, newKeyType, assuranceLevel string) (bool, error) {
	return d.keyTracker.CheckKeyRotation(oldProofKeyID, newProofKeyID, webID, oldKeyType, newKeyType, assuranceLevel)
}

// RecordKeyUsage records that a key was used in a valid proof
func (d *DPoPKeyRotationDetector) RecordKeyUsage(keyID string, webID string) error {
	return d.keyTracker.RecordKeyUsage(keyID, webID)
}

// RegisterKey registers a DPoP key
func (d *DPoPKeyRotationDetector) RegisterKey(keyID string, publicKey crypto.PublicKey, keyType string, algorithm string, webID string) error {
	return d.keyTracker.RegisterKeyWithWebID(keyID, publicKey, keyType, algorithm, webID)
}

// GetActiveKeysByWebID returns all active keys for a WebID
func (d *DPoPKeyRotationDetector) GetActiveKeysByWebID(webID string) []*DPoPKeyInfo {
	return d.keyTracker.GetActiveKeysByWebID(webID)
}

// InvalidateKeysByWebID invalidates all keys for a WebID
func (d *DPoPKeyRotationDetector) InvalidateKeysByWebID(webID string) {
	d.keyTracker.InvalidateKeysByWebID(webID)
}

// CheckReplay checks if a DPoP proof has been replayed
func (d *DPoPKeyRotationDetector) CheckReplay(nonce string, expiresAt time.Time) bool {
	return !d.replayCache.Store(nonce, expiresAt)
}

// StoreReplay stores a DPoP nonce to prevent replay
func (d *DPoPKeyRotationDetector) StoreReplay(nonce string, expiresAt time.Time) bool {
	return d.replayCache.Store(nonce, expiresAt)
}
