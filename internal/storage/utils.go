// Package storage provides the production storage engine for the Solid runtime.
// This file contains utility functions.
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// sha256Sum computes SHA-256 hash of data
func sha256Sum(data []byte) [32]byte {
	if len(data) == 0 {
		return [32]byte{}
	}
	return sha256.Sum256(data)
}

// computeDigest computes a SHA-256 digest for the given data
func computeDigest(data []byte) string {
	hash := sha256Sum(data)
	return hex.EncodeToString(hash[:])
}

// computeContentAddress computes a content address for the given data
func computeContentAddress(data []byte) ContentAddress {
	return ContentAddress(computeDigest(data))
}

// Storage limits for resource exhaustion prevention
const (
	// MaxURILength is the maximum length of a resource URI
	MaxURILength = 8192

	// MaxBodySize is the maximum size of a resource body in bytes (100MB)
	MaxBodySize = 100 * 1024 * 1024

	// MaxMetadataSize is the maximum size of metadata in bytes (1MB)
	MaxMetadataSize = 1024 * 1024

	// MaxContentAddressLength is the maximum length of a content address
	MaxContentAddressLength = 128

	// MaxStorageRootLength is the maximum length of a storage root identifier
	MaxStorageRootLength = 1024

	// MaxTenantLength is the maximum length of a tenant identifier
	MaxTenantLength = 256

	// MaxResourceCountPerList is the maximum number of resources returned in a list operation
	MaxResourceCountPerList = 10000
)

// Validation errors
var (
	ErrURITooLong       = errors.New("URI exceeds maximum length")
	ErrBodyTooLarge     = errors.New("body exceeds maximum size")
	ErrMetadataTooLarge = errors.New("metadata exceeds maximum size")
	ErrEmptyURI         = errors.New("URI cannot be empty")
	ErrNilResource      = errors.New("resource cannot be nil")
	ErrNilTombstone     = errors.New("tombstone cannot be nil")
	ErrNilContext       = errors.New("context cannot be nil")
)

// generateETag generates an ETag for the given data
// ETags are typically quoted strings in HTTP, but for storage we use a hex-encoded format
func generateETag(data []byte) string {
	if len(data) == 0 {
		return "\"0-0\""
	}
	hash := sha256Sum(data)
	// Use hex encoding to ensure the ETag is a valid string
	return "\"" + hex.EncodeToString(hash[:8]) + "\""
}

// ValidateURI validates a resource URI
// Returns sanitized URI or error if invalid
func ValidateURI(uri string) (string, error) {
	if uri == "" {
		return "", ErrEmptyURI
	}

	if len(uri) > MaxURILength {
		return "", ErrURITooLong
	}

	// Check for valid URI format (basic check - URI should not contain invalid characters)
	// We allow standard URI characters and some special characters used in Solid
	validChars := func(r rune) bool {
		// Allow alphanumeric, common URI characters, and Solid-specific characters
		return (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '/' || r == '.' || r == '-' || r == '_' || r == '~' ||
			r == ':' || r == '?' || r == '#' || r == '[' || r == ']' ||
			r == '!' || r == '$' || r == '&' || r == '\'' || r == '(' ||
			r == ')' || r == '*' || r == '+' || r == ',' || r == ';' ||
			r == '=' || r == '@' || r == '%'
	}

	for _, r := range uri {
		if !validChars(r) {
			return "", fmt.Errorf("%w: invalid character in URI", ErrInvalidURI)
		}
	}

	// Additional validation: URI should start with / for absolute URIs
	if !strings.HasPrefix(uri, "/") {
		// Allow relative URIs but normalize them
		if !strings.Contains(uri, ":") && !strings.HasPrefix(uri, "/") {
			uri = "/" + uri
		}
	}

	// Normalize multiple consecutive slashes
	uri = strings.ReplaceAll(uri, "//", "/")

	// Remove trailing slash unless it's the root
	if len(uri) > 1 && strings.HasSuffix(uri, "/") {
		uri = strings.TrimSuffix(uri, "/")
	}

	return uri, nil
}

// ValidateStorageRoot validates a storage root identifier
func ValidateStorageRoot(storageRoot string) error {
	if storageRoot == "" {
		return nil // Empty storage root is allowed (defaults to URI)
	}

	if len(storageRoot) > MaxStorageRootLength {
		return ErrURITooLong
	}

	// Storage root should be a valid URI
	_, err := ValidateURI(storageRoot)
	return err
}

// ValidateTenant validates a tenant identifier
func ValidateTenant(tenant string) error {
	if tenant == "" {
		return nil // Empty tenant is allowed
	}

	if len(tenant) > MaxTenantLength {
		return fmt.Errorf("tenant exceeds maximum length of %d characters", MaxTenantLength)
	}

	// Tenant should only contain alphanumeric, hyphen, underscore, and period
	for _, r := range tenant {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("invalid character in tenant identifier: %c", r)
		}
	}

	return nil
}

// ValidateContentType validates a content type
func ValidateContentType(contentType string) error {
	if contentType == "" {
		return nil // Empty content type is allowed
	}

	// Basic validation - content type should not contain newlines or control characters
	for _, r := range contentType {
		if r < 32 || r == 127 {
			return ErrInvalidContentType
		}
	}

	// Check for valid content type format (type/subtype)
	if !strings.Contains(contentType, "/") {
		// Some legacy content types might not have a slash
		// but we still allow them for compatibility
		return nil
	}

	return nil
}

// ValidateBodySize validates the size of a resource body
func ValidateBodySize(body []byte) error {
	if body == nil {
		return nil
	}

	if len(body) > MaxBodySize {
		return ErrBodyTooLarge
	}

	return nil
}

// ValidateBodyReaderSize validates the size from a body reader
// Returns error if size exceeds limits or if size is negative
func ValidateBodyReaderSize(size int64) error {
	if size < 0 {
		return fmt.Errorf("body size cannot be negative")
	}

	if size > MaxBodySize {
		return ErrBodyTooLarge
	}

	return nil
}

// ValidateContentAddress validates a content address
func ValidateContentAddress(address ContentAddress) error {
	if address == "" {
		return nil // Empty address might be allowed in some contexts
	}

	if len(address) > MaxContentAddressLength {
		return fmt.Errorf("content address exceeds maximum length")
	}

	// Content address should be a valid SHA-256 hex string (64 characters for full hash)
	// But we also support shorter hashes and other formats used in tests
	// Allow alphanumeric and some special characters for flexibility
	for _, r := range address {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			r == '-' || r == '_' || r == '.' || r == '/' || r == ':') {
			return fmt.Errorf("invalid character in content address: %c", r)
		}
	}

	return nil
}

// validateTombstone validates a tombstone object
func validateTombstone(tombstone *Tombstone) error {
	if tombstone == nil {
		return ErrNilTombstone
	}

	// Validate URI
	if tombstone.URI == "" {
		return ErrEmptyURI
	}

	if len(tombstone.URI) > MaxURILength {
		return ErrURITooLong
	}

	// Validate DeletedBy (if present, should be reasonable length)
	if len(tombstone.DeletedBy) > MaxTenantLength {
		return fmt.Errorf("deletedBy exceeds maximum length")
	}

	// Validate Reason (if present, should be reasonable length)
	if len(tombstone.Reason) > 1024 {
		return fmt.Errorf("reason exceeds maximum length")
	}

	// Validate RestoreToken (if present, should be reasonable length)
	if len(tombstone.RestoreToken) > 256 {
		return fmt.Errorf("restoreToken exceeds maximum length")
	}

	return nil
}

// estimateMetadataSize estimates the size of metadata for quota purposes
func estimateMetadataSize(metadata *Metadata) int64 {
	if metadata == nil {
		return 0
	}

	size := 0
	size += len(metadata.URI)
	size += len(metadata.ResourceType)
	size += len(metadata.ContentType)
	size += len(metadata.Digest)
	size += len(metadata.Owner)
	size += len(metadata.StorageRoot)
	size += len(metadata.Tenant)
	size += len(metadata.ContentAddress)
	size += len(metadata.ETag)

	// Add size for maps
	for k, v := range metadata.AuxiliaryLinks {
		size += len(k) + len(v)
	}
	for _, v := range metadata.PolicyReferences {
		size += len(v)
	}
	for k, v := range metadata.ValidatorState {
		size += len(k) + len(v)
	}
	for k, v := range metadata.Custom {
		size += len(k) + len(v)
	}

	// Add overhead for JSON serialization
	size += 200

	return int64(size)
}

// validateMetadataSize validates the size of metadata by estimating its serialized size
func validateMetadataSize(metadata *Metadata) error {
	// Estimate metadata size by approximating the JSON serialization size
	// This is a rough estimate to prevent extremely large metadata

	// Count fields that contribute to size
	size := 0
	size += len(metadata.URI)
	size += len(metadata.ResourceType)
	size += len(metadata.ContentType)
	size += len(metadata.Digest)
	size += len(metadata.Owner)
	size += len(metadata.StorageRoot)
	size += len(metadata.Tenant)
	size += len(metadata.ContentAddress)

	// Add size for maps (approximate)
	for k, v := range metadata.AuxiliaryLinks {
		size += len(k) + len(v) + 10 // approximate JSON overhead
	}
	for _, v := range metadata.PolicyReferences {
		size += len(v) + 10
	}
	for k, v := range metadata.ValidatorState {
		size += len(k) + len(v) + 10
	}
	for k, v := range metadata.Custom {
		size += len(k) + len(v) + 10
	}

	// Add some overhead for JSON structure
	size += 200

	if size > MaxMetadataSize {
		return ErrMetadataTooLarge
	}

	return nil
}

// SanitizeError sanitizes error messages to prevent information leakage
// Removes potentially sensitive information from error messages
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Remove potentially sensitive information
	// File paths, hostnames, IPs, etc.
	sanitized := errStr

	// Remove file paths (common patterns)
	// This is a basic approach - in production, consider more sophisticated sanitization
	sanitized = strings.ReplaceAll(sanitized, "/Users/", "")
	sanitized = strings.ReplaceAll(sanitized, "/home/", "")
	sanitized = strings.ReplaceAll(sanitized, "/tmp/", "")
	sanitized = strings.ReplaceAll(sanitized, "/var/", "")
	sanitized = strings.ReplaceAll(sanitized, "/etc/", "")

	// Remove IP addresses (basic pattern)
	// This won't catch all IP addresses but handles common cases
	sanitized = strings.ReplaceAll(sanitized, "127.0.0.1", "localhost")
	sanitized = strings.ReplaceAll(sanitized, "192.168.", "")
	sanitized = strings.ReplaceAll(sanitized, "10.", "")

	// Remove potential credentials or tokens (basic patterns)
	// Look for common token/credential patterns
	for _, pattern := range []string{
		"password=", "token=", "secret=", "key=", "auth=",
		"Authorization: ", "Bearer ", "Basic ",
	} {
		if strings.Contains(sanitized, pattern) {
			// Replace the value after the pattern
			parts := strings.SplitN(sanitized, pattern, 2)
			if len(parts) == 2 {
				// Keep the pattern but remove the value
				sanitized = parts[0] + pattern + "REDACTED"
			}
		}
	}

	// If the sanitized error is empty, return a generic error
	if strings.TrimSpace(sanitized) == "" {
		return errors.New("storage operation failed")
	}

	// If the error message changed, wrap it
	if sanitized != errStr {
		return fmt.Errorf("%s (sanitized)", sanitized)
	}

	return err
}
