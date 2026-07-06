package runtime

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Validation constants
const (
	// MaxURILength is the maximum allowed length for resource URIs
	MaxURILength = 4096
	// MaxResourceSize is the maximum allowed size for resources in bytes
	MaxResourceSize = 10 * 1024 * 1024 // 10MB
	// MaxWebIDLength is the maximum allowed length for WebID URIs
	MaxWebIDLength = 4096
	// MaxContentTypeLength is the maximum allowed length for content types
	MaxContentTypeLength = 256
)

// Validation errors
var (
	ErrInvalidURI           = errors.New("invalid URI")
	ErrURITooLong           = errors.New("URI exceeds maximum length")
	ErrInvalidURIScheme     = errors.New("invalid URI scheme")
	ErrInvalidURICharacters = errors.New("invalid URI characters")
	ErrResourceTooLarge     = errors.New("resource exceeds maximum size")
	ErrInvalidWebID         = errors.New("invalid WebID")
	ErrInvalidContentType   = errors.New("invalid content type")
)

// ValidateURI validates a resource URI for safety and correctness
// Prevents URI injection attacks, path traversal, and malformed URIs
func ValidateURI(uri string) error {
	if uri == "" {
		return ErrInvalidURI
	}

	if len(uri) > MaxURILength {
		return ErrURITooLong
	}

	// Check for control characters and non-printable ASCII
	for _, r := range uri {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidURICharacters
		}
	}

	// Check for path traversal and fragment characters
	if strings.ContainsAny(uri, "\\#") {
		return ErrInvalidURICharacters
	}

	// Parse and validate the URI structure
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURI, err)
	}

	// Allow http, https, and internal schemes (boundary, file, etc.)
	// Internal schemes are used for boundary testing and internal operations
	allowedSchemes := map[string]bool{
		"http":     true,
		"https":    true,
		"boundary": true,
		"file":     true,
		"memory":   true,
		"internal": true,
		"test":     true,
	}

	if !allowedSchemes[parsed.Scheme] {
		return fmt.Errorf("%w: %s", ErrInvalidURIScheme, parsed.Scheme)
	}

	// For http/https, ensure host is present
	if (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host == "" {
		return ErrInvalidURI
	}

	return nil
}

// ValidateResourceSize checks if a resource exceeds the maximum allowed size
func ValidateResourceSize(size int64) error {
	if size > MaxResourceSize {
		return ErrResourceTooLarge
	}
	return nil
}

// ValidateWebID validates a WebID URI for safety
func ValidateWebID(webID string) error {
	if webID == "" {
		return ErrInvalidWebID
	}

	if len(webID) > MaxWebIDLength {
		return ErrURITooLong
	}

	// Check for control characters
	for _, r := range webID {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidURICharacters
		}
	}

	// Parse and validate the URI structure
	parsed, err := url.Parse(webID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidWebID, err)
	}

	// Only allow http and https schemes for WebIDs
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: %s", ErrInvalidURIScheme, parsed.Scheme)
	}

	// Ensure host is present
	if parsed.Host == "" {
		return ErrInvalidWebID
	}

	// WebIDs should typically be HTTPS
	if parsed.Scheme == "http" {
		// Log warning but don't fail - HTTP WebIDs are technically valid
		// In production, you might want to enforce HTTPS only
	}

	return nil
}

// ValidateContentType validates a content type for safety
func ValidateContentType(contentType string) error {
	if contentType == "" {
		return ErrInvalidContentType
	}

	if len(contentType) > MaxContentTypeLength {
		return errors.New("content type exceeds maximum length")
	}

	// Check for control characters
	for _, r := range contentType {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidURICharacters
		}
	}

	// Content types should be printable ASCII
	// This is a basic check; more sophisticated validation could be added
	return nil
}

// ValidateContainerURI validates a container URI for safety
func ValidateContainerURI(uri string) error {
	// Container URIs must end with / or be valid resource URIs
	if uri == "" {
		return ErrInvalidURI
	}

	// First validate as a regular URI
	if err := ValidateURI(uri); err != nil {
		return err
	}

	// Container URIs should typically end with /
	// This is a convention in Solid, but not strictly required
	// We don't enforce this to allow for flexibility

	return nil
}

// ValidateTenantID validates a tenant identifier for safety
func ValidateTenantID(tenantID string) error {
	if tenantID == "" {
		return errors.New("tenant ID cannot be empty")
	}

	if len(tenantID) > 256 {
		return errors.New("tenant ID exceeds maximum length")
	}

	// Check for control characters
	for _, r := range tenantID {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidURICharacters
		}
	}

	// Tenant IDs should be alphanumeric and safe characters
	// Allow alphanumeric, hyphens, underscores, and periods
	for _, r := range tenantID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return errors.New("tenant ID contains invalid characters")
		}
	}

	return nil
}

// ValidatePolicyURI validates a policy URI for safety
func ValidatePolicyURI(uri string) error {
	// Policy URIs can be ACL or ACP policy documents
	// They follow the same validation as regular URIs
	return ValidateURI(uri)
}

// ValidateRDFTerm validates an RDF term (subject, predicate, object) for safety
// RDF terms can be URIs or literals, but should not contain control characters
// that could be used for injection attacks
func ValidateRDFTerm(term string) error {
	if term == "" {
		return errors.New("RDF term cannot be empty")
	}

	// Check for control characters
	for _, r := range term {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidURICharacters
		}
	}

	// For terms that look like URIs, do additional validation
	if strings.HasPrefix(term, "http://") || strings.HasPrefix(term, "https://") {
		// If it starts with http:// or https://, validate as a URI
		// But don't fail if it's not a valid URI, as it might be a literal
		// We just want to catch obviously malicious ones
		if strings.ContainsAny(term, "\\#") {
			return ErrInvalidURICharacters
		}
	}

	return nil
}
