package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

// DIDParser parses and validates DID strings and DID documents
type DIDParser struct {
	options DIDParserOptions
	logger  *slog.Logger
}

// DIDParserOptions configures the DID parser
type DIDParserOptions struct {
	// MaxDIDLength is the maximum allowed DID string length
	MaxDIDLength int
	// MaxMethodSpecificIDLength is the maximum allowed method-specific ID length
	MaxMethodSpecificIDLength int
	// AllowedMethods is a list of allowed DID methods (empty means all are allowed)
	AllowedMethods []string
	// RequireHostLikeID determines if method-specific IDs must be host-like
	RequireHostLikeID bool
	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultDIDParserOptions returns safe default options
func DefaultDIDParserOptions() DIDParserOptions {
	return DIDParserOptions{
		MaxDIDLength:              MaxDIDLength,
		MaxMethodSpecificIDLength: MaxMethodSpecificIDLength,
		AllowedMethods:            []string{DIDMethodSolid},
		RequireHostLikeID:         false,
		Logger:                    nil,
	}
}

// NewDIDParser creates a new DID parser
func NewDIDParser(options DIDParserOptions) *DIDParser {
	if options.MaxDIDLength == 0 {
		options.MaxDIDLength = MaxDIDLength
	}
	if options.MaxMethodSpecificIDLength == 0 {
		options.MaxMethodSpecificIDLength = MaxMethodSpecificIDLength
	}
	return &DIDParser{
		options: options,
		logger:  options.Logger,
	}
}

// ParseDID parses a DID string and validates it
func (p *DIDParser) ParseDID(didString string) (DID, error) {
	if didString == "" {
		return DID{}, fmt.Errorf("%w: empty DID string", ErrInvalidDID)
	}

	// Check length
	if len(didString) > p.options.MaxDIDLength {
		return DID{}, fmt.Errorf("%w: DID exceeds maximum length (%d > %d)", ErrDIDTooLong, len(didString), p.options.MaxDIDLength)
	}

	// Check prefix
	if !strings.HasPrefix(didString, DIDPrefix) {
		return DID{}, fmt.Errorf("%w: missing 'did:' prefix", ErrInvalidDID)
	}

	// Remove prefix
	rest := strings.TrimPrefix(didString, DIDPrefix)

	// Find first colon
	colonIndex := strings.Index(rest, ":")
	if colonIndex < 0 {
		return DID{}, fmt.Errorf("%w: missing method separator ':'", ErrInvalidDID)
	}

	method := rest[:colonIndex]
	methodSpecificID := rest[colonIndex+1:]

	// Validate method
	if method == "" {
		return DID{}, fmt.Errorf("%w: empty method", ErrInvalidDIDMethod)
	}

	// Check if method is allowed
	if len(p.options.AllowedMethods) > 0 {
		allowed := false
		for _, allowedMethod := range p.options.AllowedMethods {
			if strings.EqualFold(method, allowedMethod) {
				allowed = true
				break
			}
		}
		if !allowed {
			return DID{}, fmt.Errorf("%w: method '%s' not allowed", ErrInvalidDIDMethod, method)
		}
	}

	// Validate method-specific ID
	if methodSpecificID == "" {
		return DID{}, fmt.Errorf("%w: empty method-specific ID", ErrInvalidMethodSpecificID)
	}

	if len(methodSpecificID) > p.options.MaxMethodSpecificIDLength {
		return DID{}, fmt.Errorf("%w: method-specific ID exceeds maximum length (%d > %d)",
			ErrInvalidMethodSpecificID, len(methodSpecificID), p.options.MaxMethodSpecificIDLength)
	}

	// Check for unsafe characters
	if containsUnsafeCharacters(methodSpecificID) {
		return DID{}, fmt.Errorf("%w: method-specific ID contains unsafe characters", ErrUnsafeDID)
	}

	// If host-like is required, normalize and validate it
	if p.options.RequireHostLikeID {
		// Normalize to lowercase for host-like IDs
		normalizedID := strings.ToLower(methodSpecificID)
		if !hostLikeIDRegex.MatchString(normalizedID) {
			return DID{}, fmt.Errorf("%w: method-specific ID is not host-like", ErrInvalidMethodSpecificID)
		}
		methodSpecificID = normalizedID
	}

	return DID{
		Method:           method,
		MethodSpecificID: methodSpecificID,
		Original:         didString,
	}, nil
}

// ParseDIDURL parses a DID URL string
func (p *DIDParser) ParseDIDURL(didURL string) (DIDURL, error) {
	if didURL == "" {
		return DIDURL{}, fmt.Errorf("empty DID URL string")
	}

	// Parse as DID first
	did, err := p.ParseDID(didURL)
	if err != nil {
		// Check if it's a DID with path/query/fragment
		if strings.HasPrefix(didURL, DIDPrefix) {
			// Try to extract DID and the rest
			rest := strings.TrimPrefix(didURL, DIDPrefix)
			colonIndex := strings.Index(rest, ":")
			if colonIndex >= 0 {
				method := rest[:colonIndex]
				afterMethod := rest[colonIndex+1:]

				// Find where the DID ends and path/query/fragment begins
				// DID method-specific ID can contain :, but path starts with /
				pathStart := strings.Index(afterMethod, "/")
				queryStart := strings.Index(afterMethod, "?")
				fragmentStart := strings.Index(afterMethod, "#")

				// Find the earliest special character
				var endIndex int
				if pathStart >= 0 {
					endIndex = pathStart
				}
				if queryStart >= 0 && (endIndex == 0 || queryStart < endIndex) {
					endIndex = queryStart
				}
				if fragmentStart >= 0 && (endIndex == 0 || fragmentStart < endIndex) {
					endIndex = fragmentStart
				}

				if endIndex > 0 {
					methodSpecificID := afterMethod[:endIndex]
					did = DID{
						Method:           method,
						MethodSpecificID: methodSpecificID,
						Original:         fmt.Sprintf("did:%s:%s", method, methodSpecificID),
					}

					// Parse the rest
					var path, query, fragment string
					if pathStart >= 0 {
						remainder := afterMethod[pathStart:]
						if queryStart >= 0 {
							path = remainder[:strings.Index(remainder, "?")]
						} else if fragmentStart >= 0 {
							path = remainder[:strings.Index(remainder, "#")]
						} else {
							path = remainder
						}
					}
					if queryStart >= 0 {
						remainder := afterMethod[queryStart+1:]
						if fragmentStart >= 0 {
							query = remainder[:strings.Index(remainder, "#")]
						} else {
							query = remainder
						}
					}
					if fragmentStart >= 0 {
						fragment = afterMethod[fragmentStart+1:]
					}

					return DIDURL{
						DID:      did,
						Path:     path,
						Query:    query,
						Fragment: fragment,
					}, nil
				}
			}
		}
		return DIDURL{}, fmt.Errorf("invalid DID URL: %w", err)
	}

	return DIDURL{
		DID: did,
	}, nil
}

// ParseDIDDocument parses a DID document from JSON
func (p *DIDParser) ParseDIDDocument(data []byte, expectedDID string) (DIDDocument, error) {
	// This is a placeholder - in a real implementation, we would parse JSON
	// For now, we return a basic document structure
	// The actual JSON parsing will be implemented when we add the JSON parser

	var doc DIDDocument

	// Validate input size
	if len(data) > p.options.MaxDIDLength {
		return DIDDocument{}, fmt.Errorf("%w: document exceeds maximum size", ErrInvalidDID)
	}

	// Validate expected DID
	if expectedDID == "" {
		return DIDDocument{}, fmt.Errorf("expected DID is required")
	}

	did, err := p.ParseDID(expectedDID)
	if err != nil {
		return DIDDocument{}, fmt.Errorf("invalid expected DID: %w", err)
	}

	doc.ID = did.NormalizedString()

	return doc, nil
}

// ValidateDIDDocument validates a parsed DID document
func (p *DIDParser) ValidateDIDDocument(doc DIDDocument) error {
	// Check ID
	if doc.ID == "" {
		return fmt.Errorf("%w: missing ID", ErrInvalidDID)
	}

	// Parse ID as DID to validate format
	parsedDID, err := p.ParseDID(doc.ID)
	if err != nil {
		return fmt.Errorf("%w: invalid DID in document ID", err)
	}

	// Check that the document ID matches the parsed DID
	if parsedDID.NormalizedString() != doc.ID {
		return fmt.Errorf("%w: document ID does not match normalized DID", ErrInvalidDID)
	}

	// Check verification methods
	if len(doc.VerificationMethod) == 0 {
		return fmt.Errorf("%w: at least one verification method is required", ErrVerificationMethodInvalid)
	}

	for i, vm := range doc.VerificationMethod {
		if !vm.IsValid() {
			return fmt.Errorf("%w: verification method %d is invalid", ErrVerificationMethodInvalid, i)
		}
		// Verify controller matches document ID
		if vm.Controller != doc.ID {
			return fmt.Errorf("%w: verification method controller does not match document ID", ErrVerificationMethodInvalid)
		}
		// Verify ID is a DID URL under the document ID
		if !strings.HasPrefix(vm.ID, doc.ID) || vm.ID == doc.ID {
			return fmt.Errorf("%w: verification method ID must be a DID URL under the document ID", ErrVerificationMethodInvalid)
		}
	}

	// Check authentication references
	for _, authRef := range doc.Authentication {
		if authRef == "" {
			return fmt.Errorf("%w: empty authentication reference", ErrVerificationMethodInvalid)
		}
		// Verify it references a verification method
		found := false
		for _, vm := range doc.VerificationMethod {
			if vm.ID == authRef {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: authentication reference '%s' not found in verification methods", ErrVerificationMethodInvalid, authRef)
		}
	}

	// Check service endpoints
	for i, service := range doc.Service {
		if !service.IsValid() {
			return fmt.Errorf("service %d is invalid", i)
		}
		if !service.IsHTTPS() {
			p.logValidationWarning(fmt.Sprintf("service %d uses non-HTTPS endpoint: %s", i, service.ServiceEndpoint))
		}
	}

	// Check for deactivation
	if doc.Deactivated {
		p.logValidationWarning("DID document is deactivated")
	}

	return nil
}

// containsUnsafeCharacters checks if a string contains characters that are unsafe for DIDs
func containsUnsafeCharacters(s string) bool {
	for _, r := range s {
		// DIDs should only contain alphanumeric, hyphen, period, underscore, colon
		// But we need to be careful with the regex match
		if !(('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') ||
			r == '-' || r == '.' || r == '_' || r == ':') {
			return true
		}
	}
	return false
}

// logValidationWarning logs a validation warning if a logger is configured
func (p *DIDParser) logValidationWarning(message string) {
	if p.logger != nil {
		p.logger.Warn("DID validation warning", "message", message)
	}
}

// IsHostLikeID checks if a method-specific ID is host-like (DNS-style)
func (p *DIDParser) IsHostLikeID(methodSpecificID string) bool {
	return hostLikeIDRegex.MatchString(methodSpecificID)
}

// NormalizeHostLikeID normalizes a host-like ID to lowercase
func (p *DIDParser) NormalizeHostLikeID(methodSpecificID string) string {
	if p.IsHostLikeID(methodSpecificID) {
		return strings.ToLower(methodSpecificID)
	}
	return methodSpecificID
}

// Context for DID operations
func (p *DIDParser) Context() context.Context {
	return context.Background()
}

// ParseSolidDID is a convenience function to parse a did:solid DID
func (p *DIDParser) ParseSolidDID(didString string) (DID, error) {
	did, err := p.ParseDID(didString)
	if err != nil {
		return DID{}, err
	}
	if !did.IsSolidDID() {
		return DID{}, fmt.Errorf("%w: not a did:solid DID", ErrInvalidDIDMethod)
	}
	return did, nil
}

// DIDDocumentMetadata contains metadata about a resolved DID document
type DIDDocumentMetadata struct {
	// DID is the resolved DID
	DID DID
	// Document is the parsed DID document
	Document DIDDocument
	// ResolvedAt is when the document was resolved
	ResolvedAt time.Time
	// ExpiresAt is when the cached document expires (if cached)
	ExpiresAt *time.Time
	// SourceURL is the URL from which the document was fetched (if applicable)
	SourceURL *url.URL
	// ValidationWarnings contains any validation warnings
	ValidationWarnings []string
	// IsCached indicates if the document was served from cache
	IsCached bool
}

// IsValid checks if the resolved DID document is valid and not expired
func (m DIDDocumentMetadata) IsValid() bool {
	if !m.Document.IsValid() {
		return false
	}
	if m.ExpiresAt != nil && time.Now().After(*m.ExpiresAt) {
		return false
	}
	return true
}
