package authn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/identity"
)

// DIDBindingPredicate is the predicate used for DID-to-WebID binding
// This matches the constant defined in the identity package
const DIDBindingPredicate = "https://solidproject.org/ns/did#controller"

// DIDBindingOptions configures DID binding behavior
type DIDBindingOptions struct {
	// Enabled determines if DID binding is active
	Enabled bool
	// Resolver is the DID resolver to use
	Resolver *identity.Resolver
	// MaxWebIDProfileSize is the maximum size of a WebID profile in bytes
	MaxWebIDProfileSize int
	// Timeout is the timeout for DID resolution and WebID profile fetching
	Timeout time.Duration
	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultDIDBindingOptions returns safe default options
func DefaultDIDBindingOptions() DIDBindingOptions {
	return DIDBindingOptions{
		Enabled:             false, // Disabled by default for safety
		Resolver:            nil,
		MaxWebIDProfileSize: 65536, // 64 KiB
		Timeout:             10 * time.Second,
		Logger:              nil,
	}
}

// DIDBinder provides DID binding functionality for agent identities
type DIDBinder struct {
	options DIDBindingOptions
	client  *http.Client
}

// NewDIDBinder creates a new DID binder
func NewDIDBinder(options DIDBindingOptions) *DIDBinder {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: options.Timeout,
	}

	return &DIDBinder{
		options: options,
		client:  client,
	}
}

// ErrDIDBinding is returned when DID binding fails
var ErrDIDBinding = errors.New("DID binding failed")

// ErrDIDNotFound is returned when a DID is not found
var ErrDIDNotFound = errors.New("DID not found")

// ErrDIDResolutionFailed is returned when DID resolution fails
var ErrDIDResolutionFailed = errors.New("DID resolution failed")

// ResolveDIDFromWebIDProfile attempts to extract a DID from a WebID profile
// This looks for the DID binding predicate in the profile
func (db *DIDBinder) ResolveDIDFromWebIDProfile(ctx context.Context, webIDProfileURL string) (string, error) {
	// Check if DID binding is enabled
	if !db.options.Enabled || db.options.Resolver == nil {
		return "", nil // Return empty DID, not an error - DID is optional
	}

	// Check context deadline
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context cancelled: %w", err)
	}

	// Validate WebID profile URL
	webIDProfileURL = strings.TrimSpace(webIDProfileURL)
	if webIDProfileURL == "" {
		return "", nil
	}

	// Only fetch HTTPS URLs
	if !strings.HasPrefix(webIDProfileURL, "https://") {
		// In shadow mode, we don't fail hard
		db.logBindingWarning(fmt.Sprintf("WebID profile URL is not HTTPS: %s", webIDProfileURL))
		return "", nil
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, webIDProfileURL, nil)
	if err != nil {
		db.logBindingError(fmt.Sprintf("failed to create request for WebID profile %s: %v", webIDProfileURL, err))
		return "", nil // Don't fail hard in shadow mode
	}

	// Set headers
	req.Header.Set("Accept", "text/turtle,application/ld+json,application/json")
	req.Header.Set("User-Agent", "solid-sidecar/1.0")

	// Execute request
	resp, err := db.client.Do(req)
	if err != nil {
		db.logBindingWarning(fmt.Sprintf("failed to fetch WebID profile %s: %v", webIDProfileURL, err))
		return "", nil // Don't fail hard in shadow mode
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		db.logBindingWarning(fmt.Sprintf("WebID profile %s returned status %d", webIDProfileURL, resp.StatusCode))
		return "", nil
	}

	// Read response body with size limit
	body, err := readLimitedBody(resp.Body, db.options.MaxWebIDProfileSize)
	if err != nil {
		db.logBindingWarning(fmt.Sprintf("failed to read WebID profile %s: %v", webIDProfileURL, err))
		return "", nil
	}

	// Parse the WebID profile to find the DID
	// For now, we do a simple string search for the DID binding predicate
	// In a production implementation, we would use the RDF parser from internal/authz
	did := extractDIDFromProfile(body, DIDBindingPredicate)
	if did == "" {
		// No DID found in profile
		return "", nil
	}

	// Validate the extracted DID
	if !isValidDID(did) {
		db.logBindingWarning(fmt.Sprintf("invalid DID extracted from WebID profile %s: %s", webIDProfileURL, did))
		return "", nil
	}

	// Try to resolve the DID to verify it exists
	if _, err := db.options.Resolver.Resolve(ctx, did); err != nil {
		db.logBindingWarning(fmt.Sprintf("failed to resolve DID %s from WebID profile %s: %v", did, webIDProfileURL, err))
		return "", nil // Don't fail hard - the DID might be valid but the resolver can't reach it
	}

	return did, nil
}

// ResolveAndValidateDIDBinding performs full DID binding validation
// This includes:
// 1. Extracting DID from WebID profile
// 2. Resolving the DID document
// 3. Validating bidirectional binding (DID -> WebID and WebID -> DID)
func (db *DIDBinder) ResolveAndValidateDIDBinding(ctx context.Context, webID string) (string, AssuranceLevel, error) {
	// Check if DID binding is enabled
	if !db.options.Enabled || db.options.Resolver == nil {
		return "", AssuranceLevelBasic, nil
	}

	// Extract DID from WebID profile
	did, err := db.ResolveDIDFromWebIDProfile(ctx, webID)
	if err != nil {
		return "", AssuranceLevelBasic, fmt.Errorf("%w: failed to resolve DID from WebID profile: %v", ErrDIDBinding, err)
	}

	// If no DID found, return basic assurance
	if did == "" {
		return "", AssuranceLevelBasic, nil
	}

	// Validate bidirectional binding
	if err := db.options.Resolver.ValidateDIDBinding(ctx, did, webID); err != nil {
		db.logBindingWarning(fmt.Sprintf("DID binding validation failed for DID %s and WebID %s: %v", did, webID, err))
		// In shadow mode, we don't fail hard - just return basic assurance
		return "", AssuranceLevelBasic, nil
	}

	// DID binding is valid - return standard assurance
	return did, AssuranceLevelStandard, nil
}

// EnrichTrustedIdentityWithDID takes a TrustedIdentity and attempts to enrich it with a DID
func (db *DIDBinder) EnrichTrustedIdentityWithDID(ctx context.Context, trusted TrustedIdentity) (AgentIdentity, error) {
	// Convert TrustedIdentity to AgentIdentity
	agentIdentity := ConvertTrustedIdentityToAgentIdentity(trusted, "", "")

	// If DID binding is not enabled, return basic identity
	if !db.options.Enabled || db.options.Resolver == nil {
		return agentIdentity, nil
	}

	// Try to resolve DID from WebID profile
	did, assurance, err := db.ResolveAndValidateDIDBinding(ctx, trusted.WebID)
	if err != nil {
		// Log but don't fail - return the identity without DID
		db.logBindingError(fmt.Sprintf("failed to enrich identity with DID: %v", err))
		return agentIdentity, nil
	}

	// If we found a valid DID, update the agent identity
	if did != "" {
		agentIdentity.DID = did
		agentIdentity.AssuranceLevel = assurance
		// Update verification source
		if trusted.ClientID != "" {
			agentIdentity.VerificationSource = VerificationSourceCombined
		} else {
			agentIdentity.VerificationSource = VerificationSourceDID
		}
	}

	return agentIdentity, nil
}

// readLimitedBody reads a response body with a size limit
func readLimitedBody(body io.Reader, maxSize int) ([]byte, error) {
	// Limit the reader to maxSize + 1 to detect overflow
	limitedReader := io.LimitReader(body, int64(maxSize)+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}

	// Check if we exceeded the limit
	if len(data) > maxSize {
		return nil, fmt.Errorf("response exceeds maximum size (%d > %d)", len(data), maxSize)
	}

	return data, nil
}

// extractDIDFromProfile extracts a DID from a WebID profile
// This looks for the DID binding predicate
func extractDIDFromProfile(body []byte, predicate string) string {
	bodyStr := string(body)

	// Look for patterns like:
	// <#me> <predicate> <did:solid:alice> .
	// or with angle brackets:
	// <#me> <https://solidproject.org/ns/did#controller> <did:solid:alice> .

	// Try to find the predicate and extract the DID
	predicateIdx := strings.Index(bodyStr, predicate)
	if predicateIdx < 0 {
		// Try with angle brackets
		predicateWithBrackets := "<" + predicate + ">"
		predicateIdx = strings.Index(bodyStr, predicateWithBrackets)
		if predicateIdx < 0 {
			return ""
		}
		// Move past the predicate
		predicateIdx += len(predicateWithBrackets)
	} else {
		// Move past the predicate
		predicateIdx += len(predicate)
	}

	// Find the next DID after the predicate
	// Look for did: prefix
	didPrefix := "did:"
	didStart := strings.Index(bodyStr[predicateIdx:], didPrefix)
	if didStart < 0 {
		return ""
	}
	didStart += predicateIdx

	// Extract the DID
	// Find the end of the DID (space, ., >, or newline)
	didEnd := len(bodyStr)
	for i := didStart; i < len(bodyStr); i++ {
		c := bodyStr[i]
		if c == ' ' || c == '.' || c == '>' || c == '\n' || c == '\r' || c == '\t' {
			didEnd = i
			break
		}
	}

	if didEnd <= didStart {
		return ""
	}

	did := strings.TrimSpace(bodyStr[didStart:didEnd])

	// Clean up the DID (remove angle brackets if present)
	did = strings.Trim(did, "<>\"'")

	// Validate basic DID format
	if !isValidDID(did) {
		return ""
	}

	return did
}

// logBindingError logs a DID binding error
func (db *DIDBinder) logBindingError(message string) {
	if db.options.Logger != nil {
		db.options.Logger.Error("DID binding error",
			"message", message,
		)
	}
}

// logBindingWarning logs a DID binding warning
func (db *DIDBinder) logBindingWarning(message string) {
	if db.options.Logger != nil {
		db.options.Logger.Warn("DID binding warning",
			"message", message,
		)
	}
}
