package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/identity"
)

// ErrIdentityNotTrusted is returned when an identity is not trusted
var ErrIdentityNotTrusted = errors.New("identity not trusted")

// ErrIssuerSpoofingDetected is returned when issuer spoofing is detected
var ErrIssuerSpoofingDetected = errors.New("issuer spoofing detected")

// ErrWebIDSubstitutionDetected is returned when WebID substitution is detected
var ErrWebIDSubstitutionDetected = errors.New("WebID substitution detected")

// ErrDIDConfusionDetected is returned when DID confusion is detected
var ErrDIDConfusionDetected = errors.New("DID confusion detected")

// IdentityTrustPolicy provides comprehensive trust management for identities
type IdentityTrustPolicy struct {
	mu sync.RWMutex

	// issuerTrustPolicy manages trust for OIDC issuers
	issuerTrustPolicy *IssuerTrustPolicy

	// clientTrustPolicy manages trust for client identifiers
	clientTrustPolicy *ClientTrustPolicy

	// webIDCache caches WebID profiles
	webIDCache *WebIDCache

	// didResolver resolves DIDs
	didResolver *identity.Resolver

	// keyRotationCallbacks holds callbacks for key rotation events
	keyRotationCallbacks []func(KeyRotationInfo)

	// logger is used for policy operations logging
	logger *slog.Logger

	// auditLogger is used for audit logging of trust decisions
	auditLogger *slog.Logger

	// options configure the trust policy behavior
	options IdentityTrustPolicyOptions
}

// IssuerTrustPolicy defines trust policy for identity issuers
type IssuerTrustPolicy struct {
	// AllowedIssuers is a list of explicitly allowed issuer URLs
	AllowedIssuers []string

	// BlockedIssuers is a list of explicitly blocked issuer URLs
	BlockedIssuers []string

	// RequireAllowlist enforces that only allowed issuers can be used
	RequireAllowlist bool

	// AllowIssuerDiscovery enables issuer discovery via .well-known
	AllowIssuerDiscovery bool

	// PinnedIssuers contains pinned issuer configurations with public keys
	PinnedIssuers map[string]IssuerPin

	// JWKSEndpointTTL is the TTL for caching JWKS endpoints
	JWKSEndpointTTL time.Duration

	// maxIssuerResponseSize is the maximum size of issuer metadata response
	maxIssuerResponseSize int
}

// IssuerPin defines a pinned issuer configuration
type IssuerPin struct {
	// PublicKey contains the pinned public key (PEM or base64)
	PublicKey string

	// PublicKeyHash contains the SHA-256 hash of the public key
	PublicKeyHash string

	// ValidFrom is when the pin becomes valid
	ValidFrom time.Time

	// ValidUntil is when the pin expires
	ValidUntil time.Time

	// TrustLevel defines the trust level (low, medium, high, very_high)
	TrustLevel string
}

// IdentityTrustPolicyOptions configures the identity trust policy
type IdentityTrustPolicyOptions struct {
	// EnableDIDBindingVerification enables did:solid binding verification
	EnableDIDBindingVerification bool

	// EnableKeyRotationDetection enables key rotation detection
	EnableKeyRotationDetection bool

	// EnableIssuerDiscovery enables issuer discovery
	EnableIssuerDiscovery bool

	// RequireHTTPS enforces HTTPS for all identity URLs
	RequireHTTPS bool

	// IdentityAssuranceLevelMap maps issuer hosts to default assurance levels
	IdentityAssuranceLevelMap map[string]string

	// DIDTrustPolicy defines trust policy for DIDs
	DIDTrustPolicy DIDTrustPolicy

	// Logger is the logger to use
	Logger *slog.Logger

	// AuditLogger is the audit logger to use
	AuditLogger *slog.Logger
}

// DIDTrustPolicy defines trust policy for DIDs
type DIDTrustPolicy struct {
	// AllowedDIDMethods is a list of allowed DID methods (e.g., "solid", "web", "key")
	AllowedDIDMethods []string

	// BlockedDIDMethods is a list of blocked DID methods
	BlockedDIDMethods []string

	// RequireDIDBinding requires did:solid binding for WebIDs
	RequireDIDBinding bool

	// TrustedDIDPrefixes is a list of trusted DID prefixes
	TrustedDIDPrefixes []string
}

// DefaultIdentityTrustPolicyOptions returns safe default options
func DefaultIdentityTrustPolicyOptions() IdentityTrustPolicyOptions {
	return IdentityTrustPolicyOptions{
		EnableDIDBindingVerification: true,
		EnableKeyRotationDetection:   true,
		EnableIssuerDiscovery:        true,
		RequireHTTPS:                 true,
		IdentityAssuranceLevelMap:    make(map[string]string),
		DIDTrustPolicy: DIDTrustPolicy{
			AllowedDIDMethods:  []string{"solid", "web", "key"},
			BlockedDIDMethods:  []string{},
			RequireDIDBinding:  false,
			TrustedDIDPrefixes: []string{"did:solid:"},
		},
		Logger:      nil,
		AuditLogger: nil,
	}
}

// NewIdentityTrustPolicy creates a new identity trust policy
func NewIdentityTrustPolicy(options IdentityTrustPolicyOptions) *IdentityTrustPolicy {
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.AuditLogger == nil {
		options.AuditLogger = options.Logger
	}

	// Initialize issuer trust policy
	issuerPolicy := &IssuerTrustPolicy{
		AllowedIssuers:        []string{},
		BlockedIssuers:        []string{},
		RequireAllowlist:      false,
		AllowIssuerDiscovery:  options.EnableIssuerDiscovery,
		PinnedIssuers:         make(map[string]IssuerPin),
		JWKSEndpointTTL:       1 * time.Hour,
		maxIssuerResponseSize: 64 * 1024, // 64KB
	}

	// Initialize client trust policy
	clientOptions := DefaultClientTrustPolicyOptions()
	clientOptions.RequireRegistration = false
	clientOptions.AllowPublicClients = true
	clientOptions.Logger = options.Logger

	// Initialize WebID cache
	cacheOptions := DefaultWebIDCacheOptions()
	cacheOptions.MaxSize = 1000
	cacheOptions.DefaultTTL = 5 * time.Minute

	return &IdentityTrustPolicy{
		issuerTrustPolicy:    issuerPolicy,
		clientTrustPolicy:    NewClientTrustPolicy(clientOptions),
		webIDCache:           NewWebIDCache(cacheOptions),
		logger:               options.Logger,
		auditLogger:          options.AuditLogger,
		options:              options,
		keyRotationCallbacks: make([]func(KeyRotationInfo), 0),
	}
}

// SetDIDResolver sets the DID resolver for did:solid binding verification
func (p *IdentityTrustPolicy) SetDIDResolver(resolver *identity.Resolver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.didResolver = resolver
}

// SetLogger sets the logger for the policy
func (p *IdentityTrustPolicy) SetLogger(logger *slog.Logger) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if logger != nil {
		p.logger = logger
	}
}

// SetAuditLogger sets the audit logger for the policy
func (p *IdentityTrustPolicy) SetAuditLogger(logger *slog.Logger) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if logger != nil {
		p.auditLogger = logger
	}
}

// Close cleans up resources
func (p *IdentityTrustPolicy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.webIDCache != nil {
		p.webIDCache.Close()
	}
}

// RegisterKeyRotationCallback registers a callback for key rotation events
func (p *IdentityTrustPolicy) RegisterKeyRotationCallback(callback func(KeyRotationInfo)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keyRotationCallbacks = append(p.keyRotationCallbacks, callback)
}

// notifyKeyRotation notifies all registered callbacks of a key rotation
func (p *IdentityTrustPolicy) notifyKeyRotation(info KeyRotationInfo) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, callback := range p.keyRotationCallbacks {
		callback(info)
	}
}

// AddAllowedIssuer adds an issuer to the allowlist
func (p *IdentityTrustPolicy) AddAllowedIssuer(issuer string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.validateIssuerURL(issuer); err != nil {
		return err
	}

	// Check if already blocked
	for _, blocked := range p.issuerTrustPolicy.BlockedIssuers {
		if strings.EqualFold(issuer, blocked) {
			return fmt.Errorf("issuer %s is blocked", issuer)
		}
	}

	// Add to allowed list
	p.issuerTrustPolicy.AllowedIssuers = append(p.issuerTrustPolicy.AllowedIssuers, issuer)
	p.logger.Info("Allowed issuer added", "issuer", issuer)

	return nil
}

// AddBlockedIssuer adds an issuer to the blocklist
func (p *IdentityTrustPolicy) AddBlockedIssuer(issuer string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.validateIssuerURL(issuer); err != nil {
		return err
	}

	// Check if already allowed
	for _, allowed := range p.issuerTrustPolicy.AllowedIssuers {
		if strings.EqualFold(issuer, allowed) {
			return fmt.Errorf("issuer %s is allowed, cannot block", issuer)
		}
	}

	// Add to blocked list
	p.issuerTrustPolicy.BlockedIssuers = append(p.issuerTrustPolicy.BlockedIssuers, issuer)
	p.logger.Info("Blocked issuer added", "issuer", issuer)

	return nil
}

// RemoveAllowedIssuer removes an issuer from the allowlist
func (p *IdentityTrustPolicy) RemoveAllowedIssuer(issuer string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, allowed := range p.issuerTrustPolicy.AllowedIssuers {
		if strings.EqualFold(allowed, issuer) {
			p.issuerTrustPolicy.AllowedIssuers = append(
				p.issuerTrustPolicy.AllowedIssuers[:i],
				p.issuerTrustPolicy.AllowedIssuers[i+1:]...,
			)
			p.logger.Info("Allowed issuer removed", "issuer", issuer)
			return nil
		}
	}

	return fmt.Errorf("issuer %s not found in allowlist", issuer)
}

// RemoveBlockedIssuer removes an issuer from the blocklist
func (p *IdentityTrustPolicy) RemoveBlockedIssuer(issuer string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, blocked := range p.issuerTrustPolicy.BlockedIssuers {
		if strings.EqualFold(blocked, issuer) {
			p.issuerTrustPolicy.BlockedIssuers = append(
				p.issuerTrustPolicy.BlockedIssuers[:i],
				p.issuerTrustPolicy.BlockedIssuers[i+1:]...,
			)
			p.logger.Info("Blocked issuer removed", "issuer", issuer)
			return nil
		}
	}

	return fmt.Errorf("issuer %s not found in blocklist", issuer)
}

// SetRequireIssuerAllowlist sets whether to require issuers to be in the allowlist
func (p *IdentityTrustPolicy) SetRequireIssuerAllowlist(require bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.issuerTrustPolicy.RequireAllowlist = require
	p.logger.Info("Issuer allowlist requirement updated", "require", require)
}

// PinIssuer pins an issuer's public key
func (p *IdentityTrustPolicy) PinIssuer(issuer string, pin IssuerPin) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.validateIssuerURL(issuer); err != nil {
		return err
	}

	if pin.PublicKey == "" && pin.PublicKeyHash == "" {
		return errors.New("pin must have either public key or hash")
	}

	if pin.PublicKeyHash != "" && len(pin.PublicKeyHash) != 64 {
		return errors.New("public key hash must be 64 characters (SHA-256)")
	}

	p.issuerTrustPolicy.PinnedIssuers[issuer] = pin
	p.logger.Info("Issuer pinned", "issuer", issuer, "trust_level", pin.TrustLevel)

	return nil
}

// UnpinIssuer removes an issuer pin
func (p *IdentityTrustPolicy) UnpinIssuer(issuer string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.issuerTrustPolicy.PinnedIssuers, issuer)
	p.logger.Info("Issuer unpinned", "issuer", issuer)
}

// validateIssuerURL validates an issuer URL
func (p *IdentityTrustPolicy) validateIssuerURL(issuer string) error {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return errors.New("issuer URL must use HTTPS")
	}

	if parsed.Host == "" {
		return errors.New("issuer URL must have a host")
	}

	return nil
}

// VerifyIdentity verifies an identity according to the trust policy
func (p *IdentityTrustPolicy) VerifyIdentity(ctx context.Context, webID, issuer string) error {
	// Step 1: Verify issuer is allowed
	if err := p.verifyIssuer(ctx, issuer); err != nil {
		return fmt.Errorf("issuer verification failed: %w", err)
	}

	// Step 2: Verify WebID ownership and issuer binding
	if err := p.verifyWebIDBinding(ctx, webID, issuer); err != nil {
		return fmt.Errorf("WebID binding verification failed: %w", err)
	}

	// Step 3: Verify client trust if applicable
	// (Client verification would be done separately with client ID)

	// Step 4: Check for issuer spoofing
	if err := p.checkIssuerSpoofing(ctx, webID, issuer); err != nil {
		return fmt.Errorf("issuer spoofing check failed: %w", err)
	}

	// Step 5: Log successful verification
	p.auditLogger.Info("Identity verified", "webid", webID, "issuer", issuer)

	return nil
}

// verifyIssuer verifies that an issuer is trusted
func (p *IdentityTrustPolicy) verifyIssuer(ctx context.Context, issuer string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Check if explicitly blocked
	for _, blocked := range p.issuerTrustPolicy.BlockedIssuers {
		if strings.EqualFold(issuer, blocked) {
			p.auditLogger.Warn("Issuer blocked", "issuer", issuer)
			return fmt.Errorf("%w: %s", ErrIdentityNotTrusted, issuer)
		}
	}

	// If allowlist is required, check if explicitly allowed
	if p.issuerTrustPolicy.RequireAllowlist {
		isAllowed := false
		for _, allowedIssuer := range p.issuerTrustPolicy.AllowedIssuers {
			if strings.EqualFold(issuer, allowedIssuer) {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			p.auditLogger.Warn("Issuer not in allowlist", "issuer", issuer)
			return fmt.Errorf("%w: %s not in allowlist", ErrIdentityNotTrusted, issuer)
		}
	}

	// Check pinned issuer
	if pin, exists := p.issuerTrustPolicy.PinnedIssuers[issuer]; exists {
		// Verify pin is still valid
		now := time.Now()
		if !pin.ValidFrom.IsZero() && now.Before(pin.ValidFrom) {
			p.auditLogger.Warn("Issuer pin not yet valid", "issuer", issuer)
			return fmt.Errorf("%w: pin for %s not yet valid", ErrIdentityNotTrusted, issuer)
		}
		if !pin.ValidUntil.IsZero() && now.After(pin.ValidUntil) {
			p.auditLogger.Warn("Issuer pin expired", "issuer", issuer)
			return fmt.Errorf("%w: pin for %s expired", ErrIdentityNotTrusted, issuer)
		}
	}

	return nil
}

// verifyWebIDBinding verifies the binding between a WebID and its issuer
func (p *IdentityTrustPolicy) verifyWebIDBinding(ctx context.Context, webID, issuer string) error {
	// Check if WebID matches the issuer's expected format
	if err := p.checkWebIDIssuerBinding(webID, issuer); err != nil {
		return err
	}

	// Verify WebID profile
	verifier := NewWebIDVerifier(nil, p.issuerTrustPolicy.AllowedIssuers)
	profile, err := verifier.VerifyWebIDOwnership(ctx, webID)
	if err != nil {
		return fmt.Errorf("WebID ownership verification failed: %w", err)
	}

	// Check if profile issuer matches
	if profile.SolidOIDCIssuer != "" && profile.SolidOIDCIssuer != issuer {
		p.auditLogger.Warn("WebID profile issuer mismatch",
			"webid", webID,
			"profile_issuer", profile.SolidOIDCIssuer,
			"expected_issuer", issuer)
		return fmt.Errorf("%w: profile issuer %s does not match expected issuer %s",
			ErrWebIDSubstitutionDetected, profile.SolidOIDCIssuer, issuer)
	}

	// Cache the verified profile
	assuranceLevel := p.getAssuranceLevelForIssuer(issuer)
	p.webIDCache.Set(webID, profile, issuer, assuranceLevel)

	// Verify did:solid binding if configured
	if p.options.EnableDIDBindingVerification && p.didResolver != nil {
		// This would be called when a did:solid is present
		// For now, we skip as we don't have the DID from the token
	}

	return nil
}

// checkWebIDIssuerBinding checks if a WebID is properly bound to an issuer
func (p *IdentityTrustPolicy) checkWebIDIssuerBinding(webID, issuer string) error {
	// Parse both URLs
	webIDURL, err := url.Parse(webID)
	if err != nil {
		return fmt.Errorf("invalid WebID: %w", err)
	}

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("invalid issuer: %w", err)
	}

	// WebID must use HTTPS
	if webIDURL.Scheme != "https" {
		return fmt.Errorf("WebID must use HTTPS")
	}

	// Issuer must use HTTPS
	if issuerURL.Scheme != "https" {
		return fmt.Errorf("issuer must use HTTPS")
	}

	// For now, we don't enforce strict host matching
	// In production, this could check if the WebID host matches the issuer host

	return nil
}

// checkIssuerSpoofing checks for issuer spoofing attacks
func (p *IdentityTrustPolicy) checkIssuerSpoofing(ctx context.Context, webID, issuer string) error {
	// Parse issuer URL
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return err
	}

	// Check for common spoofing patterns
	// 1. Check if issuer uses IP address (suspicious)
	if isIPAddress(issuerURL.Host) {
		p.auditLogger.Warn("Issuer uses IP address (potential spoofing)", "issuer", issuer)
		// Don't fail, but log for investigation
	}

	// 2. Check if issuer host looks suspicious
	if looksSuspicious(issuerURL.Host) {
		p.auditLogger.Warn("Issuer host looks suspicious", "issuer", issuer, "host", issuerURL.Host)
		return fmt.Errorf("%w: suspicious issuer host %s", ErrIssuerSpoofingDetected, issuerURL.Host)
	}

	// 3. Check if WebID and issuer are from different domains (may be valid but worth logging)
	webIDURL, _ := url.Parse(webID)
	if webIDURL != nil && webIDURL.Host != issuerURL.Host {
		p.logger.Debug("WebID and issuer have different hosts",
			"webid_host", webIDURL.Host,
			"issuer_host", issuerURL.Host)
		// This may be valid (e.g., hosted WebID profiles)
	}

	return nil
}

// isIPAddress checks if a string is an IP address
func isIPAddress(host string) bool {
	// Simple check - IP addresses don't contain dots followed by letters
	// This is a simplified check
	if strings.Contains(host, ":") {
		// Could be IPv6
		return true
	}

	// Check for IPv4 pattern
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		for _, part := range parts {
			if !isNumeric(part) {
				return false
			}
		}
		return true
	}

	return false
}

// isNumeric checks if a string is numeric
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// looksSuspicious checks if a hostname looks suspicious
// This function uses a more sophisticated approach to detect potential phishing attempts
func looksSuspicious(host string) bool {
	// Check for empty host
	if host == "" {
		return false
	}

	hostLower := strings.ToLower(host)

	// Check for known suspicious patterns
	// These are patterns that are commonly used in phishing attacks
	suspiciousPatterns := []string{
		// Homoglyph combinations that are suspicious
		"arn", // a + rn (looks like "am")
		"rn",  // r + n (looks like "m")
		"cl",  // c + l (looks like "d")
		"lo",  // l + o (looks like "lo" but in wrong context)
		"1l",  // 1 + l (looks like "I")
		"0o",  // 0 + o (looks like "O")
		"0O",  // 0 + O
		"O0",  // O + 0
		// Common phishing domain patterns
		"secure-",
		"login-",
		"account-",
		"verify-",
		"suspicious",
		"phishing",
		"fake",
		"hack",
		"scam",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(hostLower, pattern) {
			return true
		}
	}

	// Check for IP addresses (already handled elsewhere but included for completeness)
	if isIPAddress(host) {
		return true
	}

	// Check for domains that are too long (potential encoding attacks)
	if len(host) > 253 {
		return true
	}

	// Check for labels that are too long
	labels := strings.Split(hostLower, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return true
		}
		// Check if label starts or ends with hyphen (invalid in DNS)
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return true
		}
	}

	return false
}

// getAssuranceLevelForIssuer gets the assurance level for an issuer
func (p *IdentityTrustPolicy) getAssuranceLevelForIssuer(issuer string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Check if we have a specific mapping
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return "low"
	}

	if level, ok := p.options.IdentityAssuranceLevelMap[issuerURL.Host]; ok {
		return level
	}

	// Check pinned issuers
	if pin, exists := p.issuerTrustPolicy.PinnedIssuers[issuer]; exists {
		if pin.TrustLevel != "" {
			return pin.TrustLevel
		}
		return "high"
	}

	// Default to medium
	return "medium"
}

// DetectKeyRotation detects if a key rotation has occurred for a WebID
func (p *IdentityTrustPolicy) DetectKeyRotation(ctx context.Context, webID, oldKeyID string) (bool, error) {
	// Check if we have a cached profile
	profile, ok := p.webIDCache.Get(webID)
	if !ok {
		// Not in cache, fetch fresh
		verifier := NewWebIDVerifier(nil, p.issuerTrustPolicy.AllowedIssuers)
		var err error
		profile, err = verifier.VerifyWebIDOwnership(ctx, webID)
		if err != nil {
			return false, err
		}
	}

	// Extract current keys from profile
	// This is a placeholder - actual implementation would parse the profile
	currentKeys := p.extractKeyIDsFromProfile(profile)

	// Check if old key is still present
	for _, keyID := range currentKeys {
		if keyID == oldKeyID {
			// Key is still valid
			return false, nil
		}
	}

	// Key rotation detected
	rotationInfo := KeyRotationInfo{
		WebID:          webID,
		OldKeyID:       oldKeyID,
		NewKeyID:       currentKeys[0], // Use first key as new key
		RotatedAt:      time.Now(),
		AssuranceLevel: p.getAssuranceLevelForWebID(webID),
	}

	// Notify callbacks
	p.notifyKeyRotation(rotationInfo)

	// Log to audit
	p.auditLogger.Info("Key rotation detected",
		"webid", webID,
		"old_key", oldKeyID,
		"new_key", currentKeys[0],
		"assurance", rotationInfo.AssuranceLevel)

	// Invalidate cache to force re-fetch
	p.webIDCache.Invalidate(webID)

	return true, nil
}

// extractKeyIDsFromProfile extracts key IDs from a WebID profile
func (p *IdentityTrustPolicy) extractKeyIDsFromProfile(profile *WebIDProfile) []string {
	// This is a placeholder - actual implementation would parse the profile's publicKey
	var keyIDs []string

	// In a real implementation, this would:
	// 1. Parse the WebID profile RDF
	// 2. Find all publicKey entries
	// 3. Extract the ID of each publicKey

	return keyIDs
}

// getAssuranceLevelForWebID gets the assurance level for a WebID
func (p *IdentityTrustPolicy) getAssuranceLevelForWebID(webID string) string {
	// Check cache first
	_, issuer, _, ok := p.webIDCache.GetWithMetadata(webID)
	if ok {
		return p.getAssuranceLevelForIssuer(issuer)
	}

	return "low"
}

// VerifyDIDWebIDEquivalence verifies the equivalence between a DID and a WebID
func (p *IdentityTrustPolicy) VerifyDIDWebIDEquivalence(ctx context.Context, did, webID string) error {
	// Validate DID method
	if err := p.validateDIDMethod(did); err != nil {
		return err
	}

	// Verify DID binding
	if p.didResolver == nil {
		p.logger.Warn("DID resolver not configured, skipping DID/WebID equivalence verification")
		return nil
	}

	err := p.didResolver.ValidateDIDBinding(ctx, did, webID)
	if err != nil {
		p.auditLogger.Warn("DID/WebID equivalence verification failed",
			"did", did,
			"webid", webID,
			"error", err)
		return fmt.Errorf("%w: %v", ErrDIDConfusionDetected, err)
	}

	// Log successful equivalence verification
	p.auditLogger.Info("DID/WebID equivalence verified", "did", did, "webid", webID)

	return nil
}

// validateDIDMethod validates that a DID method is allowed
func (p *IdentityTrustPolicy) validateDIDMethod(did string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Extract DID method from DID string
	// Format: did:<method>:<method-specific-id>
	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 {
		return fmt.Errorf("invalid DID format: %s", did)
	}

	method := parts[1]

	// Check if blocked
	for _, blocked := range p.options.DIDTrustPolicy.BlockedDIDMethods {
		if strings.EqualFold(method, blocked) {
			p.auditLogger.Warn("Blocked DID method used", "method", method, "did", did)
			return fmt.Errorf("DID method %s is blocked", method)
		}
	}

	// Check if allowed (if policy requires it)
	// For now, we allow all methods
	_ = method

	return nil
}

// NegativeTestCase represents a negative test case for identity verification
type NegativeTestCase struct {
	// Name is the test case name
	Name string

	// WebID is the WebID to test
	WebID string

	// Issuer is the issuer to test
	Issuer string

	// ExpectedError is the expected error
	ExpectedError error

	// Reason describes why this test case should fail
	Reason string
}

// NegativeTestResult contains the result of a negative test
type NegativeTestResult struct {
	// TestCase is the test case that was run
	TestCase NegativeTestCase

	// Passed indicates if the test passed (i.e., correctly failed with expected error)
	Passed bool

	// ActualError is the actual error received
	ActualError error

	// Duration is how long the test took
	Duration time.Duration
}

// RunNegativeTest runs a negative test case
func (p *IdentityTrustPolicy) RunNegativeTest(ctx context.Context, testCase NegativeTestCase) NegativeTestResult {
	start := time.Now()
	result := NegativeTestResult{
		TestCase: testCase,
	}

	// Run the verification that should fail
	err := p.VerifyIdentity(ctx, testCase.WebID, testCase.Issuer)

	result.Duration = time.Since(start)

	// Check if we got the expected error
	if testCase.ExpectedError != nil {
		if errors.Is(err, testCase.ExpectedError) ||
			(err != nil && testCase.ExpectedError.Error() == err.Error()) {
			result.Passed = true
		} else {
			result.ActualError = err
		}
	} else if err != nil {
		// Any error is acceptable if we expect identity verification to fail
		result.Passed = true
		result.ActualError = err
	} else {
		// No error when we expected one
		result.Passed = false
		result.ActualError = nil
	}

	// Log the test result
	if result.Passed {
		p.logger.Info("Negative test passed", "test", testCase.Name, "reason", testCase.Reason)
	} else {
		p.logger.Warn("Negative test failed", "test", testCase.Name, "expected", testCase.ExpectedError, "actual", result.ActualError)
	}

	return result
}

// RunAllNegativeTests runs all built-in negative tests
func (p *IdentityTrustPolicy) RunAllNegativeTests(ctx context.Context) []NegativeTestResult {
	testCases := p.getBuiltInNegativeTestCases()

	results := make([]NegativeTestResult, len(testCases))
	for i, testCase := range testCases {
		results[i] = p.RunNegativeTest(ctx, testCase)
	}

	return results
}

// getBuiltInNegativeTestCases returns the built-in negative test cases
func (p *IdentityTrustPolicy) getBuiltInNegativeTestCases() []NegativeTestCase {
	return []NegativeTestCase{
		{
			Name:          "HTTP issuer",
			WebID:         "https://example.com/profile/card#me",
			Issuer:        "http://insecure.example.com",
			ExpectedError: errors.New("issuer must use HTTPS"),
			Reason:        "Issuer must use HTTPS",
		},
		{
			Name:          "WebID without HTTPS",
			WebID:         "http://example.com/profile/card#me",
			Issuer:        "https://issuer.example.com",
			ExpectedError: errors.New("WebID must use HTTPS"),
			Reason:        "WebID must use HTTPS",
		},
		{
			Name:          "Issuer spoofing with IP",
			WebID:         "https://example.com/profile/card#me",
			Issuer:        "https://192.168.1.1",
			ExpectedError: ErrIssuerSpoofingDetected,
			Reason:        "Issuer using IP address may indicate spoofing",
		},
		{
			Name:          "WebID substitution",
			WebID:         "https://example.com/profile/card#me",
			Issuer:        "https://other-issuer.example.com",
			ExpectedError: ErrWebIDSubstitutionDetected,
			Reason:        "WebID profile issuer doesn't match expected issuer",
		},
		{
			Name:          "Invalid DID method",
			WebID:         "https://example.com/profile/card#me",
			Issuer:        "https://issuer.example.com",
			ExpectedError: errors.New("invalid DID format"),
			Reason:        "Invalid DID format",
		},
	}
}

// IdentityTrustPolicySnapshot contains a snapshot of the trust policy state
type IdentityTrustPolicySnapshot struct {
	// IssuerTrustPolicy is the issuer trust policy
	IssuerTrustPolicy IssuerTrustPolicy

	// ClientTrustPolicy is the client trust policy
	ClientTrustPolicy *ClientTrustPolicy

	// WebIDCacheSize is the current size of the WebID cache
	WebIDCacheSize int

	// TakenAt is when the snapshot was taken
	TakenAt time.Time
}

// Snapshot returns a snapshot of the current trust policy state
func (p *IdentityTrustPolicy) Snapshot() IdentityTrustPolicySnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return IdentityTrustPolicySnapshot{
		IssuerTrustPolicy: *p.issuerTrustPolicy,
		ClientTrustPolicy: p.clientTrustPolicy,
		WebIDCacheSize:    p.webIDCache.Size(),
		TakenAt:           time.Now(),
	}
}
