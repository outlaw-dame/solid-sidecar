// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements tenant-specific authentication and authorization configuration.
package runtime

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// TenantAuthConfig holds tenant-specific authentication configuration
type TenantAuthConfig struct {
	// IssuerTrustPolicy defines the trust policy for identity issuers
	IssuerTrustPolicy TenantIssuerTrustPolicy

	// AuthzMode defines the authorization mode for this tenant
	AuthzMode TenantAuthzMode

	// CompressionMode defines the compression mode for this tenant
	CompressionMode TenantCompressionMode

	// DPoPSettings defines DPoP-specific settings for this tenant
	DPoPSettings TenantDPoPSettings

	// WebIDProfileCacheTTL is the TTL for WebID profile caching (0 = disabled)
	WebIDProfileCacheTTL time.Duration

	// MaxWebIDProfileCacheSize is the maximum number of WebID profiles to cache
	MaxWebIDProfileCacheSize int

	// IdentityAssuranceLevel defines the minimum identity assurance level required
	IdentityAssuranceLevel string
}

// TenantIssuerTrustPolicy defines trust policy for identity issuers
type TenantIssuerTrustPolicy struct {
	// AllowedIssuers is a list of allowed identity issuer URLs
	// If empty, all issuers are allowed (not recommended for production)
	AllowedIssuers []string

	// BlockedIssuers is a list of explicitly blocked identity issuer URLs
	BlockedIssuers []string

	// RequireIssuerAllowlist enforces that only allowed issuers can be used
	RequireIssuerAllowlist bool

	// AllowIssuerDiscovery enables issuer discovery via .well-known configuration
	AllowIssuerDiscovery bool

	// IssuerPinning contains pinned issuer configurations
	IssuerPinning map[string]TenantIssuerPin

	// JWKSEndpointTTL is the TTL for JWKS endpoint caching
	JWKSEndpointTTL time.Duration
}

// TenantIssuerPin defines pinned issuer configuration
type TenantIssuerPin struct {
	// PublicKey contains the pinned public key
	PublicKey string

	// PublicKeyHash contains the pinned public key hash (SHA-256)
	PublicKeyHash string

	// ValidFrom is when the pin becomes valid
	ValidFrom time.Time

	// ValidUntil is when the pin expires
	ValidUntil time.Time

	// TrustLevel defines the trust level for this pinned issuer
	TrustLevel string
}

// TenantAuthzMode defines the authorization mode for a tenant
type TenantAuthzMode string

const (
	// TenantAuthzModeInherit inherits the global authorization mode
	TenantAuthzModeInherit TenantAuthzMode = "inherit"

	// TenantAuthzModeShadow runs in shadow mode (CSS authoritative)
	TenantAuthzModeShadow TenantAuthzMode = "shadow"

	// TenantAuthzModeNative runs in native authorization mode
	TenantAuthzModeNative TenantAuthzMode = "native"

	// TenantAuthzModeCSSOnly only allows CSS-based authorization
	TenantAuthzModeCSSOnly TenantAuthzMode = "css_only"
)

// TenantCompressionMode defines the compression mode for a tenant
type TenantCompressionMode string

const (
	// TenantCompressionModeInherit inherits the global compression mode
	TenantCompressionModeInherit TenantCompressionMode = "inherit"

	// TenantCompressionModeDisabled disables compression
	TenantCompressionModeDisabled TenantCompressionMode = "disabled"

	// TenantCompressionModeGzip enables GZIP compression
	TenantCompressionModeGzip TenantCompressionMode = "gzip"

	// TenantCompressionModeDeflate enables DEFLATE compression
	TenantCompressionModeDeflate TenantCompressionMode = "deflate"

	// TenantCompressionModeBrotli enables Brotli compression
	TenantCompressionModeBrotli TenantCompressionMode = "brotli"

	// TenantCompressionModeZstd enables Zstandard compression
	TenantCompressionModeZstd TenantCompressionMode = "zstd"
)

// TenantDPoPSettings defines DPoP-specific settings for a tenant
type TenantDPoPSettings struct {
	// RequireDPoPForAllRequests requires DPoP for all requests
	RequireDPoPForAllRequests bool

	// RequireDPoPForWriteRequests requires DPoP for write requests only
	RequireDPoPForWriteRequests bool

	// DPoPReplayWindow is the replay window for DPoP nonces
	DPoPReplayWindow time.Duration

	// DPoPMaxNonceAge is the maximum age for DPoP nonces
	DPoPMaxNonceAge time.Duration

	// DPoPNonceCleanupInterval is the interval for nonce cleanup
	DPoPNonceCleanupInterval time.Duration
}

// DefaultTenantAuthConfig returns a safe default tenant authentication configuration
func DefaultTenantAuthConfig() *TenantAuthConfig {
	return &TenantAuthConfig{
		IssuerTrustPolicy: TenantIssuerTrustPolicy{
			AllowedIssuers:        []string{},
			BlockedIssuers:        []string{},
			RequireIssuerAllowlist: false,
			AllowIssuerDiscovery:   true,
			IssuerPinning:          make(map[string]TenantIssuerPin),
			JWKSEndpointTTL:        1 * time.Hour,
		},
		AuthzMode:         TenantAuthzModeInherit,
		CompressionMode:   TenantCompressionModeInherit,
		DPoPSettings: TenantDPoPSettings{
			RequireDPoPForAllRequests:   false,
			RequireDPoPForWriteRequests: true,
			DPoPReplayWindow:            10 * time.Minute,
			DPoPMaxNonceAge:            10 * time.Minute,
			DPoPNonceCleanupInterval:   5 * time.Minute,
		},
		WebIDProfileCacheTTL:   5 * time.Minute,
		MaxWebIDProfileCacheSize: 1000,
		IdentityAssuranceLevel:  "low",
	}
}

// ValidateTenantAuthConfig validates the tenant authentication configuration
func ValidateTenantAuthConfig(config *TenantAuthConfig) error {
	if config == nil {
		return errors.New("tenant auth config cannot be nil")
	}

	// Validate issuer trust policy
	for _, issuer := range config.IssuerTrustPolicy.AllowedIssuers {
		if strings.TrimSpace(issuer) == "" {
			return errors.New("allowed issuers cannot contain empty strings")
		}
		if !isValidURL(issuer) {
			return fmt.Errorf("invalid issuer URL: %s", issuer)
		}
	}

	for _, issuer := range config.IssuerTrustPolicy.BlockedIssuers {
		if strings.TrimSpace(issuer) == "" {
			return errors.New("blocked issuers cannot contain empty strings")
		}
		if !isValidURL(issuer) {
			return fmt.Errorf("invalid blocked issuer URL: %s", issuer)
		}
	}

	// Validate issuer pinning
	for issuer, pin := range config.IssuerTrustPolicy.IssuerPinning {
		if !isValidURL(issuer) {
			return fmt.Errorf("invalid pinned issuer URL: %s", issuer)
		}
		if pin.PublicKey == "" && pin.PublicKeyHash == "" {
			return fmt.Errorf("pinned issuer %s must have either public key or hash", issuer)
		}
		if pin.PublicKey != "" && len(pin.PublicKey) > 4096 {
			return fmt.Errorf("public key for issuer %s exceeds maximum length", issuer)
		}
		if pin.PublicKeyHash != "" && len(pin.PublicKeyHash) != 64 {
			return fmt.Errorf("invalid public key hash length for issuer %s", issuer)
		}
		if !pin.ValidFrom.IsZero() && !pin.ValidUntil.IsZero() && pin.ValidFrom.After(pin.ValidUntil) {
			return fmt.Errorf("invalid validity period for pinned issuer %s", issuer)
		}
	}

	// Validate authz mode
	switch config.AuthzMode {
	case TenantAuthzModeInherit, TenantAuthzModeShadow, TenantAuthzModeNative, TenantAuthzModeCSSOnly:
		// Valid modes
	default:
		return fmt.Errorf("invalid authz mode: %s", config.AuthzMode)
	}

	// Validate compression mode
	switch config.CompressionMode {
	case TenantCompressionModeInherit, TenantCompressionModeDisabled, TenantCompressionModeGzip, TenantCompressionModeDeflate, TenantCompressionModeBrotli, TenantCompressionModeZstd:
		// Valid modes
	default:
		return fmt.Errorf("invalid compression mode: %s", config.CompressionMode)
	}

	// Validate DPoP settings
	if config.DPoPSettings.DPoPReplayWindow < 0 {
		return errors.New("DPoP replay window cannot be negative")
	}
	if config.DPoPSettings.DPoPMaxNonceAge < 0 {
		return errors.New("DPoP max nonce age cannot be negative")
	}
	if config.DPoPSettings.DPoPNonceCleanupInterval <= 0 {
		return errors.New("DPoP nonce cleanup interval must be positive")
	}

	// Validate cache settings
	if config.WebIDProfileCacheTTL < 0 {
		return errors.New("WebID profile cache TTL cannot be negative")
	}
	if config.MaxWebIDProfileCacheSize < 0 {
		return errors.New("max WebID profile cache size cannot be negative")
	}
	if config.MaxWebIDProfileCacheSize > 100000 {
		return errors.New("max WebID profile cache size exceeds maximum of 100000")
	}

	// Validate identity assurance level
	validAssuranceLevels := []string{"low", "medium", "high", "very_high"}
	isValid := false
	for _, level := range validAssuranceLevels {
		if config.IdentityAssuranceLevel == level {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid identity assurance level: %s", config.IdentityAssuranceLevel)
	}

	return nil
}

// isValidURL is a simple URL validation helper
func isValidURL(urlStr string) bool {
	// Simple validation - URL should start with http:// or https://
	urlStr = strings.TrimSpace(urlStr)
	return strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://")
}

// TenantAuthManager manages tenant authentication configurations
type TenantAuthManager struct {
	mu sync.RWMutex

	// tenantAuthConfigs maps tenant IDs to their authentication configurations
	tenantAuthConfigs map[string]*TenantAuthConfig

	// defaultAuthConfig is the default authentication configuration
	defaultAuthConfig *TenantAuthConfig

	// logger is the logger for this manager
	logger *slog.Logger
}

// NewTenantAuthManager creates a new tenant authentication manager
func NewTenantAuthManager(logger *slog.Logger) *TenantAuthManager {
	if logger == nil {
		logger = slog.Default()
	}

	return &TenantAuthManager{
		tenantAuthConfigs:  make(map[string]*TenantAuthConfig),
		defaultAuthConfig: DefaultTenantAuthConfig(),
		logger:            logger,
	}
}

// SetDefaultAuthConfig sets the default authentication configuration
func (m *TenantAuthManager) SetDefaultAuthConfig(config *TenantAuthConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if config == nil {
		return errors.New("default auth config cannot be nil")
	}

	if err := ValidateTenantAuthConfig(config); err != nil {
		return fmt.Errorf("invalid default auth config: %w", err)
	}

	m.defaultAuthConfig = config
	m.logger.Info("Default tenant auth config updated")
	return nil
}

// AddTenantAuthConfig adds an authentication configuration for a specific tenant
func (m *TenantAuthManager) AddTenantAuthConfig(tenantID string, config *TenantAuthConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if tenantID == "" {
		return errors.New("tenant ID cannot be empty")
	}

	if config == nil {
		return errors.New("tenant auth config cannot be nil")
	}

	if err := ValidateTenantAuthConfig(config); err != nil {
		return fmt.Errorf("invalid tenant auth config for %s: %w", tenantID, err)
	}

	// Create a deep copy to prevent external modification
	configCopy := m.copyTenantAuthConfig(config)
	m.tenantAuthConfigs[tenantID] = configCopy

	m.logger.Info("Tenant auth config added", "tenant_id", tenantID)
	return nil
}

// UpdateTenantAuthConfig updates the authentication configuration for a specific tenant
func (m *TenantAuthManager) UpdateTenantAuthConfig(tenantID string, config *TenantAuthConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if tenantID == "" {
		return errors.New("tenant ID cannot be empty")
	}

	if config == nil {
		return errors.New("tenant auth config cannot be nil")
	}

	if err := ValidateTenantAuthConfig(config); err != nil {
		return fmt.Errorf("invalid tenant auth config for %s: %w", tenantID, err)
	}

	if _, exists := m.tenantAuthConfigs[tenantID]; !exists {
		return fmt.Errorf("tenant auth config not found for %s", tenantID)
	}

	// Create a deep copy to prevent external modification
	configCopy := m.copyTenantAuthConfig(config)
	m.tenantAuthConfigs[tenantID] = configCopy

	m.logger.Info("Tenant auth config updated", "tenant_id", tenantID)
	return nil
}

// GetTenantAuthConfig returns the authentication configuration for a specific tenant
func (m *TenantAuthManager) GetTenantAuthConfig(tenantID string) (*TenantAuthConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if tenantID == "" {
		return nil, errors.New("tenant ID cannot be empty")
	}

	config, exists := m.tenantAuthConfigs[tenantID]
	if !exists {
		// Return default config if tenant-specific config not found
		return m.copyTenantAuthConfig(m.defaultAuthConfig), nil
	}

	// Return a copy to prevent external modification
	return m.copyTenantAuthConfig(config), nil
}

// RemoveTenantAuthConfig removes the authentication configuration for a specific tenant
func (m *TenantAuthManager) RemoveTenantAuthConfig(tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if tenantID == "" {
		return errors.New("tenant ID cannot be empty")
	}

	if _, exists := m.tenantAuthConfigs[tenantID]; !exists {
		return fmt.Errorf("tenant auth config not found for %s", tenantID)
	}

	delete(m.tenantAuthConfigs, tenantID)
	m.logger.Info("Tenant auth config removed", "tenant_id", tenantID)
	return nil
}

// ListTenantAuthConfigs returns all tenant authentication configurations
func (m *TenantAuthManager) ListTenantAuthConfigs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tenantIDs := make([]string, 0, len(m.tenantAuthConfigs))
	for tenantID := range m.tenantAuthConfigs {
		tenantIDs = append(tenantIDs, tenantID)
	}
	return tenantIDs
}

// copyTenantAuthConfig creates a deep copy of a tenant authentication configuration
func (m *TenantAuthManager) copyTenantAuthConfig(config *TenantAuthConfig) *TenantAuthConfig {
	if config == nil {
		return nil
	}

	// Copy issuer trust policy
	allowedIssuers := make([]string, len(config.IssuerTrustPolicy.AllowedIssuers))
	copy(allowedIssuers, config.IssuerTrustPolicy.AllowedIssuers)

	blockedIssuers := make([]string, len(config.IssuerTrustPolicy.BlockedIssuers))
	copy(blockedIssuers, config.IssuerTrustPolicy.BlockedIssuers)

	issuerPinning := make(map[string]TenantIssuerPin, len(config.IssuerTrustPolicy.IssuerPinning))
	for k, v := range config.IssuerTrustPolicy.IssuerPinning {
		issuerPinning[k] = v // TenantIssuerPin is a struct, so this is a shallow copy
	}

	// Copy DPoP settings (struct copy is sufficient)
	dpopSettings := config.DPoPSettings

	return &TenantAuthConfig{
		IssuerTrustPolicy: TenantIssuerTrustPolicy{
			AllowedIssuers:        allowedIssuers,
			BlockedIssuers:        blockedIssuers,
			RequireIssuerAllowlist: config.IssuerTrustPolicy.RequireIssuerAllowlist,
			AllowIssuerDiscovery:   config.IssuerTrustPolicy.AllowIssuerDiscovery,
			IssuerPinning:          issuerPinning,
			JWKSEndpointTTL:        config.IssuerTrustPolicy.JWKSEndpointTTL,
		},
		AuthzMode:         config.AuthzMode,
		CompressionMode:   config.CompressionMode,
		DPoPSettings:      dpopSettings,
		WebIDProfileCacheTTL:   config.WebIDProfileCacheTTL,
		MaxWebIDProfileCacheSize: config.MaxWebIDProfileCacheSize,
		IdentityAssuranceLevel:  config.IdentityAssuranceLevel,
	}
}

// GetEffectiveAuthzMode returns the effective authorization mode for a tenant
func (m *TenantAuthManager) GetEffectiveAuthzMode(tenantID string) TenantAuthzMode {
	config, err := m.GetTenantAuthConfig(tenantID)
	if err != nil || config == nil {
		return TenantAuthzModeInherit
	}

	return config.AuthzMode
}

// GetEffectiveCompressionMode returns the effective compression mode for a tenant
func (m *TenantAuthManager) GetEffectiveCompressionMode(tenantID string) TenantCompressionMode {
	config, err := m.GetTenantAuthConfig(tenantID)
	if err != nil || config == nil {
		return TenantCompressionModeInherit
	}

	return config.CompressionMode
}

// IsIssuerAllowed checks if an issuer is allowed for a specific tenant
func (m *TenantAuthManager) IsIssuerAllowed(tenantID string, issuerURL string) bool {
	config, err := m.GetTenantAuthConfig(tenantID)
	if err != nil || config == nil {
		// Use default config
		config = m.defaultAuthConfig
	}

	// Check if issuer is explicitly blocked
	for _, blocked := range config.IssuerTrustPolicy.BlockedIssuers {
		if strings.EqualFold(issuerURL, blocked) {
			return false
		}
	}

	// If allowlist is required, check if issuer is in the allowed list
	if config.IssuerTrustPolicy.RequireIssuerAllowlist {
		for _, allowed := range config.IssuerTrustPolicy.AllowedIssuers {
			if strings.EqualFold(issuerURL, allowed) {
				return true
			}
		}
		return false
	}

	// If allowlist is not required, issuer is allowed (unless blocked)
	return true
}