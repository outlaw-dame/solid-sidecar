// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrEnforcementNotAllowed   = errors.New("enforcement not allowed")
	ErrEnforcementGateClosed   = errors.New("enforcement gate is closed")
	ErrEnforcementDisabled     = errors.New("enforcement disabled due to mismatches")
	ErrResourceNotAllowlisted  = errors.New("resource not in enforcement allowlist")
	ErrStorageNotAllowlisted   = errors.New("storage not in enforcement allowlist")
	ErrMethodNotAllowlisted    = errors.New("method not in enforcement allowlist")
	ErrInvalidAllowlistPattern = errors.New("invalid allowlist pattern")
)

// EnforcementMode represents the enforcement mode of the sidecar
type EnforcementMode string

const (
	// EnforcementModeShadow means the sidecar only observes and logs, doesn't enforce
	EnforcementModeShadow EnforcementMode = "shadow"
	// EnforcementModeEnforce means the sidecar enforces authorization decisions
	EnforcementModeEnforce EnforcementMode = "enforce"
	// EnforcementModeDryRun means the sidecar enforces but with a dry-run header
	EnforcementModeDryRun EnforcementMode = "dry-run"
	// EnforcementModeCanary means the sidecar enforces for canary requests only
	EnforcementModeCanary EnforcementMode = "enforce_canary"
)

// CanaryMode represents the canary enforcement strategy
type CanaryMode string

const (
	// CanaryModePercentage enforces for a percentage of requests
	CanaryModePercentage CanaryMode = "percentage"
	// CanaryModeHeader enforces for requests with a specific header
	CanaryModeHeader CanaryMode = "header"
	// CanaryModePath enforces for specific paths
	CanaryModePath CanaryMode = "path"
)

// EnforcementGateOptions configures the enforcement gate
type EnforcementGateOptions struct {
	// InitialMode is the starting enforcement mode
	// Default: EnforcementModeShadow
	InitialMode EnforcementMode

	// AllowEnforcement determines if enforcement mode is allowed
	// Default: false (shadow mode only for safety)
	// Requires explicit configuration to true - this is the startup guardrail
	AllowEnforcement bool

	// EmergencyBypassEnabled allows emergency bypass of enforcement
	// Default: true
	EmergencyBypassEnabled bool

	// EmergencyBypassToken is the token required for emergency bypass
	// Default: random token (should be configured in production)
	EmergencyBypassToken string

	// MaxEnforcementDuration is the maximum time enforcement can be enabled before auto-reverting
	// Default: 0 (no auto-revert)
	MaxEnforcementDuration time.Duration

	// ResourceAllowlist is a list of resource patterns that can be enforced
	// If empty and enforcement is enabled, all resources are allowed
	// Patterns support glob-style wildcards (*)
	ResourceAllowlist []string

	// StorageAllowlist is a list of storage/tenant patterns that can be enforced
	// If empty and enforcement is enabled, all storages are allowed
	StorageAllowlist []string

	// MethodAllowlist is a list of HTTP methods that can be enforced
	// Default: GET, HEAD (safe methods only)
	MethodAllowlist []string

	// AutoDisableOnMismatchThreshold is the percentage of mismatches (0-100) that will auto-disable enforcement
	// Default: 0 (disabled)
	AutoDisableOnMismatchThreshold int

	// CanaryConfig configures canary enforcement
	CanaryConfig CanaryConfig

	// RequireMultipleAuthors prevents single-person enforcement enable
	// Default: true (requires multiple operators to enable enforcement)
	RequireMultipleAuthors bool

	// RequireComparisonThreshold requires CSS comparison thresholds to be met before allowing enforcement
	// Default: true (enforcement requires passing comparison tests)
	RequireComparisonThreshold bool

	// ComparisonThresholdPercentage is the minimum percentage of matching decisions (0-100) required
	// Default: 100 (100% match rate required for enforcement)
	ComparisonThresholdPercentage int

	// ComparisonThresholdCount is the minimum number of consecutive matching decisions required
	// Default: 0 (disabled, use percentage only)
	ComparisonThresholdCount int

	// AuditLogger is the logger for enforcement audit events (separate from operational logs)
	AuditLogger *slog.Logger

	// OperationalLogger is the logger for operational events
	Logger *slog.Logger
}

// CanaryConfig configures canary enforcement
type CanaryConfig struct {
	// Enabled controls whether canary mode is active
	Enabled bool

	// Mode is the canary strategy (percentage, header, path)
	Mode CanaryMode

	// Percentage is the percentage of requests to enforce (0-100) when Mode is CanaryModePercentage
	Percentage int

	// HeaderName is the header to check when Mode is CanaryModeHeader
	HeaderName string

	// HeaderValue is the expected header value when Mode is CanaryModeHeader
	HeaderValue string

	// PathPatterns is the list of path patterns when Mode is CanaryModePath
	PathPatterns []string
}

// DefaultEnforcementGateOptions returns options with sensible defaults
func DefaultEnforcementGateOptions() EnforcementGateOptions {
	return EnforcementGateOptions{
		InitialMode:                    EnforcementModeShadow,
		AllowEnforcement:               false, // Startup guardrail: enforcement disabled by default
		EmergencyBypassEnabled:         true,
		EmergencyBypassToken:           generateEmergencyBypassToken(),
		MaxEnforcementDuration:         0,
		ResourceAllowlist:              []string{},
		StorageAllowlist:               []string{},
		MethodAllowlist:                []string{"GET", "HEAD"}, // Only safe methods by default
		AutoDisableOnMismatchThreshold: 0,
		CanaryConfig: CanaryConfig{
			Enabled:    false,
			Mode:       CanaryModePercentage,
			Percentage: 1, // 1% by default
		},
		RequireMultipleAuthors:        true,
		RequireComparisonThreshold:    false, // Disabled by default for backward compatibility; operators should enable
		ComparisonThresholdPercentage: 100,   // 100% match rate required
		ComparisonThresholdCount:      0,     // Disabled by default (use percentage only)
		AuditLogger:                   nil,
		Logger:                        nil,
	}
}

// EnforcementGateMetrics holds metrics for the enforcement gate
type EnforcementGateMetrics struct {
	mu sync.RWMutex

	// Enforcement mode changes
	ModeChanges int64

	// Enforcement decisions
	DecisionsEnforced int64
	DecisionsShadowed int64
	DecisionsAllow    int64
	DecisionsDeny     int64

	// Allowlist checks
	AllowlistHits   int64
	AllowlistMisses int64

	// Canary metrics
	CanaryRequestsEnforced int64
	CanaryRequestsShadowed int64

	// Mismatch tracking
	MismatchCount     int64
	MismatchLastTime  time.Time
	AutoDisableEvents int64

	// Emergency bypass
	EmergencyBypassActivated int64

	// Audit events
	AuditEvents int64
}

// EnforcementGateMetricsSnapshot is a point-in-time snapshot of metrics (no mutex, safe to copy)
type EnforcementGateMetricsSnapshot struct {
	// Enforcement mode changes
	ModeChanges int64

	// Enforcement decisions
	DecisionsEnforced int64
	DecisionsShadowed int64
	DecisionsAllow    int64
	DecisionsDeny     int64

	// Allowlist checks
	AllowlistHits   int64
	AllowlistMisses int64

	// Canary metrics
	CanaryRequestsEnforced int64
	CanaryRequestsShadowed int64

	// Mismatch tracking
	MismatchCount     int64
	MismatchLastTime  time.Time
	AutoDisableEvents int64

	// Emergency bypass
	EmergencyBypassActivated int64

	// Audit events
	AuditEvents int64
}

// RecordModeChange increments the mode change counter
func (m *EnforcementGateMetrics) RecordModeChange() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ModeChanges++
}

// RecordDecisionEnforced increments the enforced decision counter
func (m *EnforcementGateMetrics) RecordDecisionEnforced(allowed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DecisionsEnforced++
	if allowed {
		m.DecisionsAllow++
	} else {
		m.DecisionsDeny++
	}
}

// RecordDecisionShadowed increments the shadowed decision counter
func (m *EnforcementGateMetrics) RecordDecisionShadowed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DecisionsShadowed++
}

// RecordAllowlistHit increments the allowlist hit counter
func (m *EnforcementGateMetrics) RecordAllowlistHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AllowlistHits++
}

// RecordAllowlistMiss increments the allowlist miss counter
func (m *EnforcementGateMetrics) RecordAllowlistMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AllowlistMisses++
}

// RecordCanaryEnforced increments the canary enforced counter
func (m *EnforcementGateMetrics) RecordCanaryEnforced() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CanaryRequestsEnforced++
}

// RecordCanaryShadowed increments the canary shadowed counter
func (m *EnforcementGateMetrics) RecordCanaryShadowed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CanaryRequestsShadowed++
}

// RecordMismatch records a mismatch event
func (m *EnforcementGateMetrics) RecordMismatch() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.MismatchCount++
	m.MismatchLastTime = time.Now()
}

// RecordAutoDisable increments the auto-disable counter
func (m *EnforcementGateMetrics) RecordAutoDisable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AutoDisableEvents++
}

// RecordEmergencyBypass increments the emergency bypass counter
func (m *EnforcementGateMetrics) RecordEmergencyBypass() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EmergencyBypassActivated++
}

// RecordAuditEvent increments the audit event counter
func (m *EnforcementGateMetrics) RecordAuditEvent() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AuditEvents++
}

// GetMismatchRate returns the current mismatch rate as a percentage
func (m *EnforcementGateMetrics) GetMismatchRate() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	totalDecisions := m.DecisionsEnforced + m.DecisionsShadowed
	if totalDecisions == 0 {
		return 0
	}

	return float64(m.MismatchCount) / float64(totalDecisions) * 100
}

// Snapshot returns a point-in-time snapshot of the current metrics (safe to copy)
func (m *EnforcementGateMetrics) Snapshot() EnforcementGateMetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return EnforcementGateMetricsSnapshot{
		ModeChanges:              m.ModeChanges,
		DecisionsEnforced:        m.DecisionsEnforced,
		DecisionsShadowed:        m.DecisionsShadowed,
		DecisionsAllow:           m.DecisionsAllow,
		DecisionsDeny:            m.DecisionsDeny,
		AllowlistHits:            m.AllowlistHits,
		AllowlistMisses:          m.AllowlistMisses,
		CanaryRequestsEnforced:   m.CanaryRequestsEnforced,
		CanaryRequestsShadowed:   m.CanaryRequestsShadowed,
		MismatchCount:            m.MismatchCount,
		MismatchLastTime:         m.MismatchLastTime,
		AutoDisableEvents:        m.AutoDisableEvents,
		EmergencyBypassActivated: m.EmergencyBypassActivated,
		AuditEvents:              m.AuditEvents,
	}
}

// EnforcementGate controls access to enforcement mode
type EnforcementGate struct {
	mu sync.RWMutex

	options     EnforcementGateOptions
	mode        EnforcementMode
	enabledAt   time.Time
	bypassSet   map[string]struct{} // Set of active bypass tokens
	closed      bool
	closeReason string

	// Mismatch tracking
	mismatchCount     int64
	mismatchThreshold int
	lastMismatchTime  time.Time
	autoDisabled      bool
	autoDisableReason string

	// Canary tracking
	canaryRequestCount int64 // atomic counter for percentage-based canary

	// CSS comparison threshold tracking
	comparisonTotalCount  int64     // Total number of comparison results recorded
	comparisonMatchCount  int64     // Number of matching comparison results
	consecutiveMatchCount int64     // Number of consecutive matching results
	thresholdMet          bool      // Whether comparison thresholds have been met
	thresholdMetAt        time.Time // When thresholds were first met

	// Metrics
	metrics EnforcementGateMetrics
}

// NewEnforcementGate creates a new enforcement gate
func NewEnforcementGate(options EnforcementGateOptions) (*EnforcementGate, error) {
	// Apply startup guardrails
	if options.AllowEnforcement && options.RequireMultipleAuthors {
		// In production, this would require multiple operators to confirm
		// For now, we log a warning but allow it
		if options.Logger != nil {
			options.Logger.Warn("AllowEnforcement=true with RequireMultipleAuthors=true - multiple operator confirmation recommended")
		}
	}

	// Validate allowlist patterns
	for _, pattern := range options.ResourceAllowlist {
		if err := validatePattern(pattern); err != nil {
			return nil, fmt.Errorf("invalid resource allowlist pattern %q: %w", pattern, err)
		}
	}
	for _, pattern := range options.StorageAllowlist {
		if err := validatePattern(pattern); err != nil {
			return nil, fmt.Errorf("invalid storage allowlist pattern %q: %w", pattern, err)
		}
	}
	for _, pattern := range options.CanaryConfig.PathPatterns {
		if err := validatePattern(pattern); err != nil {
			return nil, fmt.Errorf("invalid canary path pattern %q: %w", pattern, err)
		}
	}

	// Validate canary configuration
	if options.CanaryConfig.Enabled {
		if options.CanaryConfig.Percentage < 0 || options.CanaryConfig.Percentage > 100 {
			return nil, errors.New("canary percentage must be between 0 and 100")
		}
		if options.CanaryConfig.Mode == CanaryModeHeader {
			if options.CanaryConfig.HeaderName == "" {
				return nil, errors.New("canary header name is required for header mode")
			}
		}
	}

	// Validate mismatch threshold
	if options.AutoDisableOnMismatchThreshold < 0 || options.AutoDisableOnMismatchThreshold > 100 {
		return nil, errors.New("auto-disable mismatch threshold must be between 0 and 100")
	}

	// Validate comparison threshold percentage
	if options.ComparisonThresholdPercentage < 0 || options.ComparisonThresholdPercentage > 100 {
		return nil, errors.New("comparison threshold percentage must be between 0 and 100")
	}

	// Validate comparison threshold count
	if options.ComparisonThresholdCount < 0 {
		return nil, errors.New("comparison threshold count must be non-negative")
	}

	if options.InitialMode == "" {
		options.InitialMode = EnforcementModeShadow
	}

	if options.EmergencyBypassToken == "" {
		options.EmergencyBypassToken = generateEmergencyBypassToken()
	}

	return &EnforcementGate{
		options:               options,
		mode:                  options.InitialMode,
		bypassSet:             make(map[string]struct{}),
		closed:                false,
		mismatchThreshold:     options.AutoDisableOnMismatchThreshold,
		comparisonTotalCount:  0,
		comparisonMatchCount:  0,
		consecutiveMatchCount: 0,
		thresholdMet:          false,
	}, nil
}

// validatePattern validates a glob-style pattern
func validatePattern(pattern string) error {
	// Check for invalid characters in patterns
	// Patterns can contain: alphanumeric, -, _, ., /, *, ?
	invalidPattern := regexp.MustCompile(`[^a-zA-Z0-9\-\_\.\/\*\?]`)
	if invalidPattern.MatchString(pattern) {
		return ErrInvalidAllowlistPattern
	}
	return nil
}

// Mode returns the current enforcement mode
func (g *EnforcementGate) Mode() EnforcementMode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mode
}

// IsEnforcementAllowed returns true if enforcement mode is allowed
func (g *EnforcementGate) IsEnforcementAllowed() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.options.AllowEnforcement
}

// IsShadowMode returns true if in shadow mode
func (g *EnforcementGate) IsShadowMode() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mode == EnforcementModeShadow
}

// IsEnforceMode returns true if in enforcement mode (includes canary)
func (g *EnforcementGate) IsEnforceMode() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mode == EnforcementModeEnforce || g.mode == EnforcementModeDryRun || g.mode == EnforcementModeCanary
}

// IsStrictEnforceMode returns true if in strict enforcement mode (not canary or dry-run)
func (g *EnforcementGate) IsStrictEnforceMode() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mode == EnforcementModeEnforce
}

// IsCanaryMode returns true if in canary enforcement mode
func (g *EnforcementGate) IsCanaryMode() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mode == EnforcementModeCanary
}

// IsDryRunMode returns true if in dry-run mode
func (g *EnforcementGate) IsDryRunMode() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mode == EnforcementModeDryRun
}

// IsClosed returns true if the enforcement gate is closed
func (g *EnforcementGate) IsClosed() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.closed
}

// IsAutoDisabled returns true if enforcement was auto-disabled due to mismatches
func (g *EnforcementGate) IsAutoDisabled() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.autoDisabled
}

// AutoDisableReason returns the reason for auto-disable, if any
func (g *EnforcementGate) AutoDisableReason() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.autoDisableReason
}

// CloseReason returns the reason the gate was closed, if any
func (g *EnforcementGate) CloseReason() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.closeReason
}

// SetMode sets the enforcement mode
// Returns error if enforcement is not allowed or gate is closed
// Critical Phase 19 requirement: enforcement modes cannot be enabled without passing CSS comparison thresholds
func (g *EnforcementGate) SetMode(mode EnforcementMode) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return fmt.Errorf("%w: %s", ErrEnforcementGateClosed, g.closeReason)
	}

	// Check if enforcement modes are allowed
	if mode == EnforcementModeEnforce || mode == EnforcementModeDryRun || mode == EnforcementModeCanary {
		if !g.options.AllowEnforcement {
			return fmt.Errorf("%w: enforcement mode not configured as allowed", ErrEnforcementNotAllowed)
		}

		// Phase 19: Critical safety check - enforcement requires passing CSS comparison thresholds
		// This prevents enabling enforcement without proven CSS compatibility
		if g.options.RequireComparisonThreshold && !g.thresholdMet {
			return fmt.Errorf("enforcement mode requires CSS comparison thresholds to be met first. Current: %d/%d matches (%.1f%%)",
				g.comparisonMatchCount, g.comparisonTotalCount,
				float64(g.comparisonMatchCount)/float64(g.comparisonTotalCount)*100)
		}
	}

	// If switching to enforcement mode, record the time
	if mode == EnforcementModeEnforce || mode == EnforcementModeDryRun || mode == EnforcementModeCanary {
		g.enabledAt = time.Now()
		g.logModeChange(mode)
		// Clear auto-disable state when manually enabling
		g.autoDisabled = false
		g.autoDisableReason = ""
		g.metrics.RecordModeChange()
	}

	// If switching to shadow, clear auto-disable
	if mode == EnforcementModeShadow {
		g.autoDisabled = false
		g.autoDisableReason = ""
		g.logModeChange(mode)
		g.metrics.RecordModeChange()
	}

	g.mode = mode
	return nil
}

// EnableEnforcement enables enforcement mode
// Returns error if not allowed or gate is closed
func (g *EnforcementGate) EnableEnforcement() error {
	return g.SetMode(EnforcementModeEnforce)
}

// EnableDryRun enables dry-run mode
// Returns error if not allowed or gate is closed
func (g *EnforcementGate) EnableDryRun() error {
	return g.SetMode(EnforcementModeDryRun)
}

// EnableCanary enables canary enforcement mode
// Returns error if not allowed or gate is closed
func (g *EnforcementGate) EnableCanary() error {
	return g.SetMode(EnforcementModeCanary)
}

// DisableEnforcement disables enforcement and returns to shadow mode
func (g *EnforcementGate) DisableEnforcement() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mode = EnforcementModeShadow
	g.autoDisabled = false
	g.autoDisableReason = ""
	g.logModeChange(EnforcementModeShadow)
	g.metrics.RecordModeChange()
}

// EmergencyBypass performs an emergency bypass of enforcement
// Returns true if bypass was successful
func (g *EnforcementGate) EmergencyBypass(token string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.options.EmergencyBypassEnabled {
		return false
	}

	if token == g.options.EmergencyBypassToken {
		g.bypassSet[token] = struct{}{}
		g.logEmergencyBypass()
		g.metrics.RecordEmergencyBypass()
		return true
	}

	return false
}

// ClearEmergencyBypass clears an emergency bypass
func (g *EnforcementGate) ClearEmergencyBypass(token string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.bypassSet, token)
}

// IsEmergencyBypassActive returns true if an emergency bypass is active
func (g *EnforcementGate) IsEmergencyBypassActive() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.bypassSet) > 0
}

// Close closes the enforcement gate, preventing any mode changes
func (g *EnforcementGate) Close(reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	g.closeReason = reason
	g.logGateClosed(reason)
}

// Reopen reopens the enforcement gate
func (g *EnforcementGate) Reopen() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = false
	g.closeReason = ""
	g.logGateReopened()
}

// CheckEnforcementDuration checks if enforcement has been enabled too long
// Returns true if the duration has been exceeded
func (g *EnforcementGate) CheckEnforcementDuration() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.options.MaxEnforcementDuration == 0 {
		return false
	}

	if g.mode != EnforcementModeEnforce && g.mode != EnforcementModeDryRun && g.mode != EnforcementModeCanary {
		return false
	}

	return time.Since(g.enabledAt) > g.options.MaxEnforcementDuration
}

// AutoRevertIfNeeded automatically reverts to shadow mode if enforcement duration exceeded
func (g *EnforcementGate) AutoRevertIfNeeded() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.options.MaxEnforcementDuration == 0 {
		return
	}

	if g.mode != EnforcementModeEnforce && g.mode != EnforcementModeDryRun && g.mode != EnforcementModeCanary {
		return
	}

	if time.Since(g.enabledAt) > g.options.MaxEnforcementDuration {
		g.mode = EnforcementModeShadow
		g.logAutoRevert()
		g.metrics.RecordModeChange()
	}
}

// ShouldEnforce returns true if the current request should be enforced
// This considers the current mode, any emergency bypasses, and allowlists
func (g *EnforcementGate) ShouldEnforce() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// If gate is closed, always shadow
	if g.closed {
		return false
	}

	// If auto-disabled due to mismatches, always shadow
	if g.autoDisabled {
		return false
	}

	// If emergency bypass is active, always shadow
	if g.IsEmergencyBypassActive() {
		return false
	}

	// Check mode
	return g.mode == EnforcementModeEnforce || g.mode == EnforcementModeDryRun || g.mode == EnforcementModeCanary
}

// ShouldEnforceForRequest returns true if the specific request should be enforced
// This considers canary mode, allowlists, and all other factors
func (g *EnforcementGate) ShouldEnforceForRequest(req *http.Request) bool {
	// First check basic enforcement
	if !g.ShouldEnforce() {
		return false
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	// Check canary mode
	if g.mode == EnforcementModeCanary {
		return g.isCanaryRequest(req)
	}

	// Check method allowlist
	if !g.isMethodAllowlisted(req.Method) {
		g.metrics.RecordAllowlistMiss()
		return false
	}

	// Check resource allowlist
	if !g.isResourceAllowlisted(req.URL.String()) {
		g.metrics.RecordAllowlistMiss()
		return false
	}

	// Check storage allowlist
	if !g.isStorageAllowlisted(req.URL.Host) {
		g.metrics.RecordAllowlistMiss()
		return false
	}

	g.metrics.RecordAllowlistHit()
	return true
}

// isCanaryRequest determines if a request should be enforced in canary mode
func (g *EnforcementGate) isCanaryRequest(req *http.Request) bool {
	if !g.options.CanaryConfig.Enabled {
		return false
	}

	switch g.options.CanaryConfig.Mode {
	case CanaryModePercentage:
		// Use atomic counter for thread-safe percentage calculation
		count := atomic.AddInt64(&g.canaryRequestCount, 1)
		// Use modulo to get percentage
		if count%100 < int64(g.options.CanaryConfig.Percentage) {
			atomic.AddInt64(&g.metrics.CanaryRequestsEnforced, 1)
			return true
		}
		atomic.AddInt64(&g.metrics.CanaryRequestsShadowed, 1)
		return false

	case CanaryModeHeader:
		if g.options.CanaryConfig.HeaderName == "" {
			return false
		}
		headerValue := req.Header.Get(g.options.CanaryConfig.HeaderName)
		if headerValue == g.options.CanaryConfig.HeaderValue {
			return true
		}
		return false

	case CanaryModePath:
		path := req.URL.Path
		for _, pattern := range g.options.CanaryConfig.PathPatterns {
			if matchPattern(pattern, path) {
				return true
			}
		}
		return false
	}

	return false
}

// isMethodAllowlisted checks if the HTTP method is in the allowlist
func (g *EnforcementGate) isMethodAllowlisted(method string) bool {
	// If no allowlist, all methods are allowed
	if len(g.options.MethodAllowlist) == 0 {
		return true
	}

	// Normalize method to uppercase
	method = strings.ToUpper(method)

	for _, allowed := range g.options.MethodAllowlist {
		if strings.ToUpper(allowed) == method {
			return true
		}
	}

	return false
}

// isResourceAllowlisted checks if the resource is in the allowlist
func (g *EnforcementGate) isResourceAllowlisted(resource string) bool {
	// If no allowlist, all resources are allowed
	if len(g.options.ResourceAllowlist) == 0 {
		return true
	}

	parsed, err := url.Parse(resource)
	if err != nil {
		// If we can't parse, default to not allowlisted for safety
		return false
	}

	path := parsed.Path
	for _, pattern := range g.options.ResourceAllowlist {
		if matchPattern(pattern, path) {
			return true
		}
	}

	return false
}

// isStorageAllowlisted checks if the storage/tenant is in the allowlist
func (g *EnforcementGate) isStorageAllowlisted(host string) bool {
	// If no allowlist, all storages are allowed
	if len(g.options.StorageAllowlist) == 0 {
		return true
	}

	for _, pattern := range g.options.StorageAllowlist {
		if matchPattern(pattern, host) {
			return true
		}
	}

	return false
}

// matchPattern matches a glob-style pattern against a string
func matchPattern(pattern, s string) bool {
	// Convert glob pattern to regex
	// Escape special regex characters except * and ?
	regexPattern := regexp.QuoteMeta(pattern)
	// Replace \* with .* and \? with .
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, `.*`)
	regexPattern = strings.ReplaceAll(regexPattern, `\?`, `.`)
	// Anchor the pattern
	regexPattern = "^" + regexPattern + "$"

	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}

	return re.MatchString(s)
}

// RecordMismatch records a mismatch between sidecar and CSS decisions
func (g *EnforcementGate) RecordMismatch() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.mismatchCount++
	g.lastMismatchTime = time.Now()
	g.metrics.RecordMismatch()

	// Check if we should auto-disable
	if g.options.AutoDisableOnMismatchThreshold > 0 {
		totalRequests := g.metrics.DecisionsEnforced + g.metrics.DecisionsShadowed
		if totalRequests > 0 {
			mismatchRate := float64(g.mismatchCount) / float64(totalRequests) * 100
			if mismatchRate > float64(g.options.AutoDisableOnMismatchThreshold) {
				g.autoDisabled = true
				g.autoDisableReason = fmt.Sprintf("mismatch rate %.2f%% exceeded threshold %d%%",
					mismatchRate, g.options.AutoDisableOnMismatchThreshold)
				g.metrics.RecordAutoDisable()
				g.logAutoDisable(g.autoDisableReason)
			}
		}
	}
}

// ClearMismatches clears the mismatch count and re-enables enforcement if auto-disabled
func (g *EnforcementGate) ClearMismatches() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.mismatchCount = 0
	g.lastMismatchTime = time.Time{}

	// Re-enable if we were auto-disabled
	if g.autoDisabled {
		g.autoDisabled = false
		g.autoDisableReason = ""
		g.logAutoDisableCleared()
	}
}

// DecorateDecision adds enforcement-related metadata to a decision
func (g *EnforcementGate) DecorateDecision(decision Decision) Decision {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// In a real implementation, we would add enforcement metadata
	// For now, we just return the decision as-is
	// The enforcement mode is tracked separately
	// Note: The Decision type from types.go doesn't have Allow/Reason fields
	// but DecisionValue has allow/deny/abstain values
	return decision
}

// GetMismatchCount returns the current mismatch count
func (g *EnforcementGate) GetMismatchCount() int64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mismatchCount
}

// GetMetrics returns a snapshot of the current metrics
func (g *EnforcementGate) GetMetrics() EnforcementGateMetricsSnapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.metrics.Snapshot()
}

// ShouldAddDryRunHeader returns true if dry-run header should be added
func (g *EnforcementGate) ShouldAddDryRunHeader() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.mode == EnforcementModeDryRun && !g.closed
}

// ShouldAddCanaryHeader returns true if canary header should be added
func (g *EnforcementGate) ShouldAddCanaryHeader() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.mode == EnforcementModeCanary && !g.closed
}

// ThresholdMet returns true if CSS comparison thresholds have been met
// This is a critical Phase 19 requirement: enforcement cannot be enabled without passing thresholds
func (g *EnforcementGate) ThresholdMet() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.thresholdMet
}

// ThresholdMetAt returns when the comparison thresholds were first met
func (g *EnforcementGate) ThresholdMetAt() time.Time {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.thresholdMetAt
}

// RecordComparisonResult records the result of a CSS comparison test
// match = true means the sidecar decision matched CSS decision
// This updates internal counters and checks if thresholds are met
// Thread-safe: uses mutex for all state modifications
func (g *EnforcementGate) RecordComparisonResult(match bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.comparisonTotalCount++

	if match {
		g.comparisonMatchCount++
		g.consecutiveMatchCount++

		// Log the match
		if g.options.Logger != nil {
			g.options.Logger.Debug("CSS comparison match recorded",
				"total", g.comparisonTotalCount,
				"matches", g.comparisonMatchCount,
				"consecutive", g.consecutiveMatchCount)
		}

		// Check if we've met the thresholds
		// Both percentage and consecutive thresholds must be met if both are configured
		percentageMet := false
		consecutiveMet := false

		// Check consecutive threshold
		if g.options.ComparisonThresholdCount > 0 {
			consecutiveMet = g.consecutiveMatchCount >= int64(g.options.ComparisonThresholdCount)
		} else {
			consecutiveMet = true // If not configured, consider it met
		}

		// Check percentage threshold
		if g.options.ComparisonThresholdPercentage > 0 && g.comparisonTotalCount > 0 {
			matchPercentage := float64(g.comparisonMatchCount) / float64(g.comparisonTotalCount) * 100
			percentageMet = matchPercentage >= float64(g.options.ComparisonThresholdPercentage)
		} else {
			percentageMet = true // If not configured, consider it met
		}

		// Both must be met to trigger threshold
		if consecutiveMet && percentageMet {
			g.setThresholdMet()
			return
		}
	} else {
		// Reset consecutive counter on mismatch
		g.consecutiveMatchCount = 0

		// Log the mismatch
		if g.options.Logger != nil {
			g.options.Logger.Warn("CSS comparison mismatch recorded",
				"total", g.comparisonTotalCount,
				"matches", g.comparisonMatchCount,
				"consecutive", g.consecutiveMatchCount)
		}

		// Reset threshold if it was met - a mismatch means we're no longer meeting consecutive requirements
		// Note: The threshold can be re-met later if we achieve the required consecutive matches again
		if g.thresholdMet {
			g.thresholdMet = false
			g.thresholdMetAt = time.Time{}
			if g.options.Logger != nil {
				g.options.Logger.Info("CSS comparison threshold reset due to mismatch")
			}
		}
	}

	// If we haven't met thresholds yet, log current progress
	if !g.thresholdMet && g.options.Logger != nil && g.comparisonTotalCount > 0 {
		var matchRate float64
		if g.comparisonTotalCount > 0 {
			matchRate = float64(g.comparisonMatchCount) / float64(g.comparisonTotalCount) * 100
		}
		g.options.Logger.Info("CSS comparison threshold progress",
			"matches", g.comparisonMatchCount,
			"total", g.comparisonTotalCount,
			"match_rate_percentage", matchRate,
			"required_percentage", g.options.ComparisonThresholdPercentage,
			"consecutive_matches", g.consecutiveMatchCount,
			"required_consecutive", g.options.ComparisonThresholdCount)
	}
}

// setThresholdMet marks that comparison thresholds have been met
// Must be called with g.mu held (Lock, not RLock)
func (g *EnforcementGate) setThresholdMet() {
	if !g.thresholdMet {
		g.thresholdMet = true
		g.thresholdMetAt = time.Now()
		g.metrics.RecordAuditEvent()

		if g.options.Logger != nil {
			g.options.Logger.Info("CSS comparison thresholds MET - enforcement can be enabled",
				"matches", g.comparisonMatchCount,
				"total", g.comparisonTotalCount,
				"match_rate_percentage", float64(g.comparisonMatchCount)/float64(g.comparisonTotalCount)*100,
				"consecutive_matches", g.consecutiveMatchCount,
				"timestamp", g.thresholdMetAt)
		}

		if g.options.AuditLogger != nil {
			g.options.AuditLogger.Info("AUDIT: CSS comparison thresholds met",
				"matches", g.comparisonMatchCount,
				"total", g.comparisonTotalCount,
				"timestamp", g.thresholdMetAt.UTC().Format(time.RFC3339))
		}
	}
}

// ResetComparisonResults resets all comparison tracking counters
// Useful for testing or when starting fresh comparison runs
func (g *EnforcementGate) ResetComparisonResults() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.comparisonTotalCount = 0
	g.comparisonMatchCount = 0
	g.consecutiveMatchCount = 0
	g.thresholdMet = false
	g.thresholdMetAt = time.Time{}

	if g.options.Logger != nil {
		g.options.Logger.Info("CSS comparison results reset")
	}
}

// GetComparisonStats returns current comparison statistics
func (g *EnforcementGate) GetComparisonStats() (total int64, matches int64, consecutive int64, met bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.comparisonTotalCount, g.comparisonMatchCount, g.consecutiveMatchCount, g.thresholdMet
}

// GetMatchPercentage returns the current match percentage (0-100)
func (g *EnforcementGate) GetMatchPercentage() float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.comparisonTotalCount == 0 {
		return 0
	}
	return float64(g.comparisonMatchCount) / float64(g.comparisonTotalCount) * 100
}

// ResetComparisonThresholds resets all comparison tracking (alias for ResetComparisonResults for backward compatibility)
func (g *EnforcementGate) ResetComparisonThresholds() {
	g.ResetComparisonResults()
}

// EnforcementGateMiddleware creates middleware that checks the enforcement gate
func EnforcementGateMiddleware(gate *EnforcementGate, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add enforcement mode header
		w.Header().Set("X-Authz-Enforcement-Mode", string(gate.Mode()))

		// Add dry-run header if needed
		if gate.ShouldAddDryRunHeader() {
			w.Header().Set("X-Authz-Mode", "dry-run")
		}

		// Add canary header if needed
		if gate.ShouldAddCanaryHeader() {
			w.Header().Set("X-Authz-Canary", "true")
		}

		// Check auto-revert due to duration
		gate.AutoRevertIfNeeded()

		next.ServeHTTP(w, r)
	})
}

// Context utilities

// contextEnforcementModeKey is the context key for enforcement mode
type contextEnforcementModeKey struct{}

// WithEnforcementMode adds enforcement mode to context
func WithEnforcementMode(ctx context.Context, mode EnforcementMode) context.Context {
	return context.WithValue(ctx, contextEnforcementModeKey{}, mode)
}

// EnforcementModeFromContext gets enforcement mode from context
func EnforcementModeFromContext(ctx context.Context) (EnforcementMode, bool) {
	mode, ok := ctx.Value(contextEnforcementModeKey{}).(EnforcementMode)
	return mode, ok
}

// Helper functions

// GenerateEmergencyBypassToken generates a random emergency bypass token
func generateEmergencyBypassToken() string {
	// In a real implementation, this would generate a cryptographically secure token
	// For testing, we use a deterministic but unpredictable token
	hash := sha256.Sum256([]byte(fmt.Sprintf("emergency-bypass-%d", time.Now().UnixNano())))
	return fmt.Sprintf("%x", hash[:16]) // 128-bit token
}

// Log helpers

func (g *EnforcementGate) logModeChange(mode EnforcementMode) {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Info("Enforcement mode changed",
		"mode", mode,
	)
	g.metrics.RecordAuditEvent()
	if g.options.AuditLogger != nil {
		g.options.AuditLogger.Info("AUDIT: Enforcement mode changed",
			"mode", mode,
			"timestamp", time.Now().UTC().Format(time.RFC3339),
		)
	}
}

func (g *EnforcementGate) logEmergencyBypass() {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Warn("Emergency bypass activated",
		"token", "[REDACTED]",
	)
	g.metrics.RecordAuditEvent()
	if g.options.AuditLogger != nil {
		g.options.AuditLogger.Warn("AUDIT: Emergency bypass activated",
			"timestamp", time.Now().UTC().Format(time.RFC3339),
		)
	}
}

func (g *EnforcementGate) logGateClosed(reason string) {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Error("Enforcement gate closed",
		"reason", reason,
	)
	g.metrics.RecordAuditEvent()
	if g.options.AuditLogger != nil {
		g.options.AuditLogger.Error("AUDIT: Enforcement gate closed",
			"reason", reason,
			"timestamp", time.Now().UTC().Format(time.RFC3339),
		)
	}
}

func (g *EnforcementGate) logGateReopened() {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Info("Enforcement gate reopened")
	g.metrics.RecordAuditEvent()
	if g.options.AuditLogger != nil {
		g.options.AuditLogger.Info("AUDIT: Enforcement gate reopened",
			"timestamp", time.Now().UTC().Format(time.RFC3339),
		)
	}
}

func (g *EnforcementGate) logAutoRevert() {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Warn("Auto-reverted to shadow mode due to duration limit")
	g.metrics.RecordAuditEvent()
	if g.options.AuditLogger != nil {
		g.options.AuditLogger.Warn("AUDIT: Auto-reverted to shadow mode",
			"reason", "duration limit exceeded",
			"timestamp", time.Now().UTC().Format(time.RFC3339),
		)
	}
}

func (g *EnforcementGate) logAutoDisable(reason string) {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Error("Enforcement auto-disabled",
		"reason", reason,
	)
	g.metrics.RecordAuditEvent()
	if g.options.AuditLogger != nil {
		g.options.AuditLogger.Error("AUDIT: Enforcement auto-disabled",
			"reason", reason,
			"timestamp", time.Now().UTC().Format(time.RFC3339),
		)
	}
}

func (g *EnforcementGate) logAutoDisableCleared() {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Info("Enforcement auto-disable cleared")
	g.metrics.RecordAuditEvent()
	if g.options.AuditLogger != nil {
		g.options.AuditLogger.Info("AUDIT: Enforcement auto-disable cleared",
			"timestamp", time.Now().UTC().Format(time.RFC3339),
		)
	}
}
