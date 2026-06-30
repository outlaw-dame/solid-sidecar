// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

var ErrEnforcementNotAllowed = errors.New("enforcement not allowed")
var ErrEnforcementGateClosed = errors.New("enforcement gate is closed")

// EnforcementMode represents the enforcement mode of the sidecar
type EnforcementMode string

const (
	// EnforcementModeShadow means the sidecar only observes and logs, doesn't enforce
	EnforcementModeShadow EnforcementMode = "shadow"
	// EnforcementModeEnforce means the sidecar enforces authorization decisions
	EnforcementModeEnforce EnforcementMode = "enforce"
	// EnforcementModeDryRun means the sidecar enforces but with a dry-run header
	EnforcementModeDryRun EnforcementMode = "dry-run"
)

// EnforcementGateOptions configures the enforcement gate
type EnforcementGateOptions struct {
	// InitialMode is the starting enforcement mode
	// Default: EnforcementModeShadow
	InitialMode EnforcementMode

	// AllowEnforcement determines if enforcement mode is allowed
	// Default: false (shadow mode only for safety)
	AllowEnforcement bool

	// EmergencyBypassEnabled allows emergency bypass of enforcement
	// Default: true
	EmergencyBypassEnabled bool

	// EmergencyBypassToken is the token required for emergency bypass
	// Default: random token (should be configured)
	EmergencyBypassToken string

	// MaxEnforcementDuration is the maximum time enforcement can be enabled before auto-reverting
	// Default: 0 (no auto-revert)
	MaxEnforcementDuration time.Duration

	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultEnforcementGateOptions returns options with sensible defaults
func DefaultEnforcementGateOptions() EnforcementGateOptions {
	// Generate a random emergency bypass token
	// In production, this should be configured to a known value
	return EnforcementGateOptions{
		InitialMode:            EnforcementModeShadow,
		AllowEnforcement:       false,
		EmergencyBypassEnabled: true,
		EmergencyBypassToken:   generateEmergencyBypassToken(),
		MaxEnforcementDuration: 0,
		Logger:                 nil,
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
}

// NewEnforcementGate creates a new enforcement gate
func NewEnforcementGate(options EnforcementGateOptions) (*EnforcementGate, error) {
	if options.InitialMode == "" {
		options.InitialMode = EnforcementModeShadow
	}

	if options.EmergencyBypassToken == "" {
		options.EmergencyBypassToken = generateEmergencyBypassToken()
	}

	return &EnforcementGate{
		options:   options,
		mode:      options.InitialMode,
		bypassSet: make(map[string]struct{}),
		closed:    false,
	}, nil
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

// IsEnforceMode returns true if in enforcement mode
func (g *EnforcementGate) IsEnforceMode() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mode == EnforcementModeEnforce
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

// CloseReason returns the reason the gate was closed, if any
func (g *EnforcementGate) CloseReason() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.closeReason
}

// SetMode sets the enforcement mode
// Returns error if enforcement is not allowed or gate is closed
func (g *EnforcementGate) SetMode(mode EnforcementMode) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return fmt.Errorf("%w: %s", ErrEnforcementGateClosed, g.closeReason)
	}

	// Check if enforcement modes are allowed
	if mode == EnforcementModeEnforce || mode == EnforcementModeDryRun {
		if !g.options.AllowEnforcement {
			return fmt.Errorf("%w: enforcement mode not configured as allowed", ErrEnforcementNotAllowed)
		}
	}

	// If switching to enforcement mode, record the time
	if mode == EnforcementModeEnforce || mode == EnforcementModeDryRun {
		g.enabledAt = time.Now()
		g.logModeChange(mode)
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

// DisableEnforcement disables enforcement and returns to shadow mode
func (g *EnforcementGate) DisableEnforcement() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mode = EnforcementModeShadow
	g.logModeChange(EnforcementModeShadow)
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
		g.logEmergencyBypass(token)
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

	if g.mode != EnforcementModeEnforce && g.mode != EnforcementModeDryRun {
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

	if g.mode != EnforcementModeEnforce && g.mode != EnforcementModeDryRun {
		return
	}

	if time.Since(g.enabledAt) > g.options.MaxEnforcementDuration {
		g.mode = EnforcementModeShadow
		g.logAutoRevert()
	}
}

// ShouldEnforce returns true if the current request should be enforced
// This considers the current mode and any emergency bypasses
func (g *EnforcementGate) ShouldEnforce() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// If gate is closed, always shadow
	if g.closed {
		return false
	}

	// If emergency bypass is active, always shadow
	if g.IsEmergencyBypassActive() {
		return false
	}

	// Check mode
	return g.mode == EnforcementModeEnforce || g.mode == EnforcementModeDryRun
}

// ShouldAddDryRunHeader returns true if dry-run header should be added
func (g *EnforcementGate) ShouldAddDryRunHeader() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.mode == EnforcementModeDryRun && !g.closed
}

// DecorateDecision adds enforcement-related metadata to a decision
func (g *EnforcementGate) DecorateDecision(decision Decision) Decision {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Add enforcement mode to decision metadata if available
	// Note: Decision struct doesn't have a Metadata field currently,
	// so we'll need to add it or use a different approach
	// For now, we just return the decision as-is
	return decision
}

// GenerateEmergencyBypassToken generates a random emergency bypass token
func generateEmergencyBypassToken() string {
	// In a real implementation, this would generate a cryptographically secure token
	// For now, we use a simple timestamp-based token for testing
	return "emergency-bypass-" + fmt.Sprintf("%d", time.Now().UnixNano())
}

// EnforcementGateMiddleware creates middleware that checks the enforcement gate
func EnforcementGateMiddleware(gate *EnforcementGate, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if we should enforce
		if gate.ShouldEnforce() {
			// In enforcement mode, we would enforce decisions
			// For now, we just pass through
			// In a real implementation, this would check authorization
		}

		// Add dry-run header if needed
		if gate.ShouldAddDryRunHeader() {
			w.Header().Set("X-Authz-Mode", "dry-run")
		}

		// Add enforcement mode header
		w.Header().Set("X-Authz-Enforcement-Mode", string(gate.Mode()))

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

// Log helpers

func (g *EnforcementGate) logModeChange(mode EnforcementMode) {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Info("Enforcement mode changed",
		"mode", mode,
	)
}

func (g *EnforcementGate) logEmergencyBypass(token string) {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Warn("Emergency bypass activated",
		"token", "[REDACTED]",
	)
}

func (g *EnforcementGate) logGateClosed(reason string) {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Error("Enforcement gate closed",
		"reason", reason,
	)
}

func (g *EnforcementGate) logGateReopened() {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Info("Enforcement gate reopened")
}

func (g *EnforcementGate) logAutoRevert() {
	if g.options.Logger == nil {
		return
	}
	g.options.Logger.Warn("Auto-reverted to shadow mode due to duration limit")
}
