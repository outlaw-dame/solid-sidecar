// Package runtime provides the native Go/Rust Solid runtime path.
// This package implements the layers needed to evolve from CSS sidecar to a
// scalable Solid implementation while preserving compatibility.
//
// The runtime is designed with the following principles:
// 1. Gateway compatibility layer - maintains CSS compatibility
// 2. Storage abstraction - allows swapping storage backends
// 3. Metadata/index layer - efficient resource discovery
// 4. RDF graph/index layer - RDF parsing and indexing
// 5. Policy engine - authorization policy evaluation
// 6. Notification/live-update layer - real-time updates
// 7. Multi-storage/multi-tenant runtime - scalable architecture
// 8. CSS migration and compatibility mode - smooth transition
//
// All layers are designed to:
// - Maintain CSS compatibility
// - Be testable with fixture-backed tests
// - Support rollback to CSS behavior
// - Never skip compatibility tests
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Common errors for the runtime package
var (
	ErrRuntimeNotInitialized = errors.New("runtime not initialized")
	ErrLayerNotAvailable     = errors.New("layer not available")
	ErrCompatibilityCheck    = errors.New("CSS compatibility check failed")
	ErrStorageNotFound       = errors.New("storage backend not found")
	ErrMigrationInProgress   = errors.New("migration in progress")
)

// RuntimeMode represents the current runtime mode
type RuntimeMode string

const (
	// RuntimeModeCSSProxy means all requests are proxied to CSS (default)
	RuntimeModeCSSProxy RuntimeMode = "css_proxy"
	// RuntimeModeHybrid means some requests use native path, others use CSS
	RuntimeModeHybrid RuntimeMode = "hybrid"
	// RuntimeModeNative means all requests use native Solid runtime
	RuntimeModeNative RuntimeMode = "native"
)

// RuntimeModeComparisonEvidence stores CSS comparison results for mode transition verification
type RuntimeModeComparisonEvidence struct {
	// CSSProxyBaseline contains baseline behavior evidence from CSS proxy mode
	CSSProxyBaseline RuntimeComparisonBaseline

	// HybridComparison contains comparison results from hybrid mode testing
	HybridComparison RuntimeComparisonResults

	// NativeComparison contains comparison results from native mode testing
	NativeComparison RuntimeComparisonResults

	// LastComparisonTimestamp is when the most recent comparison was performed
	LastComparisonTimestamp time.Time

	// ComparisonPassed indicates whether comparison tests passed for transition readiness
	ComparisonPassed bool
}

// RuntimeComparisonBaseline stores baseline behavior measurements
type RuntimeComparisonBaseline struct {
	// RequestCount is the number of requests processed
	RequestCount int64
	// SuccessRate is the percentage of successful requests
	SuccessRate float64
	// AverageLatency is the average request latency
	AverageLatency time.Duration
	// ErrorRate is the percentage of requests that resulted in errors
	ErrorRate float64
}

// RuntimeComparisonResults stores comparison test results between modes
type RuntimeComparisonResults struct {
	// ComparisonTimestamp is when this comparison was performed
	ComparisonTimestamp time.Time
	// TestDuration is how long the comparison test ran
	TestDuration time.Duration
	// RequestCount is the number of test requests processed
	RequestCount int64
	// BehaviorMatches is the number of requests with matching behavior
	BehaviorMatches int64
	// BehaviorMismatches is the number of requests with different behavior
	BehaviorMismatches int64
	// AllowedDifferences is the number of intentionally allowed behavior differences
	AllowedDifferences int64
	// CriticalMismatches is the number of critical behavior differences that block transition
	CriticalMismatches int64
	// Passed indicates whether the comparison passed the readiness criteria
	Passed bool
}

// RuntimeConfig holds configuration for the Solid runtime
type RuntimeConfig struct {
	// Mode determines which runtime path to use
	Mode RuntimeMode

	// EnableCSSComparison enables CSS behavior comparison (required for migration)
	EnableCSSComparison bool

	// DefaultStorage is the default storage backend to use
	DefaultStorage string

	// Logger is the logger for runtime operations
	Logger *slog.Logger

	// MaxRetries is the maximum number of retries for transient failures
	MaxRetries int

	// BackoffBaseDelay is the base delay for exponential backoff
	BackoffBaseDelay int

	// BackoffMaxDelay is the maximum delay for exponential backoff
	BackoffMaxDelay int

	// ProductionMode controls whether production safety guardrails are enabled
	// When true, native and hybrid modes require explicit readiness verification
	ProductionMode bool

	// AllowNativeMode allows transition to native mode (requires ProductionMode=false or explicit readiness)
	AllowNativeMode bool

	// AllowHybridMode allows transition to hybrid mode (requires ProductionMode=false or explicit readiness)
	AllowHybridMode bool

	// RequireComparisonEvidence requires CSS comparison evidence before allowing mode transitions
	RequireComparisonEvidence bool

	// ComparisonEvidence provides stored comparison results for mode transition verification
	ComparisonEvidence RuntimeModeComparisonEvidence
}

// DefaultRuntimeConfig returns a safe default configuration
func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Mode:                      RuntimeModeCSSProxy,
		EnableCSSComparison:       true, // Always enabled for safety
		DefaultStorage:            "default",
		Logger:                    nil,
		MaxRetries:                3,
		BackoffBaseDelay:          100,   // 100ms
		BackoffMaxDelay:           5000,  // 5s
		ProductionMode:            true,  // Production safety enabled by default
		AllowNativeMode:           false, // Native mode disabled by default in production
		AllowHybridMode:           false, // Hybrid mode disabled by default in production
		RequireComparisonEvidence: true,  // Require CSS comparison before mode transitions
		ComparisonEvidence: RuntimeModeComparisonEvidence{
			ComparisonPassed: false, // No comparison evidence by default
		},
	}
}

// TestRuntimeConfig returns a configuration suitable for testing
// This disables production safety guardrails to allow mode transitions in tests
func TestRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Mode:                      RuntimeModeCSSProxy,
		EnableCSSComparison:       true,
		DefaultStorage:            "default",
		Logger:                    nil,
		MaxRetries:                3,
		BackoffBaseDelay:          100,
		BackoffMaxDelay:           5000,
		ProductionMode:            false, // Disabled for testing
		AllowNativeMode:           true,  // Allow all modes in tests
		AllowHybridMode:           true,  // Allow all modes in tests
		RequireComparisonEvidence: false, // Don't require comparison evidence in tests
		ComparisonEvidence: RuntimeModeComparisonEvidence{
			ComparisonPassed: true, // Assume tests have passed comparison
		},
	}
}

// Runtime is the main Solid runtime structure
type Runtime struct {
	mu sync.RWMutex

	config RuntimeConfig
	mode   RuntimeMode

	// Mode transition history for rollback support
	modeHistory []RuntimeMode

	// Layers
	gateway       *GatewayCompatibilityLayer
	storage       *StorageAbstractionLayer
	metadata      *MetadataIndexLayer
	rdf           *RDFGraphIndexLayer
	policyEngine  *PolicyEngineLayer
	notification  *NotificationLayer
	resourceIndex *ResourceIndexLayer
	eventStream   *EventStreamLayer
	multiStorage  *MultiStorageLayer
	migration     *CSSMigrationLayer

	// State
	initialized bool
	migrating   bool
}

// New creates a new Solid runtime with the given configuration
func New(config RuntimeConfig) (*Runtime, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	rt := &Runtime{
		config: config,
		mode:   config.Mode,
	}

	// Initialize all layers
	var err error

	// Layer 1: Gateway Compatibility Layer
	rt.gateway, err = NewGatewayCompatibilityLayer(GatewayCompatibilityConfig{
		Logger:           config.Logger,
		EnableComparison: config.EnableCSSComparison,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize gateway compatibility layer: %w", err)
	}

	// Layer 2: Storage Abstraction Layer
	rt.storage = NewStorageAbstractionLayer(StorageAbstractionConfig{
		DefaultStorage: config.DefaultStorage,
		Logger:         config.Logger,
		MaxRetries:     config.MaxRetries,
		BackoffBase:    config.BackoffBaseDelay,
		BackoffMax:     config.BackoffMaxDelay,
	})

	// Layer 3: Metadata/Index Layer
	rt.metadata = NewMetadataIndexLayer(MetadataIndexConfig{
		Logger: config.Logger,
	})

	// Layer 4: RDF Graph/Index Layer
	rt.rdf = NewRDFGraphIndexLayer(RDFGraphIndexConfig{
		Logger: config.Logger,
	})

	// Layer 5: Policy Engine Layer
	rt.policyEngine = NewPolicyEngineLayer(PolicyEngineConfig{
		Logger: config.Logger,
	})

	// Layer 6: Resource Index Layer (Phase 16)
	rt.resourceIndex = NewResourceIndexLayer(DefaultResourceIndexConfig())

	// Layer 6.1: Notification/Live-Update Layer
	rt.notification = NewNotificationLayer(NotificationConfig{
		Logger: config.Logger,
	})

	// Layer 6.2: Event Stream Layer (Phase 16)
	// Connect event stream to notification layer
	rt.eventStream = NewEventStreamLayer(DefaultEventStreamConfig(), rt.notification)

	// Layer 7: Multi-Storage/Multi-Tenant Layer
	rt.multiStorage = NewMultiStorageLayer(MultiStorageConfig{
		Logger: config.Logger,
	})

	// Layer 8: CSS Migration and Compatibility Mode
	rt.migration = NewCSSMigrationLayer(CSSMigrationConfig{
		Logger:           config.Logger,
		EnableComparison: config.EnableCSSComparison,
	})

	rt.initialized = true

	config.Logger.Info("Solid runtime initialized",
		"mode", config.Mode,
		"enable_css_comparison", config.EnableCSSComparison,
	)

	return rt, nil
}

// Mode returns the current runtime mode
func (rt *Runtime) Mode() RuntimeMode {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.mode
}

// SetMode sets the runtime mode
func (rt *Runtime) SetMode(mode RuntimeMode) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Validate the mode transition
	if !rt.canTransition(rt.mode, mode) {
		return fmt.Errorf("cannot transition from %s to %s: production safety guardrails prevent this transition", rt.mode, mode)
	}

	// Record current mode in history before changing
	rt.modeHistory = append(rt.modeHistory, rt.mode)
	// Keep only the last 10 mode transitions to prevent memory bloat
	if len(rt.modeHistory) > 10 {
		rt.modeHistory = rt.modeHistory[len(rt.modeHistory)-10:]
	}

	previousMode := rt.mode
	rt.mode = mode
	rt.config.Logger.Info("Runtime mode changed", "old_mode", previousMode, "new_mode", mode)
	return nil
}

// RollbackMode reverts to the previous runtime mode if safe to do so
func (rt *Runtime) RollbackMode() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if len(rt.modeHistory) == 0 {
		return fmt.Errorf("no previous mode available for rollback")
	}

	previousMode := rt.modeHistory[len(rt.modeHistory)-1]

	// Validate the rollback transition
	if !rt.canTransition(rt.mode, previousMode) {
		return fmt.Errorf("cannot rollback from %s to %s: production safety guardrails prevent this transition", rt.mode, previousMode)
	}

	// Remove the last entry from history (we're rolling back past it)
	rt.modeHistory = rt.modeHistory[:len(rt.modeHistory)-1]

	rt.config.Logger.Warn("Runtime mode rollback initiated", "from_mode", rt.mode, "to_mode", previousMode)
	rt.mode = previousMode
	return nil
}

// ModeHistory returns the recent mode transition history
func (rt *Runtime) ModeHistory() []RuntimeMode {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	history := make([]RuntimeMode, len(rt.modeHistory))
	copy(history, rt.modeHistory)
	return history
}

// SetComparisonEvidence sets the CSS comparison evidence for mode transition verification
func (rt *Runtime) SetComparisonEvidence(evidence RuntimeModeComparisonEvidence) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.config.ComparisonEvidence = evidence
}

// UpdateComparisonEvidence updates specific comparison results
func (rt *Runtime) UpdateComparisonEvidence(mode RuntimeMode, results RuntimeComparisonResults) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	switch mode {
	case RuntimeModeCSSProxy:
		rt.config.ComparisonEvidence.CSSProxyBaseline = RuntimeComparisonBaseline{
			RequestCount:   results.RequestCount,
			SuccessRate:    float64(results.BehaviorMatches) / float64(results.RequestCount) * 100,
			AverageLatency: results.TestDuration / time.Duration(results.RequestCount),
			ErrorRate:      float64(results.BehaviorMismatches) / float64(results.RequestCount) * 100,
		}
	case RuntimeModeHybrid:
		rt.config.ComparisonEvidence.HybridComparison = results
	case RuntimeModeNative:
		rt.config.ComparisonEvidence.NativeComparison = results
	default:
		return fmt.Errorf("unknown runtime mode: %s", mode)
	}

	// Update overall comparison passed status
	rt.config.ComparisonEvidence.ComparisonPassed =
		rt.config.ComparisonEvidence.HybridComparison.Passed &&
			rt.config.ComparisonEvidence.NativeComparison.Passed

	rt.config.ComparisonEvidence.LastComparisonTimestamp = time.Now()
	return nil
}

// ClearComparisonEvidence clears all comparison evidence
func (rt *Runtime) ClearComparisonEvidence() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.config.ComparisonEvidence = RuntimeModeComparisonEvidence{
		ComparisonPassed: false,
	}
}

// IsModeTransitionAllowed checks if a mode transition would be allowed without actually performing it
func (rt *Runtime) IsModeTransitionAllowed(to RuntimeMode) bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.canTransition(rt.mode, to)
}

// canTransition checks if a mode transition is allowed with production safety guardrails
func (rt *Runtime) canTransition(from, to RuntimeMode) bool {
	// Always allow staying in the same mode
	if from == to {
		return true
	}

	// Production safety guardrails: prevent unsafe mode transitions
	if rt.config.ProductionMode {
		// In production mode, native and hybrid modes require explicit permission
		switch to {
		case RuntimeModeNative:
			if !rt.config.AllowNativeMode {
				return false
			}
			// If comparison evidence is required, check that it exists and passed
			if rt.config.RequireComparisonEvidence {
				if !rt.config.ComparisonEvidence.ComparisonPassed {
					return false
				}
				// Ensure native comparison has been performed and passed
				if !rt.config.ComparisonEvidence.NativeComparison.Passed {
					return false
				}
			}
		case RuntimeModeHybrid:
			if !rt.config.AllowHybridMode {
				return false
			}
			// If comparison evidence is required, check that it exists and passed
			if rt.config.RequireComparisonEvidence {
				if !rt.config.ComparisonEvidence.ComparisonPassed {
					return false
				}
				// Ensure hybrid comparison has been performed and passed
				if !rt.config.ComparisonEvidence.HybridComparison.Passed {
					return false
				}
			}
		}
	}

	// Define allowed transitions
	allowedTransitions := map[RuntimeMode][]RuntimeMode{
		RuntimeModeCSSProxy: {RuntimeModeHybrid, RuntimeModeNative},
		RuntimeModeHybrid:   {RuntimeModeCSSProxy, RuntimeModeNative},
		RuntimeModeNative:   {RuntimeModeCSSProxy, RuntimeModeHybrid},
	}

	transitions, ok := allowedTransitions[from]
	if !ok {
		return false
	}

	for _, t := range transitions {
		if t == to {
			return true
		}
	}
	return false
}

// IsInitialized returns true if the runtime is initialized
func (rt *Runtime) IsInitialized() bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.initialized
}

// Gateway returns the gateway compatibility layer
func (rt *Runtime) Gateway() *GatewayCompatibilityLayer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.gateway
}

// Storage returns the storage abstraction layer
func (rt *Runtime) Storage() *StorageAbstractionLayer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.storage
}

// Metadata returns the metadata/index layer
func (rt *Runtime) Metadata() *MetadataIndexLayer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.metadata
}

// RDF returns the RDF graph/index layer
func (rt *Runtime) RDF() *RDFGraphIndexLayer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.rdf
}

// PolicyEngine returns the policy engine layer
func (rt *Runtime) PolicyEngine() *PolicyEngineLayer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.policyEngine
}

// ResourceIndex returns the resource index layer
func (rt *Runtime) ResourceIndex() *ResourceIndexLayer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.resourceIndex
}

// EventStream returns the event stream layer
func (rt *Runtime) EventStream() *EventStreamLayer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.eventStream
}

// Notification returns the notification layer
func (rt *Runtime) Notification() *NotificationLayer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.notification
}

// MultiStorage returns the multi-storage layer
func (rt *Runtime) MultiStorage() *MultiStorageLayer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.multiStorage
}

// Migration returns the CSS migration layer
func (rt *Runtime) Migration() *CSSMigrationLayer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.migration
}

// StartMigration starts the CSS migration process
func (rt *Runtime) StartMigration(ctx context.Context) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.migrating {
		return ErrMigrationInProgress
	}

	if !rt.initialized {
		return ErrRuntimeNotInitialized
	}

	rt.migrating = true
	go func() {
		defer func() {
			rt.mu.Lock()
			rt.migrating = false
			rt.mu.Unlock()
		}()

		// Run migration in background
		if err := rt.migration.Run(ctx); err != nil {
			rt.config.Logger.Error("Migration failed", "error", err)
		}
	}()

	return nil
}

// IsMigrating returns true if a migration is in progress
func (rt *Runtime) IsMigrating() bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.migrating
}

// Close cleans up runtime resources
func (rt *Runtime) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if !rt.initialized {
		return nil
	}

	var errors []error

	// Close all layers that need cleanup
	if rt.gateway != nil {
		if err := rt.gateway.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if rt.storage != nil {
		if err := rt.storage.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if rt.metadata != nil {
		if err := rt.metadata.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if rt.rdf != nil {
		if err := rt.rdf.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if rt.policyEngine != nil {
		if err := rt.policyEngine.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if rt.eventStream != nil {
		if err := rt.eventStream.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if rt.resourceIndex != nil {
		if err := rt.resourceIndex.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if rt.notification != nil {
		if err := rt.notification.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if rt.multiStorage != nil {
		if err := rt.multiStorage.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if rt.migration != nil {
		if err := rt.migration.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	rt.initialized = false

	if len(errors) > 0 {
		return fmt.Errorf("errors during runtime close: %v", errors)
	}

	return nil
}
