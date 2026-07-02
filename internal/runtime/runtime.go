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
}

// DefaultRuntimeConfig returns a safe default configuration
func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Mode:                RuntimeModeCSSProxy,
		EnableCSSComparison: true, // Always enabled for safety
		DefaultStorage:      "default",
		Logger:              nil,
		MaxRetries:          3,
		BackoffBaseDelay:    100,  // 100ms
		BackoffMaxDelay:     5000, // 5s
	}
}

// Runtime is the main Solid runtime structure
type Runtime struct {
	mu sync.RWMutex

	config RuntimeConfig
	mode   RuntimeMode

	// Layers
	gateway      *GatewayCompatibilityLayer
	storage      *StorageAbstractionLayer
	metadata     *MetadataIndexLayer
	rdf          *RDFGraphIndexLayer
	policyEngine *PolicyEngineLayer
	notification *NotificationLayer
	multiStorage *MultiStorageLayer
	migration    *CSSMigrationLayer

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

	// Layer 6: Notification/Live-Update Layer
	rt.notification = NewNotificationLayer(NotificationConfig{
		Logger: config.Logger,
	})

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
		return fmt.Errorf("cannot transition from %s to %s", rt.mode, mode)
	}

	rt.mode = mode
	rt.config.Logger.Info("Runtime mode changed", "old_mode", rt.mode, "new_mode", mode)
	return nil
}

// canTransition checks if a mode transition is allowed
func (rt *Runtime) canTransition(from, to RuntimeMode) bool {
	// Always allow staying in the same mode
	if from == to {
		return true
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
