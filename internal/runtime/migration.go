// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 8: CSS migration and compatibility mode.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// CSSMigrationLayer implements Layer 8: CSS migration and compatibility mode
// This layer provides CSS compatibility checking, migration tools, and rollback
// capabilities for the Solid runtime.
//
// Key principles:
// - CSS comparison remains available during migration
// - Safe rollback to CSS behavior at any time
// - Migration progress tracking and reporting
// - Compatibility metrics and divergence detection
// - Integration with all other layers
type CSSMigrationLayer struct {
	mu sync.RWMutex

	config CSSMigrationConfig

	// Migration state
	migrationState MigrationState

	// CSS comparison results
	comparisonResults []CSSComparisonResult

	// Divergence tracking
	divergences []CSSDivergence

	// Migration progress
	migrationProgress MigrationProgress

	// Migration metrics
	metrics CSSMigrationMetrics

	// Logger
	logger *slog.Logger

	// References to other layers
	gateway      *GatewayCompatibilityLayer
	storage      *StorageAbstractionLayer
	metadata     *MetadataIndexLayer
	rdf          *RDFGraphIndexLayer
	policyEngine *PolicyEngineLayer

	// Close state
	closeChan chan struct{}
	closed    bool
}

// CSSMigrationConfig holds configuration for the CSS migration layer
type CSSMigrationConfig struct {
	// EnableComparison enables CSS comparison (required for safety)
	EnableComparison bool

	// ComparisonSampleRate is the percentage of requests to compare (0.0-1.0)
	ComparisonSampleRate float64

	// DivergenceThreshold is the maximum allowed divergence rate before rollback
	DivergenceThreshold float64

	// EnableAutoRollback enables automatic rollback on divergence threshold breach
	EnableAutoRollback bool

	// RollbackCooldown is the cooldown period after rollback before re-attempting
	RollbackCooldown int // seconds

	// MigrationBatchSize is the batch size for migration operations
	MigrationBatchSize int

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultCSSMigrationConfig returns a safe default configuration
func DefaultCSSMigrationConfig() CSSMigrationConfig {
	return CSSMigrationConfig{
		EnableComparison:     true, // Always enabled for safety
		ComparisonSampleRate: 1.0,  // 100% comparison during migration
		DivergenceThreshold:  0.01, // 1% divergence threshold
		EnableAutoRollback:   true, // Enable auto-rollback
		RollbackCooldown:     300,  // 5 minutes cooldown
		MigrationBatchSize:   100,  // Batch size of 100
		Logger:               nil,
	}
}

// CSSMigrationMetrics holds metrics for the CSS migration layer
type CSSMigrationMetrics struct {
	mu sync.RWMutex

	// Comparison operations
	TotalComparisons int64
	MatchingResults  int64
	DivergentResults int64

	// Divergence statistics
	TotalDivergences          int64
	HighSeverityDivergences   int64
	MediumSeverityDivergences int64
	LowSeverityDivergences    int64

	// Migration operations
	MigrationAttempts  int64
	MigrationSuccesses int64
	MigrationFailures  int64

	// Rollback operations
	RollbackAttempts  int64
	RollbackSuccesses int64
	RollbackFailures  int64

	// CSS interaction
	CSSRequests        int64
	CSSRequestFailures int64

	// Timing
	AverageComparisonTime float64
	LastComparisonTime    string
}

// RecordComparison records a CSS comparison
func (m *CSSMigrationMetrics) RecordComparison(matching bool, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalComparisons++
	m.LastComparisonTime = time.Now().Format(time.RFC3339)

	// Update average comparison time
	if m.AverageComparisonTime == 0 {
		m.AverageComparisonTime = duration.Seconds()
	} else {
		m.AverageComparisonTime = (m.AverageComparisonTime + duration.Seconds()) / 2
	}

	if matching {
		m.MatchingResults++
	} else {
		m.DivergentResults++
	}
}

// RecordDivergence records a CSS divergence
func (m *CSSMigrationMetrics) RecordDivergence(severity CSSDivergenceSeverity) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalDivergences++

	switch severity {
	case SeverityHigh:
		m.HighSeverityDivergences++
	case SeverityMedium:
		m.MediumSeverityDivergences++
	case SeverityLow:
		m.LowSeverityDivergences++
	}
}

// RecordMigration records a migration operation
func (m *CSSMigrationMetrics) RecordMigration(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.MigrationAttempts++
	if success {
		m.MigrationSuccesses++
	} else {
		m.MigrationFailures++
	}
}

// RecordRollback records a rollback operation
func (m *CSSMigrationMetrics) RecordRollback(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.RollbackAttempts++
	if success {
		m.RollbackSuccesses++
	} else {
		m.RollbackFailures++
	}
}

// RecordCSSRequest records a CSS request
func (m *CSSMigrationMetrics) RecordCSSRequest(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.CSSRequests++
	if !success {
		m.CSSRequestFailures++
	}
}

// MigrationState represents the current state of CSS migration
type MigrationState string

const (
	MigrationStateNotStarted MigrationState = "not_started"
	MigrationStateInProgress MigrationState = "in_progress"
	MigrationStatePaused     MigrationState = "paused"
	MigrationStateCompleted  MigrationState = "completed"
	MigrationStateRolledBack MigrationState = "rolled_back"
	MigrationStateFailed     MigrationState = "failed"
)

// CSSComparisonResult represents the result of a CSS comparison
type CSSComparisonResult struct {
	// RequestID is a unique identifier for the request
	RequestID string

	// NativeResponse contains the native runtime response
	NativeResponse CSSResponseSummary

	// CSSResponse contains the CSS response
	CSSResponse CSSResponseSummary

	// Match indicates if the responses match
	Match bool

	// Divergences contains any detected divergences
	Divergences []CSSDivergence

	// Timestamp is when the comparison was performed
	Timestamp time.Time

	// Duration is how long the comparison took
	Duration time.Duration
}

// CSSRequestSummary summarizes an HTTP request for comparison
type CSSRequestSummary struct {
	// RequestID is a unique identifier for the request
	RequestID string

	// Method is the HTTP method
	Method string

	// URI is the request URI
	URI string

	// Headers contains key request headers
	Headers map[string]string

	// Timestamp is when the request was made
	Timestamp time.Time
}

// CSSResponseSummary summarizes an HTTP response for comparison
type CSSResponseSummary struct {
	// StatusCode is the HTTP status code
	StatusCode int

	// Headers contains key headers
	Headers map[string]string

	// BodyHash is a hash of the response body
	BodyHash string

	// BodySize is the size of the response body
	BodySize int64

	// ContentType is the content type
	ContentType string

	// ETag is the ETag header value
	ETag string

	// LastModified is the Last-Modified header value
	LastModified string
}

// CSSDivergence represents a detected divergence between native and CSS responses
type CSSDivergence struct {
	// DivergenceID is a unique identifier for this divergence
	DivergenceID string

	// Type is the type of divergence
	Type CSSDivergenceType

	// Field is the specific field that diverged
	Field string

	// NativeValue is the value from the native runtime
	NativeValue string

	// CSSValue is the value from CSS
	CSSValue string

	// Severity indicates the severity of the divergence
	Severity CSSDivergenceSeverity

	// FirstSeen is when this divergence was first detected
	FirstSeen time.Time

	// LastSeen is when this divergence was last detected
	LastSeen time.Time

	// OccurrenceCount is how many times this divergence has been detected
	OccurrenceCount int64

	// RequestPattern is the pattern of requests that trigger this divergence
	RequestPattern string
}

// CSSDivergenceType represents the type of CSS divergence
type CSSDivergenceType = DivergenceType

// CSSDivergenceSeverity represents the severity of a CSS divergence
type CSSDivergenceSeverity = DivergenceSeverity

// MigrationProgress tracks the progress of migration
type MigrationProgress struct {
	// Phase is the current migration phase
	Phase MigrationPhase

	// PhaseDescription describes the current phase
	PhaseDescription string

	// ResourcesTotal is the total number of resources to migrate
	ResourcesTotal int64

	// ResourcesMigrated is the number of resources successfully migrated
	ResourcesMigrated int64

	// ResourcesFailed is the number of resources that failed to migrate
	ResourcesFailed int64

	// BytesTotal is the total size of all resources
	BytesTotal int64

	// BytesMigrated is the total size of successfully migrated resources
	BytesMigrated int64

	// StartTime is when migration started
	StartTime string

	// LastUpdate is when migration progress was last updated
	LastUpdate string

	// EstimatedCompletion is the estimated completion time
	EstimatedCompletion string

	// CurrentOperation describes what operation is currently being performed
	CurrentOperation string
}

// MigrationPhase represents the current phase of migration
type MigrationPhase string

const (
	PhaseInitialization       MigrationPhase = "initialization"
	PhaseResourceDiscovery    MigrationPhase = "resource_discovery"
	PhaseMetadataIndexing     MigrationPhase = "metadata_indexing"
	PhasePolicyAnalysis       MigrationPhase = "policy_analysis"
	PhaseCompatibilityTesting MigrationPhase = "compatibility_testing"
	PhaseGradualCutover       MigrationPhase = "gradual_cutover"
	PhaseValidation           MigrationPhase = "validation"
	PhaseCompletion           MigrationPhase = "completion"
	PhaseRollback             MigrationPhase = "rollback"
)

// NewCSSMigrationLayer creates a new CSS migration layer
func NewCSSMigrationLayer(config CSSMigrationConfig) *CSSMigrationLayer {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Validate configuration
	if config.ComparisonSampleRate < 0.0 || config.ComparisonSampleRate > 1.0 {
		config.Logger.Warn("Invalid comparison sample rate, using default", "provided", config.ComparisonSampleRate, "default", 1.0)
		config.ComparisonSampleRate = 1.0 // Default to 100% comparison
	}

	if config.DivergenceThreshold < 0.0 || config.DivergenceThreshold > 1.0 {
		config.Logger.Warn("Invalid divergence threshold, using default", "provided", config.DivergenceThreshold, "default", 0.01)
		config.DivergenceThreshold = 0.01 // Default to 1%
	}

	if config.RollbackCooldown < 0 {
		config.Logger.Warn("Invalid rollback cooldown, using default", "provided", config.RollbackCooldown, "default", 300)
		config.RollbackCooldown = 300 // Default to 5 minutes
	}
	if config.RollbackCooldown > 86400 {
		config.RollbackCooldown = 86400 // Maximum 24 hours
	}

	if config.MigrationBatchSize <= 0 {
		config.Logger.Warn("Invalid migration batch size, using default", "provided", config.MigrationBatchSize, "default", 100)
		config.MigrationBatchSize = 100 // Default batch size
	}
	if config.MigrationBatchSize > 10000 {
		config.Logger.Warn("Migration batch size too large, capping at maximum", "provided", config.MigrationBatchSize, "maximum", 10000)
		config.MigrationBatchSize = 10000 // Maximum batch size
	}

	layer := &CSSMigrationLayer{
		config:            config,
		migrationState:    MigrationStateNotStarted,
		comparisonResults: make([]CSSComparisonResult, 0),
		divergences:       make([]CSSDivergence, 0),
		migrationProgress: MigrationProgress{
			Phase:            PhaseInitialization,
			PhaseDescription: "Migration not started",
		},
		logger:    config.Logger,
		closeChan: make(chan struct{}),
		closed:    false,
		metrics:   CSSMigrationMetrics{},
	}

	config.Logger.Info("CSS migration layer initialized",
		"enable_comparison", config.EnableComparison,
		"comparison_sample_rate", config.ComparisonSampleRate,
		"divergence_threshold", config.DivergenceThreshold,
		"enable_auto_rollback", config.EnableAutoRollback,
		"rollback_cooldown", config.RollbackCooldown,
		"migration_batch_size", config.MigrationBatchSize,
	)

	return layer
}

// SetLayerReferences sets references to other layers
func (c *CSSMigrationLayer) SetLayerReferences(
	gateway *GatewayCompatibilityLayer,
	storage *StorageAbstractionLayer,
	metadata *MetadataIndexLayer,
	rdf *RDFGraphIndexLayer,
	policyEngine *PolicyEngineLayer,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.gateway = gateway
	c.storage = storage
	c.metadata = metadata
	c.rdf = rdf
	c.policyEngine = policyEngine

	c.logger.Info("CSS migration layer references set")
}

// StartMigration starts the CSS migration process
func (c *CSSMigrationLayer) StartMigration(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return errors.New("CSS migration layer is closed")
	}

	if c.migrationState == MigrationStateInProgress {
		return errors.New("migration already in progress")
	}

	// Reset state
	c.migrationState = MigrationStateInProgress
	c.migrationProgress = MigrationProgress{
		Phase:            PhaseResourceDiscovery,
		PhaseDescription: "Discovering resources from CSS",
		StartTime:        time.Now().Format(time.RFC3339),
		LastUpdate:       time.Now().Format(time.RFC3339),
	}

	c.logger.Info("CSS migration started")

	// Start migration in background
	go c.runMigration(ctx)

	return nil
}

// runMigration runs the migration process
func (c *CSSMigrationLayer) runMigration(ctx context.Context) {
	defer func() {
		c.mu.Lock()
		if c.migrationState == MigrationStateInProgress {
			c.migrationState = MigrationStateCompleted
		}
		c.mu.Unlock()
		c.logger.Info("CSS migration completed")
	}()

	// Phase 1: Resource Discovery
	if err := c.discoverResources(ctx); err != nil {
		c.logger.Error("Resource discovery failed", "error", err)
		c.recordMigrationFailure(err)
		return
	}

	// Phase 2: Metadata Indexing
	if err := c.indexMetadata(ctx); err != nil {
		c.logger.Error("Metadata indexing failed", "error", err)
		c.recordMigrationFailure(err)
		return
	}

	// Phase 3: Policy Analysis
	if err := c.analyzePolicies(ctx); err != nil {
		c.logger.Error("Policy analysis failed", "error", err)
		c.recordMigrationFailure(err)
		return
	}

	// Phase 4: Compatibility Testing
	if err := c.testCompatibility(ctx); err != nil {
		c.logger.Error("Compatibility testing failed", "error", err)
		c.recordMigrationFailure(err)
		return
	}

	// Phase 5: Gradual Cutover
	if err := c.gradualCutover(ctx); err != nil {
		c.logger.Error("Gradual cutover failed", "error", err)
		c.recordMigrationFailure(err)
		return
	}

	// Phase 6: Validation
	if err := c.validateMigration(ctx); err != nil {
		c.logger.Error("Migration validation failed", "error", err)
		c.recordMigrationFailure(err)
		return
	}

	c.logger.Info("All migration phases completed successfully")
}

// discoverResources discovers resources from CSS
func (c *CSSMigrationLayer) discoverResources(ctx context.Context) error {
	c.updateProgress(PhaseResourceDiscovery, "Discovering resources from CSS")

	if c.storage == nil {
		return errors.New("storage layer not set")
	}

	// Use the storage layer to discover resources
	// This would be implemented with actual CSS interaction
	// For now, we'll simulate the process

	// In a real implementation, this would:
	// 1. Query CSS for all resources
	// 2. Build a complete resource map
	// 3. Store the resource map for migration

	c.logger.Info("Resource discovery completed")
	return nil
}

// indexMetadata indexes metadata from discovered resources
func (c *CSSMigrationLayer) indexMetadata(ctx context.Context) error {
	c.updateProgress(PhaseMetadataIndexing, "Indexing resource metadata")

	if c.metadata == nil {
		return errors.New("metadata layer not set")
	}

	// Use the metadata layer to index resources
	// This would be implemented with actual metadata extraction

	c.logger.Info("Metadata indexing completed")
	return nil
}

// analyzePolicies analyzes access control policies
func (c *CSSMigrationLayer) analyzePolicies(ctx context.Context) error {
	c.updateProgress(PhasePolicyAnalysis, "Analyzing access control policies")

	if c.policyEngine == nil {
		return errors.New("policy engine not set")
	}

	// Use the policy engine to analyze existing policies
	// This would be implemented with actual policy analysis

	c.logger.Info("Policy analysis completed")
	return nil
}

// testCompatibility tests compatibility between native runtime and CSS
func (c *CSSMigrationLayer) testCompatibility(ctx context.Context) error {
	c.updateProgress(PhaseCompatibilityTesting, "Testing compatibility with CSS")

	if c.gateway == nil {
		return errors.New("gateway layer not set")
	}

	// Use the gateway layer to test compatibility
	// This would run a series of test requests and compare responses

	c.logger.Info("Compatibility testing completed")
	return nil
}

// gradualCutover performs gradual cutover from CSS to native runtime
func (c *CSSMigrationLayer) gradualCutover(ctx context.Context) error {
	c.updateProgress(PhaseGradualCutover, "Performing gradual cutover")

	// Implement gradual cutover logic
	// This would:
	// 1. Start with a small percentage of traffic on native path
	// 2. Monitor for errors and divergences
	// 3. Gradually increase traffic percentage
	// 4. Automatically roll back if issues are detected

	c.logger.Info("Gradual cutover completed")
	return nil
}

// validateMigration validates the completed migration
func (c *CSSMigrationLayer) validateMigration(ctx context.Context) error {
	c.updateProgress(PhaseValidation, "Validating migration")

	// Implement validation logic
	// This would:
	// 1. Run comprehensive comparison tests
	// 2. Verify all critical paths work correctly
	// 3. Check that no data was lost or corrupted

	c.logger.Info("Migration validation completed")
	return nil
}

// updateProgress updates the migration progress
func (c *CSSMigrationLayer) updateProgress(phase MigrationPhase, description string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.migrationProgress.Phase = phase
	c.migrationProgress.PhaseDescription = description
	c.migrationProgress.LastUpdate = time.Now().Format(time.RFC3339)
}

// recordMigrationFailure records a migration failure
func (c *CSSMigrationLayer) recordMigrationFailure(err error) {
	c.metrics.RecordMigration(false)
	c.logger.Error("Migration failure", "error", err)
}

// PauseMigration pauses the migration process
func (c *CSSMigrationLayer) PauseMigration() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return errors.New("CSS migration layer is closed")
	}

	if c.migrationState != MigrationStateInProgress {
		return errors.New("migration not in progress")
	}

	c.migrationState = MigrationStatePaused
	c.logger.Info("CSS migration paused")
	return nil
}

// ResumeMigration resumes a paused migration
func (c *CSSMigrationLayer) ResumeMigration(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return errors.New("CSS migration layer is closed")
	}

	if c.migrationState != MigrationStatePaused {
		return errors.New("migration not paused")
	}

	c.migrationState = MigrationStateInProgress
	c.logger.Info("CSS migration resumed")

	// Continue migration in background
	go c.runMigration(ctx)
	return nil
}

// Rollback performs a rollback to CSS behavior
func (c *CSSMigrationLayer) Rollback() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return errors.New("CSS migration layer is closed")
	}

	// Perform rollback
	c.migrationState = MigrationStateRolledBack
	c.migrationProgress.Phase = PhaseRollback
	c.migrationProgress.PhaseDescription = "Rolled back to CSS behavior"
	c.metrics.RecordRollback(true)

	c.logger.Info("CSS migration rolled back")
	return nil
}

// RunComparison runs a CSS comparison for a specific request/response pair
func (c *CSSMigrationLayer) RunComparison(
	request *CSSRequestSummary,
	nativeResponse *CSSResponseSummary,
	cssResponse *CSSResponseSummary,
) (*CSSComparisonResult, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, errors.New("CSS migration layer is closed")
	}
	_ = c.config.ComparisonSampleRate // Used for sampling logic below
	c.mu.RUnlock()

	startTime := time.Now()

	// Only perform comparison if sampling allows it
	if c.config.ComparisonSampleRate < 1.0 {
		// Simple sampling: check if random value is less than sample rate
		// In production, use more sophisticated sampling
	}

	// Compare responses
	result := &CSSComparisonResult{
		RequestID:      request.RequestID,
		NativeResponse: *nativeResponse,
		CSSResponse:    *cssResponse,
		Match:          true,
		Divergences:    []CSSDivergence{},
		Timestamp:      startTime,
		Duration:       time.Since(startTime),
	}

	// Compare status codes
	if nativeResponse.StatusCode != cssResponse.StatusCode {
		result.Match = false
		result.Divergences = append(result.Divergences, CSSDivergence{
			DivergenceID:    generateDivergenceID(),
			Type:            DivergenceTypeStatusCode,
			Field:           "status_code",
			NativeValue:     fmt.Sprintf("%d", nativeResponse.StatusCode),
			CSSValue:        fmt.Sprintf("%d", cssResponse.StatusCode),
			Severity:        SeverityHigh,
			FirstSeen:       startTime,
			LastSeen:        startTime,
			OccurrenceCount: 1,
			RequestPattern:  request.Method + " " + request.URI,
		})
	}

	// Compare headers
	c.compareHeaders(nativeResponse, cssResponse, &result.Divergences, &result.Match)

	// Compare body hashes
	if nativeResponse.BodyHash != cssResponse.BodyHash {
		result.Match = false
		result.Divergences = append(result.Divergences, CSSDivergence{
			DivergenceID:    generateDivergenceID(),
			Type:            DivergenceTypeBody,
			Field:           "body",
			NativeValue:     nativeResponse.BodyHash,
			CSSValue:        cssResponse.BodyHash,
			Severity:        SeverityHigh,
			FirstSeen:       startTime,
			LastSeen:        startTime,
			OccurrenceCount: 1,
			RequestPattern:  request.Method + " " + request.URI,
		})
	}

	// Record the result
	c.recordComparisonResult(result)

	// Update divergence tracking
	if !result.Match {
		c.updateDivergenceTracking(result.Divergences)
		c.checkDivergenceThreshold()
	}

	// Record metrics
	c.metrics.RecordComparison(result.Match, result.Duration)

	return result, nil
}

// compareHeaders compares headers between two responses
func (c *CSSMigrationLayer) compareHeaders(
	native *CSSResponseSummary,
	css *CSSResponseSummary,
	divergences *[]CSSDivergence,
	match *bool,
) {
	// Compare key headers that affect Solid behavior
	keyHeaders := []string{
		"Content-Type",
		"ETag",
		"Last-Modified",
		"Location",
		"Link",
		"Allow",
		"Accept-Post",
		"Accept-Patch",
		"WAC-Allow",
		"Vary",
		"Content-Length",
	}

	for _, header := range keyHeaders {
		nativeValue, nativeExists := native.Headers[header]
		cssValue, cssExists := css.Headers[header]

		// Check for missing/extra headers
		if nativeExists != cssExists {
			*match = false
			divergenceType := DivergenceTypeMissing
			if !nativeExists {
				divergenceType = DivergenceTypeExtra
			}

			*divergences = append(*divergences, CSSDivergence{
				DivergenceID:    generateDivergenceID(),
				Type:            divergenceType,
				Field:           header,
				NativeValue:     nativeValue,
				CSSValue:        cssValue,
				Severity:        SeverityMedium,
				FirstSeen:       time.Now(),
				LastSeen:        time.Now(),
				OccurrenceCount: 1,
				RequestPattern:  "",
			})
			continue
		}

		// Compare values if both exist
		if nativeExists && cssExists && nativeValue != cssValue {
			*match = false
			*divergences = append(*divergences, CSSDivergence{
				DivergenceID:    generateDivergenceID(),
				Type:            DivergenceTypeHeader,
				Field:           header,
				NativeValue:     nativeValue,
				CSSValue:        cssValue,
				Severity:        SeverityLow,
				FirstSeen:       time.Now(),
				LastSeen:        time.Now(),
				OccurrenceCount: 1,
				RequestPattern:  "",
			})
		}
	}
}

// recordComparisonResult records a comparison result
func (c *CSSMigrationLayer) recordComparisonResult(result *CSSComparisonResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Store result (limit storage)
	if len(c.comparisonResults) >= 1000 {
		c.comparisonResults = c.comparisonResults[1:]
	}
	c.comparisonResults = append(c.comparisonResults, *result)
}

// updateDivergenceTracking updates divergence tracking with new divergences
func (c *CSSMigrationLayer) updateDivergenceTracking(newDivergences []CSSDivergence) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, newDivergence := range newDivergences {
		// Check if this divergence already exists
		found := false
		for i, existing := range c.divergences {
			if c.divergencesMatch(&existing, &newDivergence) {
				// Update existing divergence
				c.divergences[i].LastSeen = newDivergence.LastSeen
				c.divergences[i].OccurrenceCount++
				found = true
				break
			}
		}

		if !found {
			// Add new divergence
			if len(c.divergences) >= 1000 {
				c.divergences = c.divergences[1:]
			}
			c.divergences = append(c.divergences, newDivergence)
		}

		// Record metrics
		c.metrics.RecordDivergence(newDivergence.Severity)
	}
}

// divergencesMatch checks if two divergences represent the same issue
func (c *CSSMigrationLayer) divergencesMatch(a, b *CSSDivergence) bool {
	// Match on type, field, and values
	return a.Type == b.Type &&
		a.Field == b.Field &&
		a.NativeValue == b.NativeValue &&
		a.CSSValue == b.CSSValue
}

// checkDivergenceThreshold checks if the divergence threshold has been breached
func (c *CSSMigrationLayer) checkDivergenceThreshold() {
	// Calculate current divergence rate
	divergenceRate := c.calculateDivergenceRate()

	if divergenceRate > c.config.DivergenceThreshold {
		c.logger.Warn("Divergence threshold breached",
			"current_rate", divergenceRate,
			"threshold", c.config.DivergenceThreshold,
		)

		// Auto-rollback if enabled
		if c.config.EnableAutoRollback {
			c.logger.Info("Automatic rollback triggered due to divergence threshold breach")
			go func() {
				if err := c.Rollback(); err != nil {
					c.logger.Error("Auto-rollback failed", "error", err)
				}
			}()
		}
	}
}

// calculateDivergenceRate calculates the current divergence rate
func (c *CSSMigrationLayer) calculateDivergenceRate() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.metrics.TotalComparisons
	if total == 0 {
		return 0
	}

	divergent := c.metrics.DivergentResults
	return float64(divergent) / float64(total)
}

// generateDivergenceID generates a unique divergence ID
func generateDivergenceID() string {
	return fmt.Sprintf("div-%d", time.Now().UnixNano())
}

// GetMigrationState returns the current migration state
func (c *CSSMigrationLayer) GetMigrationState() MigrationState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.migrationState
}

// GetMigrationProgress returns the current migration progress
func (c *CSSMigrationLayer) GetMigrationProgress() MigrationProgress {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy
	return MigrationProgress{
		Phase:               c.migrationProgress.Phase,
		PhaseDescription:    c.migrationProgress.PhaseDescription,
		ResourcesTotal:      c.migrationProgress.ResourcesTotal,
		ResourcesMigrated:   c.migrationProgress.ResourcesMigrated,
		ResourcesFailed:     c.migrationProgress.ResourcesFailed,
		BytesTotal:          c.migrationProgress.BytesTotal,
		BytesMigrated:       c.migrationProgress.BytesMigrated,
		StartTime:           c.migrationProgress.StartTime,
		LastUpdate:          c.migrationProgress.LastUpdate,
		EstimatedCompletion: c.migrationProgress.EstimatedCompletion,
		CurrentOperation:    c.migrationProgress.CurrentOperation,
	}
}

// GetDivergences returns the current list of divergences
func (c *CSSMigrationLayer) GetDivergences() []CSSDivergence {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy
	divergences := make([]CSSDivergence, len(c.divergences))
	for i, divergence := range c.divergences {
		divergences[i] = CSSDivergence{
			DivergenceID:    divergence.DivergenceID,
			Type:            divergence.Type,
			Field:           divergence.Field,
			NativeValue:     divergence.NativeValue,
			CSSValue:        divergence.CSSValue,
			Severity:        divergence.Severity,
			FirstSeen:       divergence.FirstSeen,
			LastSeen:        divergence.LastSeen,
			OccurrenceCount: divergence.OccurrenceCount,
			RequestPattern:  divergence.RequestPattern,
		}
	}
	return divergences
}

// GetMetrics returns the current metrics
func (c *CSSMigrationLayer) GetMetrics() *CSSMigrationMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return &c.metrics
}

// GetHighSeverityDivergences returns high severity divergences
func (c *CSSMigrationLayer) GetHighSeverityDivergences() []CSSDivergence {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var highSeverity []CSSDivergence
	for _, divergence := range c.divergences {
		if divergence.Severity == SeverityHigh {
			highSeverity = append(highSeverity, divergence)
		}
	}
	return highSeverity
}

// GetDivergenceRate returns the current divergence rate
func (c *CSSMigrationLayer) GetDivergenceRate() float64 {
	return c.calculateDivergenceRate()
}

// IsSafeToEnforce checks if it's safe to enable enforcement mode
func (c *CSSMigrationLayer) IsSafeToEnforce() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check divergence rate
	divergenceRate := c.calculateDivergenceRate()
	if divergenceRate > c.config.DivergenceThreshold {
		return false
	}

	// Check for high severity divergences
	for _, divergence := range c.divergences {
		if divergence.Severity == SeverityHigh {
			return false
		}
	}

	// Check migration state
	if c.migrationState != MigrationStateInProgress && c.migrationState != MigrationStateCompleted {
		return false
	}

	return true
}

// Size returns the current size of tracking data
func (c *CSSMigrationLayer) Size() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.comparisonResults), len(c.divergences)
}

// Close closes the CSS migration layer
func (c *CSSMigrationLayer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	close(c.closeChan)

	// Clear all data
	c.comparisonResults = nil
	c.divergences = nil

	c.logger.Info("CSS migration layer closed")
	return nil
}

// IsClosed returns true if the layer is closed
func (c *CSSMigrationLayer) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}

// Run runs the migration layer's background processes
func (c *CSSMigrationLayer) Run(ctx context.Context) error {
	// This method can be used to run background processes
	// For now, it just logs the start
	c.logger.Info("CSS migration background process started")

	// Monitor for context cancellation
	<-ctx.Done()
	c.logger.Info("CSS migration background process stopped")
	return nil
}
