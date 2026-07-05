// Package migration provides tools for migrating from CSS-backed deployments to native runtime.
// This file implements Layer 9: Migration tooling for Phase 25.
package migration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrMigrationAlreadyInProgress is returned when a migration is already running
var ErrMigrationAlreadyInProgress = errors.New("migration already in progress")

// ErrMigrationNotStarted is returned when migration hasn't been started
var ErrMigrationNotStarted = errors.New("migration not started")

// ErrMigrationPaused is returned when migration is paused
var ErrMigrationPaused = errors.New("migration paused")

// ErrMigrationCompleted is returned when migration has already completed
var ErrMigrationCompleted = errors.New("migration already completed")

// ErrMigrationFailed is returned when migration has failed
var ErrMigrationFailed = errors.New("migration failed")

// ErrDryRunMode is returned when attempting destructive operations in dry-run mode
var ErrDryRunMode = errors.New("operation not allowed in dry-run mode")

// ErrRollbackNotAvailable is returned when rollback is not available
var ErrRollbackNotAvailable = errors.New("rollback not available")

// MigrationState represents the current state of a migration job
type MigrationState string

const (
	MigrationStateCreated    MigrationState = "created"
	MigrationStateScanning   MigrationState = "scanning"
	MigrationStateExporting  MigrationState = "exporting"
	MigrationStateAnalyzing  MigrationState = "analyzing"
	MigrationStateImporting  MigrationState = "importing"
	MigrationStateVerifying  MigrationState = "verifying"
	MigrationStatePaused     MigrationState = "paused"
	MigrationStateCompleted  MigrationState = "completed"
	MigrationStateFailed     MigrationState = "failed"
	MigrationStateRolledBack MigrationState = "rolled_back"
)

// MigrationMode represents the migration execution mode
type MigrationMode string

const (
	MigrationModeDryRun MigrationMode = "dry_run"
	MigrationModeLive   MigrationMode = "live"
)

// MigrationConfig holds configuration for a migration job
type MigrationConfig struct {
	// CSSEndpoint is the URL of the CSS server to migrate from
	CSSEndpoint string

	// TargetStorageConfig is the configuration for the target native storage
	TargetStorageConfig string

	// Mode is the migration mode (dry_run or live)
	Mode MigrationMode

	// BatchSize is the number of resources to process in each batch
	BatchSize int

	// MaxConcurrentBatches is the maximum number of concurrent batches
	MaxConcurrentBatches int

	// EnableChecksumVerification enables checksum verification of migrated resources
	EnableChecksumVerification bool

	// EnablePolicyComparison enables policy comparison between CSS and native
	EnablePolicyComparison bool

	// EnableIdentityMapping enables identity/issuer mapping checks
	EnableIdentityMapping bool

	// CreateBackup enables automatic backup creation before destructive steps
	CreateBackup bool

	// BackupDirectory is the directory to store backups
	BackupDirectory string

	// TemporaryDirectory is the directory for temporary migration files
	TemporaryDirectory string

	// LogLevel is the logging level for migration operations
	LogLevel slog.Level

	// Timeout is the timeout for individual migration operations
	Timeout time.Duration

	// RetryCount is the number of retries for failed operations
	RetryCount int

	// RetryDelay is the delay between retries
	RetryDelay time.Duration

	// Logger is the logger for migration operations
	Logger *slog.Logger
}

// DefaultMigrationConfig returns a safe default configuration
func DefaultMigrationConfig() MigrationConfig {
	return MigrationConfig{
		CSSEndpoint:                "http://localhost:3000",
		TargetStorageConfig:        "",
		Mode:                       MigrationModeDryRun,
		BatchSize:                  100,
		MaxConcurrentBatches:       4,
		EnableChecksumVerification: true,
		EnablePolicyComparison:     true,
		EnableIdentityMapping:      true,
		CreateBackup:               true,
		BackupDirectory:            "/var/backups/solid-migration",
		TemporaryDirectory:         "/tmp/solid-migration",
		LogLevel:                   slog.LevelInfo,
		Timeout:                    5 * time.Minute,
		RetryCount:                 3,
		RetryDelay:                 1 * time.Second,
		Logger:                     nil,
	}
}

// MigrationJob represents a migration job from CSS to native runtime
type MigrationJob struct {
	mu sync.RWMutex

	// JobID is a unique identifier for this migration job
	JobID string

	// Config is the configuration for this migration
	Config MigrationConfig

	// State is the current state of the migration
	State MigrationState

	// StartTime is when the migration started
	StartTime time.Time

	// EndTime is when the migration completed or failed
	EndTime time.Time

	// Inventory is the CSS inventory discovered during scanning
	Inventory *CSSInventory

	// ExportReport contains the results of the export phase
	ExportReport *ExportReport

	// AnalysisReport contains the results of the analysis phase
	AnalysisReport *AnalysisReport

	// ImportReport contains the results of the import phase
	ImportReport *ImportReport

	// VerificationReport contains the results of the verification phase
	VerificationReport *VerificationReport

	// RollbackPlan contains the rollback plan for this migration
	RollbackPlan *RollbackPlan

	// Errors contains any errors that occurred during migration
	Errors []MigrationError

	// Progress tracks the current progress of the migration
	Progress MigrationProgress

	// Logger is the logger for this job
	Logger *slog.Logger

	// Context for cancellation
	Context context.Context
	Cancel  context.CancelFunc

	// Close channel
	closeChan chan struct{}
	closed    bool
}

// MigrationProgress tracks the progress of a migration
type MigrationProgress struct {
	// CurrentPhase is the current phase of migration
	CurrentPhase MigrationPhase

	// PhaseDescription describes the current phase
	PhaseDescription string

	// ResourcesTotal is the total number of resources to migrate
	ResourcesTotal int64

	// ResourcesScanned is the number of resources scanned
	ResourcesScanned int64

	// ResourcesExported is the number of resources exported
	ResourcesExported int64

	// ResourcesAnalyzed is the number of resources analyzed
	ResourcesAnalyzed int64

	// ResourcesImported is the number of resources imported
	ResourcesImported int64

	// ResourcesVerified is the number of resources verified
	ResourcesVerified int64

	// ResourcesFailed is the number of resources that failed
	ResourcesFailed int64

	// BytesTotal is the total size in bytes
	BytesTotal int64

	// BytesProcessed is the total bytes processed
	BytesProcessed int64

	// StartTime is when the current phase started
	PhaseStartTime time.Time

	// EstimatedCompletion is the estimated completion time
	EstimatedCompletion string
}

// MigrationPhase represents the current phase of migration
type MigrationPhase string

const (
	PhaseInitialization       MigrationPhase = "initialization"
	PhaseCSSConnectionCheck   MigrationPhase = "css_connection_check"
	PhaseResourceDiscovery    MigrationPhase = "resource_discovery"
	PhaseContainerDiscovery   MigrationPhase = "container_discovery"
	PhaseAuxiliaryDiscovery   MigrationPhase = "auxiliary_discovery"
	PhaseACLDiscovery         MigrationPhase = "acl_discovery"
	PhaseACPDiscovery         MigrationPhase = "acp_discovery"
	PhaseMetadataDiscovery    MigrationPhase = "metadata_discovery"
	PhaseStorageDescription   MigrationPhase = "storage_description"
	PhaseExport               MigrationPhase = "export"
	PhaseChecksumVerification MigrationPhase = "checksum_verification"
	PhasePolicyComparison     MigrationPhase = "policy_comparison"
	PhaseIdentityMapping      MigrationPhase = "identity_mapping"
	PhaseImport               MigrationPhase = "import"
	PhaseValidation           MigrationPhase = "validation"
	PhaseBackup               MigrationPhase = "backup"
	PhaseCleanup              MigrationPhase = "cleanup"
	PhaseAnalysis             MigrationPhase = "analysis"
	PhaseVerification         MigrationPhase = "verification"
)

// MigrationError represents an error that occurred during migration
type MigrationError struct {
	// ErrorID is a unique identifier for this error
	ErrorID string

	// Timestamp is when the error occurred
	Timestamp time.Time

	// Phase is the phase during which the error occurred
	Phase MigrationPhase

	// ResourceURI is the URI of the resource being processed (if applicable)
	ResourceURI string

	// Error is the underlying error
	Error error

	// Severity indicates the severity of the error
	Severity ErrorSeverity

	// Retryable indicates if this error can be retried
	Retryable bool

	// RetryCount is the number of times this error has been retried
	RetryCount int
}

// ErrorSeverity represents the severity of a migration error
type ErrorSeverity string

const (
	SeverityLow    ErrorSeverity = "low"
	SeverityMedium ErrorSeverity = "medium"
	SeverityHigh   ErrorSeverity = "high"
	SeverityFatal  ErrorSeverity = "fatal"
)

// NewMigrationService creates a new migration service
func NewMigrationService(config MigrationConfig) *MigrationService {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	service := &MigrationService{
		config:    config,
		jobs:      make(map[string]*MigrationJob),
		logger:    config.Logger,
		closeChan: make(chan struct{}),
		closed:    false,
		metrics:   MigrationServiceMetrics{},
	}

	// Validate configuration
	if err := service.validateConfig(); err != nil {
		config.Logger.Warn("Invalid migration configuration", "error", err)
	}

	config.Logger.Info("Migration service created",
		"css_endpoint", config.CSSEndpoint,
		"mode", config.Mode,
		"batch_size", config.BatchSize,
		"max_concurrent_batches", config.MaxConcurrentBatches,
	)

	return service
}

// MigrationService provides migration functionality from CSS to native runtime
type MigrationService struct {
	mu sync.RWMutex

	// Config is the default configuration for migration jobs
	config MigrationConfig

	// Jobs are the current migration jobs
	jobs map[string]*MigrationJob

	// Logger is the logger for the service
	logger *slog.Logger

	// Metrics tracks service-level metrics
	metrics MigrationServiceMetrics

	// Close state
	closeChan chan struct{}
	closed    bool
}

// MigrationServiceMetrics holds metrics for the migration service
type MigrationServiceMetrics struct {
	mu sync.RWMutex

	// Job metrics
	JobsCreated   int64
	JobsCompleted int64
	JobsFailed    int64
	JobsCancelled int64

	// Resource metrics
	TotalResourcesDiscovered int64
	TotalResourcesMigrated   int64
	TotalResourcesFailed     int64

	// Phase metrics
	PhaseDurations map[MigrationPhase]time.Duration

	// Error metrics
	ErrorsBySeverity map[ErrorSeverity]int64
	ErrorsByPhase    map[MigrationPhase]int64

	// Timing
	AverageJobDuration  time.Duration
	LongestJobDuration  time.Duration
	ShortestJobDuration time.Duration
}

// validateConfig validates the migration service configuration
func (s *MigrationService) validateConfig() error {
	if s.config.CSSEndpoint == "" {
		return errors.New("CSS endpoint cannot be empty")
	}

	// Validate CSS endpoint URL
	if !strings.HasPrefix(s.config.CSSEndpoint, "http://") &&
		!strings.HasPrefix(s.config.CSSEndpoint, "https://") {
		return errors.New("CSS endpoint must be a valid HTTP/HTTPS URL")
	}

	if s.config.BatchSize <= 0 {
		return errors.New("batch size must be positive")
	}

	if s.config.BatchSize > 10000 {
		return errors.New("batch size cannot exceed 10000")
	}

	if s.config.MaxConcurrentBatches <= 0 {
		return errors.New("max concurrent batches must be positive")
	}

	if s.config.MaxConcurrentBatches > 16 {
		return errors.New("max concurrent batches cannot exceed 16")
	}

	if s.config.RetryCount < 0 {
		return errors.New("retry count cannot be negative")
	}

	if s.config.RetryCount > 10 {
		return errors.New("retry count cannot exceed 10")
	}

	if s.config.RetryDelay < 0 {
		return errors.New("retry delay cannot be negative")
	}

	if s.config.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	// Validate paths
	if s.config.CreateBackup {
		if err := validateDirectoryPath(s.config.BackupDirectory); err != nil {
			return fmt.Errorf("invalid backup directory: %w", err)
		}
	}

	if err := validateDirectoryPath(s.config.TemporaryDirectory); err != nil {
		return fmt.Errorf("invalid temporary directory: %w", err)
	}

	return nil
}

// validateDirectoryPath validates a directory path for security
func validateDirectoryPath(path string) error {
	if path == "" {
		return errors.New("path cannot be empty")
	}

	// Clean the path to prevent directory traversal
	cleaned := filepath.Clean(path)

	// Check for suspicious patterns
	if strings.Contains(cleaned, "..") ||
		strings.HasPrefix(cleaned, "/dev/") ||
		strings.HasPrefix(cleaned, "/proc/") ||
		strings.HasPrefix(cleaned, "/sys/") {
		return errors.New("path contains suspicious patterns")
	}

	// Ensure the path is within allowed locations
	if filepath.IsAbs(cleaned) {
		allowedPrefixes := []string{
			"/var/", "/opt/", "/tmp/", "/home/",
			"/mnt/", "/srv/", "/data/",
		}
		isAllowed := false
		for _, prefix := range allowedPrefixes {
			if strings.HasPrefix(cleaned, prefix) {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return errors.New("path must be in an allowed location")
		}
	}

	return nil
}

// CreateMigrationJob creates a new migration job
func (s *MigrationService) CreateMigrationJob(config MigrationConfig) (*MigrationJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errors.New("migration service is closed")
	}

	// Validate configuration
	if err := s.validateMigrationConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Generate unique job ID
	jobID := s.generateJobID()

	// Create job context
	ctx, cancel := context.WithCancel(context.Background())

	// Create the migration job
	job := &MigrationJob{
		JobID:     jobID,
		Config:    config,
		State:     MigrationStateCreated,
		StartTime: time.Now().UTC(),
		Progress: MigrationProgress{
			CurrentPhase:     PhaseInitialization,
			PhaseDescription: "Job created, ready to start",
			PhaseStartTime:   time.Now().UTC(),
		},
		Logger:    config.Logger,
		Context:   ctx,
		Cancel:    cancel,
		closeChan: make(chan struct{}),
		closed:    false,
	}

	// Store the job
	s.jobs[jobID] = job

	s.metrics.RecordJobCreated()
	s.logger.Info("Migration job created",
		"job_id", jobID,
		"css_endpoint", config.CSSEndpoint,
		"mode", config.Mode,
	)

	return job, nil
}

// validateMigrationConfig validates a migration job configuration
func (s *MigrationService) validateMigrationConfig(config *MigrationConfig) error {
	// Use the service-level validation
	if config.CSSEndpoint == "" {
		config.CSSEndpoint = s.config.CSSEndpoint
	}

	if config.Mode == "" {
		config.Mode = s.config.Mode
	}

	if config.BatchSize <= 0 {
		config.BatchSize = s.config.BatchSize
	}

	if config.MaxConcurrentBatches <= 0 {
		config.MaxConcurrentBatches = s.config.MaxConcurrentBatches
	}

	if config.Timeout <= 0 {
		config.Timeout = s.config.Timeout
	}

	if config.Logger == nil {
		config.Logger = s.logger
	}

	// Validate the CSS endpoint
	if config.CSSEndpoint == "" {
		return errors.New("CSS endpoint cannot be empty")
	}

	if !strings.HasPrefix(config.CSSEndpoint, "http://") &&
		!strings.HasPrefix(config.CSSEndpoint, "https://") {
		return errors.New("CSS endpoint must be a valid HTTP/HTTPS URL")
	}

	// Validate target storage config if provided
	if config.TargetStorageConfig != "" {
		if !s.isValidStorageConfig(config.TargetStorageConfig) {
			return errors.New("invalid target storage configuration")
		}
	}

	return nil
}

// isValidStorageConfig validates a storage configuration string
func (s *MigrationService) isValidStorageConfig(config string) bool {
	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"..", "//", "~", "$", ";", "|", "&",
		"`", "'", "\"", "\\", "\n", "\r",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(config, pattern) {
			return false
		}
	}

	// Check length
	if len(config) > 4096 {
		return false
	}

	return true
}

// generateJobID generates a unique job ID
func (s *MigrationService) generateJobID() string {
	timestamp := time.Now().UnixNano()
	random := randString(8)
	return fmt.Sprintf("mig-%d-%s", timestamp, random)
}

// StartJob starts a migration job
func (s *MigrationService) StartJob(jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("migration service is closed")
	}

	job, exists := s.jobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	if job.State != MigrationStateCreated {
		return fmt.Errorf("job %s is not in created state: %s", jobID, job.State)
	}

	job.State = MigrationStateScanning
	job.Progress.CurrentPhase = PhaseCSSConnectionCheck
	job.Progress.PhaseStartTime = time.Now().UTC()

	// Start the migration in a goroutine
	go func() {
		defer func() {
			if err := recover(); err != nil {
				job.Logger.Error("Migration job panicked",
					"job_id", jobID,
					"error", err,
				)
				job.recordError(MigrationError{
					ErrorID:   generateErrorID(),
					Timestamp: time.Now().UTC(),
					Phase:     job.Progress.CurrentPhase,
					Error:     fmt.Errorf("panic: %v", err),
					Severity:  SeverityFatal,
					Retryable: false,
				})
				job.State = MigrationStateFailed
				job.EndTime = time.Now().UTC()
			}
		}()

		// Run the migration
		if err := job.Run(); err != nil {
			job.Logger.Error("Migration job failed",
				"job_id", jobID,
				"error", err,
			)
			job.State = MigrationStateFailed
		} else {
			job.State = MigrationStateCompleted
		}
		job.EndTime = time.Now().UTC()

		s.updateJobMetrics(job)
	}()

	return nil
}

// Run executes the migration job
func (j *MigrationJob) Run() error {
	j.Logger.Info("Starting migration job",
		"job_id", j.JobID,
		"mode", j.Config.Mode,
	)

	// Phase 1: CSS Connection Check
	if err := j.checkCSSConnection(); err != nil {
		return fmt.Errorf("CSS connection check failed: %w", err)
	}

	// Phase 2: Resource Discovery (CSS Inventory Scan)
	if err := j.scanCSSInventory(); err != nil {
		return fmt.Errorf("CSS inventory scan failed: %w", err)
	}

	// Phase 3: Export from CSS
	if err := j.exportFromCSS(); err != nil {
		return fmt.Errorf("CSS export failed: %w", err)
	}

	// Phase 4: Analysis
	if err := j.analyzeMigration(); err != nil {
		return fmt.Errorf("migration analysis failed: %w", err)
	}

	// Phase 5: Backup creation (if enabled and in live mode)
	if j.Config.CreateBackup && j.Config.Mode == MigrationModeLive {
		if err := j.createBackup(); err != nil {
			return fmt.Errorf("backup creation failed: %w", err)
		}
	}

	// Phase 6: Import to Native Storage
	if err := j.importToNative(); err != nil {
		return fmt.Errorf("native import failed: %w", err)
	}

	// Phase 7: Verification
	if err := j.verifyMigration(); err != nil {
		return fmt.Errorf("migration verification failed: %w", err)
	}

	j.Logger.Info("Migration job completed successfully", "job_id", j.JobID)
	return nil
}

// checkCSSConnection checks the connection to the CSS server
func (j *MigrationJob) checkCSSConnection() error {
	j.updateProgress(PhaseCSSConnectionCheck, "Checking CSS server connection")
	defer func() { j.Progress.PhaseStartTime = time.Now().UTC() }()

	// In a real implementation, this would make an HTTP request to the CSS endpoint
	// For now, we'll simulate the check
	j.Logger.Info("CSS connection check", "endpoint", j.Config.CSSEndpoint)

	// Validate the endpoint is reachable
	// This is a placeholder - actual implementation would use HTTP client
	if strings.HasPrefix(j.Config.CSSEndpoint, "http://") ||
		strings.HasPrefix(j.Config.CSSEndpoint, "https://") {
		j.Logger.Info("CSS endpoint appears valid", "endpoint", j.Config.CSSEndpoint)
	} else {
		return fmt.Errorf("invalid CSS endpoint: %s", j.Config.CSSEndpoint)
	}

	return nil
}

// scanCSSInventory performs CSS inventory scanning
func (j *MigrationJob) scanCSSInventory() error {
	j.updateProgress(PhaseResourceDiscovery, "Scanning CSS inventory")

	// Create inventory scanner
	scanner := NewCSSInventoryScanner(CSSInventoryScannerConfig{
		CSSEndpoint: j.Config.CSSEndpoint,
		Logger:      j.Config.Logger,
		Timeout:     j.Config.Timeout,
		RetryCount:  j.Config.RetryCount,
		RetryDelay:  j.Config.RetryDelay,
	})

	// Run the scan
	inventory, err := scanner.Scan(context.Background())
	if err != nil {
		return fmt.Errorf("inventory scan failed: %w", err)
	}

	j.Inventory = inventory
	j.Progress.ResourcesTotal = int64(len(inventory.Resources))
	j.Progress.ResourcesScanned = int64(len(inventory.Resources))

	j.Logger.Info("CSS inventory scan completed",
		"resources", len(inventory.Resources),
		"containers", len(inventory.Containers),
		"auxiliary_resources", len(inventory.AuxiliaryResources),
		"acl_resources", len(inventory.ACLResources),
		"acp_resources", len(inventory.ACPResources),
		"storage_descriptions", len(inventory.StorageDescriptions),
	)

	return nil
}

// exportFromCSS exports data from CSS
func (j *MigrationJob) exportFromCSS() error {
	j.updateProgress(PhaseExport, "Exporting data from CSS")

	if j.Inventory == nil {
		return errors.New("inventory not scanned, cannot export")
	}

	// Create export reader
	reader := NewCSSExportReader(CSSExportReaderConfig{
		CSSEndpoint:     j.Config.CSSEndpoint,
		Inventory:       j.Inventory,
		Logger:          j.Config.Logger,
		Timeout:         j.Config.Timeout,
		RetryCount:      j.Config.RetryCount,
		RetryDelay:      j.Config.RetryDelay,
		BatchSize:       j.Config.BatchSize,
		ExportDirectory: j.Config.TemporaryDirectory,
	})

	// Run the export
	exportReport, err := reader.Export(context.Background())
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	j.ExportReport = exportReport
	j.Progress.ResourcesExported = int64(len(exportReport.ExportedResources))
	j.Progress.BytesProcessed = exportReport.TotalBytesExported

	j.Logger.Info("CSS export completed",
		"resources_exported", len(exportReport.ExportedResources),
		"bytes_exported", exportReport.TotalBytesExported,
		"errors", len(exportReport.Errors),
	)

	return nil
}

// analyzeMigration analyzes the migration for issues
func (j *MigrationJob) analyzeMigration() error {
	j.updateProgress(PhaseAnalysis, "Analyzing migration")

	if j.ExportReport == nil {
		return errors.New("export not completed, cannot analyze")
	}

	// Create analyzer
	analyzer := NewMigrationAnalyzer(MigrationAnalyzerConfig{
		ExportReport:               j.ExportReport,
		EnableChecksumVerification: j.Config.EnableChecksumVerification,
		EnablePolicyComparison:     j.Config.EnablePolicyComparison,
		EnableIdentityMapping:      j.Config.EnableIdentityMapping,
		Logger:                     j.Config.Logger,
	})

	// Run the analysis
	analysisReport, err := analyzer.Analyze(context.Background())
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	j.AnalysisReport = analysisReport
	j.Progress.ResourcesAnalyzed = int64(len(analysisReport.AnalyzedResources))

	j.Logger.Info("Migration analysis completed",
		"resources_analyzed", len(analysisReport.AnalyzedResources),
		"checksum_verified", analysisReport.ChecksumsVerified,
		"checksum_mismatches", analysisReport.ChecksumMismatches,
		"policy_issues", len(analysisReport.PolicyIssues),
		"identity_issues", len(analysisReport.IdentityIssues),
	)

	return nil
}

// createBackup creates a backup of the CSS data
func (j *MigrationJob) createBackup() error {
	j.updateProgress(PhaseBackup, "Creating backup")

	if j.Config.Mode == MigrationModeDryRun {
		j.Logger.Info("Skipping backup in dry-run mode")
		return nil
	}

	// Create backup manager
	backupManager := NewBackupManager(BackupManagerConfig{
		CSSEndpoint: j.Config.CSSEndpoint,
		Inventory:   j.Inventory,
		BackupDir:   j.Config.BackupDirectory,
		Logger:      j.Config.Logger,
		Timeout:     j.Config.Timeout,
	})

	// Create backup
	backupReport, err := backupManager.CreateBackup(context.Background())
	if err != nil {
		return fmt.Errorf("backup creation failed: %w", err)
	}

	j.RollbackPlan = &RollbackPlan{
		BackupLocation:    backupReport.BackupPath,
		BackupTimestamp:   time.Now().UTC(),
		ResourcesBackedUp: int64(len(backupReport.BackedUpResources)),
		RollbackInstructions: []string{
			"1. Stop all traffic to native runtime",
			"2. Restore from backup: " + backupReport.BackupPath,
			"3. Verify CSS functionality",
			"4. Resume CSS-only operations",
		},
	}

	j.Logger.Info("Backup created",
		"location", backupReport.BackupPath,
		"resources_backed_up", len(backupReport.BackedUpResources),
	)

	return nil
}

// importToNative imports data to the native storage engine
func (j *MigrationJob) importToNative() error {
	j.updateProgress(PhaseImport, "Importing to native storage")

	if j.Config.Mode == MigrationModeDryRun {
		j.Logger.Info("Skipping import in dry-run mode")
		// Simulate import counts
		j.Progress.ResourcesImported = j.Progress.ResourcesExported
		return nil
	}

	if j.ExportReport == nil {
		return errors.New("export not completed, cannot import")
	}

	// Create import writer
	writer := NewNativeImportWriter(NativeImportWriterConfig{
		ExportReport: j.ExportReport,
		TargetConfig: j.Config.TargetStorageConfig,
		BatchSize:    j.Config.BatchSize,
		Logger:       j.Config.Logger,
		Timeout:      j.Config.Timeout,
		RetryCount:   j.Config.RetryCount,
		RetryDelay:   j.Config.RetryDelay,
	})

	// Run the import
	importReport, err := writer.Import(context.Background())
	if err != nil {
		return fmt.Errorf("import failed: %w", err)
	}

	j.ImportReport = importReport
	j.Progress.ResourcesImported = int64(len(importReport.ImportedResources))

	j.Logger.Info("Native import completed",
		"resources_imported", len(importReport.ImportedResources),
		"bytes_imported", importReport.TotalBytesImported,
		"errors", len(importReport.Errors),
	)

	return nil
}

// verifyMigration verifies the completed migration
func (j *MigrationJob) verifyMigration() error {
	j.updateProgress(PhaseVerification, "Verifying migration")

	if j.Config.Mode == MigrationModeDryRun {
		j.Logger.Info("Skipping verification in dry-run mode")
		// Simulate verification
		j.Progress.ResourcesVerified = j.Progress.ResourcesImported
		return nil
	}

	if j.ImportReport == nil {
		return errors.New("import not completed, cannot verify")
	}

	// Create verifier
	verifier := NewMigrationVerifier(MigrationVerifierConfig{
		ImportReport:               j.ImportReport,
		CSSEndpoint:                j.Config.CSSEndpoint,
		EnableChecksumVerification: j.Config.EnableChecksumVerification,
		Logger:                     j.Config.Logger,
		Timeout:                    j.Config.Timeout,
	})

	// Run the verification
	verificationReport, err := verifier.Verify(context.Background())
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	j.VerificationReport = verificationReport
	j.Progress.ResourcesVerified = int64(len(verificationReport.VerifiedResources))

	j.Logger.Info("Migration verification completed",
		"resources_verified", len(verificationReport.VerifiedResources),
		"verification_errors", len(verificationReport.Errors),
		"all_verified", verificationReport.AllResourcesVerified,
	)

	return nil
}

// updateProgress updates the migration progress
func (j *MigrationJob) updateProgress(phase MigrationPhase, description string) {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.Progress.CurrentPhase = phase
	j.Progress.PhaseDescription = description
	j.Progress.PhaseStartTime = time.Now().UTC()
}

// recordError records a migration error
func (j *MigrationJob) recordError(err MigrationError) {
	j.mu.Lock()
	defer j.mu.Unlock()

	err.ErrorID = generateErrorID()
	err.Timestamp = time.Now().UTC()
	j.Errors = append(j.Errors, err)

	j.Logger.Error("Migration error",
		"error_id", err.ErrorID,
		"phase", err.Phase,
		"resource", err.ResourceURI,
		"error", err.Error,
		"severity", err.Severity,
	)
}

// GenerateChecksum generates a SHA-256 checksum for data
func GenerateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// generateErrorID generates a unique error ID
func generateErrorID() string {
	return fmt.Sprintf("err-%d-%s", time.Now().UnixNano(), randString(4))
}

// randString generates a random string of the specified length
func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

// recordJobMetrics records metrics for a completed job
func (s *MigrationService) updateJobMetrics(job *MigrationJob) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()

	s.metrics.JobsCompleted++

	// Update phase durations
	if s.metrics.PhaseDurations == nil {
		s.metrics.PhaseDurations = make(map[MigrationPhase]time.Duration)
	}

	// Update error metrics
	if s.metrics.ErrorsBySeverity == nil {
		s.metrics.ErrorsBySeverity = make(map[ErrorSeverity]int64)
	}
	if s.metrics.ErrorsByPhase == nil {
		s.metrics.ErrorsByPhase = make(map[MigrationPhase]int64)
	}

	for _, err := range job.Errors {
		s.metrics.ErrorsBySeverity[err.Severity]++
		s.metrics.ErrorsByPhase[err.Phase]++
	}
}

// GetJob returns a migration job by ID
func (s *MigrationService) GetJob(jobID string) (*MigrationJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, errors.New("migration service is closed")
	}

	job, exists := s.jobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	return job, nil
}

// ListJobs returns all migration jobs
func (s *MigrationService) ListJobs() []*MigrationJob {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil
	}

	jobs := make([]*MigrationJob, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	return jobs
}

// PauseJob pauses a migration job
func (s *MigrationService) PauseJob(jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("migration service is closed")
	}

	job, exists := s.jobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	if job.State != MigrationStateScanning &&
		job.State != MigrationStateExporting &&
		job.State != MigrationStateAnalyzing &&
		job.State != MigrationStateImporting &&
		job.State != MigrationStateVerifying {
		return fmt.Errorf("job %s cannot be paused in state: %s", jobID, job.State)
	}

	job.State = MigrationStatePaused
	job.Logger.Info("Migration job paused", "job_id", jobID)

	return nil
}

// ResumeJob resumes a paused migration job
func (s *MigrationService) ResumeJob(jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("migration service is closed")
	}

	job, exists := s.jobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	if job.State != MigrationStatePaused {
		return fmt.Errorf("job %s is not paused", jobID)
	}

	job.State = MigrationStateScanning // Resume from scanning phase
	job.Logger.Info("Migration job resumed", "job_id", jobID)

	// Start the job in a goroutine
	go func() {
		if err := job.Run(); err != nil {
			job.Logger.Error("Resumed migration job failed",
				"job_id", jobID,
				"error", err,
			)
			job.State = MigrationStateFailed
		} else {
			job.State = MigrationStateCompleted
		}
		job.EndTime = time.Now().UTC()
	}()

	return nil
}

// CancelJob cancels a migration job
func (s *MigrationService) CancelJob(jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("migration service is closed")
	}

	job, exists := s.jobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	// Cancel the job context
	job.Cancel()

	job.State = MigrationStateFailed
	job.EndTime = time.Now().UTC()
	job.Logger.Info("Migration job cancelled", "job_id", jobID)

	s.metrics.RecordJobCancelled()

	return nil
}

// RollbackJob performs a rollback for a migration job
func (s *MigrationService) RollbackJob(jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("migration service is closed")
	}

	job, exists := s.jobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	if job.RollbackPlan == nil {
		return ErrRollbackNotAvailable
	}

	if job.Config.Mode == MigrationModeDryRun {
		return ErrDryRunMode
	}

	// Create rollback executor
	rollbackExecutor := NewRollbackExecutor(RollbackExecutorConfig{
		RollbackPlan: job.RollbackPlan,
		Logger:       job.Config.Logger,
		Timeout:      job.Config.Timeout,
	})

	// Execute rollback
	if err := rollbackExecutor.Execute(context.Background()); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	job.State = MigrationStateRolledBack
	job.EndTime = time.Now().UTC()
	job.Logger.Info("Migration job rolled back", "job_id", jobID)

	return nil
}

// GetMetrics returns the service metrics
func (s *MigrationService) GetMetrics() *MigrationServiceMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return &s.metrics
}

// Close closes the migration service
func (s *MigrationService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	close(s.closeChan)

	// Cancel all jobs
	for _, job := range s.jobs {
		job.Cancel()
		close(job.closeChan)
	}

	s.jobs = nil

	s.logger.Info("Migration service closed")
	return nil
}

// IsClosed returns true if the service is closed
func (s *MigrationService) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// RecordJobCreated records a job creation
func (m *MigrationServiceMetrics) RecordJobCreated() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.JobsCreated++
}

// RecordJobCompleted records a job completion
func (m *MigrationServiceMetrics) RecordJobCompleted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.JobsCompleted++
}

// RecordJobFailed records a job failure
func (m *MigrationServiceMetrics) RecordJobFailed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.JobsFailed++
}

// RecordJobCancelled records a job cancellation
func (m *MigrationServiceMetrics) RecordJobCancelled() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.JobsCancelled++
}

// ExportReport represents the report from the export phase
type ExportReport struct {
	// ExportedResources contains the URIs of exported resources
	ExportedResources []string

	// ExportErrors contains any errors that occurred during export
	Errors []MigrationError

	// TotalBytesExported is the total number of bytes exported
	TotalBytesExported int64

	// StartTime is when the export started
	StartTime time.Time

	// EndTime is when the export completed
	EndTime time.Time

	// ExportedResourceDetails contains detailed information about each exported resource
	ExportedResourceDetails []ExportedResource
}

// ExportedResource represents a resource that has been exported from CSS
type ExportedResource struct {
	// URI is the original URI of the resource
	URI string

	// TargetPath is the path where the resource was exported
	TargetPath string

	// ResourceType is the type of the exported resource
	ResourceType ResourceType

	// ContentType is the MIME type of the resource
	ContentType string

	// Size is the size of the resource in bytes
	Size int64

	// Checksum is the SHA-256 checksum of the resource content
	Checksum string

	// ExportTime is when the resource was exported
	ExportTime time.Time

	// Success indicates whether the export was successful
	Success bool

	// Error contains any error that occurred during export
	Error error

	// Metadata contains exported metadata
	Metadata map[string]interface{}

	// Links contains the links for this resource
	Links []ResourceLink
}

// AnalysisReport represents the report from the analysis phase
type AnalysisReport struct {
	// AnalyzedResources contains the URIs of analyzed resources
	AnalyzedResources []string

	// ChecksumsVerified is the number of resources with verified checksums
	ChecksumsVerified int64

	// ChecksumMismatches is the number of resources with checksum mismatches
	ChecksumMismatches int64

	// PolicyIssues contains any policy-related issues found
	PolicyIssues []PolicyIssue

	// IdentityIssues contains any identity/issuer mapping issues found
	IdentityIssues []IdentityIssue

	// StartTime is when the analysis started
	StartTime time.Time

	// EndTime is when the analysis completed
	EndTime time.Time
}

// PolicyIssue represents a policy-related issue found during analysis
type PolicyIssue struct {
	// ResourceURI is the URI of the resource with the issue
	ResourceURI string

	// IssueType is the type of issue (e.g., missing_policy, invalid_rule, etc.)
	IssueType string

	// Description describes the issue
	Description string

	// Severity indicates the severity of the issue
	Severity ErrorSeverity

	// CSSPolicy is the CSS policy
	CSSPolicy string

	// NativePolicy is the equivalent native policy
	NativePolicy string
}

// IdentityIssue represents an identity/issuer mapping issue
type IdentityIssue struct {
	// ResourceURI is the URI of the resource with the issue
	ResourceURI string

	// IssueType is the type of issue
	IssueType string

	// Description describes the issue
	Description string

	// Severity indicates the severity of the issue
	Severity ErrorSeverity

	// CSSIdentity is the CSS identity
	CSSIdentity string

	// NativeIdentity is the mapped native identity
	NativeIdentity string
}

// ImportReport represents the report from the import phase
type ImportReport struct {
	// ImportedResources contains the URIs of imported resources
	ImportedResources []string

	// ImportErrors contains any errors that occurred during import
	Errors []MigrationError

	// TotalBytesImported is the total number of bytes imported
	TotalBytesImported int64

	// StartTime is when the import started
	StartTime time.Time

	// EndTime is when the import completed
	EndTime time.Time
}

// VerificationReport represents the report from the verification phase
type VerificationReport struct {
	// VerifiedResources contains the URIs of verified resources
	VerifiedResources []string

	// VerificationErrors contains any errors that occurred during verification
	Errors []MigrationError

	// AllResourcesVerified indicates if all resources were successfully verified
	AllResourcesVerified bool

	// StartTime is when the verification started
	StartTime time.Time

	// EndTime is when the verification completed
	EndTime time.Time
}

// RollbackPlan contains the rollback plan for a migration
type RollbackPlan struct {
	// BackupLocation is the location of the backup
	BackupLocation string

	// BackupTimestamp is when the backup was created
	BackupTimestamp time.Time

	// ResourcesBackedUp is the number of resources backed up
	ResourcesBackedUp int64

	// RollbackInstructions contains the instructions for rollback
	RollbackInstructions []string
}

// BackupReport represents the report from a backup operation
type BackupReport struct {
	// BackupPath is the path to the backup
	BackupPath string

	// BackedUpResources contains the URIs of backed up resources
	BackedUpResources []string

	// TotalBytesBackedUp is the total number of bytes backed up
	TotalBytesBackedUp int64

	// StartTime is when the backup started
	StartTime time.Time

	// EndTime is when the backup completed
	EndTime time.Time
}

// JSON serialization for configuration
func (c *MigrationConfig) ToJSON() (string, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes configuration from JSON
func (c *MigrationConfig) FromJSON(data string) error {
	return json.Unmarshal([]byte(data), c)
}

// SaveConfig saves configuration to a file
func (c *MigrationConfig) SaveConfig(path string) error {
	configJSON, err := c.ToJSON()
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write config file
	if err := os.WriteFile(path, []byte(configJSON), 0640); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*MigrationConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultMigrationConfig()
	if err := config.FromJSON(string(data)); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

// WriteJSONReport writes a report to a JSON file
func WriteJSONReport(path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create report directory: %w", err)
		}
	}

	// Write report file
	if err := os.WriteFile(path, jsonData, 0640); err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}

	return nil
}

// ReadJSONReport reads a report from a JSON file
func ReadJSONReport[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read report file: %w", err)
	}

	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}

	return &result, nil
}
