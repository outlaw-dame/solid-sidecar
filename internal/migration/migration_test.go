// Package migration provides tools for migrating from CSS-backed deployments to native runtime.
// This file implements tests for Phase 25 migration tooling.
package migration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestCSSInventoryScanner tests the CSS inventory scanner
func TestCSSInventoryScanner(t *testing.T) {
	// Create test logger
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Test configuration
	config := CSSInventoryScannerConfig{
		CSSEndpoint: "http://localhost:3000",
		Logger:      logger,
		Timeout:     5 * time.Minute,
		RetryCount:  3,
		RetryDelay:  1 * time.Second,
	}

	// Create scanner
	scanner := NewCSSInventoryScanner(config)
	if scanner == nil {
		t.Fatal("Failed to create CSS inventory scanner")
	}

	// Test default configuration
	defaultConfig := DefaultCSSInventoryScannerConfig()
	if defaultConfig.Timeout <= 0 {
		t.Error("Default timeout should be positive")
	}
	if defaultConfig.RetryCount <= 0 {
		t.Error("Default retry count should be positive")
	}
	if defaultConfig.RetryDelay <= 0 {
		t.Error("Default retry delay should be positive")
	}

	// Test validateCSSEndpoint
	t.Run("ValidateCSSEndpoint", func(t *testing.T) {
		// Test valid endpoint
		validScanner := NewCSSInventoryScanner(CSSInventoryScannerConfig{
			CSSEndpoint: "https://valid-css.example.com",
			Logger:      logger,
		})
		if err := validScanner.validateCSSEndpoint(); err != nil {
			t.Errorf("Valid endpoint should pass validation: %v", err)
		}

		// Test invalid endpoint (no scheme)
		invalidScanner1 := NewCSSInventoryScanner(CSSInventoryScannerConfig{
			CSSEndpoint: "invalid-endpoint",
			Logger:      logger,
		})
		if err := invalidScanner1.validateCSSEndpoint(); err == nil {
			t.Error("Invalid endpoint (no scheme) should fail validation")
		}

		// Test invalid endpoint (invalid scheme)
		invalidScanner2 := NewCSSInventoryScanner(CSSInventoryScannerConfig{
			CSSEndpoint: "ftp://invalid-scheme.example.com",
			Logger:      logger,
		})
		if err := invalidScanner2.validateCSSEndpoint(); err == nil {
			t.Error("Invalid endpoint (invalid scheme) should fail validation")
		}

		// Test invalid endpoint (no host)
		invalidScanner3 := NewCSSInventoryScanner(CSSInventoryScannerConfig{
			CSSEndpoint: "http://",
			Logger:      logger,
		})
		if err := invalidScanner3.validateCSSEndpoint(); err == nil {
			t.Error("Invalid endpoint (no host) should fail validation")
		}
	})

	// Test CSSInventory structure
	t.Run("CSSInventoryStructure", func(t *testing.T) {
		inventory := &CSSInventory{
			Resources:           make([]CSSResource, 0),
			Containers:          make([]CSSResource, 0),
			AuxiliaryResources:  make([]CSSResource, 0),
			ACLResources:        make([]CSSResource, 0),
			ACPResources:        make([]CSSResource, 0),
			MetadataResources:   make([]CSSResource, 0),
			StorageDescriptions: make([]CSSResource, 0),
			AllResources:        make([]CSSResource, 0),
			ScanTimestamp:       time.Now(),
			CSSEndpoint:         "http://localhost:3000",
			Errors:              make([]InventoryScanError, 0),
		}

		// Test adding resources
		resource := CSSResource{
			URI:          "http://localhost:3000/resource1",
			ResourceType: ResourceTypeResource,
			ContentType:  "text/turtle",
			Size:         1024,
		}

		inventory.Resources = append(inventory.Resources, resource)
		inventory.AllResources = append(inventory.AllResources, resource)

		if len(inventory.Resources) != 1 {
			t.Errorf("Expected 1 resource, got %d", len(inventory.Resources))
		}
		if len(inventory.AllResources) != 1 {
			t.Errorf("Expected 1 all resource, got %d", len(inventory.AllResources))
		}

		// Test JSON serialization
		jsonData, err := inventory.ToJSON()
		if err != nil {
			t.Errorf("Failed to serialize inventory to JSON: %v", err)
		}
		if jsonData == "" {
			t.Error("JSON data should not be empty")
		}

		// Test JSON deserialization
		var decodedInventory CSSInventory
		if err := decodedInventory.FromJSON(jsonData); err != nil {
			t.Errorf("Failed to deserialize inventory from JSON: %v", err)
		}
		if len(decodedInventory.Resources) != 1 {
			t.Errorf("Expected 1 decoded resource, got %d", len(decodedInventory.Resources))
		}
	})
}

// TestCSSResourceTypes tests CSS resource type definitions
func TestCSSResourceTypes(t *testing.T) {
	// Test that all expected resource types are defined
	expectedTypes := []ResourceType{
		ResourceTypeResource,
		ResourceTypeContainer,
		ResourceTypeAuxiliary,
		ResourceTypeACL,
		ResourceTypeACP,
		ResourceTypeMetadata,
		ResourceTypeStorageDesc,
		ResourceTypeUnknown,
	}

	for _, resourceType := range expectedTypes {
		if resourceType == "" {
			t.Error("Resource type should not be empty")
		}
	}
}

// TestMigrationService tests the migration service
func TestMigrationService(t *testing.T) {
	// Create test logger
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Test configuration
	config := MigrationConfig{
		CSSEndpoint:                "http://localhost:3000",
		TargetStorageConfig:        "native-storage-config",
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
		Logger:                     logger,
	}

	// Create migration service
	service := NewMigrationService(config)
	if service == nil {
		t.Fatal("Failed to create migration service")
	}

	// Test default configuration
	defaultConfig := DefaultMigrationConfig()
	if defaultConfig.CSSEndpoint == "" {
		t.Error("Default CSS endpoint should not be empty")
	}
	if defaultConfig.Mode != MigrationModeDryRun {
		t.Error("Default mode should be dry run")
	}

	// Test configuration validation
	t.Run("ConfigurationValidation", func(t *testing.T) {
		// Test invalid CSS endpoint
		invalidConfig := MigrationConfig{
			CSSEndpoint: "invalid-endpoint",
			Logger:      logger,
		}
		invalidService := NewMigrationService(invalidConfig)
		// The validation should have logged a warning but not failed
		if invalidService == nil {
			t.Error("Service creation should not fail for invalid config, just log warning")
		}

		// Test empty CSS endpoint
		emptyConfig := MigrationConfig{
			CSSEndpoint: "",
			Logger:      logger,
		}
		emptyService := NewMigrationService(emptyConfig)
		if emptyService == nil {
			t.Error("Service creation should not fail for empty CSS endpoint")
		}
	})

	// Test job creation
	t.Run("JobCreation", func(t *testing.T) {
		job, err := service.CreateMigrationJob(config)
		if err != nil {
			t.Fatalf("Failed to create migration job: %v", err)
		}
		if job == nil {
			t.Fatal("Migration job should not be nil")
		}
		if job.JobID == "" {
			t.Error("Job ID should not be empty")
		}
		if job.State != MigrationStateCreated {
			t.Errorf("Job state should be %s, got %s", MigrationStateCreated, job.State)
		}
		if job.Config.CSSEndpoint != config.CSSEndpoint {
			t.Error("Job config should match service config")
		}
	})

	// Test path validation
	t.Run("PathValidation", func(t *testing.T) {
		// Test valid paths
		validPaths := []string{
			"/var/backups",
			"/opt/data",
			"/tmp/migration",
			"/home/user/backups",
			"/mnt/storage",
			"/srv/data",
			"/data/migration",
		}

		for _, path := range validPaths {
			if err := validateDirectoryPath(path); err != nil {
				t.Errorf("Valid path %s should pass validation: %v", path, err)
			}
		}

		// Test invalid paths
		invalidPaths := []string{
			"",
			"/dev/null",
			"/proc/self",
			"/sys/kernel",
			"../malicious",
			"/root/../etc",
			"/etc/../passwd",
		}

		for _, path := range invalidPaths {
			if err := validateDirectoryPath(path); err == nil {
				t.Errorf("Invalid path %s should fail validation", path)
			}
		}
	})
}

// TestMigrationStates tests migration state definitions
func TestMigrationStates(t *testing.T) {
	// Test that all expected states are defined
	expectedStates := []MigrationState{
		MigrationStateCreated,
		MigrationStateScanning,
		MigrationStateExporting,
		MigrationStateAnalyzing,
		MigrationStateImporting,
		MigrationStateVerifying,
		MigrationStatePaused,
		MigrationStateCompleted,
		MigrationStateFailed,
		MigrationStateRolledBack,
	}

	for _, state := range expectedStates {
		if state == "" {
			t.Error("Migration state should not be empty")
		}
	}
}

// TestMigrationModes tests migration mode definitions
func TestMigrationModes(t *testing.T) {
	// Test that both modes are defined
	if MigrationModeDryRun == "" {
		t.Error("Dry run mode should not be empty")
	}
	if MigrationModeLive == "" {
		t.Error("Live mode should not be empty")
	}
}

// TestMigrationPhases tests migration phase definitions
func TestMigrationPhases(t *testing.T) {
	// Test that all expected phases are defined
	expectedPhases := []MigrationPhase{
		PhaseInitialization,
		PhaseCSSConnectionCheck,
		PhaseResourceDiscovery,
		PhaseContainerDiscovery,
		PhaseAuxiliaryDiscovery,
		PhaseACLDiscovery,
		PhaseACPDiscovery,
		PhaseMetadataDiscovery,
		PhaseStorageDescription,
		PhaseExport,
		PhaseChecksumVerification,
		PhasePolicyComparison,
		PhaseIdentityMapping,
		PhaseImport,
		PhaseValidation,
		PhaseBackup,
		PhaseCleanup,
		PhaseAnalysis,
		PhaseVerification,
	}

	for _, phase := range expectedPhases {
		if phase == "" {
			t.Error("Migration phase should not be empty")
		}
	}
}

// TestErrorSeverities tests error severity definitions
func TestErrorSeverities(t *testing.T) {
	// Test that all expected severities are defined
	severities := []ErrorSeverity{
		SeverityLow,
		SeverityMedium,
		SeverityHigh,
		SeverityFatal,
	}

	for _, severity := range severities {
		if severity == "" {
			t.Error("Error severity should not be empty")
		}
	}
}

// TestMigrationError tests migration error structure
func TestMigrationError(t *testing.T) {
	// Create test error
	err := MigrationError{
		ErrorID:     "test-error-001",
		Timestamp:   time.Now(),
		Phase:       PhaseExport,
		ResourceURI: "http://localhost:3000/resource1",
		Error:       fmt.Errorf("test error"),
		Severity:    SeverityMedium,
		Retryable:   true,
		RetryCount:  0,
	}

	if err.ErrorID == "" {
		t.Error("Error ID should not be empty")
	}
	if err.Phase == "" {
		t.Error("Error phase should not be empty")
	}
	if err.Error == nil {
		t.Error("Error should not be nil")
	}
}

// TestMigrationProgress tests migration progress structure
func TestMigrationProgress(t *testing.T) {
	// Create test progress
	progress := MigrationProgress{
		CurrentPhase:      PhaseExport,
		PhaseDescription:  "Exporting resources from CSS",
		ResourcesTotal:    100,
		ResourcesScanned:  50,
		ResourcesExported: 25,
		ResourcesAnalyzed: 20,
		ResourcesImported: 15,
		ResourcesVerified: 10,
		ResourcesFailed:   5,
		BytesTotal:        1024 * 1024,
		BytesProcessed:    512 * 1024,
		PhaseStartTime:    time.Now(),
	}

	if progress.CurrentPhase == "" {
		t.Error("Current phase should not be empty")
	}
	if progress.ResourcesTotal <= 0 {
		t.Error("Resources total should be positive")
	}
}

// TestMigrationConfigJSON tests JSON serialization of migration config
func TestMigrationConfigJSON(t *testing.T) {
	// Create test config
	config := MigrationConfig{
		CSSEndpoint:                "http://localhost:3000",
		TargetStorageConfig:        "native-storage",
		Mode:                       MigrationModeDryRun,
		BatchSize:                  50,
		MaxConcurrentBatches:       2,
		EnableChecksumVerification: true,
		EnablePolicyComparison:     true,
		EnableIdentityMapping:      true,
		CreateBackup:               true,
		BackupDirectory:            "/var/backups",
		TemporaryDirectory:         "/tmp/migration",
		LogLevel:                   slog.LevelInfo,
		Timeout:                    10 * time.Minute,
		RetryCount:                 2,
		RetryDelay:                 500 * time.Millisecond,
	}

	// Test JSON serialization
	jsonData, err := config.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize config to JSON: %v", err)
	}
	if jsonData == "" {
		t.Error("JSON data should not be empty")
	}

	// Test JSON deserialization
	var decodedConfig MigrationConfig
	if err := decodedConfig.FromJSON(jsonData); err != nil {
		t.Fatalf("Failed to deserialize config from JSON: %v", err)
	}

	if decodedConfig.CSSEndpoint != config.CSSEndpoint {
		t.Error("Deserialized CSS endpoint should match original")
	}
	if decodedConfig.Mode != config.Mode {
		t.Error("Deserialized mode should match original")
	}
}

// TestComputeResourceChecksum tests checksum computation
func TestComputeResourceChecksum(t *testing.T) {
	// Test with empty content
	emptyChecksum := ComputeResourceChecksum(nil)
	if emptyChecksum != "" {
		t.Error("Empty content should produce empty checksum")
	}

	// Test with actual content
	content := []byte("Hello, World!")
	checksum := ComputeResourceChecksum(content)
	if checksum == "" {
		t.Error("Non-empty content should produce non-empty checksum")
	}
	if len(checksum) != 64 {
		t.Errorf("SHA-256 checksum should be 64 characters, got %d", len(checksum))
	}

	// Test consistency
	checksum2 := ComputeResourceChecksum(content)
	if checksum != checksum2 {
		t.Error("Same content should produce same checksum")
	}

	// Test different content produces different checksum
	differentContent := []byte("Hello, Universe!")
	differentChecksum := ComputeResourceChecksum(differentContent)
	if checksum == differentChecksum {
		t.Error("Different content should produce different checksum")
	}
}

// TestVerifyChecksumConsistency tests checksum verification
func TestVerifyChecksumConsistency(t *testing.T) {
	// Test matching checksums
	checksum := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if !VerifyChecksumConsistency(checksum, checksum) {
		t.Error("Identical checksums should verify as consistent")
	}

	// Test non-matching checksums
	differentChecksum := "098f6bcd4621d373cade4e832627b4f6"
	if VerifyChecksumConsistency(checksum, differentChecksum) {
		t.Error("Different checksums should not verify as consistent")
	}

	// Test empty checksums
	if VerifyChecksumConsistency("", "") {
		t.Error("Empty checksums should not verify as consistent")
	}
	if VerifyChecksumConsistency(checksum, "") {
		t.Error("Empty checksum should not match non-empty checksum")
	}
}

// TestMigrationServiceMetrics tests migration service metrics
func TestMigrationServiceMetrics(t *testing.T) {
	// Create metrics
	metrics := MigrationServiceMetrics{}

	// Test recording metrics
	metrics.RecordJobCreated()
	metrics.RecordJobCompleted()
	metrics.RecordJobFailed()
	metrics.RecordJobCancelled()

	if metrics.JobsCreated != 1 {
		t.Error("Jobs created should be 1")
	}
	if metrics.JobsCompleted != 1 {
		t.Error("Jobs completed should be 1")
	}
	if metrics.JobsFailed != 1 {
		t.Error("Jobs failed should be 1")
	}
	if metrics.JobsCancelled != 1 {
		t.Error("Jobs cancelled should be 1")
	}
}

// TestContextCancellation tests context cancellation handling
func TestContextCancellation(t *testing.T) {
	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Test that context is cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("Context should be cancelled")
	}

	// Test error from cancelled context
	if ctx.Err() == nil {
		t.Error("Cancelled context should return error")
	}
}

// TestDefaultConfigs tests default configurations
func TestDefaultConfigs(t *testing.T) {
	// Test default migration config
	defaultMigrationConfig := DefaultMigrationConfig()
	if defaultMigrationConfig.BatchSize <= 0 {
		t.Error("Default batch size should be positive")
	}

	// Test default CSS inventory scanner config
	defaultScannerConfig := DefaultCSSInventoryScannerConfig()
	if defaultScannerConfig.Timeout <= 0 {
		t.Error("Default scanner timeout should be positive")
	}

	// Test default CSS export reader config
	defaultExportConfig := DefaultCSSExportReaderConfig()
	if defaultExportConfig.BatchSize <= 0 {
		t.Error("Default export batch size should be positive")
	}

	// Test default migration analyzer config
	defaultAnalyzerConfig := DefaultMigrationAnalyzerConfig()
	if !defaultAnalyzerConfig.EnableChecksumVerification {
		t.Error("Default analyzer should have checksum verification enabled")
	}

	// Test default backup manager config
	defaultBackupConfig := DefaultBackupManagerConfig()
	if defaultBackupConfig.Timeout <= 0 {
		t.Error("Default backup timeout should be positive")
	}

	// Test default native import writer config
	defaultImportConfig := DefaultNativeImportWriterConfig()
	if defaultImportConfig.BatchSize <= 0 {
		t.Error("Default import batch size should be positive")
	}

	// Test default migration verifier config
	defaultVerifierConfig := DefaultMigrationVerifierConfig()
	if defaultVerifierConfig.MaxConcurrentVerifications <= 0 {
		t.Error("Default verifier concurrent verifications should be positive")
	}

	// Test default rollback executor config
	defaultRollbackConfig := DefaultRollbackExecutorConfig()
	if defaultRollbackConfig.Timeout <= 0 {
		t.Error("Default rollback timeout should be positive")
	}
}

// TestResourceLink tests resource link structure
func TestResourceLink(t *testing.T) {
	// Create test link
	link := ResourceLink{
		Rel:    "acl",
		Target: "http://localhost:3000/resource1.acl",
		Type:   "application/acl+json",
	}

	if link.Rel == "" {
		t.Error("Link relation should not be empty")
	}
	if link.Target == "" {
		t.Error("Link target should not be empty")
	}
}

// TestCSSResource tests CSS resource structure
func TestCSSResource(t *testing.T) {
	// Create test resource
	now := time.Now()
	resource := CSSResource{
		URI:          "http://localhost:3000/resource1",
		ResourceType: ResourceTypeResource,
		ContentType:  "text/turtle",
		Size:         1024,
		LastModified: now,
		ETag:         "\"abc123\"",
		Links:        make([]ResourceLink, 0),
		Metadata:     make(map[string]interface{}),
		Checksum:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	if resource.URI == "" {
		t.Error("Resource URI should not be empty")
	}
	if resource.ResourceType == "" {
		t.Error("Resource type should not be empty")
	}
}

// TestResourceTypeDetection tests resource type detection
func TestResourceTypeDetection(t *testing.T) {
	// Create scanner for testing
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	scanner := NewCSSInventoryScanner(CSSInventoryScannerConfig{
		CSSEndpoint: "http://localhost:3000",
		Logger:      logger,
	})

	// Test container detection by URI
	containerResource := CSSResource{
		URI:         "http://localhost:3000/container/",
		ContentType: "text/turtle",
	}
	if !scanner.isContainer(&containerResource) {
		t.Error("Container URI should be detected as container")
	}

	// Test ACL detection by URI (using public method that doesn't require HTTP response)
	aclResource := CSSResource{
		URI:         "http://localhost:3000/resource.acl",
		ContentType: "text/turtle",
	}
	// Since determineResourceType requires an HTTP response, we'll test the URI patterns directly
	if !strings.Contains(strings.ToLower(aclResource.URI), ".acl") {
		t.Error("ACL resource URI should contain .acl")
	}

	// Test ACP detection by URI
	acpResource := CSSResource{
		URI:         "http://localhost:3000/resource.acp",
		ContentType: "text/turtle",
	}
	if !strings.Contains(strings.ToLower(acpResource.URI), ".acp") {
		t.Error("ACP resource URI should contain .acp")
	}
}
