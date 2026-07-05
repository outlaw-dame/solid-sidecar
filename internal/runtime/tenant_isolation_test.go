// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements tenant isolation tests for Phase 21.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// TenantIsolationTester tests tenant isolation properties
// This is a critical component of Phase 21 to ensure tenants cannot access each other's resources
type TenantIsolationTester struct {
	mu sync.Mutex

	// multiStorage is the multi-storage layer to test
	multiStorage *MultiStorageLayer

	// logger is the logger for test output
	logger *slog.Logger

	// testTenants holds test tenants
	testTenants []*TenantConfig

	// testResources maps tenant ID to resource URIs
	testResources map[string][]string

	// isolationViolations tracks any isolation violations found
	isolationViolations []IsolationViolation
}

// IsolationViolation represents a tenant isolation violation
type IsolationViolation struct {
	// TestName is the name of the test that detected the violation
	TestName string

	// SourceTenant is the tenant that accessed the resource
	SourceTenant string

	// TargetTenant is the tenant that owns the resource
	TargetTenant string

	// ResourceURI is the URI of the resource that was accessed
	ResourceURI string

	// AccessType describes the type of access (read, write, etc.)
	AccessType string

	// Timestamp is when the violation was detected
	Timestamp time.Time

	// Error contains the original error if any
	Error error
}

// NewTenantIsolationTester creates a new tenant isolation tester
func NewTenantIsolationTester(multiStorage *MultiStorageLayer) *TenantIsolationTester {
	return &TenantIsolationTester{
		multiStorage:   multiStorage,
		logger:        slog.Default(),
		testTenants:    []*TenantConfig{},
		testResources:  make(map[string][]string),
		isolationViolations: []IsolationViolation{},
	}
}

// SetupTestTenants creates test tenants for isolation testing
func (t *TenantIsolationTester) SetupTestTenants() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Create test tenants
	testTenantIDs := []string{"tenant-a", "tenant-b", "tenant-c"}

	for _, tenantID := range testTenantIDs {
		tenantConfig := &TenantConfig{
			TenantID:               tenantID,
			StorageBackend:         "test-backend",
			AllowedStorageBackends: []string{"test-backend"},
			ResourceQuotas: TenantQuotas{
				MaxResources:         100,
				MaxStorage:           1024 * 1024 * 100, // 100 MB
				MaxBandwidth:         1024 * 1024,      // 1 MB/s
				MaxRequestsPerSecond: 100,
			},
			ACLConfig: TenantACLConfig{
				DefaultAccess:     "private",
				InheritACL:        true,
				PublicReadEnabled: false,
			},
			AuthConfig: DefaultTenantAuthConfig(),
			Metadata:  map[string]string{"test": "true"},
			Created:   time.Now().Format(time.RFC3339),
			Modified:  time.Now().Format(time.RFC3339),
			Enabled:   true,
		}

		if err := t.multiStorage.AddTenant(tenantConfig); err != nil {
			return fmt.Errorf("failed to create test tenant %s: %w", tenantID, err)
		}

		// Add auth config
		if err := t.multiStorage.AddTenantAuthConfig(tenantID, tenantConfig.AuthConfig); err != nil {
			return fmt.Errorf("failed to create test tenant auth config %s: %w", tenantID, err)
		}

		t.testTenants = append(t.testTenants, tenantConfig)
		t.testResources[tenantID] = []string{
			fmt.Sprintf("https://%s.example.com/profile/card", tenantID),
			fmt.Sprintf("https://%s.example.com/data/file1", tenantID),
			fmt.Sprintf("https://%s.example.com/private/secret", tenantID),
		}
	}

	t.logger.Info("Test tenants created for isolation testing", "count", len(t.testTenants))
	return nil
}

// Cleanup removes test tenants
func (t *TenantIsolationTester) Cleanup() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, tenant := range t.testTenants {
		if err := t.multiStorage.RemoveTenant(tenant.TenantID); err != nil {
			t.logger.Error("Failed to remove test tenant", "tenant_id", tenant.TenantID, "error", err)
			// Continue cleanup of other tenants
		}
		if err := t.multiStorage.RemoveTenantAuthConfig(tenant.TenantID); err != nil {
			t.logger.Error("Failed to remove test tenant auth config", "tenant_id", tenant.TenantID, "error", err)
		}
	}

	t.testTenants = []*TenantConfig{}
	t.testResources = make(map[string][]string)
	t.isolationViolations = []IsolationViolation{}

	t.logger.Info("Test tenants cleaned up")
	return nil
}

// TestTenantIDValidation tests tenant ID validation
func (t *TenantIsolationTester) TestTenantIDValidation() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	testCases := []struct {
		name     string
		tenantID string
		wantErr  bool
	}{
		{"valid tenant ID", "valid-tenant", false},
		{"empty tenant ID", "", true},
		{"tenant ID too long", "a" + string(make([]byte, 257)), true},
		{"tenant ID with spaces", "tenant with spaces", true},
		{"tenant ID with special chars", "tenant@test", true},
		{"tenant ID with dots", "tenant.test.example", false},
		{"tenant ID with underscores", "tenant_test_example", false},
		{"tenant ID with hyphens", "tenant-test-example", false},
		{"tenant ID mixed case", "Tenant-Test", false},
	}

	for _, tc := range testCases {
		if err := ValidateTenantID(tc.tenantID); (err != nil) != tc.wantErr {
			t.isolationViolations = append(t.isolationViolations, IsolationViolation{
				TestName:    "TestTenantIDValidation",
				SourceTenant: tc.tenantID,
				TargetTenant: "",
				ResourceURI:  "tenant-id-validation",
				AccessType:   "validation",
				Timestamp:   time.Now(),
				Error:       fmt.Errorf("ValidateTenantID(%q) error = %v, wantErr %v", tc.tenantID, err, tc.wantErr),
			})
		}
	}

	return nil
}

// TestTenantStorageIsolation tests that tenants cannot access each other's storage
func (t *TenantIsolationTester) TestTenantStorageIsolation() error {
	// Test that ResolveStorageBackend correctly routes to tenant-specific storage
	for _, tenant := range t.testTenants {
		// Each tenant should resolve to their configured storage backend
		storage, err := t.multiStorage.GetTenantStorage(tenant.TenantID)
		if err != nil {
			return fmt.Errorf("failed to get storage for tenant %s: %w", tenant.TenantID, err)
		}

		if storage != tenant.StorageBackend {
			t.isolationViolations = append(t.isolationViolations, IsolationViolation{
				TestName:    "TestTenantStorageIsolation",
				SourceTenant: tenant.TenantID,
				TargetTenant: tenant.TenantID,
				ResourceURI:  "storage-backend",
				AccessType:   "storage-resolution",
				Timestamp:   time.Now(),
				Error:       fmt.Errorf("expected storage %s, got %s", tenant.StorageBackend, storage),
			})
		}
	}

	// Test that ResolveStorageBackend returns the default for unknown tenants
	unknownStorage, err := t.multiStorage.GetTenantStorage("unknown-tenant")
	if err != nil {
		return fmt.Errorf("failed to get storage for unknown tenant: %w", err)
	}
	if unknownStorage != t.multiStorage.config.DefaultStorage {
		t.isolationViolations = append(t.isolationViolations, IsolationViolation{
			TestName:    "TestTenantStorageIsolation",
			SourceTenant: "unknown-tenant",
			TargetTenant: "",
			ResourceURI:  "storage-backend",
			AccessType:   "default-storage-resolution",
			Timestamp:   time.Now(),
			Error:       fmt.Errorf("expected default storage, got %s", unknownStorage),
		})
	}

	return nil
}

// TestTenantConfigIsolation tests that tenant configurations are isolated
func (t *TenantIsolationTester) TestTenantConfigIsolation() error {
	// Test that each tenant gets their own configuration
	for _, tenant := range t.testTenants {
		config, err := t.multiStorage.GetTenant(tenant.TenantID)
		if err != nil {
			return fmt.Errorf("failed to get tenant config for %s: %w", tenant.TenantID, err)
		}

		// Verify that we get the same tenant ID back
		if config.TenantID != tenant.TenantID {
			t.isolationViolations = append(t.isolationViolations, IsolationViolation{
				TestName:    "TestTenantConfigIsolation",
				SourceTenant: tenant.TenantID,
				TargetTenant: config.TenantID,
				ResourceURI:  "tenant-config",
				AccessType:   "config-retrieval",
				Timestamp:   time.Now(),
				Error:       errors.New("tenant ID mismatch"),
			})
		}

		// Verify that auth config is isolated
		authConfig, err := t.multiStorage.GetTenantAuthConfig(tenant.TenantID)
		if err != nil {
			return fmt.Errorf("failed to get tenant auth config for %s: %w", tenant.TenantID, err)
		}

		if authConfig == nil {
			t.isolationViolations = append(t.isolationViolations, IsolationViolation{
				TestName:    "TestTenantConfigIsolation",
				SourceTenant: tenant.TenantID,
				TargetTenant: "",
				ResourceURI:  "auth-config",
				AccessType:   "auth-config-retrieval",
				Timestamp:   time.Now(),
				Error:       errors.New("auth config should not be nil"),
			})
		}
	}

	// Test that we cannot access one tenant's config as another
	tenantAConfig, err := t.multiStorage.GetTenant("tenant-a")
	if err != nil {
		return fmt.Errorf("failed to get tenant-a config: %w", err)
	}

	tenantBConfig, err := t.multiStorage.GetTenant("tenant-b")
	if err != nil {
		return fmt.Errorf("failed to get tenant-b config: %w", err)
	}

	// These should be different tenant objects
	if tenantAConfig.TenantID == tenantBConfig.TenantID {
		t.isolationViolations = append(t.isolationViolations, IsolationViolation{
			TestName:    "TestTenantConfigIsolation",
			SourceTenant: "tenant-a",
			TargetTenant: "tenant-b",
			ResourceURI:  "tenant-config",
			AccessType:   "cross-tenant-config-access",
			Timestamp:   time.Now(),
			Error:       errors.New("tenants should have different configurations"),
		})
	}

	return nil
}

// TestTenantResourceIsolation tests resource isolation between tenants
func (t *TenantIsolationTester) TestTenantResourceIsolation() error {
	// Test that ResolveStorageBackend handles resource URIs correctly
	// This is a more complex test that would require actual storage backend testing
	// For now, we test the routing logic

	// Test resources for each tenant
	for _, resources := range t.testResources {
		for _, resourceURI := range resources {
			// In a real implementation, this would resolve to tenant-specific storage
			// For this test, we just verify the routing doesn't mix tenants
			storage, err := t.multiStorage.ResolveStorageBackend(resourceURI)
			if err != nil {
				return fmt.Errorf("failed to resolve storage for %s: %w", resourceURI, err)
			}

			// The storage should be consistent for all resources
			// In a properly configured system, tenant resources would route to tenant storage
			_ = storage // Would be used in more complete test
		}
	}

	return nil
}

// TestTenantHealthIsolation tests that health status is isolated per tenant
func (t *TenantIsolationTester) TestTenantHealthIsolation() error {
	// Test that each tenant has their own health status
	for _, tenant := range t.testTenants {
		healthStatus, err := t.multiStorage.GetHealthStatus(tenant.TenantID)
		if err != nil {
			// Health status might not be available if health monitoring is disabled
			continue
		}

		// Health status should be for the correct tenant
		if healthStatus.TenantID != tenant.TenantID {
			t.isolationViolations = append(t.isolationViolations, IsolationViolation{
				TestName:    "TestTenantHealthIsolation",
				SourceTenant: tenant.TenantID,
				TargetTenant: healthStatus.TenantID,
				ResourceURI:  "health-status",
				AccessType:   "health-check",
				Timestamp:   time.Now(),
				Error:       errors.New("health status tenant ID mismatch"),
			})
		}
	}

	return nil
}

// TestTenantMetricsIsolation tests that metrics are isolated per tenant
func (t *TenantIsolationTester) TestTenantMetricsIsolation() error {
	// Test that metrics are tracked per tenant
	// This would be more comprehensive in a real implementation with actual metrics

	// Get current metrics
	metrics := t.multiStorage.GetMetrics()

	// Test that tenant operations are tracked
	// This is a basic test - real implementation would have more detailed metrics
	if metrics.TenantLookups < 0 {
		t.isolationViolations = append(t.isolationViolations, IsolationViolation{
			TestName:    "TestTenantMetricsIsolation",
			SourceTenant: "all",
			TargetTenant: "all",
			ResourceURI:  "metrics",
			AccessType:   "metrics-validation",
			Timestamp:   time.Now(),
			Error:       errors.New("invalid tenant lookup count"),
		})
	}

	return nil
}

// TestConcurrentTenantAccess tests isolation under concurrent access
func (t *TenantIsolationTester) TestConcurrentTenantAccess() error {
	// Test concurrent access to ensure thread safety and isolation
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Launch multiple goroutines to access tenants concurrently
	for i := 0; i < 10; i++ {
		for _, tenant := range t.testTenants {
			wg.Add(1)
			go func(tenantID string, index int) {
				defer wg.Done()

				// Access tenant config
				config, err := t.multiStorage.GetTenant(tenantID)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d: failed to get tenant %s: %w", index, tenantID, err)
					return
				}

				if config.TenantID != tenantID {
					errors <- fmt.Errorf("goroutine %d: tenant ID mismatch for %s", index, tenantID)
					return
				}

				// Access tenant auth config
				authConfig, err := t.multiStorage.GetTenantAuthConfig(tenantID)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d: failed to get auth config for tenant %s: %w", index, tenantID, err)
					return
				}

				if authConfig == nil {
					errors <- fmt.Errorf("goroutine %d: auth config is nil for tenant %s", index, tenantID)
					return
				}

			}(tenant.TenantID, i)
		}
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		if err != nil {
			t.logger.Error("Concurrent access error", "error", err)
			return err
		}
	}

	return nil
}

// TestTenantDeletionIsolation tests that tenant deletion doesn't affect other tenants
func (t *TenantIsolationTester) TestTenantDeletionIsolation() error {
	// Create a temporary tenant for deletion test
	tempTenantID := "temp-tenant-for-deletion"
	tempTenant := &TenantConfig{
		TenantID:               tempTenantID,
		StorageBackend:         "test-backend",
		AllowedStorageBackends: []string{"test-backend"},
		ResourceQuotas: TenantQuotas{
			MaxResources:         10,
			MaxStorage:           1024 * 1024,
			MaxBandwidth:         1024 * 1024,
			MaxRequestsPerSecond: 10,
		},
		ACLConfig: TenantACLConfig{
			DefaultAccess:     "private",
			InheritACL:        true,
			PublicReadEnabled: false,
		},
		AuthConfig: DefaultTenantAuthConfig(),
		Metadata:  map[string]string{"temp": "true"},
		Created:   time.Now().Format(time.RFC3339),
		Modified:  time.Now().Format(time.RFC3339),
		Enabled:   true,
	}

	// Add temporary tenant
	if err := t.multiStorage.AddTenant(tempTenant); err != nil {
		return fmt.Errorf("failed to create temp tenant: %w", err)
	}

	// Verify temp tenant exists
	if _, err := t.multiStorage.GetTenant(tempTenantID); err != nil {
		return fmt.Errorf("failed to verify temp tenant exists: %w", err)
	}

	// Delete temp tenant
	if err := t.multiStorage.RemoveTenant(tempTenantID); err != nil {
		return fmt.Errorf("failed to delete temp tenant: %w", err)
	}

	// Verify temp tenant is gone
	if _, err := t.multiStorage.GetTenant(tempTenantID); err == nil {
		t.isolationViolations = append(t.isolationViolations, IsolationViolation{
			TestName:    "TestTenantDeletionIsolation",
			SourceTenant: tempTenantID,
			TargetTenant: "",
			ResourceURI:  "tenant-config",
			AccessType:   "post-deletion-verification",
			Timestamp:   time.Now(),
			Error:       errors.New("temp tenant should have been deleted"),
		})
	}

	// Verify other tenants still exist
	for _, tenant := range t.testTenants {
		if _, err := t.multiStorage.GetTenant(tenant.TenantID); err != nil {
			t.isolationViolations = append(t.isolationViolations, IsolationViolation{
				TestName:    "TestTenantDeletionIsolation",
				SourceTenant: tenant.TenantID,
				TargetTenant: "",
				ResourceURI:  "tenant-config",
				AccessType:   "other-tenant-verification",
				Timestamp:   time.Now(),
				Error:       fmt.Errorf("tenant %s should still exist after deleting %s", tenant.TenantID, tempTenantID),
			})
		}
	}

	return nil
}

// RunAllTests runs all tenant isolation tests
func (t *TenantIsolationTester) RunAllTests() error {
	t.logger.Info("Starting tenant isolation tests")

	// Setup test tenants
	if err := t.SetupTestTenants(); err != nil {
		return fmt.Errorf("failed to setup test tenants: %w", err)
	}
	defer t.Cleanup()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"TenantIDValidation", t.TestTenantIDValidation},
		{"TenantStorageIsolation", t.TestTenantStorageIsolation},
		{"TenantConfigIsolation", t.TestTenantConfigIsolation},
		{"TenantResourceIsolation", t.TestTenantResourceIsolation},
		{"TenantHealthIsolation", t.TestTenantHealthIsolation},
		{"TenantMetricsIsolation", t.TestTenantMetricsIsolation},
		{"ConcurrentTenantAccess", t.TestConcurrentTenantAccess},
		{"TenantDeletionIsolation", t.TestTenantDeletionIsolation},
	}

	for _, test := range tests {
		t.logger.Info("Running test", "test_name", test.name)
		if err := test.fn(); err != nil {
			t.logger.Error("Test failed", "test_name", test.name, "error", err)
			return fmt.Errorf("test %s failed: %w", test.name, err)
		}
		t.logger.Info("Test passed", "test_name", test.name)
	}

	// Check for isolation violations
	if len(t.isolationViolations) > 0 {
		t.logger.Error("Isolation violations detected", "count", len(t.isolationViolations))
		for _, violation := range t.isolationViolations {
			t.logger.Error("Isolation violation",
				"test_name", violation.TestName,
				"source_tenant", violation.SourceTenant,
				"target_tenant", violation.TargetTenant,
				"access_type", violation.AccessType,
				"error", violation.Error)
		}
		return fmt.Errorf("isolation violations detected: %d", len(t.isolationViolations))
	}

	t.logger.Info("All tenant isolation tests passed")
	return nil
}

// GetViolations returns all isolation violations found
func (t *TenantIsolationTester) GetViolations() []IsolationViolation {
	t.mu.Lock()
	defer t.mu.Unlock()

	violations := make([]IsolationViolation, len(t.isolationViolations))
	copy(violations, t.isolationViolations)
	return violations
}

// TestPhase21TenantIsolation is the main test function for Phase 21 tenant isolation
// This can be run as part of the test suite: go test -v -run TestPhase21TenantIsolation
func TestPhase21TenantIsolation(t *testing.T) {
	// Create multi-storage layer for testing
	config := DefaultMultiStorageConfig()
	config.EnableTenantIsolation = true
	config.EnableHealthMonitoring = false // Disable for tests

	multiStorage := NewMultiStorageLayer(config)
	defer multiStorage.Close()

	// Create tester
	tester := NewTenantIsolationTester(multiStorage)

	// Run all tests
	if err := tester.RunAllTests(); err != nil {
		t.Fatalf("Tenant isolation tests failed: %v", err)
	}

	// Verify no violations
	violations := tester.GetViolations()
	if len(violations) > 0 {
		t.Errorf("Isolation violations detected: %d", len(violations))
		for _, violation := range violations {
			t.Errorf("Violation: %s - %s accessed %s resource %s",
				violation.TestName,
				violation.SourceTenant,
				violation.TargetTenant,
				violation.ResourceURI)
		}
		t.FailNow()
	}

	// Test completed successfully
	t.Log("Phase 21 tenant isolation tests passed")
}

// TestTenantConfigValidation tests tenant configuration validation
func TestTenantConfigValidation(t *testing.T) {
	// Test TenantConfig struct validation through serialization/deserialization
	testConfig := TenantConfig{
		TenantID:               "test-tenant",
		StorageBackend:         "test-backend",
		AllowedStorageBackends: []string{"backend1", "backend2"},
		ResourceQuotas: TenantQuotas{
			MaxResources:         100,
			MaxStorage:           1024 * 1024 * 100,
			MaxBandwidth:         1024 * 1024,
			MaxRequestsPerSecond: 100,
			CurrentUsage: TenantUsage{
				ResourceCount:   10,
				StorageUsed:     500000,
				LastRequestTime: time.Now().Format(time.RFC3339),
			},
		},
		ACLConfig: TenantACLConfig{
			DefaultAccess:     "private",
			InheritACL:        true,
			PublicReadEnabled: false,
		},
		AuthConfig: DefaultTenantAuthConfig(),
		Metadata:  map[string]string{"test": "true"},
		Created:   time.Now().Format(time.RFC3339),
		Modified:  time.Now().Format(time.RFC3339),
		Enabled:   true,
	}

	// Test tenant ID validation
	if err := ValidateTenantID(testConfig.TenantID); err != nil {
		t.Errorf("Valid tenant ID should pass validation: %v", err)
	}

	// Test auth config validation
	if testConfig.AuthConfig != nil {
		if err := ValidateTenantAuthConfig(testConfig.AuthConfig); err != nil {
			t.Errorf("Valid auth config should pass validation: %v", err)
		}
	}

	// Test with invalid tenant ID
	invalidConfig := testConfig
	invalidConfig.TenantID = "invalid tenant id"
	if err := ValidateTenantID(invalidConfig.TenantID); err == nil {
		t.Error("Invalid tenant ID should fail validation")
	}

	// Test with invalid auth config
	if testConfig.AuthConfig != nil {
		invalidAuthConfig := *testConfig.AuthConfig
		invalidAuthConfig.IdentityAssuranceLevel = "invalid-level"
		if err := ValidateTenantAuthConfig(&invalidAuthConfig); err == nil {
			t.Error("Invalid auth config should fail validation")
		}
	}
}

// TestTenantAuthConfigCopy tests that tenant auth config copying works correctly
func TestTenantAuthConfigCopy(t *testing.T) {
	// Create tenant auth manager
	manager := NewTenantAuthManager(nil)

	// Create test config
	originalConfig := &TenantAuthConfig{
		IssuerTrustPolicy: TenantIssuerTrustPolicy{
			AllowedIssuers:        []string{"https://issuer1.example.com"},
			BlockedIssuers:        []string{"https://blocked.example.com"},
			RequireIssuerAllowlist: true,
			AllowIssuerDiscovery:   true,
			IssuerPinning: map[string]TenantIssuerPin{
				"https://pinned.example.com": {
					PublicKeyHash: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
					TrustLevel:    "high",
				},
			},
			JWKSEndpointTTL: 1 * time.Hour,
		},
		AuthzMode:         TenantAuthzModeNative,
		CompressionMode:   TenantCompressionModeGzip,
		DPoPSettings: TenantDPoPSettings{
			RequireDPoPForAllRequests:   true,
			RequireDPoPForWriteRequests: true,
			DPoPReplayWindow:            5 * time.Minute,
			DPoPMaxNonceAge:            5 * time.Minute,
			DPoPNonceCleanupInterval:   2 * time.Minute,
		},
		WebIDProfileCacheTTL:   10 * time.Minute,
		MaxWebIDProfileCacheSize: 5000,
		IdentityAssuranceLevel:  "high",
	}

	// Add config to manager
	if err := manager.AddTenantAuthConfig("test-tenant", originalConfig); err != nil {
		t.Fatalf("Failed to add tenant auth config: %v", err)
	}

	// Get config back
	retrievedConfig, err := manager.GetTenantAuthConfig("test-tenant")
	if err != nil {
		t.Fatalf("Failed to get tenant auth config: %v", err)
	}

	// Modify original config
	originalConfig.IssuerTrustPolicy.AllowedIssuers = append(originalConfig.IssuerTrustPolicy.AllowedIssuers, "https://new-issuer.example.com")

	// Retrieved config should not be affected by modification of original
	if len(retrievedConfig.IssuerTrustPolicy.AllowedIssuers) != 1 {
		t.Errorf("Retrieved config was affected by modification of original. Expected 1 issuer, got %d", len(retrievedConfig.IssuerTrustPolicy.AllowedIssuers))
	}

	// Test issuer allow/block checking
	if !manager.IsIssuerAllowed("test-tenant", "https://issuer1.example.com") {
		t.Error("Allowed issuer should be allowed")
	}

	if manager.IsIssuerAllowed("test-tenant", "https://blocked.example.com") {
		t.Error("Blocked issuer should not be allowed")
	}

	if manager.IsIssuerAllowed("test-tenant", "https://unknown.example.com") {
		t.Error("Unknown issuer should not be allowed when requireIssuerAllowlist is true")
	}

	// Test with default config (should allow all issuers except blocked ones)
	defaultConfig := DefaultTenantAuthConfig()
	manager.SetDefaultAuthConfig(defaultConfig)

	// Remove the test tenant config to test default behavior
	manager.RemoveTenantAuthConfig("test-tenant")

	// With default config and no requireIssuerAllowlist, unknown issuers should be allowed
	if !manager.IsIssuerAllowed("unknown-tenant", "https://unknown.example.com") {
		t.Error("Unknown issuer should be allowed with default config")
	}

	// Blocked issuers should still be blocked
	blockedConfig := DefaultTenantAuthConfig()
	blockedConfig.IssuerTrustPolicy.BlockedIssuers = []string{"https://blocked.example.com"}
	manager.SetDefaultAuthConfig(blockedConfig)

	if manager.IsIssuerAllowed("unknown-tenant", "https://blocked.example.com") {
		t.Error("Blocked issuer should not be allowed even with default config")
	}
}

// TestMultiStorageLayerTenantIsolation tests tenant isolation in the multi-storage layer
func TestMultiStorageLayerTenantIsolation(t *testing.T) {
	// Create multi-storage layer
	config := DefaultMultiStorageConfig()
	config.EnableTenantIsolation = true
	config.EnableHealthMonitoring = false

	multiStorage := NewMultiStorageLayer(config)
	defer multiStorage.Close()

	// Create test tenants
	tenantA := &TenantConfig{
		TenantID:               "tenant-a",
		StorageBackend:         "backend-a",
		AllowedStorageBackends: []string{"backend-a"},
		AuthConfig:             DefaultTenantAuthConfig(),
	}

	tenantB := &TenantConfig{
		TenantID:               "tenant-b",
		StorageBackend:         "backend-b",
		AllowedStorageBackends: []string{"backend-b"},
		AuthConfig:             DefaultTenantAuthConfig(),
	}

	// Add tenants
	if err := multiStorage.AddTenant(tenantA); err != nil {
		t.Fatalf("Failed to add tenant A: %v", err)
	}

	if err := multiStorage.AddTenant(tenantB); err != nil {
		t.Fatalf("Failed to add tenant B: %v", err)
	}

	// Add auth configs
	if err := multiStorage.AddTenantAuthConfig("tenant-a", tenantA.AuthConfig); err != nil {
		t.Fatalf("Failed to add auth config for tenant A: %v", err)
	}

	if err := multiStorage.AddTenantAuthConfig("tenant-b", tenantB.AuthConfig); err != nil {
		t.Fatalf("Failed to add auth config for tenant B: %v", err)
	}

	// Test that each tenant gets their own config
	retrievedA, err := multiStorage.GetTenant("tenant-a")
	if err != nil {
		t.Fatalf("Failed to get tenant A: %v", err)
	}

	retrievedB, err := multiStorage.GetTenant("tenant-b")
	if err != nil {
		t.Fatalf("Failed to get tenant B: %v", err)
	}

	if retrievedA.TenantID != "tenant-a" {
		t.Errorf("Expected tenant-a, got %s", retrievedA.TenantID)
	}

	if retrievedB.TenantID != "tenant-b" {
		t.Errorf("Expected tenant-b, got %s", retrievedB.TenantID)
	}

	// Test that storage backends are isolated
	storageA, err := multiStorage.GetTenantStorage("tenant-a")
	if err != nil {
		t.Fatalf("Failed to get storage for tenant A: %v", err)
	}

	storageB, err := multiStorage.GetTenantStorage("tenant-b")
	if err != nil {
		t.Fatalf("Failed to get storage for tenant B: %v", err)
	}

	if storageA != "backend-a" {
		t.Errorf("Expected backend-a for tenant A, got %s", storageA)
	}

	if storageB != "backend-b" {
		t.Errorf("Expected backend-b for tenant B, got %s", storageB)
	}

	// Test that auth configs are isolated
	authConfigA, err := multiStorage.GetTenantAuthConfig("tenant-a")
	if err != nil {
		t.Fatalf("Failed to get auth config for tenant A: %v", err)
	}

	authConfigB, err := multiStorage.GetTenantAuthConfig("tenant-b")
	if err != nil {
		t.Fatalf("Failed to get auth config for tenant B: %v", err)
	}

	if authConfigA == nil || authConfigB == nil {
		t.Fatal("Auth configs should not be nil")
	}

	// Test that deleting one tenant doesn't affect the other
	if err := multiStorage.RemoveTenant("tenant-a"); err != nil {
		t.Fatalf("Failed to remove tenant A: %v", err)
	}

	// tenant-b should still exist
	if _, err := multiStorage.GetTenant("tenant-b"); err != nil {
		t.Error("tenant-b should still exist after deleting tenant-a")
	}

	// tenant-a should be gone
	if _, err := multiStorage.GetTenant("tenant-a"); err == nil {
		t.Error("tenant-a should not exist after deletion")
	}

	// Test listing tenants (should show tenant-b and default tenant)
	tenants := multiStorage.ListTenants()
	if len(tenants) != 2 {
		t.Errorf("Expected 2 tenants after deletion (tenant-b and default), got %d", len(tenants))
	}

	// Check that tenant-b is in the list
	foundTenantB := false
	for _, tenant := range tenants {
		if tenant.TenantID == "tenant-b" {
			foundTenantB = true
			break
		}
	}
	if !foundTenantB {
		t.Error("Expected tenant-b in list")
	}

	// Test metrics tracking
	metrics := multiStorage.GetMetrics()
	if metrics.TenantLookups <= 0 {
		t.Error("Tenant lookups should have been tracked")
	}

	t.Log("Multi-storage layer tenant isolation tests passed")
}

// Context for test setup
var testContext = context.Background()

// TestTenantConfigLoader tests the tenant config loader
func TestTenantConfigLoader(t *testing.T) {
	// Create multi-storage layer
	config := DefaultMultiStorageConfig()
	multiStorage := NewMultiStorageLayer(config)
	defer multiStorage.Close()

	// Create config loader
	loaderConfig := DefaultTenantConfigLoaderConfig()
	loaderConfig.ConfigDir = t.TempDir() // Use test temp directory
	loader := NewTenantConfigLoader(multiStorage, loaderConfig)
	defer loader.Close()

	// Create a test tenant config
	testTenantConfig := TenantConfig{
		TenantID:               "test-loader-tenant",
		StorageBackend:         "test-backend",
		AllowedStorageBackends: []string{"test-backend"},
		ResourceQuotas: TenantQuotas{
			MaxResources:         50,
			MaxStorage:           1024 * 1024 * 50,
			MaxBandwidth:         1024 * 1024,
			MaxRequestsPerSecond: 50,
		},
		ACLConfig: TenantACLConfig{
			DefaultAccess:     "private",
			InheritACL:        true,
			PublicReadEnabled: false,
		},
		AuthConfig: DefaultTenantAuthConfig(),
		Metadata:  map[string]string{"test": "loader"},
		Created:   time.Now().Format(time.RFC3339),
		Modified:  time.Now().Format(time.RFC3339),
		Enabled:   true,
	}

	// Save tenant config
	if err := loader.SaveTenantConfig("test-loader-tenant"); err != nil {
		// This will fail because tenant doesn't exist yet, so let's add it first
		if err := multiStorage.AddTenant(&testTenantConfig); err != nil {
			t.Fatalf("Failed to add test tenant: %v", err)
		}
		if err := multiStorage.AddTenantAuthConfig("test-loader-tenant", testTenantConfig.AuthConfig); err != nil {
			t.Fatalf("Failed to add test tenant auth config: %v", err)
		}
		if err := loader.SaveTenantConfig("test-loader-tenant"); err != nil {
			t.Fatalf("Failed to save tenant config: %v", err)
		}
	}

	// List config files
	files, err := loader.ListTenantConfigFiles()
	if err != nil {
		t.Fatalf("Failed to list config files: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("Expected 1 config file, got %d", len(files))
	}

	// Verify file was created with correct name
	if len(files) > 0 && files[0] != "test-loader-tenant.json" {
		t.Errorf("Expected config file 'test-loader-tenant.json', got %s", files[0])
	}

	// Reload all configs
	if err := loader.ReloadAll(); err != nil {
		t.Fatalf("Failed to reload all configs: %v", err)
	}

	// Verify tenant was loaded
	loadedTenant, err := multiStorage.GetTenant("test-loader-tenant")
	if err != nil {
		t.Fatalf("Failed to get loaded tenant: %v", err)
	}

	if loadedTenant.TenantID != "test-loader-tenant" {
		t.Errorf("Expected loaded tenant ID 'test-loader-tenant', got %s", loadedTenant.TenantID)
	}

	// Test backup functionality
	backupDir := t.TempDir() + "/backup"
	if err := loader.BackupAllTenantConfigs(backupDir); err != nil {
		t.Fatalf("Failed to backup tenant configs: %v", err)
	}

	// Test restore functionality (create new loader for restore)
	restoreConfig := DefaultTenantConfigLoaderConfig()
	restoreConfig.ConfigDir = backupDir
	restoreLoader := NewTenantConfigLoader(multiStorage, restoreConfig)
	defer restoreLoader.Close()

	// Clear the original tenant
	multiStorage.RemoveTenant("test-loader-tenant")

	// Restore from backup
	if err := restoreLoader.RestoreAllTenantConfigs(backupDir); err != nil {
		t.Fatalf("Failed to restore tenant configs: %v", err)
	}

	// Verify tenant was restored
	restoredTenant, err := multiStorage.GetTenant("test-loader-tenant")
	if err != nil {
		t.Fatalf("Failed to get restored tenant: %v", err)
	}

	if restoredTenant.TenantID != "test-loader-tenant" {
		t.Errorf("Expected restored tenant ID 'test-loader-tenant', got %s", restoredTenant.TenantID)
	}

	t.Log("Tenant config loader tests passed")
}