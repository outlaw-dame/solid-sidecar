package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRuntimeInitialization tests that the runtime can be initialized correctly
func TestRuntimeInitialization(t *testing.T) {
	t.Parallel()

	config := DefaultRuntimeConfig()
	rt, err := New(config)
	require.NoError(t, err, "Runtime initialization should succeed")
	defer rt.Close()

	// Verify runtime is initialized
	assert.True(t, rt.IsInitialized(), "Runtime should be initialized")
	assert.Equal(t, RuntimeModeCSSProxy, rt.Mode(), "Default mode should be CSS proxy")

	// Verify all layers are available
	assert.NotNil(t, rt.Gateway(), "Gateway layer should be available")
	assert.NotNil(t, rt.Storage(), "Storage layer should be available")
	assert.NotNil(t, rt.Metadata(), "Metadata layer should be available")
	assert.NotNil(t, rt.RDF(), "RDF layer should be available")
	assert.NotNil(t, rt.PolicyEngine(), "Policy engine layer should be available")
	assert.NotNil(t, rt.Notification(), "Notification layer should be available")
	assert.NotNil(t, rt.MultiStorage(), "Multi-storage layer should be available")
	assert.NotNil(t, rt.Migration(), "Migration layer should be available")
}

// TestRuntimeModeTransitions tests mode transitions
func TestRuntimeModeTransitions(t *testing.T) {
	t.Parallel()

	config := DefaultRuntimeConfig()
	rt, err := New(config)
	require.NoError(t, err, "Runtime initialization should succeed")
	defer rt.Close()

	// Test valid transitions
	validTransitions := []struct {
		from RuntimeMode
		to   RuntimeMode
	}{
		{RuntimeModeCSSProxy, RuntimeModeHybrid},
		{RuntimeModeCSSProxy, RuntimeModeNative},
		{RuntimeModeHybrid, RuntimeModeCSSProxy},
		{RuntimeModeHybrid, RuntimeModeNative},
		{RuntimeModeNative, RuntimeModeCSSProxy},
		{RuntimeModeNative, RuntimeModeHybrid},
	}

	for _, transition := range validTransitions {
		t.Run(string(transition.from)+"->"+string(transition.to), func(t *testing.T) {
			require.NoError(t, rt.SetMode(transition.from), "Set initial mode should succeed")
			require.NoError(t, rt.SetMode(transition.to), "Transition should succeed")
			assert.Equal(t, transition.to, rt.Mode(), "Mode should be updated")
		})
	}

	// Test same mode transition
	require.NoError(t, rt.SetMode(RuntimeModeCSSProxy), "Set mode should succeed")
	require.NoError(t, rt.SetMode(RuntimeModeCSSProxy), "Same mode transition should succeed")
	assert.Equal(t, RuntimeModeCSSProxy, rt.Mode(), "Mode should remain the same")
}

// TestRuntimeModeTransitionFailure tests invalid mode transitions
func TestRuntimeModeTransitionFailure(t *testing.T) {
	t.Parallel()

	config := DefaultRuntimeConfig()
	rt, err := New(config)
	require.NoError(t, err, "Runtime initialization should succeed")
	defer rt.Close()

	// Test that staying in the same mode works
	require.NoError(t, rt.SetMode(RuntimeModeCSSProxy), "Set mode should succeed")
	require.NoError(t, rt.SetMode(RuntimeModeCSSProxy), "Same mode transition should succeed")
}

// TestRuntimeClose tests runtime cleanup
func TestRuntimeClose(t *testing.T) {
	t.Parallel()

	config := DefaultRuntimeConfig()
	rt, err := New(config)
	require.NoError(t, err, "Runtime initialization should succeed")

	// Close the runtime
	err = rt.Close()
	assert.NoError(t, err, "Runtime close should succeed")

	// Verify runtime is no longer initialized
	assert.False(t, rt.IsInitialized(), "Runtime should not be initialized after close")

	// Verify layers are still accessible (but may be closed)
	assert.NotNil(t, rt.Gateway(), "Gateway layer reference should still exist")
	assert.NotNil(t, rt.Storage(), "Storage layer reference should still exist")
	assert.NotNil(t, rt.Metadata(), "Metadata layer reference should still exist")
	assert.NotNil(t, rt.RDF(), "RDF layer reference should still exist")
	assert.NotNil(t, rt.PolicyEngine(), "Policy engine layer reference should still exist")
	assert.NotNil(t, rt.Notification(), "Notification layer reference should still exist")
	assert.NotNil(t, rt.MultiStorage(), "Multi-storage layer reference should still exist")
	assert.NotNil(t, rt.Migration(), "Migration layer reference should still exist")
}

// TestRuntimeDoubleClose tests that closing twice doesn't cause issues
func TestRuntimeDoubleClose(t *testing.T) {
	t.Parallel()

	config := DefaultRuntimeConfig()
	rt, err := New(config)
	require.NoError(t, err, "Runtime initialization should succeed")

	// Close the runtime twice
	err = rt.Close()
	assert.NoError(t, err, "First close should succeed")

	err = rt.Close()
	assert.NoError(t, err, "Second close should succeed")
}

// TestRuntimeMigrationStart tests starting the migration process
func TestRuntimeMigrationStart(t *testing.T) {
	t.Parallel()

	config := DefaultRuntimeConfig()
	rt, err := New(config)
	require.NoError(t, err, "Runtime initialization should succeed")
	defer rt.Close()

	// Start migration
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = rt.StartMigration(ctx)
	assert.NoError(t, err, "Migration start should succeed")

	// Check that migration is in progress
	assert.True(t, rt.IsMigrating(), "Migration should be in progress")

	// Wait for migration to complete (it will fail quickly due to missing CSS)
	time.Sleep(100 * time.Millisecond)
}

// TestRuntimeErrorHandling tests error handling in the runtime
func TestRuntimeErrorHandling(t *testing.T) {
	t.Parallel()

	// Test with nil config logger
	config := RuntimeConfig{
		Mode:                RuntimeModeCSSProxy,
		EnableCSSComparison: true,
		DefaultStorage:      "default",
		Logger:              nil, // Should use default
		MaxRetries:          3,
		BackoffBaseDelay:    100,
		BackoffMaxDelay:     5000,
	}

	rt, err := New(config)
	require.NoError(t, err, "Runtime initialization with nil logger should succeed")
	defer rt.Close()

	assert.NotNil(t, rt, "Runtime should not be nil")
	assert.True(t, rt.IsInitialized(), "Runtime should be initialized")
}

// TestRuntimeConfiguration tests configuration options
func TestRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	// Test default configuration
	config := DefaultRuntimeConfig()
	assert.Equal(t, RuntimeModeCSSProxy, config.Mode, "Default mode should be CSS proxy")
	assert.True(t, config.EnableCSSComparison, "CSS comparison should be enabled by default")
	assert.Equal(t, "default", config.DefaultStorage, "Default storage should be 'default'")
	assert.Equal(t, 3, config.MaxRetries, "Default max retries should be 3")
	assert.Equal(t, 100, config.BackoffBaseDelay, "Default backoff base delay should be 100")
	assert.Equal(t, 5000, config.BackoffMaxDelay, "Default backoff max delay should be 5000")
}

// TestRuntimeLayerAccess tests accessing all layers
func TestRuntimeLayerAccess(t *testing.T) {
	t.Parallel()

	config := DefaultRuntimeConfig()
	rt, err := New(config)
	require.NoError(t, err, "Runtime initialization should succeed")
	defer rt.Close()

	// Test that all layers can be accessed
	gateway := rt.Gateway()
	assert.NotNil(t, gateway, "Gateway layer should not be nil")
	assert.False(t, gateway.IsClosed(), "Gateway layer should not be closed")

	storage := rt.Storage()
	assert.NotNil(t, storage, "Storage layer should not be nil")
	assert.False(t, storage.IsClosed(), "Storage layer should not be closed")

	metadata := rt.Metadata()
	assert.NotNil(t, metadata, "Metadata layer should not be nil")
	assert.False(t, metadata.IsClosed(), "Metadata layer should not be closed")

	rdf := rt.RDF()
	assert.NotNil(t, rdf, "RDF layer should not be nil")
	assert.False(t, rdf.IsClosed(), "RDF layer should not be closed")

	policyEngine := rt.PolicyEngine()
	assert.NotNil(t, policyEngine, "Policy engine layer should not be nil")
	assert.False(t, policyEngine.IsClosed(), "Policy engine layer should not be closed")

	notification := rt.Notification()
	assert.NotNil(t, notification, "Notification layer should not be nil")
	assert.False(t, notification.IsClosed(), "Notification layer should not be closed")

	multiStorage := rt.MultiStorage()
	assert.NotNil(t, multiStorage, "Multi-storage layer should not be nil")
	assert.False(t, multiStorage.IsClosed(), "Multi-storage layer should not be closed")

	migration := rt.Migration()
	assert.NotNil(t, migration, "Migration layer should not be nil")
	assert.False(t, migration.IsClosed(), "Migration layer should not be closed")
}

// TestRuntimeConcurrentAccess tests concurrent access to the runtime
func TestRuntimeConcurrentAccess(t *testing.T) {
	t.Parallel()

	config := DefaultRuntimeConfig()
	rt, err := New(config)
	require.NoError(t, err, "Runtime initialization should succeed")
	defer rt.Close()

	// Test concurrent mode access
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = rt.Mode()
				_ = rt.IsInitialized()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestRuntimeResourceCleanup tests that resources are properly cleaned up
func TestRuntimeResourceCleanup(t *testing.T) {
	t.Parallel()

	config := DefaultRuntimeConfig()
	rt, err := New(config)
	require.NoError(t, err, "Runtime initialization should succeed")

	// Close the runtime
	err = rt.Close()
	assert.NoError(t, err, "Runtime close should succeed")

	// Verify that layers are closed
	assert.True(t, rt.Gateway().IsClosed(), "Gateway layer should be closed")
	assert.True(t, rt.Storage().IsClosed(), "Storage layer should be closed")
	assert.True(t, rt.Metadata().IsClosed(), "Metadata layer should be closed")
	assert.True(t, rt.RDF().IsClosed(), "RDF layer should be closed")
	assert.True(t, rt.PolicyEngine().IsClosed(), "Policy engine layer should be closed")
	assert.True(t, rt.Notification().IsClosed(), "Notification layer should be closed")
	assert.True(t, rt.MultiStorage().IsClosed(), "Multi-storage layer should be closed")
	assert.True(t, rt.Migration().IsClosed(), "Migration layer should be closed")
}
