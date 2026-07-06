package observability

import (
	"context"
	"testing"
	"time"
)

func TestDefaultPerformanceBaselines(t *testing.T) {
	baselines := DefaultPerformanceBaselines()

	// Verify HTTP baselines
	if baselines.HTTP.MaxAvgDuration != 0.5 {
		t.Errorf("Expected HTTP.MaxAvgDuration to be 0.5, got %f", baselines.HTTP.MaxAvgDuration)
	}
	if baselines.HTTP.MaxP95Duration != 1.0 {
		t.Errorf("Expected HTTP.MaxP95Duration to be 1.0, got %f", baselines.HTTP.MaxP95Duration)
	}
	if baselines.HTTP.MaxP99Duration != 2.0 {
		t.Errorf("Expected HTTP.MaxP99Duration to be 2.0, got %f", baselines.HTTP.MaxP99Duration)
	}
	if baselines.HTTP.MaxErrorRate != 0.01 {
		t.Errorf("Expected HTTP.MaxErrorRate to be 0.01, got %f", baselines.HTTP.MaxErrorRate)
	}

	// Verify AuthZ baselines
	if baselines.AuthZ.MaxAvgEvalTime != 0.01 {
		t.Errorf("Expected AuthZ.MaxAvgEvalTime to be 0.01, got %f", baselines.AuthZ.MaxAvgEvalTime)
	}
	if baselines.AuthZ.MaxP95EvalTime != 0.05 {
		t.Errorf("Expected AuthZ.MaxP95EvalTime to be 0.05, got %f", baselines.AuthZ.MaxP95EvalTime)
	}
	if baselines.AuthZ.MinCacheHitRate != 0.9 {
		t.Errorf("Expected AuthZ.MinCacheHitRate to be 0.9, got %f", baselines.AuthZ.MinCacheHitRate)
	}
	if baselines.AuthZ.MaxMismatchRate != 0.001 {
		t.Errorf("Expected AuthZ.MaxMismatchRate to be 0.001, got %f", baselines.AuthZ.MaxMismatchRate)
	}

	// Verify Cache baselines
	if baselines.Cache.MinHitRate != 0.85 {
		t.Errorf("Expected Cache.MinHitRate to be 0.85, got %f", baselines.Cache.MinHitRate)
	}

	// Verify Transport baselines
	if baselines.Transport.MaxAvgSyncTime != 1.0 {
		t.Errorf("Expected Transport.MaxAvgSyncTime to be 1.0, got %f", baselines.Transport.MaxAvgSyncTime)
	}
	if baselines.Transport.MaxFailureRate != 0.01 {
		t.Errorf("Expected Transport.MaxFailureRate to be 0.01, got %f", baselines.Transport.MaxFailureRate)
	}

	// Verify Runtime baselines
	if baselines.Runtime.MaxGoroutines != 10000 {
		t.Errorf("Expected Runtime.MaxGoroutines to be 10000, got %d", baselines.Runtime.MaxGoroutines)
	}
	if baselines.Runtime.MaxMemoryUsage != 8*1024*1024*1024 {
		t.Errorf("Expected Runtime.MaxMemoryUsage to be 8GB, got %d", baselines.Runtime.MaxMemoryUsage)
	}
	if baselines.Runtime.MaxGCPause != 0.1 {
		t.Errorf("Expected Runtime.MaxGCPause to be 0.1, got %f", baselines.Runtime.MaxGCPause)
	}
	if baselines.Runtime.MaxCPUUtilization != 0.9 {
		t.Errorf("Expected Runtime.MaxCPUUtilization to be 0.9, got %f", baselines.Runtime.MaxCPUUtilization)
	}
}

func TestDefaultBottleneckThresholds(t *testing.T) {
	thresholds := DefaultBottleneckThresholds()

	// Verify HTTP thresholds
	if thresholds.HTTP.HighLatencyThreshold != 1.0 {
		t.Errorf("Expected HTTP.HighLatencyThreshold to be 1.0, got %f", thresholds.HTTP.HighLatencyThreshold)
	}
	if thresholds.HTTP.HighErrorRateThreshold != 0.01 {
		t.Errorf("Expected HTTP.HighErrorRateThreshold to be 0.01, got %f", thresholds.HTTP.HighErrorRateThreshold)
	}

	// Verify Runtime thresholds
	if thresholds.Runtime.HighGoroutineThreshold != 10000 {
		t.Errorf("Expected Runtime.HighGoroutineThreshold to be 10000, got %d", thresholds.Runtime.HighGoroutineThreshold)
	}
	if thresholds.Runtime.HighMemoryThreshold != 8*1024*1024*1024 {
		t.Errorf("Expected Runtime.HighMemoryThreshold to be 8GB, got %d", thresholds.Runtime.HighMemoryThreshold)
	}
	if thresholds.Runtime.HighGCPauseThreshold != 0.1 {
		t.Errorf("Expected Runtime.HighGCPauseThreshold to be 0.1, got %f", thresholds.Runtime.HighGCPauseThreshold)
	}
}

func TestDefaultSLADefinitions(t *testing.T) {
	defs := DefaultSLADefinitions()

	// Verify Availability SLA
	if defs.Availability.Target != 0.999 {
		t.Errorf("Expected Availability.Target to be 0.999, got %f", defs.Availability.Target)
	}
	if defs.Availability.ErrorBudget != 0.001 {
		t.Errorf("Expected Availability.ErrorBudget to be 0.001, got %f", defs.Availability.ErrorBudget)
	}

	// Verify Latency SLA
	if defs.Latency.P50Target != 0.01 {
		t.Errorf("Expected Latency.P50Target to be 0.01, got %f", defs.Latency.P50Target)
	}
	if defs.Latency.P95Target != 0.1 {
		t.Errorf("Expected Latency.P95Target to be 0.1, got %f", defs.Latency.P95Target)
	}
	if defs.Latency.P99Target != 0.5 {
		t.Errorf("Expected Latency.P99Target to be 0.5, got %f", defs.Latency.P99Target)
	}
}

func TestDefaultTuningParameters(t *testing.T) {
	params := DefaultTuningParameters()

	// Verify RateLimit parameters
	if params.RateLimit.GlobalRPS != 1000 {
		t.Errorf("Expected RateLimit.GlobalRPS to be 1000, got %f", params.RateLimit.GlobalRPS)
	}
	if params.RateLimit.GlobalBurst != 100 {
		t.Errorf("Expected RateLimit.GlobalBurst to be 100, got %d", params.RateLimit.GlobalBurst)
	}

	// Verify Cache parameters
	if params.Cache.TTL != 5*time.Minute {
		t.Errorf("Expected Cache.TTL to be 5 minutes, got %v", params.Cache.TTL)
	}
	if params.Cache.MaxSize != 10000 {
		t.Errorf("Expected Cache.MaxSize to be 10000, got %d", params.Cache.MaxSize)
	}

	// Verify Concurrency parameters
	if params.Concurrency.MaxGoroutines != 1000 {
		t.Errorf("Expected Concurrency.MaxGoroutines to be 1000, got %d", params.Concurrency.MaxGoroutines)
	}
	if params.Concurrency.WorkerPoolSize != 100 {
		t.Errorf("Expected Concurrency.WorkerPoolSize to be 100, got %d", params.Concurrency.WorkerPoolSize)
	}

	// Verify Transport parameters
	if params.Transport.GlobalTimeout != 30*time.Second {
		t.Errorf("Expected Transport.GlobalTimeout to be 30 seconds, got %v", params.Transport.GlobalTimeout)
	}
	if params.Transport.MaxRetries != 3 {
		t.Errorf("Expected Transport.MaxRetries to be 3, got %d", params.Transport.MaxRetries)
	}

	// Verify Runtime parameters
	if params.Runtime.MaxGoroutines != 10000 {
		t.Errorf("Expected Runtime.MaxGoroutines to be 10000, got %d", params.Runtime.MaxGoroutines)
	}
	if params.Runtime.MaxMemoryUsage != 8*1024*1024*1024 {
		t.Errorf("Expected Runtime.MaxMemoryUsage to be 8GB, got %d", params.Runtime.MaxMemoryUsage)
	}
}

func TestNewProductionMetrics(t *testing.T) {
	pm := NewProductionMetrics(1 * time.Minute)

	// Verify basic fields
	if pm.collectionInterval != 1*time.Minute {
		t.Errorf("Expected collectionInterval to be 1 minute, got %v", pm.collectionInterval)
	}
	if pm.closed {
		t.Error("Expected closed to be false")
	}
	if pm.closeChan == nil {
		t.Error("Expected closeChan to be initialized")
	}

	// Verify baselines are set
	if pm.baselines.HTTP.MaxAvgDuration != 0.5 {
		t.Error("Expected baselines to be set with default values")
	}

	// Verify SLA definitions are set
	if pm.slaDefinitions.Availability.Target != 0.999 {
		t.Error("Expected SLA definitions to be set with default values")
	}

	// Verify thresholds are set
	if pm.bottleneckThresholds.HTTP.HighLatencyThreshold != 1.0 {
		t.Error("Expected bottleneck thresholds to be set with default values")
	}

	// Verify config tuner is initialized
	if pm.configTuner == nil {
		t.Error("Expected configTuner to be initialized")
	}
}

func TestProductionMetricsStartStop(t *testing.T) {
	pm := NewProductionMetrics(1 * time.Hour) // Long interval so it doesn't collect again

	// Start should succeed
	if err := pm.Start(); err != nil {
		t.Fatalf("Failed to start production metrics: %v", err)
	}

	// Give it a moment to do initial collection
	time.Sleep(50 * time.Millisecond)

	// Check that current snapshot is populated
	snapshot := pm.GetCurrentSnapshot()
	if snapshot == nil {
		t.Error("Expected current snapshot to be populated after start")
	} else {
		if snapshot.Timestamp.IsZero() {
			t.Error("Expected snapshot timestamp to be set")
		}
		if snapshot.RuntimeMetrics.Goroutines == 0 {
			t.Error("Expected runtime metrics to be collected")
		}
	}

	// Stop should succeed
	if err := pm.Stop(); err != nil {
		t.Fatalf("Failed to stop production metrics: %v", err)
	}

	// Give the goroutine time to exit
	time.Sleep(10 * time.Millisecond)

	// Trying to start again should fail
	if err := pm.Start(); err == nil {
		t.Error("Expected Start to fail after Stop")
	}

	// Trying to stop again should fail
	if err := pm.Stop(); err == nil {
		t.Error("Expected Stop to fail when already closed")
	}
}

func TestCollectRuntimeMetrics(t *testing.T) {
	pm := NewProductionMetrics(1 * time.Minute)

	// Manually collect metrics
	ctx := context.Background()
	snapshot := &MetricsSnapshot{}

	// This should not panic
	pm.collectRuntimeMetrics(ctx, snapshot)

	// Verify runtime metrics are collected
	if snapshot.RuntimeMetrics.Goroutines == 0 {
		t.Error("Expected goroutines to be collected")
	}
	if snapshot.RuntimeMetrics.MemoryAllocated == 0 {
		t.Error("Expected memory allocated to be collected")
	}
	if snapshot.RuntimeMetrics.MemorySys == 0 {
		t.Error("Expected memory sys to be collected")
	}
	if snapshot.RuntimeMetrics.GCCount == 0 {
		// This might be 0 if no GC has happened, but that's fine
		// We just want to make sure it doesn't panic
	}

	// Verify uptime is positive
	if snapshot.RuntimeMetrics.Uptime <= 0 {
		t.Error("Expected uptime to be positive")
	}
}

func TestAnalyzeBottlenecks(t *testing.T) {
	pm := NewProductionMetrics(1 * time.Minute)

	// Manually create a snapshot to test detection
	snapshot := &MetricsSnapshot{
		HTTPMetrics: HTTPMetricsSnapshot{
			P95RequestDuration: 0.5, // Below threshold
		},
		RuntimeMetrics: RuntimeMetricsSnapshot{
			Goroutines:      5000,    // Below threshold
			MemoryAllocated: 1000000, // Below threshold
			GCPauseAvg:      0.05,    // Below threshold
		},
	}

	// Set the snapshot directly for testing
	pm.mu.Lock()
	pm.currentSnapshot = snapshot
	pm.mu.Unlock()

	// Analyze bottlenecks - should not panic
	bottlenecks := pm.AnalyzeBottlenecks()

	// With metrics below thresholds, bottlenecks should be empty
	if bottlenecks == nil {
		t.Fatal("Expected bottlenecks to be a slice (can be empty), got nil")
	}
	if len(bottlenecks) != 0 {
		t.Errorf("Expected no bottlenecks with healthy metrics, got %d", len(bottlenecks))
	}

	// Now test with high metrics
	pm.mu.Lock()
	snapshot.RuntimeMetrics.Goroutines = 20000 // Above threshold
	pm.currentSnapshot = snapshot
	pm.mu.Unlock()

	bottlenecks = pm.AnalyzeBottlenecks()
	if len(bottlenecks) == 0 {
		t.Error("Expected bottlenecks to be detected with high goroutine count")
	}
	if len(bottlenecks) != 1 {
		t.Errorf("Expected 1 bottleneck, got %d", len(bottlenecks))
	}
	if bottlenecks[0].Type != "runtime" {
		t.Errorf("Expected runtime bottleneck, got %s", bottlenecks[0].Type)
	}
}

func TestCheckSLACompliance(t *testing.T) {
	pm := NewProductionMetrics(1 * time.Minute)

	// Start to populate current snapshot
	pm.Start()
	defer pm.Stop()

	time.Sleep(10 * time.Millisecond)

	// Check SLA compliance - should not panic
	compliance := pm.CheckSLACompliance()

	// Verify it returns a valid struct
	if compliance.Latency.P99Compliance < 0 || compliance.Latency.P99Compliance > 1 {
		t.Errorf("Expected P99Compliance to be between 0 and 1, got %f", compliance.Latency.P99Compliance)
	}
}

func TestCalculatePerformanceTrends(t *testing.T) {
	pm := NewProductionMetrics(1 * time.Minute)

	// Start to populate snapshots
	pm.Start()
	defer pm.Stop()

	// Wait for initial collection
	time.Sleep(10 * time.Millisecond)

	// Calculate trends - should not panic
	trends := pm.CalculatePerformanceTrends()

	// Verify it returns a valid struct
	if trends == nil {
		t.Error("Expected trends to be non-nil")
	}
}

func TestSetBaselines(t *testing.T) {
	pm := NewProductionMetrics(1 * time.Minute)

	// Set custom baselines
	customBaselines := DefaultPerformanceBaselines()
	customBaselines.HTTP.MaxAvgDuration = 1.0

	pm.SetBaselines(customBaselines)

	// Verify they were set
	if pm.baselines.HTTP.MaxAvgDuration != 1.0 {
		t.Error("Expected custom baselines to be set")
	}
}

func TestSetSLADefinitions(t *testing.T) {
	pm := NewProductionMetrics(1 * time.Minute)

	// Set custom SLA definitions
	customSLAs := DefaultSLADefinitions()
	customSLAs.Availability.Target = 0.9999

	pm.SetSLADefinitions(customSLAs)

	// Verify they were set
	if pm.slaDefinitions.Availability.Target != 0.9999 {
		t.Error("Expected custom SLA definitions to be set")
	}
}

func TestSetBottleneckThresholds(t *testing.T) {
	pm := NewProductionMetrics(1 * time.Minute)

	// Set custom thresholds
	customThresholds := DefaultBottleneckThresholds()
	customThresholds.HTTP.HighLatencyThreshold = 2.0

	pm.SetBottleneckThresholds(customThresholds)

	// Verify they were set
	if pm.bottleneckThresholds.HTTP.HighLatencyThreshold != 2.0 {
		t.Error("Expected custom thresholds to be set")
	}
}

func TestGetSetTuningParameters(t *testing.T) {
	pm := NewProductionMetrics(1 * time.Minute)

	// Set custom parameters
	customParams := DefaultTuningParameters()
	customParams.RateLimit.GlobalRPS = 2000

	pm.SetTuningParameters(customParams)

	// Get them back
	retrievedParams := pm.GetTuningParameters()

	// Verify they were set
	if retrievedParams.RateLimit.GlobalRPS != 2000 {
		t.Errorf("Expected custom GlobalRPS to be 2000, got %f", retrievedParams.RateLimit.GlobalRPS)
	}
}

func TestNewConfigurationTuner(t *testing.T) {
	tuner := NewConfigurationTuner()

	// Verify it has default parameters
	if tuner.currentParams.RateLimit.GlobalRPS != 1000 {
		t.Error("Expected configuration tuner to have default parameters")
	}
}
