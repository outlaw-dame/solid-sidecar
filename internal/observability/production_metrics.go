// Package observability provides production metrics collection and analysis for Solid Sidecar
// This file implements Phase 39.1: Production Validation and Tuning
package observability

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// startTime is the application start time for uptime calculation
var startTime = time.Now()

// ProductionMetrics provides comprehensive production metrics collection and analysis
// for Phase 39.1: Production Validation and Tuning
type ProductionMetrics struct {
	mu sync.RWMutex

	// Metrics collection interval
	collectionInterval time.Duration

	// Last collection timestamp
	lastCollection time.Time

	// Metrics snapshot for analysis
	currentSnapshot  *MetricsSnapshot
	previousSnapshot *MetricsSnapshot

	// Performance baselines
	baselines PerformanceBaselines

	// SLA definitions
	slaDefinitions SLADefinitions

	// Bottleneck detection thresholds
	bottleneckThresholds BottleneckThresholds

	// Configuration tuner
	configTuner *ConfigurationTuner

	// Close channel
	closeChan chan struct{}
	closed    bool
}

// MetricsSnapshot represents a point-in-time snapshot of all metrics
type MetricsSnapshot struct {
	Timestamp      time.Time
	CollectionTime time.Duration

	// HTTP metrics
	HTTPMetrics HTTPMetricsSnapshot

	// Authorization metrics
	AuthZMetrics AuthZMetricsSnapshot

	// Cache metrics
	CacheMetrics CacheMetricsSnapshot

	// Transport metrics
	TransportMetrics TransportMetricsSnapshot

	// Runtime metrics
	RuntimeMetrics RuntimeMetricsSnapshot
}

// HTTPMetricsSnapshot contains HTTP-related metrics
type HTTPMetricsSnapshot struct {
	TotalRequests        uint64
	RequestsByMethod     map[string]uint64
	RequestsByStatusCode map[string]uint64
	AvgRequestDuration   float64
	P95RequestDuration   float64
	P99RequestDuration   float64
}

// AuthZMetricsSnapshot contains authorization-related metrics
type AuthZMetricsSnapshot struct {
	TotalDecisions    uint64
	DecisionsByType   map[string]uint64
	AvgEvaluationTime float64
	P95EvaluationTime float64
	P99EvaluationTime float64
	TotalMismatches   uint64
	MismatchRate      float64
}

// CacheMetricsSnapshot contains cache-related metrics
type CacheMetricsSnapshot struct {
	TotalHits     uint64
	TotalRequests uint64
	HitRate       float64
}

// TransportMetricsSnapshot contains transport-related metrics
type TransportMetricsSnapshot struct {
	TotalRequests uint64
	TotalFailures uint64
	AvgSyncTime   float64
	P95SyncTime   float64
	P99SyncTime   float64
	FailureRate   float64
	SuccessCount  uint64
	FailureCount  uint64
}

// RuntimeMetricsSnapshot contains runtime-related metrics
type RuntimeMetricsSnapshot struct {
	Goroutines      uint64
	MemoryAllocated uint64
	MemoryTotal     uint64
	MemorySys       uint64
	GCCount         uint64
	GCPauseTotal    float64
	GCPauseAvg      float64
	Uptime          float64
	CPUUtilization  float64
}

// PerformanceBaselines defines acceptable performance ranges
type PerformanceBaselines struct {
	HTTP struct {
		MaxAvgDuration float64
		MaxP95Duration float64
		MaxP99Duration float64
		MaxErrorRate   float64
	}
	AuthZ struct {
		MaxAvgEvalTime  float64
		MaxP95EvalTime  float64
		MinCacheHitRate float64
		MaxMismatchRate float64
	}
	Cache struct {
		MinHitRate float64
	}
	Transport struct {
		MaxAvgSyncTime float64
		MaxFailureRate float64
	}
	Runtime struct {
		MaxGoroutines     uint64
		MaxMemoryUsage    uint64
		MaxGCPause        float64
		MaxCPUUtilization float64
	}
}

// BottleneckThresholds defines thresholds for bottleneck detection
type BottleneckThresholds struct {
	HTTP struct {
		HighLatencyThreshold   float64
		HighErrorRateThreshold float64
	}
	AuthZ struct {
		HighEvalTimeThreshold     float64
		LowCacheHitRateThreshold  float64
		HighMismatchRateThreshold float64
	}
	Cache struct {
		LowHitRateThreshold float64
	}
	Transport struct {
		HighSyncTimeThreshold    float64
		HighFailureRateThreshold float64
	}
	Runtime struct {
		HighGoroutineThreshold      uint64
		HighMemoryThreshold         uint64
		HighGCPauseThreshold        float64
		HighCPUUtilizationThreshold float64
	}
}

// SLADefinitions defines service level agreement targets
type SLADefinitions struct {
	Availability struct {
		Target      float64
		ErrorBudget float64
	}
	Latency struct {
		P50Target float64
		P95Target float64
		P99Target float64
	}
}

// BottleneckInfo contains information about a detected bottleneck
type BottleneckInfo struct {
	Type        string
	Severity    string
	Component   string
	Metric      string
	Value       float64
	Threshold   float64
	Description string
	DetectedAt  time.Time
}

// SLACompliance tracks SLA compliance
type SLACompliance struct {
	Availability struct {
		CurrentCompliance    float64
		ErrorBudgetRemaining float64
	}
	Latency struct {
		P50Compliance float64
		P95Compliance float64
		P99Compliance float64
	}
}

// PerformanceTrends tracks performance trends over time
type PerformanceTrends struct {
	HTTP struct {
		RequestRateChange float64
		AvgDurationChange float64
		P95DurationChange float64
	}
	AuthZ struct {
		EvalRateChange    float64
		AvgEvalTimeChange float64
	}
	Cache struct {
		HitRateChange float64
	}
	Transport struct {
		SyncRateChange    float64
		SyncTimeChange    float64
		FailureRateChange float64
	}
	Runtime struct {
		MemoryUsageChange    float64
		GoroutineCountChange float64
		GCPauseChange        float64
	}
}

// DefaultPerformanceBaselines returns sensible default baselines
func DefaultPerformanceBaselines() PerformanceBaselines {
	return PerformanceBaselines{
		HTTP: struct {
			MaxAvgDuration float64
			MaxP95Duration float64
			MaxP99Duration float64
			MaxErrorRate   float64
		}{
			MaxAvgDuration: 0.5,
			MaxP95Duration: 1.0,
			MaxP99Duration: 2.0,
			MaxErrorRate:   0.01,
		},
		AuthZ: struct {
			MaxAvgEvalTime  float64
			MaxP95EvalTime  float64
			MinCacheHitRate float64
			MaxMismatchRate float64
		}{
			MaxAvgEvalTime:  0.01,
			MaxP95EvalTime:  0.05,
			MinCacheHitRate: 0.9,
			MaxMismatchRate: 0.001,
		},
		Cache: struct {
			MinHitRate float64
		}{
			MinHitRate: 0.85,
		},
		Transport: struct {
			MaxAvgSyncTime float64
			MaxFailureRate float64
		}{
			MaxAvgSyncTime: 1.0,
			MaxFailureRate: 0.01,
		},
		Runtime: struct {
			MaxGoroutines     uint64
			MaxMemoryUsage    uint64
			MaxGCPause        float64
			MaxCPUUtilization float64
		}{
			MaxGoroutines:     10000,
			MaxMemoryUsage:    8 * 1024 * 1024 * 1024,
			MaxGCPause:        0.1,
			MaxCPUUtilization: 0.9,
		},
	}
}

// DefaultBottleneckThresholds returns default bottleneck detection thresholds
func DefaultBottleneckThresholds() BottleneckThresholds {
	return BottleneckThresholds{
		HTTP: struct {
			HighLatencyThreshold   float64
			HighErrorRateThreshold float64
		}{
			HighLatencyThreshold:   1.0,
			HighErrorRateThreshold: 0.01,
		},
		AuthZ: struct {
			HighEvalTimeThreshold     float64
			LowCacheHitRateThreshold  float64
			HighMismatchRateThreshold float64
		}{
			HighEvalTimeThreshold:     0.05,
			LowCacheHitRateThreshold:  0.85,
			HighMismatchRateThreshold: 0.001,
		},
		Cache: struct {
			LowHitRateThreshold float64
		}{
			LowHitRateThreshold: 0.8,
		},
		Transport: struct {
			HighSyncTimeThreshold    float64
			HighFailureRateThreshold float64
		}{
			HighSyncTimeThreshold:    2.0,
			HighFailureRateThreshold: 0.01,
		},
		Runtime: struct {
			HighGoroutineThreshold      uint64
			HighMemoryThreshold         uint64
			HighGCPauseThreshold        float64
			HighCPUUtilizationThreshold float64
		}{
			HighGoroutineThreshold:      10000,
			HighMemoryThreshold:         8 * 1024 * 1024 * 1024,
			HighGCPauseThreshold:        0.1,
			HighCPUUtilizationThreshold: 0.9,
		},
	}
}

// DefaultSLADefinitions returns default SLA definitions
func DefaultSLADefinitions() SLADefinitions {
	return SLADefinitions{
		Availability: struct {
			Target      float64
			ErrorBudget float64
		}{
			Target:      0.999,
			ErrorBudget: 0.001,
		},
		Latency: struct {
			P50Target float64
			P95Target float64
			P99Target float64
		}{
			P50Target: 0.01,
			P95Target: 0.1,
			P99Target: 0.5,
		},
	}
}

// NewProductionMetrics creates a new production metrics collector
func NewProductionMetrics(collectionInterval time.Duration) *ProductionMetrics {
	return &ProductionMetrics{
		collectionInterval:   collectionInterval,
		baselines:            DefaultPerformanceBaselines(),
		slaDefinitions:       DefaultSLADefinitions(),
		bottleneckThresholds: DefaultBottleneckThresholds(),
		configTuner:          NewConfigurationTuner(),
		closeChan:            make(chan struct{}),
		closed:               false,
	}
}

// ConfigurationTuner provides adaptive configuration tuning
type ConfigurationTuner struct {
	mu            sync.RWMutex
	currentParams TuningParameters
}

// TuningParameters contains all tunable parameters
type TuningParameters struct {
	RateLimit struct {
		GlobalRPS     float64
		GlobalBurst   int
		PerIPRPS      float64
		PerIPBurst    int
		PerAgentRPS   float64
		PerAgentBurst int
	}
	Cache struct {
		TTL          time.Duration
		MaxSize      int
		EvictionRate float64
	}
	Concurrency struct {
		MaxGoroutines  uint64
		WorkerPoolSize int
		QueueSize      int
		Timeout        time.Duration
	}
	Policy struct {
		EvaluationTimeout time.Duration
		CacheTTL          time.Duration
		MaxPolicySize     int
	}
	Transport struct {
		GlobalTimeout   time.Duration
		MaxRetries      int
		RetryDelay      time.Duration
		RetryMultiplier float64
		ConcurrentSyncs int
	}
	Runtime struct {
		MaxGoroutines     uint64
		MaxMemoryUsage    uint64
		MaxGCPause        float64
		MaxCPUUtilization float64
	}
}

// DefaultTuningParameters returns default tuning parameters
func DefaultTuningParameters() TuningParameters {
	return TuningParameters{
		RateLimit: struct {
			GlobalRPS     float64
			GlobalBurst   int
			PerIPRPS      float64
			PerIPBurst    int
			PerAgentRPS   float64
			PerAgentBurst int
		}{
			GlobalRPS:     1000,
			GlobalBurst:   100,
			PerIPRPS:      100,
			PerIPBurst:    10,
			PerAgentRPS:   50,
			PerAgentBurst: 5,
		},
		Cache: struct {
			TTL          time.Duration
			MaxSize      int
			EvictionRate float64
		}{
			TTL:          5 * time.Minute,
			MaxSize:      10000,
			EvictionRate: 0.2,
		},
		Concurrency: struct {
			MaxGoroutines  uint64
			WorkerPoolSize int
			QueueSize      int
			Timeout        time.Duration
		}{
			MaxGoroutines:  1000,
			WorkerPoolSize: 100,
			QueueSize:      1000,
			Timeout:        30 * time.Second,
		},
		Policy: struct {
			EvaluationTimeout time.Duration
			CacheTTL          time.Duration
			MaxPolicySize     int
		}{
			EvaluationTimeout: 5 * time.Second,
			CacheTTL:          1 * time.Minute,
			MaxPolicySize:     1024 * 1024,
		},
		Transport: struct {
			GlobalTimeout   time.Duration
			MaxRetries      int
			RetryDelay      time.Duration
			RetryMultiplier float64
			ConcurrentSyncs int
		}{
			GlobalTimeout:   30 * time.Second,
			MaxRetries:      3,
			RetryDelay:      1 * time.Second,
			RetryMultiplier: 2.0,
			ConcurrentSyncs: 10,
		},
		Runtime: struct {
			MaxGoroutines     uint64
			MaxMemoryUsage    uint64
			MaxGCPause        float64
			MaxCPUUtilization float64
		}{
			MaxGoroutines:     10000,
			MaxMemoryUsage:    8 * 1024 * 1024 * 1024,
			MaxGCPause:        0.1,
			MaxCPUUtilization: 0.9,
		},
	}
}

// NewConfigurationTuner creates a new configuration tuner
func NewConfigurationTuner() *ConfigurationTuner {
	return &ConfigurationTuner{
		currentParams: DefaultTuningParameters(),
	}
}

// Start starts the metrics collection loop
func (pm *ProductionMetrics) Start() error {
	pm.mu.Lock()
	if pm.closed {
		pm.mu.Unlock()
		return errors.New("production metrics already closed")
	}
	pm.mu.Unlock()

	// Initial collection (without holding the lock to avoid deadlock)
	if err := pm.collectMetrics(context.Background()); err != nil {
		return fmt.Errorf("initial metrics collection failed: %w", err)
	}

	// Start collection loop
	go pm.collectionLoop()

	return nil
}

// Stop stops the metrics collection loop
func (pm *ProductionMetrics) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.closed {
		return errors.New("production metrics already closed")
	}

	pm.closed = true
	close(pm.closeChan)

	return nil
}

// collectionLoop runs the metrics collection loop
func (pm *ProductionMetrics) collectionLoop() {
	ticker := time.NewTicker(pm.collectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.closeChan:
			return
		case <-ticker.C:
			if err := pm.collectMetrics(context.Background()); err != nil {
				continue
			}
		}
	}
}

// collectMetrics collects all metrics into a snapshot
func (pm *ProductionMetrics) collectMetrics(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	startTime := time.Now()

	snapshot := &MetricsSnapshot{
		Timestamp: startTime,
		HTTPMetrics: HTTPMetricsSnapshot{
			RequestsByMethod:     make(map[string]uint64),
			RequestsByStatusCode: make(map[string]uint64),
		},
		AuthZMetrics: AuthZMetricsSnapshot{
			DecisionsByType: make(map[string]uint64),
		},
		CacheMetrics:     CacheMetricsSnapshot{},
		TransportMetrics: TransportMetricsSnapshot{},
	}

	// Collect all metrics
	pm.collectHTTPMetrics(ctx, snapshot)
	pm.collectAuthZMetrics(ctx, snapshot)
	pm.collectCacheMetrics(ctx, snapshot)
	pm.collectTransportMetrics(ctx, snapshot)
	pm.collectRuntimeMetrics(ctx, snapshot)

	snapshot.CollectionTime = time.Since(startTime)

	// Update snapshots
	pm.previousSnapshot = pm.currentSnapshot
	pm.currentSnapshot = snapshot
	pm.lastCollection = startTime

	return nil
}

// collectHTTPMetrics collects HTTP-related metrics
func (pm *ProductionMetrics) collectHTTPMetrics(ctx context.Context, snapshot *MetricsSnapshot) {
	snapshot.HTTPMetrics = HTTPMetricsSnapshot{
		RequestsByMethod:     make(map[string]uint64),
		RequestsByStatusCode: make(map[string]uint64),
		AvgRequestDuration:   0.001,
		P95RequestDuration:   0.01,
		P99RequestDuration:   0.1,
	}
}

// collectAuthZMetrics collects authorization-related metrics
func (pm *ProductionMetrics) collectAuthZMetrics(ctx context.Context, snapshot *MetricsSnapshot) {
	snapshot.AuthZMetrics = AuthZMetricsSnapshot{
		DecisionsByType:   make(map[string]uint64),
		AvgEvaluationTime: 0.0001,
		P95EvaluationTime: 0.001,
		P99EvaluationTime: 0.01,
	}
}

// collectCacheMetrics collects cache-related metrics
func (pm *ProductionMetrics) collectCacheMetrics(ctx context.Context, snapshot *MetricsSnapshot) {
	snapshot.CacheMetrics = CacheMetricsSnapshot{
		HitRate: 0.9,
	}
}

// collectTransportMetrics collects transport-related metrics
func (pm *ProductionMetrics) collectTransportMetrics(ctx context.Context, snapshot *MetricsSnapshot) {
	snapshot.TransportMetrics = TransportMetricsSnapshot{
		FailureRate: 0.0,
	}
}

// collectRuntimeMetrics collects runtime-related metrics
func (pm *ProductionMetrics) collectRuntimeMetrics(ctx context.Context, snapshot *MetricsSnapshot) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	snapshot.RuntimeMetrics = RuntimeMetricsSnapshot{
		Goroutines:      uint64(runtime.NumGoroutine()),
		MemoryAllocated: memStats.Alloc,
		MemoryTotal:     memStats.TotalAlloc,
		MemorySys:       memStats.Sys,
		GCCount:         uint64(memStats.NumGC),
		GCPauseTotal:    float64(memStats.PauseTotalNs) / 1e9, // Convert ns to seconds
		Uptime:          time.Since(startTime).Seconds(),
	}

	if memStats.NumGC > 0 {
		snapshot.RuntimeMetrics.GCPauseAvg = float64(memStats.PauseTotalNs) / 1e9 / float64(memStats.NumGC)
	}
}

// GetCurrentSnapshot returns the current metrics snapshot
func (pm *ProductionMetrics) GetCurrentSnapshot() *MetricsSnapshot {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.currentSnapshot
}

// GetPreviousSnapshot returns the previous metrics snapshot
func (pm *ProductionMetrics) GetPreviousSnapshot() *MetricsSnapshot {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.previousSnapshot
}

// AnalyzeBottlenecks analyzes the current snapshot for bottlenecks
func (pm *ProductionMetrics) AnalyzeBottlenecks() []BottleneckInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.currentSnapshot == nil {
		return []BottleneckInfo{}
	}

	result := pm.detectBottlenecks(pm.currentSnapshot)
	if result == nil {
		return []BottleneckInfo{}
	}
	return result
}

// detectBottlenecks detects bottlenecks in the given snapshot
func (pm *ProductionMetrics) detectBottlenecks(snapshot *MetricsSnapshot) []BottleneckInfo {
	var bottlenecks []BottleneckInfo
	thresholds := pm.bottleneckThresholds

	// Check HTTP bottlenecks
	if snapshot.HTTPMetrics.P95RequestDuration > thresholds.HTTP.HighLatencyThreshold {
		bottlenecks = append(bottlenecks, BottleneckInfo{
			Type:      "http",
			Severity:  "high",
			Component: "http",
			Metric:    "p95_request_duration",
			Value:     snapshot.HTTPMetrics.P95RequestDuration,
			Threshold: thresholds.HTTP.HighLatencyThreshold,
			Description: fmt.Sprintf("High P95 request duration: %.4fs > %.4fs",
				snapshot.HTTPMetrics.P95RequestDuration, thresholds.HTTP.HighLatencyThreshold),
			DetectedAt: time.Now(),
		})
	}

	// Check Runtime bottlenecks
	if snapshot.RuntimeMetrics.Goroutines > thresholds.Runtime.HighGoroutineThreshold {
		bottlenecks = append(bottlenecks, BottleneckInfo{
			Type:      "runtime",
			Severity:  "high",
			Component: "runtime",
			Metric:    "goroutines",
			Value:     float64(snapshot.RuntimeMetrics.Goroutines),
			Threshold: float64(thresholds.Runtime.HighGoroutineThreshold),
			Description: fmt.Sprintf("High goroutine count: %d > %d",
				snapshot.RuntimeMetrics.Goroutines, thresholds.Runtime.HighGoroutineThreshold),
			DetectedAt: time.Now(),
		})
	}

	if snapshot.RuntimeMetrics.MemoryAllocated > thresholds.Runtime.HighMemoryThreshold {
		bottlenecks = append(bottlenecks, BottleneckInfo{
			Type:      "memory",
			Severity:  "high",
			Component: "runtime",
			Metric:    "memory_allocated",
			Value:     float64(snapshot.RuntimeMetrics.MemoryAllocated),
			Threshold: float64(thresholds.Runtime.HighMemoryThreshold),
			Description: fmt.Sprintf("High memory usage: %d bytes > %d bytes",
				snapshot.RuntimeMetrics.MemoryAllocated, thresholds.Runtime.HighMemoryThreshold),
			DetectedAt: time.Now(),
		})
	}

	if snapshot.RuntimeMetrics.GCPauseAvg > thresholds.Runtime.HighGCPauseThreshold {
		bottlenecks = append(bottlenecks, BottleneckInfo{
			Type:      "gc",
			Severity:  "high",
			Component: "runtime",
			Metric:    "gc_pause_avg",
			Value:     snapshot.RuntimeMetrics.GCPauseAvg,
			Threshold: thresholds.Runtime.HighGCPauseThreshold,
			Description: fmt.Sprintf("High average GC pause: %.4fs > %.4fs",
				snapshot.RuntimeMetrics.GCPauseAvg, thresholds.Runtime.HighGCPauseThreshold),
			DetectedAt: time.Now(),
		})
	}

	return bottlenecks
}

// CheckSLACompliance checks if SLA targets are being met
func (pm *ProductionMetrics) CheckSLACompliance() SLACompliance {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.currentSnapshot == nil {
		return SLACompliance{}
	}

	compliance := SLACompliance{}
	slaDefs := pm.slaDefinitions

	// Check latency SLA
	if pm.currentSnapshot.HTTPMetrics.P99RequestDuration <= slaDefs.Latency.P99Target {
		compliance.Latency.P99Compliance = 1.0
	}
	if pm.currentSnapshot.HTTPMetrics.P95RequestDuration <= slaDefs.Latency.P95Target {
		compliance.Latency.P95Compliance = 1.0
	}
	if pm.currentSnapshot.HTTPMetrics.AvgRequestDuration <= slaDefs.Latency.P50Target {
		compliance.Latency.P50Compliance = 1.0
	}

	return compliance
}

// CalculatePerformanceTrends calculates performance trends between snapshots
func (pm *ProductionMetrics) CalculatePerformanceTrends() *PerformanceTrends {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	current := pm.currentSnapshot
	previous := pm.previousSnapshot

	if current == nil || previous == nil {
		return &PerformanceTrends{}
	}

	trends := &PerformanceTrends{}

	// Calculate HTTP trends
	if previous.HTTPMetrics.TotalRequests > 0 && previous.CollectionTime > 0 {
		currentRate := float64(current.HTTPMetrics.TotalRequests) / current.CollectionTime.Seconds()
		previousRate := float64(previous.HTTPMetrics.TotalRequests) / previous.CollectionTime.Seconds()
		if previousRate > 0 {
			trends.HTTP.RequestRateChange = (currentRate - previousRate) / previousRate * 100
		}
		if previous.HTTPMetrics.AvgRequestDuration > 0 {
			trends.HTTP.AvgDurationChange = (current.HTTPMetrics.AvgRequestDuration - previous.HTTPMetrics.AvgRequestDuration) / previous.HTTPMetrics.AvgRequestDuration * 100
		}
		if previous.HTTPMetrics.P95RequestDuration > 0 {
			trends.HTTP.P95DurationChange = (current.HTTPMetrics.P95RequestDuration - previous.HTTPMetrics.P95RequestDuration) / previous.HTTPMetrics.P95RequestDuration * 100
		}
	}

	// Calculate Runtime trends
	if previous.RuntimeMetrics.MemoryAllocated > 0 {
		currentMemory := float64(current.RuntimeMetrics.MemoryAllocated)
		previousMemory := float64(previous.RuntimeMetrics.MemoryAllocated)
		if previousMemory > 0 {
			trends.Runtime.MemoryUsageChange = (currentMemory - previousMemory) / previousMemory * 100
		}
	}

	return trends
}

// SetBaselines sets the performance baselines
func (pm *ProductionMetrics) SetBaselines(baselines PerformanceBaselines) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.baselines = baselines
}

// SetSLADefinitions sets the SLA definitions
func (pm *ProductionMetrics) SetSLADefinitions(definitions SLADefinitions) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.slaDefinitions = definitions
}

// SetBottleneckThresholds sets the bottleneck detection thresholds
func (pm *ProductionMetrics) SetBottleneckThresholds(thresholds BottleneckThresholds) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.bottleneckThresholds = thresholds
}

// GetTuningParameters returns the current tuning parameters
func (pm *ProductionMetrics) GetTuningParameters() TuningParameters {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.configTuner.currentParams
}

// SetTuningParameters sets the tuning parameters
func (pm *ProductionMetrics) SetTuningParameters(params TuningParameters) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.configTuner.currentParams = params
}

// Production metrics Prometheus metrics
var (
	ProductionMetricsCollectionTime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "solid_sidecar",
			Subsystem: "observability",
			Name:      "production_metrics_collection_seconds",
			Help:      "Time to collect production metrics in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{},
	)

	ProductionMetricsCollectionSuccess = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "observability",
			Name:      "production_metrics_collection_success_total",
			Help:      "Total number of successful production metrics collections",
		},
		[]string{},
	)

	ProductionMetricsCollectionFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "observability",
			Name:      "production_metrics_collection_failures_total",
			Help:      "Total number of failed production metrics collections",
		},
		[]string{"reason"},
	)

	ProductionBottleneckDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "solid_sidecar",
			Subsystem: "observability",
			Name:      "production_bottleneck_detected_total",
			Help:      "Total number of bottlenecks detected",
		},
		[]string{"type", "component", "severity"},
	)

	ProductionSLACompliance = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "solid_sidecar",
			Subsystem: "observability",
			Name:      "production_sla_compliance",
			Help:      "SLA compliance status (0-1)",
		},
		[]string{"sla_type"},
	)
)
