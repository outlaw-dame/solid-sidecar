// Package observability provides observability utilities for the Solid runtime.
// This file implements memory and goroutine leak detection as required by Phase 17.
package observability

import (
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// LeakDetector monitors for memory and goroutine leaks
type LeakDetector struct {
	mu sync.RWMutex

	// Memory tracking
	startMemStats runtime.MemStats
	lastMemStats  runtime.MemStats
	peakMemStats  runtime.MemStats

	// Goroutine tracking
	startGoroutines int
	lastGoroutines  int
	peakGoroutines  int

	// Configuration
	config LeakDetectorConfig

	// State
	startedAt time.Time
	closed    bool

	// Leak thresholds
	memoryLeakThreshold    float64 // Percentage increase to consider a leak
	goroutineLeakThreshold int     // Number of goroutines increase to consider a leak

	// Alert state
	memoryLeakAlert    bool
	goroutineLeakAlert bool

	// Cleanup functions for testing
	cleanupFuncs []func()
}

// LeakDetectorConfig holds configuration for the leak detector
type LeakDetectorConfig struct {
	// CheckInterval is how often to check for leaks
	CheckInterval time.Duration

	// MemoryLeakThreshold is the percentage increase in memory to trigger an alert (0.0-1.0)
	MemoryLeakThreshold float64

	// GoroutineLeakThreshold is the number of goroutines increase to trigger an alert
	GoroutineLeakThreshold int

	// EnableGC enables garbage collection before memory checks
	EnableGC bool

	// MaxChecks is the maximum number of checks to perform (0 = unlimited)
	MaxChecks int

	// OnLeakDetected is called when a leak is detected
	OnLeakDetected func(leakType string, details map[string]interface{})
}

// DefaultLeakDetectorConfig returns safe defaults for leak detection
func DefaultLeakDetectorConfig() LeakDetectorConfig {
	return LeakDetectorConfig{
		CheckInterval:          1 * time.Minute,
		MemoryLeakThreshold:    0.1, // 10% memory increase
		GoroutineLeakThreshold: 10,  // 10 goroutines increase
		EnableGC:               true,
		MaxChecks:              0, // unlimited
		OnLeakDetected:         nil,
	}
}

// NewLeakDetector creates a new leak detector
func NewLeakDetector(config LeakDetectorConfig) *LeakDetector {
	// Apply defaults for zero values
	if config.CheckInterval <= 0 {
		config.CheckInterval = 1 * time.Minute
	}
	if config.MemoryLeakThreshold <= 0 {
		config.MemoryLeakThreshold = 0.1
	}
	if config.GoroutineLeakThreshold <= 0 {
		config.GoroutineLeakThreshold = 10
	}

	detector := &LeakDetector{
		config:                 config,
		memoryLeakThreshold:    config.MemoryLeakThreshold,
		goroutineLeakThreshold: config.GoroutineLeakThreshold,
		startedAt:              time.Now(),
		closed:                 false,
		cleanupFuncs:           make([]func(), 0),
	}

	// Capture initial stats
	detector.captureInitialStats()

	return detector
}

// captureInitialStats captures the initial memory and goroutine statistics
func (d *LeakDetector) captureInitialStats() {
	runtime.ReadMemStats(&d.startMemStats)
	d.startGoroutines = runtime.NumGoroutine()
	d.lastMemStats = d.startMemStats
	d.lastGoroutines = d.startGoroutines
	d.peakMemStats = d.startMemStats
	d.peakGoroutines = d.startGoroutines
}

// Start starts the leak detection monitoring
func (d *LeakDetector) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return fmt.Errorf("leak detector is closed")
	}

	// Start monitoring goroutine
	go d.monitorLoop()

	return nil
}

// monitorLoop runs the leak detection monitoring loop
func (d *LeakDetector) monitorLoop() {
	ticker := time.NewTicker(d.config.CheckInterval)
	defer ticker.Stop()

	checkCount := 0

	for {
		select {
		case <-ticker.C:
			checkCount++

			// Check if we've reached max checks
			if d.config.MaxChecks > 0 && checkCount > d.config.MaxChecks {
				d.logger().Debug("Leak detector reached maximum checks")
				return
			}

			// Run leak detection
			d.detectLeaks()

		case <-d.getCloseChan():
			return
		}
	}
}

// detectLeaks performs a leak detection check
func (d *LeakDetector) detectLeaks() {
	// Force GC if enabled to get accurate memory stats
	if d.config.EnableGC {
		debug.FreeOSMemory()
		runtime.GC()
	}

	// Get current stats
	var currentMemStats runtime.MemStats
	runtime.ReadMemStats(&currentMemStats)
	currentGoroutines := runtime.NumGoroutine()

	d.mu.Lock()
	defer d.mu.Unlock()

	// Update peak stats
	if currentMemStats.Alloc > d.peakMemStats.Alloc {
		d.peakMemStats = currentMemStats
	}
	if currentGoroutines > d.peakGoroutines {
		d.peakGoroutines = currentGoroutines
	}

	// Check for memory leaks
	memoryIncrease := float64(currentMemStats.Alloc-d.lastMemStats.Alloc) / float64(d.lastMemStats.Alloc)
	if memoryIncrease > d.memoryLeakThreshold {
		if !d.memoryLeakAlert {
			d.memoryLeakAlert = true
			d.logger().Warn("Memory leak detected",
				"increase_percent", fmt.Sprintf("%.2f%%", memoryIncrease*100),
				"current_alloc", currentMemStats.Alloc,
				"previous_alloc", d.lastMemStats.Alloc,
				"peak_alloc", d.peakMemStats.Alloc,
				"threshold_percent", fmt.Sprintf("%.2f%%", d.memoryLeakThreshold*100),
			)

			if d.config.OnLeakDetected != nil {
				d.config.OnLeakDetected("memory", map[string]interface{}{
					"increase_percent":     memoryIncrease * 100,
					"current_alloc_bytes":  currentMemStats.Alloc,
					"previous_alloc_bytes": d.lastMemStats.Alloc,
					"peak_alloc_bytes":     d.peakMemStats.Alloc,
					"threshold_percent":    d.memoryLeakThreshold * 100,
				})
			}
		}
	} else {
		d.memoryLeakAlert = false
	}

	// Check for goroutine leaks
	goroutineIncrease := currentGoroutines - d.lastGoroutines
	if goroutineIncrease > d.goroutineLeakThreshold {
		if !d.goroutineLeakAlert {
			d.goroutineLeakAlert = true
			d.logger().Warn("Goroutine leak detected",
				"increase_count", goroutineIncrease,
				"current_goroutines", currentGoroutines,
				"previous_goroutines", d.lastGoroutines,
				"peak_goroutines", d.peakGoroutines,
				"threshold_count", d.goroutineLeakThreshold,
			)

			if d.config.OnLeakDetected != nil {
				d.config.OnLeakDetected("goroutine", map[string]interface{}{
					"increase_count":      goroutineIncrease,
					"current_goroutines":  currentGoroutines,
					"previous_goroutines": d.lastGoroutines,
					"peak_goroutines":     d.peakGoroutines,
					"threshold_count":     d.goroutineLeakThreshold,
				})
			}
		}
	} else {
		d.goroutineLeakAlert = false
	}

	// Update last stats
	d.lastMemStats = currentMemStats
	d.lastGoroutines = currentGoroutines
}

// GetMemoryStats returns the current and peak memory statistics
func (d *LeakDetector) GetMemoryStats() (current, peak runtime.MemStats, peakReached bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var currentMemStats runtime.MemStats
	runtime.ReadMemStats(&currentMemStats)

	return currentMemStats, d.peakMemStats, d.memoryLeakAlert
}

// GetGoroutineStats returns the current and peak goroutine counts
func (d *LeakDetector) GetGoroutineStats() (current, peak, increase int, peakReached bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	current = runtime.NumGoroutine()
	increase = current - d.lastGoroutines

	return current, d.peakGoroutines, increase, d.goroutineLeakAlert
}

// GetLeakStatus returns the current leak detection status
func (d *LeakDetector) GetLeakStatus() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var currentMemStats runtime.MemStats
	runtime.ReadMemStats(&currentMemStats)
	currentGoroutines := runtime.NumGoroutine()

	return map[string]interface{}{
		"started_at":               d.startedAt.Format(time.RFC3339),
		"memory_leak_detected":     d.memoryLeakAlert,
		"goroutine_leak_detected":  d.goroutineLeakAlert,
		"current_memory_alloc":     currentMemStats.Alloc,
		"peak_memory_alloc":        d.peakMemStats.Alloc,
		"current_goroutines":       currentGoroutines,
		"peak_goroutines":          d.peakGoroutines,
		"memory_threshold_percent": d.memoryLeakThreshold * 100,
		"goroutine_threshold":      d.goroutineLeakThreshold,
		"check_interval":           d.config.CheckInterval.String(),
		"last_check":               time.Now().Format(time.RFC3339),
	}
}

// ResetPeaks resets the peak memory and goroutine statistics
func (d *LeakDetector) ResetPeaks() {
	d.mu.Lock()
	defer d.mu.Unlock()

	var currentMemStats runtime.MemStats
	runtime.ReadMemStats(&currentMemStats)
	currentGoroutines := runtime.NumGoroutine()

	d.peakMemStats = currentMemStats
	d.peakGoroutines = currentGoroutines
}

// Close stops the leak detector and cleans up resources
func (d *LeakDetector) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true
	close(d.getCloseChan())

	// Run cleanup functions
	for _, cleanup := range d.cleanupFuncs {
		cleanup()
	}
	d.cleanupFuncs = nil

	return nil
}

// IsClosed returns true if the leak detector is closed
func (d *LeakDetector) IsClosed() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.closed
}

// AddCleanup adds a cleanup function to be called when the detector is closed
func (d *LeakDetector) AddCleanup(cleanup func()) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		// If already closed, run cleanup immediately
		cleanup()
		return
	}

	d.cleanupFuncs = append(d.cleanupFuncs, cleanup)
}

// closeChan is used to signal the monitoring loop to stop
func (d *LeakDetector) getCloseChan() chan struct{} {
	// Use a cached channel to avoid allocations
	var closeChan chan struct{}
	var closeChanOnce sync.Once

	closeChanOnce.Do(func() {
		closeChan = make(chan struct{})
	})

	return closeChan
}

// logger returns a logger for the leak detector
func (d *LeakDetector) logger() *slog.Logger {
	// For now, use default logger
	// In a real implementation, this would use the configured logger
	return slog.Default()
}

// GoroutineTracker provides fine-grained goroutine tracking for specific operations
type GoroutineTracker struct {
	mu sync.RWMutex

	// Active goroutines by operation
	activeGoroutines map[string]int64

	// Historical peaks
	peakGoroutines map[string]int64

	// Timeouts
	timeoutDuration time.Duration

	// Cleanup
	closed bool
}

// NewGoroutineTracker creates a new goroutine tracker
func NewGoroutineTracker(timeoutDuration time.Duration) *GoroutineTracker {
	if timeoutDuration <= 0 {
		timeoutDuration = 5 * time.Minute
	}

	return &GoroutineTracker{
		activeGoroutines: make(map[string]int64),
		peakGoroutines:   make(map[string]int64),
		timeoutDuration:  timeoutDuration,
		closed:           false,
	}
}

// StartOperation tracks the start of an operation that spawns goroutines
func (g *GoroutineTracker) StartOperation(operation string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return
	}

	g.activeGoroutines[operation]++

	// Update peak
	if g.activeGoroutines[operation] > g.peakGoroutines[operation] {
		g.peakGoroutines[operation] = g.activeGoroutines[operation]
	}
}

// EndOperation tracks the end of an operation
func (g *GoroutineTracker) EndOperation(operation string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return
	}

	if g.activeGoroutines[operation] > 0 {
		g.activeGoroutines[operation]--
	}
}

// GetOperationStats returns statistics for a specific operation
func (g *GoroutineTracker) GetOperationStats(operation string) (active, peak int64) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.activeGoroutines[operation], g.peakGoroutines[operation]
}

// GetAllStats returns statistics for all tracked operations
func (g *GoroutineTracker) GetAllStats() map[string]map[string]int64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := make(map[string]map[string]int64)

	for operation, active := range g.activeGoroutines {
		stats[operation] = map[string]int64{
			"active": active,
			"peak":   g.peakGoroutines[operation],
		}
	}

	return stats
}

// ResetPeaks resets all peak statistics
func (g *GoroutineTracker) ResetPeaks() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.peakGoroutines = make(map[string]int64)
}

// Close stops the goroutine tracker
func (g *GoroutineTracker) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.closed = true
	g.activeGoroutines = make(map[string]int64)
	g.peakGoroutines = make(map[string]int64)
}

// MemoryTracker provides memory usage tracking for specific components
type MemoryTracker struct {
	mu sync.RWMutex

	// Memory usage by component
	memoryUsage map[string]int64

	// Peak memory usage by component
	peakMemoryUsage map[string]int64

	// Total memory usage
	totalMemory int64
	peakTotal   int64

	// Closed state
	closed bool
}

// NewMemoryTracker creates a new memory tracker
func NewMemoryTracker() *MemoryTracker {
	return &MemoryTracker{
		memoryUsage:     make(map[string]int64),
		peakMemoryUsage: make(map[string]int64),
		closed:          false,
	}
}

// TrackAllocation tracks memory allocation for a component
func (m *MemoryTracker) TrackAllocation(component string, bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}

	m.memoryUsage[component] += bytes
	m.totalMemory += bytes

	// Update peaks
	if m.memoryUsage[component] > m.peakMemoryUsage[component] {
		m.peakMemoryUsage[component] = m.memoryUsage[component]
	}
	if m.totalMemory > m.peakTotal {
		m.peakTotal = m.totalMemory
	}
}

// TrackDeallocation tracks memory deallocation for a component
func (m *MemoryTracker) TrackDeallocation(component string, bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}

	m.memoryUsage[component] -= bytes
	if m.memoryUsage[component] < 0 {
		m.memoryUsage[component] = 0
	}

	m.totalMemory -= bytes
	if m.totalMemory < 0 {
		m.totalMemory = 0
	}
}

// GetComponentMemory returns memory usage for a specific component
func (m *MemoryTracker) GetComponentMemory(component string) (current, peak int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.memoryUsage[component], m.peakMemoryUsage[component]
}

// GetTotalMemory returns total memory usage
func (m *MemoryTracker) GetTotalMemory() (current, peak int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.totalMemory, m.peakTotal
}

// GetAllMemoryStats returns memory statistics for all components
func (m *MemoryTracker) GetAllMemoryStats() map[string]map[string]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]map[string]int64)

	for component, current := range m.memoryUsage {
		stats[component] = map[string]int64{
			"current": current,
			"peak":    m.peakMemoryUsage[component],
		}
	}

	stats["total"] = map[string]int64{
		"current": m.totalMemory,
		"peak":    m.peakTotal,
	}

	return stats
}

// ResetPeaks resets all peak memory statistics
func (m *MemoryTracker) ResetPeaks() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.peakMemoryUsage = make(map[string]int64)
	m.peakTotal = 0
}

// Close stops the memory tracker
func (m *MemoryTracker) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.memoryUsage = make(map[string]int64)
	m.peakMemoryUsage = make(map[string]int64)
	m.totalMemory = 0
	m.peakTotal = 0
}
