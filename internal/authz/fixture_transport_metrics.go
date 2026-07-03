// Package authz provides authorization for Solid with fixture distribution transport metrics.
package authz

import (
	"sync"
	"time"
)

// TransportMethod represents the transport method type for metrics
// Keep this as a string type for flexibility in metric cardinality
type TransportMethod string

const (
	// Transport method constants for metrics
	TransportMethodHTTP    TransportMethod = "http"
	TransportMethodS3      TransportMethod = "s3"
	TransportMethodSSH     TransportMethod = "ssh"
	TransportMethodLocal   TransportMethod = "local"
	TransportMethodUnknown TransportMethod = "unknown"
)

// TransportOperation represents the type of transport operation
type TransportOperation string

const (
	TransportOpDistribute TransportOperation = "distribute"
	TransportOpValidate   TransportOperation = "validate"
	TransportOpConnect    TransportOperation = "connect"
	TransportOpUpload     TransportOperation = "upload"
	TransportOpDownload   TransportOperation = "download"
)

// TransportOutcome represents the outcome of a transport operation
type TransportOutcome string

const (
	TransportOutcomeSuccess   TransportOutcome = "success"
	TransportOutcomeFailure   TransportOutcome = "failure"
	TransportOutcomeTimeout   TransportOutcome = "timeout"
	TransportOutcomeRetry     TransportOutcome = "retry"
	TransportOutcomeCancelled TransportOutcome = "cancelled"
)

// TransportMetricsKey uniquely identifies a transport metric
type TransportMetricsKey struct {
	Method    TransportMethod
	Operation TransportOperation
	Outcome   TransportOutcome
}

// TransportMetricsSnapshot contains a snapshot of transport metrics
type TransportMetricsSnapshot struct {
	// Counters for total operations
	OperationsTotal map[TransportMetricsKey]uint64
	// Histogram buckets for operation durations (in milliseconds)
	// Key: TransportMetricsKey, Value: histogram buckets
	OperationDurationMs map[TransportMetricsKey][]uint64
	// Payload size histogram (in bytes)
	// Key: TransportMethod, Value: histogram buckets
	PayloadBytes map[TransportMethod][]uint64
	// Current concurrent operations gauge
	ConcurrentOperations map[TransportMethod]int64
	// Retry attempt counter
	RetryAttemptsTotal map[TransportMetricsKey]uint64
	// Timestamp of snapshot
	TimestampUnix time.Time
}

// TransportMetrics provides metrics collection for fixture distribution transports
type TransportMetrics struct {
	mu sync.RWMutex

	// Counters
	operationsTotal map[TransportMetricsKey]uint64

	// Histograms (for duration and payload size)
	// We use fixed buckets: [0, 10, 50, 100, 500, 1000, 5000, 10000, 30000, 60000, +inf]
	durationBucketsMs []uint64
	payloadBuckets    []uint64

	// Operation duration histogram data
	// Key: TransportMetricsKey, Value: count per bucket
	operationDurations map[TransportMetricsKey][]uint64

	// Payload size histogram data
	// Key: TransportMethod, Value: count per bucket
	payloadSizes map[TransportMethod][]uint64

	// Gauges
	concurrentOperations map[TransportMethod]int64

	// Retry counters
	retryAttemptsTotal map[TransportMetricsKey]uint64

	// Timestamp
	timestampUnix time.Time
}

// NewTransportMetrics creates a new TransportMetrics instance
func NewTransportMetrics() *TransportMetrics {
	// Initialize with standard histogram buckets (in ms for duration, in bytes for payload)
	// Duration buckets: 0ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s, 10s, 30s, 60s, +inf
	durationBuckets := []uint64{0, 10, 50, 100, 500, 1000, 5000, 10000, 30000, 60000}

	// Payload buckets: 0B, 1KB, 10KB, 100KB, 1MB, 10MB, +inf
	payloadBuckets := []uint64{0, 1024, 10240, 102400, 1048576, 10485760}

	return &TransportMetrics{
		operationsTotal:      make(map[TransportMetricsKey]uint64),
		operationDurations:   make(map[TransportMetricsKey][]uint64),
		payloadSizes:         make(map[TransportMethod][]uint64),
		concurrentOperations: make(map[TransportMethod]int64),
		retryAttemptsTotal:   make(map[TransportMetricsKey]uint64),
		durationBucketsMs:    durationBuckets,
		payloadBuckets:       payloadBuckets,
		timestampUnix:        time.Now().UTC(),
	}
}

// RecordOperation records a transport operation with timing and outcome
func (m *TransportMetrics) RecordOperation(method TransportMethod, operation TransportOperation,
	durationMs uint64, payloadBytes uint64, outcome TransportOutcome) {

	if m == nil {
		return
	}

	key := TransportMetricsKey{
		Method:    method,
		Operation: operation,
		Outcome:   outcome,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Increment operation counter
	m.operationsTotal[key]++

	// Record duration in histogram
	if m.operationDurations[key] == nil {
		m.operationDurations[key] = make([]uint64, len(m.durationBucketsMs)+1)
	}
	bucket := m.findDurationBucket(durationMs)
	m.operationDurations[key][bucket]++

	// Record payload size in histogram
	if payloadBytes > 0 {
		if m.payloadSizes[method] == nil {
			m.payloadSizes[method] = make([]uint64, len(m.payloadBuckets)+1)
		}
		payloadBucket := m.findPayloadBucket(payloadBytes)
		m.payloadSizes[method][payloadBucket]++
	}

	// Update timestamp
	m.timestampUnix = time.Now().UTC()
}

// IncrementConcurrent starts tracking a concurrent operation
func (m *TransportMetrics) IncrementConcurrent(method TransportMethod) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.concurrentOperations[method]++
}

// DecrementConcurrent stops tracking a concurrent operation
func (m *TransportMetrics) DecrementConcurrent(method TransportMethod) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.concurrentOperations[method] > 0 {
		m.concurrentOperations[method]--
	}
}

// RecordRetry records a retry attempt
func (m *TransportMetrics) RecordRetry(method TransportMethod, operation TransportOperation, outcome TransportOutcome) {
	if m == nil {
		return
	}
	key := TransportMetricsKey{
		Method:    method,
		Operation: operation,
		Outcome:   outcome,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retryAttemptsTotal[key]++
}

// Snapshot returns a snapshot of the current metrics
func (m *TransportMetrics) Snapshot() TransportMetricsSnapshot {
	if m == nil {
		return TransportMetricsSnapshot{
			OperationsTotal:      make(map[TransportMetricsKey]uint64),
			OperationDurationMs:  make(map[TransportMetricsKey][]uint64),
			PayloadBytes:         make(map[TransportMethod][]uint64),
			ConcurrentOperations: make(map[TransportMethod]int64),
			RetryAttemptsTotal:   make(map[TransportMetricsKey]uint64),
			TimestampUnix:        time.Now().UTC(),
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	snapshot := TransportMetricsSnapshot{
		OperationsTotal:      make(map[TransportMetricsKey]uint64),
		OperationDurationMs:  make(map[TransportMetricsKey][]uint64),
		PayloadBytes:         make(map[TransportMethod][]uint64),
		ConcurrentOperations: make(map[TransportMethod]int64),
		RetryAttemptsTotal:   make(map[TransportMetricsKey]uint64),
		TimestampUnix:        m.timestampUnix,
	}

	// Copy counters
	for key, value := range m.operationsTotal {
		snapshot.OperationsTotal[key] = value
	}

	// Copy duration histograms
	for key, buckets := range m.operationDurations {
		snapshot.OperationDurationMs[key] = append([]uint64(nil), buckets...)
	}

	// Copy payload histograms
	for method, buckets := range m.payloadSizes {
		snapshot.PayloadBytes[method] = append([]uint64(nil), buckets...)
	}

	// Copy gauges
	for method, count := range m.concurrentOperations {
		snapshot.ConcurrentOperations[method] = count
	}

	// Copy retry counters
	for key, value := range m.retryAttemptsTotal {
		snapshot.RetryAttemptsTotal[key] = value
	}

	return snapshot
}

// Reset clears all metrics
func (m *TransportMetrics) Reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.operationsTotal = make(map[TransportMetricsKey]uint64)
	m.operationDurations = make(map[TransportMetricsKey][]uint64)
	m.payloadSizes = make(map[TransportMethod][]uint64)
	m.concurrentOperations = make(map[TransportMethod]int64)
	m.retryAttemptsTotal = make(map[TransportMetricsKey]uint64)
	m.timestampUnix = time.Now().UTC()
}

// findDurationBucket returns the bucket index for a given duration
// Uses exponential-ish buckets: 0, 10, 50, 100, 500, 1000, 5000, 10000, 30000, 60000, +inf
func (m *TransportMetrics) findDurationBucket(durationMs uint64) int {
	buckets := m.durationBucketsMs
	for i, threshold := range buckets {
		if durationMs < threshold {
			return i
		}
	}
	return len(buckets) // +inf bucket
}

// findPayloadBucket returns the bucket index for a given payload size
// Uses buckets: 0, 1KB, 10KB, 100KB, 1MB, 10MB, +inf
func (m *TransportMetrics) findPayloadBucket(payloadBytes uint64) int {
	buckets := m.payloadBuckets
	for i, threshold := range buckets {
		if payloadBytes < threshold {
			return i
		}
	}
	return len(buckets) // +inf bucket
}

// TransportMetricsRecorder interface for dependency injection
type TransportMetricsRecorder interface {
	RecordOperation(method TransportMethod, operation TransportOperation, durationMs uint64, payloadBytes uint64, outcome TransportOutcome)
	IncrementConcurrent(method TransportMethod)
	DecrementConcurrent(method TransportMethod)
	RecordRetry(method TransportMethod, operation TransportOperation, outcome TransportOutcome)
	Snapshot() TransportMetricsSnapshot
	Reset()
}

// NopTransportMetricsRecorder is a no-op implementation for testing
type NopTransportMetricsRecorder struct{}

// RecordOperation does nothing
func (n *NopTransportMetricsRecorder) RecordOperation(method TransportMethod, operation TransportOperation,
	durationMs uint64, payloadBytes uint64, outcome TransportOutcome) {
}

// IncrementConcurrent does nothing
func (n *NopTransportMetricsRecorder) IncrementConcurrent(method TransportMethod) {}

// DecrementConcurrent does nothing
func (n *NopTransportMetricsRecorder) DecrementConcurrent(method TransportMethod) {}

// RecordRetry does nothing
func (n *NopTransportMetricsRecorder) RecordRetry(method TransportMethod, operation TransportOperation, outcome TransportOutcome) {
}

// Snapshot returns empty snapshot
func (n *NopTransportMetricsRecorder) Snapshot() TransportMetricsSnapshot {
	return TransportMetricsSnapshot{
		OperationsTotal:      make(map[TransportMetricsKey]uint64),
		OperationDurationMs:  make(map[TransportMetricsKey][]uint64),
		PayloadBytes:         make(map[TransportMethod][]uint64),
		ConcurrentOperations: make(map[TransportMethod]int64),
		RetryAttemptsTotal:   make(map[TransportMetricsKey]uint64),
		TimestampUnix:        time.Now().UTC(),
	}
}

// Reset does nothing
func (n *NopTransportMetricsRecorder) Reset() {}

// Global default metrics recorder
var defaultTransportMetricsRecorder TransportMetricsRecorder = NewTransportMetrics()

// SetDefaultTransportMetricsRecorder sets the global metrics recorder
func SetDefaultTransportMetricsRecorder(recorder TransportMetricsRecorder) {
	defaultTransportMetricsRecorder = recorder
}

// GetDefaultTransportMetricsRecorder returns the global metrics recorder
func GetDefaultTransportMetricsRecorder() TransportMetricsRecorder {
	return defaultTransportMetricsRecorder
}

// RecordTransportOperation records an operation using the default recorder
func RecordTransportOperation(method TransportMethod, operation TransportOperation,
	durationMs uint64, payloadBytes uint64, outcome TransportOutcome) {
	defaultTransportMetricsRecorder.RecordOperation(method, operation, durationMs, payloadBytes, outcome)
}

// IncrementTransportConcurrent increments concurrent using the default recorder
func IncrementTransportConcurrent(method TransportMethod) {
	defaultTransportMetricsRecorder.IncrementConcurrent(method)
}

// DecrementTransportConcurrent decrements concurrent using the default recorder
func DecrementTransportConcurrent(method TransportMethod) {
	defaultTransportMetricsRecorder.DecrementConcurrent(method)
}

// RecordTransportRetry records a retry using the default recorder
func RecordTransportRetry(method TransportMethod, operation TransportOperation, outcome TransportOutcome) {
	defaultTransportMetricsRecorder.RecordRetry(method, operation, outcome)
}
