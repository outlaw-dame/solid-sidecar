package authz

import (
	"strings"
	"testing"
	"time"
)

// TestTransportMetricsCreation tests that metrics can be created
func TestTransportMetricsCreation(t *testing.T) {
	metrics := NewTransportMetrics()
	if metrics == nil {
		t.Fatal("Expected non-nil metrics")
	}

	// Verify buckets are initialized
	if len(metrics.durationBucketsMs) == 0 {
		t.Error("Expected duration buckets to be initialized")
	}
	if len(metrics.payloadBuckets) == 0 {
		t.Error("Expected payload buckets to be initialized")
	}
}

// TestRecordOperation tests recording a single operation
func TestRecordOperation(t *testing.T) {
	metrics := NewTransportMetrics()

	start := time.Now()
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 100, 1024, TransportOutcomeSuccess)
	duration := time.Since(start).Milliseconds()

	snapshot := metrics.Snapshot()

	key := TransportMetricsKey{
		Method:    TransportMethodS3,
		Operation: TransportOpDistribute,
		Outcome:   TransportOutcomeSuccess,
	}

	if snapshot.OperationsTotal[key] != 1 {
		t.Errorf("Expected 1 operation, got %d", snapshot.OperationsTotal[key])
	}

	if duration >= 10 {
		t.Logf("Warning: Recording operation took %d ms", duration)
	}
}

// TestRecordMultipleOperations tests recording multiple operations
func TestRecordMultipleOperations(t *testing.T) {
	metrics := NewTransportMetrics()

	// Record multiple operations
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 100, 1024, TransportOutcomeSuccess)
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 200, 2048, TransportOutcomeSuccess)
	metrics.RecordOperation(TransportMethodSSH, TransportOpDistribute, 50, 512, TransportOutcomeFailure)

	snapshot := metrics.Snapshot()

	// Check S3 success count
	s3Key := TransportMetricsKey{
		Method:    TransportMethodS3,
		Operation: TransportOpDistribute,
		Outcome:   TransportOutcomeSuccess,
	}
	if snapshot.OperationsTotal[s3Key] != 2 {
		t.Errorf("Expected 2 S3 success operations, got %d", snapshot.OperationsTotal[s3Key])
	}

	// Check SSH failure count
	sshKey := TransportMetricsKey{
		Method:    TransportMethodSSH,
		Operation: TransportOpDistribute,
		Outcome:   TransportOutcomeFailure,
	}
	if snapshot.OperationsTotal[sshKey] != 1 {
		t.Errorf("Expected 1 SSH failure operation, got %d", snapshot.OperationsTotal[sshKey])
	}
}

// TestConcurrentOperations tests concurrent operation tracking
func TestConcurrentOperations(t *testing.T) {
	metrics := NewTransportMetrics()

	// Increment concurrent
	metrics.IncrementConcurrent(TransportMethodS3)
	metrics.IncrementConcurrent(TransportMethodS3)
	metrics.IncrementConcurrent(TransportMethodSSH)

	snapshot := metrics.Snapshot()

	if snapshot.ConcurrentOperations[TransportMethodS3] != 2 {
		t.Errorf("Expected 2 concurrent S3 operations, got %d", snapshot.ConcurrentOperations[TransportMethodS3])
	}
	if snapshot.ConcurrentOperations[TransportMethodSSH] != 1 {
		t.Errorf("Expected 1 concurrent SSH operation, got %d", snapshot.ConcurrentOperations[TransportMethodSSH])
	}

	// Decrement concurrent
	metrics.DecrementConcurrent(TransportMethodS3)
	snapshot = metrics.Snapshot()

	if snapshot.ConcurrentOperations[TransportMethodS3] != 1 {
		t.Errorf("Expected 1 concurrent S3 operation after decrement, got %d", snapshot.ConcurrentOperations[TransportMethodS3])
	}
}

// TestConcurrentOperationsCannotGoNegative tests that concurrent count doesn't go negative
func TestConcurrentOperationsCannotGoNegative(t *testing.T) {
	metrics := NewTransportMetrics()

	// Decrement without incrementing
	metrics.DecrementConcurrent(TransportMethodS3)

	snapshot := metrics.Snapshot()

	if snapshot.ConcurrentOperations[TransportMethodS3] != 0 {
		t.Errorf("Expected 0 concurrent operations (cannot be negative), got %d", snapshot.ConcurrentOperations[TransportMethodS3])
	}
}

// TestRecordRetry tests retry recording
func TestRecordRetry(t *testing.T) {
	metrics := NewTransportMetrics()

	metrics.RecordRetry(TransportMethodS3, TransportOpDistribute, TransportOutcomeRetry)
	metrics.RecordRetry(TransportMethodS3, TransportOpDistribute, TransportOutcomeRetry)

	snapshot := metrics.Snapshot()

	key := TransportMetricsKey{
		Method:    TransportMethodS3,
		Operation: TransportOpDistribute,
		Outcome:   TransportOutcomeRetry,
	}

	if snapshot.RetryAttemptsTotal[key] != 2 {
		t.Errorf("Expected 2 retry attempts, got %d", snapshot.RetryAttemptsTotal[key])
	}
}

// TestReset tests that metrics can be reset
func TestReset(t *testing.T) {
	metrics := NewTransportMetrics()

	// Add some data
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 100, 1024, TransportOutcomeSuccess)
	metrics.IncrementConcurrent(TransportMethodS3)
	metrics.RecordRetry(TransportMethodS3, TransportOpDistribute, TransportOutcomeRetry)

	// Verify data exists
	snapshot := metrics.Snapshot()
	if len(snapshot.OperationsTotal) == 0 {
		t.Fatal("Expected operations to be recorded")
	}

	// Reset
	metrics.Reset()

	// Verify data is cleared
	snapshot = metrics.Snapshot()
	if len(snapshot.OperationsTotal) != 0 {
		t.Error("Expected operations to be cleared after reset")
	}
	if len(snapshot.ConcurrentOperations) != 0 {
		t.Error("Expected concurrent operations to be cleared after reset")
	}
	if len(snapshot.RetryAttemptsTotal) != 0 {
		t.Error("Expected retry attempts to be cleared after reset")
	}
}

// TestDurationBuckets tests duration histogram buckets
func TestDurationBuckets(t *testing.T) {
	metrics := NewTransportMetrics()

	// Record operations with different durations
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 5, 0, TransportOutcomeSuccess)      // < 10ms
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 50, 0, TransportOutcomeSuccess)     // < 100ms
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 1000, 0, TransportOutcomeSuccess)   // 1s
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 10000, 0, TransportOutcomeSuccess)  // 10s
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 100000, 0, TransportOutcomeSuccess) // > 60s

	snapshot := metrics.Snapshot()
	key := TransportMetricsKey{
		Method:    TransportMethodS3,
		Operation: TransportOpDistribute,
		Outcome:   TransportOutcomeSuccess,
	}

	buckets := snapshot.OperationDurationMs[key]
	if len(buckets) == 0 {
		t.Fatal("Expected duration buckets to be recorded")
	}

	// Verify total count
	var total uint64
	for _, count := range buckets {
		total += count
	}
	if total != 5 {
		t.Errorf("Expected 5 total operations in duration buckets, got %d", total)
	}
}

// TestPayloadBuckets tests payload size histogram buckets
func TestPayloadBuckets(t *testing.T) {
	metrics := NewTransportMetrics()

	// Record operations with different payload sizes
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 0, 512, TransportOutcomeSuccess)      // < 1KB
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 0, 5120, TransportOutcomeSuccess)     // < 10KB
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 0, 51200, TransportOutcomeSuccess)    // < 100KB
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 0, 524288, TransportOutcomeSuccess)   // < 1MB
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 0, 5242880, TransportOutcomeSuccess)  // < 5MB
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 0, 15728640, TransportOutcomeSuccess) // > 10MB

	snapshot := metrics.Snapshot()
	buckets := snapshot.PayloadBytes[TransportMethodS3]

	if len(buckets) == 0 {
		t.Fatal("Expected payload buckets to be recorded")
	}

	// Verify total count
	var total uint64
	for _, count := range buckets {
		total += count
	}
	if total != 6 {
		t.Errorf("Expected 6 total payload operations in buckets, got %d", total)
	}
}

// TestNopTransportMetricsRecorder tests the no-op recorder
func TestNopTransportMetricsRecorder(t *testing.T) {
	recorder := &NopTransportMetricsRecorder{}

	// All operations should be safe
	recorder.RecordOperation(TransportMethodS3, TransportOpDistribute, 100, 1024, TransportOutcomeSuccess)
	recorder.IncrementConcurrent(TransportMethodS3)
	recorder.DecrementConcurrent(TransportMethodS3)
	recorder.RecordRetry(TransportMethodS3, TransportOpDistribute, TransportOutcomeRetry)

	snapshot := recorder.Snapshot()
	if len(snapshot.OperationsTotal) != 0 {
		t.Error("Expected no operations in no-op recorder")
	}

	recorder.Reset() // Should not panic
}

// TestGlobalRecorder tests the global recorder functions
func TestGlobalRecorder(t *testing.T) {
	// Get the default recorder
	recorder := GetDefaultTransportMetricsRecorder()
	if recorder == nil {
		t.Fatal("Expected non-nil default recorder")
	}

	// Record using global functions
	RecordTransportOperation(TransportMethodHTTP, TransportOpDistribute, 50, 1024, TransportOutcomeSuccess)
	IncrementTransportConcurrent(TransportMethodHTTP)
	RecordTransportRetry(TransportMethodHTTP, TransportOpDistribute, TransportOutcomeRetry)

	snapshot := recorder.Snapshot()
	key := TransportMetricsKey{
		Method:    TransportMethodHTTP,
		Operation: TransportOpDistribute,
		Outcome:   TransportOutcomeSuccess,
	}

	if snapshot.OperationsTotal[key] != 1 {
		t.Errorf("Expected 1 operation in global recorder, got %d", snapshot.OperationsTotal[key])
	}

	if snapshot.ConcurrentOperations[TransportMethodHTTP] != 1 {
		t.Errorf("Expected 1 concurrent operation in global recorder, got %d", snapshot.ConcurrentOperations[TransportMethodHTTP])
	}

	// Clean up
	DecrementTransportConcurrent(TransportMethodHTTP)
}

// TestMetricKeyString tests that metric keys can be converted to strings
func TestMetricKeyString(t *testing.T) {
	key := TransportMetricsKey{
		Method:    TransportMethodS3,
		Operation: TransportOpDistribute,
		Outcome:   TransportOutcomeSuccess,
	}

	// Just verify it doesn't panic
	_ = key

	// Test that we can use it as a map key
	m := make(map[TransportMetricsKey]bool)
	m[key] = true

	if !m[key] {
		t.Error("Expected to find key in map")
	}
}

// TestAllTransportMethods tests all transport method constants
func TestAllTransportMethods(t *testing.T) {
	methods := []TransportMethod{
		TransportMethodHTTP,
		TransportMethodS3,
		TransportMethodSSH,
		TransportMethodLocal,
		TransportMethodUnknown,
	}

	for _, method := range methods {
		if strings.TrimSpace(string(method)) == "" {
			t.Errorf("Expected non-empty transport method, got: %s", method)
		}
	}
}

// TestAllOperations tests all operation constants
func TestAllOperations(t *testing.T) {
	operations := []TransportOperation{
		TransportOpDistribute,
		TransportOpValidate,
		TransportOpConnect,
		TransportOpUpload,
		TransportOpDownload,
	}

	for _, op := range operations {
		if strings.TrimSpace(string(op)) == "" {
			t.Errorf("Expected non-empty operation, got: %s", op)
		}
	}
}

// TestAllOutcomes tests all outcome constants
func TestAllOutcomes(t *testing.T) {
	outcomes := []TransportOutcome{
		TransportOutcomeSuccess,
		TransportOutcomeFailure,
		TransportOutcomeTimeout,
		TransportOutcomeRetry,
		TransportOutcomeCancelled,
	}

	for _, outcome := range outcomes {
		if strings.TrimSpace(string(outcome)) == "" {
			t.Errorf("Expected non-empty outcome, got: %s", outcome)
		}
	}
}

// TestSnapshotImmutability tests that snapshot doesn't change with subsequent operations
func TestSnapshotImmutability(t *testing.T) {
	metrics := NewTransportMetrics()

	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 100, 1024, TransportOutcomeSuccess)

	snapshot := metrics.Snapshot()

	// Record more operations
	metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, 100, 1024, TransportOutcomeSuccess)

	// Snapshot should not have changed
	key := TransportMetricsKey{
		Method:    TransportMethodS3,
		Operation: TransportOpDistribute,
		Outcome:   TransportOutcomeSuccess,
	}

	if snapshot.OperationsTotal[key] != 1 {
		t.Errorf("Expected snapshot to have 1 operation (immutable), got %d", snapshot.OperationsTotal[key])
	}
}

// TestNilRecorder tests that nil recorder (Nop implementation) doesn't panic
func TestNilRecorder(t *testing.T) {
	// Use the Nop recorder which is safe for all operations
	recorder := &NopTransportMetricsRecorder{}

	// All these should not panic
	recorder.RecordOperation(TransportMethodS3, TransportOpDistribute, 100, 1024, TransportOutcomeSuccess)
	recorder.IncrementConcurrent(TransportMethodS3)
	recorder.DecrementConcurrent(TransportMethodS3)
	recorder.RecordRetry(TransportMethodS3, TransportOpDistribute, TransportOutcomeRetry)

	snapshot := recorder.Snapshot()
	_ = snapshot

	recorder.Reset()
}

// TestSetDefaultRecorder tests setting a custom default recorder
func TestSetDefaultRecorder(t *testing.T) {
	original := GetDefaultTransportMetricsRecorder()

	// Set a new default
	custom := NewTransportMetrics()
	SetDefaultTransportMetricsRecorder(custom)

	if GetDefaultTransportMetricsRecorder() != custom {
		t.Error("Expected custom recorder to be the default")
	}

	// Record using global functions
	RecordTransportOperation(TransportMethodS3, TransportOpDistribute, 100, 1024, TransportOutcomeSuccess)

	snapshot := custom.Snapshot()
	key := TransportMetricsKey{
		Method:    TransportMethodS3,
		Operation: TransportOpDistribute,
		Outcome:   TransportOutcomeSuccess,
	}

	if snapshot.OperationsTotal[key] != 1 {
		t.Errorf("Expected 1 operation in custom recorder, got %d", snapshot.OperationsTotal[key])
	}

	// Restore original
	SetDefaultTransportMetricsRecorder(original)
}

// BenchmarkTransportMetrics benchmarks metrics recording
func BenchmarkTransportMetrics(b *testing.B) {
	metrics := NewTransportMetrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, uint64(i%1000), uint64(i%10000), TransportOutcomeSuccess)
	}
}

// BenchmarkTransportMetricsConcurrent benchmarks concurrent metrics recording
func BenchmarkTransportMetricsConcurrent(b *testing.B) {
	metrics := NewTransportMetrics()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := uint64(0)
		for pb.Next() {
			metrics.RecordOperation(TransportMethodS3, TransportOpDistribute, i%1000, i%10000, TransportOutcomeSuccess)
			i++
		}
	})
}
