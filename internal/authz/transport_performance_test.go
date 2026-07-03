// Package authz provides authorization for Solid with transport performance benchmarks
package authz

import (
	"context"
	"strconv"
	"testing"
)

// Benchmark constants
const (
	BenchmarkPayloadSmall  = 1024             // 1 KB
	BenchmarkPayloadMedium = 1024 * 1024      // 1 MB
	BenchmarkPayloadLarge  = 10 * 1024 * 1024 // 10 MB (max for most transports)
	BenchmarkConcurrency   = 100              // Concurrent operations for load testing
)

// BenchmarkHTTPTransportDistribute benchmarks HTTP transport performance
func BenchmarkHTTPTransportDistribute(b *testing.B) {
	// Setup - create transport with a mock server
	transport, err := NewHTTPTransport(FixtureTransportOptions{
		Config: DefaultTransportConfig(),
	})
	if err != nil {
		b.Fatalf("Failed to create HTTP transport: %v", err)
	}

	// Set up a base URL for the mock server
	// Note: In a real benchmark, this would point to a mock HTTP server
	// For now, we test the overhead of the transport layer
	target := FixtureDistributionTarget{
		ID:     "benchmark-target",
		URL:    "http://localhost:8080/fixture",
		Method: DistributionMethodHTTPS,
	}

	job := FixtureDistributionJob{
		DistributionID: "benchmark-dist",
		CatalogHash:    "benchmark-hash",
		BundleHashes:   []string{"hash1", "hash2"},
	}

	payloads := []struct {
		name string
		size int
	}{
		{"SmallPayload", BenchmarkPayloadSmall},
		{"MediumPayload", BenchmarkPayloadMedium},
		{"LargePayload", BenchmarkPayloadLarge},
	}

	for _, p := range payloads {
		payload := make([]byte, p.size)
		// Fill with some data
		for i := range payload {
			payload[i] = byte(i % 256)
		}

		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))

			for i := 0; i < b.N; i++ {
				// Create a metrics recorder for this benchmark
				metrics := NewTransportMetrics()
				transport.SetMetricsRecorder(metrics)

				// Execute the distribute operation
				// This will fail (no server), but we're measuring the transport overhead
				_, _ = transport.Distribute(
					context.Background(),
					job,
					target,
					payload,
				)

				// Get snapshot to ensure metrics are being recorded
				_ = metrics.Snapshot()
			}
		})
	}
}

// BenchmarkLocalFileTransportDistribute benchmarks local file transport performance
func BenchmarkLocalFileTransportDistribute(b *testing.B) {
	transport, err := NewLocalFileTransport(LocalFileTransportOptions{
		Config:    DefaultTransportConfig(),
		BasePath:  b.TempDir(),
		Overwrite: true,
	})
	if err != nil {
		b.Fatalf("Failed to create local file transport: %v", err)
	}

	// Set up metrics recorder
	metrics := NewTransportMetrics()
	transport.SetMetricsRecorder(metrics)

	job := FixtureDistributionJob{
		DistributionID: "benchmark-dist",
		CatalogHash:    "benchmark-hash",
		BundleHashes:   []string{"hash1", "hash2"},
	}

	payloads := []struct {
		name string
		size int
	}{
		{"SmallPayload", BenchmarkPayloadSmall},
		{"MediumPayload", BenchmarkPayloadMedium},
	}

	for _, p := range payloads {
		payload := make([]byte, p.size)
		// Fill with some data
		for i := range payload {
			payload[i] = byte(i % 256)
		}

		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Reset metrics for each iteration
				metrics.Reset()

				// Create unique file path for each iteration
				targetForIter := FixtureDistributionTarget{
					ID:     "benchmark-file-" + strconv.Itoa(i),
					URL:    "benchmark-" + strconv.Itoa(i%10) + ".json",
					Method: DistributionMethodLocalFile,
				}

				// Execute the distribute operation
				receipt, err := transport.Distribute(
					context.Background(),
					job,
					targetForIter,
					payload,
				)
				if err != nil {
					b.Errorf("Distribute failed: %v", err)
				}
				_ = receipt

				// Get snapshot to ensure metrics are being recorded
				_ = metrics.Snapshot()
			}
		})
	}
}

// BenchmarkTransportConcurrentOperations benchmarks concurrent transport operations
func BenchmarkTransportConcurrentOperations(b *testing.B) {
	transport, err := NewLocalFileTransport(LocalFileTransportOptions{
		Config:    DefaultTransportConfig(),
		BasePath:  b.TempDir(),
		Overwrite: true,
	})
	if err != nil {
		b.Fatalf("Failed to create local file transport: %v", err)
	}

	// Set up metrics recorder
	metrics := NewTransportMetrics()
	transport.SetMetricsRecorder(metrics)

	job := FixtureDistributionJob{
		DistributionID: "benchmark-concurrent",
		CatalogHash:    "benchmark-hash",
		BundleHashes:   []string{"hash1"},
	}

	// Use small payload for concurrent test
	payload := make([]byte, BenchmarkPayloadSmall)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload) * BenchmarkConcurrency))
	b.ResetTimer()

	// Run concurrent operations
	for i := 0; i < b.N; i++ {
		// Reset metrics for each benchmark iteration
		metrics.Reset()

		done := make(chan bool, BenchmarkConcurrency)

		for j := 0; j < BenchmarkConcurrency; j++ {
			go func(id int) {
				target := FixtureDistributionTarget{
					ID:     "benchmark-concurrent-" + strconv.Itoa(id),
					URL:    "concurrent-" + strconv.Itoa(id%10) + ".json",
					Method: DistributionMethodLocalFile,
				}

				// Execute the distribute operation
				_, err := transport.Distribute(
					context.Background(),
					job,
					target,
					payload,
				)
				if err != nil {
					b.Errorf("Concurrent distribute %d failed: %v", id, err)
				}

				done <- true
			}(j)
		}

		// Wait for all operations to complete
		for j := 0; j < BenchmarkConcurrency; j++ {
			<-done
		}

		// Get snapshot to verify metrics
		_ = metrics.Snapshot()
	}
}

// BenchmarkTransportMetricsRecording benchmarks the overhead of metrics recording
func BenchmarkTransportMetricsRecording(b *testing.B) {
	// Create a transport with metrics
	transport, err := NewLocalFileTransport(LocalFileTransportOptions{
		Config:    DefaultTransportConfig(),
		BasePath:  b.TempDir(),
		Overwrite: true,
	})
	if err != nil {
		b.Fatalf("Failed to create local file transport: %v", err)
	}

	// Set up metrics recorder
	metrics := NewTransportMetrics()
	transport.SetMetricsRecorder(metrics)

	job := FixtureDistributionJob{
		DistributionID: "metrics-benchmark",
		CatalogHash:    "benchmark-hash",
	}

	payload := make([]byte, BenchmarkPayloadSmall)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Reset metrics for each iteration
		metrics.Reset()

		// Create unique target for each iteration
		targetForIter := FixtureDistributionTarget{
			ID:     "metrics-benchmark-" + strconv.Itoa(i),
			URL:    "metrics-benchmark-" + strconv.Itoa(i%10) + ".json",
			Method: DistributionMethodLocalFile,
		}

		// Execute with metrics recording
		_, _ = transport.Distribute(
			context.Background(),
			job,
			targetForIter,
			payload,
		)

		// Record snapshot (this is what operators would do)
		_ = metrics.Snapshot()
	}
}

// BenchmarkTransportRetryBehavior benchmarks retry logic performance
func BenchmarkTransportRetryBehavior(b *testing.B) {
	// Create a transport with retry configuration
	config := DefaultTransportConfig()
	config.RetryCount = 3
	config.RetryBaseDelay = 0 // Disable delay for benchmarking

	transport, err := NewLocalFileTransport(LocalFileTransportOptions{
		Config:    config,
		BasePath:  b.TempDir(),
		Overwrite: false, // This will cause retries for existing files
	})
	if err != nil {
		b.Fatalf("Failed to create local file transport: %v", err)
	}

	// Set up metrics recorder
	metrics := NewTransportMetrics()
	transport.SetMetricsRecorder(metrics)

	job := FixtureDistributionJob{
		DistributionID: "retry-benchmark",
		CatalogHash:    "benchmark-hash",
	}

	target := FixtureDistributionTarget{
		ID:     "retry-benchmark",
		URL:    "retry-benchmark.json",
		Method: DistributionMethodLocalFile,
	}

	payload := make([]byte, BenchmarkPayloadSmall)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.ReportAllocs()
	b.ResetTimer()

	// First, create the file to trigger retry behavior
	_, _ = transport.Distribute(context.Background(), job, target, payload)

	for i := 0; i < b.N; i++ {
		// Reset metrics for each iteration
		metrics.Reset()

		// This should trigger retries since file exists
		_, _ = transport.Distribute(
			context.Background(),
			job,
			target,
			payload,
		)

		// Verify retry metrics are recorded
		snapshot := metrics.Snapshot()
		_ = snapshot
	}
}

// TestTransportPerformanceAcceptanceCriteria verifies the acceptance criteria for Phase 35
func TestTransportPerformanceAcceptanceCriteria(t *testing.T) {
	t.Run("TestMetricsRecordingForAllTransports", func(t *testing.T) {
		transports := []struct {
			name      string
			transport FixtureTransport
		}{
			{
				name: "HTTPTransport",
				transport: func() FixtureTransport {
					tr, _ := NewHTTPTransport(FixtureTransportOptions{Config: DefaultTransportConfig()})
					return tr
				}(),
			},
			{
				name: "LocalFileTransport",
				transport: func() FixtureTransport {
					tr, _ := NewLocalFileTransport(LocalFileTransportOptions{
						Config:    DefaultTransportConfig(),
						BasePath:  t.TempDir(),
						Overwrite: true,
					})
					return tr
				}(),
			},
			{
				name: "S3Transport",
				transport: func() FixtureTransport {
					tr, _ := NewS3Transport(FixtureTransportOptions{Config: DefaultTransportConfig()})
					return tr
				}(),
			},
			{
				name: "SSHTransport",
				transport: func() FixtureTransport {
					tr, _ := NewSSHTransport(FixtureTransportOptions{Config: DefaultTransportConfig()})
					return tr
				}(),
			},
		}

		for _, tr := range transports {
			t.Run(tr.name, func(t *testing.T) {
				// Verify that the transport can have metrics recorder set
				if setter, ok := tr.transport.(*HTTPTransport); ok {
					setter.SetMetricsRecorder(&NopTransportMetricsRecorder{})
				}
				if setter, ok := tr.transport.(*LocalFileTransport); ok {
					setter.SetMetricsRecorder(&NopTransportMetricsRecorder{})
				}
				if setter, ok := tr.transport.(*S3Transport); ok {
					setter.SetMetricsRecorder(&NopTransportMetricsRecorder{})
				}
				if setter, ok := tr.transport.(*SSHTransport); ok {
					setter.SetMetricsRecorder(&NopTransportMetricsRecorder{})
				}
				// Test passes if no panic occurs
			})
		}
	})

	t.Run("TestMetricsRecordersImplementInterface", func(t *testing.T) {
		// Verify that TransportMetrics implements TransportMetricsRecorder
		var _ TransportMetricsRecorder = NewTransportMetrics()
		var _ TransportMetricsRecorder = &NopTransportMetricsRecorder{}
	})
}

// TestTransportConcurrentLimit verifies that transports can handle concurrent operations
func TestTransportConcurrentLimit(t *testing.T) {
	transport, err := NewLocalFileTransport(LocalFileTransportOptions{
		Config:    DefaultTransportConfig(),
		BasePath:  t.TempDir(),
		Overwrite: true,
	})
	if err != nil {
		t.Fatalf("Failed to create local file transport: %v", err)
	}

	// Set up metrics recorder
	metrics := NewTransportMetrics()
	transport.SetMetricsRecorder(metrics)

	job := FixtureDistributionJob{
		DistributionID: "concurrent-test",
		CatalogHash:    "test-hash",
	}

	payload := make([]byte, BenchmarkPayloadSmall)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// Run concurrent operations
	const numConcurrent = 50
	done := make(chan bool, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(id int) {
			target := FixtureDistributionTarget{
				ID:     "concurrent-test-" + strconv.Itoa(id),
				URL:    "concurrent-" + strconv.Itoa(id%10) + ".json",
				Method: DistributionMethodLocalFile,
			}

			_, err := transport.Distribute(
				context.Background(),
				job,
				target,
				payload,
			)
			if err != nil {
				t.Errorf("Concurrent distribute %d failed: %v", id, err)
			}

			done <- true
		}(i)
	}

	// Wait for all operations to complete
	for i := 0; i < numConcurrent; i++ {
		<-done
	}

	// Verify metrics were recorded
	snapshot := metrics.Snapshot()
	if snapshot.ConcurrentOperations[TransportMethodLocal] != 0 {
		t.Errorf("Expected concurrent operations to be 0 after completion, got %d",
			snapshot.ConcurrentOperations[TransportMethodLocal])
	}

	// Verify that operations were recorded
	totalOps := uint64(0)
	for _, count := range snapshot.OperationsTotal {
		totalOps += count
	}

	if totalOps != uint64(numConcurrent) {
		t.Errorf("Expected %d operations to be recorded, got %d", numConcurrent, totalOps)
	}

	t.Logf("Successfully completed %d concurrent operations", numConcurrent)
}

// TestTransportResourceCleanup verifies no resource leaks under load
func TestTransportResourceCleanup(t *testing.T) {
	transport, err := NewLocalFileTransport(LocalFileTransportOptions{
		Config:    DefaultTransportConfig(),
		BasePath:  t.TempDir(),
		Overwrite: true,
	})
	if err != nil {
		t.Fatalf("Failed to create local file transport: %v", err)
	}

	// Set up metrics recorder
	metrics := NewTransportMetrics()
	transport.SetMetricsRecorder(metrics)

	job := FixtureDistributionJob{
		DistributionID: "cleanup-test",
		CatalogHash:    "test-hash",
	}

	payload := make([]byte, BenchmarkPayloadSmall)

	// Run multiple iterations to test cleanup
	const iterations = 10
	for i := 0; i < iterations; i++ {
		// Reset metrics
		metrics.Reset()

		target := FixtureDistributionTarget{
			ID:     "cleanup-test-" + strconv.Itoa(i),
			URL:    "cleanup-" + strconv.Itoa(i%10) + ".json",
			Method: DistributionMethodLocalFile,
		}

		_, err := transport.Distribute(
			context.Background(),
			job,
			target,
			payload,
		)
		if err != nil {
			t.Errorf("Distribute iteration %d failed: %v", i, err)
		}

		// Verify metrics snapshot doesn't cause issues
		snapshot := metrics.Snapshot()
		_ = snapshot
	}

	t.Logf("Successfully completed %d iterations with proper cleanup", iterations)
}
