// Package load provides load testing utilities for the Solid runtime.
// This file implements load tests as required by Phase 17.
package load

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// LoadTestConfig holds configuration for load tests
type LoadTestConfig struct {
	Target                string
	RequestsPerSecond     float64
	Duration              time.Duration
	ConcurrentWorkers     int
	MaxConnectionsPerHost int
	Timeout               time.Duration
	TLSConfig             *tls.Config
	Headers               map[string]string
	Logger                *slog.Logger
}

// DefaultLoadTestConfig returns safe defaults for load testing
func DefaultLoadTestConfig() LoadTestConfig {
	return LoadTestConfig{
		Target:                "http://localhost:8080",
		RequestsPerSecond:     100,
		Duration:              60 * time.Second,
		ConcurrentWorkers:     10,
		MaxConnectionsPerHost: 100,
		Timeout:               30 * time.Second,
		TLSConfig:             nil,
		Headers:               make(map[string]string),
		Logger:                slog.Default(),
	}
}

// LoadTestResult holds the results of a load test
type LoadTestResult struct {
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	RequestsPerSecond  float64
	AverageLatency     float64
	P50Latency         float64
	P95Latency         float64
	P99Latency         float64
	MaxLatency         float64
	MinLatency         float64
	StatusCodes        map[int]int64
	Errors             map[string]int64
	StartTime          time.Time
	EndTime            time.Time
	WorkerResults      []WorkerResult
}

// WorkerResult holds results for a single worker
type WorkerResult struct {
	WorkerID     int
	Requests     int64
	Successful   int64
	Failed       int64
	TotalLatency time.Duration
	MinLatency   time.Duration
	MaxLatency   time.Duration
	StatusCodes  map[int]int64
	Errors       map[string]int64
	StartTime    time.Time
	EndTime      time.Time
}

// LoadTester manages load testing
type LoadTester struct {
	config LoadTestConfig
	client *http.Client
	logger *slog.Logger
}

// NewLoadTester creates a new load tester
func NewLoadTester(config LoadTestConfig) *LoadTester {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	transport := &http.Transport{
		MaxIdleConns:    config.MaxConnectionsPerHost,
		MaxConnsPerHost: config.MaxConnectionsPerHost,
		IdleConnTimeout: 90 * time.Second,
		TLSClientConfig: config.TLSConfig,
	}

	return &LoadTester{
		config: config,
		client: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		},
		logger: config.Logger,
	}
}

// generateRequestURL generates a random request URL for testing
func (lt *LoadTester) generateRequestURL() string {
	patterns := []string{
		"", "/", "/.well-known/solid", "/.well-known/webid",
		"/profile/card", "/data/", "/inbox/", "/outbox/",
	}
	pattern := patterns[rand.Intn(len(patterns))]

	if pattern == "/data/" || pattern == "/inbox/" || pattern == "/outbox/" {
		return lt.config.Target + pattern + generateRandomString(8) + "/"
	}
	return lt.config.Target + pattern
}

// generateRandomString generates a random string of the given length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// makeRequest makes a single HTTP request
func (lt *LoadTester) makeRequest(ctx context.Context) (int, time.Duration, error) {
	start := time.Now()
	url := lt.generateRequestURL()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range lt.config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := lt.client.Do(req)
	if err != nil {
		return 0, time.Since(start), fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read a small amount to trigger the request
	buf := make([]byte, 1024)
	_, _ = resp.Body.Read(buf)

	return resp.StatusCode, time.Since(start), nil
}

// worker runs a single worker that makes requests
func (lt *LoadTester) worker(ctx context.Context, workerID int, result *WorkerResult, wg *sync.WaitGroup) {
	defer wg.Done()

	result.WorkerID = workerID
	result.StartTime = time.Now()
	result.StatusCodes = make(map[int]int64)
	result.Errors = make(map[string]int64)

	requestsPerWorker := lt.config.RequestsPerSecond / float64(lt.config.ConcurrentWorkers)
	minDelay := time.Duration(float64(time.Second) / requestsPerWorker)

	for {
		select {
		case <-ctx.Done():
			result.EndTime = time.Now()
			return
		default:
			statusCode, latency, err := lt.makeRequest(ctx)

			atomic.AddInt64(&result.Requests, 1)
			result.TotalLatency += latency

			if err != nil {
				atomic.AddInt64(&result.Failed, 1)
				errStr := err.Error()
				result.Errors[errStr]++
			} else {
				atomic.AddInt64(&result.Successful, 1)
				result.StatusCodes[statusCode]++
			}

			if result.MinLatency == 0 || latency < result.MinLatency {
				result.MinLatency = latency
			}
			if latency > result.MaxLatency {
				result.MaxLatency = latency
			}

			if minDelay > 0 {
				time.Sleep(minDelay)
			}
		}
	}
}

// Run runs the load test
func (lt *LoadTester) Run() (*LoadTestResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lt.config.Duration+10*time.Second)
	defer cancel()

	result := &LoadTestResult{
		StartTime:     time.Now(),
		StatusCodes:   make(map[int]int64),
		Errors:        make(map[string]int64),
		WorkerResults: make([]WorkerResult, lt.config.ConcurrentWorkers),
	}

	var wg sync.WaitGroup
	for i := 0; i < lt.config.ConcurrentWorkers; i++ {
		wg.Add(1)
		go lt.worker(ctx, i, &result.WorkerResults[i], &wg)
	}
	wg.Wait()

	result.EndTime = time.Now()

	// Calculate totals
	for _, wr := range result.WorkerResults {
		atomic.AddInt64(&result.TotalRequests, wr.Requests)
		atomic.AddInt64(&result.SuccessfulRequests, wr.Successful)
		atomic.AddInt64(&result.FailedRequests, wr.Failed)

		for code, count := range wr.StatusCodes {
			result.StatusCodes[code] += count
		}
		for err, count := range wr.Errors {
			result.Errors[err] += count
		}
	}

	totalDuration := result.EndTime.Sub(result.StartTime).Seconds()
	if totalDuration > 0 {
		result.RequestsPerSecond = float64(result.TotalRequests) / totalDuration
	}

	return result, nil
}

// PrintResults prints the load test results
func (lt *LoadTester) PrintResults(result *LoadTestResult) {
	fmt.Println()
	fmt.Println("=== Solid Runtime Load Test Results ===")
	fmt.Println()
	fmt.Printf("Test Duration: %v\n", result.EndTime.Sub(result.StartTime))
	fmt.Printf("Target: %s\n", lt.config.Target)
	fmt.Printf("Concurrent Workers: %d\n", lt.config.ConcurrentWorkers)
	fmt.Printf("Target RPS: %.2f\n", lt.config.RequestsPerSecond)
	fmt.Println()
	fmt.Println("--- Summary ---")
	fmt.Printf("Total Requests: %d\n", result.TotalRequests)
	fmt.Printf("Successful: %d (%.2f%%)\n", result.SuccessfulRequests,
		float64(result.SuccessfulRequests)/float64(result.TotalRequests)*100)
	fmt.Printf("Failed: %d (%.2f%%)\n", result.FailedRequests,
		float64(result.FailedRequests)/float64(result.TotalRequests)*100)
	fmt.Printf("Actual RPS: %.2f\n", result.RequestsPerSecond)
	fmt.Println()

	if len(result.StatusCodes) > 0 {
		fmt.Println("--- Status Codes ---")
		for code, count := range result.StatusCodes {
			fmt.Printf("%d: %d\n", code, count)
		}
		fmt.Println()
	}

	if len(result.Errors) > 0 {
		fmt.Println("--- Errors ---")
		for err, count := range result.Errors {
			fmt.Printf("%s: %d\n", err, count)
		}
		fmt.Println()
	}
}

// TestSolidLoadTest is a basic test to verify the load tester works
func TestSolidLoadTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	config := DefaultLoadTestConfig()
	config.Target = "http://localhost:8080"
	config.RequestsPerSecond = 10
	config.Duration = 5 * time.Second
	config.ConcurrentWorkers = 2

	lt := NewLoadTester(config)
	if lt == nil {
		t.Error("Failed to create load tester")
	}

	url := lt.generateRequestURL()
	if url == "" {
		t.Error("Failed to generate request URL")
	}
	t.Logf("Generated test URL: %s", url)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
