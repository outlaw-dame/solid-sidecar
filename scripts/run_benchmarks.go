//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// BenchmarkHTTPRequests is a simple benchmark
func BenchmarkHTTPRequests(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	b.ResetTimer()
	b.SetBytes(1024)

	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest("GET", server.URL+"/test", nil)
		if err != nil {
			b.Fatal(err)
		}

		req.Header.Set("Authorization", "Bearer test-token")

		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		defer resp.Body.Close()

		buf := make([]byte, 1024)
		_, _ = resp.Body.Read(buf)
	}
}

func main() {
	// Run benchmarks
	fmt.Println("Running benchmarks...")

	// Create a benchmark result
	result := testing.Benchmark(BenchmarkHTTPRequests)

	fmt.Printf("BenchmarkHTTPRequests: %s\n", result.String())
}
