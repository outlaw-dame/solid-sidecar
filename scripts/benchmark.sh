#!/bin/bash

# Solid Sidecar Benchmark Suite
# This script runs comprehensive benchmarks for v0.2.0 Beta preparation

set -e

echo "=========================================="
echo "Solid Sidecar Performance Benchmark Suite"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BENCHMARK_PACKAGE="./test/load"
OUTPUT_DIR="./benchmarks"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="${OUTPUT_DIR}/benchmark_results_${TIMESTAMP}.md"

# Create output directory
mkdir -p "${OUTPUT_DIR}"

echo "Starting benchmarks..."
echo ""

# Run all benchmarks
echo -e "${BLUE}Running Benchmarks...${NC}"
echo ""

# Run each benchmark individually and capture results
echo "1. HTTP Authenticated Requests Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkHTTPAuthenticatedRequests -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo "2. Policy Evaluation Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkPolicyEvaluation -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo "3. Storage Operations Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkStorageOperations -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo "4. DID Resolution Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkDIDResolution -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo "5. Concurrent HTTP Requests Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkConcurrentHTTPRequests -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo "6. Memory Allocation Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkMemoryAllocation -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo "7. JWT Parsing Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkJWTParsing -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo "8. Configuration Loading Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkConfigurationLoading -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo "9. Metrics Collection Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkMetricsCollection -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo "10. Error Handling Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkErrorHandling -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo "11. Critical Path Benchmark"
go test ${BENCHMARK_PACKAGE} -bench=BenchmarkCriticalPath -benchmem -run=^$ -benchtime=1s -count=3 2>&1 | tee -a "${OUTPUT_FILE}" || true
echo ""

echo ""
echo -e "${GREEN}All benchmarks completed!${NC}"
echo ""
echo "Benchmark results saved to: ${OUTPUT_FILE}"
echo ""

# Generate summary report
echo "Generating summary report..."
echo ""

# Add header to output file
{
    echo "# Solid Sidecar Performance Benchmark Report"
    echo ""
    echo "**Generated**: $(date)"
    echo "**Version**: v0.1.0-alpha"
    echo "**Phase**: v0.2.0 Beta Preparation"
    echo "**Environment**: $(uname -a)"
    echo "**Go Version**: $(go version)"
    echo ""
    echo "---"
    echo ""
    cat "${OUTPUT_FILE}"
} > "${OUTPUT_FILE}.final"

mv "${OUTPUT_FILE}.final" "${OUTPUT_FILE}"

# Clean up temporary file
rm -f "${OUTPUT_FILE}.final"

echo ""
echo -e "${YELLOW}Summary Report:${NC}"
echo "================"
echo ""
echo "Benchmark results have been saved to:"
echo "  ${OUTPUT_FILE}"
echo ""
echo "Next steps:"
echo "  1. Review ${OUTPUT_FILE} for baseline metrics"
echo "  2. Identify performance bottlenecks"
echo "  3. Create optimization roadmap"
echo ""
echo -e "${GREEN}Benchmark suite completed successfully!${NC}"
