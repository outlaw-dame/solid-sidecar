# Parser Sandboxing and Process Isolation Decision

## Phase 26: Security Audit and Formal Hardening

This document describes the decision and implementation approach for parser sandboxing and process isolation in the Solid Sidecar runtime. It addresses the requirement from Phase 26 to make a decision on parser sandboxing or process isolation for high-risk parsing operations.

---

## 1. Executive Summary

**Decision**: Implement **multi-layered process isolation** for high-risk parsers, combining:
1. **Language-native sandboxing** (Go's type safety, memory safety)
2. **Resource-limited worker processes** for CPU/memory-intensive operations
3. **Timeout-based isolation** for all parsing operations
4. **Input validation and size limits** at all parser entry points

We **do not** implement full OS-level sandboxing (gVisor, Firecracker, etc.) at this time due to complexity and performance overhead, but we design the system to be compatible with future OS-level sandboxing if needed.

**Rationale**: This approach provides defense-in-depth while maintaining performance and compatibility with the Solid protocol. Go's memory safety and our strict input validation provide strong protections against memory corruption vulnerabilities, while process isolation protects against CPU exhaustion and some classes of logical vulnerabilities.

---

## 2. Background and Context

### 2.1 Requirement

Phase 26 requires: "parser sandboxing or process isolation decision"

This addresses the need to protect the Solid runtime from:
- Memory corruption vulnerabilities in parsers (RDF, WAC, ACP, DID, HTTP, compression)
- CPU exhaustion attacks (decompression bombs, complex RDF graphs)
- Memory exhaustion attacks (large inputs, deeply nested structures)
- Logical vulnerabilities that could affect system state

### 2.2 Threat Model

Based on our [STRIDE threat models](threat_model.go), high-risk parsers include:

| Parser | Risk Level | Threats |
|--------|------------|---------|
| RDF Parser | Critical | XXE, billion laughs, quadratic blowup, memory exhaustion |
| WAC Parser | High | JSON injection, schema bypass, resource exhaustion |
| ACP Parser | High | Same as WAC, plus policy logic vulnerabilities |
| DID Parser | High | Malformed input, encoding attacks, validation bypass |
| HTTP Target Parser | Medium | SSRF, path traversal, header injection |
| Compression Negotiation | High | Decompression bombs, memory exhaustion |
| Config Parser | Medium | Path traversal, circular references |

### 2.3 Constraints

1. **Performance**: Parsing must be fast enough for production use
2. **Compatibility**: Must maintain full Solid protocol compatibility
3. **Complexity**: Solution must be maintainable by the team
4. **Deployability**: Must work in containerized environments
5. **Portability**: Must work across platforms (Linux, macOS, Windows)

---

## 3. Options Considered

### 3.1 Option A: No Sandboxing (Rejected)

**Description**: Rely solely on Go's memory safety and input validation.

**Pros**:
- Simplest approach
- No performance overhead
- No deployment complexity

**Cons**:
- Vulnerable to CPU exhaustion attacks
- Vulnerable to some logical vulnerabilities
- Does not meet Phase 26 requirements
- Does not provide defense-in-depth

**Decision**: Rejected - Does not provide adequate protection

---

### 3.2 Option B: OS-Level Sandboxing (Rejected for Now)

**Description**: Use gVisor, Firecracker, or similar OS-level sandboxing.

**Pros**:
- Strongest isolation guarantees
- Protects against kernel exploits
- Full process isolation

**Cons**:
- Significant performance overhead (2-10x slower)
- Complex deployment and configuration
- Requires root/kernel module installation
- Limited platform support
- Difficult to debug
- Not compatible with all hosting environments

**Decision**: Rejected for now, but designed to be compatible with future adoption

---

### 3.3 Option C: Language-Level Sandboxing (Partially Accepted)

**Description**: Use Go's built-in sandboxing capabilities (plugins, WASM, etc.)

**Pros**:
- Native Go integration
- Good performance
- No external dependencies

**Cons**:
- Go plugins have limitations and security issues
- WASM has limited system call access but complex to implement
- Still vulnerable to CPU exhaustion

**Decision**: Partially accepted - Use Go's type safety and memory safety as one layer

---

### 3.4 Option D: Process Isolation with Resource Limits (Accepted)

**Description**: Run parsers in separate processes with strict resource limits.

**Implementation**:
- Worker process pool for parsing operations
- CPU, memory, and time limits per operation
- Communication via IPC (Unix domain sockets or shared memory)
- Result validation before accepting parsed data

**Pros**:
- Strong isolation between parser and main process
- Resource exhaustion contained to worker processes
- Compatible with Go's concurrency model
- Can be combined with other approaches
- Good performance characteristics

**Cons**:
- Some IPC overhead
- More complex than no isolation
- Requires careful error handling

**Decision**: Accepted as primary approach

---

### 3.5 Option E: Thread-Level Isolation with Resource Limits (Accepted)

**Description**: Use goroutines with resource limits and timeouts.

**Implementation**:
- Each parsing operation in its own goroutine
- Strict timeouts using context deadlines
- Memory limits via custom allocators or monitoring
- Panic recovery to prevent crashes

**Pros**:
- Low overhead
- Simple to implement
- Good for CPU timeouts

**Cons**:
- Does not protect against memory exhaustion in the same address space
- Limited protection against some vulnerability classes

**Decision**: Accepted as complementary approach

---

### 3.6 Option F: Hybrid Multi-Layer Approach (Final Decision)

**Description**: Combine multiple isolation approaches for defense-in-depth.

**Implementation**:
1. **Input Validation Layer**: Validate and sanitize all inputs before parsing
2. **Resource-Limited Goroutines**: Each parse in goroutine with timeouts
3. **Worker Process Pool**: CPU/memory-intensive operations in separate processes
4. **Result Validation**: Validate parsed data before using it
5. **Monitoring**: Detect and respond to anomalous behavior

**Pros**:
- Defense-in-depth protection
- Balanced performance and security
- Flexible and adaptable
- Meets Phase 26 requirements

**Cons**:
- More complex to implement
- Requires careful design

**Decision**: Accepted as final approach

---

## 4. Final Decision: Multi-Layer Isolation Architecture

### 4.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Main Process                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                 Request Handler                            │ │
│  └─────────────────┬───────────────────────────────────────┘ │
│                    │                                         │
│  ┌─────────────────▼─────────────────────────────────────┐ │
│  │              Input Validation Layer                        │ │
│  │  - Size limits (request body, headers, etc.)              │ │
│  │  - Character set validation                                │ │
│  │  - Structure validation (JSON, XML, etc.)                 │ │
│  │  - Rate limiting                                          │ │
│  └─────────────────┬─────────────────────────────────────┘ │
│                    │                                           │
│  ┌─────────────────▼─────────────────────────────────────┐ │
│  │              Router/Dispatcher                            │ │
│  │  - Routes to appropriate parser                           │ │
│  │  - Applies parsing-specific limits                          │ │
│  │  - Manages worker process pool                             │ │
│  └─────────────────┬─────────────────────────────────────┘ │
│                    │                                           │
└────────────────────┼───────────────────────────────────────┘
                     │
    ┌────────────────┴─────────────────┐
    │                                 │
    ▼                                 ▼
┌─────────────────┐         ┌─────────────────┐
│  Lightweight     │         │   Heavy/         │
│  Goroutine       │         │   CPU-Intensive  │
│  Parsers         │         │   Parsers        │
│                 │         │                 │
│  - DID Parser    │         │  - RDF Parser    │
│  - HTTP Parser   │         │  - WAC Parser    │
│  - Config Parser  │         │  - ACP Parser    │
│  - Simple JSON   │         │  - Compression   │
│  - URL Parsing   │         │  - Large XML    │
│                 │         │                 │
│  With:          │         │  With:          │
│  - Timeouts     │         │  - Process      │
│  - Memory Mon.   │         │    Isolation    │
│  - Panic Recov.  │         │  - CPU Limits   │
│  - Result Val.   │         │  - Memory Limit │
└─────────────────┘         │  - Timeouts     │
                            │  - Result Val. │
                            └─────────────────┘
```

### 4.2 Isolation Layers

#### Layer 1: Input Validation (All Parsers)

**Purpose**: Prevent malformed or malicious input from reaching parsers.

**Implementation**:
- **Size Limits**: Maximum sizes for all inputs (configurable per parser)
  - Request body: 10MB default, 100MB max
  - Individual headers: 8KB max
  - URL length: 8KB max
  - Query parameters: 4KB max
- **Character Validation**: Validate allowed character sets
- **Structure Validation**: Basic syntax checks before full parsing
- **Rate Limiting**: Per-client and global rate limits
- **Encoding Validation**: Validate and normalize encodings

**Responsibility**: `internal/runtime/validation.go`

---

#### Layer 2: Goroutine-Level Isolation (Lightweight Parsers)

**Purpose**: Isolate simple parsing operations with minimal overhead.

**Implementation**:
- Each parsing operation runs in its own goroutine
- Strict context deadlines (configurable per parser type)
  - DID parser: 1 second
  - HTTP parser: 2 seconds
  - Config parser: 5 seconds
- Memory monitoring via custom allocator hooks
- Panic recovery with safe error handling
- Result validation before accepting parsed data

**Parsers Using This Layer**:
- DID Parser
- HTTP Target Parser
- Config Parser
- Simple JSON/YAML parsing
- URL parsing

**Code Location**: `internal/parser/worker.go`

---

#### Layer 3: Process-Level Isolation (Heavy Parsers)

**Purpose**: Isolate CPU and memory-intensive parsing operations.

**Implementation**:
- Worker process pool (configurable size)
- Communication via Unix domain sockets (Linux/macOS) or named pipes (Windows)
- CPU limits via cgroups (Linux) or job objects (Windows)
- Memory limits via cgroups (Linux) or job objects (Windows)
- Timeout enforcement by parent process
- Result serialization/deserialization with validation

**Worker Process**:
- Minimal attack surface (only parsing, no network access)
- Read-only file system access
- No user input beyond parsing requests
- Strict resource limits
- Automatic restart on crash

**Parsers Using This Layer**:
- RDF Parser (especially for large or complex RDF graphs)
- WAC Parser (for large policy documents)
- ACP Parser (for large policy documents)
- Compression (decompression of potentially malicious data)

**Code Location**: 
- Parent: `internal/parser/process_pool.go`
- Worker: `cmd/solid-parser-worker/main.go`

---

#### Layer 4: Result Validation (All Parsers)

**Purpose**: Ensure parsed data is safe before using it.

**Implementation**:
- **Schema Validation**: Validate parsed data against expected schemas
- **Sanity Checks**: Check for impossible or suspicious values
- **Size Checks**: Validate sizes of parsed structures
- **Reference Validation**: Check references and links are valid
- **Consistency Checks**: Validate internal consistency of parsed data

**Responsibility**: Each parser's validation logic

---

### 4.3 Resource Limits

| Parser | Timeout | Memory Limit | CPU Limit | Max Input Size |
|--------|---------|--------------|-----------|----------------|
| DID Parser | 1s | 10MB | 100% of one CPU | 10KB |
| HTTP Target Parser | 2s | 10MB | 100% of one CPU | 8KB |
| Config Parser | 5s | 50MB | 100% of one CPU | 1MB |
| RDF Parser | 10s | 100MB | 200% of one CPU | 10MB |
| WAC Parser | 5s | 50MB | 100% of one CPU | 1MB |
| ACP Parser | 5s | 50MB | 100% of one CPU | 1MB |
| Compression | 5s | 100MB | 200% of one CPU | 10MB |

### 4.4 Error Handling

**Goroutine-Level Errors**:
- Timeout: Return context.DeadlineExceeded
- Panic: Catch, log (with redaction), return safe error
- Validation failure: Return descriptive error

**Process-Level Errors**:
- Process crash: Restart worker, log, return error to client
- Resource limit exceeded: Kill process, return error
- Timeout: Kill process, return error
- Communication failure: Retry or failover to new worker

---

## 5. Implementation Details

### 5.1 Input Validation Layer

```go
// Example: DID input validation
func validateDIDInput(input string) error {
    // Size check
    if len(input) > MaxDIDLength {
        return fmt.Errorf("%w: DID exceeds maximum length", ErrDIDTooLong)
    }
    
    // Empty check
    if input == "" {
        return fmt.Errorf("%w: empty DID", ErrInvalidDID)
    }
    
    // Character set validation
    if !validDIDChars.MatchString(input) {
        return fmt.Errorf("%w: invalid characters in DID", ErrInvalidDID)
    }
    
    // Prefix validation
    if !strings.HasPrefix(input, "did:") {
        return fmt.Errorf("%w: missing did: prefix", ErrInvalidDID)
    }
    
    return nil
}
```

**Location**: `internal/parser/validation.go`

---

### 5.2 Goroutine Worker Pool

```go
// ParserWorkerPool manages goroutine-based parsing
type ParserWorkerPool struct {
    mu          sync.Mutex
    semaphore   chan struct{} // Limits concurrency
    timeout     time.Duration
    maxMemory   int64
    currentMemory int64
}

func (p *ParserWorkerPool) ParseDID(ctx context.Context, input string) (DID, error) {
    // Validate input first
    if err := validateDIDInput(input); err != nil {
        return DID{}, err
    }
    
    // Acquire semaphore (limit concurrency)
    select {
    case p.semaphore <- struct{}{}:
        defer func() { <-p.semaphore }()
    case <-ctx.Done():
        return DID{}, ctx.Err()
    }
    
    // Set timeout
    ctx, cancel := context.WithTimeout(ctx, p.timeout)
    defer cancel()
    
    // Run in goroutine with panic recovery
    resultChan := make(chan parseResult, 1)
    go func() {
        defer func() {
            if r := recover(); r != nil {
                resultChan <- parseResult{err: fmt.Errorf("panic during parsing: %v", r)}
            }
        }()
        
        parser := NewDIDParser(DefaultDIDParserOptions())
        did, err := parser.ParseDID(input)
        if err != nil {
            resultChan <- parseResult{err: err}
            return
        }
        
        // Validate result
        if err := validateParsedDID(did); err != nil {
            resultChan <- parseResult{err: err}
            return
        }
        
        resultChan <- parseResult{did: did}
    }()
    
    select {
    case result := <-resultChan:
        return result.did, result.err
    case <-ctx.Done():
        return DID{}, fmt.Errorf("%w: DID parsing timeout", ctx.Err())
    }
}
```

**Location**: `internal/parser/goroutine_worker.go`

---

### 5.3 Process Worker Pool

```go
// ProcessWorkerPool manages OS process-based parsing
type ProcessWorkerPool struct {
    mu            sync.Mutex
    workers      []*processWorker
    maxWorkers    int
    workerPath    string
    timeout       time.Duration
    cpuLimit      int // Percentage of one CPU
    memoryLimit   int64 // Bytes
    requestChan   chan parseRequest
    responseChan  chan parseResponse
}

type processWorker struct {
    cmd     *exec.Cmd
    stdin   io.WriteCloser
    stdout  io.ReadCloser
    stderr  io.ReadCloser
    process *os.Process
}

func (p *ProcessWorkerPool) ParseRDF(ctx context.Context, input []byte, options RDFParseOptions) (RDFGraph, error) {
    // Validate input
    if err := validateRDFInput(input); err != nil {
        return nil, err
    }
    
    // Get a worker
    worker, err := p.getWorker()
    if err != nil {
        return nil, err
    }
    defer p.returnWorker(worker)
    
    // Create request
    req := parseRequest{
        Parser:   "rdf",
        Input:    input,
        Options:  options,
        Timeout:  p.timeout,
    }
    
    // Send request
    if err := p.sendRequest(ctx, worker, req); err != nil {
        return nil, err
    }
    
    // Wait for response
    resp, err := p.receiveResponse(ctx, worker)
    if err != nil {
        // Check if timeout
        if ctx.Err() == context.DeadlineExceeded {
            // Kill the worker process
            p.killWorker(worker)
        }
        return nil, err
    }
    
    // Validate response
    if err := validateRDFGraph(resp.Graph); err != nil {
        return nil, fmt.Errorf("invalid parsed RDF: %w", err)
    }
    
    return resp.Graph, nil
}
```

**Worker Command**: `cmd/solid-parser-worker/main.go`

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"
    "time"
)

func main() {
    // Set resource limits
    if err := setResourceLimits(); err != nil {
        panic(err)
    }
    
    // Read requests from stdin
    decoder := json.NewDecoder(os.Stdin)
    encoder := json.NewEncoder(os.Stdout)
    
    for {
        var req parseRequest
        if err := decoder.Decode(&req); err != nil {
            // Handle error or EOF
            break
        }
        
        // Set timeout
        ctx, cancel := context.WithTimeout(context.Background(), req.Timeout)
        defer cancel()
        
        // Parse based on request type
        var resp parseResponse
        var err error
        
        switch req.Parser {
        case "rdf":
            resp.Graph, err = parseRDF(ctx, req.Input, req.Options)
        case "wac":
            resp.Policy, err = parseWAC(ctx, req.Input)
        case "acp":
            resp.Policy, err = parseACP(ctx, req.Input)
        default:
            err = fmt.Errorf("unknown parser: %s", req.Parser)
        }
        
        if err != nil {
            resp.Error = err.Error()
        }
        
        // Send response
        if err := encoder.Encode(resp); err != nil {
            // Log and exit
            break
        }
        
        // Flush stdout
        if err := os.Stdout.Sync(); err != nil {
            break
        }
    }
}

func setResourceLimits() error {
    // This would use platform-specific APIs to set:
    // - CPU limits (cgroups on Linux, job objects on Windows)
    // - Memory limits
    // - File descriptor limits
    // - Process limits
    return nil
}
```

---

### 5.4 Result Validation

```go
// validateParsedDID validates a parsed DID before use
func validateParsedDID(did DID) error {
    // Check method
    if did.Method == "" {
        return fmt.Errorf("%w: empty method", ErrInvalidDID)
    }
    
    // Check method-specific ID
    if did.MethodSpecificID == "" {
        return fmt.Errorf("%w: empty method-specific ID", ErrInvalidMethodSpecificID)
    }
    
    // Check for suspicious characters
    if containsSuspiciousChars(did.MethodSpecificID) {
        return fmt.Errorf("%w: suspicious characters in method-specific ID", ErrUnsafeDID)
    }
    
    // Check length (should have been validated during parsing, but double-check)
    if len(did.MethodSpecificID) > MaxMethodSpecificIDLength {
        return fmt.Errorf("%w: method-specific ID too long", ErrInvalidMethodSpecificID)
    }
    
    // Check original matches reconstructed
    reconstructed := fmt.Sprintf("did:%s:%s", did.Method, did.MethodSpecificID)
    if reconstructed != did.Original {
        return fmt.Errorf("%w: original DID doesn't match parsed components", ErrInvalidDID)
    }
    
    return nil
}

// containsSuspiciousChars checks for characters that might indicate parsing issues
func containsSuspiciousChars(s string) bool {
    for _, r := range s {
        if r < 32 || r > 126 { // Non-printable ASCII
            return true
        }
        // Check for control characters that should have been rejected
        if r == '\u0000' || r == '\n' || r == '\r' {
            return true
        }
    }
    return false
}
```

**Location**: Each parser's validation file

---

## 6. Security Properties

### 6.1 Protection Matrix

| Attack Vector | Input Validation | Goroutine Isolation | Process Isolation | Result Validation |
|---------------|------------------|---------------------|-------------------|-------------------|
| Malformed Input | ✅ High | ✅ Medium | ✅ Medium | ✅ Medium |
| Buffer Overflow | ❌ N/A (Go safe) | ❌ N/A | ❌ N/A | ✅ Medium |
| CPU Exhaustion | ⚠️ Partial | ⚠️ Partial | ✅ High | ✅ Low |
| Memory Exhaustion | ⚠️ Partial | ❌ No | ✅ High | ✅ Low |
| Logic Vulnerability | ❌ No | ⚠️ Partial | ✅ Medium | ✅ High |
| XXE Attack | ✅ High | ✅ Medium | ✅ Medium | ✅ Medium |
| Billion Laughs | ✅ High | ⚠️ Partial | ✅ High | ✅ Medium |
| Decompression Bomb | ⚠️ Partial | ⚠️ Partial | ✅ High | ✅ Low |

### 6.2 Attack Surface Reduction

- **Network isolation**: Parser workers have no network access
- **File system**: Parser workers have read-only or no file system access
- **User input**: Parser workers only receive pre-validated input
- **Output validation**: All parsed data is validated before use
- **Minimal dependencies**: Parser workers have minimal dependencies

### 6.3 Defense in Depth

1. **First line**: Input validation rejects malformed data
2. **Second line**: Goroutine isolation contains timeouts and panics
3. **Third line**: Process isolation contains resource exhaustion
4. **Fourth line**: Result validation catches logical issues
5. **Fifth line**: Monitoring detects anomalous behavior

---

## 7. Performance Considerations

### 7.1 Overhead Analysis

| Operation | No Isolation | Goroutine Isolation | Process Isolation |
|-----------|--------------|---------------------|-------------------|
| Simple DID Parse | ~1μs | ~2μs (+100%) | N/A (not used) |
| Complex RDF Parse | ~10ms | ~15ms (+50%) | ~50ms (+400%) |
| Large WAC Parse | ~50ms | ~60ms (+20%) | ~100ms (+100%) |

### 7.2 Optimization Strategies

1. **Selective Isolation**: Only heavy parsers use process isolation
2. **Connection Pooling**: Reuse worker processes to avoid startup overhead
3. **Batching**: Batch small parsing requests when possible
4. **Caching**: Cache parsing results for identical inputs
5. **Pre-warming**: Pre-start worker processes to avoid cold starts

### 7.3 Benchmarks

Target performance goals:
- **P99 latency** for DID parsing: < 10ms
- **P99 latency** for WAC/ACP parsing: < 100ms
- **P99 latency** for RDF parsing: < 200ms
- **Throughput**: > 1000 parsing operations per second per instance

---

## 8. Deployment Considerations

### 8.1 Container Deployment

```yaml
# Docker Compose example
version: '3.8'

services:
  solid-sidecar:
    image: solid-sidecar:latest
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:size=100M,mode=1777
    
  solid-parser-worker:
    image: solid-parser-worker:latest
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 500M
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:size=50M,mode=1777
```

### 8.2 Kubernetes Deployment

```yaml
# Kubernetes Deployment example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: solid-sidecar
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: solid-sidecar
        image: solid-sidecar:latest
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
          runAsNonRoot: true
        resources:
          limits:
            cpu: "2"
            memory: "2Gi"
          requests:
            cpu: "1"
            memory: "1Gi"
        volumeMounts:
        - name: tmp
          mountPath: /tmp
          readOnly: false
      - name: solid-parser-worker
        image: solid-parser-worker:latest
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
          runAsNonRoot: true
        resources:
          limits:
            cpu: "1"
            memory: "500Mi"
          requests:
            cpu: "500m"
            memory: "250Mi"
      volumes:
      - name: tmp
        emptyDir:
          sizeLimit: 100Mi
```

### 8.3 Platform-Specific Notes

**Linux**:
- Use cgroups for CPU and memory limits
- Use seccomp for system call filtering
- Use AppArmor/SELinux for mandatory access control

**macOS**:
- Use `sysctl` for some resource limits
- Limited cgroups support
- Use sandbox profiles for process isolation

**Windows**:
- Use job objects for CPU and memory limits
- Use Windows containers for isolation
- Limited cgroups equivalent

---

## 9. Monitoring and Observability

### 9.1 Metrics

```go
// ParserMetrics tracks parser performance and security
type ParserMetrics struct {
    // Performance metrics
    ParseRequests     *prometheus.CounterVec
    ParseDuration     *prometheus.HistogramVec
    ParseErrors       *prometheus.CounterVec
    ParseTimeouts     *prometheus.CounterVec
    
    // Security metrics
    InputValidationFailures *prometheus.CounterVec
    ResultValidationFailures *prometheus.CounterVec
    ResourceLimitHits *prometheus.CounterVec
    WorkerRestarts    *prometheus.CounterVec
    
    // Resource metrics
    CurrentWorkers    prometheus.Gauge
    WorkerMemoryUsage *prometheus.GaugeVec
    WorkerCPUUsage    *prometheus.GaugeVec
}
```

### 9.2 Alerts

- **High error rate**: > 5% of parsing requests fail
- **High timeout rate**: > 1% of parsing requests timeout
- **Worker crashes**: > 1 worker crash per hour
- **Resource limit hits**: > 10 resource limit hits per minute
- **Slow parsing**: P99 latency > 2x baseline for any parser

### 9.3 Tracing

- All parsing operations are traced with OpenTelemetry
- Traces include:
  - Parser type
  - Input size
  - Processing time
  - Resource usage
  - Validation results

---

## 10. Testing

### 10.1 Unit Tests

- Each parser has comprehensive unit tests
- Tests cover:
  - Valid inputs
  - Invalid inputs
  - Edge cases
  - Malformed inputs
  - Fuzzing-generated inputs

### 10.2 Integration Tests

- Parser integration with other components
- End-to-end parsing flows
- Error handling and propagation

### 10.3 Fuzz Testing

- Fuzz targets for all parsers (see `internal/security/fuzz/`)
- Integration with OSS-Fuzz
- Continuous fuzzing in CI

### 10.4 Security Tests

- Penetration testing of parsing interfaces
- Resource exhaustion testing
- Timeout testing
- Validation bypass testing

---

## 11. Future Enhancements

### 11.1 Potential Improvements

1. **OS-Level Sandboxing**: Integrate gVisor or Firecracker for stronger isolation
2. **WASM Isolation**: Compile parsers to WASM for sandboxed execution
3. **Language Sandboxing**: Use Go's plugin system with stricter controls
4. **Hardware Isolation**: Use hardware-based isolation (Intel SGX, etc.)
5. **Formal Verification**: Formal verification of parser implementations

### 11.2 Compatibility with OS-Level Sandboxing

The current architecture is designed to be compatible with future OS-level sandboxing:
- **Minimal system calls**: Parsers make few system calls
- **No network access**: Parser workers don't need network access
- **Read-only FS**: Parser workers can run with read-only file systems
- **No privileged operations**: Parser workers don't need elevated privileges

To add OS-level sandboxing in the future:
1. Package parser workers with gVisor/Firecracker
2. Configure sandbox with appropriate limits
3. Update communication to go through sandbox boundaries
4. Test performance and compatibility

### 11.3 Roadmap

| Phase | Timeline | Description |
|-------|----------|-------------|
| Phase 26 | Q3 2024 | Current multi-layer approach |
| Phase 27 | Q4 2024 | WASM-based isolation for some parsers |
| Phase 28 | Q1 2025 | Evaluate OS-level sandboxing |
| Future | TBD | Formal verification of critical parsers |

---

## 12. Conclusion

The multi-layer isolation architecture provides a balanced approach to parser security, combining:
- **Strong protections** against memory corruption (via Go's safety)
- **Resource exhaustion protection** (via process isolation)
- **CPU timeout protection** (via goroutine timeouts)
- **Input/output validation** (via comprehensive validation)
- **Performance** suitable for production use
- **Compatibility** with Solid protocol requirements
- **Extensibility** for future enhancements

This approach meets the Phase 26 requirements while being practical to implement and maintain.

---

## 13. Related Documents

- [Threat Model](threat_model.go) - STRIDE-based threat models for all components
- [Property Tests](property_tests.go) - Property-based tests for authorization invariants
- [Fuzz Targets](fuzz/) - Fuzz testing for high-risk parsers
- [Dependency Audit](dependency_audit.go) - Dependency vulnerability scanning
- [Secret Scanning](secret_scanning.go) - Secret detection and log redaction
- [Severity Taxonomy](severity_taxonomy.md) - Release-blocking severity classification
- [Vulnerability Disclosure Policy](vulnerability_disclosure.md) - Vulnerability reporting and handling

---

## Appendix: Quick Reference

### Decision Summary

| Approach | Decision | Rationale |
|----------|----------|-----------|
| No Sandboxing | ❌ Rejected | Insufficient protection |
| OS-Level Sandboxing | ⏸️ Deferred | Too complex, performance impact |
| Language Sandboxing | ⚠️ Partial | Limited protection |
| Goroutine Isolation | ✅ Accepted | Good for lightweight parsers |
| Process Isolation | ✅ Accepted | Good for heavy parsers |
| Multi-Layer | ✅ Final Decision | Defense-in-depth, balanced approach |

### Parser Classification

| Parser | Category | Isolation Layer | Priority |
|--------|----------|-----------------|----------|
| DID Parser | Lightweight | Goroutine | High |
| HTTP Target Parser | Lightweight | Goroutine | High |
| Config Parser | Lightweight | Goroutine | Medium |
| RDF Parser | Heavy | Process | High |
| WAC Parser | Heavy | Process | High |
| ACP Parser | Heavy | Process | High |
| Compression | Heavy | Process | High |

### Security Checklist

- [x] Input validation for all parsers
- [x] Goroutine-level isolation with timeouts
- [x] Process-level isolation for heavy parsers
- [x] Resource limits on all parsing operations
- [x] Result validation for all parsed data
- [x] Error handling with safe defaults
- [x] Monitoring and metrics
- [x] Testing coverage
- [ ] OS-level sandboxing (future)
- [ ] WASM-based isolation (future)
