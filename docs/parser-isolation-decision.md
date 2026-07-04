# Parser Isolation Decision

## Overview

This document analyzes and documents the isolation strategy for parsers in the solid-sidecar project. Parser isolation is critical for security, as parsing untrusted input is a common source of vulnerabilities including memory corruption, denial of service, and information disclosure.

## Threat Model for Parsers

### Attack Surface

Parsers in solid-sidecar process untrusted input from:
1. **HTTP Requests**: Headers, URLs, query parameters, request bodies
2. **DID Documents**: Fetched from remote servers
3. **Policy Documents**: WAC, ACP, SAI policies from user-controlled resources
4. **RDF Data**: Resource descriptions, metadata, auxiliary resources
5. **Configuration**: User-provided configuration files
6. **Fixture Data**: Distribution transports (S3, SSH, HTTP, local files)

### Risk Categories

| Parser Type | Risk Level | Impact | Likelihood |
|-------------|------------|--------|------------|
| RDF (Turtle, N-Triples) | HIGH | Memory corruption, DoS | High |
| WAC Policy | HIGH | Auth bypass, DoS | High |
| ACP Policy | HIGH | Auth bypass, DoS | High |
| DID Documents | HIGH | Identity spoofing, DoS | High |
| HTTP Targets (URLs) | MEDIUM | SSRF, DoS | Medium |
| Compression Headers | MEDIUM | DoS | Medium |
| Configuration | LOW | Misconfiguration | Low |

### Historical Context

Parser vulnerabilities have been a significant source of security issues:
- CVE-2021-44228 (Log4Shell): Parser/deserialization vulnerability
- Heartbleed: Memory disclosure from parser bug
- Numerous RDF parser vulnerabilities in various libraries
- JSON parser vulnerabilities (e.g., CVE-2022-24834)

## Isolation Options Analysis

### Option 1: In-Process with Memory Safety

**Description**: Run parsers in the main process with memory-safe languages and bounded allocations.

**Applicable To**: Go parsers (DID, WAC, ACP, config, compression)

**Pros**:
- ✅ Fast: No IPC overhead
- ✅ Simple: No inter-process communication
- ✅ Go memory model: No buffer overflows, use-after-free
- ✅ Easy debugging: Single process
- ✅ Full language safety: Go's type system and runtime

**Cons**:
- ❌ Memory exhaustion: Large inputs can consume all memory
- ❌ CPU exhaustion: Complex inputs can consume all CPU
- ❌ Panics: Parser bugs can crash the main process
- ❌ Shared state: Parser state corruption affects main process

**Mitigations**:
- Bounded allocations (max document sizes, max recursion depth)
- Timeout contexts for parsing operations
- Panic recovery with proper cleanup
- Input validation before parsing
- Resource limits (goroutine limits, memory limits)

**Decision**: ✅ **ACCEPTABLE** for Go parsers with proper mitigations

**Implementation**:
```go
// Example: Bounded parsing with timeout
func ParseWithBounds(input []byte, maxSize int, timeout time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    
    if len(input) > maxSize {
        return ErrInputTooLarge
    }
    
    // Parse with bounded allocations
    // Use context for early cancellation
}
```

### Option 2: Separate Process (Out-of-Process)

**Description**: Run parsers in separate processes with IPC for communication.

**Applicable To**: Rust parsers (RDF), complex/high-risk parsers

**Pros**:
- ✅ Complete isolation: Parser crash doesn't affect main process
- ✅ Strong security boundary: Process-level sandboxing possible
- ✅ Resource isolation: Separate memory space, CPU limits
- ✅ Easy to replace: Can swap parser implementations
- ✅ Technology flexibility: Different languages, different security models

**Cons**:
- ❌ IPC overhead: Serialization/deserialization cost
- ❌ Complexity: Inter-process communication
- ❌ Error handling: More failure modes
- ❌ Deployment: More processes to manage
- ❌ Debugging: Cross-process debugging is harder

**Mitigations**:
- Efficient IPC (shared memory, Unix domain sockets)
- Timeout for parser processes
- Process health monitoring
- Graceful degradation on parser failure
- Circuit breakers for parser timeouts

**Decision**: ✅ **REQUIRED** for Rust RDF parser

**Implementation**:
```rust
// Rust RDF parser as separate process
// Communicates via stdin/stdout or Unix domain socket
// Parent process sets resource limits (rlimit)
// Timeout enforced by parent
```

### Option 3: WASM Sandbox

**Description**: Run parsers in WebAssembly with strict resource limits.

**Applicable To**: Future consideration, third-party parsers

**Pros**:
- ✅ Strong isolation: WASM memory model
- ✅ Portable: Runs anywhere with WASM support
- ✅ Fine-grained control: Memory, CPU, fuel limits
- ✅ Safe: No direct system access

**Cons**:
- ❌ Performance: WASM execution overhead
- ❌ Complexity: WASM toolchain, compilation
- ❌ Maturity: WASM ecosystem still evolving
- ❌ Integration: Requires WASM runtime
- ❌ Debugging: Limited debugging support

**Decision**: ⚠️ **FUTURE CONSIDERATION** - Not required for current scope

**Implementation**: Future - Consider for high-risk third-party parsers

### Option 4: OS-Level Sandboxing

**Description**: Use OS-level sandboxing (seccomp, namespaces, containers).

**Applicable To**: All parsers (if running in containerized environment)

**Pros**:
- ✅ Strongest isolation: OS-level controls
- ✅ System call filtering: Prevent dangerous syscalls
- ✅ Resource limits: CPU, memory, file descriptors
- ✅ Network isolation: Restrict network access

**Cons**:
- ❌ Complexity: Requires OS-specific code
- ❌ Overhead: Additional system calls, context switches
- ❌ Portability: Different per OS/platform
- ❌ Privileges: May require elevated privileges

**Decision**: ⚠️ **OPTIONAL** - Use if available in deployment environment

**Implementation**:
```go
// Linux seccomp example (conceptual)
import "golang.org/x/sys/unix"

func applySandbox() error {
    // Restrict system calls for parser process
    // Allow only: read, write, exit, etc.
    // Block: execve, openat (for certain paths), socket, etc.
}
```

### Option 5: Language-Specific Sandboxing

**Description**: Use language-specific sandboxing features.

**Applicable To**: Go (plugins), Rust (unstable features)

**Pros**:
- ✅ Language-native: No external dependencies
- ✅ Fine-grained: Per-function control

**Cons**:
- ❌ Limited: Not all languages support this
- ❌ Complex: Hard to get right
- ❌ Maintenance: Requires ongoing effort

**Decision**: ❌ **NOT RECOMMENDED** - Too complex, limited benefits

## Final Decisions

### Go Parsers

| Parser | Isolation Strategy | Rationale |
|--------|-------------------|-----------|
| DID Parser (`internal/identity/did_parser.go`) | In-process with bounds | Go memory safety, bounded allocations |
| WAC Parser (`internal/authz/wac/`) | In-process with bounds | Go memory safety, bounded allocations |
| ACP Parser (`internal/authz/acp/`) | In-process with bounds | Go memory safety, bounded allocations |
| Config Parser (`internal/config/`) | In-process | Low risk, trusted input source |
| Compression Parser (`internal/compression/`) | In-process | Low risk, bounded input |
| URL/HTTP Target Parser (`internal/gateway/`) | In-process with bounds | SSRF protection already implemented |

**Common Mitigations for Go Parsers**:
1. All parsers must have input size limits
2. All parsers must have timeout contexts
3. All parsers must validate input before parsing
4. All parsers must use panic recovery
5. All parsers must have resource limits (goroutine, memory)
6. All parsers must log errors without sensitive data

### Rust Parsers

| Parser | Isolation Strategy | Rationale |
|--------|-------------------|-----------|
| RDF Parser (`rust/solid_rdf_parser/`) | **Separate process** | High risk, memory-unsafe language |
| Policy Kernel (`rust/solid_policy_kernel/`) | Separate process (already) | High risk, complex logic |

**Implementation for Rust Parsers**:
1. Compile as separate binary
2. Communicate via stdin/stdout or Unix domain socket
3. Set resource limits (rlimit) from parent process
4. Enforce timeouts from parent process
5. Monitor process health
6. Implement graceful degradation

### General Principles

1. **Defense in Depth**: Multiple layers of protection
   - Input validation before parsing
   - Bounded allocations during parsing
   - Timeout enforcement
   - Process isolation for high-risk parsers
   - OS-level sandboxing (if available)

2. **Fail-Secure**: Always fail to a safe state
   - Parser errors = deny access (for authz parsers)
   - Parser timeouts = deny access
   - Parser crashes = deny access
   - Input too large = reject

3. **Least Privilege**: Parsers get minimum necessary access
   - File access: Only to specific directories
   - Network access: Only to allowed hosts
   - System calls: Only safe syscalls

4. **Monitoring**: Track parser behavior
   - Parse time metrics
   - Parse error rates
   - Input size histograms
   - Resource usage

## Implementation Requirements

### For All Parsers

1. **Input Validation**
   ```go
   func validateInput(input []byte) error {
       if len(input) > MaxInputSize {
           return ErrInputTooLarge
       }
       // Other validations...
       return nil
   }
   ```

2. **Timeout Enforcement**
   ```go
   func parseWithTimeout(ctx context.Context, input []byte) error {
       done := make(chan error, 1)
       go func() {
           done <- parse(input)
       }()
       
       select {
       case err := <-done:
           return err
       case <-ctx.Done():
           return ctx.Err()
       }
   }
   ```

3. **Panic Recovery**
   ```go
   func safeParse(input []byte) (result Result, err error) {
       defer func() {
           if r := recover(); r != nil {
               err = fmt.Errorf("parse panic: %v", r)
           }
       }()
       return parse(input)
   }
   ```

4. **Resource Limits**
   ```go
   // Use context with deadlines
   // Limit goroutines (use worker pools)
   // Limit memory (use custom allocators or bounds checking)
   ```

### For Separate Process Parsers

1. **Process Creation**
   ```go
   func startParserProcess() (*exec.Cmd, error) {
       cmd := exec.Command("solid-rdf-parser")
       cmd.Stdin = pipeR
       cmd.Stdout = pipeW
       cmd.Stderr = logWriter
       
       // Set resource limits
       cmd.SysProcAttr = &syscall.SysProcAttr{
           Setpgid: true,
           // Setrlimit for memory, CPU, etc.
       }
       
       return cmd, cmd.Start()
   }
   ```

2. **IPC Protocol**
   ```go
   // Request format
   type ParseRequest struct {
       Input  []byte
       Format string
       Timeout time.Duration
   }
   
   // Response format
   type ParseResponse struct {
       Result interface{}
       Error  string
   }
   ```

3. **Health Monitoring**
   ```go
   func monitorParserProcess(ctx context.Context, cmd *exec.Cmd) error {
       // Monitor process health
       // Restart if crashed
       // Enforce timeouts
       // Track resource usage
   }
   ```

## Testing Requirements

### Unit Tests
- [ ] Parse correct inputs
- [ ] Reject malformed inputs
- [ ] Handle edge cases (empty, max size, etc.)
- [ ] Respect timeouts
- [ ] Recover from panics
- [ ] Handle resource exhaustion

### Fuzz Tests
- [ ] Fuzz all parsers with generated inputs
- [ ] Fuzz with known malicious inputs
- [ ] Fuzz with boundary values
- [ ] Fuzz with large inputs
- [ ] Fuzz with malformed inputs

### Integration Tests
- [ ] Parser in process isolation
- [ ] Parser with real inputs
- [ ] Parser with adversarial inputs
- [ ] Parser resource limits
- [ ] Parser timeout behavior

### Security Tests
- [ ] Memory safety tests
- [ ] Input validation bypass attempts
- [ ] Resource exhaustion tests
- [ ] Timeout bypass attempts

## Monitoring and Metrics

### Metrics to Collect

| Metric | Type | Description |
|--------|------|-------------|
| `parser_parse_total` | Counter | Total parse operations |
| `parser_parse_duration_seconds` | Histogram | Parse operation duration |
| `parser_parse_errors_total` | Counter | Parse errors by type |
| `parser_input_size_bytes` | Histogram | Input size distribution |
| `parser_timeout_total` | Counter | Timeout occurrences |
| `parser_panic_total` | Counter | Panic occurrences |
| `parser_memory_usage_bytes` | Gauge | Memory usage (for separate processes) |

### Alerts to Configure

| Alert | Condition | Severity |
|-------|-----------|----------|
| HighParseErrorRate | error rate > 5% | High |
| ParseTimeoutSpike | timeouts > 1% | High |
| ParsePanic | any panics | Critical |
| LargeInputDetected | input > 90% of max | Warning |

## Verification

### Acceptance Criteria

- [ ] All parsers have input size limits
- [ ] All parsers have timeout enforcement
- [ ] All parsers have panic recovery
- [ ] High-risk parsers run in separate processes
- [ ] Fuzz tests exist for all parsers
- [ ] Security tests pass for all parsers
- [ ] Monitoring in place for all parsers
- [ ] Documentation updated for all parsers

### Verification Steps

1. **Code Review**
   - Check all parsers for bounds checking
   - Check all parsers for timeout handling
   - Check all parsers for panic recovery
   - Check separate process implementation

2. **Testing**
   - Run all unit tests
   - Run all fuzz tests (smoke tests in CI)
   - Run all security tests
   - Run all integration tests

3. **Monitoring**
   - Verify metrics are collected
   - Verify alerts are configured
   - Verify dashboards show parser health

## Future Considerations

### WASM Sandboxing
- Evaluate WASM for high-risk third-party parsers
- Consider wasmtime or similar runtime
- Evaluate performance impact
- Consider portability benefits

### eBPF-Based Sandboxing
- Evaluate eBPF for system call filtering
- Consider using Falco or similar tools
- Evaluate performance impact

### Hardware-Based Isolation
- Consider hardware security modules (HSMs)
- Consider trusted execution environments (TEEs)
- Evaluate for cryptographic operations

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-07-04 | Initial version |
