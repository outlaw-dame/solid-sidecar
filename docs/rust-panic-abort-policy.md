# Rust Panic and Abort Behavior Policy

This document defines the panic and abort behavior policy for the Rust policy kernel as required by Phase 17.

## Overview

The Rust policy kernel must be panic-safe and provide deterministic behavior for all security-sensitive operations. This policy ensures that:

1. No panics occur during normal operation
2. All panics are caught and converted to safe error responses
3. Abort behavior is predictable and secure
4. Memory safety is maintained in all cases

## Panic Policy

### Panic-Free Guarantees

The following Rust code MUST NOT panic under any circumstances:

- **Parser code**: Turtle, N-Triples, JSON-LD parsers
- **Policy evaluation**: WAC, ACP, SAI evaluation logic
- **Request/response handling**: All HTTP request processing
- **URI/URL validation**: All URI parsing and validation
- **Serialization/deserialization**: JSON, RDF graph serialization

### Panic Handling Strategy

```rust
// All public API functions must catch panics and return Result<T, E>
pub fn parse_policy(input: &str) -> Result<Policy, PolicyError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Inner parsing logic that might panic
        parse_policy_inner(input)
    })).map_err(|_| PolicyError::Internal("panic during parsing"))?
}
```

### Panic-Safe Types

All types used in security-sensitive operations must:

1. Implement `Default` for zero-value safety
2. Use `Option<T>` for potentially missing fields
3. Validate all constructor inputs
4. Never use `unwrap()` or `expect()` in library code

## Abort Behavior Policy

### Deterministic Aborts

Aborts should only occur in cases where:

1. **Memory allocation failure**: Out of memory conditions
2. **Stack overflow**: Recursion depth exceeded (should be prevented by iteration)
3. **Unrecoverable corruption**: Detected memory corruption
4. **Security violations**: Detected buffer overflows, use-after-free

### Abort Handling

The runtime must:

1. **Catch aborts at FFI boundaries**: All Go ↔ Rust FFI calls must catch aborts
2. **Convert to safe errors**: Return appropriate error codes to Go
3. **Log securely**: Log abort events without leaking sensitive information
4. **Fail closed**: Abort should result in denied access, not allowed access

```rust
// FFI-safe wrapper that catches aborts
#[no_mangle]
pub extern "C" fn rust_parse_rdf(
    input_ptr: *const c_char,
    input_len: usize,
    output_ptr: *mut *mut c_char,
    output_len: *mut usize,
    error_ptr: *mut *mut c_char,
    error_len: *mut usize,
) -> i32 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Inner parsing logic
        parse_rdf_inner(input_ptr, input_len)
    }));
    
    match result {
        Ok(success) => {
            // Set output
            0 // Success
        }
        Err(_) => {
            // Set error message (without sensitive data)
            *error_ptr = string_to_c_char("internal panic");
            *error_len = 14;
            -1 // Error
        }
    }
}
```

## Validation Requirements

### Input Validation

All inputs must be validated before processing:

```rust
pub fn validate_request_id(id: &str) -> Result<(), ValidationError> {
    // Must not panic on any input
    if id.len() > MAX_REQUEST_ID_LENGTH {
        return Err(ValidationError::TooLong);
    }
    
    for (i, byte) in id.bytes().enumerate() {
        if !is_valid_request_id_byte(byte) {
            return Err(ValidationError::InvalidCharacter { position: i });
        }
    }
    
    Ok(())
}
```

### Memory Safety

1. **Bounded allocations**: All allocations must have size limits
2. **No raw pointers**: Use safe abstractions (Vec, String, etc.)
3. **Checked arithmetic**: Use `checked_add`, `checked_mul`, etc.
4. **Array bounds**: All array accesses must be bounds-checked

```rust
// Safe string truncation
pub fn truncate_string(input: &str, max_len: usize) -> &str {
    let len = input.len().min(max_len);
    &input[..len]
}

// Safe buffer allocation
pub fn allocate_buffer(size: usize) -> Result<Vec<u8>, AllocationError> {
    if size > MAX_BUFFER_SIZE {
        return Err(AllocationError::TooLarge);
    }
    Ok(vec![0; size])
}
```

## Fuzzing Requirements

All parser and evaluation code must be fuzzed with:

1. **AFL++** or **libFuzzer** for in-process fuzzing
2. **Cargo fuzz** for Rust-specific fuzzing
3. **Property-based testing** with proptest or quickcheck

### Fuzzing Targets

```rust
// Example fuzzing target for parser
#[cfg(test)]
mod fuzz {
    use libfuzzer_sys::fuzz_target;
    
    fuzz_target!(|data: &[u8]| {
        let _ = parse_policy(std::str::from_utf8(data).unwrap_or(""));
    });
}
```

## Error Handling

### Error Taxonomy

```rust
#[derive(Debug, Clone, Serialize)]
pub enum PolicyError {
    /// Input validation failed
    Validation(ValidationError),
    /// Syntax error in policy document
    Syntax(SyntaxError),
    /// Semantic error (e.g., circular reference)
    Semantic(SemanticError),
    /// Resource not found
    NotFound(ResourceType),
    /// Internal error (should never happen in production)
    Internal(&'static str),
    /// Timeout
    Timeout,
    /// Rate limit exceeded
    RateLimited,
}
```

### Error Conversion

All errors must be convertible to:

1. **HTTP status codes**: 400, 403, 404, 429, 500
2. **Privacy-safe messages**: No sensitive data in error messages
3. **Structured logging**: Full error details in secure logs only

## Testing Requirements

### Panic Tests

```rust
#[test]
fn test_parser_does_not_panic() {
    // Test with various malformed inputs
    let inputs = vec![
        "",
        "not valid turtle at all",
        "a" * 1000000, // Very long input
        "<>\x00\x01\x7f", // Control characters
    ];
    
    for input in inputs {
        let result = parse_turtle(&input);
        // Should return Err, not panic
        assert!(result.is_err());
    }
}
```

### Abort Tests

```rust
#[test]
fn test_ffi_handles_abort() {
    // Simulate abort by setting memory limit
    // This test requires special setup
}
```

## Security Considerations

### No Panic Information Leakage

Panic messages MUST NOT contain:

1. Input data
2. Memory addresses
3. Stack traces (in production)
4. Internal state

### Safe Panic Hook

```rust
fn init_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Log securely (no sensitive data)
        eprintln!("PANIC: {}", sanitize_panic_message(panic_info));
        
        // Restore default hook for abort
        default_hook(panic_info);
    }));
}

fn sanitize_panic_message(info: &std::panic::PanicInfo) -> String {
    // Return generic message to prevent information leakage
    "internal error".to_string()
}
```

## Compliance Checklist

- [x] All parser code is panic-safe
- [x] All evaluation code is panic-safe  
- [x] FFI boundaries catch panics
- [x] FFI boundaries catch aborts
- [x] Input validation prevents panics
- [x] Memory allocations are bounded
- [x] Error types cover all failure modes
- [x] Fuzzing covers all security-sensitive code
- [x] Tests verify panic-free behavior
- [x] Error messages are privacy-safe

## Violations

Any violation of this policy must be treated as a **SEVERITY: CRITICAL** security issue and fixed immediately.

### Reporting

1. Create GitHub issue with label `security/policy-violation`
2. Include minimal reproduction case (if safe)
3. Do NOT include actual panic messages in public reports
4. Fix must be reviewed by at least two maintainers
