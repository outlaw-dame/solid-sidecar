// Package observability provides privacy-safe logging utilities for Solid Sidecar
package observability

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TestDefaultPrivacyConfig tests the default privacy configuration
func TestDefaultPrivacyConfig(t *testing.T) {
	

	config := DefaultPrivacyConfig()

	if !config.Enabled {
		t.Error("Expected privacy to be enabled by default")
	}
	if !config.RedactWebIDs {
		t.Error("Expected WebID redaction to be enabled by default")
	}
	if !config.RedactTokens {
		t.Error("Expected token redaction to be enabled by default")
	}
	if !config.RedactQueryParams {
		t.Error("Expected query parameter redaction to be enabled by default")
	}
	if config.RedactURIs {
		t.Error("Expected URI redaction to be disabled by default (path-only is kept)")
	}
}

// TestSetGetPrivacyConfig tests setting and getting privacy configuration
func TestSetGetPrivacyConfig(t *testing.T) {
	

	// Save original config
	original := globalPrivacyConfig
	defer func() {
		globalPrivacyConfig = original
	}()

	// Set new config
	newConfig := PrivacyConfig{
		Enabled:      false,
		RedactWebIDs: false,
	}
	SetPrivacyConfig(newConfig)

	// Get config
	config := GetPrivacyConfig()
	if config.Enabled {
		t.Error("Expected privacy to be disabled after setting")
	}
	if config.RedactWebIDs {
		t.Error("Expected WebID redaction to be disabled after setting")
	}
}

// TestIsPrivacyEnabled tests the IsPrivacyEnabled function
func TestIsPrivacyEnabled(t *testing.T) {
	

	// Save original config
	original := globalPrivacyConfig
	defer func() {
		globalPrivacyConfig = original
	}()

	// Test enabled
	SetPrivacyConfig(PrivacyConfig{Enabled: true})
	if !IsPrivacyEnabled() {
		t.Error("Expected IsPrivacyEnabled to return true when enabled")
	}

	// Test disabled
	SetPrivacyConfig(PrivacyConfig{Enabled: false})
	if IsPrivacyEnabled() {
		t.Error("Expected IsPrivacyEnabled to return false when disabled")
	}
}

// TestSanitizeString tests string sanitization
func TestSanitizeString(t *testing.T) {
	

	// Save original config and enable all redaction
	original := globalPrivacyConfig
	SetPrivacyConfig(PrivacyConfig{
		Enabled:          true,
		RedactWebIDs:     true,
		RedactTokens:     true,
		RedactQueryParams: true,
	})
	defer func() {
		globalPrivacyConfig = original
	}()

	// Test WebID redaction
	webID := "https://user.example.org/profile/card#me"
	result := SanitizeString(webID)
	if result != "[REDACTED:webid]" {
		t.Errorf("Expected WebID to be redacted, got: %s", result)
	}

	// Test Bearer token redaction
	bearerToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	result = SanitizeString(bearerToken)
	if result != "[REDACTED:token]" {
		t.Errorf("Expected Bearer token to be redacted, got: %s", result)
	}

	// Test JWT token redaction
	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	result = SanitizeString(jwtToken)
	if result != "[REDACTED:token]" {
		t.Errorf("Expected JWT token to be redacted, got: %s", result)
	}

	// Test normal string (should not be redacted)
	normal := "Normal log message"
	result = SanitizeString(normal)
	if result != normal {
		t.Errorf("Expected normal string to not be redacted, got: %s", result)
	}

	// Test URI with query params (should have params removed)
	uriWithParams := "https://example.org/resource?secret=123&key=abc"
	result = SanitizeString(uriWithParams)
	expected := "https://example.org/resource"
	if result != expected {
		t.Errorf("Expected URI query params to be removed, got: %s", result)
	}
}

// TestSanitizeStringDisabled tests string sanitization when disabled
func TestSanitizeStringDisabled(t *testing.T) {
	

	// Save original config
	original := globalPrivacyConfig
	defer func() {
		globalPrivacyConfig = original
	}()

	// Disable privacy
	SetPrivacyConfig(PrivacyConfig{Enabled: false})

	// Test that nothing is redacted when disabled
	webID := "https://user.example.org/profile/card#me"
	result := SanitizeString(webID)
	if result != webID {
		t.Errorf("Expected string to not be redacted when privacy is disabled, got: %s", result)
	}
}

// TestHashWebID tests WebID hashing
func TestHashWebID(t *testing.T) {
	

	// Save original config
	original := globalPrivacyConfig
	SetPrivacyConfig(PrivacyConfig{
		Enabled:      true,
		RedactWebIDs: true,
	})
	defer func() {
		globalPrivacyConfig = original
	}()

	// Test hashing
	webID := "https://user.example.org/profile/card#me"
	result := HashWebID(webID)
	
	// Should start with "webid:"
	if !strings.HasPrefix(result, "webid:") {
		t.Errorf("Expected hashed WebID to start with 'webid:', got: %s", result)
	}
	
	// Should be consistent
	result2 := HashWebID(webID)
	if result != result2 {
		t.Errorf("Expected consistent hashing, got: %s and %s", result, result2)
	}
	
	// Different WebIDs should have different hashes
	webID2 := "https://other.example.org/profile/card#me"
	result3 := HashWebID(webID2)
	if result == result3 {
		t.Errorf("Expected different WebIDs to have different hashes, got: %s for both", result)
	}
}

// TestSanitizeURI tests URI sanitization
func TestSanitizeURI(t *testing.T) {
	

	testCases := []struct {
		input    string
		expected string
	}{
		{"https://example.org/path?query=value", "https://example.org/path"},
		{"https://example.org/path#fragment", "https://example.org/path"},
		{"https://example.org/path?query=value#fragment", "https://example.org/path"},
		{"https://example.org/path", "https://example.org/path"},
		{"https://example.org", "https://example.org"},
		{"", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := sanitizeURI(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// TestSanitizeMap tests map sanitization
func TestSanitizeMap(t *testing.T) {
	

	// Save original config
	original := globalPrivacyConfig
	SetPrivacyConfig(PrivacyConfig{
		Enabled:      true,
		RedactWebIDs: true,
		RedactTokens: true,
	})
	defer func() {
		globalPrivacyConfig = original
	}()

	input := map[string]any{
		"webid":   "https://user.example.org/profile/card#me",
		"token":   "Bearer eyJhbGciOiJIUzI1NiJ9",
		"message": "Hello",
		"count":   42,
	}

	result := SanitizeMap(input)

	if result["webid"] != "[REDACTED:webid]" {
		t.Errorf("Expected webid to be redacted, got: %v", result["webid"])
	}
	if result["token"] != "[REDACTED:token]" {
		t.Errorf("Expected token to be redacted, got: %v", result["token"])
	}
	if result["message"] != "Hello" {
		t.Errorf("Expected message to not be redacted, got: %v", result["message"])
	}
	if result["count"] != 42 {
		t.Errorf("Expected count to not be redacted, got: %v", result["count"])
	}
}

// TestPrivacySafeLogger tests the PrivacySafeLogger
func TestPrivacySafeLogger(t *testing.T) {
	

	// Save original config
	original := globalPrivacyConfig
	SetPrivacyConfig(PrivacyConfig{
		Enabled:          true,
		RedactWebIDs:     true,
		RedactTokens:     true,
		RedactQueryParams: true,
	})
	defer func() {
		globalPrivacyConfig = original
	}()

	// Create a logger with a buffer to capture output
	var buf bytes.Buffer
	logger := &PrivacySafeLogger{
		logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	}

	// Log a message with sensitive data
	logger.Info("Test message",
		"webid", "https://user.example.org/profile/card#me",
		"token", "Bearer eyJhbGciOiJIUzI1NiJ9",
		"message", "Hello",
	)

	output := buf.String()
	
	// Check that webid is redacted
	if strings.Contains(output, "https://user.example.org") {
		t.Error("Expected WebID to be redacted in output")
	}
	
	// Check that token is redacted
	if strings.Contains(output, "Bearer eyJ") {
		t.Error("Expected token to be redacted in output")
	}
	
	// Check that message is not redacted
	if !strings.Contains(output, "Hello") {
		t.Error("Expected message to not be redacted in output")
	}
	
	// Check that redacted placeholders are present
	if !strings.Contains(output, "REDACTED") {
		t.Error("Expected REDACTED placeholder in output")
	}
}

// TestPrivacySafeLoggerWithContext tests the PrivacySafeLogger with context
func TestPrivacySafeLoggerWithContext(t *testing.T) {
	

	// Save original config
	original := globalPrivacyConfig
	SetPrivacyConfig(PrivacyConfig{
		Enabled:          true,
		RedactWebIDs:     true,
		RedactTokens:     true,
		RedactQueryParams: true,
	})
	defer func() {
		globalPrivacyConfig = original
	}()

	// Create context with values
	ctx := context.Background()
	ctx = WithRequestID(ctx, "req-123")
	ctx = WithCorrelationID(ctx, "corr-456")
	ctx = WithSessionID(ctx, "sess-789")
	ctx = WithAgentIdentity(ctx, "https://agent.example.org/profile/card#me")

	// Create a logger with a buffer to capture output
	var buf bytes.Buffer
	logger := &PrivacySafeLogger{
		logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	}

	// Log a message with context
	withContext := logger.WithContext(ctx)
	withContext.Info("Test message with context")

	output := buf.String()
	
	// Check that request ID is present
	if !strings.Contains(output, "req-123") {
		t.Error("Expected request ID to be in output")
	}
	
	// Check that correlation ID is present
	if !strings.Contains(output, "corr-456") {
		t.Error("Expected correlation ID to be in output")
	}
	
	// Check that session ID is present
	if !strings.Contains(output, "sess-789") {
		t.Error("Expected session ID to be in output")
	}
	
	// Check that agent identity is hashed
	if strings.Contains(output, "agent.example.org") {
		t.Error("Expected agent identity to be hashed in output")
	}
	
	// Check that hashed agent identity is present
	if !strings.Contains(output, "agent_identity_hash") {
		t.Error("Expected agent_identity_hash to be in output")
	}
}

// TestGlobalPrivacyFunctions tests the global privacy-safe logging functions
func TestGlobalPrivacyFunctions(t *testing.T) {
	

	// Save original config
	original := globalPrivacyConfig
	defer func() {
		globalPrivacyConfig = original
	}()

	// Enable privacy
	SetPrivacyConfig(PrivacyConfig{Enabled: true, RedactWebIDs: true})

	// Test that global functions don't panic
	PrivacyDebug("Debug message")
	PrivacyInfo("Info message")
	PrivacyWarn("Warn message")
	PrivacyError("Error message")

	// Test with context
	ctx := WithRequestID(context.Background(), "test-req")
	PrivacyDebugContext(ctx, "Debug with context")
	PrivacyInfoContext(ctx, "Info with context")
	PrivacyWarnContext(ctx, "Warn with context")
	PrivacyErrorContext(ctx, "Error with context")
}

// TestIsWebID tests the isWebID function
func TestIsWebID(t *testing.T) {
	

	testCases := []struct {
		input    string
		expected bool
	}{
		{"https://user.example.org/profile/card#me", true},
		{"http://user.example.org/profile/card#me", true},
		{"https://example.org/profile/card#me", true},
		{"not-a-webid", false},
		{"", false},
		{"user@example.org", false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := isWebID(tc.input)
			if result != tc.expected {
				t.Errorf("Expected isWebID(%s) = %v, got %v", tc.input, tc.expected, result)
			}
		})
	}
}

// TestIsToken tests the isToken function
func TestIsToken(t *testing.T) {
	

	testCases := []struct {
		input    string
		expected bool
	}{
		{"Bearer eyJhbGciOiJIUzI1NiJ9", true},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", true},
		{"abc123def456", true},
		{"not-a-token", false},
		{"", false},
		{"Bearer", false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := isToken(tc.input)
			if result != tc.expected {
				t.Errorf("Expected isToken(%s) = %v, got %v", tc.input, tc.expected, result)
			}
		})
	}
}

// TestIsBase64Like tests the isBase64Like function
func TestIsBase64Like(t *testing.T) {
	

	testCases := []struct {
		input    string
		expected bool
	}{
		{"SGVsbG8=", true},
		{"SGVsbG8gV29ybGQ=", true},
		{"SGVsbG8gV29ybGQ=", true},
		{"not-base64!", false},
		{"", false},
		{"abc123", true}, // Could be base64
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := isBase64Like(tc.input)
			if result != tc.expected {
				t.Errorf("Expected isBase64Like(%s) = %v, got %v", tc.input, tc.expected, result)
			}
		})
	}
}

// TestSanitizeValue tests value sanitization based on key
func TestSanitizeValue(t *testing.T) {
	

	// Save original config
	original := globalPrivacyConfig
	SetPrivacyConfig(PrivacyConfig{
		Enabled:      true,
		RedactWebIDs: true,
		RedactTokens: true,
	})
	defer func() {
		globalPrivacyConfig = original
	}()

	testCases := []struct {
		key      string
		value    any
		expected any
	}{
		{"webid", "https://user.example.org/profile/card#me", "[REDACTED:webid]"},
		{"WebID", "https://user.example.org/profile/card#me", "[REDACTED:WebID]"},
		{"authorization", "Bearer token", "[REDACTED:authorization]"},
		{"Authorization", "Bearer token", "[REDACTED:Authorization]"},
		{"token", "secret-token", "[REDACTED:token]"},
		{"password", "secret123", "[REDACTED:password]"},
		{"message", "Hello", "Hello"},
		{"count", 42, 42},
		{"enabled", true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.key, func(t *testing.T) {
			result := sanitizeValue(tc.key, tc.value)
			if result != tc.expected {
				t.Errorf("Expected sanitizeValue(%s, %v) = %v, got %v", tc.key, tc.value, tc.expected, result)
			}
		})
	}
}

// TestPrivacyDisabled tests that no redaction occurs when privacy is disabled
func TestPrivacyDisabled(t *testing.T) {
	

	// Save original config
	original := globalPrivacyConfig
	defer func() {
		globalPrivacyConfig = original
	}()

	// Disable privacy
	SetPrivacyConfig(PrivacyConfig{Enabled: false})

	// Test that sensitive data is not redacted
	webID := "https://user.example.org/profile/card#me"
	result := SanitizeString(webID)
	if result != webID {
		t.Errorf("Expected no redaction when privacy disabled, got: %s", result)
	}

	// Test map sanitization
	input := map[string]any{"webid": webID, "token": "secret"}
	resultMap := SanitizeMap(input)
	if resultMap["webid"] != webID {
		t.Errorf("Expected webid to not be redacted when privacy disabled, got: %v", resultMap["webid"])
	}
}
