// Package observability provides privacy-safe logging utilities for Solid Sidecar
// This file implements Phase 39.3: Structured logging with privacy-safe field redaction
package observability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/url"
	"strings"
)

// PrivacyConfig configures privacy-safe logging behavior
type PrivacyConfig struct {
	// Enabled controls whether privacy redaction is active
	Enabled bool
	// RedactWebIDs controls whether WebIDs are redacted
	RedactWebIDs bool
	// RedactURIs controls whether full URIs are redacted (path-only is kept)
	RedactURIs bool
	// RedactTokens controls whether tokens and credentials are redacted
	RedactTokens bool
	// RedactQueryParams controls whether query parameters are redacted from URIs
	RedactQueryParams bool
	// RedactHeaders controls which headers to redact
	RedactHeaders []string
}

// DefaultPrivacyConfig returns default privacy configuration
// By default, privacy-safe logging is enabled with conservative redaction
func DefaultPrivacyConfig() PrivacyConfig {
	return PrivacyConfig{
		Enabled:           true,
		RedactWebIDs:      true,
		RedactURIs:        false, // Keep path-only URIs
		RedactTokens:      true,
		RedactQueryParams: true,
		RedactHeaders: []string{
			"authorization",
			"cookie",
			"x-api-key",
			"x-access-token",
			"x-refresh-token",
			"dpop",
			"digest",
		},
	}
}

// globalPrivacyConfig is the global privacy configuration
var globalPrivacyConfig = DefaultPrivacyConfig()

// SetPrivacyConfig sets the global privacy configuration
func SetPrivacyConfig(config PrivacyConfig) {
	globalPrivacyConfig = config
}

// GetPrivacyConfig returns the current privacy configuration
func GetPrivacyConfig() PrivacyConfig {
	return globalPrivacyConfig
}

// IsPrivacyEnabled returns true if privacy-safe logging is enabled
func IsPrivacyEnabled() bool {
	return globalPrivacyConfig.Enabled
}

// SanitizeString sanitizes a string for logging based on privacy configuration
func SanitizeString(value string) string {
	if !globalPrivacyConfig.Enabled {
		return value
	}

	// If the string looks like a token, redact it (check this first as tokens might look like URIs)
	if globalPrivacyConfig.RedactTokens && isToken(value) {
		return "[REDACTED:token]"
	}

	// If the string looks like a WebID, redact it
	if globalPrivacyConfig.RedactWebIDs && isWebID(value) {
		return "[REDACTED:webid]"
	}

	// If the string is a full URI and we're only keeping paths, redact query params
	if globalPrivacyConfig.RedactQueryParams {
		value = sanitizeURI(value)
	}

	return value
}

// isWebID checks if a string looks like a WebID
func isWebID(value string) bool {
	if value == "" {
		return false
	}
	// WebIDs typically start with http:// or https:// and contain Solid-specific patterns
	lowerValue := strings.ToLower(value)
	if !(strings.HasPrefix(lowerValue, "http://") || strings.HasPrefix(lowerValue, "https://")) {
		return false
	}

	// Check for common WebID patterns - be specific to avoid false positives
	webIDPatterns := []string{
		"/profile/card#me",
		"/profile/card#",
		"#me",
		"/.well-known/webid",
		"/webid",
		"/profile/",
	}

	for _, pattern := range webIDPatterns {
		if strings.Contains(lowerValue, pattern) {
			return true
		}
	}

	return false
}

// isToken checks if a string looks like a token (Bearer token, JWT, etc.)
func isToken(value string) bool {
	if value == "" {
		return false
	}

	// Check for Bearer prefix
	if strings.HasPrefix(value, "Bearer ") {
		return true
	}

	// Check for JWT-like structure (three base64-encoded parts separated by dots)
	parts := strings.Split(value, ".")
	if len(parts) == 3 {
		// Check if all parts look like base64
		for _, part := range parts {
			if !isBase64Like(part) {
				return false
			}
		}
		return true
	}

	// Check for hex-encoded strings that look like tokens
	if len(value) >= 16 && isHex(value) {
		return true
	}

	// Check for strings that look like random tokens (alphanumeric, no spaces, reasonable length)
	if len(value) >= 12 && len(value) <= 128 {
		isAlphanumeric := true
		for _, c := range value {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				isAlphanumeric = false
				break
			}
		}
		if isAlphanumeric {
			return true
		}
	}

	return false
}

// isBase64Like checks if a string looks like base64 encoding
// This includes both standard Base64 and Base64URL (used in JWTs)
func isBase64Like(value string) bool {
	if value == "" {
		return false
	}
	// Base64 strings typically only contain A-Z, a-z, 0-9, +, /, and = (for padding)
	// Base64URL (used in JWTs) uses - and _ instead of + and /
	for _, c := range value {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '=' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// isHex checks if a string looks like hexadecimal encoding
func isHex(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// sanitizeURI removes query parameters and fragments from URIs
func sanitizeURI(uri string) string {
	if uri == "" {
		return ""
	}

	// Parse the URI and remove query and fragment
	parsed, err := url.Parse(uri)
	if err != nil {
		// If parsing fails, just return the original
		return uri
	}

	// If it doesn't look like a proper URL (no scheme), return as-is
	if parsed.Scheme == "" && parsed.Host == "" {
		// This is not a URL, just return the original
		return uri
	}

	// Return only the scheme + host + path
	if parsed.Scheme != "" && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host + parsed.Path
	}

	// If we have a scheme but no host, or host but no scheme, return what we can
	if parsed.Scheme != "" {
		return parsed.Scheme + ":" + parsed.Path
	}
	if parsed.Host != "" {
		return "//" + parsed.Host + parsed.Path
	}

	// Fallback
	return parsed.Path
}

// HashWebID hashes a WebID for logging (preserves uniqueness while protecting privacy)
func HashWebID(webID string) string {
	if webID == "" || !globalPrivacyConfig.RedactWebIDs || !globalPrivacyConfig.Enabled {
		return webID
	}

	hash := sha256.Sum256([]byte(webID))
	return "webid:" + hex.EncodeToString(hash[:])[:16] // Use first 16 chars of hash
}

// HashURI hashes a URI for logging (preserves uniqueness while protecting privacy)
func HashURI(uri string) string {
	if uri == "" || !globalPrivacyConfig.Enabled {
		return uri
	}

	// If we're not redacting URIs, just sanitize query params
	if !globalPrivacyConfig.RedactURIs {
		return sanitizeURI(uri)
	}

	hash := sha256.Sum256([]byte(uri))
	return "uri:" + hex.EncodeToString(hash[:])[:16]
}

// SanitizeMap sanitizes a map of string keys and values for logging
func SanitizeMap(m map[string]any) map[string]any {
	if !globalPrivacyConfig.Enabled {
		return m
	}

	sanitized := make(map[string]any, len(m))
	for k, v := range m {
		sanitized[k] = sanitizeValue(k, v)
	}
	return sanitized
}

// sanitizeValue sanitizes a value based on its key
func sanitizeValue(key string, value any) any {
	if !globalPrivacyConfig.Enabled {
		return value
	}

	keyLower := strings.ToLower(key)

	// Check if this key should be redacted
	for _, header := range globalPrivacyConfig.RedactHeaders {
		if strings.ToLower(header) == keyLower {
			return "[REDACTED:" + key + "]"
		}
	}

	// Check for common sensitive keys
	sensitiveKeys := []string{"webid", "agent", "authorization", "cookie", "token", "password", "secret", "credential", "api_key", "access_token", "refresh_token", "private_key", "did", "issuer"}
	for _, sensitive := range sensitiveKeys {
		if keyLower == sensitive {
			return "[REDACTED:" + key + "]"
		}
	}

	// Handle specific types
	switch v := value.(type) {
	case string:
		return SanitizeString(v)
	case []byte:
		return SanitizeString(string(v))
	case map[string]any:
		return SanitizeMap(v)
	default:
		return v
	}
}

// PrivacySafeLogger wraps slog.Logger with privacy-safe logging
// This implements Phase 39.3: Structured logging with privacy-safe field redaction
type PrivacySafeLogger struct {
	logger *slog.Logger
}

// NewPrivacySafeLogger creates a new privacy-safe logger
func NewPrivacySafeLogger() *PrivacySafeLogger {
	return &PrivacySafeLogger{
		logger: slog.Default(),
	}
}

// NewPrivacySafeLoggerWithLevel creates a new privacy-safe logger with a specific level
func NewPrivacySafeLoggerWithLevel(level slog.Level) *PrivacySafeLogger {
	return &PrivacySafeLogger{
		logger: slog.New(slog.NewJSONHandler(nil, &slog.HandlerOptions{Level: level})),
	}
}

// WithContext adds context fields to the logger
func (l *PrivacySafeLogger) WithContext(ctx context.Context) *PrivacySafeLogger {
	// Extract context fields and sanitize them
	fields := extractAndSanitizeContext(ctx)

	// Create a new logger with the sanitized fields
	newLogger := l.logger.With(fields...)

	return &PrivacySafeLogger{
		logger: newLogger,
	}
}

// extractAndSanitizeContext extracts fields from context and sanitizes them
func extractAndSanitizeContext(ctx context.Context) []any {
	if !globalPrivacyConfig.Enabled {
		return nil
	}

	fields := []any{}

	// Extract and sanitize request ID
	if requestID := RequestIDFromContext(ctx); requestID != "" {
		fields = append(fields, "request_id", requestID)
	}

	// Extract and sanitize correlation ID
	if correlationID := CorrelationIDFromContext(ctx); correlationID != "" {
		fields = append(fields, "correlation_id", correlationID)
	}

	// Extract and sanitize session ID
	if sessionID := SessionIDFromContext(ctx); sessionID != "" {
		fields = append(fields, "session_id", sessionID)
	}

	// Extract and sanitize agent identity (hash it for privacy)
	if agentID := AgentIdentityFromContext(ctx); agentID != "" {
		if globalPrivacyConfig.RedactWebIDs {
			fields = append(fields, "agent_identity_hash", HashWebID(agentID))
		} else {
			fields = append(fields, "agent_identity", agentID)
		}
	}

	return fields
}

// WithFields adds sanitized fields to the logger
func (l *PrivacySafeLogger) WithFields(fields map[string]any) *PrivacySafeLogger {
	sanitized := SanitizeMap(fields)

	// Convert map to slice of key-value pairs
	attrs := make([]any, 0, len(sanitized)*2)
	for k, v := range sanitized {
		attrs = append(attrs, k, v)
	}

	return &PrivacySafeLogger{
		logger: l.logger.With(attrs...),
	}
}

// Log logs a message with the given level and sanitized attributes
func (l *PrivacySafeLogger) Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	// Sanitize the arguments
	sanitizedArgs := sanitizeArgs(args)

	// Add context fields
	logger := l.logger
	if ctx != nil {
		contextFields := extractAndSanitizeContext(ctx)
		if len(contextFields) > 0 {
			logger = l.logger.With(contextFields...)
		}
	}

	logger.Log(ctx, level, msg, sanitizedArgs...)
}

// sanitizeArgs sanitizes a slice of arguments (alternating key-value pairs)
func sanitizeArgs(args []any) []any {
	if !globalPrivacyConfig.Enabled || len(args) == 0 {
		return args
	}

	sanitized := make([]any, 0, len(args))

	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			// Odd number of arguments - just append the last one
			sanitized = append(sanitized, args[i])
			break
		}

		key := args[i]
		value := args[i+1]

		keyStr, ok := key.(string)
		if !ok {
			// Key is not a string - just append as-is
			sanitized = append(sanitized, key, value)
			continue
		}

		// Sanitize the value based on the key
		sanitized = append(sanitized, keyStr, sanitizeValue(keyStr, value))
	}

	return sanitized
}

// Debug logs a debug message with sanitized attributes
func (l *PrivacySafeLogger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, sanitizeArgs(args)...)
}

// Info logs an info message with sanitized attributes
func (l *PrivacySafeLogger) Info(msg string, args ...any) {
	l.logger.Info(msg, sanitizeArgs(args)...)
}

// Warn logs a warning message with sanitized attributes
func (l *PrivacySafeLogger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, sanitizeArgs(args)...)
}

// Error logs an error message with sanitized attributes
func (l *PrivacySafeLogger) Error(msg string, args ...any) {
	l.logger.Error(msg, sanitizeArgs(args)...)
}

// DebugContext logs a debug message with context and sanitized attributes
func (l *PrivacySafeLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	sanitized := sanitizeArgs(args)
	contextFields := extractAndSanitizeContext(ctx)
	allArgs := append(contextFields, sanitized...)
	l.logger.Debug(msg, allArgs...)
}

// InfoContext logs an info message with context and sanitized attributes
func (l *PrivacySafeLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	sanitized := sanitizeArgs(args)
	contextFields := extractAndSanitizeContext(ctx)
	allArgs := append(contextFields, sanitized...)
	l.logger.Info(msg, allArgs...)
}

// WarnContext logs a warning message with context and sanitized attributes
func (l *PrivacySafeLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	sanitized := sanitizeArgs(args)
	contextFields := extractAndSanitizeContext(ctx)
	allArgs := append(contextFields, sanitized...)
	l.logger.Warn(msg, allArgs...)
}

// ErrorContext logs an error message with context and sanitized attributes
func (l *PrivacySafeLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	sanitized := sanitizeArgs(args)
	contextFields := extractAndSanitizeContext(ctx)
	allArgs := append(contextFields, sanitized...)
	l.logger.Error(msg, allArgs...)
}

// Global privacy-safe logging functions

// PrivacyDebug logs a debug message with privacy-safe redaction
func PrivacyDebug(msg string, args ...any) {
	if globalPrivacyConfig.Enabled {
		logger := NewPrivacySafeLogger()
		logger.Debug(msg, args...)
	} else {
		slog.Debug(msg, args...)
	}
}

// PrivacyInfo logs an info message with privacy-safe redaction
func PrivacyInfo(msg string, args ...any) {
	if globalPrivacyConfig.Enabled {
		logger := NewPrivacySafeLogger()
		logger.Info(msg, args...)
	} else {
		slog.Info(msg, args...)
	}
}

// PrivacyWarn logs a warning message with privacy-safe redaction
func PrivacyWarn(msg string, args ...any) {
	if globalPrivacyConfig.Enabled {
		logger := NewPrivacySafeLogger()
		logger.Warn(msg, args...)
	} else {
		slog.Warn(msg, args...)
	}
}

// PrivacyError logs an error message with privacy-safe redaction
func PrivacyError(msg string, args ...any) {
	if globalPrivacyConfig.Enabled {
		logger := NewPrivacySafeLogger()
		logger.Error(msg, args...)
	} else {
		slog.Error(msg, args...)
	}
}

// PrivacyDebugContext logs a debug message with context and privacy-safe redaction
func PrivacyDebugContext(ctx context.Context, msg string, args ...any) {
	if globalPrivacyConfig.Enabled {
		logger := NewPrivacySafeLogger()
		logger.DebugContext(ctx, msg, args...)
	} else {
		slog.DebugContext(ctx, msg, args...)
	}
}

// PrivacyInfoContext logs an info message with context and privacy-safe redaction
func PrivacyInfoContext(ctx context.Context, msg string, args ...any) {
	if globalPrivacyConfig.Enabled {
		logger := NewPrivacySafeLogger()
		logger.InfoContext(ctx, msg, args...)
	} else {
		slog.InfoContext(ctx, msg, args...)
	}
}

// PrivacyWarnContext logs a warning message with context and privacy-safe redaction
func PrivacyWarnContext(ctx context.Context, msg string, args ...any) {
	if globalPrivacyConfig.Enabled {
		logger := NewPrivacySafeLogger()
		logger.WarnContext(ctx, msg, args...)
	} else {
		slog.WarnContext(ctx, msg, args...)
	}
}

// PrivacyErrorContext logs an error message with context and privacy-safe redaction
func PrivacyErrorContext(ctx context.Context, msg string, args ...any) {
	if globalPrivacyConfig.Enabled {
		logger := NewPrivacySafeLogger()
		logger.ErrorContext(ctx, msg, args...)
	} else {
		slog.ErrorContext(ctx, msg, args...)
	}
}
