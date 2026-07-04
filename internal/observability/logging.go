package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// NewLogger creates a structured JSON logger for sidecar runtime events.
// Supports different log levels: debug, info, warn, error
func NewLogger(level string) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel}))
}

// NewLoggerWithOptions creates a structured JSON logger with custom options
func NewLoggerWithOptions(level string, addSource bool) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slogLevel,
		AddSource: addSource,
	}))
}

// RequestID returns a middleware that ensures every request and response has a
// stable request identifier. It accepts a caller-provided X-Request-ID only when
// it is small and does not contain obvious header injection characters.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := sanitizeRequestID(r.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), requestID)))
	})
}

// CorrelationIDMiddleware returns a middleware that ensures every request has a
// correlation ID for distributed tracing. Uses X-Correlation-ID header or generates one.
func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID := sanitizeRequestID(r.Header.Get("X-Correlation-ID"))
		if correlationID == "" {
			correlationID = RequestIDFromContext(r.Context())
			if correlationID == "" {
				correlationID = newRequestID()
			}
		}
		w.Header().Set("X-Correlation-ID", correlationID)
		ctx := WithCorrelationID(r.Context(), correlationID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FullContextMiddleware returns a middleware that sets up complete context with
// request ID, correlation ID, and other identifiers for observability.
func FullContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := sanitizeRequestID(r.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := WithRequestID(r.Context(), requestID)

		correlationID := sanitizeRequestID(r.Header.Get("X-Correlation-ID"))
		if correlationID == "" {
			correlationID = requestID
		}
		w.Header().Set("X-Correlation-ID", correlationID)
		ctx = WithCorrelationID(ctx, correlationID)

		if sessionID := sanitizeRequestID(r.Header.Get("X-Session-ID")); sessionID != "" {
			ctx = WithSessionID(ctx, sessionID)
		}

		if agentID := sanitizeRequestID(r.Header.Get("X-Agent-ID")); agentID != "" {
			ctx = WithAgentIdentity(ctx, agentID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AccessLog returns a middleware that logs HTTP request access with full context.
func AccessLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		attrs := []any{
			"request_id", RequestIDFromContext(r.Context()),
			"method", r.Method,
			"path", r.URL.EscapedPath(),
			"status", recorder.status,
			"duration_ms", time.Since(start).Milliseconds(),
		}

		if correlationID := CorrelationIDFromContext(r.Context()); correlationID != "" {
			attrs = append(attrs, "correlation_id", correlationID)
		}

		if sessionID := SessionIDFromContext(r.Context()); sessionID != "" {
			attrs = append(attrs, "session_id", sessionID)
		}

		if agentID := AgentIdentityFromContext(r.Context()); agentID != "" {
			attrs = append(attrs, "agent_identity_hash", agentID)
		}

		logger.Info("request completed", attrs...)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func sanitizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		return ""
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return ""
	}
	return value
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

// GenerateCorrelationID generates a new correlation ID
func GenerateCorrelationID() string {
	return newRequestID()
}

// ContextLogger returns a logger with context values pre-populated
func ContextLogger(logger *slog.Logger, ctx context.Context) *slog.Logger {
	attrs := make([]any, 0, 8)

	if requestID := RequestIDFromContext(ctx); requestID != "" {
		attrs = append(attrs, "request_id", requestID)
	}

	if correlationID := CorrelationIDFromContext(ctx); correlationID != "" {
		attrs = append(attrs, "correlation_id", correlationID)
	}

	if sessionID := SessionIDFromContext(ctx); sessionID != "" {
		attrs = append(attrs, "session_id", sessionID)
	}

	if agentID := AgentIdentityFromContext(ctx); agentID != "" {
		attrs = append(attrs, "agent_identity_hash", agentID)
	}

	if len(attrs) > 0 {
		return logger.With(attrs...)
	}
	return logger
}

// LogError logs an error with full context
func LogError(logger *slog.Logger, ctx context.Context, err error, msg string, attrs ...any) {
	fullAttrs := []any{"error", err.Error()}

	if requestID := RequestIDFromContext(ctx); requestID != "" {
		fullAttrs = append(fullAttrs, "request_id", requestID)
	}

	if correlationID := CorrelationIDFromContext(ctx); correlationID != "" {
		fullAttrs = append(fullAttrs, "correlation_id", correlationID)
	}

	if sessionID := SessionIDFromContext(ctx); sessionID != "" {
		fullAttrs = append(fullAttrs, "session_id", sessionID)
	}

	if agentID := AgentIdentityFromContext(ctx); agentID != "" {
		fullAttrs = append(fullAttrs, "agent_identity_hash", agentID)
	}

	fullAttrs = append(fullAttrs, attrs...)
	logger.Error(msg, fullAttrs...)
}

// LogWarn logs a warning with full context
func LogWarn(logger *slog.Logger, ctx context.Context, msg string, attrs ...any) {
	fullAttrs := make([]any, 0, len(attrs)+8)

	if requestID := RequestIDFromContext(ctx); requestID != "" {
		fullAttrs = append(fullAttrs, "request_id", requestID)
	}

	if correlationID := CorrelationIDFromContext(ctx); correlationID != "" {
		fullAttrs = append(fullAttrs, "correlation_id", correlationID)
	}

	if sessionID := SessionIDFromContext(ctx); sessionID != "" {
		fullAttrs = append(fullAttrs, "session_id", sessionID)
	}

	if agentID := AgentIdentityFromContext(ctx); agentID != "" {
		fullAttrs = append(fullAttrs, "agent_identity_hash", agentID)
	}

	fullAttrs = append(fullAttrs, attrs...)
	logger.Warn(msg, fullAttrs...)
}

// LogInfo logs an info message with full context
func LogInfo(logger *slog.Logger, ctx context.Context, msg string, attrs ...any) {
	fullAttrs := make([]any, 0, len(attrs)+8)

	if requestID := RequestIDFromContext(ctx); requestID != "" {
		fullAttrs = append(fullAttrs, "request_id", requestID)
	}

	if correlationID := CorrelationIDFromContext(ctx); correlationID != "" {
		fullAttrs = append(fullAttrs, "correlation_id", correlationID)
	}

	if sessionID := SessionIDFromContext(ctx); sessionID != "" {
		fullAttrs = append(fullAttrs, "session_id", sessionID)
	}

	if agentID := AgentIdentityFromContext(ctx); agentID != "" {
		fullAttrs = append(fullAttrs, "agent_identity_hash", agentID)
	}

	fullAttrs = append(fullAttrs, attrs...)
	logger.Info(msg, fullAttrs...)
}

// LogDebug logs a debug message with full context
func LogDebug(logger *slog.Logger, ctx context.Context, msg string, attrs ...any) {
	fullAttrs := make([]any, 0, len(attrs)+8)

	if requestID := RequestIDFromContext(ctx); requestID != "" {
		fullAttrs = append(fullAttrs, "request_id", requestID)
	}

	if correlationID := CorrelationIDFromContext(ctx); correlationID != "" {
		fullAttrs = append(fullAttrs, "correlation_id", correlationID)
	}

	if sessionID := SessionIDFromContext(ctx); sessionID != "" {
		fullAttrs = append(fullAttrs, "session_id", sessionID)
	}

	if agentID := AgentIdentityFromContext(ctx); agentID != "" {
		fullAttrs = append(fullAttrs, "agent_identity_hash", agentID)
	}

	fullAttrs = append(fullAttrs, attrs...)
	logger.Debug(msg, fullAttrs...)
}
