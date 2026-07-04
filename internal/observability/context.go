package observability

import "context"

// Context keys
type contextKey string

const (
	requestIDContextKey contextKey = "request_id"
	correlationIDKey    contextKey = "correlation_id"
	agentIdentityKey    contextKey = "agent_identity"
	sessionIDKey        contextKey = "session_id"
)

// Request ID context functions
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey, requestID)
}

func RequestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey).(string)
	return value
}

// Correlation ID context functions
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, correlationIDKey, correlationID)
}

func CorrelationIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(correlationIDKey).(string)
	return value
}

// Agent Identity context functions
func WithAgentIdentity(ctx context.Context, agentID string) context.Context {
	return context.WithValue(ctx, agentIdentityKey, agentID)
}

func AgentIdentityFromContext(ctx context.Context) string {
	value, _ := ctx.Value(agentIdentityKey).(string)
	return value
}

// Session ID context functions
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey, sessionID)
}

func SessionIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(sessionIDKey).(string)
	return value
}
