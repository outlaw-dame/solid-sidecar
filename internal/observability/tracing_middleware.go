// Package observability provides distributed tracing middleware for Solid Sidecar
// This implements Phase 39.3: Distributed tracing across all components
package observability

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// TracingMiddleware wraps an HTTP handler with distributed tracing
func TracingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Start a new span for this request
		ctx, span := StartSpan(r.Context(), "http.request",
			trace.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.url", sanitizeURLForTracing(r.URL.String())),
				attribute.String("http.host", r.Host),
				attribute.String("http.remote_addr", r.RemoteAddr),
				attribute.String("http.user_agent", r.UserAgent()),
			))
		defer span.End()

		// Add request ID to span if available
		if requestID := RequestIDFromContext(r.Context()); requestID != "" {
			span.SetAttributes(attribute.String("request.id", requestID))
		}

		// Add correlation ID to span if available
		if correlationID := CorrelationIDFromContext(r.Context()); correlationID != "" {
			span.SetAttributes(attribute.String("correlation.id", correlationID))
		}

		// Add session ID to span if available
		if sessionID := SessionIDFromContext(r.Context()); sessionID != "" {
			span.SetAttributes(attribute.String("session.id", sessionID))
		}

		// Add agent identity hash to span if available (privacy-safe)
		if agentID := AgentIdentityFromContext(r.Context()); agentID != "" {
			span.SetAttributes(attribute.String("agent.identity.hash", HashWebID(agentID)))
		}

		// Create a wrapped response writer to capture status code
		wrapped := &tracingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			span:           span,
			startTime:      time.Now(),
		}

		// Serve the request
		next.ServeHTTP(wrapped, r.WithContext(ctx))

		// Update span with response information
		wrapped.finalize()
	})
}

// sanitizeURLForTracing removes sensitive information from URLs for tracing
func sanitizeURLForTracing(urlStr string) string {
	if !globalPrivacyConfig.Enabled {
		return urlStr
	}

	// Sanitize the URL to remove query parameters that might contain sensitive data
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	// Remove query parameters for privacy
	parsed.RawQuery = ""
	return parsed.String()
}

// tracingResponseWriter wraps http.ResponseWriter to capture status code and other response data
// This implements Phase 39.3: Distributed tracing with comprehensive response tracking
type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	span         trace.Span
	startTime    time.Time
	bytesWritten int64
}

func (w *tracingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)

	// Record status code in span immediately
	w.span.SetAttributes(attribute.Int("http.status_code", statusCode))

	// Set span status based on status code
	if statusCode >= 500 {
		w.span.SetStatus(codes.Error, "server error")
	} else if statusCode >= 400 {
		w.span.SetStatus(codes.Error, "client error")
	} else {
		w.span.SetStatus(codes.Ok, "success")
	}
}

func (w *tracingResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == http.StatusOK {
		// If no status code set yet, default to 200
		w.statusCode = http.StatusOK
		w.span.SetAttributes(attribute.Int("http.status_code", http.StatusOK))
		w.span.SetStatus(codes.Ok, "success")
	}

	n, err := w.ResponseWriter.Write(b)
	if err != nil {
		RecordSpanError(w.span, err)
		w.span.SetStatus(codes.Error, err.Error())
	}
	w.bytesWritten += int64(n)
	return n, err
}

func (w *tracingResponseWriter) finalize() {
	// Record the total duration
	duration := time.Since(w.startTime)
	w.span.SetAttributes(attribute.Float64("http.duration_seconds", duration.Seconds()))

	// Record bytes written
	if w.bytesWritten > 0 {
		w.span.SetAttributes(attribute.Int64("http.response_bytes", w.bytesWritten))
	}

	// Ensure status code is recorded (in case Write was called without WriteHeader)
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
		w.span.SetAttributes(attribute.Int("http.status_code", http.StatusOK))
		w.span.SetStatus(codes.Ok, "success")
	}
}

// AuthZTracingMiddleware adds authorization-specific tracing to the middleware
// This implements Phase 39.3: Authorization-specific distributed tracing
func AuthZTracingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := StartSpan(r.Context(), "authz.evaluation",
			trace.WithAttributes(
				attribute.String("component", "authz"),
				attribute.String("operation", "evaluate"),
			))
		defer span.End()

		// Add context attributes
		if requestID := RequestIDFromContext(ctx); requestID != "" {
			span.SetAttributes(attribute.String("request.id", requestID))
		}
		if correlationID := CorrelationIDFromContext(ctx); correlationID != "" {
			span.SetAttributes(attribute.String("correlation.id", correlationID))
		}

		// Create response writer
		wrapped := &authZTracingResponseWriter{
			ResponseWriter: w,
			span:           span,
		}

		next.ServeHTTP(wrapped, r.WithContext(ctx))
	})
}

// authZTracingResponseWriter wraps response writer for authz-specific tracing
type authZTracingResponseWriter struct {
	http.ResponseWriter
	span trace.Span
}

func (w *authZTracingResponseWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
	w.span.SetAttributes(attribute.Int("http.status_code", statusCode))
}

// PolicyDecisionTracing traces a policy decision evaluation
// This implements Phase 39.3: Policy decision tracing with context
func PolicyDecisionTracing(ctx context.Context, policyType string, decisionFunc func() (string, error)) (string, error) {
	_, span := StartSpan(ctx, "policy.decision",
		trace.WithAttributes(
			attribute.String("policy.type", policyType),
			attribute.String("component", "authz"),
			attribute.String("operation", "policy.decision"),
		))
	defer span.End()

	decision, err := decisionFunc()
	if err != nil {
		RecordSpanError(span, err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.String("authz.decision", "error"))
	} else {
		span.SetStatus(codes.Ok, "success")
		span.SetAttributes(attribute.String("authz.decision", decision))
	}

	return decision, err
}

// TransportTracing traces transport-level operations
// This implements Phase 39.3: Transport-level distributed tracing
func TransportTracing(ctx context.Context, transportType, operation string, handler func() error) error {
	_, span := StartSpan(ctx, "transport."+operation,
		trace.WithAttributes(
			attribute.String("transport.type", transportType),
			attribute.String("operation", operation),
			attribute.String("component", "transport"),
		))
	defer span.End()

	err := handler()
	if err != nil {
		RecordSpanError(span, err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "success")
	}

	return err
}

// ReverseProxyTracing traces reverse proxy operations
// This implements Phase 39.3: Reverse proxy distributed tracing
func ReverseProxyTracing(ctx context.Context, method, path string, handler func() (*http.Response, error)) (*http.Response, error) {
	_, span := StartSpan(ctx, "proxy.request",
		trace.WithAttributes(
			attribute.String("http.method", method),
			attribute.String("http.url", sanitizeURLForTracing(path)),
			attribute.String("component", "proxy"),
			attribute.String("operation", "forward"),
		))
	defer span.End()

	resp, err := handler()
	if err != nil {
		RecordSpanError(span, err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Record response status code
	if resp != nil {
		span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
		span.SetStatus(codes.Ok, "success")
	}

	return resp, err
}

// InitializeTracingExporter initializes OpenTelemetry tracing with configurable exporter
// This implements Phase 39.3: Full OpenTelemetry integration with exporter support
func InitializeTracingExporter(serviceName, endpoint string, sampleRate float64) (*TracerProvider, error) {
	return InitTracer(serviceName, endpoint, sampleRate)
}

// IsTracingConfigured returns true if tracing is configured and enabled
func IsTracingConfigured() bool {
	return globalTracer != nil && !globalTracer.closed
}
