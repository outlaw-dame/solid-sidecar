// Package observability provides distributed tracing utilities for Solid Sidecar
package observability

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TracerProvider holds the OpenTelemetry tracer provider
type TracerProvider struct {
	provider *sdktrace.TracerProvider
	closed   bool
	mu       sync.Mutex
}

// globalTracer is the global tracer provider instance
var globalTracer *TracerProvider
var globalTracerOnce sync.Once

// InitTracer initializes the OpenTelemetry tracer provider with Jaeger exporter
func InitTracer(serviceName, endpoint string, sampleRate float64) (*TracerProvider, error) {
	globalTracerOnce.Do(func() {
		var err error
		globalTracer, err = newTracerProvider(serviceName, endpoint, sampleRate)
		if err != nil {
			globalTracer = nil
			return
		}
		otel.SetTracerProvider(globalTracer.provider)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
	})

	if globalTracer == nil {
		return nil, errors.New("failed to initialize tracer provider")
	}
	return globalTracer, nil
}

// newTracerProvider creates a new tracer provider
func newTracerProvider(serviceName, endpoint string, sampleRate float64) (*TracerProvider, error) {
	// Create Jaeger exporter
	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(endpoint)))
	if err != nil {
		return nil, err
	}

	// Create resource with service name
	resource, err := resource.New(context.Background(),
		resource.WithAttributes(
			// Service information
			attribute.String("service.name", serviceName),
			attribute.String("service.version", "1.0.0"),
			// Environment
			attribute.String("environment", "production"),
			// Additional identifiers
			attribute.String("telemetry.sdk.language", "go"),
			attribute.String("telemetry.sdk.name", "opentelemetry"),
		),
	)
	if err != nil {
		return nil, err
	}

	// Create sampler with configured sample rate
	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRate))

	// Create batch span processor
	batchProcessor := sdktrace.NewBatchSpanProcessor(exporter)

	// Create tracer provider
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(resource),
		sdktrace.WithSpanProcessor(batchProcessor),
	)

	return &TracerProvider{
		provider: provider,
		closed:   false,
	}, nil
}

// Tracer returns a tracer for the given name
func (tp *TracerProvider) Tracer(name string) trace.Tracer {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.provider.Tracer(name)
}

// Close shuts down the tracer provider
func (tp *TracerProvider) Close() error {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if tp.closed {
		return nil
	}
	tp.closed = true
	return tp.provider.Shutdown(context.Background())
}

// GlobalTracer returns the global tracer provider
func GlobalTracer() *TracerProvider {
	return globalTracer
}

// GetTracer returns a tracer from the global provider
func GetTracer(name string) trace.Tracer {
	if globalTracer != nil {
		return globalTracer.Tracer(name)
	}
	// Return a no-op tracer if not initialized
	return trace.NewNoopTracerProvider().Tracer(name)
}

// ShutdownTracer shuts down the global tracer provider
func ShutdownTracer() error {
	if globalTracer != nil {
		return globalTracer.Close()
	}
	return nil
}

// StartSpan starts a new span with the given name and options
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return GetTracer("solid-sidecar").Start(ctx, name, opts...)
}

// SpanAttributes defines common span attributes for Solid Sidecar operations
type SpanAttributes struct {
	Method        string
	Path          string
	StatusCode    int
	AuthZDecision string
	PolicyType    string
	TransportType string
	RequestID     string
	CorrelationID string
	SessionID     string
	AgentIdentity string
	Component     string
	Operation     string
}

// WithSpanAttributes returns span start options with the given attributes
func WithSpanAttributes(attrs SpanAttributes) []trace.SpanStartOption {
	options := []trace.SpanStartOption{}

	// Only add non-empty attributes
	if attrs.Method != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("http.method", attrs.Method),
		))
	}
	if attrs.Path != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("http.url", attrs.Path),
		))
	}
	if attrs.StatusCode != 0 {
		options = append(options, trace.WithAttributes(
			attribute.Int("http.status_code", attrs.StatusCode),
		))
	}
	if attrs.AuthZDecision != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("authz.decision", attrs.AuthZDecision),
		))
	}
	if attrs.PolicyType != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("policy.type", attrs.PolicyType),
		))
	}
	if attrs.TransportType != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("transport.type", attrs.TransportType),
		))
	}
	if attrs.RequestID != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("request.id", attrs.RequestID),
		))
	}
	if attrs.CorrelationID != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("correlation.id", attrs.CorrelationID),
		))
	}
	if attrs.SessionID != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("session.id", attrs.SessionID),
		))
	}
	if attrs.AgentIdentity != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("agent.identity.hash", attrs.AgentIdentity),
		))
	}
	if attrs.Component != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("component", attrs.Component),
		))
	}
	if attrs.Operation != "" {
		options = append(options, trace.WithAttributes(
			attribute.String("operation", attrs.Operation),
		))
	}

	return options
}

// WithContextAttributes returns span start options with attributes from context
func WithContextAttributes(ctx context.Context) []trace.SpanStartOption {
	attrs := SpanAttributes{}

	if requestID := RequestIDFromContext(ctx); requestID != "" {
		attrs.RequestID = requestID
	}
	if correlationID := CorrelationIDFromContext(ctx); correlationID != "" {
		attrs.CorrelationID = correlationID
	}
	if sessionID := SessionIDFromContext(ctx); sessionID != "" {
		attrs.SessionID = sessionID
	}
	if agentID := AgentIdentityFromContext(ctx); agentID != "" {
		attrs.AgentIdentity = agentID
	}

	return WithSpanAttributes(attrs)
}

// EndSpanWithError ends a span with error status if err is not nil
func EndSpanWithError(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "success")
	}
	span.End()
}

// EndSpanWithStatus ends a span with the specified status code
func EndSpanWithStatus(span trace.Span, statusCode int, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else if statusCode >= 500 {
		span.SetStatus(codes.Error, "server error")
	} else if statusCode >= 400 {
		span.SetStatus(codes.Error, "client error")
	} else {
		span.SetStatus(codes.Ok, "success")
	}
	span.End()
}

// RecordSpanError records an error on a span
func RecordSpanError(span trace.Span, err error) {
	if err != nil && span != nil {
		span.RecordError(err)
	}
}

// SetSpanAttribute sets an attribute on a span
func SetSpanAttribute(span trace.Span, key string, value any) {
	if span == nil {
		return
	}
	// Convert value to string for generic attribute setting
	var attr attribute.KeyValue
	switch v := value.(type) {
	case string:
		attr = attribute.String(key, v)
	case int:
		attr = attribute.Int(key, v)
	case int64:
		attr = attribute.Int64(key, v)
	case float64:
		attr = attribute.Float64(key, v)
	case bool:
		attr = attribute.Bool(key, v)
	default:
		attr = attribute.String(key, fmt.Sprintf("%v", v))
	}
	span.SetAttributes(attr)
}

// TraceHTTPRequest traces an HTTP request with full context
func TraceHTTPRequest(ctx context.Context, method, path string, handler func() (int, error)) (int, error) {
	_, span := StartSpan(ctx, "http.request", WithContextAttributes(ctx)...)
	defer span.End()

	SetSpanAttribute(span, "http.method", method)
	SetSpanAttribute(span, "http.url", path)

	statusCode, err := handler()

	SetSpanAttribute(span, "http.status_code", statusCode)
	EndSpanWithStatus(span, statusCode, err)

	return statusCode, err
}

// TraceFunction traces a function execution with error handling
func TraceFunction(ctx context.Context, component, operation string, handler func() error) error {
	_, span := StartSpan(ctx, operation,
		trace.WithAttributes(
			attribute.String("component", component),
			attribute.String("operation", operation),
		))
	defer span.End()

	err := handler()
	EndSpanWithError(span, err)

	return err
}

// TraceWithResult traces a function with result value and error
func TraceWithResult[T any](ctx context.Context, component, operation string, handler func() (T, error)) (T, error) {
	_, span := StartSpan(ctx, operation,
		trace.WithAttributes(
			attribute.String("component", component),
			attribute.String("operation", operation),
		))
	defer span.End()

	result, err := handler()
	EndSpanWithError(span, err)

	return result, err
}

// HealthCheckTracer provides tracing for health checks
type HealthCheckTracer struct {
	tracer trace.Tracer
}

func NewHealthCheckTracer() *HealthCheckTracer {
	return &HealthCheckTracer{
		tracer: GetTracer("health"),
	}
}

func (h *HealthCheckTracer) TraceLiveness(ctx context.Context, handler func() error) error {
	ctx, span := h.tracer.Start(ctx, "health.liveness")
	defer span.End()

	err := handler()
	EndSpanWithError(span, err)
	return err
}

func (h *HealthCheckTracer) TraceReadiness(ctx context.Context, handler func() error) error {
	ctx, span := h.tracer.Start(ctx, "health.readiness")
	defer span.End()

	err := handler()
	EndSpanWithError(span, err)
	return err
}

func (h *HealthCheckTracer) TraceStartup(ctx context.Context, handler func() error) error {
	ctx, span := h.tracer.Start(ctx, "health.startup")
	defer span.End()

	err := handler()
	EndSpanWithError(span, err)
	return err
}

// AuthZTracer provides tracing for authorization operations
type AuthZTracer struct {
	tracer trace.Tracer
}

func NewAuthZTracer() *AuthZTracer {
	return &AuthZTracer{
		tracer: GetTracer("authz"),
	}
}

func (a *AuthZTracer) TracePolicyEvaluation(ctx context.Context, policyType string, handler func() (string, error)) (string, error) {
	_, span := a.tracer.Start(ctx, "policy.evaluate",
		trace.WithAttributes(
			attribute.String("policy.type", policyType),
		))
	defer span.End()

	decision, err := handler()

	if err != nil {
		RecordSpanError(span, err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		SetSpanAttribute(span, "authz.decision", decision)
		span.SetStatus(codes.Ok, "success")
	}

	return decision, err
}

func (a *AuthZTracer) TracePolicyDiscovery(ctx context.Context, resourceURI string, handler func() error) error {
	_, span := a.tracer.Start(ctx, "policy.discover",
		trace.WithAttributes(
			attribute.String("resource.uri", resourceURI),
		))
	defer span.End()

	err := handler()
	EndSpanWithError(span, err)
	return err
}

// TransportTracer provides tracing for fixture distribution transport operations
type TransportTracer struct {
	tracer trace.Tracer
}

func NewTransportTracer() *TransportTracer {
	return &TransportTracer{
		tracer: GetTracer("transport"),
	}
}

func (t *TransportTracer) TraceFixtureSync(ctx context.Context, transportType, operation string, handler func() error) error {
	_, span := t.tracer.Start(ctx, "fixture.sync",
		trace.WithAttributes(
			attribute.String("transport.type", transportType),
			attribute.String("operation", operation),
		))
	defer span.End()

	err := handler()
	EndSpanWithError(span, err)
	return err
}

func (t *TransportTracer) TraceTransportRequest(ctx context.Context, transportType, operation string, handler func() ([]byte, error)) ([]byte, error) {
	_, span := t.tracer.Start(ctx, "transport.request",
		trace.WithAttributes(
			attribute.String("transport.type", transportType),
			attribute.String("operation", operation),
		))
	defer span.End()

	result, err := handler()

	if err != nil {
		RecordSpanError(span, err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		SetSpanAttribute(span, "result.size", len(result))
		span.SetStatus(codes.Ok, "success")
	}

	return result, err
}

// IsTracingEnabled returns true if tracing is enabled
func IsTracingEnabled() bool {
	return globalTracer != nil && !globalTracer.closed
}
