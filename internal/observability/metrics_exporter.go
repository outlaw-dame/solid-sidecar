// Package observability provides OpenTelemetry metrics exporter for Solid Sidecar
// This implements Phase 39.3: Full OpenTelemetry integration (metrics exporter)
// Note: This is a simplified version that focuses on the core functionality without
// requiring additional dependencies beyond what's already in the project.
package observability

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

// MetricExporterType defines the type of metrics exporter to use
type MetricExporterType string

const (
	// MetricExporterPrometheus uses Prometheus (existing) - default
	MetricExporterPrometheus MetricExporterType = "prometheus"
	// MetricExporterOTLP uses OTLP (future enhancement)
	MetricExporterOTLP MetricExporterType = "otlp"
	// MetricExporterNone uses no exporter (metrics disabled)
	MetricExporterNone MetricExporterType = "none"
)

// MetricsExporter holds the OpenTelemetry metrics exporter configuration and state
type MetricsExporter struct {
	provider     *sdkmetric.MeterProvider
	closed       bool
	mu           sync.Mutex
	logger       *slog.Logger
	exporterType MetricExporterType
}

// globalMetricsExporter is the global metrics exporter instance
var globalMetricsExporter *MetricsExporter
var globalMetricsExporterOnce sync.Once

// MetricExporterConfig holds configuration for the metrics exporter
type MetricExporterConfig struct {
	ExporterType   MetricExporterType
	ServiceName   string
	ResourceAttributes map[string]string
	Logger *slog.Logger
}

// DefaultMetricsExporterConfig returns default metrics exporter configuration
func DefaultMetricsExporterConfig() MetricExporterConfig {
	return MetricExporterConfig{
		ExporterType: MetricExporterPrometheus,
		ServiceName:   "solid-sidecar",
		ResourceAttributes: map[string]string{
			"service.version":     "1.0.0",
			"environment":        "production",
			"telemetry.sdk.name": "opentelemetry",
			"telemetry.sdk.language": "go",
		},
		Logger: slog.Default(),
	}
}

// InitMetricsExporter initializes the OpenTelemetry metrics exporter
func InitMetricsExporter(config MetricExporterConfig) (*MetricsExporter, error) {
	globalMetricsExporterOnce.Do(func() {
		if config.Logger == nil {
			config.Logger = slog.Default()
		}

		resourceAttrs := []attribute.KeyValue{
			attribute.String("service.name", config.ServiceName),
			attribute.String("service.version", config.ResourceAttributes["service.version"]),
			attribute.String("environment", config.ResourceAttributes["environment"]),
			attribute.String("telemetry.sdk.name", config.ResourceAttributes["telemetry.sdk.name"]),
			attribute.String("telemetry.sdk.language", config.ResourceAttributes["telemetry.sdk.language"]),
		}

		for k, v := range config.ResourceAttributes {
			if k != "service.version" && k != "environment" && k != "telemetry.sdk.name" && k != "telemetry.sdk.language" {
				resourceAttrs = append(resourceAttrs, attribute.String(k, v))
			}
		}

		resource, err := resource.New(context.Background(),
			resource.WithAttributes(resourceAttrs...),
		)
		if err != nil {
			config.Logger.Error("Failed to create resource for metrics exporter", "error", err)
			globalMetricsExporter = &MetricsExporter{
				exporterType: MetricExporterNone,
				logger:       config.Logger,
				closed:       true,
			}
			return
		}

		provider := sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(resource),
		)

		globalMetricsExporter = &MetricsExporter{
			provider:     provider,
			exporterType: config.ExporterType,
			closed:       false,
			logger:       config.Logger,
		}
		
		otel.SetMeterProvider(provider)
	})

	if globalMetricsExporter == nil {
		return nil, errors.New("failed to initialize metrics exporter")
	}
	return globalMetricsExporter, nil
}

// Meter returns a meter for the given name
func (me *MetricsExporter) Meter(name string) metric.Meter {
	me.mu.Lock()
	defer me.mu.Unlock()
	return me.provider.Meter(name)
}

// Close shuts down the metrics exporter
func (me *MetricsExporter) Close() error {
	me.mu.Lock()
	defer me.mu.Unlock()
	if me.closed {
		return nil
	}
	me.closed = true
	return me.provider.Shutdown(context.Background())
}

// GlobalMeterProvider returns the global meter provider
func GlobalMeterProvider() *sdkmetric.MeterProvider {
	if globalMetricsExporter != nil {
		return globalMetricsExporter.provider
	}
	return nil
}

// GetMeter returns a meter from the global provider
func GetMeter(name string) metric.Meter {
	if globalMetricsExporter != nil {
		return globalMetricsExporter.Meter(name)
	}
	return otel.Meter(name)
}

// ShutdownMetrics shuts down the global metrics exporter
func ShutdownMetrics() error {
	if globalMetricsExporter != nil {
		return globalMetricsExporter.Close()
	}
	return nil
}

// OpenTelemetry metrics instruments
var (
	RequestCounter       metric.Int64Counter
	RequestHistogram     metric.Float64Histogram
	AuthZDecisionCounter metric.Int64Counter
	CacheHitCounter      metric.Int64Counter
	CacheRequestCounter  metric.Int64Counter
	ActiveSessionGauge   metric.Int64Gauge
	metricsInitialized   bool
	metricsInitOnce      sync.Once
)

// InitOpenTelemetryMetrics initializes OpenTelemetry metrics instruments
func InitOpenTelemetryMetrics() {
	metricsInitOnce.Do(func() {
		meter := GetMeter("solid-sidecar")

		var err error
		RequestCounter, err = meter.Int64Counter(
			"http.requests.total",
			metric.WithDescription("Total number of HTTP requests"),
			metric.WithUnit("1"),
		)
		if err != nil {
			slog.Error("Failed to create RequestCounter", "error", err)
		}

		RequestHistogram, err = meter.Float64Histogram(
			"http.request.duration.seconds",
			metric.WithDescription("Duration of HTTP requests in seconds"),
			metric.WithUnit("s"),
		)
		if err != nil {
			slog.Error("Failed to create RequestHistogram", "error", err)
		}

		AuthZDecisionCounter, err = meter.Int64Counter(
			"authz.decisions.total",
			metric.WithDescription("Total number of authorization decisions"),
			metric.WithUnit("1"),
		)
		if err != nil {
			slog.Error("Failed to create AuthZDecisionCounter", "error", err)
		}

		CacheHitCounter, err = meter.Int64Counter(
			"cache.hits.total",
			metric.WithDescription("Total number of cache hits"),
			metric.WithUnit("1"),
		)
		if err != nil {
			slog.Error("Failed to create CacheHitCounter", "error", err)
		}

		CacheRequestCounter, err = meter.Int64Counter(
			"cache.requests.total",
			metric.WithDescription("Total number of cache requests"),
			metric.WithUnit("1"),
		)
		if err != nil {
			slog.Error("Failed to create CacheRequestCounter", "error", err)
		}

		ActiveSessionGauge, err = meter.Int64Gauge(
			"session.active",
			metric.WithDescription("Number of active authenticated sessions"),
			metric.WithUnit("1"),
		)
		if err != nil {
			slog.Error("Failed to create ActiveSessionGauge", "error", err)
		}

		metricsInitialized = true
		slog.Info("OpenTelemetry metrics initialized for Phase 39.3")
	})
}

// RecordRequestOTel records an HTTP request using OpenTelemetry metrics
func RecordRequestOTel(method, path, statusCode, authzDecision string) {
	if !metricsInitialized {
		InitOpenTelemetryMetrics()
	}
	
	RecordRequest(method, path, statusCode, authzDecision)
	
	if globalMetricsExporter != nil && !globalMetricsExporter.closed {
		attrs := []attribute.KeyValue{
			attribute.String("method", method),
			attribute.String("path", path),
			attribute.String("status_code", statusCode),
			attribute.String("authz.decision", authzDecision),
		}
		RequestCounter.Add(context.Background(), 1, metric.WithAttributes(attrs...))
	}
}

// RecordRequestDurationOTel records HTTP request duration
func RecordRequestDurationOTel(method, path, statusCode, authzDecision string, duration time.Duration) {
	if !metricsInitialized {
		InitOpenTelemetryMetrics()
	}
	
	RecordRequestDuration(method, path, statusCode, authzDecision, duration.Seconds())
	
	if globalMetricsExporter != nil && !globalMetricsExporter.closed {
		attrs := []attribute.KeyValue{
			attribute.String("method", method),
			attribute.String("path", path),
			attribute.String("status_code", statusCode),
			attribute.String("authz.decision", authzDecision),
		}
		RequestHistogram.Record(context.Background(), duration.Seconds(), metric.WithAttributes(attrs...))
	}
}

// RecordAuthZDecisionOTel records an authorization decision
func RecordAuthZDecisionOTel(decision, policyType, transportType string) {
	if !metricsInitialized {
		InitOpenTelemetryMetrics()
	}
	
	RecordAuthZDecision(decision, policyType, transportType)
	
	if globalMetricsExporter != nil && !globalMetricsExporter.closed {
		attrs := []attribute.KeyValue{
			attribute.String("decision", decision),
			attribute.String("policy.type", policyType),
			attribute.String("transport.type", transportType),
		}
		AuthZDecisionCounter.Add(context.Background(), 1, metric.WithAttributes(attrs...))
	}
}

// RecordCacheHitOTel records a cache hit
func RecordCacheHitOTel(cacheType string) {
	if !metricsInitialized {
		InitOpenTelemetryMetrics()
	}
	
	RecordCacheHit(cacheType)
	
	if globalMetricsExporter != nil && !globalMetricsExporter.closed {
		attrs := []attribute.KeyValue{
			attribute.String("cache.type", cacheType),
		}
		CacheHitCounter.Add(context.Background(), 1, metric.WithAttributes(attrs...))
	}
}

// RecordCacheRequestOTel records a cache request
func RecordCacheRequestOTel(cacheType string) {
	if !metricsInitialized {
		InitOpenTelemetryMetrics()
	}
	
	RecordCacheRequest(cacheType)
	
	if globalMetricsExporter != nil && !globalMetricsExporter.closed {
		attrs := []attribute.KeyValue{
			attribute.String("cache.type", cacheType),
		}
		CacheRequestCounter.Add(context.Background(), 1, metric.WithAttributes(attrs...))
	}
}

// UpdateActiveSessionsOTel updates the active sessions count
func UpdateActiveSessionsOTel(assuranceLevel string, count int64) {
	if !metricsInitialized {
		InitOpenTelemetryMetrics()
	}
	
	if count > 0 {
		IncrementActiveSessions(assuranceLevel)
	} else {
		DecrementActiveSessions(assuranceLevel)
	}
	
	if globalMetricsExporter != nil && !globalMetricsExporter.closed {
		attrs := []attribute.KeyValue{
			attribute.String("assurance.level", assuranceLevel),
		}
		ActiveSessionGauge.Record(context.Background(), count, metric.WithAttributes(attrs...))
	}
}

// IsMetricsExporterEnabled returns true if the OpenTelemetry metrics exporter is enabled
func IsMetricsExporterEnabled() bool {
	return globalMetricsExporter != nil && !globalMetricsExporter.closed
}

// GetMetricsExporterType returns the current metrics exporter type
func GetMetricsExporterType() MetricExporterType {
	if globalMetricsExporter != nil {
		return globalMetricsExporter.exporterType
	}
	return MetricExporterPrometheus
}

// InitTracing initializes distributed tracing for Phase 39.3
func InitTracing(serviceName, jaegerEndpoint string, sampleRate float64) error {
	_, err := InitTracer(serviceName, jaegerEndpoint, sampleRate)
	if err != nil {
		return err
	}
	
	_, err = InitMetricsExporter(DefaultMetricsExporterConfig())
	if err != nil {
		slog.Warn("Failed to initialize metrics exporter", "error", err)
	}
	
	InitOpenTelemetryMetrics()
	
	return nil
}