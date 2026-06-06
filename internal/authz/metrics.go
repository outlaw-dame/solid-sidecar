package authz

import "sync"

const (
	ShadowMetricDecision         = "decision"
	ShadowMetricWarning          = "warning"
	ShadowMetricFallbackDecision = "fallback_decision"
	ShadowMetricFallbackFailure  = "fallback_failure"
)

type ShadowMetricEvent struct {
	Event       string
	Decision    DecisionValue
	ReasonCode  ReasonCode
	ErrorReason string
}

type ShadowMetricKey struct {
	Event       string
	Decision    string
	ReasonCode  string
	ErrorReason string
}

type ShadowMetricsSnapshot struct {
	Counters map[ShadowMetricKey]uint64
}

type ShadowMetricsRecorder interface {
	RecordShadowMetric(event ShadowMetricEvent)
}

type ShadowMetrics struct {
	mu       sync.RWMutex
	counters map[ShadowMetricKey]uint64
}

func NewShadowMetrics() *ShadowMetrics {
	return &ShadowMetrics{counters: make(map[ShadowMetricKey]uint64)}
}

func (m *ShadowMetrics) RecordShadowMetric(event ShadowMetricEvent) {
	if m == nil {
		return
	}
	key := ShadowMetricKey{
		Event:       event.Event,
		Decision:    string(event.Decision),
		ReasonCode:  string(event.ReasonCode),
		ErrorReason: event.ErrorReason,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counters == nil {
		m.counters = make(map[ShadowMetricKey]uint64)
	}
	m.counters[key]++
}

func (m *ShadowMetrics) Snapshot() ShadowMetricsSnapshot {
	if m == nil {
		return ShadowMetricsSnapshot{Counters: map[ShadowMetricKey]uint64{}}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	counters := make(map[ShadowMetricKey]uint64, len(m.counters))
	for key, value := range m.counters {
		counters[key] = value
	}
	return ShadowMetricsSnapshot{Counters: counters}
}

func recordShadowMetric(recorder ShadowMetricsRecorder, event ShadowMetricEvent) {
	if recorder != nil {
		recorder.RecordShadowMetric(event)
	}
}
