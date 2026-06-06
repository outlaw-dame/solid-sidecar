package authz

import "testing"

func TestShadowMetricKeyUsesOnlyAggregateDimensions(t *testing.T) {
	key := ShadowMetricKey{
		Event:       ShadowMetricWarning,
		Decision:    string(DecisionAbstain),
		ReasonCode:  string(ReasonKernelAbstainShadowMode),
		ErrorReason: ShadowErrorReasonBackoffActive,
	}

	metrics := NewShadowMetrics()
	metrics.RecordShadowMetric(ShadowMetricEvent{
		Event:       ShadowMetricWarning,
		Decision:    DecisionAbstain,
		ReasonCode:  ReasonKernelAbstainShadowMode,
		ErrorReason: ShadowErrorReasonBackoffActive,
	})

	if got := metrics.Snapshot().Counters[key]; got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}
}

func TestBackoffActiveMetricReasonIsStable(t *testing.T) {
	if ShadowErrorReasonBackoffActive != "backoff_active" {
		t.Fatalf("backoff reason = %q", ShadowErrorReasonBackoffActive)
	}
}
