package authz

import (
	"sync"
	"testing"
)

func TestShadowMetricsSnapshotIsCopy(t *testing.T) {
	metrics := NewShadowMetrics()
	key := ShadowMetricKey{Event: ShadowMetricDecision, Decision: string(DecisionAbstain), ReasonCode: string(ReasonKernelAbstainShadowMode)}
	metrics.RecordShadowMetric(ShadowMetricEvent{Event: ShadowMetricDecision, Decision: DecisionAbstain, ReasonCode: ReasonKernelAbstainShadowMode})

	snapshot := metrics.Snapshot()
	if snapshot.Counters[key] != 1 {
		t.Fatalf("counter = %d, want 1", snapshot.Counters[key])
	}
	snapshot.Counters[key] = 99
	fresh := metrics.Snapshot()
	if fresh.Counters[key] != 1 {
		t.Fatalf("mutating snapshot changed metrics: got %d", fresh.Counters[key])
	}
}

func TestShadowMetricsConcurrentRecord(t *testing.T) {
	metrics := NewShadowMetrics()
	const workers = 16
	const perWorker = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				metrics.RecordShadowMetric(ShadowMetricEvent{Event: ShadowMetricWarning, ErrorReason: ShadowErrorReasonEvaluationFailed})
			}
		}()
	}
	wg.Wait()

	key := ShadowMetricKey{Event: ShadowMetricWarning, ErrorReason: ShadowErrorReasonEvaluationFailed}
	if got := metrics.Snapshot().Counters[key]; got != workers*perWorker {
		t.Fatalf("counter = %d, want %d", got, workers*perWorker)
	}
}

func TestNilShadowMetricsSnapshot(t *testing.T) {
	var metrics *ShadowMetrics
	if len(metrics.Snapshot().Counters) != 0 {
		t.Fatal("nil metrics snapshot should be empty")
	}
}
