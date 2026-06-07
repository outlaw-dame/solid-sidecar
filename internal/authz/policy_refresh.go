package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

var ErrInvalidPolicyRefresh = errors.New("invalid authz policy refresh input")

type PolicyRefreshAction string

const (
	PolicyRefreshNow   PolicyRefreshAction = "refresh_now"
	PolicyRefreshLater PolicyRefreshAction = "refresh_later"
	PolicyRefreshSkip  PolicyRefreshAction = "skip"
)

type PolicyRefreshReason string

const (
	PolicyRefreshReasonMissing   PolicyRefreshReason = "missing"
	PolicyRefreshReasonExpired   PolicyRefreshReason = "expired"
	PolicyRefreshReasonStale     PolicyRefreshReason = "stale"
	PolicyRefreshReasonFresh     PolicyRefreshReason = "fresh"
	PolicyRefreshReasonNoSource  PolicyRefreshReason = "no_source"
)

type PolicyCacheStore interface {
	GetPolicyCacheRecord(ctx context.Context, source PolicySource) (PolicySourceCacheRecord, bool, error)
	PutPolicyCacheRecord(ctx context.Context, record PolicySourceCacheRecord) error
	ListPolicyCacheRecords(ctx context.Context) ([]PolicySourceCacheRecord, error)
}

type InMemoryPolicyCacheStore struct {
	mu      sync.RWMutex
	records map[string]PolicySourceCacheRecord
	nowUnix int64
}

func NewInMemoryPolicyCacheStore(records []PolicySourceCacheRecord, nowUnix int64) (*InMemoryPolicyCacheStore, error) {
	store := &InMemoryPolicyCacheStore{records: make(map[string]PolicySourceCacheRecord), nowUnix: nowUnix}
	normalized, err := NormalizePolicyCacheRecords(records, nowUnix)
	if err != nil {
		return nil, err
	}
	for _, record := range normalized {
		store.records[record.CacheKey] = record
	}
	return store, nil
}

func (s *InMemoryPolicyCacheStore) GetPolicyCacheRecord(ctx context.Context, source PolicySource) (PolicySourceCacheRecord, bool, error) {
	if s == nil {
		return PolicySourceCacheRecord{}, false, fmt.Errorf("%w: nil policy cache store", ErrInvalidPolicyRefresh)
	}
	if err := ctx.Err(); err != nil {
		return PolicySourceCacheRecord{}, false, err
	}
	key := PolicySourceCacheKey(source)
	if key == "" {
		return PolicySourceCacheRecord{}, false, ErrInvalidPolicySource
	}
	s.mu.RLock()
	record, ok := s.records[key]
	s.mu.RUnlock()
	if !ok {
		return PolicySourceCacheRecord{}, false, nil
	}
	normalized, err := normalizePolicyCacheRecord(record, s.nowUnix)
	if err != nil {
		return PolicySourceCacheRecord{}, false, err
	}
	return normalized, true, nil
}

func (s *InMemoryPolicyCacheStore) PutPolicyCacheRecord(ctx context.Context, record PolicySourceCacheRecord) error {
	if s == nil {
		return fmt.Errorf("%w: nil policy cache store", ErrInvalidPolicyRefresh)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	normalized, err := normalizePolicyCacheRecord(record, s.nowUnix)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]PolicySourceCacheRecord)
	}
	s.records[normalized.CacheKey] = normalized
	return nil
}

func (s *InMemoryPolicyCacheStore) ListPolicyCacheRecords(ctx context.Context) ([]PolicySourceCacheRecord, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil policy cache store", ErrInvalidPolicyRefresh)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	records := make([]PolicySourceCacheRecord, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, record)
	}
	s.mu.RUnlock()
	return NormalizePolicyCacheRecords(records, s.nowUnix)
}

type PolicyRefreshPlanOptions struct {
	Sources          []PolicySource
	Records          []PolicySourceCacheRecord
	NowUnix          int64
	RefreshWindowSec int64
}

type PolicyRefreshPlan struct {
	PlanVersion string              `json:"plan_version"`
	CreatedAt   int64               `json:"created_at_unix"`
	Items       []PolicyRefreshItem `json:"items"`
}

type PolicyRefreshItem struct {
	Source       PolicySource        `json:"source"`
	CacheKey     string              `json:"cache_key"`
	Action       PolicyRefreshAction `json:"action"`
	Reason       PolicyRefreshReason `json:"reason"`
	NextCheckAt  int64               `json:"next_check_at_unix,omitempty"`
	RecordState  PolicyCacheState    `json:"record_state,omitempty"`
	RecordVersion string             `json:"record_version,omitempty"`
}

func BuildPolicyRefreshPlan(options PolicyRefreshPlanOptions) (PolicyRefreshPlan, error) {
	if options.NowUnix < 0 || options.RefreshWindowSec < 0 {
		return PolicyRefreshPlan{}, fmt.Errorf("%w: negative refresh timing", ErrInvalidPolicyRefresh)
	}
	sources, err := NormalizePolicySources(options.Sources)
	if err != nil {
		return PolicyRefreshPlan{}, err
	}
	records, err := NormalizePolicyCacheRecords(options.Records, options.NowUnix)
	if err != nil {
		return PolicyRefreshPlan{}, err
	}
	recordsByKey := make(map[string]PolicySourceCacheRecord, len(records))
	for _, record := range records {
		recordsByKey[record.CacheKey] = record
	}

	items := make([]PolicyRefreshItem, 0, len(sources))
	for _, source := range sources {
		key := PolicySourceCacheKey(source)
		if key == "" {
			return PolicyRefreshPlan{}, fmt.Errorf("%w: invalid policy source cache key", ErrInvalidPolicyRefresh)
		}
		record, ok := recordsByKey[key]
		item := PolicyRefreshItem{Source: source, CacheKey: key}
		if !ok {
			item.Action = PolicyRefreshNow
			item.Reason = PolicyRefreshReasonMissing
			item.NextCheckAt = options.NowUnix
			items = append(items, item)
			continue
		}
		item.RecordState = record.State
		item.RecordVersion = record.Version
		switch record.State {
		case PolicyCacheExpired:
			item.Action = PolicyRefreshNow
			item.Reason = PolicyRefreshReasonExpired
			item.NextCheckAt = options.NowUnix
		case PolicyCacheStale:
			item.Action = PolicyRefreshNow
			item.Reason = PolicyRefreshReasonStale
			item.NextCheckAt = options.NowUnix
		default:
			if record.ExpiresAtUnix > 0 && record.ExpiresAtUnix-options.NowUnix <= options.RefreshWindowSec {
				item.Action = PolicyRefreshLater
				item.Reason = PolicyRefreshReasonFresh
				item.NextCheckAt = record.ExpiresAtUnix
			} else {
				item.Action = PolicyRefreshSkip
				item.Reason = PolicyRefreshReasonFresh
				item.NextCheckAt = nextCheckForRecord(record, options.NowUnix)
			}
		}
		items = append(items, item)
	}
	sortPolicyRefreshItems(items)
	return PolicyRefreshPlan{PlanVersion: PolicyRefreshPlanVersion(items, options.NowUnix), CreatedAt: options.NowUnix, Items: items}, nil
}

func nextCheckForRecord(record PolicySourceCacheRecord, nowUnix int64) int64 {
	if record.ExpiresAtUnix > 0 {
		return record.ExpiresAtUnix
	}
	if nowUnix > 0 {
		return nowUnix
	}
	return 0
}

func sortPolicyRefreshItems(items []PolicyRefreshItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Action != items[j].Action {
			return refreshActionRank(items[i].Action) < refreshActionRank(items[j].Action)
		}
		if items[i].NextCheckAt != items[j].NextCheckAt {
			return items[i].NextCheckAt < items[j].NextCheckAt
		}
		return items[i].CacheKey < items[j].CacheKey
	})
}

func refreshActionRank(action PolicyRefreshAction) int {
	switch action {
	case PolicyRefreshNow:
		return 0
	case PolicyRefreshLater:
		return 1
	case PolicyRefreshSkip:
		return 2
	default:
		return 3
	}
}

func PolicyRefreshPlanVersion(items []PolicyRefreshItem, createdAt int64) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%020d", createdAt))
	builder.WriteByte('\x1e')
	for _, item := range items {
		builder.WriteString(item.CacheKey)
		builder.WriteByte('\x1f')
		builder.WriteString(string(item.Action))
		builder.WriteByte('\x1f')
		builder.WriteString(string(item.Reason))
		builder.WriteByte('\x1f')
		builder.WriteString(fmt.Sprintf("%020d", item.NextCheckAt))
		builder.WriteByte('\x1f')
		builder.WriteString(string(item.RecordState))
		builder.WriteByte('\x1f')
		builder.WriteString(item.RecordVersion)
		builder.WriteByte('\x1e')
	}
	return "sha256:" + sha256Hex(builder.String())
}
