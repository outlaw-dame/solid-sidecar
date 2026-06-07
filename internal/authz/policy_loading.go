package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

var ErrInvalidPolicyLoad = errors.New("invalid authz policy load input")

type PolicyCacheState string

const (
	PolicyCacheFresh   PolicyCacheState = "fresh"
	PolicyCacheStale   PolicyCacheState = "stale"
	PolicyCacheExpired PolicyCacheState = "expired"
)

type PolicySourceLoadResult struct {
	Loaded   LoadedPolicySource     `json:"loaded"`
	Metadata PolicySourceCacheRecord `json:"metadata"`
}

type PolicySourceLoader interface {
	LoadPolicySource(ctx context.Context, source PolicySource) (PolicySourceLoadResult, error)
}

type PolicySourceCacheRecord struct {
	CacheKey      string           `json:"cache_key"`
	Source        PolicySource     `json:"source"`
	Document      PolicyDocument   `json:"document"`
	LoadedAtUnix  int64            `json:"loaded_at_unix"`
	ExpiresAtUnix int64            `json:"expires_at_unix,omitempty"`
	State         PolicyCacheState `json:"state"`
	Version       string           `json:"version"`
}

type InMemoryPolicySourceEntry struct {
	Content       []byte
	ContentType   string
	LoadedAtUnix  int64
	ExpiresAtUnix int64
	Version       string
}

type InMemoryPolicySourceLoader struct {
	mu      sync.RWMutex
	entries map[string]InMemoryPolicySourceEntry
}

func NewInMemoryPolicySourceLoader(entries map[PolicySource]InMemoryPolicySourceEntry) (*InMemoryPolicySourceLoader, error) {
	loader := &InMemoryPolicySourceLoader{entries: make(map[string]InMemoryPolicySourceEntry)}
	for source, entry := range entries {
		if err := loader.Store(source, entry); err != nil {
			return nil, err
		}
	}
	return loader, nil
}

func (l *InMemoryPolicySourceLoader) Store(source PolicySource, entry InMemoryPolicySourceEntry) error {
	if l == nil {
		return fmt.Errorf("%w: nil in-memory policy source loader", ErrInvalidPolicyLoad)
	}
	normalized, err := normalizePolicySource(source)
	if err != nil {
		return err
	}
	entry, err = normalizeInMemoryPolicySourceEntry(normalized, entry)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = make(map[string]InMemoryPolicySourceEntry)
	}
	l.entries[PolicySourceCacheKey(normalized)] = entry
	return nil
}

func (l *InMemoryPolicySourceLoader) LoadPolicySource(ctx context.Context, source PolicySource) (PolicySourceLoadResult, error) {
	if l == nil {
		return PolicySourceLoadResult{}, fmt.Errorf("%w: nil in-memory policy source loader", ErrInvalidPolicyLoad)
	}
	if err := ctx.Err(); err != nil {
		return PolicySourceLoadResult{}, err
	}
	normalized, err := normalizePolicySource(source)
	if err != nil {
		return PolicySourceLoadResult{}, err
	}
	key := PolicySourceCacheKey(normalized)
	l.mu.RLock()
	entry, ok := l.entries[key]
	l.mu.RUnlock()
	if !ok {
		return PolicySourceLoadResult{}, fmt.Errorf("%w: policy source not found", ErrInvalidPolicyLoad)
	}
	entry, err = normalizeInMemoryPolicySourceEntry(normalized, entry)
	if err != nil {
		return PolicySourceLoadResult{}, err
	}
	loaded := LoadedPolicySource{Source: normalized, Content: copyBytes(entry.Content)}
	metadata, err := PolicyCacheRecordForLoadedSource(loaded, entry.LoadedAtUnix, entry.ExpiresAtUnix, entry.Version)
	if err != nil {
		return PolicySourceLoadResult{}, err
	}
	return PolicySourceLoadResult{Loaded: loaded, Metadata: metadata}, nil
}

func normalizeInMemoryPolicySourceEntry(source PolicySource, entry InMemoryPolicySourceEntry) (InMemoryPolicySourceEntry, error) {
	if len(entry.Content) == 0 {
		return InMemoryPolicySourceEntry{}, fmt.Errorf("%w: empty policy source content", ErrInvalidPolicyLoad)
	}
	if int64(len(entry.Content)) > MaxLoadedPolicyDocumentBytes {
		return InMemoryPolicySourceEntry{}, fmt.Errorf("%w: policy source content too large", ErrInvalidPolicyLoad)
	}
	contentType := strings.TrimSpace(entry.ContentType)
	if contentType == "" {
		contentType = source.ContentType
	}
	if contentType == "" {
		return InMemoryPolicySourceEntry{}, fmt.Errorf("%w: policy source content type is required", ErrInvalidPolicyLoad)
	}
	normalizedContentType, err := normalizeContentType(contentType)
	if err != nil {
		return InMemoryPolicySourceEntry{}, fmt.Errorf("%w: invalid policy source content type", ErrInvalidPolicyLoad)
	}
	version := strings.TrimSpace(entry.Version)
	if version != "" && containsControlRune(version) {
		return InMemoryPolicySourceEntry{}, fmt.Errorf("%w: invalid policy source cache version", ErrInvalidPolicyLoad)
	}
	return InMemoryPolicySourceEntry{
		Content:       copyBytes(entry.Content),
		ContentType:   normalizedContentType,
		LoadedAtUnix:  entry.LoadedAtUnix,
		ExpiresAtUnix: entry.ExpiresAtUnix,
		Version:       version,
	}, nil
}

func PolicySourceCacheKey(source PolicySource) string {
	normalized, err := normalizePolicySource(source)
	if err != nil {
		return ""
	}
	parts := []string{
		normalized.URI,
		string(normalized.Kind),
		fmt.Sprintf("%010d", normalized.Priority),
		normalized.ContentType,
	}
	return "policy-source:" + sha256Hex(strings.Join(parts, "\x1f"))
}

func PolicyCacheRecordForLoadedSource(loaded LoadedPolicySource, loadedAtUnix int64, expiresAtUnix int64, version string) (PolicySourceCacheRecord, error) {
	documents, err := PolicyDocumentsFromLoadedSources([]LoadedPolicySource{loaded})
	if err != nil {
		return PolicySourceCacheRecord{}, err
	}
	if len(documents) != 1 {
		return PolicySourceCacheRecord{}, fmt.Errorf("%w: expected one loaded policy document", ErrInvalidPolicyLoad)
	}
	source, err := normalizePolicySource(loaded.Source)
	if err != nil {
		return PolicySourceCacheRecord{}, err
	}
	version = strings.TrimSpace(version)
	if version == "" {
		version = PolicySourceCacheVersion(source, documents[0], loadedAtUnix, expiresAtUnix)
	}
	return PolicySourceCacheRecord{
		CacheKey:      PolicySourceCacheKey(source),
		Source:        source,
		Document:      documents[0],
		LoadedAtUnix:  loadedAtUnix,
		ExpiresAtUnix: expiresAtUnix,
		State:         PolicyCacheStateAt(loadedAtUnix, expiresAtUnix, loadedAtUnix),
		Version:       version,
	}, nil
}

func PolicySourceCacheVersion(source PolicySource, document PolicyDocument, loadedAtUnix int64, expiresAtUnix int64) string {
	normalizedSource, err := normalizePolicySource(source)
	if err != nil {
		return ""
	}
	normalizedDocuments, err := NormalizePolicyDocuments([]PolicyDocument{document})
	if err != nil || len(normalizedDocuments) != 1 {
		return ""
	}
	parts := []string{
		normalizedSource.URI,
		string(normalizedSource.Kind),
		fmt.Sprintf("%010d", normalizedSource.Priority),
		normalizedSource.ContentType,
		normalizedDocuments[0].URI,
		normalizedDocuments[0].SHA256,
		normalizedDocuments[0].ContentType,
		fmt.Sprintf("%020d", loadedAtUnix),
		fmt.Sprintf("%020d", expiresAtUnix),
	}
	return "sha256:" + sha256Hex(strings.Join(parts, "\x1f"))
}

func PolicyCacheStateAt(loadedAtUnix int64, expiresAtUnix int64, nowUnix int64) PolicyCacheState {
	if loadedAtUnix <= 0 {
		return PolicyCacheStale
	}
	if expiresAtUnix > 0 && nowUnix >= expiresAtUnix {
		return PolicyCacheExpired
	}
	return PolicyCacheFresh
}

func NormalizePolicyCacheRecords(input []PolicySourceCacheRecord, nowUnix int64) ([]PolicySourceCacheRecord, error) {
	if len(input) == 0 {
		return nil, nil
	}
	seen := make(map[string]PolicySourceCacheRecord, len(input))
	for _, record := range input {
		normalized, err := normalizePolicyCacheRecord(record, nowUnix)
		if err != nil {
			return nil, err
		}
		if existing, ok := seen[normalized.CacheKey]; ok {
			if existing.Version != normalized.Version || existing.Document.SHA256 != normalized.Document.SHA256 {
				return nil, fmt.Errorf("%w: conflicting policy source cache record", ErrInvalidPolicyLoad)
			}
			continue
		}
		seen[normalized.CacheKey] = normalized
	}
	out := make([]PolicySourceCacheRecord, 0, len(seen))
	for _, record := range seen {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CacheKey != out[j].CacheKey {
			return out[i].CacheKey < out[j].CacheKey
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

func normalizePolicyCacheRecord(record PolicySourceCacheRecord, nowUnix int64) (PolicySourceCacheRecord, error) {
	source, err := normalizePolicySource(record.Source)
	if err != nil {
		return PolicySourceCacheRecord{}, err
	}
	documents, err := NormalizePolicyDocuments([]PolicyDocument{record.Document})
	if err != nil || len(documents) != 1 {
		return PolicySourceCacheRecord{}, fmt.Errorf("%w: invalid policy cache document", ErrInvalidPolicyLoad)
	}
	cacheKey := strings.TrimSpace(record.CacheKey)
	if cacheKey == "" {
		cacheKey = PolicySourceCacheKey(source)
	}
	if cacheKey != PolicySourceCacheKey(source) {
		return PolicySourceCacheRecord{}, fmt.Errorf("%w: cache key does not match source", ErrInvalidPolicyLoad)
	}
	version := strings.TrimSpace(record.Version)
	if version == "" {
		version = PolicySourceCacheVersion(source, documents[0], record.LoadedAtUnix, record.ExpiresAtUnix)
	}
	if version == "" || containsControlRune(version) {
		return PolicySourceCacheRecord{}, fmt.Errorf("%w: invalid policy cache version", ErrInvalidPolicyLoad)
	}
	return PolicySourceCacheRecord{
		CacheKey:      cacheKey,
		Source:        source,
		Document:      documents[0],
		LoadedAtUnix:  record.LoadedAtUnix,
		ExpiresAtUnix: record.ExpiresAtUnix,
		State:         PolicyCacheStateAt(record.LoadedAtUnix, record.ExpiresAtUnix, nowUnix),
		Version:       version,
	}, nil
}

func copyBytes(input []byte) []byte {
	if len(input) == 0 {
		return nil
	}
	out := make([]byte, len(input))
	copy(out, input)
	return out
}
