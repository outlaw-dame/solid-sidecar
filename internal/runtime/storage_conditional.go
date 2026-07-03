package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	// ErrStoragePreconditionFailed indicates storage validator state did not satisfy a conditional operation.
	ErrStoragePreconditionFailed = errors.New("storage precondition failed")
	// ErrStorageConditionalUnsupported indicates the selected backend cannot safely perform conditional writes.
	ErrStorageConditionalUnsupported = errors.New("storage conditional operation unsupported")
)

// StoragePreconditions models Solid/HTTP validator preconditions at the storage boundary.
// It intentionally mirrors If-Match and If-None-Match instead of hiding them in the HTTP layer,
// because storage must be able to prevent lost updates independently of the gateway.
type StoragePreconditions struct {
	IfMatch     []string
	IfNoneMatch []string
}

// IsEmpty returns true when no validator preconditions are set.
func (p StoragePreconditions) IsEmpty() bool {
	return len(p.IfMatch) == 0 && len(p.IfNoneMatch) == 0
}

// ConditionalStorageBackend is implemented by backends that can perform validator-aware writes atomically.
type ConditionalStorageBackend interface {
	StorageBackend
	PutConditional(ctx context.Context, uri string, resource *StorageResource, preconditions StoragePreconditions) error
	DeleteConditional(ctx context.Context, uri string, preconditions StoragePreconditions) error
}

// PutConditional stores a resource in the default backend only if validator preconditions match.
func (s *StorageAbstractionLayer) PutConditional(ctx context.Context, uri string, resource *StorageResource, preconditions StoragePreconditions) error {
	if err := ValidateURI(uri); err != nil {
		s.metrics.RecordValidationFailure("uri")
		return fmt.Errorf("invalid URI: %w", err)
	}
	if resource == nil {
		s.metrics.RecordValidationFailure("resource")
		return errors.New("resource must not be nil")
	}
	if err := ValidateResourceSize(int64(len(resource.Body))); err != nil {
		s.metrics.RecordValidationFailure("size")
		return fmt.Errorf("resource validation failed: %w", err)
	}
	if _, err := s.getDefaultBackend(); err != nil {
		return err
	}
	return s.PutConditionalToBackend(ctx, s.defaultBackend, uri, resource, preconditions)
}

// PutConditionalToBackend stores a resource in a named backend only if validator preconditions match.
func (s *StorageAbstractionLayer) PutConditionalToBackend(ctx context.Context, backendName string, uri string, resource *StorageResource, preconditions StoragePreconditions) error {
	backend, err := s.GetBackend(backendName)
	if err != nil {
		return err
	}
	conditional, ok := backend.(ConditionalStorageBackend)
	if !ok {
		return fmt.Errorf("%w: backend %q", ErrStorageConditionalUnsupported, backendName)
	}
	_, err = s.doWithRetry(ctx, "conditional_write", backendName, func() (*StorageResource, error) {
		return nil, conditional.PutConditional(ctx, uri, resource, preconditions)
	})
	return err
}

// DeleteConditional removes a resource from the default backend only if validator preconditions match.
func (s *StorageAbstractionLayer) DeleteConditional(ctx context.Context, uri string, preconditions StoragePreconditions) error {
	if err := ValidateURI(uri); err != nil {
		s.metrics.RecordValidationFailure("uri")
		return fmt.Errorf("invalid URI: %w", err)
	}
	if _, err := s.getDefaultBackend(); err != nil {
		return err
	}
	return s.DeleteConditionalFromBackend(ctx, s.defaultBackend, uri, preconditions)
}

// DeleteConditionalFromBackend removes a resource from a named backend only if validator preconditions match.
func (s *StorageAbstractionLayer) DeleteConditionalFromBackend(ctx context.Context, backendName string, uri string, preconditions StoragePreconditions) error {
	backend, err := s.GetBackend(backendName)
	if err != nil {
		return err
	}
	conditional, ok := backend.(ConditionalStorageBackend)
	if !ok {
		return fmt.Errorf("%w: backend %q", ErrStorageConditionalUnsupported, backendName)
	}
	_, err = s.doWithRetry(ctx, "conditional_delete", backendName, func() (*StorageResource, error) {
		return nil, conditional.DeleteConditional(ctx, uri, preconditions)
	})
	return err
}

// PutConditional stores a resource in memory only if validator preconditions match.
func (m *InMemoryStorageBackend) PutConditional(ctx context.Context, uri string, resource *StorageResource, preconditions StoragePreconditions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("in-memory backend is closed")
	}
	current, exists := m.data[uri]
	if err := evaluateStoragePreconditions(currentETag(current, exists), exists, preconditions); err != nil {
		return err
	}
	stored := copyStorageResource(resource)
	stored.URI = uri
	stored.LastModified = time.Now().UTC()
	if stored.ETag == "" {
		stored.ETag = strongStorageETag(stored.Body)
	}
	stored.Metadata.ETag = stored.ETag
	stored.Metadata.Size = int64(len(stored.Body))
	if stored.Metadata.ContentType == "" {
		stored.Metadata.ContentType = stored.ContentType
	}
	if stored.Metadata.Created.IsZero() && exists {
		stored.Metadata.Created = current.Metadata.Created
	}
	if stored.Metadata.Created.IsZero() {
		stored.Metadata.Created = stored.LastModified
	}
	stored.Metadata.LastModified = stored.LastModified
	m.data[uri] = stored
	return nil
}

// DeleteConditional removes an in-memory resource only if validator preconditions match.
func (m *InMemoryStorageBackend) DeleteConditional(ctx context.Context, uri string, preconditions StoragePreconditions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("in-memory backend is closed")
	}
	current, exists := m.data[uri]
	if err := evaluateStoragePreconditions(currentETag(current, exists), exists, preconditions); err != nil {
		return err
	}
	delete(m.data, uri)
	return nil
}

// PutConditional issues an HTTP PUT with If-Match/If-None-Match headers.
func (h *HTTPStorageBackend) PutConditional(ctx context.Context, uri string, resource *StorageResource, preconditions StoragePreconditions) error {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return errors.New("HTTP backend is closed")
	}
	h.mu.RUnlock()
	url, err := h.buildURL(uri)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(resource.Body))
	if err != nil {
		return err
	}
	if resource.ContentType != "" {
		req.Header.Set("Content-Type", resource.ContentType)
	}
	applyStoragePreconditionHeaders(req.Header, preconditions)
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusPreconditionFailed {
		return fmt.Errorf("%w: HTTP %d", ErrStoragePreconditionFailed, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}
	return nil
}

// DeleteConditional issues an HTTP DELETE with If-Match/If-None-Match headers.
func (h *HTTPStorageBackend) DeleteConditional(ctx context.Context, uri string, preconditions StoragePreconditions) error {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return errors.New("HTTP backend is closed")
	}
	h.mu.RUnlock()
	url, err := h.buildURL(uri)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	applyStoragePreconditionHeaders(req.Header, preconditions)
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusPreconditionFailed {
		return fmt.Errorf("%w: HTTP %d", ErrStoragePreconditionFailed, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}
	return nil
}

func applyStoragePreconditionHeaders(header http.Header, preconditions StoragePreconditions) {
	for _, value := range preconditions.IfMatch {
		header.Add("If-Match", value)
	}
	for _, value := range preconditions.IfNoneMatch {
		header.Add("If-None-Match", value)
	}
}

func evaluateStoragePreconditions(current string, exists bool, preconditions StoragePreconditions) error {
	if len(preconditions.IfMatch) > 0 {
		if !exists || !etagListMatches(preconditions.IfMatch, current, exists) {
			return fmt.Errorf("%w: If-Match did not match current validator", ErrStoragePreconditionFailed)
		}
	}
	if len(preconditions.IfNoneMatch) > 0 {
		if etagListMatches(preconditions.IfNoneMatch, current, exists) {
			return fmt.Errorf("%w: If-None-Match matched current validator", ErrStoragePreconditionFailed)
		}
	}
	return nil
}

func etagListMatches(values []string, current string, exists bool) bool {
	for _, value := range values {
		if value == "*" {
			return exists
		}
		if exists && value != "" && value == current {
			return true
		}
	}
	return false
}

func currentETag(resource *StorageResource, exists bool) string {
	if !exists || resource == nil {
		return ""
	}
	if resource.ETag != "" {
		return resource.ETag
	}
	return resource.Metadata.ETag
}

func strongStorageETag(body []byte) string {
	digest := sha256.Sum256(body)
	return fmt.Sprintf("\"sha256-%s\"", hex.EncodeToString(digest[:]))
}

func copyStorageResource(resource *StorageResource) *StorageResource {
	if resource == nil {
		return nil
	}
	metadata := resource.Metadata
	if resource.Metadata.Custom != nil {
		metadata.Custom = make(map[string]string, len(resource.Metadata.Custom))
		for key, value := range resource.Metadata.Custom {
			metadata.Custom[key] = value
		}
	}
	return &StorageResource{
		URI:          resource.URI,
		ContentType:  resource.ContentType,
		Body:         append([]byte(nil), resource.Body...),
		Metadata:     metadata,
		ETag:         resource.ETag,
		LastModified: resource.LastModified,
	}
}
