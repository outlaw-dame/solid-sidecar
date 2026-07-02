package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// StorageAbstractionLayer implements Layer 2: Storage abstraction
// This layer provides a unified interface for different storage backends,
// allowing them to be swapped without changing protocol behavior
//
// Key principles:
// - Storage backend can be swapped without changing protocol behavior
// - All storage operations are idempotent where applicable
// - All operations have proper timeout and retry logic
// - All operations are properly instrumented with metrics
type StorageAbstractionLayer struct {
	mu sync.RWMutex

	config StorageAbstractionConfig

	// Registered storage backends
	backends map[string]StorageBackend

	// Default storage backend name
	defaultBackend string

	// Metrics
	metrics StorageAbstractionMetrics

	// Logger
	logger *slog.Logger

	// Close state
	closed bool
}

// StorageAbstractionConfig holds configuration for the storage abstraction layer
type StorageAbstractionConfig struct {
	// DefaultStorage is the default storage backend to use
	DefaultStorage string

	// MaxRetries is the maximum number of retries for transient failures
	MaxRetries int

	// BackoffBase is the base delay for exponential backoff (in milliseconds)
	BackoffBase int

	// BackoffMax is the maximum delay for exponential backoff (in milliseconds)
	BackoffMax int

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultStorageAbstractionConfig returns a safe default configuration
func DefaultStorageAbstractionConfig() StorageAbstractionConfig {
	return StorageAbstractionConfig{
		DefaultStorage: "default",
		MaxRetries:     3,
		BackoffBase:    100,  // 100ms
		BackoffMax:     5000, // 5s
		Logger:         nil,
	}
}

// StorageAbstractionMetrics holds metrics for the storage abstraction layer
type StorageAbstractionMetrics struct {
	mu sync.RWMutex

	// Total operations
	TotalOperations int64

	// Successful operations
	SuccessfulOperations int64

	// Failed operations
	FailedOperations int64

	// Operations by type
	ReadOperations   int64
	WriteOperations  int64
	DeleteOperations int64
	ListOperations   int64

	// Retry metrics
	RetryAttempts int64
	MaxRetriesHit int64

	// Validation metrics
	ValidationFailures       int64
	ValidationFailuresByType map[string]int64

	// Backend-specific metrics
	BackendOperations map[string]int64
}

// RecordOperation records a storage operation
func (m *StorageAbstractionMetrics) RecordOperation(operation string, backend string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalOperations++
	if success {
		m.SuccessfulOperations++
	} else {
		m.FailedOperations++
	}

	switch operation {
	case "read":
		m.ReadOperations++
	case "write":
		m.WriteOperations++
	case "delete":
		m.DeleteOperations++
	case "list":
		m.ListOperations++
	}

	// Track backend operations
	if m.BackendOperations == nil {
		m.BackendOperations = make(map[string]int64)
	}
	m.BackendOperations[backend]++
}

// RecordRetry records a retry attempt
func (m *StorageAbstractionMetrics) RecordRetry() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RetryAttempts++
}

// RecordMaxRetriesHit records hitting the max retries limit
func (m *StorageAbstractionMetrics) RecordMaxRetriesHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.MaxRetriesHit++
}

// RecordValidationFailure records a validation failure
func (m *StorageAbstractionMetrics) RecordValidationFailure(failureType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ValidationFailures++
	if m.ValidationFailuresByType == nil {
		m.ValidationFailuresByType = make(map[string]int64)
	}
	m.ValidationFailuresByType[failureType]++
}

// StorageBackend is the interface that all storage backends must implement
type StorageBackend interface {
	// Name returns the name of the storage backend
	Name() string

	// Get retrieves a resource by URI
	Get(ctx context.Context, uri string) (*StorageResource, error)

	// Put stores a resource
	Put(ctx context.Context, uri string, resource *StorageResource) error

	// Delete removes a resource
	Delete(ctx context.Context, uri string) error

	// List lists resources in a container
	List(ctx context.Context, containerURI string) ([]*StorageResource, error)

	// Exists checks if a resource exists
	Exists(ctx context.Context, uri string) (bool, error)

	// Head retrieves metadata only (no body)
	Head(ctx context.Context, uri string) (*StorageResourceMetadata, error)

	// Close cleans up backend resources
	Close() error

	// HealthCheck checks if the backend is healthy
	HealthCheck(ctx context.Context) error
}

// StorageResource represents a resource stored in a storage backend
type StorageResource struct {
	// URI is the resource identifier
	URI string

	// ContentType is the MIME type of the resource
	ContentType string

	// Body is the resource content
	Body []byte

	// Metadata contains additional resource metadata
	Metadata StorageResourceMetadata

	// ETag is the entity tag for caching
	ETag string

	// LastModified is when the resource was last modified
	LastModified time.Time
}

// StorageResourceMetadata contains metadata about a storage resource
type StorageResourceMetadata struct {
	// Size is the size of the resource in bytes
	Size int64

	// ContentType is the MIME type
	ContentType string

	// ETag is the entity tag
	ETag string

	// LastModified is when the resource was last modified
	LastModified time.Time

	// Created is when the resource was created
	Created time.Time

	// Custom metadata key-value pairs
	Custom map[string]string
}

// NewStorageAbstractionLayer creates a new storage abstraction layer
func NewStorageAbstractionLayer(config StorageAbstractionConfig) *StorageAbstractionLayer {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	layer := &StorageAbstractionLayer{
		config:         config,
		defaultBackend: config.DefaultStorage,
		backends:       make(map[string]StorageBackend),
		logger:         config.Logger,
		closed:         false,
		metrics: StorageAbstractionMetrics{
			BackendOperations:        make(map[string]int64),
			ValidationFailuresByType: make(map[string]int64),
		},
	}

	config.Logger.Info("Storage abstraction layer initialized",
		"default_backend", config.DefaultStorage,
		"max_retries", config.MaxRetries,
		"backoff_base", config.BackoffBase,
		"backoff_max", config.BackoffMax,
	)

	return layer
}

// RegisterBackend registers a new storage backend
func (s *StorageAbstractionLayer) RegisterBackend(name string, backend StorageBackend) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("cannot register backend: storage layer is closed")
	}

	if _, exists := s.backends[name]; exists {
		return fmt.Errorf("backend %q already registered", name)
	}

	s.backends[name] = backend
	s.logger.Info("Storage backend registered", "name", name, "backend", backend.Name())
	return nil
}

// UnregisterBackend unregisters a storage backend
func (s *StorageAbstractionLayer) UnregisterBackend(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("cannot unregister backend: storage layer is closed")
	}

	if _, exists := s.backends[name]; !exists {
		return fmt.Errorf("backend %q not found", name)
	}

	if err := s.backends[name].Close(); err != nil {
		s.logger.Error("Error closing backend", "name", name, "error", err)
	}

	delete(s.backends, name)
	s.logger.Info("Storage backend unregistered", "name", name)
	return nil
}

// GetBackend returns a storage backend by name
func (s *StorageAbstractionLayer) GetBackend(name string) (StorageBackend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, errors.New("storage layer is closed")
	}

	backend, exists := s.backends[name]
	if !exists {
		return nil, fmt.Errorf("backend %q not found", name)
	}

	return backend, nil
}

// SetDefaultBackend sets the default storage backend
func (s *StorageAbstractionLayer) SetDefaultBackend(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("cannot set default backend: storage layer is closed")
	}

	if _, exists := s.backends[name]; !exists {
		return fmt.Errorf("backend %q not found", name)
	}

	s.defaultBackend = name
	s.logger.Info("Default storage backend changed", "name", name)
	return nil
}

// Get retrieves a resource from the default backend
func (s *StorageAbstractionLayer) Get(ctx context.Context, uri string) (*StorageResource, error) {
	// Validate URI to prevent injection attacks and path traversal
	if err := ValidateURI(uri); err != nil {
		s.metrics.RecordValidationFailure("uri")
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	_, err := s.getDefaultBackend()
	if err != nil {
		return nil, err
	}

	return s.GetFromBackend(ctx, s.defaultBackend, uri)
}

// GetFromBackend retrieves a resource from a specific backend
func (s *StorageAbstractionLayer) GetFromBackend(ctx context.Context, backendName string, uri string) (*StorageResource, error) {
	backend, err := s.GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	return s.doWithRetry(ctx, "read", backendName, func() (*StorageResource, error) {
		return backend.Get(ctx, uri)
	})
}

// Put stores a resource in the default backend
func (s *StorageAbstractionLayer) Put(ctx context.Context, uri string, resource *StorageResource) error {
	// Validate URI to prevent injection attacks and path traversal
	if err := ValidateURI(uri); err != nil {
		s.metrics.RecordValidationFailure("uri")
		return fmt.Errorf("invalid URI: %w", err)
	}

	// Validate resource size to prevent DoS attacks
	if err := ValidateResourceSize(int64(len(resource.Body))); err != nil {
		s.metrics.RecordValidationFailure("size")
		return fmt.Errorf("resource validation failed: %w", err)
	}

	_, err := s.getDefaultBackend()
	if err != nil {
		return err
	}

	return s.PutToBackend(ctx, s.defaultBackend, uri, resource)
}

// PutToBackend stores a resource in a specific backend
func (s *StorageAbstractionLayer) PutToBackend(ctx context.Context, backendName string, uri string, resource *StorageResource) error {
	backend, err := s.GetBackend(backendName)
	if err != nil {
		return err
	}

	_, err = s.doWithRetry(ctx, "write", backendName, func() (*StorageResource, error) {
		return nil, backend.Put(ctx, uri, resource)
	})
	return err
}

// Delete removes a resource from the default backend
func (s *StorageAbstractionLayer) Delete(ctx context.Context, uri string) error {
	// Validate URI to prevent injection attacks and path traversal
	if err := ValidateURI(uri); err != nil {
		s.metrics.RecordValidationFailure("uri")
		return fmt.Errorf("invalid URI: %w", err)
	}

	_, err := s.getDefaultBackend()
	if err != nil {
		return err
	}

	return s.DeleteFromBackend(ctx, s.defaultBackend, uri)
}

// DeleteFromBackend removes a resource from a specific backend
func (s *StorageAbstractionLayer) DeleteFromBackend(ctx context.Context, backendName string, uri string) error {
	backend, err := s.GetBackend(backendName)
	if err != nil {
		return err
	}

	_, err = s.doWithRetry(ctx, "delete", backendName, func() (*StorageResource, error) {
		return nil, backend.Delete(ctx, uri)
	})
	return err
}

// List lists resources in a container from the default backend
func (s *StorageAbstractionLayer) List(ctx context.Context, containerURI string) ([]*StorageResource, error) {
	// Validate container URI to prevent injection attacks and path traversal
	if err := ValidateURI(containerURI); err != nil {
		s.metrics.RecordValidationFailure("uri")
		return nil, fmt.Errorf("invalid container URI: %w", err)
	}

	_, err := s.getDefaultBackend()
	if err != nil {
		return nil, err
	}

	return s.ListFromBackend(ctx, s.defaultBackend, containerURI)
}

// ListFromBackend lists resources in a container from a specific backend
func (s *StorageAbstractionLayer) ListFromBackend(ctx context.Context, backendName string, containerURI string) ([]*StorageResource, error) {
	backend, err := s.GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	// List doesn't have a simple retry pattern since it returns a slice
	// We'll do a simple retry loop
	var resources []*StorageResource
	var lastErr error

	for attempt := 0; attempt <= s.config.MaxRetries; attempt++ {
		if attempt > 0 {
			s.metrics.RecordRetry()
			backoff := s.calculateBackoff(attempt)
			time.Sleep(time.Duration(backoff) * time.Millisecond)
		}

		resources, lastErr = backend.List(ctx, containerURI)
		if lastErr == nil {
			s.metrics.RecordOperation("list", backendName, true)
			return resources, nil
		}

		// Check if we should retry
		if !s.shouldRetry(lastErr) {
			s.metrics.RecordOperation("list", backendName, false)
			return nil, lastErr
		}
	}

	s.metrics.RecordOperation("list", backendName, false)
	s.metrics.RecordMaxRetriesHit()
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// Exists checks if a resource exists in the default backend
func (s *StorageAbstractionLayer) Exists(ctx context.Context, uri string) (bool, error) {
	// Validate URI to prevent injection attacks and path traversal
	if err := ValidateURI(uri); err != nil {
		s.metrics.RecordValidationFailure("uri")
		return false, fmt.Errorf("invalid URI: %w", err)
	}

	_, err := s.getDefaultBackend()
	if err != nil {
		return false, err
	}

	return s.ExistsInBackend(ctx, s.defaultBackend, uri)
}

// ExistsInBackend checks if a resource exists in a specific backend
func (s *StorageAbstractionLayer) ExistsInBackend(ctx context.Context, backendName string, uri string) (bool, error) {
	backend, err := s.GetBackend(backendName)
	if err != nil {
		return false, err
	}

	exists, err := s.doWithRetryBool(ctx, "exists", backendName, func() (bool, error) {
		return backend.Exists(ctx, uri)
	})
	return exists, err
}

// Head retrieves metadata only from the default backend
func (s *StorageAbstractionLayer) Head(ctx context.Context, uri string) (*StorageResourceMetadata, error) {
	// Validate URI to prevent injection attacks and path traversal
	if err := ValidateURI(uri); err != nil {
		s.metrics.RecordValidationFailure("uri")
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	_, err := s.getDefaultBackend()
	if err != nil {
		return nil, err
	}

	return s.HeadFromBackend(ctx, s.defaultBackend, uri)
}

// HeadFromBackend retrieves metadata only from a specific backend
func (s *StorageAbstractionLayer) HeadFromBackend(ctx context.Context, backendName string, uri string) (*StorageResourceMetadata, error) {
	backend, err := s.GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	metadata, err := s.doWithRetryMetadata(ctx, "head", backendName, func() (*StorageResourceMetadata, error) {
		return backend.Head(ctx, uri)
	})
	return metadata, err
}

// doWithRetry executes an operation with exponential backoff retry
func (s *StorageAbstractionLayer) doWithRetry(
	ctx context.Context,
	operation string,
	backendName string,
	fn func() (*StorageResource, error),
) (*StorageResource, error) {
	var result *StorageResource
	var lastErr error

	for attempt := 0; attempt <= s.config.MaxRetries; attempt++ {
		if attempt > 0 {
			s.metrics.RecordRetry()
			backoff := s.calculateBackoff(attempt)
			select {
			case <-ctx.Done():
				s.metrics.RecordOperation(operation, backendName, false)
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			case <-time.After(time.Duration(backoff) * time.Millisecond):
			}
		}

		result, lastErr = fn()
		if lastErr == nil {
			s.metrics.RecordOperation(operation, backendName, true)
			return result, nil
		}

		// Check if we should retry
		if !s.shouldRetry(lastErr) {
			s.metrics.RecordOperation(operation, backendName, false)
			return nil, lastErr
		}
	}

	s.metrics.RecordOperation(operation, backendName, false)
	s.metrics.RecordMaxRetriesHit()
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// doWithRetryBool executes a boolean operation with exponential backoff retry
func (s *StorageAbstractionLayer) doWithRetryBool(
	ctx context.Context,
	operation string,
	backendName string,
	fn func() (bool, error),
) (bool, error) {
	var result bool
	var lastErr error

	for attempt := 0; attempt <= s.config.MaxRetries; attempt++ {
		if attempt > 0 {
			s.metrics.RecordRetry()
			backoff := s.calculateBackoff(attempt)
			select {
			case <-ctx.Done():
				s.metrics.RecordOperation(operation, backendName, false)
				return false, fmt.Errorf("context cancelled: %w", ctx.Err())
			case <-time.After(time.Duration(backoff) * time.Millisecond):
			}
		}

		result, lastErr = fn()
		if lastErr == nil {
			s.metrics.RecordOperation(operation, backendName, true)
			return result, nil
		}

		// Check if we should retry
		if !s.shouldRetry(lastErr) {
			s.metrics.RecordOperation(operation, backendName, false)
			return false, lastErr
		}
	}

	s.metrics.RecordOperation(operation, backendName, false)
	s.metrics.RecordMaxRetriesHit()
	return false, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// doWithRetryMetadata executes a metadata operation with exponential backoff retry
func (s *StorageAbstractionLayer) doWithRetryMetadata(
	ctx context.Context,
	operation string,
	backendName string,
	fn func() (*StorageResourceMetadata, error),
) (*StorageResourceMetadata, error) {
	var result *StorageResourceMetadata
	var lastErr error

	for attempt := 0; attempt <= s.config.MaxRetries; attempt++ {
		if attempt > 0 {
			s.metrics.RecordRetry()
			backoff := s.calculateBackoff(attempt)
			select {
			case <-ctx.Done():
				s.metrics.RecordOperation(operation, backendName, false)
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			case <-time.After(time.Duration(backoff) * time.Millisecond):
			}
		}

		result, lastErr = fn()
		if lastErr == nil {
			s.metrics.RecordOperation(operation, backendName, true)
			return result, nil
		}

		// Check if we should retry
		if !s.shouldRetry(lastErr) {
			s.metrics.RecordOperation(operation, backendName, false)
			return nil, lastErr
		}
	}

	s.metrics.RecordOperation(operation, backendName, false)
	s.metrics.RecordMaxRetriesHit()
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// calculateBackoff calculates the exponential backoff delay for a given attempt
func (s *StorageAbstractionLayer) calculateBackoff(attempt int) int {
	// Exponential backoff with jitter
	backoff := s.config.BackoffBase * (1 << (attempt - 1))
	if backoff > s.config.BackoffMax {
		backoff = s.config.BackoffMax
	}
	return backoff
}

// shouldRetry determines if an error is retryable
func (s *StorageAbstractionLayer) shouldRetry(err error) bool {
	if err == nil {
		return false
	}

	// Retry on network errors, timeouts, and 5xx errors
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Check for temporary errors
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Check for connection errors
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	// Check for HTTP 5xx errors (if wrapped)
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		if httpErr.StatusCode >= 500 && httpErr.StatusCode < 600 {
			return true
		}
	}

	return false
}

// getDefaultBackend returns the default backend
func (s *StorageAbstractionLayer) getDefaultBackend() (StorageBackend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, errors.New("storage layer is closed")
	}

	backend, exists := s.backends[s.defaultBackend]
	if !exists {
		return nil, fmt.Errorf("default backend %q not found", s.defaultBackend)
	}

	return backend, nil
}

// GetBackendNames returns the names of all registered backends
func (s *StorageAbstractionLayer) GetBackendNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.backends))
	for name := range s.backends {
		names = append(names, name)
	}
	return names
}

// HealthCheck checks the health of all backends
func (s *StorageAbstractionLayer) HealthCheck(ctx context.Context) map[string]error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return map[string]error{"error": errors.New("storage layer is closed")}
	}

	results := make(map[string]error)
	for name, backend := range s.backends {
		if err := backend.HealthCheck(ctx); err != nil {
			results[name] = err
		} else {
			results[name] = nil
		}
	}
	return results
}

// Close closes the storage abstraction layer and all backends
func (s *StorageAbstractionLayer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	// Close all backends
	for name, backend := range s.backends {
		if err := backend.Close(); err != nil {
			s.logger.Error("Error closing storage backend", "name", name, "error", err)
			// Continue closing other backends
		}
	}

	s.logger.Info("Storage abstraction layer closed")
	return nil
}

// GetMetrics returns the current metrics
func (s *StorageAbstractionLayer) GetMetrics() *StorageAbstractionMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &s.metrics
}

// IsClosed returns true if the layer is closed
func (s *StorageAbstractionLayer) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// HTTPError is a wrapper for HTTP errors
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// InMemoryStorageBackend is a simple in-memory storage backend for testing
type InMemoryStorageBackend struct {
	mu     sync.RWMutex
	data   map[string]*StorageResource
	logger *slog.Logger
	name   string
	closed bool
}

// NewInMemoryStorageBackend creates a new in-memory storage backend
func NewInMemoryStorageBackend(name string, logger *slog.Logger) *InMemoryStorageBackend {
	if logger == nil {
		logger = slog.Default()
	}
	return &InMemoryStorageBackend{
		data:   make(map[string]*StorageResource),
		logger: logger,
		name:   name,
	}
}

// Name returns the backend name
func (m *InMemoryStorageBackend) Name() string {
	return m.name
}

// Get retrieves a resource by URI
func (m *InMemoryStorageBackend) Get(ctx context.Context, uri string) (*StorageResource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("in-memory backend is closed")
	}

	resource, exists := m.data[uri]
	if !exists {
		return nil, &HTTPError{StatusCode: http.StatusNotFound, Message: "resource not found"}
	}

	// Return a copy
	return &StorageResource{
		URI:          resource.URI,
		ContentType:  resource.ContentType,
		Body:         append([]byte(nil), resource.Body...),
		Metadata:     resource.Metadata,
		ETag:         resource.ETag,
		LastModified: resource.LastModified,
	}, nil
}

// Put stores a resource
func (m *InMemoryStorageBackend) Put(ctx context.Context, uri string, resource *StorageResource) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("in-memory backend is closed")
	}

	// Store a copy
	m.data[uri] = &StorageResource{
		URI:          resource.URI,
		ContentType:  resource.ContentType,
		Body:         append([]byte(nil), resource.Body...),
		Metadata:     resource.Metadata,
		ETag:         resource.ETag,
		LastModified: time.Now().UTC(),
	}

	return nil
}

// Delete removes a resource
func (m *InMemoryStorageBackend) Delete(ctx context.Context, uri string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("in-memory backend is closed")
	}

	delete(m.data, uri)
	return nil
}

// List lists resources in a container
func (m *InMemoryStorageBackend) List(ctx context.Context, containerURI string) ([]*StorageResource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("in-memory backend is closed")
	}

	var resources []*StorageResource
	for uri, resource := range m.data {
		// Simple filtering by prefix for container listing
		if len(containerURI) == 0 || len(uri) >= len(containerURI) && uri[:len(containerURI)] == containerURI {
			resources = append(resources, &StorageResource{
				URI:          resource.URI,
				ContentType:  resource.ContentType,
				Body:         append([]byte(nil), resource.Body...),
				Metadata:     resource.Metadata,
				ETag:         resource.ETag,
				LastModified: resource.LastModified,
			})
		}
	}

	return resources, nil
}

// Exists checks if a resource exists
func (m *InMemoryStorageBackend) Exists(ctx context.Context, uri string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, errors.New("in-memory backend is closed")
	}

	_, exists := m.data[uri]
	return exists, nil
}

// Head retrieves metadata only
func (m *InMemoryStorageBackend) Head(ctx context.Context, uri string) (*StorageResourceMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("in-memory backend is closed")
	}

	resource, exists := m.data[uri]
	if !exists {
		return nil, &HTTPError{StatusCode: http.StatusNotFound, Message: "resource not found"}
	}

	return &resource.Metadata, nil
}

// Close closes the backend
func (m *InMemoryStorageBackend) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	m.data = make(map[string]*StorageResource)
	return nil
}

// HealthCheck checks backend health
func (m *InMemoryStorageBackend) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return errors.New("in-memory backend is closed")
	}

	return nil
}

// HTTPStorageBackend is a storage backend that proxies to an HTTP server (like CSS)
type HTTPStorageBackend struct {
	mu      sync.RWMutex
	client  *http.Client
	baseURL string
	name    string
	logger  *slog.Logger
	closed  bool
}

// NewHTTPStorageBackend creates a new HTTP storage backend
func NewHTTPStorageBackend(name string, baseURL string, logger *slog.Logger) *HTTPStorageBackend {
	if logger == nil {
		logger = slog.Default()
	}

	// Ensure baseURL doesn't end with /
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &HTTPStorageBackend{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		baseURL: baseURL,
		name:    name,
		logger:  logger,
	}
}

// Name returns the backend name
func (h *HTTPStorageBackend) Name() string {
	return h.name
}

// buildURL constructs a URL for a given resource URI
func (h *HTTPStorageBackend) buildURL(uri string) (string, error) {
	parsed, err := url.Parse(h.baseURL)
	if err != nil {
		return "", err
	}

	resourceURL, err := url.Parse(uri)
	if err != nil {
		return "", err
	}

	// Join the paths
	parsed.Path = resourceURL.Path
	return parsed.String(), nil
}

// Get retrieves a resource by URI
func (h *HTTPStorageBackend) Get(ctx context.Context, uri string) (*StorageResource, error) {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return nil, errors.New("HTTP backend is closed")
	}
	h.mu.RUnlock()

	url, err := h.buildURL(uri)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &StorageResource{
		URI:         uri,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		Metadata: StorageResourceMetadata{
			Size:         int64(len(body)),
			ContentType:  resp.Header.Get("Content-Type"),
			ETag:         resp.Header.Get("ETag"),
			LastModified: parseHTTPDate(resp.Header.Get("Last-Modified")),
			Created:      parseHTTPDate(resp.Header.Get("Date")),
			Custom:       make(map[string]string),
		},
		ETag:         resp.Header.Get("ETag"),
		LastModified: parseHTTPDate(resp.Header.Get("Last-Modified")),
	}, nil
}

// Put stores a resource
func (h *HTTPStorageBackend) Put(ctx context.Context, uri string, resource *StorageResource) error {
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

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(resource.Body))
	if err != nil {
		return err
	}

	// Set headers
	if resource.ContentType != "" {
		req.Header.Set("Content-Type", resource.ContentType)
	}
	if resource.ETag != "" {
		req.Header.Set("If-Match", resource.ETag)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}

	return nil
}

// Delete removes a resource
func (h *HTTPStorageBackend) Delete(ctx context.Context, uri string) error {
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

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}

	return nil
}

// List lists resources in a container
func (h *HTTPStorageBackend) List(ctx context.Context, containerURI string) ([]*StorageResource, error) {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return nil, errors.New("HTTP backend is closed")
	}
	h.mu.RUnlock()

	url, err := h.buildURL(containerURI)
	if err != nil {
		return nil, err
	}

	// Try to get the container listing
	// This is a simplified implementation - real Solid servers have specific listing formats
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add Accept header for container listing
	req.Header.Set("Accept", "text/turtle, application/ld+json, text/plain")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// If not OK, try HEAD to check if it's a single resource
		headReq, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			return nil, err
		}
		headResp, err := h.client.Do(headReq)
		if err != nil {
			return nil, err
		}
		defer headResp.Body.Close()

		if headResp.StatusCode == http.StatusOK {
			// It's a single resource, return it as a single-item list
			body, _ := io.ReadAll(resp.Body)
			return []*StorageResource{
				{
					URI:         containerURI,
					ContentType: headResp.Header.Get("Content-Type"),
					Body:        body,
					Metadata: StorageResourceMetadata{
						Size:         int64(len(body)),
						ContentType:  headResp.Header.Get("Content-Type"),
						ETag:         headResp.Header.Get("ETag"),
						LastModified: parseHTTPDate(headResp.Header.Get("Last-Modified")),
					},
					ETag:         headResp.Header.Get("ETag"),
					LastModified: parseHTTPDate(headResp.Header.Get("Last-Modified")),
				},
			}, nil
		}
		return nil, &HTTPError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}

	// Parse the response body to extract resource URIs
	// This is a simplified parsing - real implementation would use proper RDF parsing
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// For now, just return the container itself
	// A real implementation would parse the container description
	return []*StorageResource{
		{
			URI:         containerURI,
			ContentType: resp.Header.Get("Content-Type"),
			Body:        body,
			Metadata: StorageResourceMetadata{
				Size:         int64(len(body)),
				ContentType:  resp.Header.Get("Content-Type"),
				ETag:         resp.Header.Get("ETag"),
				LastModified: parseHTTPDate(resp.Header.Get("Last-Modified")),
			},
			ETag:         resp.Header.Get("ETag"),
			LastModified: parseHTTPDate(resp.Header.Get("Last-Modified")),
		},
	}, nil
}

// Exists checks if a resource exists
func (h *HTTPStorageBackend) Exists(ctx context.Context, uri string) (bool, error) {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return false, errors.New("HTTP backend is closed")
	}
	h.mu.RUnlock()

	url, err := h.buildURL(uri)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false, err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// Head retrieves metadata only
func (h *HTTPStorageBackend) Head(ctx context.Context, uri string) (*StorageResourceMetadata, error) {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return nil, errors.New("HTTP backend is closed")
	}
	h.mu.RUnlock()

	url, err := h.buildURL(uri)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}

	return &StorageResourceMetadata{
		Size:         int64(resp.ContentLength),
		ContentType:  resp.Header.Get("Content-Type"),
		ETag:         resp.Header.Get("ETag"),
		LastModified: parseHTTPDate(resp.Header.Get("Last-Modified")),
		Created:      parseHTTPDate(resp.Header.Get("Date")),
		Custom:       make(map[string]string),
	}, nil
}

// Close closes the backend
func (h *HTTPStorageBackend) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}

	h.closed = true
	h.client.CloseIdleConnections()
	return nil
}

// HealthCheck checks backend health
func (h *HTTPStorageBackend) HealthCheck(ctx context.Context) error {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return errors.New("HTTP backend is closed")
	}
	h.mu.RUnlock()

	// Make a HEAD request to the base URL to check health
	req, err := http.NewRequestWithContext(ctx, "HEAD", h.baseURL, nil)
	if err != nil {
		return err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Any response (even 4xx) means the server is reachable
	if resp.StatusCode >= 500 {
		return &HTTPError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}

	return nil
}

// Helper functions

// parseHTTPDate parses an HTTP date header
func parseHTTPDate(dateStr string) time.Time {
	if dateStr == "" {
		return time.Time{}
	}

	// Try parsing with http.ParseTime
	t, err := http.ParseTime(dateStr)
	if err != nil {
		return time.Time{}
	}
	return t
}
