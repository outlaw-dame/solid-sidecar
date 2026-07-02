// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 6.5: Event stream layer for Solid notifications.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Hardening constants for Phase 16
type EventStreamHardeningConfig struct {
	// Maximum metadata size per event to prevent memory exhaustion
	MaxMetadataSize int

	// Maximum number of metadata keys per event
	MaxMetadataKeys int

	// Maximum metadata key length
	MaxMetadataKeyLength int

	// Maximum metadata value length
	MaxMetadataValueLength int

	// Maximum subscriber buffer size (events per subscriber)
	MaxSubscriberBufferSize int

	// Maximum time a subscriber can be inactive before cleanup
	MaxSubscriberInactivityTime time.Duration

	// Rate limiting for event publishing (events per second)
	MaxEventsPerSecond float64

	// Burst limit for event publishing
	EventBurstLimit int

	// Circuit breaker thresholds
	CircuitBreakerFailureThreshold int
	CircuitBreakerResetTimeout     time.Duration
}

// DefaultEventStreamHardeningConfig returns safe defaults for hardening
func DefaultEventStreamHardeningConfig() EventStreamHardeningConfig {
	return EventStreamHardeningConfig{
		MaxMetadataSize:                4096, // 4KB max metadata per event
		MaxMetadataKeys:                50,   // 50 metadata keys max
		MaxMetadataKeyLength:           256,  // 256 chars max key length
		MaxMetadataValueLength:         1024, // 1KB max value length
		MaxSubscriberBufferSize:        1000, // 1000 events per subscriber buffer
		MaxSubscriberInactivityTime:    1 * time.Hour,
		MaxEventsPerSecond:             1000.0, // 1000 events per second max
		EventBurstLimit:                2000,   // Allow bursts up to 2000
		CircuitBreakerFailureThreshold: 5,
		CircuitBreakerResetTimeout:     30 * time.Second,
	}
}

// EventStreamError represents errors specific to the event stream layer
var (
	ErrEventStreamClosed      = errors.New("event stream layer is closed")
	ErrInvalidEventData       = errors.New("invalid event data")
	ErrRateLimitExceeded      = errors.New("rate limit exceeded")
	ErrSubscriberLimitReached = errors.New("maximum subscribers reached")
	ErrEventBufferFull        = errors.New("event buffer is full")
	ErrCircuitBreakerOpen     = errors.New("circuit breaker is open")
	ErrInvalidPrivacyLevel    = errors.New("invalid privacy level")
	ErrAccessDenied           = errors.New("access denied")
)

// CircuitBreaker implements a circuit breaker pattern for event streaming
type CircuitBreaker struct {
	mu sync.RWMutex

	// Failure count
	failures int64

	// Failure threshold
	threshold int

	// Reset timeout
	resetTimeout time.Duration

	// Last failure time
	lastFailure time.Time

	// State: true = open (stopping requests), false = closed (allowing requests)
	state bool
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold:    threshold,
		resetTimeout: resetTimeout,
		state:        false,
	}
}

// Check checks if the circuit breaker allows requests
func (cb *CircuitBreaker) Check() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if !cb.state {
		return true
	}

	// Check if reset timeout has passed
	if time.Since(cb.lastFailure) >= cb.resetTimeout {
		return true // Allow retry after timeout
	}

	return false
}

// RecordFailure records a failure
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= int64(cb.threshold) {
		cb.state = true
	}
}

// RecordSuccess records a success
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Reset failures and state on success
	cb.failures = 0
	cb.state = false
}

// Reset resets the circuit breaker
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = false
	cb.lastFailure = time.Time{}
}

// EventStreamLayer implements Layer 6.5: Resource change event stream
// This layer provides event streaming capabilities for Solid notifications
// and integrates with the notification layer for event delivery.
//
// Key principles:
// - Privacy-safe event streaming (no sensitive data leakage)
// - Efficient event delivery with backpressure handling
// - Integration with notification and indexing layers
// - Policy-aware event filtering
// - Observability for event lag and dropped events
type EventStreamLayer struct {
	mu sync.RWMutex

	config EventStreamConfig

	// Hardening configuration
	hardeningConfig EventStreamHardeningConfig

	// Notification layer reference
	notificationLayer *NotificationLayer

	// Event buffer for streaming (separate from notification buffer)
	eventStreamBuffer []StreamEvent

	// Maximum event stream buffer size
	maxStreamBufferSize int

	// Stream subscribers
	streamSubscribers map[string]*StreamSubscriber

	// Event statistics and observability
	streamMetrics EventStreamMetrics

	// Rate limiter for event publishing
	eventRateLimiter *RateLimiter

	// Circuit breaker for event delivery
	circuitBreaker *CircuitBreaker

	// Global event counter for metrics
	globalEventCount int64

	// Logger
	logger *slog.Logger

	// Close state
	closeChan chan struct{}
	closed    bool
}

// EventStreamConfig holds configuration for the event stream layer
type EventStreamConfig struct {
	// MaxStreamBufferSize is the maximum number of events to buffer for streaming
	MaxStreamBufferSize int

	// EventRetentionTime is how long events are retained in the buffer
	EventRetentionTime time.Duration

	// MaxStreamSubscribers is the maximum number of stream subscribers
	MaxStreamSubscribers int

	// EnableObservability enables observability metrics
	EnableObservability bool

	// HardeningConfig contains security and reliability settings
	HardeningConfig EventStreamHardeningConfig

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultEventStreamConfig returns a safe default configuration
func DefaultEventStreamConfig() EventStreamConfig {
	return EventStreamConfig{
		MaxStreamBufferSize:  10000,
		EventRetentionTime:   24 * time.Hour,
		MaxStreamSubscribers: 1000,
		EnableObservability:  true,
		HardeningConfig:      DefaultEventStreamHardeningConfig(),
		Logger:               nil,
	}
}

// EventStreamMetrics holds metrics for the event stream layer
type EventStreamMetrics struct {
	mu sync.RWMutex

	// Event statistics
	TotalEventsAdded        int64
	TotalEventsStreamed     int64
	EventsDroppedDueToLimit int64

	// Subscriber statistics
	TotalSubscribers  int64
	ActiveSubscribers int64
	SubscriberErrors  int64

	// Performance metrics
	StreamLag           time.Duration
	LastStreamTime      time.Time
	AverageEventLatency time.Duration

	// Buffer statistics
	BufferHits   int64
	BufferMisses int64
}

// RecordEventAdded records an event being added to the stream
func (m *EventStreamMetrics) RecordEventAdded() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalEventsAdded++
	m.LastStreamTime = time.Now()
}

// RecordEventStreamed records an event being streamed
func (m *EventStreamMetrics) RecordEventStreamed(latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalEventsStreamed++
	m.AverageEventLatency = (m.AverageEventLatency*time.Duration(m.TotalEventsStreamed-1) + latency) / time.Duration(m.TotalEventsStreamed)
}

// RecordEventDropped records an event being dropped due to limits
func (m *EventStreamMetrics) RecordEventDropped() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsDroppedDueToLimit++
}

// RecordSubscriber records a subscriber event
func (m *EventStreamMetrics) RecordSubscriber(added bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if added {
		m.TotalSubscribers++
		m.ActiveSubscribers++
	} else {
		m.ActiveSubscribers--
	}
}

// RecordSubscriberError records a subscriber error
func (m *EventStreamMetrics) RecordSubscriberError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SubscriberErrors++
}

// StreamEvent represents an event in the event stream
// This is similar to NotificationEvent but optimized for streaming
type StreamEvent struct {
	// EventID is a unique identifier for this event
	EventID string

	// EventType is the type of event
	EventType NotificationEventType

	// ResourceURI is the URI of the affected resource
	ResourceURI string

	// ContainerURI is the URI of the container containing the resource
	ContainerURI string

	// Timestamp is when the event occurred
	Timestamp time.Time

	// Agent is the agent that caused the event (if applicable)
	Agent string

	// AgentType is the type of agent
	AgentType PolicyAgentType

	// Action is the specific action that occurred
	Action string

	// Metadata contains additional event metadata
	Metadata map[string]string

	// SequenceNumber is the sequence number for ordering
	SequenceNumber int64

	// StreamTimestamp is when the event was added to the stream
	StreamTimestamp time.Time

	// PrivacyLevel indicates the privacy sensitivity of this event
	PrivacyLevel PrivacyLevel
}

// PrivacyLevel indicates the privacy sensitivity of an event
type PrivacyLevel string

const (
	PrivacyLevelPublic    PrivacyLevel = "public"
	PrivacyLevelMetadata  PrivacyLevel = "metadata"
	PrivacyLevelSensitive PrivacyLevel = "sensitive"
	PrivacyLevelPrivate   PrivacyLevel = "private"
)

// StreamSubscriber represents a subscriber to the event stream
type StreamSubscriber struct {
	// SubscriberID is a unique identifier for this subscriber
	SubscriberID string

	// EventChannel is the channel for sending events
	EventChannel chan StreamEvent

	// Context is the context for this subscriber
	Context context.Context

	// Cancel is the cancel function for this subscriber
	Cancel context.CancelFunc

	// Filter is the subscriber's filter (optional)
	Filter StreamFilter

	// LastSent is when the last event was sent to this subscriber
	LastSent time.Time

	// Active indicates if the subscriber is still active
	Active bool

	// MinPrivacyLevel is the minimum privacy level this subscriber can see
	MinPrivacyLevel PrivacyLevel

	// WebID is the WebID of the subscriber (for authorization)
	WebID string
}

// StreamFilter represents a filter for stream events
type StreamFilter struct {
	// ResourceURIs are specific resource URIs to match
	ResourceURIs []string

	// ResourcePatterns are URI patterns to match
	ResourcePatterns []string

	// ContainerURIs are specific container URIs to match
	ContainerURIs []string

	// EventTypes are specific event types to match
	EventTypes []NotificationEventType

	// Agents are specific agents to match
	Agents []string

	// MinPrivacyLevel is the minimum privacy level to include
	MinPrivacyLevel PrivacyLevel

	// MaxPrivacyLevel is the maximum privacy level to include
	MaxPrivacyLevel PrivacyLevel
}

// NewEventStreamLayer creates a new event stream layer
func NewEventStreamLayer(config EventStreamConfig, notificationLayer *NotificationLayer) *EventStreamLayer {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	layer := &EventStreamLayer{
		config:              config,
		hardeningConfig:     config.HardeningConfig,
		notificationLayer:   notificationLayer,
		eventStreamBuffer:   make([]StreamEvent, 0, config.MaxStreamBufferSize),
		maxStreamBufferSize: config.MaxStreamBufferSize,
		streamSubscribers:   make(map[string]*StreamSubscriber),
		logger:              config.Logger,
		closeChan:           make(chan struct{}),
		closed:              false,
		streamMetrics:       EventStreamMetrics{},
	}

	// Initialize rate limiter if configured
	if config.HardeningConfig.MaxEventsPerSecond > 0 {
		layer.eventRateLimiter = NewRateLimiter(
			config.HardeningConfig.MaxEventsPerSecond,
			config.HardeningConfig.EventBurstLimit,
		)
	}

	// Initialize circuit breaker if configured
	if config.HardeningConfig.CircuitBreakerFailureThreshold > 0 {
		layer.circuitBreaker = NewCircuitBreaker(
			config.HardeningConfig.CircuitBreakerFailureThreshold,
			config.HardeningConfig.CircuitBreakerResetTimeout,
		)
	}

	// Set up event buffer cleanup
	if config.EventRetentionTime > 0 {
		go layer.eventBufferCleanup(config.EventRetentionTime)
	}

	// Set up subscriber cleanup for inactive subscribers
	if config.HardeningConfig.MaxSubscriberInactivityTime > 0 {
		go layer.subscriberCleanup(config.HardeningConfig.MaxSubscriberInactivityTime)
	}

	config.Logger.Info("Event stream layer initialized",
		"max_stream_buffer_size", config.MaxStreamBufferSize,
		"event_retention_time", config.EventRetentionTime,
		"max_stream_subscribers", config.MaxStreamSubscribers,
		"enable_observability", config.EnableObservability,
		"max_events_per_second", config.HardeningConfig.MaxEventsPerSecond,
		"event_burst_limit", config.HardeningConfig.EventBurstLimit,
		"circuit_breaker_enabled", config.HardeningConfig.CircuitBreakerFailureThreshold > 0,
	)

	return layer
}

// eventBufferCleanup periodically cleans up old events from the buffer
func (e *EventStreamLayer) eventBufferCleanup(retentionTime time.Duration) {
	ticker := time.NewTicker(5 * time.Minute) // Clean up every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.cleanOldEvents(retentionTime)
		case <-e.closeChan:
			e.logger.Info("Event stream buffer cleanup stopped")
			return
		}
	}
}

// cleanOldEvents removes events older than the retention time
func (e *EventStreamLayer) cleanOldEvents(retentionTime time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return
	}

	cutoff := time.Now().Add(-retentionTime)
	newBuffer := make([]StreamEvent, 0, len(e.eventStreamBuffer))

	for _, event := range e.eventStreamBuffer {
		if event.StreamTimestamp.After(cutoff) {
			newBuffer = append(newBuffer, event)
		}
	}

	if len(newBuffer) < len(e.eventStreamBuffer) {
		removed := len(e.eventStreamBuffer) - len(newBuffer)
		e.eventStreamBuffer = newBuffer
		e.logger.Debug("Cleaned up old events from stream buffer", "removed_count", removed)
	}
}

// subscriberCleanup periodically cleans up inactive subscribers
func (e *EventStreamLayer) subscriberCleanup(inactivityTime time.Duration) {
	ticker := time.NewTicker(5 * time.Minute) // Clean up every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.cleanInactiveSubscribers(inactivityTime)
		case <-e.closeChan:
			e.logger.Info("Event stream subscriber cleanup stopped")
			return
		}
	}
}

// cleanInactiveSubscribers removes subscribers that have been inactive too long
func (e *EventStreamLayer) cleanInactiveSubscribers(inactivityTime time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return
	}

	cutoff := time.Now().Add(-inactivityTime)

	for id, subscriber := range e.streamSubscribers {
		// Check if subscriber has been inactive too long
		if subscriber.LastSent.Before(cutoff) && !subscriber.LastSent.IsZero() {
			// Close and remove inactive subscriber
			close(subscriber.EventChannel)
			if subscriber.Cancel != nil {
				subscriber.Cancel()
			}
			delete(e.streamSubscribers, id)

			if e.config.EnableObservability {
				e.streamMetrics.RecordSubscriber(false)
			}

			e.logger.Debug("Cleaned up inactive subscriber", "subscriber_id", id)
		}
	}
}

// GetGlobalEventCount returns the current global event count
func (e *EventStreamLayer) GetGlobalEventCount() int64 {
	return atomic.LoadInt64(&e.globalEventCount)
}

// ResetCircuitBreaker resets the circuit breaker (for testing or manual intervention)
func (e *EventStreamLayer) ResetCircuitBreaker() {
	if e.circuitBreaker != nil {
		e.circuitBreaker.Reset()
	}
}

// AddEvent adds an event to the event stream with hardening protections
func (e *EventStreamLayer) AddEvent(event StreamEvent) error {
	// Check if layer is closed
	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return ErrEventStreamClosed
	}
	e.mu.RUnlock()

	// Validate event data with comprehensive checks
	if err := ValidateURI(event.ResourceURI); err != nil {
		return fmt.Errorf("%w: invalid resource URI: %v", ErrInvalidEventData, err)
	}

	if event.ContainerURI != "" {
		if err := ValidateContainerURI(event.ContainerURI); err != nil {
			return fmt.Errorf("%w: invalid container URI: %v", ErrInvalidEventData, err)
		}
	}

	// Validate event type
	if !isValidNotificationEventType(event.EventType) {
		return fmt.Errorf("%w: invalid event type: %s", ErrInvalidEventData, event.EventType)
	}

	// Validate agent if present
	if event.Agent != "" {
		if err := ValidateWebID(event.Agent); err != nil {
			return fmt.Errorf("%w: invalid agent WebID: %v", ErrInvalidEventData, err)
		}
	}

	// Validate metadata with hardening limits
	if len(event.Metadata) > e.hardeningConfig.MaxMetadataKeys {
		return fmt.Errorf("%w: metadata exceeds maximum keys limit (%d)", ErrInvalidEventData, e.hardeningConfig.MaxMetadataKeys)
	}

	for key, value := range event.Metadata {
		// Validate metadata key
		if len(key) > e.hardeningConfig.MaxMetadataKeyLength {
			return fmt.Errorf("%w: metadata key exceeds maximum length (%d)", ErrInvalidEventData, e.hardeningConfig.MaxMetadataKeyLength)
		}

		// Validate metadata value
		if len(value) > e.hardeningConfig.MaxMetadataValueLength {
			return fmt.Errorf("%w: metadata value exceeds maximum length (%d)", ErrInvalidEventData, e.hardeningConfig.MaxMetadataValueLength)
		}

		// Validate metadata characters (prevent injection attacks)
		for _, r := range key {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("%w: metadata key contains control characters", ErrInvalidEventData)
			}
		}
		for _, r := range value {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("%w: metadata value contains control characters", ErrInvalidEventData)
			}
		}

		// Check for sensitive keys that shouldn't be in metadata
		if isSensitiveMetadataKey(key) {
			e.logger.Warn("Sensitive metadata key detected and blocked", "key", key)
			return fmt.Errorf("%w: sensitive metadata key not allowed", ErrInvalidEventData)
		}
	}

	// Check total metadata size
	var totalMetadataSize int
	for key, value := range event.Metadata {
		totalMetadataSize += len(key) + len(value)
	}
	if totalMetadataSize > e.hardeningConfig.MaxMetadataSize {
		return fmt.Errorf("%w: total metadata size exceeds limit (%d bytes)", ErrInvalidEventData, e.hardeningConfig.MaxMetadataSize)
	}

	// Check rate limiting
	if e.eventRateLimiter != nil && !e.eventRateLimiter.Allow() {
		if e.config.EnableObservability {
			e.streamMetrics.RecordEventDropped()
		}
		return fmt.Errorf("%w: event rate limit exceeded", ErrRateLimitExceeded)
	}

	// Check circuit breaker
	if e.circuitBreaker != nil && !e.circuitBreaker.Check() {
		if e.config.EnableObservability {
			e.streamMetrics.RecordEventDropped()
		}
		return fmt.Errorf("%w: circuit breaker is open", ErrCircuitBreakerOpen)
	}

	// Validate privacy level
	if event.PrivacyLevel == "" {
		event.PrivacyLevel = PrivacyLevelMetadata // Default privacy level
	} else {
		// Validate it's a known privacy level
		validPrivacyLevels := []PrivacyLevel{
			PrivacyLevelPublic,
			PrivacyLevelMetadata,
			PrivacyLevelSensitive,
			PrivacyLevelPrivate,
		}
		valid := false
		for _, level := range validPrivacyLevels {
			if event.PrivacyLevel == level {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("%w: %s", ErrInvalidPrivacyLevel, event.PrivacyLevel)
		}
	}

	// Set timestamps if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.StreamTimestamp.IsZero() {
		event.StreamTimestamp = time.Now().UTC()
	}

	// Assign event ID if not set
	if event.EventID == "" {
		event.EventID = generateStreamEventID()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check closed state (in case it changed between RLock and Lock)
	if e.closed {
		return ErrEventStreamClosed
	}

	// Add to buffer
	e.eventStreamBuffer = append(e.eventStreamBuffer, event)

	// Increment global event counter
	atomic.AddInt64(&e.globalEventCount, 1)

	// Check buffer size with hardening
	if len(e.eventStreamBuffer) > e.maxStreamBufferSize {
		// Remove oldest event
		e.eventStreamBuffer = e.eventStreamBuffer[1:]
		if e.config.EnableObservability {
			e.streamMetrics.RecordEventDropped()
		}
	}

	if e.config.EnableObservability {
		e.streamMetrics.RecordEventAdded()
	}

	// Log the event
	e.logger.Debug("Event added to stream",
		"event_id", event.EventID,
		"event_type", event.EventType,
		"resource_uri", event.ResourceURI,
		"privacy_level", event.PrivacyLevel,
	)

	// Deliver to subscribers immediately
	go e.deliverToStreamSubscribers(event)

	return nil
}

// deliverToStreamSubscribers delivers an event to all matching stream subscribers
func (e *EventStreamLayer) deliverToStreamSubscribers(event StreamEvent) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return
	}

	startTime := time.Now()

	for _, subscriber := range e.streamSubscribers {
		if !subscriber.Active {
			continue
		}

		// Check if event matches subscriber filter
		if !e.eventMatchesStreamFilter(&event, &subscriber.Filter) {
			continue
		}

		// Check privacy level
		if event.PrivacyLevel < subscriber.MinPrivacyLevel {
			continue // Event privacy level is too restrictive
		}

		// Check if subscriber can access this event based on WebID
		if subscriber.WebID != "" && event.Agent != "" && subscriber.WebID != event.Agent {
			// For simplicity, we allow all events through for now
			// In a real implementation, you'd check authorization here
			continue
		}

		// Try to send the event
		select {
		case subscriber.EventChannel <- event:
			if e.config.EnableObservability {
				latency := time.Since(startTime)
				e.streamMetrics.RecordEventStreamed(latency)
			}
			subscriber.LastSent = time.Now()
		case <-subscriber.Context.Done():
			// Subscriber context cancelled
			subscriber.Active = false
			if e.config.EnableObservability {
				e.streamMetrics.RecordSubscriberError()
			}
		case <-e.closeChan:
			// Event stream layer closed
			return
		}
	}
}

// eventMatchesStreamFilter checks if an event matches a stream filter
func (e *EventStreamLayer) eventMatchesStreamFilter(event *StreamEvent, filter *StreamFilter) bool {
	if filter == nil {
		return true // No filter means all events match
	}

	// Check event types
	if len(filter.EventTypes) > 0 {
		matches := false
		for _, eventType := range filter.EventTypes {
			if eventType == event.EventType {
				matches = true
				break
			}
		}
		if !matches {
			return false
		}
	}

	// Check privacy level range
	if filter.MinPrivacyLevel != "" && event.PrivacyLevel < filter.MinPrivacyLevel {
		return false
	}
	if filter.MaxPrivacyLevel != "" && event.PrivacyLevel > filter.MaxPrivacyLevel {
		return false
	}

	// Check resource URIs
	if len(filter.ResourceURIs) > 0 {
		matches := false
		for _, uri := range filter.ResourceURIs {
			if uri == event.ResourceURI {
				matches = true
				break
			}
		}
		if !matches {
			return false
		}
	}

	// Check resource patterns
	if len(filter.ResourcePatterns) > 0 {
		matches := false
		for _, pattern := range filter.ResourcePatterns {
			// Simple pattern matching
			if len(pattern) > 0 && len(event.ResourceURI) >= len(pattern) {
				if event.ResourceURI[:len(pattern)] == pattern {
					matches = true
					break
				}
			}
		}
		if !matches {
			return false
		}
	}

	// Check container URIs
	if len(filter.ContainerURIs) > 0 {
		matches := false
		for _, uri := range filter.ContainerURIs {
			if uri == event.ContainerURI {
				matches = true
				break
			}
		}
		if !matches {
			return false
		}
	}

	// Check agents
	if len(filter.Agents) > 0 {
		matches := false
		for _, agent := range filter.Agents {
			if agent == event.Agent {
				matches = true
				break
			}
		}
		if !matches {
			return false
		}
	}

	return true
}

// isValidPrivacyLevel checks if a privacy level is valid
func isValidPrivacyLevel(level PrivacyLevel) bool {
	validLevels := []PrivacyLevel{
		PrivacyLevelPublic,
		PrivacyLevelMetadata,
		PrivacyLevelSensitive,
		PrivacyLevelPrivate,
	}

	for _, validLevel := range validLevels {
		if level == validLevel {
			return true
		}
	}
	return false
}

// Subscribe subscribes to the event stream with hardening protections
func (e *EventStreamLayer) Subscribe(ctx context.Context, filter StreamFilter, webID string, minPrivacyLevel PrivacyLevel) (*StreamSubscriber, error) {
	// Check if layer is closed first
	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return nil, ErrEventStreamClosed
	}
	e.mu.RUnlock()

	// Validate filter with comprehensive checks
	if len(filter.ResourceURIs) > e.hardeningConfig.MaxMetadataKeys {
		return nil, fmt.Errorf("%w: too many resource URIs in filter (%d max)", ErrInvalidEventData, e.hardeningConfig.MaxMetadataKeys)
	}

	for _, uri := range filter.ResourceURIs {
		if err := ValidateURI(uri); err != nil {
			return nil, fmt.Errorf("%w: invalid resource URI in filter: %v", ErrInvalidEventData, err)
		}
	}

	for _, uri := range filter.ContainerURIs {
		if err := ValidateContainerURI(uri); err != nil {
			return nil, fmt.Errorf("%w: invalid container URI in filter: %v", ErrInvalidEventData, err)
		}
	}

	for _, eventType := range filter.EventTypes {
		if !isValidNotificationEventType(eventType) {
			return nil, fmt.Errorf("%w: invalid event type in filter: %s", ErrInvalidEventData, eventType)
		}
	}

	// Validate privacy level range
	if filter.MinPrivacyLevel != "" && filter.MaxPrivacyLevel != "" {
		if filter.MinPrivacyLevel > filter.MaxPrivacyLevel {
			return nil, fmt.Errorf("%w: min privacy level cannot be greater than max privacy level", ErrInvalidPrivacyLevel)
		}
	}

	// Validate privacy levels if provided
	if filter.MinPrivacyLevel != "" {
		if !isValidPrivacyLevel(filter.MinPrivacyLevel) {
			return nil, fmt.Errorf("%w: invalid min privacy level: %s", ErrInvalidPrivacyLevel, filter.MinPrivacyLevel)
		}
	}
	if filter.MaxPrivacyLevel != "" {
		if !isValidPrivacyLevel(filter.MaxPrivacyLevel) {
			return nil, fmt.Errorf("%w: invalid max privacy level: %s", ErrInvalidPrivacyLevel, filter.MaxPrivacyLevel)
		}
	}

	// Validate WebID if provided
	if webID != "" {
		if err := ValidateWebID(webID); err != nil {
			return nil, fmt.Errorf("%w: invalid WebID: %v", ErrInvalidEventData, err)
		}
	}

	// Validate minPrivacyLevel parameter
	if !isValidPrivacyLevel(minPrivacyLevel) {
		return nil, fmt.Errorf("%w: invalid minPrivacyLevel parameter: %s", ErrInvalidPrivacyLevel, minPrivacyLevel)
	}

	// Validate context
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context provided", ErrInvalidEventData)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check closed state (in case it changed between RLock and Lock)
	if e.closed {
		return nil, ErrEventStreamClosed
	}

	// Check subscriber limit with circuit breaker check
	if len(e.streamSubscribers) >= e.config.MaxStreamSubscribers {
		if e.circuitBreaker != nil {
			e.circuitBreaker.RecordFailure()
		}
		return nil, ErrSubscriberLimitReached
	}

	// Create subscriber with hardened buffer size
	bufferSize := e.hardeningConfig.MaxSubscriberBufferSize
	if bufferSize <= 0 {
		bufferSize = 100 // Default buffer size
	}

	subscriber := &StreamSubscriber{
		SubscriberID:    generateStreamSubscriberID(),
		EventChannel:    make(chan StreamEvent, bufferSize), // Buffered channel with size limit
		Context:         ctx,
		Filter:          filter,
		Active:          true,
		MinPrivacyLevel: minPrivacyLevel,
		WebID:           webID,
	}

	// Create context with timeout
	ctx, cancel := context.WithCancel(ctx)
	subscriber.Cancel = cancel

	// Add to subscribers
	e.streamSubscribers[subscriber.SubscriberID] = subscriber

	if e.config.EnableObservability {
		e.streamMetrics.RecordSubscriber(true)
	}

	e.logger.Info("New stream subscriber added",
		"subscriber_id", subscriber.SubscriberID,
		"webid", webID,
		"min_privacy_level", minPrivacyLevel,
	)

	// Send recent events to new subscriber if requested
	go func() {
		// Send the last 100 events to catch up
		recentEvents := e.getRecentEvents(100)
		for _, event := range recentEvents {
			if e.eventMatchesStreamFilter(&event, &filter) && event.PrivacyLevel >= minPrivacyLevel {
				select {
				case subscriber.EventChannel <- event:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return subscriber, nil
}

// getRecentEvents returns the most recent events from the buffer
func (e *EventStreamLayer) getRecentEvents(count int) []StreamEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return []StreamEvent{}
	}

	if count <= 0 {
		return []StreamEvent{}
	}

	// Return the last 'count' events
	startIndex := 0
	if len(e.eventStreamBuffer) > count {
		startIndex = len(e.eventStreamBuffer) - count
	}

	recentEvents := make([]StreamEvent, 0, count)
	for i := startIndex; i < len(e.eventStreamBuffer); i++ {
		recentEvents = append(recentEvents, e.eventStreamBuffer[i])
	}

	return recentEvents
}

// Unsubscribe unsubscribes from the event stream
func (e *EventStreamLayer) Unsubscribe(subscriber *StreamSubscriber) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return errors.New("event stream layer is closed")
	}

	if subscriber == nil {
		return errors.New("subscriber cannot be nil")
	}

	// Find and remove the subscriber
	if existing, exists := e.streamSubscribers[subscriber.SubscriberID]; exists {
		// Close the channel
		close(existing.EventChannel)

		// Cancel the context
		if existing.Cancel != nil {
			existing.Cancel()
		}

		// Remove from map
		delete(e.streamSubscribers, subscriber.SubscriberID)

		if e.config.EnableObservability {
			e.streamMetrics.RecordSubscriber(false)
		}

		e.logger.Info("Stream subscriber removed", "subscriber_id", subscriber.SubscriberID)
		return nil
	}

	return fmt.Errorf("subscriber %s not found", subscriber.SubscriberID)
}

// GetMetrics returns the current metrics
func (e *EventStreamLayer) GetMetrics() *EventStreamMetrics {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return &e.streamMetrics
}

// Size returns the current number of subscribers and buffered events
func (e *EventStreamLayer) Size() (int, int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.streamSubscribers), len(e.eventStreamBuffer)
}

// Close closes the event stream layer
func (e *EventStreamLayer) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil
	}

	e.closed = true
	close(e.closeChan)

	// Close all subscribers
	for _, subscriber := range e.streamSubscribers {
		close(subscriber.EventChannel)
		if subscriber.Cancel != nil {
			subscriber.Cancel()
		}
	}

	// Clear buffers and subscribers
	e.eventStreamBuffer = nil
	e.streamSubscribers = nil

	e.logger.Info("Event stream layer closed")
	return nil
}

// IsClosed returns true if the layer is closed
func (e *EventStreamLayer) IsClosed() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.closed
}

// ConvertNotificationToStreamEvent converts a NotificationEvent to a StreamEvent
func ConvertNotificationToStreamEvent(notificationEvent NotificationEvent) StreamEvent {
	return StreamEvent{
		EventID:         notificationEvent.EventID,
		EventType:       notificationEvent.EventType,
		ResourceURI:     notificationEvent.ResourceURI,
		ContainerURI:    notificationEvent.ContainerURI,
		Timestamp:       notificationEvent.Timestamp,
		Agent:           notificationEvent.Agent,
		AgentType:       notificationEvent.AgentType,
		Action:          notificationEvent.Action,
		Metadata:        notificationEvent.Metadata,
		SequenceNumber:  notificationEvent.SequenceNumber,
		StreamTimestamp: time.Now().UTC(),
		PrivacyLevel:    determinePrivacyLevel(notificationEvent),
	}
}

// determinePrivacyLevel determines the privacy level for an event
func determinePrivacyLevel(event NotificationEvent) PrivacyLevel {
	// For now, we use metadata to determine privacy level
	// In a real implementation, this would be based on resource policies
	if privacy, ok := event.Metadata["privacy-level"]; ok {
		switch privacy {
		case "public":
			return PrivacyLevelPublic
		case "metadata":
			return PrivacyLevelMetadata
		case "sensitive":
			return PrivacyLevelSensitive
		case "private":
			return PrivacyLevelPrivate
		}
	}

	// Default to metadata level for most events
	return PrivacyLevelMetadata
}

// generateStreamEventID generates a unique event ID for stream events
func generateStreamEventID() string {
	return fmt.Sprintf("stream-%d", time.Now().UnixNano())
}

// generateStreamSubscriberID generates a unique subscriber ID for stream subscribers
func generateStreamSubscriberID() string {
	return fmt.Sprintf("stream-sub-%d", time.Now().UnixNano())
}

// EventStreamAsJSON serializes an event to JSON for WebSocket/SSE delivery
func EventStreamAsJSON(event StreamEvent) (string, error) {
	// Create a JSON-safe version of the event
	jsonEvent := map[string]interface{}{
		"event_id":         event.EventID,
		"event_type":       string(event.EventType),
		"resource_uri":     event.ResourceURI,
		"container_uri":    event.ContainerURI,
		"timestamp":        event.Timestamp.Format(time.RFC3339),
		"agent":            event.Agent,
		"agent_type":       string(event.AgentType),
		"action":           event.Action,
		"sequence_number":  event.SequenceNumber,
		"stream_timestamp": event.StreamTimestamp.Format(time.RFC3339),
		"privacy_level":    string(event.PrivacyLevel),
	}

	// Add metadata (filter out any sensitive fields)
	if len(event.Metadata) > 0 {
		safeMetadata := make(map[string]string)
		for key, value := range event.Metadata {
			// Skip sensitive metadata
			if !isSensitiveMetadataKey(key) {
				safeMetadata[key] = value
			}
		}
		if len(safeMetadata) > 0 {
			jsonEvent["metadata"] = safeMetadata
		}
	}

	jsonBytes, err := json.Marshal(jsonEvent)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event to JSON: %w", err)
	}

	return string(jsonBytes), nil
}

// isSensitiveMetadataKey checks if a metadata key contains sensitive information
func isSensitiveMetadataKey(key string) bool {
	sensitiveKeys := []string{
		"authorization",
		"token",
		"password",
		"secret",
		"private",
		"credential",
		"api_key",
		"access_token",
		"refresh_token",
	}

	keyLower := strings.ToLower(key)
	for _, sensitiveKey := range sensitiveKeys {
		if strings.Contains(keyLower, sensitiveKey) {
			return true
		}
	}
	return false
}
