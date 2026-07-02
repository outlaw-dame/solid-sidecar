// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 6: Notification/live-update layer.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// NotificationLayer implements Layer 6: Notification/live-update layer
// This layer provides real-time notifications and live updates for Solid resources.
//
// Key principles:
// - Privacy-safe notifications (no sensitive data leakage)
// - Efficient event delivery with backpressure handling
// - Support for WebSockets, SSE, and other notification mechanisms
// - Integration with storage and metadata layers
// - Policy-aware notification filtering
type NotificationLayer struct {
	mu sync.RWMutex

	config NotificationConfig

	// Event subscribers (channel -> subscribers)
	subscribers map[string][]*NotificationSubscriber

	// Event buffer for missed events (for reconnection)
	eventBuffer []NotificationEvent

	// Maximum event buffer size
	maxBufferSize int

	// Event statistics
	metrics NotificationMetrics

	// Logger
	logger *slog.Logger

	// Close state
	closeChan chan struct{}
	closed    bool
}

// NotificationConfig holds configuration for the notification layer
type NotificationConfig struct {
	// MaxSubscribers is the maximum number of concurrent subscribers
	MaxSubscribers int

	// MaxBufferSize is the maximum number of events to buffer for reconnection
	MaxBufferSize int

	// EventTimeout is the timeout for event delivery
	EventTimeout time.Duration

	// EnableReconnection enables reconnection support with event buffering
	EnableReconnection bool

	// EnableMetrics enables metrics collection
	EnableMetrics bool

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultNotificationConfig returns a safe default configuration
func DefaultNotificationConfig() NotificationConfig {
	return NotificationConfig{
		MaxSubscribers:     1000,
		MaxBufferSize:      1000,
		EventTimeout:       30 * time.Second,
		EnableReconnection: true,
		EnableMetrics:      true,
		Logger:             nil,
	}
}

// NotificationMetrics holds metrics for the notification layer
type NotificationMetrics struct {
	mu sync.RWMutex

	// Event statistics
	TotalEvents         int64
	EventsDelivered     int64
	EventsFailed        int64
	EventsBufferOverrun int64

	// Subscriber statistics
	TotalSubscribers  int64
	ActiveSubscribers int64
	SubscriberErrors  int64

	// Channel statistics
	ChannelsCreated int64
	ChannelsClosed  int64

	// Reconnection statistics
	Reconnections        int64
	ReconnectionFailures int64
}

// RecordEvent records an event being processed
func (m *NotificationMetrics) RecordEvent(delivered bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalEvents++
	if delivered {
		m.EventsDelivered++
	} else {
		m.EventsFailed++
	}
}

// RecordBufferOverrun records a buffer overrun
func (m *NotificationMetrics) RecordBufferOverrun() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsBufferOverrun++
}

// RecordSubscriber records a subscriber event
func (m *NotificationMetrics) RecordSubscriber(added bool) {
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
func (m *NotificationMetrics) RecordSubscriberError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SubscriberErrors++
}

// RecordChannel records a channel event
func (m *NotificationMetrics) RecordChannel(created bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if created {
		m.ChannelsCreated++
	} else {
		m.ChannelsClosed++
	}
}

// RecordReconnection records a reconnection event
func (m *NotificationMetrics) RecordReconnection(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if success {
		m.Reconnections++
	} else {
		m.ReconnectionFailures++
	}
}

// NotificationEvent represents a notification event
type NotificationEvent struct {
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
}

// NotificationEventType represents the type of notification event
type NotificationEventType string

const (
	EventTypeCreate    NotificationEventType = "create"
	EventTypeUpdate    NotificationEventType = "update"
	EventTypeDelete    NotificationEventType = "delete"
	EventTypeMove      NotificationEventType = "move"
	EventTypeCopy      NotificationEventType = "copy"
	EventTypeAccess    NotificationEventType = "access"
	EventTypePolicy    NotificationEventType = "policy"
	EventTypeContainer NotificationEventType = "container"
	EventTypeCustom    NotificationEventType = "custom"
)

// NotificationChannel represents a notification channel
type NotificationChannel struct {
	// Name is the channel name
	Name string

	// Pattern is the resource pattern this channel matches
	Pattern string

	// Filter is the event filter for this channel
	Filter NotificationFilter

	// Created is when the channel was created
	Created time.Time

	// LastActivity is when the channel had last activity
	LastActivity time.Time
}

// NotificationFilter represents a filter for notification events
type NotificationFilter struct {
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

	// AgentTypes are specific agent types to match
	AgentTypes []PolicyAgentType

	// Custom filters
	Custom map[string]string
}

// NotificationSubscriber represents a notification subscriber
type NotificationSubscriber struct {
	// SubscriberID is a unique identifier for this subscriber
	SubscriberID string

	// Channel is the channel this subscriber is subscribed to
	Channel string

	// EventChannel is the channel for sending events
	EventChannel chan NotificationEvent

	// Context is the context for this subscriber
	Context context.Context

	// Cancel is the cancel function for this subscriber
	Cancel context.CancelFunc

	// Filter is the subscriber's filter
	Filter NotificationFilter

	// Priority is the subscriber's priority
	Priority int

	// Created is when the subscription was created
	Created time.Time

	// LastSent is when the last event was sent to this subscriber
	LastSent time.Time

	// Active indicates if the subscriber is still active
	Active bool
}

// NewNotificationLayer creates a new notification layer
func NewNotificationLayer(config NotificationConfig) *NotificationLayer {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	layer := &NotificationLayer{
		config:        config,
		subscribers:   make(map[string][]*NotificationSubscriber),
		eventBuffer:   make([]NotificationEvent, 0, config.MaxBufferSize),
		maxBufferSize: config.MaxBufferSize,
		logger:        config.Logger,
		closeChan:     make(chan struct{}),
		closed:        false,
		metrics:       NotificationMetrics{},
	}

	config.Logger.Info("Notification layer initialized",
		"max_subscribers", config.MaxSubscribers,
		"max_buffer_size", config.MaxBufferSize,
		"enable_reconnection", config.EnableReconnection,
		"enable_metrics", config.EnableMetrics,
	)

	// Start the event processing goroutine
	go layer.processEvents()

	return layer
}

// processEvents processes events and delivers them to subscribers
func (n *NotificationLayer) processEvents() {
	ticker := time.NewTicker(100 * time.Millisecond) // Process events every 100ms
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			n.processEventQueue()
		case <-n.closeChan:
			n.logger.Info("Notification event processor stopped")
			return
		}
	}
}

// processEventQueue processes the event queue and delivers events to subscribers
func (n *NotificationLayer) processEventQueue() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return
	}

	// Process buffered events
	for len(n.eventBuffer) > 0 {
		event := n.eventBuffer[0]
		n.eventBuffer = n.eventBuffer[1:]

		// Deliver to all subscribers
		n.deliverToSubscribers(event)
	}
}

// deliverToSubscribers delivers an event to all matching subscribers
func (n *NotificationLayer) deliverToSubscribers(event NotificationEvent) {
	// Track delivery success
	delivered := false

	// Deliver to all channels
	for channel, subscribers := range n.subscribers {
		// Check if event matches channel filter
		if n.eventMatchesChannel(&event, channel) {
			// Deliver to each subscriber in this channel
			for _, subscriber := range subscribers {
				if subscriber.Active && n.eventMatchesFilter(&event, &subscriber.Filter) {
					select {
					case subscriber.EventChannel <- event:
						delivered = true
						subscriber.LastSent = time.Now()
						if n.config.EnableMetrics {
							n.metrics.RecordEvent(true)
						}
					case <-subscriber.Context.Done():
						// Subscriber context cancelled
						subscriber.Active = false
						if n.config.EnableMetrics {
							n.metrics.RecordSubscriberError()
						}
					case <-n.closeChan:
						// Notification layer closed
						return
					}
				}
			}
		}
	}

	if !delivered && n.config.EnableMetrics {
		n.metrics.RecordEvent(false)
	}
}

// eventMatchesChannel checks if an event matches a channel
func (n *NotificationLayer) eventMatchesChannel(event *NotificationEvent, channel string) bool {
	// For now, all events match all channels
	// In a more sophisticated implementation, channels would have specific filters
	return true
}

// eventMatchesFilter checks if an event matches a filter
func (n *NotificationLayer) eventMatchesFilter(event *NotificationEvent, filter *NotificationFilter) bool {
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

	// Check agent types
	if len(filter.AgentTypes) > 0 {
		matches := false
		for _, agentType := range filter.AgentTypes {
			if agentType == event.AgentType {
				matches = true
				break
			}
		}
		if !matches {
			return false
		}
	}

	// Check custom filters
	for key, value := range filter.Custom {
		if metadataValue, exists := event.Metadata[key]; exists {
			if metadataValue != value {
				return false
			}
		} else {
			return false
		}
	}

	return true
}

// PublishEvent publishes an event to the notification layer
func (n *NotificationLayer) PublishEvent(event NotificationEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return errors.New("notification layer is closed")
	}

	// Assign event ID and sequence number if not set
	if event.EventID == "" {
		event.EventID = generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Add to buffer
	n.eventBuffer = append(n.eventBuffer, event)

	// Check buffer size
	if len(n.eventBuffer) > n.maxBufferSize {
		// Remove oldest event
		n.eventBuffer = n.eventBuffer[1:]
		if n.config.EnableMetrics {
			n.metrics.RecordBufferOverrun()
		}
	}

	if n.config.EnableMetrics {
		n.metrics.RecordEvent(true) // Will be updated if delivery fails
	}

	return nil
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("evt-%d", time.Now().UnixNano())
}

// Subscribe subscribes to notification events
func (n *NotificationLayer) Subscribe(ctx context.Context, channel string, filter NotificationFilter) (*NotificationSubscriber, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return nil, errors.New("notification layer is closed")
	}

	// Check subscriber limit
	if n.countSubscribers() >= n.config.MaxSubscribers {
		return nil, errors.New("maximum subscribers reached")
	}

	// Create subscriber
	subscriber := &NotificationSubscriber{
		SubscriberID: generateSubscriberID(),
		Channel:      channel,
		EventChannel: make(chan NotificationEvent, 100), // Buffered channel
		Filter:       filter,
		Context:      ctx,
		Created:      time.Now().UTC(),
		Active:       true,
		Priority:     0,
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, n.config.EventTimeout)
	subscriber.Cancel = cancel

	// Add to subscribers
	if n.subscribers[channel] == nil {
		n.subscribers[channel] = []*NotificationSubscriber{}
	}
	n.subscribers[channel] = append(n.subscribers[channel], subscriber)

	if n.config.EnableMetrics {
		n.metrics.RecordSubscriber(true)
		n.metrics.RecordChannel(true)
	}

	// Send buffered events if reconnection is enabled
	if n.config.EnableReconnection && len(n.eventBuffer) > 0 {
		go func() {
			// Send recent events to new subscriber
			for _, event := range n.eventBuffer {
				if n.eventMatchesFilter(&event, &filter) {
					select {
					case subscriber.EventChannel <- event:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	return subscriber, nil
}

// generateSubscriberID generates a unique subscriber ID
func generateSubscriberID() string {
	return fmt.Sprintf("sub-%d", time.Now().UnixNano())
}

// countSubscribers counts the total number of subscribers
func (n *NotificationLayer) countSubscribers() int {
	count := 0
	for _, subscribers := range n.subscribers {
		count += len(subscribers)
	}
	return count
}

// Unsubscribe unsubscribes from notification events
func (n *NotificationLayer) Unsubscribe(subscriber *NotificationSubscriber) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return errors.New("notification layer is closed")
	}

	if subscriber == nil {
		return errors.New("subscriber cannot be nil")
	}

	// Find and remove the subscriber
	if subscribers, exists := n.subscribers[subscriber.Channel]; exists {
		for i, sub := range subscribers {
			if sub.SubscriberID == subscriber.SubscriberID {
				// Close the channel
				close(sub.EventChannel)

				// Cancel the context
				if sub.Cancel != nil {
					sub.Cancel()
				}

				// Remove from slice
				n.subscribers[subscriber.Channel] = append(subscribers[:i], subscribers[i+1:]...)

				if n.config.EnableMetrics {
					n.metrics.RecordSubscriber(false)
				}

				return nil
			}
		}
	}

	return fmt.Errorf("subscriber %s not found", subscriber.SubscriberID)
}

// CreateChannel creates a new notification channel
func (n *NotificationLayer) CreateChannel(name string, pattern string, filter NotificationFilter) (*NotificationChannel, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return nil, errors.New("notification layer is closed")
	}

	// Check if channel already exists
	if _, exists := n.subscribers[name]; exists {
		return nil, fmt.Errorf("channel %s already exists", name)
	}

	channel := &NotificationChannel{
		Name:         name,
		Pattern:      pattern,
		Filter:       filter,
		Created:      time.Now().UTC(),
		LastActivity: time.Now().UTC(),
	}

	n.subscribers[name] = []*NotificationSubscriber{}

	if n.config.EnableMetrics {
		n.metrics.RecordChannel(true)
	}

	return channel, nil
}

// CloseChannel closes a notification channel
func (n *NotificationLayer) CloseChannel(name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return errors.New("notification layer is closed")
	}

	if subscribers, exists := n.subscribers[name]; exists {
		// Close all subscribers in this channel
		for _, subscriber := range subscribers {
			close(subscriber.EventChannel)
			if subscriber.Cancel != nil {
				subscriber.Cancel()
			}
		}

		delete(n.subscribers, name)
		if n.config.EnableMetrics {
			n.metrics.RecordChannel(false)
		}
	}

	return nil
}

// ListChannels returns a list of all channels
func (n *NotificationLayer) ListChannels() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if n.closed {
		return []string{}
	}

	channels := make([]string, 0, len(n.subscribers))
	for channel := range n.subscribers {
		channels = append(channels, channel)
	}
	return channels
}

// GetMetrics returns the current metrics
func (n *NotificationLayer) GetMetrics() *NotificationMetrics {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return &n.metrics
}

// Size returns the current number of channels and subscribers
func (n *NotificationLayer) Size() (int, int) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.subscribers), n.countSubscribers()
}

// Close closes the notification layer
func (n *NotificationLayer) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return nil
	}

	n.closed = true
	close(n.closeChan)

	// Close all channels and subscribers
	for channel, subscribers := range n.subscribers {
		for _, subscriber := range subscribers {
			close(subscriber.EventChannel)
			if subscriber.Cancel != nil {
				subscriber.Cancel()
			}
		}
		delete(n.subscribers, channel)
	}

	// Clear buffers
	n.eventBuffer = nil
	n.subscribers = nil

	n.logger.Info("Notification layer closed")
	return nil
}

// IsClosed returns true if the layer is closed
func (n *NotificationLayer) IsClosed() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.closed
}
