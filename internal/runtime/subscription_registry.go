// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 6.7: Subscription registry with authentication and authorization for Phase 24.
package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ErrSubscriptionNotFound is returned when a subscription is not found
var ErrSubscriptionNotFound = errors.New("subscription not found")

// ErrSubscriptionAlreadyExists is returned when trying to create a duplicate subscription
var ErrSubscriptionAlreadyExists = errors.New("subscription already exists")

// ErrAuthenticationRequired is returned when authentication is required
var ErrAuthenticationRequired = errors.New("authentication required")

// ErrInvalidSubscriptionFilter is returned when a subscription filter is invalid
var ErrInvalidSubscriptionFilter = errors.New("invalid subscription filter")

// ErrMaxSubscriptionsReached is returned when the maximum number of subscriptions is reached
var ErrMaxSubscriptionsReached = errors.New("maximum subscriptions reached")

// SubscriptionRegistryConfig holds configuration for the subscription registry
type SubscriptionRegistryConfig struct {
	// MaxSubscriptions is the maximum number of active subscriptions
	MaxSubscriptions int

	// MaxSubscriptionsPerWebID is the maximum number of subscriptions per WebID
	MaxSubscriptionsPerWebID int

	// MaxSubscriptionAge is the maximum age of a subscription before it's considered stale
	MaxSubscriptionAge time.Duration

	// SubscriptionTimeout is the timeout for subscription operations
	SubscriptionTimeout time.Duration

	// EnableBackpressure enables backpressure handling
	EnableBackpressure bool

	// MaxBackpressureBufferSize is the maximum buffer size for backpressure
	MaxBackpressureBufferSize int

	// EnableMetrics enables metrics collection
	EnableMetrics bool

	// Logger is the logger for this component
	Logger *slog.Logger
}

// DefaultSubscriptionRegistryConfig returns a safe default configuration
func DefaultSubscriptionRegistryConfig() SubscriptionRegistryConfig {
	return SubscriptionRegistryConfig{
		MaxSubscriptions:          10000,
		MaxSubscriptionsPerWebID:  100,
		MaxSubscriptionAge:        24 * time.Hour,
		SubscriptionTimeout:       30 * time.Second,
		EnableBackpressure:        true,
		MaxBackpressureBufferSize: 1000,
		EnableMetrics:             true,
		Logger:                    nil,
	}
}

// SubscriptionStatus represents the status of a subscription
type SubscriptionStatus string

const (
	SubscriptionStatusActive    SubscriptionStatus = "active"
	SubscriptionStatusPaused    SubscriptionStatus = "paused"
	SubscriptionStatusCancelled SubscriptionStatus = "cancelled"
	SubscriptionStatusExpired   SubscriptionStatus = "expired"
	SubscriptionStatusError     SubscriptionStatus = "error"
)

// Subscription represents a subscription to resource change notifications
type Subscription struct {
	// SubscriptionID is a unique identifier for this subscription
	SubscriptionID string

	// WebID is the WebID of the subscriber (authenticated identity)
	WebID string

	// ClientID is the client identifier (may be different from WebID)
	ClientID string

	// ChannelID is the channel this subscription is for
	ChannelID string

	// Filter is the subscription filter (what events to receive)
	Filter StreamFilter

	// Endpoint is the delivery endpoint (WebSocket URL, SSE URL, etc.)
	Endpoint string

	// Protocol is the notification protocol (websocket, sse, webhook)
	Protocol NotificationProtocol

	// Status is the current status of the subscription
	Status SubscriptionStatus

	// Created is when the subscription was created
	Created time.Time

	// LastActivity is when the subscription had last activity
	LastActivity time.Time

	// LastCursor is the last event cursor/sequence number received
	LastCursor int64

	// ResumeCursor is the cursor to resume from on reconnection
	ResumeCursor int64

	// Priority is the subscription priority
	Priority int

	// Metadata contains additional subscription metadata
	Metadata map[string]string

	// ErrorCount is the number of consecutive errors
	ErrorCount int

	// LastError is the last error that occurred
	LastError string

	// LastErrorTime is when the last error occurred
	LastErrorTime time.Time

	// DeliveryStats contains delivery statistics
	DeliveryStats DeliveryStatistics
}

// DeliveryStatistics holds statistics for event delivery
type DeliveryStatistics struct {
	mu sync.RWMutex

	// EventsDelivered is the total number of events delivered
	EventsDelivered int64

	// EventsFailed is the total number of events that failed to deliver
	EventsFailed int64

	// LastDeliveryTime is when the last event was delivered
	LastDeliveryTime time.Time

	// FirstDeliveryTime is when the first event was delivered
	FirstDeliveryTime time.Time

	// TotalDeliveryLatency is the sum of all delivery latencies
	TotalDeliveryLatency time.Duration

	// MinDeliveryLatency is the minimum delivery latency
	MinDeliveryLatency time.Duration

	// MaxDeliveryLatency is the maximum delivery latency
	MaxDeliveryLatency time.Duration

	// RetryCount is the number of retries that occurred
	RetryCount int64

	// LastRetryTime is when the last retry occurred
	LastRetryTime time.Time
}

// DeliveryStatisticsSnapshot is a copy of delivery statistics without the mutex
type DeliveryStatisticsSnapshot struct {
	// EventsDelivered is the total number of events delivered
	EventsDelivered int64

	// EventsFailed is the total number of events that failed to deliver
	EventsFailed int64

	// LastDeliveryTime is when the last event was delivered
	LastDeliveryTime time.Time

	// FirstDeliveryTime is when the first event was delivered
	FirstDeliveryTime time.Time

	// TotalDeliveryLatency is the sum of all delivery latencies
	TotalDeliveryLatency time.Duration

	// MinDeliveryLatency is the minimum delivery latency
	MinDeliveryLatency time.Duration

	// MaxDeliveryLatency is the maximum delivery latency
	MaxDeliveryLatency time.Duration

	// RetryCount is the number of retries that occurred
	RetryCount int64

	// LastRetryTime is when the last retry occurred
	LastRetryTime time.Time
}

// RecordDelivery records a successful delivery
func (d *DeliveryStatistics) RecordDelivery(latency time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.EventsDelivered++
	now := time.Now()

	if d.FirstDeliveryTime.IsZero() {
		d.FirstDeliveryTime = now
	}
	d.LastDeliveryTime = now

	// Update latency statistics
	d.TotalDeliveryLatency += latency
	if d.MinDeliveryLatency == 0 || latency < d.MinDeliveryLatency {
		d.MinDeliveryLatency = latency
	}
	if latency > d.MaxDeliveryLatency {
		d.MaxDeliveryLatency = latency
	}
}

// RecordFailure records a delivery failure
func (d *DeliveryStatistics) RecordFailure() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.EventsFailed++
}

// RecordRetry records a retry attempt
func (d *DeliveryStatistics) RecordRetry() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.RetryCount++
	d.LastRetryTime = time.Now()
}

// GetAverageLatency returns the average delivery latency
func (d *DeliveryStatistics) GetAverageLatency() time.Duration {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.EventsDelivered == 0 {
		return 0
	}

	return d.TotalDeliveryLatency / time.Duration(d.EventsDelivered)
}

// GetDeliveryStats returns a snapshot of the delivery statistics
func (d *DeliveryStatistics) GetDeliveryStats() DeliveryStatisticsSnapshot {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return DeliveryStatisticsSnapshot{
		EventsDelivered:      d.EventsDelivered,
		EventsFailed:         d.EventsFailed,
		LastDeliveryTime:     d.LastDeliveryTime,
		FirstDeliveryTime:    d.FirstDeliveryTime,
		TotalDeliveryLatency: d.TotalDeliveryLatency,
		MinDeliveryLatency:   d.MinDeliveryLatency,
		MaxDeliveryLatency:   d.MaxDeliveryLatency,
		RetryCount:           d.RetryCount,
		LastRetryTime:        d.LastRetryTime,
	}
}

// NotificationProtocol represents the notification protocol
type NotificationProtocol string

const (
	ProtocolWebSocket NotificationProtocol = "websocket"
	ProtocolSSE       NotificationProtocol = "sse"
	ProtocolWebHook   NotificationProtocol = "webhook"
	ProtocolSolid     NotificationProtocol = "solid-notification"
)

// SubscriptionRegistry implements a subscription registry with authentication and authorization
type SubscriptionRegistry struct {
	mu sync.RWMutex

	config SubscriptionRegistryConfig

	// Subscriptions by ID
	subscriptions map[string]*Subscription

	// Subscriptions by WebID for quick lookup
	subscriptionsByWebID map[string][]string

	// Subscriptions by channel for quick lookup
	subscriptionsByChannel map[string][]string

	// Event log reference for cursor support
	durableLog *DurableEventLog

	// Authentication provider reference
	authProvider Authenticator

	// Authorization provider reference
	authzProvider Authorizer

	// Logger
	logger *slog.Logger

	// Close state
	closeChan chan struct{}
	closed    bool

	// Metrics
	metrics SubscriptionRegistryMetrics
}

// Authenticator interface for authentication
type Authenticator interface {
	// Authenticate authenticates a WebID and returns the authenticated identity
	Authenticate(ctx context.Context, webID, token string) (string, error)

	// ValidateWebID validates that a WebID is properly formatted
	ValidateWebID(webID string) error
}

// Authorizer interface for authorization
type Authorizer interface {
	// CheckAccess checks if an agent (WebID) has access to a resource
	CheckAccess(ctx context.Context, agent, resourceURI string, mode AccessMode) (bool, error)

	// GetAccessModes returns the access modes an agent has to a resource
	GetAccessModes(ctx context.Context, agent, resourceURI string) ([]AccessMode, error)
}

// SubscriptionRegistryMetrics holds metrics for the subscription registry
type SubscriptionRegistryMetrics struct {
	mu sync.RWMutex

	TotalSubscriptions     int64
	ActiveSubscriptions    int64
	PausedSubscriptions    int64
	CancelledSubscriptions int64
	ExpiredSubscriptions   int64
	ErrorSubscriptions     int64

	SubscriptionsByProtocol map[NotificationProtocol]int64

	TotalDeliveryAttempts int64
	TotalDeliveries       int64
	TotalDeliveryFailures int64
	TotalRetries          int64

	AuthenticationFailures int64
	AuthorizationFailures  int64

	SubscriptionCreations     int64
	SubscriptionCancellations int64
}

// SubscriptionRegistryMetricsSnapshot is a copy of metrics without the mutex
type SubscriptionRegistryMetricsSnapshot struct {
	TotalSubscriptions     int64
	ActiveSubscriptions    int64
	PausedSubscriptions    int64
	CancelledSubscriptions int64
	ExpiredSubscriptions   int64
	ErrorSubscriptions     int64

	SubscriptionsByProtocol map[NotificationProtocol]int64

	TotalDeliveryAttempts int64
	TotalDeliveries       int64
	TotalDeliveryFailures int64
	TotalRetries          int64

	AuthenticationFailures int64
	AuthorizationFailures  int64

	SubscriptionCreations     int64
	SubscriptionCancellations int64
}

// RecordSubscription records a subscription event
func (m *SubscriptionRegistryMetrics) RecordSubscription(status SubscriptionStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalSubscriptions++

	switch status {
	case SubscriptionStatusActive:
		m.ActiveSubscriptions++
	case SubscriptionStatusPaused:
		m.PausedSubscriptions++
	case SubscriptionStatusCancelled:
		m.CancelledSubscriptions++
	case SubscriptionStatusExpired:
		m.ExpiredSubscriptions++
	case SubscriptionStatusError:
		m.ErrorSubscriptions++
	}
}

// RecordProtocolUsage records usage of a notification protocol
func (m *SubscriptionRegistryMetrics) RecordProtocolUsage(protocol NotificationProtocol) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.SubscriptionsByProtocol == nil {
		m.SubscriptionsByProtocol = make(map[NotificationProtocol]int64)
	}
	m.SubscriptionsByProtocol[protocol]++
}

// RecordDelivery records a delivery attempt
func (m *SubscriptionRegistryMetrics) RecordDelivery(success bool, retried bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalDeliveryAttempts++
	if success {
		m.TotalDeliveries++
	}
	if !success {
		m.TotalDeliveryFailures++
	}
	if retried {
		m.TotalRetries++
	}
}

// RecordAuthenticationFailure records an authentication failure
func (m *SubscriptionRegistryMetrics) RecordAuthenticationFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AuthenticationFailures++
}

// RecordAuthorizationFailure records an authorization failure
func (m *SubscriptionRegistryMetrics) RecordAuthorizationFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AuthorizationFailures++
}

// RecordCreation records a subscription creation
func (m *SubscriptionRegistryMetrics) RecordCreation() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SubscriptionCreations++
}

// RecordCancellation records a subscription cancellation
func (m *SubscriptionRegistryMetrics) RecordCancellation() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SubscriptionCancellations++
}

// GetMetrics returns a snapshot of the current metrics
func (m *SubscriptionRegistryMetrics) GetMetrics() SubscriptionRegistryMetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a snapshot
	snapshot := SubscriptionRegistryMetricsSnapshot{
		TotalSubscriptions:        m.TotalSubscriptions,
		ActiveSubscriptions:       m.ActiveSubscriptions,
		PausedSubscriptions:       m.PausedSubscriptions,
		CancelledSubscriptions:    m.CancelledSubscriptions,
		ExpiredSubscriptions:      m.ExpiredSubscriptions,
		ErrorSubscriptions:        m.ErrorSubscriptions,
		TotalDeliveryAttempts:     m.TotalDeliveryAttempts,
		TotalDeliveries:           m.TotalDeliveries,
		TotalDeliveryFailures:     m.TotalDeliveryFailures,
		TotalRetries:              m.TotalRetries,
		AuthenticationFailures:    m.AuthenticationFailures,
		AuthorizationFailures:     m.AuthorizationFailures,
		SubscriptionCreations:     m.SubscriptionCreations,
		SubscriptionCancellations: m.SubscriptionCancellations,
	}

	if m.SubscriptionsByProtocol != nil {
		snapshot.SubscriptionsByProtocol = make(map[NotificationProtocol]int64)
		for k, v := range m.SubscriptionsByProtocol {
			snapshot.SubscriptionsByProtocol[k] = v
		}
	}

	return snapshot
}

// NewSubscriptionRegistry creates a new subscription registry
func NewSubscriptionRegistry(config SubscriptionRegistryConfig, durableLog *DurableEventLog) *SubscriptionRegistry {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	registry := &SubscriptionRegistry{
		config:                 config,
		subscriptions:          make(map[string]*Subscription),
		subscriptionsByWebID:   make(map[string][]string),
		subscriptionsByChannel: make(map[string][]string),
		durableLog:             durableLog,
		logger:                 config.Logger,
		closeChan:              make(chan struct{}),
		metrics: SubscriptionRegistryMetrics{
			SubscriptionsByProtocol: make(map[NotificationProtocol]int64),
		},
	}

	config.Logger.Info("Subscription registry initialized",
		"max_subscriptions", config.MaxSubscriptions,
		"max_subscriptions_per_webid", config.MaxSubscriptionsPerWebID,
		"max_subscription_age", config.MaxSubscriptionAge,
		"subscription_timeout", config.SubscriptionTimeout,
		"enable_backpressure", config.EnableBackpressure,
		"max_backpressure_buffer_size", config.MaxBackpressureBufferSize,
	)

	// Start background cleanup
	go registry.cleanupLoop()

	return registry
}

// cleanupLoop handles periodic cleanup of stale subscriptions
func (r *SubscriptionRegistry) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour) // Clean up every hour
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanupStaleSubscriptions()
		case <-r.closeChan:
			r.logger.Info("Subscription registry cleanup loop stopped")
			return
		}
	}
}

// cleanupStaleSubscriptions removes subscriptions that have exceeded their maximum age
func (r *SubscriptionRegistry) cleanupStaleSubscriptions() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}

	cutoff := time.Now().Add(-r.config.MaxSubscriptionAge)
	var toRemove []string

	for id, sub := range r.subscriptions {
		if sub.Status == SubscriptionStatusActive && sub.LastActivity.Before(cutoff) {
			sub.Status = SubscriptionStatusExpired
			toRemove = append(toRemove, id)

			// Update metrics
			r.metrics.RecordSubscription(SubscriptionStatusExpired)

			r.logger.Info("Subscription expired due to inactivity",
				"subscription_id", id,
				"webid", sub.WebID,
				"age", time.Since(sub.LastActivity),
			)
		}
	}

	// Remove expired subscriptions
	for _, id := range toRemove {
		delete(r.subscriptions, id)
		r.removeFromIndexes(id)
	}

	if len(toRemove) > 0 {
		r.logger.Info("Cleaned up stale subscriptions", "count", len(toRemove))
	}
}

// removeFromIndexes removes a subscription from all indexes
func (r *SubscriptionRegistry) removeFromIndexes(subscriptionID string) {
	// Find the subscription first
	sub, exists := r.subscriptions[subscriptionID]
	if !exists {
		return
	}

	// Remove from WebID index
	if webIDSubs, exists := r.subscriptionsByWebID[sub.WebID]; exists {
		for i, id := range webIDSubs {
			if id == subscriptionID {
				r.subscriptionsByWebID[sub.WebID] = append(webIDSubs[:i], webIDSubs[i+1:]...)
				break
			}
		}
		// Remove WebID entry if empty
		if len(r.subscriptionsByWebID[sub.WebID]) == 0 {
			delete(r.subscriptionsByWebID, sub.WebID)
		}
	}

	// Remove from channel index
	if channelSubs, exists := r.subscriptionsByChannel[sub.ChannelID]; exists {
		for i, id := range channelSubs {
			if id == subscriptionID {
				r.subscriptionsByChannel[sub.ChannelID] = append(channelSubs[:i], channelSubs[i+1:]...)
				break
			}
		}
		// Remove channel entry if empty
		if len(r.subscriptionsByChannel[sub.ChannelID]) == 0 {
			delete(r.subscriptionsByChannel, sub.ChannelID)
		}
	}
}

// SetAuthProvider sets the authentication provider
func (r *SubscriptionRegistry) SetAuthProvider(provider Authenticator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authProvider = provider
}

// SetAuthzProvider sets the authorization provider
func (r *SubscriptionRegistry) SetAuthzProvider(provider Authorizer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authzProvider = provider
}

// generateSubscriptionID generates a unique subscription ID
func (r *SubscriptionRegistry) generateSubscriptionID() string {
	// Generate random bytes for subscription ID
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if random generation fails
		return fmt.Sprintf("sub-%d-%d", time.Now().UnixNano(), len(r.subscriptions))
	}
	return "sub-" + hex.EncodeToString(b)
}

// CreateSubscription creates a new subscription with authentication and authorization
func (r *SubscriptionRegistry) CreateSubscription(
	ctx context.Context,
	webID string,
	token string,
	clientID string,
	channelID string,
	filter StreamFilter,
	endpoint string,
	protocol NotificationProtocol,
	priority int,
	metadata map[string]string,
) (*Subscription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil, ErrDurableLogClosed
	}

	// Check subscription limit
	if len(r.subscriptions) >= r.config.MaxSubscriptions {
		return nil, ErrMaxSubscriptionsReached
	}

	// Check per-WebID subscription limit
	if existingCount := len(r.subscriptionsByWebID[webID]); existingCount >= r.config.MaxSubscriptionsPerWebID {
		return nil, fmt.Errorf("maximum subscriptions per WebID reached (%d)", r.config.MaxSubscriptionsPerWebID)
	}

	// Authenticate the WebID
	if r.authProvider != nil {
		if err := r.authProvider.ValidateWebID(webID); err != nil {
			r.metrics.RecordAuthenticationFailure()
			return nil, fmt.Errorf("%w: %v", ErrAuthenticationRequired, err)
		}

		// Authenticate with token
		authenticatedWebID, err := r.authProvider.Authenticate(ctx, webID, token)
		if err != nil {
			r.metrics.RecordAuthenticationFailure()
			return nil, fmt.Errorf("%w: %v", ErrAuthenticationRequired, err)
		}

		// Use the authenticated WebID (may be different from input if aliased)
		webID = authenticatedWebID
	}

	// Validate the filter
	if err := r.validateSubscriptionFilter(filter); err != nil {
		return nil, err
	}

	// Check authorization for the resources in the filter
	if r.authzProvider != nil {
		for _, resourceURI := range filter.ResourceURIs {
			if hasAccess, err := r.authzProvider.CheckAccess(ctx, webID, resourceURI, AccessModeRead); err != nil {
				r.metrics.RecordAuthorizationFailure()
				return nil, fmt.Errorf("%w: %v", ErrAccessDenied, err)
			} else if !hasAccess {
				r.metrics.RecordAuthorizationFailure()
				return nil, fmt.Errorf("%w: WebID %s does not have read access to resource %s", ErrAccessDenied, webID, resourceURI)
			}
		}

		// Check container URIs as well
		for _, containerURI := range filter.ContainerURIs {
			if hasAccess, err := r.authzProvider.CheckAccess(ctx, webID, containerURI, AccessModeRead); err != nil {
				r.metrics.RecordAuthorizationFailure()
				return nil, fmt.Errorf("%w: %v", ErrAccessDenied, err)
			} else if !hasAccess {
				r.metrics.RecordAuthorizationFailure()
				return nil, fmt.Errorf("%w: WebID %s does not have read access to container %s", ErrAccessDenied, webID, containerURI)
			}
		}
	}

	// Check if subscription already exists for this WebID, client, channel, and filter
	if r.config.MaxSubscriptionsPerWebID > 0 {
		for _, subID := range r.subscriptionsByWebID[webID] {
			sub := r.subscriptions[subID]
			if sub.ClientID == clientID && sub.ChannelID == channelID {
				// Check if filter is the same
				if r.filtersEqual(sub.Filter, filter) {
					return nil, ErrSubscriptionAlreadyExists
				}
			}
		}
	}

	// Determine initial cursor
	initialCursor := int64(0)
	if r.durableLog != nil {
		initialCursor = r.durableLog.GetCursor()
	}

	// Create the subscription
	subscription := &Subscription{
		SubscriptionID: r.generateSubscriptionID(),
		WebID:          webID,
		ClientID:       clientID,
		ChannelID:      channelID,
		Filter:         filter,
		Endpoint:       endpoint,
		Protocol:       protocol,
		Status:         SubscriptionStatusActive,
		Created:        time.Now().UTC(),
		LastActivity:   time.Now().UTC(),
		LastCursor:     initialCursor,
		ResumeCursor:   initialCursor,
		Priority:       priority,
		Metadata:       metadata,
		ErrorCount:     0,
		DeliveryStats:  DeliveryStatistics{},
	}

	// Store the subscription
	r.subscriptions[subscription.SubscriptionID] = subscription
	r.subscriptionsByWebID[webID] = append(r.subscriptionsByWebID[webID], subscription.SubscriptionID)
	r.subscriptionsByChannel[channelID] = append(r.subscriptionsByChannel[channelID], subscription.SubscriptionID)

	// Update metrics
	r.metrics.RecordSubscription(SubscriptionStatusActive)
	r.metrics.RecordProtocolUsage(protocol)
	r.metrics.RecordCreation()

	r.logger.Info("Subscription created",
		"subscription_id", subscription.SubscriptionID,
		"webid", webID,
		"client_id", clientID,
		"channel_id", channelID,
		"protocol", protocol,
		"initial_cursor", initialCursor,
	)

	return subscription, nil
}

// filtersEqual checks if two filters are equal
func (r *SubscriptionRegistry) filtersEqual(a, b StreamFilter) bool {
	// Simple comparison for now
	// In a more sophisticated implementation, we'd do a deep comparison
	if a.MinPrivacyLevel != b.MinPrivacyLevel {
		return false
	}
	if a.MaxPrivacyLevel != b.MaxPrivacyLevel {
		return false
	}
	if len(a.EventTypes) != len(b.EventTypes) {
		return false
	}
	if len(a.ResourceURIs) != len(b.ResourceURIs) {
		return false
	}
	if len(a.ContainerURIs) != len(b.ContainerURIs) {
		return false
	}

	// For simplicity, assume they're equal if the above checks pass
	// A production implementation would do a more thorough comparison
	return true
}

// validateSubscriptionFilter validates a subscription filter
func (r *SubscriptionRegistry) validateSubscriptionFilter(filter StreamFilter) error {
	// Validate privacy level range
	if filter.MinPrivacyLevel != "" && filter.MaxPrivacyLevel != "" {
		if filter.MinPrivacyLevel > filter.MaxPrivacyLevel {
			return ErrInvalidSubscriptionFilter
		}
	}

	// Validate privacy levels
	validPrivacyLevels := []PrivacyLevel{
		PrivacyLevelPublic,
		PrivacyLevelMetadata,
		PrivacyLevelSensitive,
		PrivacyLevelPrivate,
	}

	if filter.MinPrivacyLevel != "" {
		valid := false
		for _, level := range validPrivacyLevels {
			if PrivacyLevel(filter.MinPrivacyLevel) == level {
				valid = true
				break
			}
		}
		if !valid {
			return ErrInvalidSubscriptionFilter
		}
	}

	if filter.MaxPrivacyLevel != "" {
		valid := false
		for _, level := range validPrivacyLevels {
			if PrivacyLevel(filter.MaxPrivacyLevel) == level {
				valid = true
				break
			}
		}
		if !valid {
			return ErrInvalidSubscriptionFilter
		}
	}

	return nil
}

// GetSubscription returns a subscription by ID
func (r *SubscriptionRegistry) GetSubscription(subscriptionID string) (*Subscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, ErrDurableLogClosed
	}

	subscription, exists := r.subscriptions[subscriptionID]
	if !exists {
		return nil, ErrSubscriptionNotFound
	}

	return subscription, nil
}

// GetSubscriptionsByWebID returns all subscriptions for a given WebID
func (r *SubscriptionRegistry) GetSubscriptionsByWebID(webID string) ([]*Subscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, ErrDurableLogClosed
	}

	var subscriptions []*Subscription
	for _, subID := range r.subscriptionsByWebID[webID] {
		if sub, exists := r.subscriptions[subID]; exists {
			subscriptions = append(subscriptions, sub)
		}
	}

	return subscriptions, nil
}

// GetSubscriptionsByChannel returns all subscriptions for a given channel
func (r *SubscriptionRegistry) GetSubscriptionsByChannel(channelID string) ([]*Subscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, ErrDurableLogClosed
	}

	var subscriptions []*Subscription
	for _, subID := range r.subscriptionsByChannel[channelID] {
		if sub, exists := r.subscriptions[subID]; exists {
			subscriptions = append(subscriptions, sub)
		}
	}

	return subscriptions, nil
}

// UpdateSubscription updates a subscription's metadata or settings
func (r *SubscriptionRegistry) UpdateSubscription(
	subscriptionID string,
	filter *StreamFilter,
	priority *int,
	metadata map[string]string,
) (*Subscription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil, ErrDurableLogClosed
	}

	subscription, exists := r.subscriptions[subscriptionID]
	if !exists {
		return nil, ErrSubscriptionNotFound
	}

	// Update filter if provided
	if filter != nil {
		if err := r.validateSubscriptionFilter(*filter); err != nil {
			return nil, err
		}
		subscription.Filter = *filter
	}

	// Update priority if provided
	if priority != nil {
		subscription.Priority = *priority
	}

	// Update metadata if provided
	if metadata != nil {
		if subscription.Metadata == nil {
			subscription.Metadata = make(map[string]string)
		}
		for k, v := range metadata {
			subscription.Metadata[k] = v
		}
	}

	subscription.LastActivity = time.Now().UTC()

	r.logger.Info("Subscription updated",
		"subscription_id", subscriptionID,
		"webid", subscription.WebID,
		"updated_fields", "filter, priority, metadata",
	)

	return subscription, nil
}

// UpdateCursor updates a subscription's cursor position
func (r *SubscriptionRegistry) UpdateCursor(subscriptionID string, cursor int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrDurableLogClosed
	}

	subscription, exists := r.subscriptions[subscriptionID]
	if !exists {
		return ErrSubscriptionNotFound
	}

	subscription.LastCursor = cursor
	subscription.ResumeCursor = cursor
	subscription.LastActivity = time.Now().UTC()
	subscription.ErrorCount = 0 // Reset error count on successful update
	subscription.LastError = ""

	return nil
}

// PauseSubscription pauses a subscription
func (r *SubscriptionRegistry) PauseSubscription(subscriptionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrDurableLogClosed
	}

	subscription, exists := r.subscriptions[subscriptionID]
	if !exists {
		return ErrSubscriptionNotFound
	}

	if subscription.Status == SubscriptionStatusPaused {
		return nil // Already paused
	}

	oldStatus := subscription.Status
	subscription.Status = SubscriptionStatusPaused
	subscription.LastActivity = time.Now().UTC()

	// Update metrics
	r.metrics.RecordSubscription(SubscriptionStatusPaused)
	if oldStatus == SubscriptionStatusActive {
		r.metrics.ActiveSubscriptions--
	}

	r.logger.Info("Subscription paused",
		"subscription_id", subscriptionID,
		"webid", subscription.WebID,
		"old_status", oldStatus,
	)

	return nil
}

// ResumeSubscription resumes a paused subscription
func (r *SubscriptionRegistry) ResumeSubscription(subscriptionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrDurableLogClosed
	}

	subscription, exists := r.subscriptions[subscriptionID]
	if !exists {
		return ErrSubscriptionNotFound
	}

	if subscription.Status == SubscriptionStatusActive {
		return nil // Already active
	}

	oldStatus := subscription.Status
	subscription.Status = SubscriptionStatusActive
	subscription.LastActivity = time.Now().UTC()

	// Update metrics
	r.metrics.RecordSubscription(SubscriptionStatusActive)
	if oldStatus == SubscriptionStatusPaused {
		r.metrics.PausedSubscriptions--
	}

	r.logger.Info("Subscription resumed",
		"subscription_id", subscriptionID,
		"webid", subscription.WebID,
		"old_status", oldStatus,
	)

	return nil
}

// CancelSubscription cancels a subscription
func (r *SubscriptionRegistry) CancelSubscription(subscriptionID string, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrDurableLogClosed
	}

	subscription, exists := r.subscriptions[subscriptionID]
	if !exists {
		return ErrSubscriptionNotFound
	}

	oldStatus := subscription.Status
	subscription.Status = SubscriptionStatusCancelled
	subscription.LastActivity = time.Now().UTC()
	subscription.LastError = reason

	// Update metrics
	r.metrics.RecordSubscription(SubscriptionStatusCancelled)
	r.metrics.RecordCancellation()
	if oldStatus == SubscriptionStatusActive {
		r.metrics.ActiveSubscriptions--
	}

	// Remove from indexes
	r.removeFromIndexes(subscriptionID)
	delete(r.subscriptions, subscriptionID)

	r.logger.Info("Subscription cancelled",
		"subscription_id", subscriptionID,
		"webid", subscription.WebID,
		"reason", reason,
		"old_status", oldStatus,
	)

	return nil
}

// ListSubscriptions returns all subscriptions with optional filtering
func (r *SubscriptionRegistry) ListSubscriptions(
	webID string,
	channelID string,
	status SubscriptionStatus,
	protocol NotificationProtocol,
	limit int,
	offset int,
) ([]*Subscription, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, 0, ErrDurableLogClosed
	}

	var allSubscriptions []*Subscription

	// Filter by criteria
	for _, sub := range r.subscriptions {
		// Filter by WebID
		if webID != "" && sub.WebID != webID {
			continue
		}

		// Filter by channel
		if channelID != "" && sub.ChannelID != channelID {
			continue
		}

		// Filter by status
		if status != "" && sub.Status != status {
			continue
		}

		// Filter by protocol
		if protocol != "" && sub.Protocol != protocol {
			continue
		}

		allSubscriptions = append(allSubscriptions, sub)
	}

	total := len(allSubscriptions)

	// Apply limit and offset
	if offset >= total {
		return []*Subscription{}, total, nil
	}

	end := offset + limit
	if limit == 0 || end > total {
		end = total
	}

	result := allSubscriptions[offset:end]

	return result, total, nil
}

// RecordDelivery records a delivery attempt for a subscription
func (r *SubscriptionRegistry) RecordDelivery(subscriptionID string, success bool, latency time.Duration, retried bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrDurableLogClosed
	}

	subscription, exists := r.subscriptions[subscriptionID]
	if !exists {
		return ErrSubscriptionNotFound
	}

	// Record in subscription stats
	subscription.DeliveryStats.RecordDelivery(latency)
	if !success {
		subscription.DeliveryStats.RecordFailure()
		subscription.ErrorCount++
		subscription.LastError = fmt.Sprintf("delivery failed at %s", time.Now().Format(time.RFC3339))
		subscription.LastErrorTime = time.Now().UTC()
	}

	if retried {
		subscription.DeliveryStats.RecordRetry()
	}

	// Record in registry metrics
	r.metrics.RecordDelivery(success, retried)

	// Update last activity
	subscription.LastActivity = time.Now().UTC()

	return nil
}

// CheckAccessForSubscription checks if a subscription can access a specific event
func (r *SubscriptionRegistry) CheckAccessForSubscription(
	ctx context.Context,
	subscriptionID string,
	resourceURI string,
	privacyLevel PrivacyLevel,
) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return false, ErrDurableLogClosed
	}

	subscription, exists := r.subscriptions[subscriptionID]
	if !exists {
		return false, ErrSubscriptionNotFound
	}

	// Check if subscription is active
	if subscription.Status != SubscriptionStatusActive {
		return false, nil
	}

	// Check if the privacy level is within the subscription's range
	if subscription.Filter.MinPrivacyLevel != "" {
		if privacyLevel < PrivacyLevel(subscription.Filter.MinPrivacyLevel) {
			return false, nil
		}
	}

	if subscription.Filter.MaxPrivacyLevel != "" {
		if privacyLevel > PrivacyLevel(subscription.Filter.MaxPrivacyLevel) {
			return false, nil
		}
	}

	// Check specific resource access
	if len(subscription.Filter.ResourceURIs) > 0 {
		found := false
		for _, uri := range subscription.Filter.ResourceURIs {
			if uri == resourceURI {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}

	// Check container access
	if len(subscription.Filter.ContainerURIs) > 0 {
		found := false
		for _, containerURI := range subscription.Filter.ContainerURIs {
			if containerURI == resourceURI {
				found = true
				break
			}
		}
		if !found {
			// Check if resource is in one of the containers
			// This is a simplified check - real implementation would parse container hierarchy
			for _, containerURI := range subscription.Filter.ContainerURIs {
				if isInContainer(resourceURI, containerURI) {
					found = true
					break
				}
			}
			if !found {
				return false, nil
			}
		}
	}

	// If we have authorization provider, check access
	if r.authzProvider != nil && subscription.WebID != "" {
		if hasAccess, err := r.authzProvider.CheckAccess(ctx, subscription.WebID, resourceURI, AccessModeRead); err != nil {
			return false, err
		} else if !hasAccess {
			return false, nil
		}
	}

	return true, nil
}

// isInContainer checks if a resource is in a container
func isInContainer(resourceURI, containerURI string) bool {
	// Simple implementation: check if resource URI starts with container URI
	if len(resourceURI) > len(containerURI) {
		return resourceURI[:len(containerURI)] == containerURI
	}
	return false
}

// GetMetrics returns the current metrics
func (r *SubscriptionRegistry) GetMetrics() SubscriptionRegistryMetricsSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.metrics.GetMetrics()
}

// Size returns the current number of subscriptions
func (r *SubscriptionRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.subscriptions)
}

// Close closes the subscription registry
func (r *SubscriptionRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}

	r.closed = true
	close(r.closeChan)

	// Clear all subscriptions
	r.subscriptions = nil
	r.subscriptionsByWebID = nil
	r.subscriptionsByChannel = nil

	r.logger.Info("Subscription registry closed")

	return nil
}

// IsClosed returns true if the registry is closed
func (r *SubscriptionRegistry) IsClosed() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.closed
}
