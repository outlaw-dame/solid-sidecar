// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 6.9: Solid Notifications Protocol support for Phase 24.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ErrInvalidWebSocketURL is returned when a WebSocket URL is invalid
var ErrInvalidWebSocketURL = errors.New("invalid WebSocket URL")

// ErrInvalidSSEURL is returned when a Server-Sent Events URL is invalid
var ErrInvalidSSEURL = errors.New("invalid SSE URL")

// ErrInvalidWebhookURL is returned when a webhook URL is invalid
var ErrInvalidWebhookURL = errors.New("invalid webhook URL")

// ErrNotificationProtocolNotSupported is returned when a notification protocol is not supported
var ErrNotificationProtocolNotSupported = errors.New("notification protocol not supported")

// SolidNotificationProtocol represents the Solid notification protocol
type SolidNotificationProtocol string

const (
	// SolidNotificationProtocolWebSocket represents WebSocket-based Solid notifications
	SolidNotificationProtocolWebSocket SolidNotificationProtocol = "solid-websocket"

	// SolidNotificationProtocolSSE represents Server-Sent Events based Solid notifications
	SolidNotificationProtocolSSE SolidNotificationProtocol = "solid-sse"

	// SolidNotificationProtocolWebhook represents webhook-based Solid notifications
	SolidNotificationProtocolWebhook SolidNotificationProtocol = "solid-webhook"
)

// SolidNotificationConfig holds configuration for Solid notifications
type SolidNotificationConfig struct {
	// Enabled enables Solid notifications support
	Enabled bool

	// SupportedProtocols lists the supported notification protocols
	SupportedProtocols []SolidNotificationProtocol

	// DefaultProtocol is the default notification protocol
	DefaultProtocol SolidNotificationProtocol

	// WebSocketConfig contains WebSocket-specific configuration
	WebSocketConfig WebSocketConfig

	// SSEConfig contains Server-Sent Events specific configuration
	SSEConfig SSEConfig

	// WebhookConfig contains webhook-specific configuration
	WebhookConfig WebhookConfig

	// EnableMetrics enables metrics collection
	EnableMetrics bool

	// Logger is the logger for this component
	Logger *slog.Logger
}

// WebSocketConfig contains WebSocket-specific configuration
type WebSocketConfig struct {
	// MaxConnections is the maximum number of WebSocket connections
	MaxConnections int

	// ConnectionTimeout is the timeout for WebSocket connections
	ConnectionTimeout time.Duration

	// PongWait is the time to wait for a pong response
	PongWait time.Duration

	// PingInterval is the interval for sending pings
	PingInterval time.Duration

	// MaxMessageSize is the maximum message size
	MaxMessageSize int64

	// WriteBufferSize is the write buffer size
	WriteBufferSize int

	// ReadBufferSize is the read buffer size
	ReadBufferSize int
}

// SSEConfig contains Server-Sent Events specific configuration
type SSEConfig struct {
	// MaxConnections is the maximum number of SSE connections
	MaxConnections int

	// ConnectionTimeout is the timeout for SSE connections
	ConnectionTimeout time.Duration

	// MaxRetryDuration is the maximum retry duration for SSE
	MaxRetryDuration time.Duration

	// EventBufferSize is the event buffer size for SSE
	EventBufferSize int
}

// WebhookConfig contains webhook-specific configuration
type WebhookConfig struct {
	// MaxConcurrentDeliveries is the maximum number of concurrent webhook deliveries
	MaxConcurrentDeliveries int

	// DeliveryTimeout is the timeout for webhook deliveries
	DeliveryTimeout time.Duration

	// MaxRetries is the maximum number of retries for webhook deliveries
	MaxRetries int

	// RetryDelay is the delay between webhook delivery retries
	RetryDelay time.Duration

	// EnableSigning enables webhook signature verification
	EnableSigning bool

	// SigningSecret is the secret for webhook signature verification
	SigningSecret string
}

// DefaultSolidNotificationConfig returns a safe default configuration
func DefaultSolidNotificationConfig() SolidNotificationConfig {
	return SolidNotificationConfig{
		Enabled: true,
		SupportedProtocols: []SolidNotificationProtocol{
			SolidNotificationProtocolWebSocket,
			SolidNotificationProtocolSSE,
			SolidNotificationProtocolWebhook,
		},
		DefaultProtocol: SolidNotificationProtocolWebSocket,
		WebSocketConfig: WebSocketConfig{
			MaxConnections:    1000,
			ConnectionTimeout: 30 * time.Second,
			PongWait:          60 * time.Second,
			PingInterval:      30 * time.Second,
			MaxMessageSize:    65536, // 64KB
			WriteBufferSize:   4096,
			ReadBufferSize:    4096,
		},
		SSEConfig: SSEConfig{
			MaxConnections:    1000,
			ConnectionTimeout: 30 * time.Second,
			MaxRetryDuration:  5 * time.Minute,
			EventBufferSize:   100,
		},
		WebhookConfig: WebhookConfig{
			MaxConcurrentDeliveries: 100,
			DeliveryTimeout:         30 * time.Second,
			MaxRetries:              3,
			RetryDelay:              1 * time.Second,
			EnableSigning:           true,
			SigningSecret:           "", // Should be configured
		},
		EnableMetrics: true,
		Logger:        nil,
	}
}

// SolidNotificationMessage represents a Solid notification message
type SolidNotificationMessage struct {
	// ID is a unique identifier for this notification
	ID string `json:"id"`

	// Type is the type of notification
	Type string `json:"type"`

	// Resource is the URI of the resource that changed
	Resource string `json:"resource"`

	// Container is the URI of the container containing the resource
	Container string `json:"container,omitempty"`

	// ChangeType is the type of change (create, update, delete, etc.)
	ChangeType string `json:"changeType"`

	// Actor is the WebID of the agent that caused the change
	Actor string `json:"actor,omitempty"`

	// Timestamp is when the change occurred
	Timestamp time.Time `json:"timestamp"`

	// State is the current state of the resource
	State map[string]interface{} `json:"state,omitempty"`

	// Metadata contains additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// SubscriptionID is the ID of the subscription this notification is for
	SubscriptionID string `json:"subscriptionId,omitempty"`

	// Cursor is the cursor for resumption
	Cursor string `json:"cursor,omitempty"`
}

// SolidNotificationChannel represents a Solid notification channel
type SolidNotificationChannel struct {
	// ID is a unique identifier for the channel
	ID string

	// Type is the channel type
	Type string

	// Topic is the topic of the channel
	Topic string

	// Filter is the filter for events on this channel
	Filter StreamFilter

	// Subscribers is the list of subscribers to this channel
	Subscribers []string

	// Created is when the channel was created
	Created time.Time

	// Modified is when the channel was last modified
	Modified time.Time

	// PrivacyLevel is the privacy level of the channel
	PrivacyLevel PrivacyLevel

	// Metadata contains additional channel metadata
	Metadata map[string]string
}

// SolidNotificationService implements Solid notifications protocol support
type SolidNotificationService struct {
	mu sync.RWMutex

	config SolidNotificationConfig

	// Fanout service for event delivery
	fanoutService *FanoutService

	// Subscription registry for managing subscriptions
	subscriptionRegistry *SubscriptionRegistry

	// Durable event log for storing events
	durableLog *DurableEventLog

	// Event stream layer for event processing
	eventStream *EventStreamLayer

	// WebSocket manager for WebSocket connections
	webSocketManager *WebSocketManager

	// SSE manager for Server-Sent Events connections
	sseManager *SSEManager

	// Webhook manager for webhook deliveries
	webhookManager *WebhookManager

	// Notification channels
	channels map[string]*SolidNotificationChannel

	// Metrics
	metrics SolidNotificationMetrics

	// Logger
	logger *slog.Logger

	// Close state
	closed bool
}

// SolidNotificationMetrics holds metrics for Solid notifications
type SolidNotificationMetrics struct {
	mu sync.RWMutex

	// Channel metrics
	ChannelsCreated int64
	ChannelsClosed  int64
	ActiveChannels  int64

	// Connection metrics
	ConnectionsOpened int64
	ConnectionsClosed int64
	ActiveConnections int64

	// Notification metrics
	NotificationsSent      int64
	NotificationsDelivered int64
	NotificationsFailed    int64

	// Protocol-specific metrics
	WebSocketMessagesSent     int64
	WebSocketMessagesReceived int64
	SSEEventsSent             int64
	WebhookDeliveries         int64

	// Error metrics
	ProtocolErrors   int64
	ConnectionErrors int64
	DeliveryErrors   int64

	// Performance metrics
	TotalDeliveryTime   time.Duration
	AverageDeliveryTime time.Duration
	DeliveriesCount     int64
}

// SolidNotificationMetricsSnapshot is a copy of metrics values without the mutex
type SolidNotificationMetricsSnapshot struct {
	// Channel metrics
	ChannelsCreated int64
	ChannelsClosed  int64
	ActiveChannels  int64

	// Connection metrics
	ConnectionsOpened int64
	ConnectionsClosed int64
	ActiveConnections int64

	// Notification metrics
	NotificationsSent      int64
	NotificationsDelivered int64
	NotificationsFailed    int64

	// Protocol-specific metrics
	WebSocketMessagesSent     int64
	WebSocketMessagesReceived int64
	SSEEventsSent             int64
	WebhookDeliveries         int64

	// Error metrics
	ProtocolErrors   int64
	ConnectionErrors int64
	DeliveryErrors   int64

	// Performance metrics
	TotalDeliveryTime   time.Duration
	AverageDeliveryTime time.Duration
	DeliveriesCount     int64
}

// RecordChannelCreated records a channel being created
func (m *SolidNotificationMetrics) RecordChannelCreated() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ChannelsCreated++
	m.ActiveChannels++
}

// RecordChannelClosed records a channel being closed
func (m *SolidNotificationMetrics) RecordChannelClosed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ChannelsClosed++
	m.ActiveChannels--
}

// RecordConnectionOpened records a connection being opened
func (m *SolidNotificationMetrics) RecordConnectionOpened() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ConnectionsOpened++
	m.ActiveConnections++
}

// RecordConnectionClosed records a connection being closed
func (m *SolidNotificationMetrics) RecordConnectionClosed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ConnectionsClosed++
	m.ActiveConnections--
}

// RecordNotificationSent records a notification being sent
func (m *SolidNotificationMetrics) RecordNotificationSent() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.NotificationsSent++
}

// RecordNotificationDelivered records a notification being delivered
func (m *SolidNotificationMetrics) RecordNotificationDelivered(deliveryTime time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.NotificationsDelivered++
	m.TotalDeliveryTime += deliveryTime
	m.DeliveriesCount++
	if m.DeliveriesCount > 0 {
		m.AverageDeliveryTime = m.TotalDeliveryTime / time.Duration(m.DeliveriesCount)
	}
}

// RecordNotificationFailed records a notification delivery failure
func (m *SolidNotificationMetrics) RecordNotificationFailed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.NotificationsFailed++
}

// RecordProtocolError records a protocol error
func (m *SolidNotificationMetrics) RecordProtocolError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ProtocolErrors++
}

// RecordConnectionError records a connection error
func (m *SolidNotificationMetrics) RecordConnectionError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ConnectionErrors++
}

// RecordDeliveryError records a delivery error
func (m *SolidNotificationMetrics) RecordDeliveryError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DeliveryErrors++
}

// GetMetrics returns a snapshot of the current metrics
func (m *SolidNotificationMetrics) GetMetrics() SolidNotificationMetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return SolidNotificationMetricsSnapshot{
		ChannelsCreated:           m.ChannelsCreated,
		ChannelsClosed:            m.ChannelsClosed,
		ActiveChannels:            m.ActiveChannels,
		ConnectionsOpened:         m.ConnectionsOpened,
		ConnectionsClosed:         m.ConnectionsClosed,
		ActiveConnections:         m.ActiveConnections,
		NotificationsSent:         m.NotificationsSent,
		NotificationsDelivered:    m.NotificationsDelivered,
		NotificationsFailed:       m.NotificationsFailed,
		WebSocketMessagesSent:     m.WebSocketMessagesSent,
		WebSocketMessagesReceived: m.WebSocketMessagesReceived,
		SSEEventsSent:             m.SSEEventsSent,
		WebhookDeliveries:         m.WebhookDeliveries,
		ProtocolErrors:            m.ProtocolErrors,
		ConnectionErrors:          m.ConnectionErrors,
		DeliveryErrors:            m.DeliveryErrors,
		TotalDeliveryTime:         m.TotalDeliveryTime,
		AverageDeliveryTime:       m.AverageDeliveryTime,
		DeliveriesCount:           m.DeliveriesCount,
	}
}

// NewSolidNotificationService creates a new Solid notification service
func NewSolidNotificationService(config SolidNotificationConfig) *SolidNotificationService {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	service := &SolidNotificationService{
		config:   config,
		channels: make(map[string]*SolidNotificationChannel),
		metrics:  SolidNotificationMetrics{},
		logger:   config.Logger,
		closed:   false,
	}

	// Initialize managers based on configuration
	if config.WebSocketConfig.MaxConnections > 0 {
		service.webSocketManager = NewWebSocketManager(config.WebSocketConfig, service)
	}

	if config.SSEConfig.MaxConnections > 0 {
		service.sseManager = NewSSEManager(config.SSEConfig, service)
	}

	if config.WebhookConfig.MaxConcurrentDeliveries > 0 {
		service.webhookManager = NewWebhookManager(config.WebhookConfig, service)
	}

	config.Logger.Info("Solid notification service created",
		"enabled", config.Enabled,
		"supported_protocols", len(config.SupportedProtocols),
		"default_protocol", config.DefaultProtocol,
	)

	return service
}

// SetFanoutService sets the fanout service reference
func (s *SolidNotificationService) SetFanoutService(fanoutService *FanoutService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fanoutService = fanoutService
}

// SetSubscriptionRegistry sets the subscription registry reference
func (s *SolidNotificationService) SetSubscriptionRegistry(registry *SubscriptionRegistry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscriptionRegistry = registry
}

// SetDurableLog sets the durable event log reference
func (s *SolidNotificationService) SetDurableLog(log *DurableEventLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durableLog = log
}

// SetEventStream sets the event stream layer reference
func (s *SolidNotificationService) SetEventStream(stream *EventStreamLayer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventStream = stream
}

// Start starts the Solid notification service
func (s *SolidNotificationService) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrWorkerPoolClosed
	}

	if !s.config.Enabled {
		s.logger.Info("Solid notification service is disabled")
		return nil
	}

	// Start managers
	if s.webSocketManager != nil {
		if err := s.webSocketManager.Start(); err != nil {
			return fmt.Errorf("failed to start WebSocket manager: %w", err)
		}
	}

	if s.sseManager != nil {
		if err := s.sseManager.Start(); err != nil {
			return fmt.Errorf("failed to start SSE manager: %w", err)
		}
	}

	if s.webhookManager != nil {
		if err := s.webhookManager.Start(); err != nil {
			return fmt.Errorf("failed to start webhook manager: %w", err)
		}
	}

	s.logger.Info("Solid notification service started")
	return nil
}

// Stop stops the Solid notification service
func (s *SolidNotificationService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	// Stop managers
	if s.webSocketManager != nil {
		if err := s.webSocketManager.Stop(); err != nil {
			return err
		}
	}

	if s.sseManager != nil {
		if err := s.sseManager.Stop(); err != nil {
			return err
		}
	}

	if s.webhookManager != nil {
		if err := s.webhookManager.Stop(); err != nil {
			return err
		}
	}

	s.closed = true
	s.logger.Info("Solid notification service stopped")

	return nil
}

// Close closes the Solid notification service
func (s *SolidNotificationService) Close() error {
	return s.Stop()
}

// IsClosed returns true if the service is closed
func (s *SolidNotificationService) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// IsEnabled returns true if Solid notifications are enabled
func (s *SolidNotificationService) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Enabled
}

// GetMetrics returns the current metrics
func (s *SolidNotificationService) GetMetrics() SolidNotificationMetricsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metrics.GetMetrics()
}

// NotifyResourceChange notifies subscribers about a resource change
func (s *SolidNotificationService) NotifyResourceChange(
	ctx context.Context,
	resourceURI string,
	containerURI string,
	changeType string,
	actor string,
	privacyLevel PrivacyLevel,
	metadata map[string]interface{},
) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed || !s.config.Enabled {
		return nil // Silently ignore if service is closed or disabled
	}

	// Create notification message
	now := time.Now().UTC()
	notification := SolidNotificationMessage{
		ID:         generateNotificationID(),
		Type:       "ResourceChange",
		Resource:   resourceURI,
		Container:  containerURI,
		ChangeType: changeType,
		Actor:      actor,
		Timestamp:  now,
		State:      metadata,
		Metadata:   make(map[string]interface{}),
		Cursor:     fmt.Sprintf("cursor-%d", now.UnixNano()),
	}

	// Add notification to durable log if available
	if s.durableLog != nil {
		streamEvent := StreamEvent{
			EventID:      notification.ID,
			EventType:    NotificationEventType(changeType),
			ResourceURI:  resourceURI,
			ContainerURI: containerURI,
			Timestamp:    now,
			Agent:        actor,
			Action:       changeType,
			Metadata:     convertMetadataToStringMap(metadata),
			PrivacyLevel: privacyLevel,
		}

		if err := s.durableLog.WriteEvent(streamEvent); err != nil {
			s.logger.Warn("Failed to write event to durable log", "error", err)
			// Continue with notification even if logging fails
		}
	}

	// Fan out notification using fanout service
	if s.fanoutService != nil {
		streamEvent := StreamEvent{
			EventID:      notification.ID,
			EventType:    NotificationEventType(changeType),
			ResourceURI:  resourceURI,
			ContainerURI: containerURI,
			Timestamp:    now,
			Agent:        actor,
			Action:       changeType,
			Metadata:     convertMetadataToStringMap(metadata),
			PrivacyLevel: privacyLevel,
		}

		if _, err := s.fanoutService.FanoutEventToSubscribers(streamEvent); err != nil {
			s.logger.Warn("Failed to fan out notification", "error", err)
			// Continue with direct notification delivery
		}
	}

	// Deliver notification via appropriate protocol managers
	s.deliverNotification(ctx, notification)

	// Record metrics
	s.metrics.RecordNotificationSent()

	return nil
}

// deliverNotification delivers a notification via the appropriate protocol managers
func (s *SolidNotificationService) deliverNotification(ctx context.Context, notification SolidNotificationMessage) {
	// This would be implemented based on the actual subscriptions
	// For now, we'll just log the notification
	s.logger.Info("Delivering notification",
		"notification_id", notification.ID,
		"resource", notification.Resource,
		"change_type", notification.ChangeType,
		"actor", notification.Actor,
		"timestamp", notification.Timestamp,
	)
}

// generateNotificationID generates a unique notification ID
func generateNotificationID() string {
	return fmt.Sprintf("notif-%d", time.Now().UnixNano())
}

// convertMetadataToStringMap converts interface{} metadata to string map
func convertMetadataToStringMap(metadata map[string]interface{}) map[string]string {
	if metadata == nil {
		return nil
	}

	result := make(map[string]string)
	for k, v := range metadata {
		if str, ok := v.(string); ok {
			result[k] = str
		} else {
			// Convert other types to string representation
			result[k] = fmt.Sprintf("%v", v)
		}
	}
	return result
}

// WebSocketManager manages WebSocket connections for Solid notifications
type WebSocketManager struct {
	mu sync.RWMutex

	config WebSocketConfig

	// Connections
	connections map[string]*WebSocketConnection

	// Notification service reference
	notificationService *SolidNotificationService

	// Logger
	logger *slog.Logger

	// State
	started bool
	closed  bool
}

// WebSocketConnection represents a WebSocket connection
type WebSocketConnection struct {
	// ConnectionID is a unique identifier for this connection
	ConnectionID string

	// SubscriptionID is the ID of the associated subscription
	SubscriptionID string

	// WebSocket connection (would be *gorilla/websocket.Conn in real implementation)
	// For now, we'll use a placeholder
	Connection interface{}

	// Context for this connection
	Context context.Context

	// Cancel function
	Cancel context.CancelFunc

	// Created is when the connection was created
	Created time.Time

	// LastActivity is when the connection had last activity
	LastActivity time.Time

	// State
	Connected bool
}

// NewWebSocketManager creates a new WebSocket manager
func NewWebSocketManager(config WebSocketConfig, notificationService *SolidNotificationService) *WebSocketManager {
	return &WebSocketManager{
		config:              config,
		connections:         make(map[string]*WebSocketConnection),
		notificationService: notificationService,
		logger:              notificationService.config.Logger,
	}
}

// Start starts the WebSocket manager
func (w *WebSocketManager) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.started {
		return nil
	}

	w.started = true
	w.logger.Info("WebSocket manager started")

	return nil
}

// Stop stops the WebSocket manager
func (w *WebSocketManager) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	// Close all connections
	for _, conn := range w.connections {
		w.closeConnection(conn)
	}

	w.connections = nil
	w.closed = true
	w.started = false

	w.logger.Info("WebSocket manager stopped")

	return nil
}

// closeConnection closes a WebSocket connection
func (w *WebSocketManager) closeConnection(conn *WebSocketConnection) {
	if conn.Cancel != nil {
		conn.Cancel()
	}
	conn.Connected = false
	w.notificationService.metrics.RecordConnectionClosed()
	w.logger.Info("WebSocket connection closed", "connection_id", conn.ConnectionID)
}

// SSEManager manages Server-Sent Events connections for Solid notifications
type SSEManager struct {
	mu sync.RWMutex

	config SSEConfig

	// Connections
	connections map[string]*SSEConnection

	// Notification service reference
	notificationService *SolidNotificationService

	// Logger
	logger *slog.Logger

	// State
	started bool
	closed  bool
}

// SSEConnection represents a Server-Sent Events connection
type SSEConnection struct {
	// ConnectionID is a unique identifier for this connection
	ConnectionID string

	// SubscriptionID is the ID of the associated subscription
	SubscriptionID string

	// Context for this connection
	Context context.Context

	// Cancel function
	Cancel context.CancelFunc

	// Created is when the connection was created
	Created time.Time

	// LastActivity is when the connection had last activity
	LastActivity time.Time

	// Event channel for sending events
	EventChannel chan SolidNotificationMessage

	// State
	Connected bool
}

// NewSSEManager creates a new SSE manager
func NewSSEManager(config SSEConfig, notificationService *SolidNotificationService) *SSEManager {
	return &SSEManager{
		config:              config,
		connections:         make(map[string]*SSEConnection),
		notificationService: notificationService,
		logger:              notificationService.config.Logger,
	}
}

// Start starts the SSE manager
func (s *SSEManager) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return nil
	}

	s.started = true
	s.logger.Info("SSE manager started")

	return nil
}

// Stop stops the SSE manager
func (s *SSEManager) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	// Close all connections
	for _, conn := range s.connections {
		s.closeConnection(conn)
	}

	s.connections = nil
	s.closed = true
	s.started = false

	s.logger.Info("SSE manager stopped")

	return nil
}

// closeConnection closes an SSE connection
func (s *SSEManager) closeConnection(conn *SSEConnection) {
	if conn.Cancel != nil {
		conn.Cancel()
	}
	conn.Connected = false
	close(conn.EventChannel)
	s.notificationService.metrics.RecordConnectionClosed()
	s.logger.Info("SSE connection closed", "connection_id", conn.ConnectionID)
}

// WebhookManager manages webhook deliveries for Solid notifications
type WebhookManager struct {
	mu sync.RWMutex

	config WebhookConfig

	// Webhook targets
	targets map[string]*WebhookTarget

	// Notification service reference
	notificationService *SolidNotificationService

	// Logger
	logger *slog.Logger

	// State
	started bool
	closed  bool
}

// WebhookTarget represents a webhook target
type WebhookTarget struct {
	// TargetID is a unique identifier for this target
	TargetID string

	// URL is the webhook URL
	URL string

	// SubscriptionID is the ID of the associated subscription
	SubscriptionID string

	// Secret is the secret for signing webhook deliveries
	Secret string

	// Context for this target
	Context context.Context

	// Cancel function
	Cancel context.CancelFunc

	// Created is when the target was created
	Created time.Time

	// LastDelivery is when the last delivery was made
	LastDelivery time.Time

	// DeliveryCount is the number of deliveries made to this target
	DeliveryCount int64

	// FailedCount is the number of failed deliveries to this target
	FailedCount int64

	// State
	Active bool
}

// NewWebhookManager creates a new webhook manager
func NewWebhookManager(config WebhookConfig, notificationService *SolidNotificationService) *WebhookManager {
	return &WebhookManager{
		config:              config,
		targets:             make(map[string]*WebhookTarget),
		notificationService: notificationService,
		logger:              notificationService.config.Logger,
	}
}

// Start starts the webhook manager
func (w *WebhookManager) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.started {
		return nil
	}

	w.started = true
	w.logger.Info("Webhook manager started")

	return nil
}

// Stop stops the webhook manager
func (w *WebhookManager) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	// Deactivate all targets
	for _, target := range w.targets {
		w.deactivateTarget(target)
	}

	w.targets = nil
	w.closed = true
	w.started = false

	w.logger.Info("Webhook manager stopped")

	return nil
}

// deactivateTarget deactivates a webhook target
func (w *WebhookManager) deactivateTarget(target *WebhookTarget) {
	if target.Cancel != nil {
		target.Cancel()
	}
	target.Active = false
	w.logger.Info("Webhook target deactivated", "target_id", target.TargetID)
}

// ValidateWebSocketURL validates a WebSocket URL
func (s *SolidNotificationService) ValidateWebSocketURL(urlStr string) error {
	if urlStr == "" {
		return ErrInvalidWebSocketURL
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidWebSocketURL, err)
	}

	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("%w: invalid scheme '%s', must be ws or wss", ErrInvalidWebSocketURL, u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidWebSocketURL)
	}

	return nil
}

// ValidateSSEURL validates a Server-Sent Events URL
func (s *SolidNotificationService) ValidateSSEURL(urlStr string) error {
	if urlStr == "" {
		return ErrInvalidSSEURL
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSSEURL, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: invalid scheme '%s', must be http or https", ErrInvalidSSEURL, u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidSSEURL)
	}

	return nil
}

// ValidateWebhookURL validates a webhook URL
func (s *SolidNotificationService) ValidateWebhookURL(urlStr string) error {
	if urlStr == "" {
		return ErrInvalidWebhookURL
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidWebhookURL, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: invalid scheme '%s', must be http or https", ErrInvalidWebhookURL, u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidWebhookURL)
	}

	return nil
}

// ValidateNotificationProtocol validates a notification protocol
func (s *SolidNotificationService) ValidateNotificationProtocol(protocol NotificationProtocol) error {
	// Map our protocol to Solid notification protocol
	solidProtocol := mapNotificationProtocol(protocol)

	// Check if protocol is supported
	for _, supported := range s.config.SupportedProtocols {
		if solidProtocol == supported {
			return nil
		}
	}

	return fmt.Errorf("%w: %s", ErrNotificationProtocolNotSupported, protocol)
}

// mapNotificationProtocol maps our notification protocol to Solid notification protocol
func mapNotificationProtocol(protocol NotificationProtocol) SolidNotificationProtocol {
	switch protocol {
	case ProtocolWebSocket:
		return SolidNotificationProtocolWebSocket
	case ProtocolSSE:
		return SolidNotificationProtocolSSE
	case ProtocolWebHook:
		return SolidNotificationProtocolWebhook
	case ProtocolSolid:
		return SolidNotificationProtocolWebSocket // Default to WebSocket for solid protocol
	default:
		return SolidNotificationProtocolWebSocket
	}
}

// CreateChannel creates a new Solid notification channel
func (s *SolidNotificationService) CreateChannel(
	channelID string,
	channelType string,
	topic string,
	filter StreamFilter,
	privacyLevel PrivacyLevel,
	metadata map[string]string,
) (*SolidNotificationChannel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrWorkerPoolClosed
	}

	if !s.config.Enabled {
		return nil, errors.New("Solid notifications are disabled")
	}

	// Check if channel already exists
	if _, exists := s.channels[channelID]; exists {
		return nil, fmt.Errorf("channel %s already exists", channelID)
	}

	// Create the channel
	channel := &SolidNotificationChannel{
		ID:           channelID,
		Type:         channelType,
		Topic:        topic,
		Filter:       filter,
		Subscribers:  []string{},
		Created:      time.Now().UTC(),
		Modified:     time.Now().UTC(),
		PrivacyLevel: privacyLevel,
		Metadata:     metadata,
	}

	// Store the channel
	s.channels[channelID] = channel

	// Record metrics
	s.metrics.RecordChannelCreated()

	s.logger.Info("Solid notification channel created",
		"channel_id", channelID,
		"channel_type", channelType,
		"topic", topic,
		"privacy_level", privacyLevel,
	)

	return channel, nil
}

// GetChannel returns a Solid notification channel by ID
func (s *SolidNotificationService) GetChannel(channelID string) (*SolidNotificationChannel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrWorkerPoolClosed
	}

	channel, exists := s.channels[channelID]
	if !exists {
		return nil, fmt.Errorf("channel %s not found", channelID)
	}

	return channel, nil
}

// DeleteChannel deletes a Solid notification channel
func (s *SolidNotificationService) DeleteChannel(channelID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrWorkerPoolClosed
	}

	if _, exists := s.channels[channelID]; !exists {
		return fmt.Errorf("channel %s not found", channelID)
	}

	delete(s.channels, channelID)

	// Record metrics
	s.metrics.RecordChannelClosed()

	s.logger.Info("Solid notification channel deleted", "channel_id", channelID)

	return nil
}

// ListChannels lists all Solid notification channels
func (s *SolidNotificationService) ListChannels() []*SolidNotificationChannel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil
	}

	channels := make([]*SolidNotificationChannel, 0, len(s.channels))
	for _, channel := range s.channels {
		channels = append(channels, channel)
	}

	return channels
}

// AddSubscriberToChannel adds a subscriber to a Solid notification channel
func (s *SolidNotificationService) AddSubscriberToChannel(channelID, subscriberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrWorkerPoolClosed
	}

	channel, exists := s.channels[channelID]
	if !exists {
		return fmt.Errorf("channel %s not found", channelID)
	}

	// Check if subscriber already exists
	for _, sub := range channel.Subscribers {
		if sub == subscriberID {
			return nil // Already subscribed
		}
	}

	channel.Subscribers = append(channel.Subscribers, subscriberID)
	channel.Modified = time.Now().UTC()

	s.logger.Info("Subscriber added to channel",
		"channel_id", channelID,
		"subscriber_id", subscriberID,
	)

	return nil
}

// RemoveSubscriberFromChannel removes a subscriber from a Solid notification channel
func (s *SolidNotificationService) RemoveSubscriberFromChannel(channelID, subscriberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrWorkerPoolClosed
	}

	channel, exists := s.channels[channelID]
	if !exists {
		return fmt.Errorf("channel %s not found", channelID)
	}

	// Find and remove the subscriber
	for i, sub := range channel.Subscribers {
		if sub == subscriberID {
			channel.Subscribers = append(channel.Subscribers[:i], channel.Subscribers[i+1:]...)
			channel.Modified = time.Now().UTC()

			s.logger.Info("Subscriber removed from channel",
				"channel_id", channelID,
				"subscriber_id", subscriberID,
			)
			return nil
		}
	}

	return fmt.Errorf("subscriber %s not found in channel %s", subscriberID, channelID)
}

// NotifyChannel notifies all subscribers of a channel about an event
func (s *SolidNotificationService) NotifyChannel(
	ctx context.Context,
	channelID string,
	notification SolidNotificationMessage,
) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed || !s.config.Enabled {
		return nil
	}

	channel, exists := s.channels[channelID]
	if !exists {
		return fmt.Errorf("channel %s not found", channelID)
	}

	// Set channel ID in notification
	notification.Metadata["channelId"] = channelID

	// Deliver to all subscribers
	for _, subscriberID := range channel.Subscribers {
		if err := s.deliverNotificationToSubscriber(ctx, subscriberID, notification); err != nil {
			s.logger.Warn("Failed to deliver notification to subscriber",
				"channel_id", channelID,
				"subscriber_id", subscriberID,
				"error", err,
			)
			// Continue with other subscribers
		}
	}

	return nil
}

// deliverNotificationToSubscriber delivers a notification to a specific subscriber
func (s *SolidNotificationService) deliverNotificationToSubscriber(
	ctx context.Context,
	subscriberID string,
	notification SolidNotificationMessage,
) error {
	// In a real implementation, this would look up the subscriber's delivery method
	// and deliver via the appropriate protocol manager

	// For now, we'll just log the delivery
	s.logger.Info("Notification delivered to subscriber",
		"notification_id", notification.ID,
		"subscriber_id", subscriberID,
		"resource", notification.Resource,
		"change_type", notification.ChangeType,
	)

	// Record metrics
	s.metrics.RecordNotificationDelivered(0) // 0 duration for simulation

	return nil
}

// HTTPHandler returns an HTTP handler for Solid notifications
func (s *SolidNotificationService) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.config.Enabled {
			http.Error(w, "Solid notifications are disabled", http.StatusServiceUnavailable)
			return
		}

		s.handleNotificationRequest(w, r)
	})
}

// handleNotificationRequest handles an HTTP request for Solid notifications
func (s *SolidNotificationService) handleNotificationRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleNotificationGet(w, r)
	case http.MethodPost:
		s.handleNotificationPost(w, r)
	case http.MethodDelete:
		s.handleNotificationDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleNotificationGet handles GET requests for Solid notifications
func (s *SolidNotificationService) handleNotificationGet(w http.ResponseWriter, r *http.Request) {
	// Handle WebSocket upgrade
	if s.isWebSocketUpgrade(r) {
		s.handleWebSocketConnection(w, r)
		return
	}

	// Handle SSE request
	if s.isSSERequest(r) {
		s.handleSSEConnection(w, r)
		return
	}

	// Handle channel listing
	if r.URL.Path == "/channels" {
		s.handleListChannels(w, r)
		return
	}

	// Handle specific channel
	if len(r.URL.Path) > 1 {
		channelID := r.URL.Path[1:]
		s.handleGetChannel(w, r, channelID)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleNotificationPost handles POST requests for Solid notifications
func (s *SolidNotificationService) handleNotificationPost(w http.ResponseWriter, r *http.Request) {
	// Handle channel creation
	if r.URL.Path == "/channels" {
		s.handleCreateChannel(w, r)
		return
	}

	// Handle subscription to channel
	if len(r.URL.Path) > 1 {
		channelID := r.URL.Path[1:]
		s.handleSubscribeToChannel(w, r, channelID)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleNotificationDelete handles DELETE requests for Solid notifications
func (s *SolidNotificationService) handleNotificationDelete(w http.ResponseWriter, r *http.Request) {
	// Handle channel deletion
	if len(r.URL.Path) > 1 {
		channelID := r.URL.Path[1:]
		s.handleDeleteChannel(w, r, channelID)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// isWebSocketUpgrade checks if a request is a WebSocket upgrade request
func (s *SolidNotificationService) isWebSocketUpgrade(r *http.Request) bool {
	// Check for WebSocket upgrade header
	connectionHeader := r.Header.Get("Connection")
	upgradeHeader := r.Header.Get("Upgrade")

	return connectionHeader == "Upgrade" && upgradeHeader == "websocket"
}

// isSSERequest checks if a request is a Server-Sent Events request
func (s *SolidNotificationService) isSSERequest(r *http.Request) bool {
	// Check for Accept header containing text/event-stream
	acceptHeader := r.Header.Get("Accept")
	return acceptHeader == "text/event-stream"
}

// handleWebSocketConnection handles a WebSocket connection
func (s *SolidNotificationService) handleWebSocketConnection(w http.ResponseWriter, r *http.Request) {
	// In a real implementation, this would upgrade the connection to WebSocket
	// and manage the WebSocket connection

	// For now, we'll return an error since WebSocket is not fully implemented
	http.Error(w, "WebSocket notifications not yet implemented", http.StatusNotImplemented)
}

// handleSSEConnection handles a Server-Sent Events connection
func (s *SolidNotificationService) handleSSEConnection(w http.ResponseWriter, r *http.Request) {
	// In a real implementation, this would establish an SSE connection
	// and send events as they occur

	// For now, we'll return an error since SSE is not fully implemented
	http.Error(w, "Server-Sent Events notifications not yet implemented", http.StatusNotImplemented)
}

// handleListChannels handles listing all channels
func (s *SolidNotificationService) handleListChannels(w http.ResponseWriter, r *http.Request) {
	channels := s.ListChannels()

	// Convert to JSON response
	response := struct {
		Channels []*SolidNotificationChannel `json:"channels"`
		Count    int                         `json:"count"`
	}{
		Channels: channels,
		Count:    len(channels),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleGetChannel handles getting a specific channel
func (s *SolidNotificationService) handleGetChannel(w http.ResponseWriter, r *http.Request, channelID string) {
	channel, err := s.GetChannel(channelID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(channel); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleCreateChannel handles creating a new channel
func (s *SolidNotificationService) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ChannelID    string            `json:"channelId"`
		ChannelType  string            `json:"channelType"`
		Topic        string            `json:"topic"`
		Filter       StreamFilter      `json:"filter"`
		PrivacyLevel PrivacyLevel      `json:"privacyLevel"`
		Metadata     map[string]string `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.ChannelID == "" {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	channel, err := s.CreateChannel(
		request.ChannelID,
		request.ChannelType,
		request.Topic,
		request.Filter,
		request.PrivacyLevel,
		request.Metadata,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(channel); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleSubscribeToChannel handles subscribing to a channel
func (s *SolidNotificationService) handleSubscribeToChannel(w http.ResponseWriter, r *http.Request, channelID string) {
	var request struct {
		SubscriberID string `json:"subscriberId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.SubscriberID == "" {
		http.Error(w, "Subscriber ID is required", http.StatusBadRequest)
		return
	}

	if err := s.AddSubscriberToChannel(channelID, request.SubscriberID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "subscribed",
		"channelId":    channelID,
		"subscriberId": request.SubscriberID,
	})
}

// handleDeleteChannel handles deleting a channel
func (s *SolidNotificationService) handleDeleteChannel(w http.ResponseWriter, r *http.Request, channelID string) {
	if err := s.DeleteChannel(channelID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "deleted",
		"channelId": channelID,
	})
}
