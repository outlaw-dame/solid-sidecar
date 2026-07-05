// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 6.10: Unified notification metrics and replay/resync for Phase 24.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// ErrReplayNotSupported is returned when replay is not supported
var ErrReplayNotSupported = errors.New("replay not supported")

// ErrInvalidReplayRequest is returned when a replay request is invalid
var ErrInvalidReplayRequest = errors.New("invalid replay request")

// ErrReplayInProgress is returned when a replay is already in progress
var ErrReplayInProgress = errors.New("replay already in progress")

// NotificationMetricsConfig holds configuration for notification metrics
type NotificationMetricsConfig struct {
	// EnablePrometheus enables Prometheus metrics export
	EnablePrometheus bool

	// EnableOpenTelemetry enables OpenTelemetry metrics export
	EnableOpenTelemetry bool

	// EnableLogging enables metrics logging
	EnableLogging bool

	// MetricsLogInterval is how often to log metrics
	MetricsLogInterval time.Duration

	// MaxMetricsHistory is the maximum number of historical metrics to keep
	MaxMetricsHistory int

	// EnablePercentiles enables calculation of percentile metrics
	EnablePercentiles bool

	// Percentiles to calculate
	Percentiles []float64

	// Logger is the logger for this component
	Logger *slog.Logger
}

// DefaultNotificationMetricsConfig returns a safe default configuration
func DefaultNotificationMetricsConfig() NotificationMetricsConfig {
	return NotificationMetricsConfig{
		EnablePrometheus:    false,
		EnableOpenTelemetry: false,
		EnableLogging:       true,
		MetricsLogInterval:  1 * time.Minute,
		MaxMetricsHistory:    1000,
		EnablePercentiles:   true,
		Percentiles:        []float64{0.5, 0.9, 0.95, 0.99, 0.999},
		Logger:             nil,
	}
}

// UnifiedNotificationMetrics provides a unified view of all notification-related metrics
type UnifiedNotificationMetrics struct {
	mu sync.RWMutex

	// Timestamp of the last metrics collection
	LastCollected time.Time

	// Durable event log metrics
	DurableLogMetrics DurableLogMetrics

	// Subscription registry metrics
	SubscriptionRegistryMetrics SubscriptionRegistryMetrics

	// Fanout worker pool metrics
	FanoutWorkerPoolMetrics FanoutWorkerPoolMetrics

	// Event stream metrics
	EventStreamMetrics EventStreamMetrics

	// Solid notification metrics
	SolidNotificationMetrics SolidNotificationMetrics

	// Aggregated delivery metrics
	DeliveryMetrics DeliveryMetrics

	// Historical metrics for trend analysis
	History []UnifiedNotificationMetrics

	// Metrics configuration
	config NotificationMetricsConfig

	// Logger
	logger *slog.Logger
}

// DeliveryMetrics holds aggregated delivery metrics
type DeliveryMetrics struct {
	// Total deliveries
	TotalDeliveries int64

	// Successful deliveries
	SuccessfulDeliveries int64

	// Failed deliveries
	FailedDeliveries int64

	// Delivery success rate
	SuccessRate float64

	// Delivery failure rate
	FailureRate float64

	// Average delivery latency
	AverageLatency time.Duration

	// Minimum delivery latency
	MinLatency time.Duration

	// Maximum delivery latency
	MaxLatency time.Duration

	// Latency percentiles
	LatencyPercentiles map[float64]time.Duration

	// Total delivery time
	TotalDeliveryTime time.Duration

	// Total retries
	TotalRetries int64

	// Average retries per delivery
	AverageRetries float64

	// Events dropped due to backpressure
	BackpressureDrops int64

	// Events dropped due to queue full
	QueueFullDrops int64

	// Events dropped due to storage full
	StorageFullDrops int64

	// Events dropped due to other reasons
	OtherDrops int64

	// Total drops
	TotalDrops int64

	// Drop rate
	DropRate float64

	// Connection metrics
	ActiveConnections int64
	TotalConnections   int64

	// Channel metrics
	ActiveChannels int64
	TotalChannels   int64

	// Subscription metrics
	ActiveSubscriptions   int64
	TotalSubscriptions    int64
}

// NewUnifiedNotificationMetrics creates a new unified notification metrics collector
func NewUnifiedNotificationMetrics(config NotificationMetricsConfig) *UnifiedNotificationMetrics {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	metrics := &UnifiedNotificationMetrics{
		LastCollected: time.Now(),
		History:       make([]UnifiedNotificationMetrics, 0, config.MaxMetricsHistory),
		config:        config,
		logger:        config.Logger,
		DeliveryMetrics: DeliveryMetrics{
			LatencyPercentiles: make(map[float64]time.Duration),
		},
	}

	// Start background collection
	go metrics.collectionLoop()

	config.Logger.Info("Unified notification metrics initialized",
		"enable_prometheus", config.EnablePrometheus,
		"enable_opentelemetry", config.EnableOpenTelemetry,
		"enable_logging", config.EnableLogging,
		"metrics_log_interval", config.MetricsLogInterval,
	)

	return metrics
}

// collectionLoop periodically collects and aggregates metrics
func (m *UnifiedNotificationMetrics) collectionLoop() {
	if m.config.MetricsLogInterval <= 0 {
		return
	}

	ticker := time.NewTicker(m.config.MetricsLogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.collectAndLogMetrics()
		}
	}
}

// collectAndLogMetrics collects all metrics and logs them
func (m *UnifiedNotificationMetrics) collectAndLogMetrics() {
	// Collect current metrics from all components
	// This would be called with actual component references in a real implementation
	
	// For now, we'll just log the current state
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LastCollected = time.Now()

	// Create a snapshot
	snapshot := m.createSnapshot()

	// Add to history
	if len(m.History) >= m.config.MaxMetricsHistory {
		m.History = m.History[1:]
	}
	m.History = append(m.History, *snapshot)

	// Log metrics if enabled
	if m.config.EnableLogging {
		m.logMetrics(snapshot)
	}
}

// createSnapshot creates a snapshot of the current metrics
func (m *UnifiedNotificationMetrics) createSnapshot() *UnifiedNotificationMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a deep copy
	snapshot := &UnifiedNotificationMetrics{
		LastCollected:               m.LastCollected,
		DurableLogMetrics:           m.DurableLogMetrics,
		SubscriptionRegistryMetrics: m.SubscriptionRegistryMetrics,
		FanoutWorkerPoolMetrics:      m.FanoutWorkerPoolMetrics,
		EventStreamMetrics:          m.EventStreamMetrics,
		SolidNotificationMetrics:   m.SolidNotificationMetrics,
		DeliveryMetrics:             m.DeliveryMetrics,
		config:                      m.config,
		logger:                      m.logger,
	}

	// Copy history (just references for now)
	snapshot.History = make([]UnifiedNotificationMetrics, len(m.History))
	for i, h := range m.History {
		snapshot.History[i] = h
	}

	return snapshot
}

// logMetrics logs the current metrics
func (m *UnifiedNotificationMetrics) logMetrics(metrics *UnifiedNotificationMetrics) {
	// Log delivery metrics
	m.logger.Info("Notification Metrics",
		// Durable log metrics
		"durable_events_logged", metrics.DurableLogMetrics.TotalEventsLogged,
		"durable_events_read", metrics.DurableLogMetrics.TotalEventsRead,
		"durable_corruptions_detected", metrics.DurableLogMetrics.CorruptionDetected,
		"durable_storage_full_errors", metrics.DurableLogMetrics.StorageFullErrors,

		// Subscription metrics
		"total_subscriptions", metrics.SubscriptionRegistryMetrics.TotalSubscriptions,
		"active_subscriptions", metrics.SubscriptionRegistryMetrics.ActiveSubscriptions,
		"subscription_creations", metrics.SubscriptionRegistryMetrics.SubscriptionCreations,
		"subscription_cancellations", metrics.SubscriptionRegistryMetrics.SubscriptionCancellations,
		"authentication_failures", metrics.SubscriptionRegistryMetrics.AuthenticationFailures,
		"authorization_failures", metrics.SubscriptionRegistryMetrics.AuthorizationFailures,

		// Fanout metrics
		"fanout_workers_active", metrics.FanoutWorkerPoolMetrics.WorkersActive,
		"fanout_events_distributed", metrics.FanoutWorkerPoolMetrics.EventsDistributed,
		"fanout_events_queued", metrics.FanoutWorkerPoolMetrics.EventsQueued,
		"fanout_events_dropped", metrics.FanoutWorkerPoolMetrics.EventsDropped,
		"fanout_backpressure_events", metrics.FanoutWorkerPoolMetrics.BackpressureEvents,
		"fanout_queue_full_events", metrics.FanoutWorkerPoolMetrics.QueueFullEvents,

		// Event stream metrics
		"stream_events_added", metrics.EventStreamMetrics.TotalEventsAdded,
		"stream_events_streamed", metrics.EventStreamMetrics.TotalEventsStreamed,
		"stream_events_dropped", metrics.EventStreamMetrics.EventsDroppedDueToLimit,
		"stream_subscribers", metrics.EventStreamMetrics.TotalSubscribers,
		"stream_active_subscribers", metrics.EventStreamMetrics.ActiveSubscribers,

		// Solid notification metrics
		"solid_channels_created", metrics.SolidNotificationMetrics.ChannelsCreated,
		"solid_channels_active", metrics.SolidNotificationMetrics.ActiveChannels,
		"solid_connections_opened", metrics.SolidNotificationMetrics.ConnectionsOpened,
		"solid_connections_active", metrics.SolidNotificationMetrics.ActiveConnections,
		"solid_notifications_sent", metrics.SolidNotificationMetrics.NotificationsSent,
		"solid_notifications_delivered", metrics.SolidNotificationMetrics.NotificationsDelivered,
		"solid_notifications_failed", metrics.SolidNotificationMetrics.NotificationsFailed,

		// Aggregated delivery metrics
		"delivery_total", metrics.DeliveryMetrics.TotalDeliveries,
		"delivery_successes", metrics.DeliveryMetrics.SuccessfulDeliveries,
		"delivery_failures", metrics.DeliveryMetrics.FailedDeliveries,
		"delivery_success_rate", fmt.Sprintf("%.2f%%", metrics.DeliveryMetrics.SuccessRate*100),
		"delivery_avg_latency", metrics.DeliveryMetrics.AverageLatency,
		"delivery_total_retries", metrics.DeliveryMetrics.TotalRetries,
		"delivery_drops_total", metrics.DeliveryMetrics.TotalDrops,
		"delivery_drop_rate", fmt.Sprintf("%.2f%%", metrics.DeliveryMetrics.DropRate*100),
	)
}

// UpdateFromComponents updates metrics from all components
func (m *UnifiedNotificationMetrics) UpdateFromComponents(
	durableLogMetrics *DurableLogMetrics,
	subscriptionRegistryMetrics *SubscriptionRegistryMetrics,
	fanoutPoolMetrics *FanoutWorkerPoolMetrics,
	streamMetrics *EventStreamMetrics,
	solidMetrics *SolidNotificationMetrics,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Update individual component metrics
	if durableLogMetrics != nil {
		m.DurableLogMetrics = *durableLogMetrics
	}
	if subscriptionRegistryMetrics != nil {
		m.SubscriptionRegistryMetrics = *subscriptionRegistryMetrics
	}
	if fanoutPoolMetrics != nil {
		m.FanoutWorkerPoolMetrics = *fanoutPoolMetrics
	}
	if streamMetrics != nil {
		m.EventStreamMetrics = *streamMetrics
	}
	if solidMetrics != nil {
		m.SolidNotificationMetrics = *solidMetrics
	}

	// Recalculate aggregated metrics
	m.recalculateAggregatedMetrics()
}

// recalculateAggregatedMetrics recalculates all aggregated metrics
func (m *UnifiedNotificationMetrics) recalculateAggregatedMetrics() {
	// Calculate delivery metrics
	m.calculateDeliveryMetrics()
	
	// Calculate connection metrics
	m.calculateConnectionMetrics()
	
	// Calculate channel metrics
	m.calculateChannelMetrics()
	
	// Calculate subscription metrics
	m.calculateSubscriptionMetrics()
}

// calculateDeliveryMetrics calculates delivery-related metrics
func (m *UnifiedNotificationMetrics) calculateDeliveryMetrics() {
	// Total deliveries
	totalDeliveries := m.SubscriptionRegistryMetrics.TotalDeliveries +
		m.FanoutWorkerPoolMetrics.TotalEventsSucceeded +
		m.SolidNotificationMetrics.NotificationsDelivered

	// Successful deliveries
	successfulDeliveries := m.SubscriptionRegistryMetrics.TotalDeliveries +
		m.FanoutWorkerPoolMetrics.TotalEventsSucceeded +
		m.SolidNotificationMetrics.NotificationsDelivered

	// Failed deliveries
	failedDeliveries := m.SubscriptionRegistryMetrics.TotalDeliveryFailures +
		m.FanoutWorkerPoolMetrics.TotalEventsFailed +
		m.SolidNotificationMetrics.NotificationsFailed

	// Total retries
	totalRetries := m.SubscriptionRegistryMetrics.TotalRetries +
		m.FanoutWorkerPoolMetrics.TotalEventsRetried

	// Total drops
	totalDrops := m.FanoutWorkerPoolMetrics.EventsDropped +
		m.DurableLogMetrics.StorageFullErrors +
		m.EventStreamMetrics.EventsDroppedDueToLimit

	// Calculate rates
	var successRate, failureRate float64
	if totalDeliveries > 0 {
		successRate = float64(successfulDeliveries) / float64(totalDeliveries)
		failureRate = float64(failedDeliveries) / float64(totalDeliveries)
	}

	// Calculate drop rate
	var dropRate float64
	if totalDeliveries > 0 {
		dropRate = float64(totalDrops) / float64(totalDeliveries)
	}

	// Calculate average retries
	var averageRetries float64
	if successfulDeliveries > 0 {
		averageRetries = float64(totalRetries) / float64(successfulDeliveries)
	}

	// Update delivery metrics
	m.DeliveryMetrics = DeliveryMetrics{
		TotalDeliveries:        totalDeliveries,
		SuccessfulDeliveries:   successfulDeliveries,
		FailedDeliveries:       failedDeliveries,
		SuccessRate:           successRate,
		FailureRate:           failureRate,
		AverageRetries:        averageRetries,
		TotalRetries:          totalRetries,
		BackpressureDrops:      m.FanoutWorkerPoolMetrics.BackpressureEvents,
		QueueFullDrops:        m.FanoutWorkerPoolMetrics.QueueFullEvents,
		StorageFullDrops:      m.DurableLogMetrics.StorageFullErrors,
		TotalDrops:            totalDrops,
		DropRate:              dropRate,
		LatencyPercentiles:    make(map[float64]time.Duration),
	}
}

// calculateConnectionMetrics calculates connection-related metrics
func (m *UnifiedNotificationMetrics) calculateConnectionMetrics() {
	m.DeliveryMetrics.ActiveConnections = m.SolidNotificationMetrics.ActiveConnections
	m.DeliveryMetrics.TotalConnections = m.SolidNotificationMetrics.ConnectionsOpened
}

// calculateChannelMetrics calculates channel-related metrics
func (m *UnifiedNotificationMetrics) calculateChannelMetrics() {
	m.DeliveryMetrics.ActiveChannels = m.SolidNotificationMetrics.ActiveChannels
	m.DeliveryMetrics.TotalChannels = m.SolidNotificationMetrics.ChannelsCreated
}

// calculateSubscriptionMetrics calculates subscription-related metrics
func (m *UnifiedNotificationMetrics) calculateSubscriptionMetrics() {
	m.DeliveryMetrics.ActiveSubscriptions = m.SubscriptionRegistryMetrics.ActiveSubscriptions
	m.DeliveryMetrics.TotalSubscriptions = m.SubscriptionRegistryMetrics.TotalSubscriptions
}

// GetMetrics returns the current unified metrics
func (m *UnifiedNotificationMetrics) GetMetrics() UnifiedNotificationMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy
	return *m
}

// GetDeliveryMetrics returns just the delivery metrics
func (m *UnifiedNotificationMetrics) GetDeliveryMetrics() DeliveryMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.DeliveryMetrics
}

// RecordDelivery records a delivery with latency
func (m *UnifiedNotificationMetrics) RecordDelivery(success bool, latency time.Duration, retried bool) {
	// This would update the underlying component metrics
	// For now, we'll update the aggregated metrics directly
	m.mu.Lock()
	defer m.mu.Unlock()

	if success {
		m.DeliveryMetrics.SuccessfulDeliveries++
	} else {
		m.DeliveryMetrics.FailedDeliveries++
	}
	
	m.DeliveryMetrics.TotalDeliveries++
	
	if retried {
		m.DeliveryMetrics.TotalRetries++
	}

	// Update latency metrics
	m.DeliveryMetrics.TotalDeliveryTime += latency
	
	// Update min/max latency
	if latency < m.DeliveryMetrics.MinLatency || m.DeliveryMetrics.MinLatency == 0 {
		m.DeliveryMetrics.MinLatency = latency
	}
	if latency > m.DeliveryMetrics.MaxLatency {
		m.DeliveryMetrics.MaxLatency = latency
	}

	// Recalculate rates
	m.recalculateAggregatedMetrics()
}

// RecordDrop records a dropped event
func (m *UnifiedNotificationMetrics) RecordDrop(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DeliveryMetrics.TotalDrops++
	
	switch reason {
	case "backpressure":
		m.DeliveryMetrics.BackpressureDrops++
	case "queue_full":
		m.DeliveryMetrics.QueueFullDrops++
	case "storage_full":
		m.DeliveryMetrics.StorageFullDrops++
	default:
		m.DeliveryMetrics.OtherDrops++
	}

	// Recalculate rates
	m.recalculateAggregatedMetrics()
}

// ReplayService provides replay and resync functionality for notifications
type ReplayService struct {
	mu sync.RWMutex

	// Durable event log for replay
	durableLog *DurableEventLog

	// Subscription registry for cursor management
	subscriptionRegistry *SubscriptionRegistry

	// Fanout service for replay delivery
	fanoutService *FanoutService

	// Configuration
	config ReplayServiceConfig

	// Replay state
	replaysInProgress map[string]*ReplaySession

	// Metrics
	metrics ReplayServiceMetrics

	// Logger
	logger *slog.Logger

	// Close state
	closed bool
}

// ReplayServiceConfig holds configuration for the replay service
type ReplayServiceConfig struct {
	// MaxConcurrentReplays is the maximum number of concurrent replay sessions
	MaxConcurrentReplays int

	// MaxReplayRate is the maximum rate of events to replay per second
	MaxReplayRate int

	// ReplayTimeout is the timeout for replay sessions
	ReplayTimeout time.Duration

	// EnableMetrics enables metrics collection
	EnableMetrics bool

	// Logger is the logger for this component
	Logger *slog.Logger
}

// DefaultReplayServiceConfig returns a safe default configuration
func DefaultReplayServiceConfig() ReplayServiceConfig {
	return ReplayServiceConfig{
		MaxConcurrentReplays: 10,
		MaxReplayRate:        1000,
		ReplayTimeout:        5 * time.Minute,
		EnableMetrics:        true,
		Logger:              nil,
	}
}

// ReplaySession represents a replay session
type ReplaySession struct {
	// SessionID is a unique identifier for this replay session
	SessionID string

	// SubscriptionID is the ID of the subscription being replayed
	SubscriptionID string

	// StartCursor is the starting cursor for replay
	StartCursor int64

	// EndCursor is the ending cursor for replay (0 means current)
	EndCursor int64

	// CurrentCursor is the current replay position
	CurrentCursor int64

	// Status is the current status of the replay session
	Status ReplaySessionStatus

	// Started is when the replay session started
	Started time.Time

	// LastActivity is when the replay session had last activity
	LastActivity time.Time

	// EventsReplayed is the number of events replayed
	EventsReplayed int64

	// EventsFailed is the number of events that failed to replay
	EventsFailed int64

	// Error contains any error that occurred
	Error error

	// Context for cancellation
	Context context.Context
	Cancel  context.CancelFunc

	// Progress channel for reporting progress
	ProgressChannel chan ReplayProgress

	// Completion channel for signaling completion
	CompletionChannel chan ReplayResult
}

// ReplaySessionStatus represents the status of a replay session
type ReplaySessionStatus string

const (
	ReplaySessionStatusPending   ReplaySessionStatus = "pending"
	ReplaySessionStatusRunning   ReplaySessionStatus = "running"
	ReplaySessionStatusPaused    ReplaySessionStatus = "paused"
	ReplaySessionStatusCompleted ReplaySessionStatus = "completed"
	ReplaySessionStatusFailed    ReplaySessionStatus = "failed"
	ReplaySessionStatusCancelled ReplaySessionStatus = "cancelled"
)

// ReplayProgress represents progress during a replay session
type ReplayProgress struct {
	// SessionID is the replay session ID
	SessionID string

	// CurrentCursor is the current replay position
	CurrentCursor int64

	// EventsReplayed is the number of events replayed so far
	EventsReplayed int64

	// ProgressPercentage is the percentage of replay completed
	ProgressPercentage float64

	// Timestamp is when this progress was reported
	Timestamp time.Time
}

// ReplayResult represents the result of a replay session
type ReplayResult struct {
	// SessionID is the replay session ID
	SessionID string

	// Success indicates if the replay was successful
	Success bool

	// StartCursor is the starting cursor for the replay
	StartCursor int64

	// EndCursor is the ending cursor for the replay
	EndCursor int64

	// FinalCursor is the cursor where replay ended
	FinalCursor int64

	// EventsReplayed is the total number of events replayed
	EventsReplayed int64

	// EventsFailed is the number of events that failed to replay
	EventsFailed int64

	// Duration is how long the replay took
	Duration time.Duration

	// Error contains any error that occurred
	Error error

	// Timestamp is when the replay completed
	Timestamp time.Time
}

// ReplayServiceMetrics holds metrics for the replay service
type ReplayServiceMetrics struct {
	mu sync.RWMutex

	// Replay sessions
	ReplaySessionsStarted  int64
	ReplaySessionsCompleted int64
	ReplaySessionsFailed    int64
	ReplaySessionsCancelled int64

	// Events replayed
	EventsReplayed int64
	EventsFailed   int64

	// Replay performance
	TotalReplayTime time.Duration
	AverageReplayTime time.Duration
	ReplayCount int64

	// Current active replays
	ActiveReplays int64

	// Errors
	ReplayErrors int64
}

// RecordReplayStarted records a replay session being started
func (m *ReplayServiceMetrics) RecordReplayStarted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ReplaySessionsStarted++
	m.ActiveReplays++
}

// RecordReplayCompleted records a replay session being completed
func (m *ReplayServiceMetrics) RecordReplayCompleted(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ReplaySessionsCompleted++
	m.ActiveReplays--
	m.TotalReplayTime += duration
	m.ReplayCount++
	if m.ReplayCount > 0 {
		m.AverageReplayTime = m.TotalReplayTime / time.Duration(m.ReplayCount)
	}
}

// RecordReplayFailed records a replay session failure
func (m *ReplayServiceMetrics) RecordReplayFailed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ReplaySessionsFailed++
	m.ActiveReplays--
	m.ReplayErrors++
}

// RecordReplayCancelled records a replay session being cancelled
func (m *ReplayServiceMetrics) RecordReplayCancelled() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ReplaySessionsCancelled++
	m.ActiveReplays--
}

// RecordEventsReplayed records events being replayed
func (m *ReplayServiceMetrics) RecordEventsReplayed(count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsReplayed += count
}

// RecordEventsFailed records replay failures
func (m *ReplayServiceMetrics) RecordEventsFailed(count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsFailed += count
}

// GetMetrics returns a copy of the current metrics
func (m *ReplayServiceMetrics) GetMetrics() ReplayServiceMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *m
}

// NewReplayService creates a new replay service
func NewReplayService(config ReplayServiceConfig) *ReplayService {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	service := &ReplayService{
		config:           config,
		replaysInProgress: make(map[string]*ReplaySession),
		metrics:          ReplayServiceMetrics{},
		logger:           config.Logger,
		closed:           false,
	}

	config.Logger.Info("Replay service initialized",
		"max_concurrent_replays", config.MaxConcurrentReplays,
		"max_replay_rate", config.MaxReplayRate,
		"replay_timeout", config.ReplayTimeout,
	)

	return service
}

// SetDurableLog sets the durable event log reference
func (s *ReplayService) SetDurableLog(log *DurableEventLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durableLog = log
}

// SetSubscriptionRegistry sets the subscription registry reference
func (s *ReplayService) SetSubscriptionRegistry(registry *SubscriptionRegistry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscriptionRegistry = registry
}

// SetFanoutService sets the fanout service reference
func (s *ReplayService) SetFanoutService(fanoutService *FanoutService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fanoutService = fanoutService
}

// StartReplay starts a replay session for a subscription
func (s *ReplayService) StartReplay(
	ctx context.Context,
	subscriptionID string,
	startCursor int64,
	endCursor int64,
) (*ReplaySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrReplayNotSupported
	}

	if s.durableLog == nil {
		return nil, ErrReplayNotSupported
	}

	// Check if replay is already in progress for this subscription
	for _, session := range s.replaysInProgress {
		if session.SubscriptionID == subscriptionID && session.Status == ReplaySessionStatusRunning {
			return nil, ErrReplayInProgress
		}
	}

	// Check concurrent replay limit
	if len(s.replaysInProgress) >= s.config.MaxConcurrentReplays {
		return nil, fmt.Errorf("maximum concurrent replays reached (%d)", s.config.MaxConcurrentReplays)
	}

	// Create replay session
	session := &ReplaySession{
		SessionID:       generateReplaySessionID(),
		SubscriptionID:  subscriptionID,
		StartCursor:     startCursor,
		EndCursor:       endCursor,
		CurrentCursor:   startCursor,
		Status:          ReplaySessionStatusPending,
		Started:         time.Now().UTC(),
		LastActivity:    time.Now().UTC(),
		ProgressChannel: make(chan ReplayProgress, 10),
		CompletionChannel: make(chan ReplayResult, 1),
	}

	// Create context with timeout
	replayCtx, cancel := context.WithTimeout(ctx, s.config.ReplayTimeout)
	session.Context = replayCtx
	session.Cancel = cancel

	// Store the session
	s.replaysInProgress[session.SessionID] = session

	// Update metrics
	s.metrics.RecordReplayStarted()

	// Start the replay in a goroutine
	go s.runReplaySession(session)

	s.logger.Info("Replay session started",
		"session_id", session.SessionID,
		"subscription_id", subscriptionID,
		"start_cursor", startCursor,
		"end_cursor", endCursor,
	)

	return session, nil
}

// runReplaySession runs a replay session
func (s *ReplayService) runReplaySession(session *ReplaySession) {
	// Mark as running
	s.updateSessionStatus(session.SessionID, ReplaySessionStatusRunning)

	// Get end cursor if not specified
	endCursor := session.EndCursor
	if endCursor == 0 && s.durableLog != nil {
		endCursor = s.durableLog.GetCursor()
		session.EndCursor = endCursor
	}

	// Calculate total events to replay
	totalEvents := endCursor - session.StartCursor
	if totalEvents < 0 {
		totalEvents = 0
	}

	// Read events from durable log
	var events []LogEntry
	var err error

	if totalEvents > 0 {
		events, err = s.durableLog.ReadEventsSince(session.StartCursor, 0) // 0 means no limit
		if err != nil {
			s.handleReplayError(session, fmt.Errorf("failed to read events: %w", err))
			return
		}
	}

	// Process events in batches
	batchSize := s.config.MaxReplayRate / 10 // Process 10 batches per second
	if batchSize < 1 {
		batchSize = 1
	}

	for i := 0; i < len(events); i += batchSize {
		// Check if session is cancelled
		select {
		case <-session.Context.Done():
			s.handleReplayError(session, session.Context.Err())
			return
		default:
		}

		// Get batch
		end := i + batchSize
		if end > len(events) {
			end = len(events)
		}
		batch := events[i:end]

		// Process batch
		if err := s.processReplayBatch(session, batch); err != nil {
			s.logger.Warn("Failed to process replay batch",
				"session_id", session.SessionID,
				"start_index", i,
				"end_index", end,
				"error", err,
			)
			// Continue with next batch
		}

		// Update progress
		session.CurrentCursor = events[end-1].SequenceNumber
		session.EventsReplayed += int64(len(batch))
		session.LastActivity = time.Now().UTC()

		// Calculate progress percentage
		var progress float64
		if totalEvents > 0 {
			progress = float64(session.CurrentCursor-session.StartCursor) / float64(totalEvents) * 100
		}

		// Send progress update
		select {
		case session.ProgressChannel <- ReplayProgress{
			SessionID:          session.SessionID,
			CurrentCursor:      session.CurrentCursor,
			EventsReplayed:    session.EventsReplayed,
			ProgressPercentage: progress,
			Timestamp:         time.Now().UTC(),
		}:
		default:
			// Channel full, skip progress update
		}

		// Rate limiting
		if s.config.MaxReplayRate > 0 {
			time.Sleep(time.Second / time.Duration(s.config.MaxReplayRate))
		}
	}

	// Complete the replay
	s.completeReplaySession(session, nil)
}

// processReplayBatch processes a batch of events during replay
func (s *ReplayService) processReplayBatch(session *ReplaySession, batch []LogEntry) error {
	if s.fanoutService == nil {
		// No fanout service, just count as replayed
		return nil
	}

	// Convert log entries to stream events and fan out
	for _, entry := range batch {
		streamEvent := LogEntryToStreamEvent(entry)
		
		// Fan out the event to the subscription
		if _, err := s.fanoutService.FanoutEventToSubscribers(streamEvent); err != nil {
			session.EventsFailed++
			s.logger.Warn("Failed to fan out replayed event",
				"session_id", session.SessionID,
				"event_id", entry.EventID,
				"error", err,
			)
			// Continue with other events
		} else {
			session.EventsReplayed++
		}
	}

	return nil
}

// handleReplayError handles an error during replay
func (s *ReplayService) handleReplayError(session *ReplaySession, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session.Status = ReplaySessionStatusFailed
	session.Error = err
	session.LastActivity = time.Now().UTC()

	// Update metrics
	s.metrics.RecordReplayFailed()

	// Close channels
	close(session.ProgressChannel)
	
	// Send completion
	session.CompletionChannel <- ReplayResult{
		SessionID:     session.SessionID,
		Success:       false,
		StartCursor:   session.StartCursor,
		EndCursor:     session.EndCursor,
		FinalCursor:   session.CurrentCursor,
		EventsReplayed: session.EventsReplayed,
		EventsFailed:   session.EventsFailed,
		Duration:      time.Since(session.Started),
		Error:         err,
		Timestamp:     time.Now().UTC(),
	}
	close(session.CompletionChannel)

	// Remove from active replays
	delete(s.replaysInProgress, session.SessionID)

	s.logger.Warn("Replay session failed",
		"session_id", session.SessionID,
		"subscription_id", session.SubscriptionID,
		"error", err,
		"events_replayed", session.EventsReplayed,
		"events_failed", session.EventsFailed,
	)
}

// completeReplaySession completes a replay session successfully
func (s *ReplayService) completeReplaySession(session *ReplaySession, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session.Status = ReplaySessionStatusCompleted
	session.LastActivity = time.Now().UTC()

	// Update metrics
	s.metrics.RecordReplayCompleted(time.Since(session.Started))
	s.metrics.RecordEventsReplayed(session.EventsReplayed)
	s.metrics.RecordEventsFailed(session.EventsFailed)

	// Close channels
	close(session.ProgressChannel)
	
	// Send completion
	session.CompletionChannel <- ReplayResult{
		SessionID:     session.SessionID,
		Success:       true,
		StartCursor:   session.StartCursor,
		EndCursor:     session.EndCursor,
		FinalCursor:   session.CurrentCursor,
		EventsReplayed: session.EventsReplayed,
		EventsFailed:   session.EventsFailed,
		Duration:      time.Since(session.Started),
		Error:         err,
		Timestamp:     time.Now().UTC(),
	}
	close(session.CompletionChannel)

	// Remove from active replays
	delete(s.replaysInProgress, session.SessionID)

	s.logger.Info("Replay session completed",
		"session_id", session.SessionID,
		"subscription_id", session.SubscriptionID,
		"events_replayed", session.EventsReplayed,
		"events_failed", session.EventsFailed,
		"duration", time.Since(session.Started),
	)
}

// updateSessionStatus updates the status of a replay session
func (s *ReplayService) updateSessionStatus(sessionID string, status ReplaySessionStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if session, exists := s.replaysInProgress[sessionID]; exists {
		session.Status = status
		session.LastActivity = time.Now().UTC()
	}
}

// PauseReplay pauses a replay session
func (s *ReplayService) PauseReplay(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrReplayNotSupported
	}

	session, exists := s.replaysInProgress[sessionID]
	if !exists {
		return fmt.Errorf("replay session %s not found", sessionID)
	}

	if session.Status != ReplaySessionStatusRunning {
		return fmt.Errorf("replay session %s is not running", sessionID)
	}

	// Pause the session
	session.Status = ReplaySessionStatusPaused
	session.LastActivity = time.Now().UTC()

	s.logger.Info("Replay session paused", "session_id", sessionID)

	return nil
}

// ResumeReplay resumes a paused replay session
func (s *ReplayService) ResumeReplay(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrReplayNotSupported
	}

	session, exists := s.replaysInProgress[sessionID]
	if !exists {
		return fmt.Errorf("replay session %s not found", sessionID)
	}

	if session.Status != ReplaySessionStatusPaused {
		return fmt.Errorf("replay session %s is not paused", sessionID)
	}

	// Resume the session
	session.Status = ReplaySessionStatusRunning
	session.LastActivity = time.Now().UTC()

	// Start a new goroutine to continue the replay
	go s.runReplaySession(session)

	s.logger.Info("Replay session resumed", "session_id", sessionID)

	return nil
}

// CancelReplay cancels a replay session
func (s *ReplayService) CancelReplay(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrReplayNotSupported
	}

	session, exists := s.replaysInProgress[sessionID]
	if !exists {
		return fmt.Errorf("replay session %s not found", sessionID)
	}

	// Cancel the session
	if session.Cancel != nil {
		session.Cancel()
	}

	session.Status = ReplaySessionStatusCancelled
	session.LastActivity = time.Now().UTC()

	// Update metrics
	s.metrics.RecordReplayCancelled()

	// Close channels
	close(session.ProgressChannel)
	close(session.CompletionChannel)

	// Remove from active replays
	delete(s.replaysInProgress, sessionID)

	s.logger.Info("Replay session cancelled", "session_id", sessionID)

	return nil
}

// GetReplaySession returns information about a replay session
func (s *ReplayService) GetReplaySession(sessionID string) (*ReplaySession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrReplayNotSupported
	}

	session, exists := s.replaysInProgress[sessionID]
	if !exists {
		return nil, fmt.Errorf("replay session %s not found", sessionID)
	}

	return session, nil
}

// ListReplaySessions lists all active replay sessions
func (s *ReplayService) ListReplaySessions() []*ReplaySession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil
	}

	sessions := make([]*ReplaySession, 0, len(s.replaysInProgress))
	for _, session := range s.replaysInProgress {
		sessions = append(sessions, session)
	}

	return sessions
}

// GetCursorForSubscription returns the current cursor for a subscription
func (s *ReplayService) GetCursorForSubscription(subscriptionID string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return -1, ErrReplayNotSupported
	}

	if s.subscriptionRegistry == nil {
		return -1, ErrReplayNotSupported
	}

	subscription, err := s.subscriptionRegistry.GetSubscription(subscriptionID)
	if err != nil {
		return -1, err
	}

	return subscription.ResumeCursor, nil
}

// GetReplayRange returns the replay range for a subscription
func (s *ReplayService) GetReplayRange(subscriptionID string) (int64, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return -1, -1, ErrReplayNotSupported
	}

	if s.subscriptionRegistry == nil || s.durableLog == nil {
		return -1, -1, ErrReplayNotSupported
	}

	// Get subscription cursor
	subscription, err := s.subscriptionRegistry.GetSubscription(subscriptionID)
	if err != nil {
		return -1, -1, err
	}

	// Get current cursor
	currentCursor := s.durableLog.GetCursor()

	return subscription.ResumeCursor, currentCursor, nil
}

// HTTPHandler returns an HTTP handler for replay operations
func (s *ReplayService) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.closed {
			http.Error(w, "Replay service is closed", http.StatusServiceUnavailable)
			return
		}

		s.handleReplayRequest(w, r)
	})
}

// handleReplayRequest handles an HTTP request for replay operations
func (s *ReplayService) handleReplayRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleReplayGet(w, r)
	case http.MethodPost:
		s.handleReplayPost(w, r)
	case http.MethodDelete:
		s.handleReplayDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleReplayGet handles GET requests for replay operations
func (s *ReplayService) handleReplayGet(w http.ResponseWriter, r *http.Request) {
	// Handle listing replay sessions
	if r.URL.Path == "/replay/sessions" {
		s.handleListReplaySessions(w, r)
		return
	}

	// Handle getting a specific replay session
	if len(r.URL.Path) > len("/replay/sessions/") && r.URL.Path[:len("/replay/sessions/")] == "/replay/sessions/" {
		sessionID := r.URL.Path[len("/replay/sessions/"):]
		s.handleGetReplaySession(w, r, sessionID)
		return
	}

	// Handle getting cursor for a subscription
	if len(r.URL.Path) > len("/replay/cursor/") && r.URL.Path[:len("/replay/cursor/")] == "/replay/cursor/" {
		subscriptionID := r.URL.Path[len("/replay/cursor/"):]
		s.handleGetReplayCursor(w, r, subscriptionID)
		return
	}

	// Handle getting replay range for a subscription
	if len(r.URL.Path) > len("/replay/range/") && r.URL.Path[:len("/replay/range/")] == "/replay/range/" {
		subscriptionID := r.URL.Path[len("/replay/range/"):]
		s.handleGetReplayRange(w, r, subscriptionID)
		return
	}

	// Handle getting metrics
	if r.URL.Path == "/replay/metrics" {
		s.handleGetReplayMetrics(w, r)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleReplayPost handles POST requests for replay operations
func (s *ReplayService) handleReplayPost(w http.ResponseWriter, r *http.Request) {
	// Handle starting a replay session
	if r.URL.Path == "/replay/sessions" {
		s.handleStartReplaySession(w, r)
		return
	}

	// Handle pausing a replay session
	if len(r.URL.Path) > len("/replay/sessions/") && r.URL.Path[:len("/replay/sessions/")] == "/replay/sessions/" {
		sessionID := r.URL.Path[len("/replay/sessions/"):]
		if r.URL.Query().Get("action") == "pause" {
			s.handlePauseReplaySession(w, r, sessionID)
			return
		}
		if r.URL.Query().Get("action") == "resume" {
			s.handleResumeReplaySession(w, r, sessionID)
			return
		}
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleReplayDelete handles DELETE requests for replay operations
func (s *ReplayService) handleReplayDelete(w http.ResponseWriter, r *http.Request) {
	// Handle cancelling a replay session
	if len(r.URL.Path) > len("/replay/sessions/") && r.URL.Path[len("/replay/sessions/"):] == "/replay/sessions/" {
		sessionID := r.URL.Path[len("/replay/sessions/"):]
		s.handleCancelReplaySession(w, r, sessionID)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleListReplaySessions handles listing all replay sessions
func (s *ReplayService) handleListReplaySessions(w http.ResponseWriter, r *http.Request) {
	sessions := s.ListReplaySessions()

	// Convert to response format
	response := struct {
		Sessions []*ReplaySession `json:"sessions"`
		Count    int               `json:"count"`
	}{
		Sessions: sessions,
		Count:    len(sessions),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleGetReplaySession handles getting a specific replay session
func (s *ReplayService) handleGetReplaySession(w http.ResponseWriter, r *http.Request, sessionID string) {
	session, err := s.GetReplaySession(sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(session); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleStartReplaySession handles starting a replay session
func (s *ReplayService) handleStartReplaySession(w http.ResponseWriter, r *http.Request) {
	var request struct {
		SubscriptionID string `json:"subscriptionId"`
		StartCursor     int64  `json:"startCursor"`
		EndCursor       int64  `json:"endCursor"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.SubscriptionID == "" {
		http.Error(w, "Subscription ID is required", http.StatusBadRequest)
		return
	}

	// Get current cursor if not specified
	if request.StartCursor == 0 {
		cursor, err := s.GetCursorForSubscription(request.SubscriptionID)
		if err != nil {
			http.Error(w, "Failed to get subscription cursor: "+err.Error(), http.StatusBadRequest)
			return
		}
		request.StartCursor = cursor
	}

	// Start replay session
	session, err := s.StartReplay(r.Context(), request.SubscriptionID, request.StartCursor, request.EndCursor)
	if err != nil {
		http.Error(w, "Failed to start replay: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(session); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handlePauseReplaySession handles pausing a replay session
func (s *ReplayService) handlePauseReplaySession(w http.ResponseWriter, r *http.Request, sessionID string) {
	if err := s.PauseReplay(sessionID); err != nil {
		http.Error(w, "Failed to pause replay: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "paused",
		"sessionId": sessionID,
	})
}

// handleResumeReplaySession handles resuming a replay session
func (s *ReplayService) handleResumeReplaySession(w http.ResponseWriter, r *http.Request, sessionID string) {
	if err := s.ResumeReplay(sessionID); err != nil {
		http.Error(w, "Failed to resume replay: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "resumed",
		"sessionId": sessionID,
	})
}

// handleCancelReplaySession handles cancelling a replay session
func (s *ReplayService) handleCancelReplaySession(w http.ResponseWriter, r *http.Request, sessionID string) {
	if err := s.CancelReplay(sessionID); err != nil {
		http.Error(w, "Failed to cancel replay: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "cancelled",
		"sessionId": sessionID,
	})
}

// handleGetReplayCursor handles getting the replay cursor for a subscription
func (s *ReplayService) handleGetReplayCursor(w http.ResponseWriter, r *http.Request, subscriptionID string) {
	cursor, err := s.GetCursorForSubscription(subscriptionID)
	if err != nil {
		http.Error(w, "Failed to get cursor: "+err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"subscriptionId": subscriptionID,
		"cursor":        cursor,
	})
}

// handleGetReplayRange handles getting the replay range for a subscription
func (s *ReplayService) handleGetReplayRange(w http.ResponseWriter, r *http.Request, subscriptionID string) {
	startCursor, endCursor, err := s.GetReplayRange(subscriptionID)
	if err != nil {
		http.Error(w, "Failed to get replay range: "+err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"subscriptionId": subscriptionID,
		"startCursor":   startCursor,
		"endCursor":     endCursor,
		"range":        endCursor - startCursor,
	})
}

// handleGetReplayMetrics handles getting replay service metrics
func (s *ReplayService) handleGetReplayMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.GetMetrics()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// Stop stops the replay service
func (s *ReplayService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	// Cancel all active replay sessions
	for _, session := range s.replaysInProgress {
		if session.Cancel != nil {
			session.Cancel()
		}
		close(session.ProgressChannel)
		close(session.CompletionChannel)
	}

	s.replaysInProgress = nil
	s.closed = true

	s.logger.Info("Replay service stopped")

	return nil
}

// Close closes the replay service
func (s *ReplayService) Close() error {
	return s.Stop()
}

// IsClosed returns true if the service is closed
func (s *ReplayService) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// GetMetrics returns the current metrics
func (s *ReplayService) GetMetrics() ReplayServiceMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metrics.GetMetrics()
}

// generateReplaySessionID generates a unique replay session ID
func generateReplaySessionID() string {
	return fmt.Sprintf("replay-%d", time.Now().UnixNano())
}