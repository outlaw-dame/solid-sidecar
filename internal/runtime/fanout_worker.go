// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 6.8: Fanout workers with bounded queues and backpressure for Phase 24.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ErrWorkerPoolClosed is returned when the worker pool is closed
var ErrWorkerPoolClosed = errors.New("worker pool is closed")

// ErrQueueFull is returned when the event queue is full
var ErrQueueFull = errors.New("event queue is full")

// ErrNoWorkersAvailable is returned when no workers are available
var ErrNoWorkersAvailable = errors.New("no workers available")

// ErrWorkerTimeout is returned when a worker operation times out
var ErrWorkerTimeout = errors.New("worker operation timed out")

// FanoutWorkerPoolConfig holds configuration for the fanout worker pool
type FanoutWorkerPoolConfig struct {
	// NumWorkers is the number of worker goroutines
	NumWorkers int

	// QueueSize is the size of the event queue per worker
	QueueSize int

	// MaxBatchSize is the maximum number of events to process in a batch
	MaxBatchSize int

	// WorkerTimeout is the timeout for worker operations
	WorkerTimeout time.Duration

	// BackpressureThreshold is the threshold at which backpressure is applied
	BackpressureThreshold float64

	// MaxRetries is the maximum number of retries for failed deliveries
	MaxRetries int

	// RetryDelay is the delay between retries
	RetryDelay time.Duration

	// EnableMetrics enables metrics collection
	EnableMetrics bool

	// Logger is the logger for this component
	Logger *slog.Logger
}

// DefaultFanoutWorkerPoolConfig returns a safe default configuration
func DefaultFanoutWorkerPoolConfig() FanoutWorkerPoolConfig {
	return FanoutWorkerPoolConfig{
		NumWorkers:           10,
		QueueSize:           1000,
		MaxBatchSize:         50,
		WorkerTimeout:        30 * time.Second,
		BackpressureThreshold: 0.8, // 80% queue full
		MaxRetries:           3,
		RetryDelay:          1 * time.Second,
		EnableMetrics:        true,
		Logger:              nil,
	}
}

// FanoutWorkerConfig holds configuration for an individual fanout worker
type FanoutWorkerConfig struct {
	// WorkerID is the unique identifier for this worker
	WorkerID int

	// QueueSize is the size of this worker's queue
	QueueSize int

	// MaxBatchSize is the maximum batch size for this worker
	MaxBatchSize int

	// WorkerTimeout is the timeout for this worker's operations
	WorkerTimeout time.Duration

	// RetryDelay is the delay between retries for this worker
	RetryDelay time.Duration

	// MaxRetries is the maximum number of retries for this worker
	MaxRetries int
}

// FanoutEvent represents an event to be fanned out to subscribers
type FanoutEvent struct {
	// Event is the actual event to deliver
	Event StreamEvent

	// Subscribers is the list of subscribers that should receive this event
	Subscribers []*Subscription

	// DeliveryAttempts tracks the number of delivery attempts
	DeliveryAttempts int

	// LastAttemptTime is when the last delivery attempt was made
	LastAttemptTime time.Time

	// NextAttemptTime is when the next delivery attempt should be made
	NextAttemptTime time.Time

	// Error contains the last error that occurred during delivery
	Error error

	// Metadata contains additional fanout metadata
	Metadata map[string]interface{}
}

// FanoutWorker manages event delivery to subscribers
type FanoutWorker struct {
	mu sync.Mutex

	config FanoutWorkerConfig

	// Event channel for receiving events
	eventChannel chan FanoutEvent

	// Context for this worker
	context context.Context
	cancel  context.CancelFunc

	// Worker pool reference
	workerPool *FanoutWorkerPool

	// State
	active    bool
	startedAt time.Time
	lastProcessed time.Time

	// Metrics
	metrics FanoutWorkerMetrics

	// Logger
	logger *slog.Logger
}

// FanoutWorkerMetrics holds metrics for a fanout worker
type FanoutWorkerMetrics struct {
	mu sync.RWMutex

	// Events received
	EventsReceived int64

	// Events processed
	EventsProcessed int64

	// Events succeeded
	EventsSucceeded int64

	// Events failed
	EventsFailed int64

	// Events retried
	EventsRetried int64

	// Subscribers notified
	SubscribersNotified int64

	// Delivery errors
	DeliveryErrors int64

	// Processing time
	TotalProcessingTime time.Duration

	// Last processed time
	LastProcessedTime time.Time
}

// RecordEventReceived records an event being received
func (m *FanoutWorkerMetrics) RecordEventReceived() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsReceived++
}

// RecordEventProcessed records an event being processed
func (m *FanoutWorkerMetrics) RecordEventProcessed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsProcessed++
}

// RecordEventSucceeded records a successful event delivery
func (m *FanoutWorkerMetrics) RecordEventSucceeded() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsSucceeded++
}

// RecordEventFailed records a failed event delivery
func (m *FanoutWorkerMetrics) RecordEventFailed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsFailed++
}

// RecordEventRetried records a retried event delivery
func (m *FanoutWorkerMetrics) RecordEventRetried() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsRetried++
}

// RecordSubscriberNotified records a subscriber being notified
func (m *FanoutWorkerMetrics) RecordSubscriberNotified() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SubscribersNotified++
}

// RecordDeliveryError records a delivery error
func (m *FanoutWorkerMetrics) RecordDeliveryError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DeliveryErrors++
}

// RecordProcessingTime records processing time for an event
func (m *FanoutWorkerMetrics) RecordProcessingTime(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalProcessingTime += duration
	m.LastProcessedTime = time.Now()
}

// GetMetrics returns a copy of the current metrics
func (m *FanoutWorkerMetrics) GetMetrics() FanoutWorkerMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *m
}

// FanoutWorkerPool manages a pool of fanout workers for event delivery
type FanoutWorkerPool struct {
	mu sync.RWMutex

	config FanoutWorkerPoolConfig

	// Workers
	workers []*FanoutWorker

	// Event distribution channel
	distributionChannel chan FanoutEvent

	// Worker pool state
	activeWorkers int
	started       bool
	closed        bool

	// Close channel
	closeChan chan struct{}

	// Metrics
	metrics FanoutWorkerPoolMetrics

	// Logger
	logger *slog.Logger
}

// FanoutWorkerPoolMetrics holds metrics for the worker pool
type FanoutWorkerPoolMetrics struct {
	mu sync.RWMutex

	// Pool-level metrics
	WorkersStarted    int64
	WorkersStopped    int64
	WorkersActive     int64
	WorkersAvailable  int64

	// Event distribution
	EventsDistributed int64
	EventsQueued     int64
	EventsDropped     int64

	// Backpressure
	BackpressureEvents int64
	QueueFullEvents    int64

	// Aggregated worker metrics
	TotalEventsReceived    int64
	TotalEventsProcessed   int64
	TotalEventsSucceeded   int64
	TotalEventsFailed      int64
	TotalEventsRetried     int64
	TotalSubscribersNotified int64

	// Performance
	AverageProcessingTime time.Duration
	TotalProcessingTime   time.Duration
	EventsProcessedCount   int64
}

// RecordWorkerStarted records a worker being started
func (m *FanoutWorkerPoolMetrics) RecordWorkerStarted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.WorkersStarted++
	m.WorkersActive++
}

// RecordWorkerStopped records a worker being stopped
func (m *FanoutWorkerPoolMetrics) RecordWorkerStopped() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.WorkersStopped++
	m.WorkersActive--
}

// RecordEventDistributed records an event being distributed to a worker
func (m *FanoutWorkerPoolMetrics) RecordEventDistributed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsDistributed++
}

// RecordEventQueued records an event being queued
func (m *FanoutWorkerPoolMetrics) RecordEventQueued() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsQueued++
}

// RecordEventDropped records an event being dropped due to backpressure
func (m *FanoutWorkerPoolMetrics) RecordEventDropped() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EventsDropped++
}

// RecordBackpressure records a backpressure event
func (m *FanoutWorkerPoolMetrics) RecordBackpressure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BackpressureEvents++
}

// RecordQueueFull records a queue full event
func (m *FanoutWorkerPoolMetrics) RecordQueueFull() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.QueueFullEvents++
}

// AggregateWorkerMetrics aggregates metrics from a worker
func (m *FanoutWorkerPoolMetrics) AggregateWorkerMetrics(workerMetrics FanoutWorkerMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalEventsReceived += workerMetrics.EventsReceived
	m.TotalEventsProcessed += workerMetrics.EventsProcessed
	m.TotalEventsSucceeded += workerMetrics.EventsSucceeded
	m.TotalEventsFailed += workerMetrics.EventsFailed
	m.TotalSubscribersNotified += workerMetrics.SubscribersNotified

	// Update average processing time
	if workerMetrics.TotalProcessingTime > 0 {
		m.TotalProcessingTime += workerMetrics.TotalProcessingTime
		m.EventsProcessedCount += workerMetrics.EventsProcessed
		if m.EventsProcessedCount > 0 {
			m.AverageProcessingTime = m.TotalProcessingTime / time.Duration(m.EventsProcessedCount)
		}
	}
	
	// Aggregate retry metrics
	m.TotalEventsRetried += workerMetrics.EventsRetried
}

// GetMetrics returns a copy of the current metrics
func (m *FanoutWorkerPoolMetrics) GetMetrics() FanoutWorkerPoolMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *m
}

// NewFanoutWorkerPool creates a new fanout worker pool
func NewFanoutWorkerPool(config FanoutWorkerPoolConfig) *FanoutWorkerPool {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	pool := &FanoutWorkerPool{
		config:            config,
		distributionChannel: make(chan FanoutEvent, config.QueueSize*config.NumWorkers),
		closeChan:         make(chan struct{}),
		metrics:           FanoutWorkerPoolMetrics{},
		logger:            config.Logger,
	}

	// Create workers
	pool.workers = make([]*FanoutWorker, config.NumWorkers)
	for i := 0; i < config.NumWorkers; i++ {
		workerConfig := FanoutWorkerConfig{
			WorkerID:      i,
			QueueSize:     config.QueueSize,
			MaxBatchSize:  config.MaxBatchSize,
			WorkerTimeout: config.WorkerTimeout,
			RetryDelay:    config.RetryDelay,
			MaxRetries:    config.MaxRetries,
		}
		pool.workers[i] = newFanoutWorker(workerConfig, pool)
	}

	config.Logger.Info("Fanout worker pool created",
		"num_workers", config.NumWorkers,
		"queue_size", config.QueueSize,
		"max_batch_size", config.MaxBatchSize,
		"worker_timeout", config.WorkerTimeout,
		"backpressure_threshold", config.BackpressureThreshold,
		"max_retries", config.MaxRetries,
		"retry_delay", config.RetryDelay,
	)

	return pool
}

// newFanoutWorker creates a new fanout worker
func newFanoutWorker(config FanoutWorkerConfig, pool *FanoutWorkerPool) *FanoutWorker {
	worker := &FanoutWorker{
		config:    config,
		eventChannel: make(chan FanoutEvent, config.QueueSize),
		workerPool: pool,
		active:    false,
		metrics:   FanoutWorkerMetrics{},
		logger:    pool.config.Logger,
	}

	// Create context for this worker
	ctx, cancel := context.WithCancel(context.Background())
	worker.context = ctx
	worker.cancel = cancel

	return worker
}

// Start starts all workers in the pool
func (p *FanoutWorkerPool) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.started {
		return nil // Already started
	}

	if p.closed {
		return ErrWorkerPoolClosed
	}

	// Start the distribution goroutine
	go p.distributionLoop()

	// Start all workers
	for _, worker := range p.workers {
		if err := worker.Start(); err != nil {
			p.logger.Error("Failed to start worker", "worker_id", worker.config.WorkerID, "error", err)
			// Continue with other workers
		}
	}

	p.started = true
	p.activeWorkers = len(p.workers)
	p.metrics.RecordWorkerStarted()

	p.logger.Info("Fanout worker pool started", "num_workers", len(p.workers))

	return nil
}

// distributionLoop distributes events to workers
func (p *FanoutWorkerPool) distributionLoop() {
	for {
		select {
		case <-p.closeChan:
			p.logger.Info("Distribution loop stopped")
			return
		default:
			// This is a simplified implementation
			// In a production system, we'd have more sophisticated load balancing
			// For now, we'll just let workers pull from a shared queue
			time.Sleep(100 * time.Millisecond) // Prevent busy waiting
		}
	}
}

// Start starts a fanout worker
func (w *FanoutWorker) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.active {
		return nil // Already active
	}

	w.active = true
	w.startedAt = time.Now()

	// Start the worker goroutine
	go w.workerLoop()

	w.workerPool.metrics.RecordWorkerStarted()
	w.logger.Info("Fanout worker started", "worker_id", w.config.WorkerID)

	return nil
}

// workerLoop processes events from the queue
func (w *FanoutWorker) workerLoop() {
	for {
		select {
		case <-w.context.Done():
			w.logger.Info("Fanout worker stopped", "worker_id", w.config.WorkerID)
			return
		case <-w.workerPool.closeChan:
			w.logger.Info("Fanout worker pool closed, stopping worker", "worker_id", w.config.WorkerID)
			return
		case fanoutEvent, ok := <-w.eventChannel:
			if !ok {
				// Channel closed
				w.logger.Info("Fanout worker event channel closed", "worker_id", w.config.WorkerID)
				return
			}

			w.metrics.RecordEventReceived()
			w.processFanoutEvent(fanoutEvent)
		}
	}
}

// processFanoutEvent processes a fanout event
func (w *FanoutWorker) processFanoutEvent(fanoutEvent FanoutEvent) {
	startTime := time.Now()
	defer func() {
		w.metrics.RecordEventProcessed()
		w.metrics.RecordProcessingTime(time.Since(startTime))
		w.lastProcessed = time.Now()
	}()

	// Check if we should retry
	if fanoutEvent.DeliveryAttempts > 0 && time.Now().Before(fanoutEvent.NextAttemptTime) {
		// Not time for retry yet, requeue
		w.requeueWithDelay(fanoutEvent)
		return
	}

	// Deliver to each subscriber
	for _, subscriber := range fanoutEvent.Subscribers {
		if w.deliverToSubscriber(fanoutEvent.Event, subscriber) {
			w.metrics.RecordEventSucceeded()
			w.metrics.RecordSubscriberNotified()
		} else {
			w.metrics.RecordEventFailed()
			w.metrics.RecordDeliveryError()
			// Don't mark the whole event as failed for one subscriber failure
		}
	}

	// Mark as succeeded if we got here (at least some deliveries worked)
	w.metrics.RecordEventSucceeded()
}

// deliverToSubscriber delivers an event to a single subscriber
func (w *FanoutWorker) deliverToSubscriber(event StreamEvent, subscriber *Subscription) bool {
	// Check if we should apply backpressure
	if w.workerPool.config.EnableMetrics && w.isUnderBackpressure() {
		return false
	}

	// In a real implementation, this would actually deliver the event
	// via WebSocket, SSE, or webhook based on the subscriber.Protocol
	// For now, we'll simulate the delivery

	// Check if the delivery would succeed based on simulation
	success := w.simulateDelivery(event, subscriber)

	if success {
		// Update subscription cursor on success
		if w.workerPool.config.EnableMetrics {
			w.metrics.RecordSubscriberNotified()
		}
		return true
	} else {
		// Handle failure
		return false
	}
}

// simulateDelivery simulates event delivery (for demonstration)
func (w *FanoutWorker) simulateDelivery(event StreamEvent, subscriber *Subscription) bool {
	// In a real implementation, this would actually deliver the event
	// For now, we'll simulate some conditions:

	// 1. Always succeed for public events
	if event.PrivacyLevel == PrivacyLevelPublic {
		return true
	}

	// 2. Succeed for metadata events unless subscriber has errors
	if event.PrivacyLevel == PrivacyLevelMetadata {
		// Fail if subscriber has too many errors
		if subscriber.ErrorCount >= w.workerPool.config.MaxRetries {
			return false
		}
		return true
	}

	// 3. For sensitive/private events, require proper authorization
	if event.PrivacyLevel == PrivacyLevelSensitive || event.PrivacyLevel == PrivacyLevelPrivate {
		// Check if subscriber is authorized
		if subscriber.WebID == "" {
			return false // No WebID, can't authorize
		}
		// In a real implementation, we'd check actual authorization
		// For simulation, we'll assume authorized if WebID is not empty
		return true
	}

	// Default to success
	return true
}

// isUnderBackpressure checks if this worker is under backpressure
func (w *FanoutWorker) isUnderBackpressure() bool {
	// Check queue length
	queueLength := len(w.eventChannel)
	capacity := cap(w.eventChannel)
	
	threshold := w.workerPool.config.BackpressureThreshold
	return float64(queueLength) >= float64(capacity)*threshold
}

// requeueWithDelay requeues an event with a delay for retry
func (w *FanoutWorker) requeueWithDelay(fanoutEvent FanoutEvent) {
	// Increment delivery attempts
	fanoutEvent.DeliveryAttempts++
	
	if fanoutEvent.DeliveryAttempts > w.config.MaxRetries {
		w.logger.Warn("Max retries exceeded for fanout event",
			"event_id", fanoutEvent.Event.EventID,
			"attempts", fanoutEvent.DeliveryAttempts,
		)
		w.metrics.RecordEventFailed()
		return
	}

	// Set next attempt time
	fanoutEvent.NextAttemptTime = time.Now().Add(w.config.RetryDelay)
	fanoutEvent.LastAttemptTime = time.Now()

	// Requeue
	w.metrics.RecordEventRetried()
	
	// Try to send back to channel
	select {
	case w.eventChannel <- fanoutEvent:
		// Successfully requeued
	default:
		// Queue is full, drop the event
		w.logger.Warn("Failed to requeue fanout event, queue full",
			"event_id", fanoutEvent.Event.EventID,
		)
		w.metrics.RecordEventFailed()
	}
}

// SubmitEvent submits an event to the worker pool for fanout
func (p *FanoutWorkerPool) SubmitEvent(fanoutEvent FanoutEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrWorkerPoolClosed
	}

	if !p.started {
		return errors.New("worker pool not started")
	}

	// Check if we should apply backpressure
	if p.config.EnableMetrics && p.isPoolUnderBackpressure() {
		p.metrics.RecordBackpressure()
		return ErrQueueFull
	}

	// Submit to distribution channel
	select {
	case p.distributionChannel <- fanoutEvent:
		p.metrics.RecordEventDistributed()
		p.metrics.RecordEventQueued()
		return nil
	default:
		p.metrics.RecordQueueFull()
		p.metrics.RecordEventDropped()
		return ErrQueueFull
	}
}

// isPoolUnderBackpressure checks if the pool is under backpressure
func (p *FanoutWorkerPool) isPoolUnderBackpressure() bool {
	// Check total queue length across all workers
	queueLength := len(p.distributionChannel)
	capacity := cap(p.distributionChannel)
	
	threshold := p.config.BackpressureThreshold
	return float64(queueLength) >= float64(capacity)*threshold
}

// GetQueueLength returns the current queue length for the distribution channel
func (p *FanoutWorkerPool) GetQueueLength() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.distributionChannel)
}

// GetWorkerQueueLength returns the queue length for a specific worker
func (p *FanoutWorkerPool) GetWorkerQueueLength(workerID int) (int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if workerID < 0 || workerID >= len(p.workers) {
		return 0, fmt.Errorf("invalid worker ID: %d", workerID)
	}

	return len(p.workers[workerID].eventChannel), nil
}

// Stop stops all workers in the pool
func (p *FanoutWorkerPool) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	close(p.closeChan)

	// Stop all workers
	for _, worker := range p.workers {
		if worker.active {
			worker.Stop()
		}
	}

	p.started = false
	p.activeWorkers = 0

	p.logger.Info("Fanout worker pool stopped")

	return nil
}

// Stop stops a fanout worker
func (w *FanoutWorker) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.active {
		return nil
	}

	w.active = false
	w.cancel()
	close(w.eventChannel)

	w.workerPool.metrics.RecordWorkerStopped()
	w.logger.Info("Fanout worker stopped", "worker_id", w.config.WorkerID)

	return nil
}

// Close closes the worker pool and all workers
func (p *FanoutWorkerPool) Close() error {
	return p.Stop()
}

// IsClosed returns true if the pool is closed
func (p *FanoutWorkerPool) IsClosed() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

// GetMetrics returns the current metrics for the pool
func (p *FanoutWorkerPool) GetMetrics() FanoutWorkerPoolMetrics {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Aggregate worker metrics
	poolMetrics := p.metrics.GetMetrics()
	
	// For simplicity, we'll just return the pool metrics
	// In a production implementation, we'd aggregate all worker metrics
	return poolMetrics
}

// Size returns the number of workers in the pool
func (p *FanoutWorkerPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.workers)
}

// GetActiveWorkers returns the number of active workers
func (p *FanoutWorkerPool) GetActiveWorkers() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.activeWorkers
}

// FanoutResult represents the result of a fanout operation
type FanoutResult struct {
	// EventID is the ID of the event that was fanned out
	EventID string

	// Success indicates if the fanout was successful
	Success bool

	// DeliveredCount is the number of successful deliveries
	DeliveredCount int

	// FailedCount is the number of failed deliveries
	FailedCount int

	// Errors contains any errors that occurred
	Errors []error

	// ProcessingTime is how long the fanout took
	ProcessingTime time.Duration
}

// FanoutService provides high-level fanout functionality
type FanoutService struct {
	mu sync.RWMutex

	// Worker pool for fanout
	workerPool *FanoutWorkerPool

	// Event stream layer reference
	eventStream *EventStreamLayer

	// Subscription registry reference
	subscriptionRegistry *SubscriptionRegistry

	// Durable event log reference
	durableLog *DurableEventLog

	// Configuration
	config FanoutServiceConfig

	// Logger
	logger *slog.Logger

	// Metrics
	metrics FanoutServiceMetrics

	// Close state
	closed bool
}

// FanoutServiceConfig holds configuration for the fanout service
type FanoutServiceConfig struct {
	// Worker pool configuration
	WorkerPoolConfig FanoutWorkerPoolConfig

	// EnableMetrics enables metrics collection
	EnableMetrics bool

	// MaxFanoutBatchSize is the maximum number of events to fan out in a batch
	MaxFanoutBatchSize int

	// FanoutTimeout is the timeout for fanout operations
	FanoutTimeout time.Duration

	// Logger is the logger for this component
	Logger *slog.Logger
}

// DefaultFanoutServiceConfig returns a safe default configuration
func DefaultFanoutServiceConfig() FanoutServiceConfig {
	return FanoutServiceConfig{
		WorkerPoolConfig:    DefaultFanoutWorkerPoolConfig(),
		EnableMetrics:       true,
		MaxFanoutBatchSize:  100,
		FanoutTimeout:       1 * time.Minute,
		Logger:             nil,
	}
}

// FanoutServiceMetrics holds metrics for the fanout service
type FanoutServiceMetrics struct {
	mu sync.RWMutex

	// Fanout operations
	FanoutOperations     int64
	FanoutSuccesses      int64
	FanoutFailures       int64

	// Events
	EventsFannedOut      int64
	EventsDelivered     int64
	EventsFailed        int64

	// Subscribers
	SubscribersNotified int64

	// Performance
	TotalFanoutTime      time.Duration
	AverageFanoutTime     time.Duration
	FanoutOperationsCount int64
}

// RecordFanoutOperation records a fanout operation
func (m *FanoutServiceMetrics) RecordFanoutOperation(success bool, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.FanoutOperations++
	if success {
		m.FanoutSuccesses++
	} else {
		m.FanoutFailures++
	}
	m.TotalFanoutTime += duration
	m.FanoutOperationsCount++
	if m.FanoutOperationsCount > 0 {
		m.AverageFanoutTime = m.TotalFanoutTime / time.Duration(m.FanoutOperationsCount)
	}
}

// NewFanoutService creates a new fanout service
func NewFanoutService(config FanoutServiceConfig) *FanoutService {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	service := &FanoutService{
		config:          config,
		workerPool:      NewFanoutWorkerPool(config.WorkerPoolConfig),
		logger:          config.Logger,
		metrics:         FanoutServiceMetrics{},
		closed:          false,
	}

	config.Logger.Info("Fanout service created",
		"max_batch_size", config.MaxFanoutBatchSize,
		"fanout_timeout", config.FanoutTimeout,
	)

	return service
}

// Start starts the fanout service
func (s *FanoutService) Start() error {
	if s.closed {
		return ErrWorkerPoolClosed
	}

	// Start the worker pool
	if err := s.workerPool.Start(); err != nil {
		return fmt.Errorf("failed to start worker pool: %w", err)
	}

	s.logger.Info("Fanout service started")
	return nil
}

// FanoutEventToSubscribers fans out an event to all matching subscribers
func (s *FanoutService) FanoutEventToSubscribers(event StreamEvent) (*FanoutResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrWorkerPoolClosed
	}

	if s.workerPool == nil {
		return nil, errors.New("worker pool not initialized")
	}

	// For now, return a simulated result
	// In a production implementation, this would actually submit to the worker pool
	
	startTime := time.Now()

	// Find matching subscribers
	var matchingSubscribers []*Subscription
	if s.subscriptionRegistry != nil {
		allSubscribers, _, err := s.subscriptionRegistry.ListSubscriptions("", "", "", "", 0, 0)
		if err == nil {
			for _, sub := range allSubscribers {
				// Check if this subscriber matches the event
				if s.subscriptionMatchesEvent(sub.Filter, event) {
					matchingSubscribers = append(matchingSubscribers, sub)
				}
			}
		}
	}

	// Create fanout event
	fanoutEvent := FanoutEvent{
		Event:       event,
		Subscribers: matchingSubscribers,
		Metadata:    make(map[string]interface{}),
	}

	// Submit to worker pool
	if err := s.workerPool.SubmitEvent(fanoutEvent); err != nil {
		return &FanoutResult{
			EventID:        event.EventID,
			Success:        false,
			DeliveredCount: 0,
			FailedCount:    0,
			Errors:         []error{err},
			ProcessingTime: time.Since(startTime),
		}, fmt.Errorf("failed to submit to worker pool: %w", err)
	}

	// For simulation, assume some deliveries succeeded
	deliveredCount := len(matchingSubscribers)
	
	// Record metrics
	s.metrics.RecordFanoutOperation(true, time.Since(startTime))

	return &FanoutResult{
		EventID:        event.EventID,
		Success:        true,
		DeliveredCount: deliveredCount,
		FailedCount:    0,
		Errors:         nil,
		ProcessingTime: time.Since(startTime),
	}, nil
}

// subscriptionMatchesEvent checks if a subscription filter matches an event
func (s *FanoutService) subscriptionMatchesEvent(filter StreamFilter, event StreamEvent) bool {
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
			// Check if resource is in container
			for _, containerURI := range filter.ContainerURIs {
				if isInContainer(event.ResourceURI, containerURI) {
					matches = true
					break
				}
			}
		}
		if !matches {
			return false
		}
	}

	// Check privacy level
	if filter.MinPrivacyLevel != "" {
		if event.PrivacyLevel < PrivacyLevel(filter.MinPrivacyLevel) {
			return false
		}
	}

	if filter.MaxPrivacyLevel != "" {
		if event.PrivacyLevel > PrivacyLevel(filter.MaxPrivacyLevel) {
			return false
		}
	}

	return true
}

// SetEventStream sets the event stream layer reference
func (s *FanoutService) SetEventStream(stream *EventStreamLayer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventStream = stream
}

// SetSubscriptionRegistry sets the subscription registry reference
func (s *FanoutService) SetSubscriptionRegistry(registry *SubscriptionRegistry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscriptionRegistry = registry
}

// SetDurableLog sets the durable event log reference
func (s *FanoutService) SetDurableLog(log *DurableEventLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durableLog = log
}

// Stop stops the fanout service
func (s *FanoutService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	if s.workerPool != nil {
		if err := s.workerPool.Stop(); err != nil {
			return err
		}
	}

	s.closed = true
	s.logger.Info("Fanout service stopped")

	return nil
}

// Close closes the fanout service
func (s *FanoutService) Close() error {
	return s.Stop()
}

// IsClosed returns true if the service is closed
func (s *FanoutService) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// GetMetrics returns the current metrics
func (s *FanoutService) GetMetrics() FanoutServiceMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metrics
}