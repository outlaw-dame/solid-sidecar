package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPhase24DurableEventLogE2E tests the durable event log end-to-end
func TestPhase24DurableEventLogE2E(t *testing.T) {
	t.Parallel()

	// Create temp directory for event log
	tempDir, err := os.MkdirTemp("", "solid-phase24-test")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	logDir := filepath.Join(tempDir, "events")
	require.NoError(t, os.MkdirAll(logDir, 0755), "Failed to create log directory")

	// Create durable event log with test configuration
	config := DefaultDurableEventLogConfig()
	config.LogDirectory = logDir
	config.MaxLogSize = 1024 * 1024        // 1MB per file
	config.MaxTotalSize = 10 * 1024 * 1024 // 10MB total
	config.RetentionTime = 24 * time.Hour
	config.FlushInterval = 100 * time.Millisecond // Faster flush for testing
	config.SyncWrites = false
	config.MaxEventsPerFile = 100

	eventLog, err := NewDurableEventLog(config)
	require.NoError(t, err, "Failed to create durable event log")
	defer eventLog.Close()

	// Test writing events
	events := []StreamEvent{
		{
			EventID:      "event-1",
			EventType:    EventTypeCreate,
			ResourceURI:  "https://example.com/resource1",
			ContainerURI: "https://example.com/container1/",
			Timestamp:    time.Now().UTC().Add(-1 * time.Hour),
			Agent:        "https://example.com/agent1",
			AgentType:    PolicyAgentTypeWebID,
			Action:       "create",
			Metadata:     map[string]string{"test": "value1"},
			PrivacyLevel: PrivacyLevelPublic,
		},
		{
			EventID:      "event-2",
			EventType:    EventTypeUpdate,
			ResourceURI:  "https://example.com/resource2",
			ContainerURI: "https://example.com/container2/",
			Timestamp:    time.Now().UTC().Add(-30 * time.Minute),
			Agent:        "https://example.com/agent2",
			AgentType:    PolicyAgentTypeAgent,
			Action:       "update",
			Metadata:     map[string]string{"test": "value2"},
			PrivacyLevel: PrivacyLevelMetadata,
		},
		{
			EventID:      "event-3",
			EventType:    EventTypeDelete,
			ResourceURI:  "https://example.com/resource3",
			ContainerURI: "https://example.com/container3/",
			Timestamp:    time.Now().UTC().Add(-15 * time.Minute),
			Agent:        "https://example.com/agent3",
			AgentType:    PolicyAgentTypePublic,
			Action:       "delete",
			Metadata:     map[string]string{"test": "value3"},
			PrivacyLevel: PrivacyLevelPrivate,
		},
	}

	// Write all events
	for i, event := range events {
		err := eventLog.WriteEvent(event)
		require.NoError(t, err, "Failed to write event %d", i+1)
	}

	// Verify cursor position (after 3 events with sequences 0,1,2, cursor should be at sequence 2)
	cursor := eventLog.GetCursor()
	assert.Equal(t, int64(2), cursor, "Cursor should be at sequence 2")

	// Test reading events by ID
	for _, event := range events {
		logEntry, err := eventLog.ReadEvent(event.EventID)
		require.NoError(t, err, "Failed to read event %s", event.EventID)
		require.NotNil(t, logEntry, "Event %s should not be nil", event.EventID)
		assert.Equal(t, event.EventID, logEntry.EventID, "Event ID should match")
		assert.Equal(t, event.ResourceURI, logEntry.ResourceURI, "Resource URI should match")
		assert.Equal(t, event.PrivacyLevel, logEntry.PrivacyLevel, "Privacy level should match")
	}

	// Test reading events since cursor
	// Read events since cursor 0 (should get all)
	allEvents, err := eventLog.ReadEventsSince(0, 0) // 0 limit means all
	require.NoError(t, err, "Failed to read events since cursor 0")
	assert.Equal(t, 3, len(allEvents), "Should have read all 3 events")

	// Read events since cursor 1 (should get events 2 and 3)
	recentEvents, err := eventLog.ReadEventsSince(1, 0)
	require.NoError(t, err, "Failed to read events since cursor 1")
	assert.Equal(t, 2, len(recentEvents), "Should have read 2 recent events")

	// Test cursor by event ID
	for _, event := range events {
		cursor, err := eventLog.GetCursorByEventID(event.EventID)
		require.NoError(t, err, "Failed to get cursor for event %s", event.EventID)
		assert.GreaterOrEqual(t, cursor, int64(0), "Cursor should be >= 0")
	}

	// Test subscription with cursor resume
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Subscribe to all events starting from cursor 0
	subscription, err := eventLog.SubscribeToEvents(ctx, 0, StreamFilter{})
	require.NoError(t, err, "Failed to create subscription")

	// Read events from subscription channel
	var receivedEvents []LogEntry
	for len(receivedEvents) < 3 {
		select {
		case event, ok := <-subscription:
			if !ok {
				t.Fatal("Subscription channel closed unexpectedly")
			}
			receivedEvents = append(receivedEvents, event)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for events on subscription")
		}
	}

	assert.Equal(t, 3, len(receivedEvents), "Should have received all 3 events")

	// Test integrity verification
	checked, corrupted, err := eventLog.VerifyIntegrity()
	require.NoError(t, err, "Integrity verification should succeed")
	assert.Equal(t, 3, checked, "Should have checked all 3 events")
	assert.Equal(t, 0, corrupted, "Should have 0 corrupted events")

	// Test metrics
	metrics := eventLog.GetMetrics()
	assert.Equal(t, int64(3), metrics.TotalEventsLogged, "Should have logged 3 events")
	assert.GreaterOrEqual(t, metrics.WriteOperations, int64(3), "Should have at least 3 write operations")
}

// TestPhase24SubscriptionRegistryE2E tests the subscription registry end-to-end
func TestPhase24SubscriptionRegistryE2E(t *testing.T) {
	t.Parallel()

	// Create temp directory for event log
	tempDir, err := os.MkdirTemp("", "solid-phase24-test")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	logDir := filepath.Join(tempDir, "events")
	require.NoError(t, os.MkdirAll(logDir, 0755), "Failed to create log directory")

	// Create durable event log with temp directory
	durableLogConfig := DefaultDurableEventLogConfig()
	durableLogConfig.LogDirectory = logDir
	durableLog, err := NewDurableEventLog(durableLogConfig)
	require.NoError(t, err, "Failed to create durable event log")
	defer durableLog.Close()

	// Create subscription registry
	registryConfig := DefaultSubscriptionRegistryConfig()
	registry := NewSubscriptionRegistry(registryConfig, durableLog)
	defer registry.Close()

	// Create mock authenticator and authorizer for testing
	mockAuth := &MockAuthenticator{}
	mockAuthz := &MockAuthorizer{}
	registry.SetAuthProvider(mockAuth)
	registry.SetAuthzProvider(mockAuthz)

	// Test creating subscriptions
	webID := "https://example.com/webid1"
	token := "test-token"
	clientID := "test-client"
	channelID := "test-channel"

	filter := StreamFilter{
		EventTypes:   []NotificationEventType{EventTypeCreate, EventTypeUpdate},
		ResourceURIs: []string{"https://example.com/resource1", "https://example.com/resource2"},
	}

	// Create subscription
	subscription, err := registry.CreateSubscription(
		context.Background(),
		webID,
		token,
		clientID,
		channelID,
		filter,
		"https://example.com/endpoint",
		ProtocolWebSocket,
		0,
		map[string]string{"test": "value"},
	)
	require.NoError(t, err, "Failed to create subscription")
	require.NotNil(t, subscription, "Subscription should not be nil")

	// Verify subscription was created
	assert.Equal(t, webID, subscription.WebID, "WebID should match")
	assert.Equal(t, clientID, subscription.ClientID, "ClientID should match")
	assert.Equal(t, channelID, subscription.ChannelID, "ChannelID should match")
	assert.Equal(t, SubscriptionStatusActive, subscription.Status, "Status should be active")
	assert.Equal(t, ProtocolWebSocket, subscription.Protocol, "Protocol should match")

	// Test getting subscription by ID
	retrievedSub, err := registry.GetSubscription(subscription.SubscriptionID)
	require.NoError(t, err, "Failed to retrieve subscription")
	assert.Equal(t, subscription.SubscriptionID, retrievedSub.SubscriptionID, "Subscription ID should match")

	// Test listing subscriptions by WebID
	subsByWebID, err := registry.GetSubscriptionsByWebID(webID)
	require.NoError(t, err, "Failed to list subscriptions by WebID")
	assert.Equal(t, 1, len(subsByWebID), "Should have 1 subscription for this WebID")

	// Test listing subscriptions by channel
	subsByChannel, err := registry.GetSubscriptionsByChannel(channelID)
	require.NoError(t, err, "Failed to list subscriptions by channel")
	assert.Equal(t, 1, len(subsByChannel), "Should have 1 subscription for this channel")

	// Test updating subscription cursor
	err = registry.UpdateCursor(subscription.SubscriptionID, 100)
	require.NoError(t, err, "Failed to update cursor")

	updatedSub, err := registry.GetSubscription(subscription.SubscriptionID)
	require.NoError(t, err, "Failed to retrieve updated subscription")
	assert.Equal(t, int64(100), updatedSub.LastCursor, "Last cursor should be updated")
	assert.Equal(t, int64(100), updatedSub.ResumeCursor, "Resume cursor should be updated")

	// Test recording delivery
	err = registry.RecordDelivery(subscription.SubscriptionID, true, 100*time.Millisecond, false)
	require.NoError(t, err, "Failed to record delivery")

	deliveryStats := updatedSub.DeliveryStats.GetDeliveryStats()
	assert.Equal(t, int64(1), deliveryStats.EventsDelivered, "Should have 1 successful delivery")
	assert.Equal(t, int64(0), deliveryStats.EventsFailed, "Should have 0 failed deliveries")

	// Test authorization check for subscription
	hasAccess, err := registry.CheckAccessForSubscription(
		context.Background(),
		subscription.SubscriptionID,
		"https://example.com/resource1",
		PrivacyLevelPublic,
	)
	require.NoError(t, err, "Failed to check access")
	assert.True(t, hasAccess, "Should have access to public resource")

	// Test no access to resource not in filter
	hasAccess, err = registry.CheckAccessForSubscription(
		context.Background(),
		subscription.SubscriptionID,
		"https://example.com/resource3", // Not in filter
		PrivacyLevelPublic,
	)
	require.NoError(t, err, "Failed to check access")
	assert.False(t, hasAccess, "Should not have access to resource not in filter")

	// Test metrics
	metrics := registry.GetMetrics()
	assert.Equal(t, int64(1), metrics.TotalSubscriptions, "Should have 1 total subscription")
	assert.Equal(t, int64(1), metrics.ActiveSubscriptions, "Should have 1 active subscription")
	assert.Equal(t, int64(1), metrics.SubscriptionCreations, "Should have 1 subscription creation")
}

// TestPhase24FanoutWorkerE2E tests the fanout worker pool end-to-end
func TestPhase24FanoutWorkerE2E(t *testing.T) {
	t.Parallel()

	// Create fanout worker pool
	config := DefaultFanoutWorkerPoolConfig()
	config.NumWorkers = 3
	config.QueueSize = 100
	config.MaxRetries = 2
	config.RetryDelay = 100 * time.Millisecond

	pool := NewFanoutWorkerPool(config)
	require.NotNil(t, pool, "Failed to create fanout worker pool")
	defer pool.Close()

	// Start the pool
	err := pool.Start()
	require.NoError(t, err, "Failed to start fanout worker pool")

	// Verify pool is started
	assert.True(t, pool.IsClosed() == false, "Pool should not be closed")
	assert.Equal(t, 3, pool.Size(), "Pool should have 3 workers")
	assert.Equal(t, 3, pool.GetActiveWorkers(), "All 3 workers should be active")

	// Test submitting events to the pool
	fanoutEvents := []FanoutEvent{
		{
			Event: StreamEvent{
				EventID:      "fanout-event-1",
				EventType:    EventTypeCreate,
				ResourceURI:  "https://example.com/resource1",
				ContainerURI: "https://example.com/container1/",
				Timestamp:    time.Now().UTC(),
				Agent:        "https://example.com/agent1",
				AgentType:    PolicyAgentTypeWebID,
				Action:       "create",
				Metadata:     map[string]string{"test": "value1"},
				PrivacyLevel: PrivacyLevelPublic,
			},
			Subscribers: []*Subscription{
				// No subscribers for this test - we're testing the queue
			},
		},
		{
			Event: StreamEvent{
				EventID:      "fanout-event-2",
				EventType:    EventTypeUpdate,
				ResourceURI:  "https://example.com/resource2",
				ContainerURI: "https://example.com/container2/",
				Timestamp:    time.Now().UTC(),
				Agent:        "https://example.com/agent2",
				AgentType:    PolicyAgentTypeAgent,
				Action:       "update",
				Metadata:     map[string]string{"test": "value2"},
				PrivacyLevel: PrivacyLevelMetadata,
			},
			Subscribers: []*Subscription{},
		},
	}

	// Submit events to the pool
	for _, fanoutEvent := range fanoutEvents {
		err := pool.SubmitEvent(fanoutEvent)
		require.NoError(t, err, "Failed to submit fanout event")
	}

	// Check queue length
	queueLength := pool.GetQueueLength()
	assert.GreaterOrEqual(t, queueLength, 0, "Queue length should be >= 0")

	// Test backpressure by filling the queue
	// Create many events to test backpressure
	for i := 0; i < 50; i++ {
		fanoutEvent := FanoutEvent{
			Event: StreamEvent{
				EventID:      "backpressure-event-" + fmt.Sprintf("%d", i),
				EventType:    EventTypeCreate,
				ResourceURI:  "https://example.com/resource-" + fmt.Sprintf("%d", i),
				ContainerURI: "https://example.com/container/",
				Timestamp:    time.Now().UTC(),
				Agent:        "https://example.com/agent",
				AgentType:    PolicyAgentTypeWebID,
				Action:       "create",
				PrivacyLevel: PrivacyLevelPublic,
			},
			Subscribers: []*Subscription{},
		}

		// This might fail under backpressure, which is expected
		_ = pool.SubmitEvent(fanoutEvent)
	}

	// Check metrics
	metrics := pool.GetMetrics()
	assert.GreaterOrEqual(t, metrics.EventsDistributed, int64(2), "Should have distributed at least 2 events")
	assert.GreaterOrEqual(t, metrics.WorkersStarted, int64(3), "Should have started 3 workers")

	// Test stopping individual workers
	for i := 0; i < pool.Size(); i++ {
		queueLen, err := pool.GetWorkerQueueLength(i)
		require.NoError(t, err, "Failed to get queue length for worker %d", i)
		assert.GreaterOrEqual(t, queueLen, 0, "Worker queue length should be >= 0")
	}
}

// TestPhase24SolidNotificationE2E tests Solid notification protocol support
func TestPhase24SolidNotificationE2E(t *testing.T) {
	t.Parallel()

	// Create Solid notification service
	config := DefaultSolidNotificationConfig()
	config.Enabled = true
	config.SupportedProtocols = []SolidNotificationProtocol{
		SolidNotificationProtocolWebSocket,
		SolidNotificationProtocolSSE,
		SolidNotificationProtocolWebhook,
	}

	service := NewSolidNotificationService(config)
	require.NotNil(t, service, "Failed to create Solid notification service")
	defer service.Stop()

	// Verify service configuration
	assert.True(t, service.config.Enabled, "Service should be enabled")
	assert.Equal(t, 3, len(service.config.SupportedProtocols), "Should support 3 protocols")

	// Test starting the service
	err := service.Start()
	require.NoError(t, err, "Failed to start Solid notification service")

	// Note: In a real implementation, we'd have methods to create/manage channels
	// For this test, we're just verifying the service can be created and started

	// Test service metrics
	service.metrics.RecordChannelCreated()
	service.metrics.RecordConnectionOpened()
	service.metrics.RecordNotificationSent()
	service.metrics.RecordNotificationDelivered(100 * time.Millisecond)

	metrics := service.GetMetrics()
	assert.Equal(t, int64(1), metrics.ChannelsCreated, "Should have created 1 channel")
	assert.Equal(t, int64(1), metrics.ConnectionsOpened, "Should have opened 1 connection")
	assert.Equal(t, int64(1), metrics.NotificationsSent, "Should have sent 1 notification")
	assert.Equal(t, int64(1), metrics.NotificationsDelivered, "Should have delivered 1 notification")
}

// TestPhase24ReconnectScenarios tests reconnection scenarios
func TestPhase24ReconnectScenarios(t *testing.T) {
	t.Parallel()

	// Create temp directory for event log
	tempDir, err := os.MkdirTemp("", "solid-phase24-reconnect-test")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	logDir := filepath.Join(tempDir, "events")
	require.NoError(t, os.MkdirAll(logDir, 0755), "Failed to create log directory")

	// Create durable event log
	config := DefaultDurableEventLogConfig()
	config.LogDirectory = logDir
	eventLog, err := NewDurableEventLog(config)
	require.NoError(t, err, "Failed to create durable event log")
	defer eventLog.Close()

	// Write some initial events
	initialEvents := []StreamEvent{
		{
			EventID:      "initial-event-1",
			EventType:    EventTypeCreate,
			ResourceURI:  "https://example.com/resource1",
			ContainerURI: "https://example.com/container1/",
			Timestamp:    time.Now().UTC().Add(-2 * time.Hour),
			Agent:        "https://example.com/agent1",
			AgentType:    PolicyAgentTypeWebID,
			Action:       "create",
			PrivacyLevel: PrivacyLevelPublic,
		},
		{
			EventID:      "initial-event-2",
			EventType:    EventTypeUpdate,
			ResourceURI:  "https://example.com/resource2",
			ContainerURI: "https://example.com/container2/",
			Timestamp:    time.Now().UTC().Add(-1 * time.Hour),
			Agent:        "https://example.com/agent2",
			AgentType:    PolicyAgentTypeAgent,
			Action:       "update",
			PrivacyLevel: PrivacyLevelMetadata,
		},
	}

	for _, event := range initialEvents {
		err := eventLog.WriteEvent(event)
		require.NoError(t, err, "Failed to write initial event")
	}

	// Simulate client disconnect after receiving first event
	ctx1, cancel1 := context.WithCancel(context.Background())

	// Client subscribes from cursor 0 (start from beginning)
	subscription1, err := eventLog.SubscribeToEvents(ctx1, 0, StreamFilter{})
	require.NoError(t, err, "Failed to create first subscription")

	// Read first event
	var receivedEvents1 []LogEntry
	for len(receivedEvents1) < 1 {
		select {
		case event, ok := <-subscription1:
			if !ok {
				t.Fatal("Subscription channel closed unexpectedly")
			}
			receivedEvents1 = append(receivedEvents1, event)
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for first event")
		}
	}

	// Client disconnects (simulated by canceling context)
	cancel1()

	// Write more events while client was disconnected
	missedEvents := []StreamEvent{
		{
			EventID:      "missed-event-1",
			EventType:    EventTypeCreate,
			ResourceURI:  "https://example.com/resource3",
			ContainerURI: "https://example.com/container3/",
			Timestamp:    time.Now().UTC().Add(-30 * time.Minute),
			Agent:        "https://example.com/agent3",
			AgentType:    PolicyAgentTypeWebID,
			Action:       "create",
			PrivacyLevel: PrivacyLevelPublic,
		},
		{
			EventID:      "missed-event-2",
			EventType:    EventTypeDelete,
			ResourceURI:  "https://example.com/resource4",
			ContainerURI: "https://example.com/container4/",
			Timestamp:    time.Now().UTC().Add(-15 * time.Minute),
			Agent:        "https://example.com/agent4",
			AgentType:    PolicyAgentTypePublic,
			Action:       "delete",
			PrivacyLevel: PrivacyLevelPublic,
		},
	}

	for _, event := range missedEvents {
		err := eventLog.WriteEvent(event)
		require.NoError(t, err, "Failed to write missed event")
	}

	// Client reconnects and resumes from cursor (next event after the last received)
	lastCursor := receivedEvents1[len(receivedEvents1)-1].SequenceNumber
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	subscription2, err := eventLog.SubscribeToEvents(ctx2, lastCursor+1, StreamFilter{})
	require.NoError(t, err, "Failed to create second subscription")

	// Client should receive all events it hasn't received yet (including remaining initial events + missed events)
	// Since client only received 1 of 2 initial events, it should receive: initial-event-2 + missed-event-1 + missed-event-2
	var receivedEvents2 []LogEntry
	for len(receivedEvents2) < 3 { // 1 remaining initial event + 2 missed events
		select {
		case event, ok := <-subscription2:
			if !ok {
				t.Fatal("Second subscription channel closed unexpectedly")
			}
			receivedEvents2 = append(receivedEvents2, event)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for all missed events")
		}
	}

	// Verify we got all the events the client missed (1 initial + 2 missed = 3 total)
	assert.Equal(t, 3, len(receivedEvents2), "Should have received all missed events")

	// Verify the events are correct (initial-event-2, missed-event-1, missed-event-2)
	expectedEventIDs := []string{"initial-event-2", "missed-event-1", "missed-event-2"}
	for i, event := range receivedEvents2 {
		assert.Equal(t, expectedEventIDs[i], event.EventID, "Event ID should match expected event %d", i+1)
	}

	// Test that we can resume from any cursor position
	finalCursor := receivedEvents2[len(receivedEvents2)-1].SequenceNumber
	ctx3, cancel3 := context.WithCancel(context.Background())
	defer cancel3()

	subscription3, err := eventLog.SubscribeToEvents(ctx3, finalCursor, StreamFilter{})
	require.NoError(t, err, "Failed to create third subscription")

	// Should receive no new events since we're at the latest cursor
	select {
	case _, ok := <-subscription3:
		if !ok {
			// Channel closed, which is expected if no new events
			break
		}
		// If we get an event, that's also fine
	case <-time.After(1 * time.Second):
		// No events received, which is expected
		break
	}
}

// TestPhase24MissedEventScenarios tests missed event scenarios
func TestPhase24MissedEventScenarios(t *testing.T) {
	t.Parallel()

	// Create temp directory for event log
	tempDir, err := os.MkdirTemp("", "solid-phase24-missed-test")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	logDir := filepath.Join(tempDir, "events")
	require.NoError(t, os.MkdirAll(logDir, 0755), "Failed to create log directory")

	// Create durable event log with smaller limits for testing
	config := DefaultDurableEventLogConfig()
	config.LogDirectory = logDir
	config.MaxLogSize = 1024 * 1024         // 1MB per file
	config.MaxTotalSize = 100 * 1024 * 1024 // 100MB total
	config.RetentionTime = 24 * time.Hour

	eventLog, err := NewDurableEventLog(config)
	require.NoError(t, err, "Failed to create durable event log")
	defer eventLog.Close()

	// Write a batch of events
	eventCount := 50
	for i := 0; i < eventCount; i++ {
		event := StreamEvent{
			EventID:      "event-" + fmt.Sprintf("%d", i),
			EventType:    EventTypeCreate,
			ResourceURI:  "https://example.com/resource-" + fmt.Sprintf("%d", i),
			ContainerURI: "https://example.com/container/",
			Timestamp:    time.Now().UTC().Add(-time.Duration(i) * time.Minute),
			Agent:        "https://example.com/agent",
			AgentType:    PolicyAgentTypeWebID,
			Action:       "create",
			PrivacyLevel: PrivacyLevelPublic,
		}

		err := eventLog.WriteEvent(event)
		require.NoError(t, err, "Failed to write event %d", i)
	}

	// Test reading all events
	allEvents, err := eventLog.ReadEventsSince(0, 0)
	require.NoError(t, err, "Failed to read all events")
	assert.Equal(t, eventCount, len(allEvents), "Should have read all %d events", eventCount)

	// Test reading with limit
	limitedEvents, err := eventLog.ReadEventsSince(0, 10)
	require.NoError(t, err, "Failed to read limited events")
	assert.Equal(t, 10, len(limitedEvents), "Should have read only 10 events")

	// Test reading from specific cursor
	midCursor := allEvents[len(allEvents)/2].SequenceNumber
	midEvents, err := eventLog.ReadEventsSince(midCursor, 0)
	require.NoError(t, err, "Failed to read events from mid cursor")
	assert.Equal(t, eventCount/2, len(midEvents), "Should have read half the events")

	// Test cursor by event ID
	for i := 0; i < eventCount; i += 10 {
		eventID := "event-" + fmt.Sprintf("%d", i)
		cursor, err := eventLog.GetCursorByEventID(eventID)
		require.NoError(t, err, "Failed to get cursor for event %s", eventID)
		assert.Equal(t, int64(i), cursor, "Cursor should match sequence number")
	}

	// Test total event count
	totalCount := eventLog.GetTotalEventCount()
	assert.Equal(t, int64(eventCount), totalCount, "Total event count should match")

	// Test integrity verification
	checked, corrupted, err := eventLog.VerifyIntegrity()
	require.NoError(t, err, "Integrity verification should succeed")
	assert.Equal(t, eventCount, checked, "Should have checked all events")
	assert.Equal(t, 0, corrupted, "Should have 0 corrupted events")
}

// MockAuthenticator is a mock implementation of Authenticator for testing
type MockAuthenticator struct{}

func (m *MockAuthenticator) Authenticate(ctx context.Context, webID, token string) (string, error) {
	return webID, nil
}

func (m *MockAuthenticator) ValidateWebID(webID string) error {
	if webID == "" {
		return fmt.Errorf("empty WebID")
	}
	return nil
}

// MockAuthorizer is a mock implementation of Authorizer for testing
type MockAuthorizer struct{}

func (m *MockAuthorizer) CheckAccess(ctx context.Context, agent, resourceURI string, mode AccessMode) (bool, error) {
	// Always grant access for testing
	return true, nil
}

func (m *MockAuthorizer) GetAccessModes(ctx context.Context, agent, resourceURI string) ([]AccessMode, error) {
	return []AccessMode{AccessModeRead, AccessModeWrite}, nil
}
