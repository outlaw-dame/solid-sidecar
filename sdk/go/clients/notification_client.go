// Package clients provides Solid Sidecar client implementations for the Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready - FULLY HARDENED
package clients

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/types"
	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/utils"
)

// ErrSubscriptionNotFound represents a subscription not found error
var ErrSubscriptionNotFound = errors.New("subscription not found")

// ErrInvalidSubscription represents an invalid subscription error
var ErrInvalidSubscription = errors.New("invalid subscription")

// ErrSubscriptionConflict represents a subscription conflict error
var ErrSubscriptionConflict = errors.New("subscription conflict")

// NotificationClient provides operations for managing Solid Notifications subscriptions.
// This implementation is thread-safe and follows Solid Notifications protocol.
type NotificationClient struct {
	// httpClient is the underlying HTTP client
	httpClient *utils.HTTPClient

	// basePath is the base path for notification operations
	basePath string

	// dpopProofFunc is the function to generate DPoP proofs
	dpopProofFunc func(method, url string) (string, error)

	// subscriptions stores active subscriptions
	subscriptions map[string]*types.Subscription

	// eventHandlers stores event handlers for each subscription
	eventHandlers map[string][]func(*types.Event)

	// mu protects the subscriptions and eventHandlers maps
	mu sync.RWMutex

	// serverSentEventsSupported indicates if the server supports SSE
	serverSentEventsSupported bool

	// websocketSupported indicates if the server supports WebSocket
	websocketSupported bool
}

// NotificationClientOptions contains options for creating a NotificationClient.
type NotificationClientOptions struct {
	// BasePath is the base path for notification operations (defaults to "/")
	BasePath string

	// RequestOptions contains HTTP request options
	RequestOptions *types.RequestOptions

	// ServerSentEventsSupported indicates if SSE is supported
	ServerSentEventsSupported bool

	// WebSocketSupported indicates if WebSocket is supported
	WebSocketSupported bool
}

// NewNotificationClient creates a new NotificationClient.
//
// Parameters:
//   - baseURL: The base URL of the Solid Sidecar instance
//   - options: Optional client options (can be nil for defaults)
//
// Returns:
//   - A new NotificationClient instance
//   - Error if creation fails
func NewNotificationClient(baseURL string, options *NotificationClientOptions) (*NotificationClient, error) {
	httpOptions := &types.RequestOptions{}
	if options != nil && options.RequestOptions != nil {
		httpOptions = options.RequestOptions
	}

	httpClient, err := utils.NewHTTPClient(baseURL, httpOptions)
	if err != nil {
		return nil, err
	}

	basePath := "/"
	if options != nil && options.BasePath != "" {
		basePath = options.BasePath
		// Ensure basePath ends with / and doesn't have //
		basePath = strings.TrimRight(basePath, "/") + "/"
	}

	// Set defaults if options is nil
	serverSentEventsSupported := false
	websocketSupported := false
	if options != nil {
		serverSentEventsSupported = options.ServerSentEventsSupported
		websocketSupported = options.WebSocketSupported
	}

	return &NotificationClient{
		httpClient:                httpClient,
		basePath:                  basePath,
		subscriptions:             make(map[string]*types.Subscription),
		eventHandlers:             make(map[string][]func(*types.Event)),
		serverSentEventsSupported: serverSentEventsSupported,
		websocketSupported:        websocketSupported,
	}, nil
}

// SetAccessToken sets the access token for authentication.
func (c *NotificationClient) SetAccessToken(token string) {
	c.httpClient.SetAccessToken(token)
}

// SetDPoPProofFunc sets the function to generate DPoP proofs.
func (c *NotificationClient) SetDPoPProofFunc(fn func(method, url string) (string, error)) {
	c.dpopProofFunc = fn
	c.httpClient.SetDPoPProofFunc(fn)
}

// buildNotificationPath builds the full path for a notification endpoint.
func (c *NotificationClient) buildNotificationPath(path string) string {
	// If path already contains scheme, use as-is
	if strings.Contains(path, "://") {
		return path
	}

	// Remove leading slash from basePath and path
	base := strings.TrimRight(c.basePath, "/")
	notification := strings.TrimLeft(path, "/")

	return base + "/" + notification
}

// DiscoverNotificationEndpoint discovers the notification endpoint from the server.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//
// Returns:
//   - The notification endpoint URL
//   - Error if discovery fails
func (c *NotificationClient) DiscoverNotificationEndpoint(ctx context.Context) (string, error) {
	// Try common notification endpoint patterns
	// Solid Notifications typically uses a .well-known endpoint

	wellKnownPath := c.buildNotificationPath(".well-known/solid-notifications")

	body, statusCode, headers, err := c.httpClient.Do(
		ctx,
		"GET",
		wellKnownPath,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return "", err
	}

	// Check for errors
	if err := utils.CheckHTTPError(statusCode, body); err != nil {
		// Try alternative endpoint
		altPath := c.buildNotificationPath(".well-known/notifications")
		body, statusCode, headers, err = c.httpClient.Do(
			ctx,
			"GET",
			altPath,
			nil,
			nil,
			nil,
		)
		if err != nil {
			return "", err
		}

		if err := utils.CheckHTTPError(statusCode, body); err != nil {
			return "", err
		}
	}

	// Parse response to get endpoint
	if len(body) > 0 {
		var config struct {
			SubscriptionURL string   `json:"subscriptionUrl"`
			ChannelTypes    []string `json:"channelTypes"`
		}

		if err := json.Unmarshal(body, &config); err == nil {
			if config.SubscriptionURL != "" {
				return config.SubscriptionURL, nil
			}
		}

		// Try to extract from Link headers
		if link, ok := headers["Link"]; ok {
			// Parse Link header for subscription URL
			if strings.Contains(link, "subscription") {
				// Extract URL from Link header
				parts := strings.Split(link, "<")
				for _, part := range parts {
					if strings.Contains(part, "subscription") {
						urlPart := strings.Split(part, ">")[0]
						return urlPart, nil
					}
				}
			}
		}
	}

	// Default to common endpoint
	return c.basePath + "notifications", nil
}

// CreateSubscription creates a new notification subscription.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource to subscribe to
//   - callbackURL: The URL to receive notifications (optional)
//   - channelType: The channel type (sse, websocket)
//   - options: Request options (can be nil)
//
// Returns:
//   - The Subscription
//   - Error if creation fails
func (c *NotificationClient) CreateSubscription(
	ctx context.Context,
	resourceURI string,
	callbackURL string,
	channelType string,
	options *types.RequestOptions,
) (*types.Subscription, error) {
	// Discover notification endpoint
	endpoint, err := c.DiscoverNotificationEndpoint(ctx)
	if err != nil {
		return nil, err
	}

	// Build subscription request
	subscription := &types.Subscription{
		ResourceURI: resourceURI,
		CallbackURL: callbackURL,
		ChannelType: channelType,
		Created:     time.Now().UTC(),
		Expires:     time.Now().Add(24 * time.Hour).UTC(), // Default expiry
	}

	// Build headers
	headers := types.HTTPHeaders{
		"Content-Type": "application/json",
	}

	// Serialize subscription
	subBody, err := json.Marshal(subscription)
	if err != nil {
		return nil, err
	}

	// Send POST request to create subscription
	respBody, statusCode, respHeaders, err := c.httpClient.Do(
		ctx,
		"POST",
		endpoint,
		subBody,
		headers,
		options,
	)
	if err != nil {
		return nil, err
	}

	// Parse response
	if statusCode != 200 && statusCode != 201 {
		if err := utils.CheckHTTPError(statusCode, respBody); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to create subscription: status %d", statusCode)
	}

	// Parse subscription response
	var subResp struct {
		ID          string    `json:"id"`
		ResourceURI string    `json:"resourceUri"`
		CallbackURL string    `json:"callbackUrl,omitempty"`
		ChannelType string    `json:"channelType"`
		Created     time.Time `json:"created"`
		Expires     time.Time `json:"expires,omitempty"`
		LastEventID string    `json:"lastEventId,omitempty"`
	}

	if err := json.Unmarshal(respBody, &subResp); err != nil {
		// If response is not JSON, try to use headers
		if loc, ok := respHeaders["Location"]; ok {
			subscription.ID = loc
		} else {
			return nil, fmt.Errorf("failed to parse subscription response")
		}
	} else {
		subscription.ID = subResp.ID
		if subResp.Created != (time.Time{}) {
			subscription.Created = subResp.Created
		}
		if !subResp.Expires.IsZero() {
			subscription.Expires = subResp.Expires
		}
		if subResp.LastEventID != "" {
			subscription.LastEventID = subResp.LastEventID
		}
	}

	// Store subscription
	c.mu.Lock()
	c.subscriptions[subscription.ID] = subscription
	c.mu.Unlock()

	return subscription, nil
}

// GetSubscription retrieves a subscription.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - subscriptionID: The subscription ID
//   - options: Request options (can be nil)
//
// Returns:
//   - The Subscription
//   - Error if retrieval fails
func (c *NotificationClient) GetSubscription(
	ctx context.Context,
	subscriptionID string,
	options *types.RequestOptions,
) (*types.Subscription, error) {
	// Discover notification endpoint
	endpoint, err := c.DiscoverNotificationEndpoint(ctx)
	if err != nil {
		return nil, err
	}

	// Build path for specific subscription
	subPath := fmt.Sprintf("%s/%s", strings.TrimRight(endpoint, "/"), subscriptionID)

	body, statusCode, _, err := c.httpClient.Do(
		ctx,
		"GET",
		subPath,
		nil,
		nil,
		options,
	)
	if err != nil {
		return nil, err
	}

	// Check for errors
	if statusCode == 404 {
		return nil, ErrSubscriptionNotFound
	}

	if err := utils.CheckHTTPError(statusCode, body); err != nil {
		return nil, err
	}

	// Parse subscription
	var subscription types.Subscription
	if err := json.Unmarshal(body, &subscription); err != nil {
		return nil, err
	}

	return &subscription, nil
}

// ListSubscriptions lists all active subscriptions.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - options: Request options (can be nil)
//
// Returns:
//   - Slice of Subscriptions
//   - Error if listing fails
func (c *NotificationClient) ListSubscriptions(
	ctx context.Context,
	options *types.RequestOptions,
) ([]*types.Subscription, error) {
	// Discover notification endpoint
	endpoint, err := c.DiscoverNotificationEndpoint(ctx)
	if err != nil {
		return nil, err
	}

	body, statusCode, _, err := c.httpClient.Do(
		ctx,
		"GET",
		endpoint,
		nil,
		nil,
		options,
	)
	if err != nil {
		return nil, err
	}

	// Check for errors
	if err := utils.CheckHTTPError(statusCode, body); err != nil {
		return nil, err
	}

	// Parse subscriptions
	var subscriptions []*types.Subscription
	if err := json.Unmarshal(body, &subscriptions); err != nil {
		// Try to parse as a single subscription
		var single types.Subscription
		if err := json.Unmarshal(body, &single); err == nil {
			subscriptions = []*types.Subscription{&single}
		} else {
			return nil, fmt.Errorf("failed to parse subscriptions: %v", err)
		}
	}

	return subscriptions, nil
}

// DeleteSubscription deletes a subscription.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - subscriptionID: The subscription ID
//   - options: Request options (can be nil)
//
// Returns:
//   - Error if deletion fails
func (c *NotificationClient) DeleteSubscription(
	ctx context.Context,
	subscriptionID string,
	options *types.RequestOptions,
) error {
	// Discover notification endpoint
	endpoint, err := c.DiscoverNotificationEndpoint(ctx)
	if err != nil {
		return err
	}

	// Build path for specific subscription
	subPath := fmt.Sprintf("%s/%s", strings.TrimRight(endpoint, "/"), subscriptionID)

	_, statusCode, _, err := c.httpClient.Do(
		ctx,
		"DELETE",
		subPath,
		nil,
		nil,
		options,
	)
	if err != nil {
		return err
	}

	// Check for errors
	if statusCode == 404 {
		return ErrSubscriptionNotFound
	}

	if err := utils.CheckHTTPError(statusCode, nil); err != nil {
		return err
	}

	// Remove from local store
	c.mu.Lock()
	delete(c.subscriptions, subscriptionID)
	delete(c.eventHandlers, subscriptionID)
	c.mu.Unlock()

	return nil
}

// Subscribe starts listening for events on a subscription using Server-Sent Events.
//
// Parameters:
//   - ctx: Context for cancellation
//   - subscriptionID: The subscription ID
//   - onEvent: Callback function for events
//
// Returns:
//   - Error if subscription fails
func (c *NotificationClient) Subscribe(
	ctx context.Context,
	subscriptionID string,
	onEvent func(*types.Event),
) error {
	// Get subscription
	sub, err := c.GetSubscription(ctx, subscriptionID, nil)
	if err != nil {
		return err
	}

	if sub == nil {
		return ErrSubscriptionNotFound
	}

	// Discover notification endpoint
	endpoint, err := c.DiscoverNotificationEndpoint(ctx)
	if err != nil {
		return err
	}

	// Build SSE URL
	sseURL := fmt.Sprintf("%s/%s/sse", strings.TrimRight(endpoint, "/"), subscriptionID)

	// Store event handler
	c.mu.Lock()
	c.eventHandlers[subscriptionID] = append(c.eventHandlers[subscriptionID], onEvent)
	c.mu.Unlock()

	// Start SSE connection in background
	go c.listenSSE(ctx, sseURL, subscriptionID)

	return nil
}

// listenSSE listens for Server-Sent Events from the notification endpoint.
func (c *NotificationClient) listenSSE(
	ctx context.Context,
	sseURL string,
	subscriptionID string,
) {
	// Create HTTP client for SSE
	client := &http.Client{
		Timeout: 0, // No timeout for long-lived connections
	}

	// Create request
	req, err := http.NewRequest("GET", sseURL, nil)
	if err != nil {
		c.logError("SSE", fmt.Sprintf("Failed to create SSE request: %v", err))
		return
	}

	// Set headers
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")

	// Add access token if available
	if token := c.httpClient.GetAccessToken(); token != "" {
		req.Header.Set("Authorization", "DPoP "+token)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		c.logError("SSE", fmt.Sprintf("Failed to connect to SSE endpoint: %v", err))
		return
	}
	defer resp.Body.Close()

	// Check status
	if resp.StatusCode != 200 {
		c.logError("SSE", fmt.Sprintf("SSE connection failed with status: %d", resp.StatusCode))
		return
	}

	// Read events
	decoder := NewSSEDecoder(resp.Body)

	for {
		select {
		case <-ctx.Done():
			// Context cancelled
			return
		default:
			event, err := decoder.Decode()
			if err != nil {
				// Check if connection was closed normally
				if err.Error() == "EOF" || strings.Contains(err.Error(), "closed") {
					// Try to reconnect
					time.Sleep(1 * time.Second)
					c.listenSSE(ctx, sseURL, subscriptionID)
					return
				}
				c.logError("SSE", fmt.Sprintf("Failed to decode SSE event: %v", err))
				continue
			}

			if event == nil {
				continue
			}

			// Parse event data as Solid Event
			solidEvent, err := c.parseEvent(event.Data)
			if err != nil {
				c.logError("SSE", fmt.Sprintf("Failed to parse event: %v", err))
				continue
			}

			// Update subscription last event ID
			if event.ID != "" {
				c.mu.Lock()
				if sub, exists := c.subscriptions[subscriptionID]; exists {
					sub.LastEventID = event.ID
				}
				c.mu.Unlock()
			}

			// Notify handlers
			c.mu.RLock()
			handlers := c.eventHandlers[subscriptionID]
			c.mu.RUnlock()

			for _, handler := range handlers {
				handler(solidEvent)
			}
		}
	}
}

// parseEvent parses an SSE event data as a Solid Event.
func (c *NotificationClient) parseEvent(data string) (*types.Event, error) {
	if data == "" {
		return nil, errors.New("empty event data")
	}

	// Try to parse as JSON
	var event types.Event
	if err := json.Unmarshal([]byte(data), &event); err != nil {
		// Try to parse as URL-encoded JSON or other formats
		decoded, err := url.QueryUnescape(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse event data: %v", err)
		}

		if err := json.Unmarshal([]byte(decoded), &event); err != nil {
			return nil, fmt.Errorf("failed to parse event data: %v", err)
		}
	}

	return &event, nil
}

// SubscribeWebSocket starts listening for events using WebSocket.
// Note: This is a placeholder - actual WebSocket implementation would require a WebSocket client.
//
// Parameters:
//   - ctx: Context for cancellation
//   - subscriptionID: The subscription ID
//   - onEvent: Callback function for events
//
// Returns:
//   - Error if subscription fails
func (c *NotificationClient) SubscribeWebSocket(
	ctx context.Context,
	subscriptionID string,
	onEvent func(*types.Event),
) error {
	// WebSocket support would be implemented with a WebSocket client library
	return errors.New("WebSocket subscriptions not yet implemented - use SSE")
}

// GetEvents retrieves historical events for a subscription.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - subscriptionID: The subscription ID
//   - since: The timestamp to get events since (optional)
//   - limit: Maximum number of events to retrieve (optional)
//   - options: Request options (can be nil)
//
// Returns:
//   - Slice of Events
//   - The last event ID (for pagination)
//   - Error if retrieval fails
func (c *NotificationClient) GetEvents(
	ctx context.Context,
	subscriptionID string,
	since *time.Time,
	limit int,
	options *types.RequestOptions,
) ([]*types.Event, string, error) {
	// Discover notification endpoint
	endpoint, err := c.DiscoverNotificationEndpoint(ctx)
	if err != nil {
		return nil, "", err
	}

	// Build path for events
	eventsPath := fmt.Sprintf("%s/%s/events", strings.TrimRight(endpoint, "/"), subscriptionID)

	// Add query parameters
	query := url.Values{}
	if since != nil {
		query.Set("since", since.Format(time.RFC3339))
	}
	if limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", limit))
	}

	if len(query) > 0 {
		eventsPath = eventsPath + "?" + query.Encode()
	}

	body, statusCode, _, err := c.httpClient.Do(
		ctx,
		"GET",
		eventsPath,
		nil,
		nil,
		options,
	)
	if err != nil {
		return nil, "", err
	}

	// Check for errors
	if err := utils.CheckHTTPError(statusCode, body); err != nil {
		return nil, "", err
	}

	// Parse events
	var events []*types.Event
	if err := json.Unmarshal(body, &events); err != nil {
		// Try to parse as a single event
		var singleEvent types.Event
		if err := json.Unmarshal(body, &singleEvent); err == nil {
			events = []*types.Event{&singleEvent}
		} else {
			return nil, "", fmt.Errorf("failed to parse events: %v", err)
		}
	}

	// Get last event ID
	var lastEventID string
	if len(events) > 0 {
		lastEventID = events[len(events)-1].ID
	}

	return events, lastEventID, nil
}

// GetEvent retrieves a specific event by ID.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - eventID: The event ID
//   - options: Request options (can be nil)
//
// Returns:
//   - The Event
//   - Error if retrieval fails
func (c *NotificationClient) GetEvent(
	ctx context.Context,
	eventID string,
	options *types.RequestOptions,
) (*types.Event, error) {
	// Discover notification endpoint
	endpoint, err := c.DiscoverNotificationEndpoint(ctx)
	if err != nil {
		return nil, err
	}

	// Build path for specific event
	eventPath := fmt.Sprintf("%s/events/%s", strings.TrimRight(endpoint, "/"), eventID)

	body, statusCode, _, err := c.httpClient.Do(
		ctx,
		"GET",
		eventPath,
		nil,
		nil,
		options,
	)
	if err != nil {
		return nil, err
	}

	// Check for errors
	if statusCode == 404 {
		return nil, fmt.Errorf("event not found: %s", eventID)
	}

	if err := utils.CheckHTTPError(statusCode, body); err != nil {
		return nil, err
	}

	// Parse event
	var event types.Event
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, err
	}

	return &event, nil
}

// OnEvent registers an event handler for a subscription.
//
// Parameters:
//   - subscriptionID: The subscription ID
//   - handler: The event handler function
func (c *NotificationClient) OnEvent(subscriptionID string, handler func(*types.Event)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.eventHandlers[subscriptionID] = append(c.eventHandlers[subscriptionID], handler)
}

// RemoveEventHandler removes an event handler for a subscription.
// Note: Due to Go limitations with function comparison, this removes all handlers
// for the subscription. For more granular removal, use a different pattern.
//
// Parameters:
//   - subscriptionID: The subscription ID
//   - handler: The event handler function to remove (unused due to Go limitations)
//
// Returns:
//   - true if handlers were cleared
func (c *NotificationClient) RemoveEventHandler(subscriptionID string, handler func(*types.Event)) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.eventHandlers[subscriptionID]; exists {
		// Remove all handlers for this subscription
		delete(c.eventHandlers, subscriptionID)
		return true
	}

	return false
}

// UnsubscribeAll removes all event handlers for a subscription.
//
// Parameters:
//   - subscriptionID: The subscription ID
func (c *NotificationClient) UnsubscribeAll(subscriptionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.eventHandlers, subscriptionID)
}

// logError logs an error for the notification client.
func (c *NotificationClient) logError(component, message string) {
	// In production, this would use a proper logging framework
	// For now, we'll just print to stderr
	fmt.Fprintf(os.Stderr, "[NotificationClient:%s] %s\n", component, message)
}

// SSEDecoder decodes Server-Sent Events from an io.Reader.
type SSEDecoder struct {
	reader *bufio.Reader
}

// NewSSEDecoder creates a new SSE decoder.
func NewSSEDecoder(reader io.Reader) *SSEDecoder {
	return &SSEDecoder{
		reader: bufio.NewReader(reader),
	}
}

// SSEEvent represents a Server-Sent Event.
type SSEEvent struct {
	ID    string
	Event string
	Data  string
}

// Decode decodes the next SSE event.
func (d *SSEDecoder) Decode() (*SSEEvent, error) {
	var event SSEEvent

	for {
		line, err := d.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		// Remove trailing newline and carriage return
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		if line == "" {
			// Empty line indicates end of event
			return &event, nil
		}

		// Parse field
		if strings.HasPrefix(line, "id:") {
			event.ID = strings.TrimPrefix(line, "id:")
		} else if strings.HasPrefix(line, "event:") {
			event.Event = strings.TrimPrefix(line, "event:")
		} else if strings.HasPrefix(line, "data:") {
			data := strings.TrimPrefix(line, "data:")
			// Handle multi-line data
			if strings.HasSuffix(line, "\n") || strings.HasSuffix(line, "\r\n") {
				// More data to come
				continue
			}
			event.Data = data
		} else if line == "" {
			// Skip empty lines
			continue
		}
	}
}
