// Package clients provides Solid Sidecar client implementations for the Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready - FULLY HARDENED
package clients

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockResourceServer provides a mock HTTP server for testing ResourceClient
// This server simulates Solid Sidecar resource endpoints with proper responses
type MockResourceServer struct {
	// mutex protects concurrent access to server state
	mutex sync.RWMutex

	// resources stores resource data by URI
	resources map[string]*mockResource

	// containers stores container URIs
	containers map[string]bool

	// etags stores ETags for each resource URI
	etags map[string]string

	// lastMethod stores the last HTTP method used
	lastMethod string

	// lastPath stores the last path requested
	lastPath string

	// lastBody stores the last request body received
	lastBody []byte

	// lastHeaders stores the last request headers
	lastHeaders http.Header

	// conditionalWriteFail indicates if conditional writes should fail
	conditionalWriteFail bool

	// simulateServerError indicates if the server should simulate errors
	simulateServerError bool

	// serverErrorCode is the error code to return when simulating errors
	serverErrorCode int
}

// mockResource represents a mock resource
type mockResource struct {
	Body         []byte
	ContentType  string
	ETag         string
	LastModified time.Time
	IsContainer  bool
	Links        map[string]string
}

// NewMockResourceServer creates a new mock resource server
func NewMockResourceServer() *MockResourceServer {
	return &MockResourceServer{
		resources:  make(map[string]*mockResource),
		containers: make(map[string]bool),
		etags:      make(map[string]string),
	}
}

// Handler returns the HTTP handler for the mock server
func (s *MockResourceServer) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mutex.Lock()
		defer s.mutex.Unlock()

		// Store request information
		s.lastMethod = r.Method
		s.lastPath = r.URL.Path

		// Read request body
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			s.lastBody = body
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		// Store headers
		s.lastHeaders = r.Header.Clone()

		// Handle simulate server error
		if s.simulateServerError {
			w.WriteHeader(s.serverErrorCode)
			return
		}

		// Route requests based on method and path
		switch r.Method {
		case "GET":
			s.handleGET(w, r)
		case "HEAD":
			s.handleHEAD(w, r)
		case "PUT":
			s.handlePUT(w, r)
		case "POST":
			s.handlePOST(w, r)
		case "DELETE":
			s.handleDELETE(w, r)
		case "PATCH":
			s.handlePATCH(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// handleGET handles GET requests
func (s *MockResourceServer) handleGET(w http.ResponseWriter, r *http.Request) {
	resourceURI := r.URL.Path

	// Check if resource exists
	if resource, exists := s.resources[resourceURI]; exists {
		// Set headers
		w.Header().Set("Content-Type", resource.ContentType)
		if resource.ETag != "" {
			w.Header().Set("ETag", resource.ETag)
		}
		if !resource.LastModified.IsZero() {
			w.Header().Set("Last-Modified", resource.LastModified.UTC().Format(http.TimeFormat))
		}
		// Add Link header for containers
		if resource.IsContainer {
			w.Header().Set("Link", `<http://www.w3.org/ns/ldp#BasicContainer>; rel="type"`)
		}

		w.WriteHeader(http.StatusOK)
		if len(resource.Body) > 0 {
			w.Write(resource.Body)
		}
		return
	}

	// Resource not found
	w.WriteHeader(http.StatusNotFound)
}

// handleHEAD handles HEAD requests
func (s *MockResourceServer) handleHEAD(w http.ResponseWriter, r *http.Request) {
	resourceURI := r.URL.Path

	// Check if resource exists
	if resource, exists := s.resources[resourceURI]; exists {
		// Set headers
		w.Header().Set("Content-Type", resource.ContentType)
		if resource.ETag != "" {
			w.Header().Set("ETag", resource.ETag)
		}
		if !resource.LastModified.IsZero() {
			w.Header().Set("Last-Modified", resource.LastModified.UTC().Format(http.TimeFormat))
		}

		w.WriteHeader(http.StatusOK)
		return
	}

	// Resource not found
	w.WriteHeader(http.StatusNotFound)
}

// handlePUT handles PUT requests
func (s *MockResourceServer) handlePUT(w http.ResponseWriter, r *http.Request) {
	resourceURI := r.URL.Path

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check conditional headers
	ifMatch := r.Header.Get("If-Match")
	ifNoneMatch := r.Header.Get("If-None-Match")

	// Check If-Match precondition
	if ifMatch != "" && ifMatch != "*" {
		currentETag := s.etags[resourceURI]
		if currentETag != ifMatch {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}

	// Check If-None-Match precondition
	if ifNoneMatch == "*" {
		if _, exists := s.resources[resourceURI]; exists {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	} else if ifNoneMatch != "" {
		currentETag := s.etags[resourceURI]
		if currentETag == ifNoneMatch {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}

	// Check if resource already exists
	_, existed := s.resources[resourceURI]

	// Generate new ETag
	newETag := fmt.Sprintf(`"etag-%d-%d"`, len(s.resources)+1, time.Now().UnixNano())

	// Store resource
	s.resources[resourceURI] = &mockResource{
		Body:         body,
		ContentType:  r.Header.Get("Content-Type"),
		ETag:         newETag,
		LastModified: time.Now().UTC(),
		IsContainer:  false,
		Links:        make(map[string]string),
	}
	s.etags[resourceURI] = newETag

	// Set response headers
	w.Header().Set("ETag", newETag)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.Header().Set("Location", resourceURI)

	// Return appropriate status code
	if !existed {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

// handlePOST handles POST requests (for container creation)
func (s *MockResourceServer) handlePOST(w http.ResponseWriter, r *http.Request) {
	resourceURI := r.URL.Path

	// Check if this is a container creation request
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/turtle") || strings.Contains(contentType, "application/ld+json") {
		// This might be a container creation
		// For now, just create it as a regular resource
		s.handlePUT(w, r)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Create new resource in container
	containerPath := resourceURI
	// Generate a new URI for the resource
	newURI := fmt.Sprintf("%s/new-resource-%d", containerPath, len(s.resources)+1)

	// Store resource
	s.resources[newURI] = &mockResource{
		Body:         body,
		ContentType:  r.Header.Get("Content-Type"),
		ETag:         fmt.Sprintf(`"etag-new-%d"`, len(s.resources)+1),
		LastModified: time.Now().UTC(),
		IsContainer:  false,
		Links:        make(map[string]string),
	}
	s.etags[newURI] = fmt.Sprintf(`"etag-new-%d"`, len(s.resources)+1)

	// Mark container
	s.containers[containerPath] = true

	// Set response headers
	w.Header().Set("Location", newURI)
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(newURI))
}

// handleDELETE handles DELETE requests
func (s *MockResourceServer) handleDELETE(w http.ResponseWriter, r *http.Request) {
	resourceURI := r.URL.Path

	// Check conditional headers
	ifMatch := r.Header.Get("If-Match")

	// Check If-Match precondition
	if ifMatch != "" && ifMatch != "*" {
		currentETag := s.etags[resourceURI]
		if currentETag != ifMatch {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}

	// Check if resource exists
	if _, exists := s.resources[resourceURI]; !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Delete the resource
	delete(s.resources, resourceURI)
	delete(s.etags, resourceURI)

	w.WriteHeader(http.StatusNoContent)
}

// handlePATCH handles PATCH requests
func (s *MockResourceServer) handlePATCH(w http.ResponseWriter, r *http.Request) {
	resourceURI := r.URL.Path

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check if resource exists
	if _, exists := s.resources[resourceURI]; !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Check conditional headers
	ifMatch := r.Header.Get("If-Match")
	if ifMatch != "" && ifMatch != "*" {
		currentETag := s.etags[resourceURI]
		if currentETag != ifMatch {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}

	// Update resource with PATCH body
	s.resources[resourceURI].Body = body
	s.resources[resourceURI].LastModified = time.Now().UTC()
	newETag := fmt.Sprintf(`"etag-patch-%d-%d"`, len(s.resources), time.Now().UnixNano())
	s.resources[resourceURI].ETag = newETag
	s.etags[resourceURI] = newETag

	// Set response headers
	w.Header().Set("ETag", newETag)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
}

// SetConditionalWriteFail enables/disables conditional write failure simulation
func (s *MockResourceServer) SetConditionalWriteFail(fail bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.conditionalWriteFail = fail
}

// SetServerError configures the server to return an error
func (s *MockResourceServer) SetServerError(code int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.simulateServerError = true
	s.serverErrorCode = code
}

// ResetServerError clears server error simulation
func (s *MockResourceServer) ResetServerError() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.simulateServerError = false
	s.serverErrorCode = 0
}

// AddResource adds a resource to the mock server
func (s *MockResourceServer) AddResource(resourceURI string, body []byte, contentType string, isContainer bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.resources[resourceURI] = &mockResource{
		Body:         body,
		ContentType:  contentType,
		ETag:         fmt.Sprintf(`"etag-%s"`, resourceURI),
		LastModified: time.Now().UTC(),
		IsContainer:  isContainer,
		Links:        make(map[string]string),
	}
	s.etags[resourceURI] = fmt.Sprintf(`"etag-%s"`, resourceURI)
	if isContainer {
		s.containers[resourceURI] = true
	}
}

// GetRequestInfo returns information about the last request
func (s *MockResourceServer) GetRequestInfo() (method, path string, body []byte, headers http.Header) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.lastMethod, s.lastPath, s.lastBody, s.lastHeaders
}

// Helper functions for testing

func createTestResourceClient() *ResourceClient {
	client, _ := NewResourceClient("https://example.com", nil)
	return client
}

func createTestResourceClientWithServer(server *httptest.Server) *ResourceClient {
	client, _ := NewResourceClient(server.URL, nil)
	return client
}

// Tests

func TestResourceClient_Get(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Add a resource
	resourceBody := []byte("test resource content")
	mockServer.AddResource("/resource", resourceBody, "text/plain", false)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Get the resource
	resource, err := client.Get(ctx, "/resource", nil)
	require.NoError(t, err)

	// Verify the resource was retrieved correctly
	require.NotNil(t, resource)
	assert.Equal(t, "/resource", resource.URI)
	assert.Equal(t, "test resource content", string(resource.Body))
	assert.Equal(t, "text/plain", resource.ContentType)
	assert.NotEmpty(t, resource.ETag)
	assert.False(t, time.Time{}.Equal(resource.LastModified))
}

func TestResourceClient_Get_NotFound(t *testing.T) {
	// Create mock server with no resources
	mockServer := NewMockResourceServer()

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Try to get a non-existent resource
	resource, err := client.Get(ctx, "/nonexistent", nil)
	require.Error(t, err)
	assert.Equal(t, ErrResourceNotFound, err)
	assert.Nil(t, resource)
}

func TestResourceClient_Head(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Add a resource
	resourceBody := []byte("test resource content")
	mockServer.AddResource("/resource", resourceBody, "text/plain", false)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Head the resource
	resource, err := client.Head(ctx, "/resource", nil)
	require.NoError(t, err)

	// Verify the resource was retrieved correctly (without body)
	require.NotNil(t, resource)
	assert.Equal(t, "/resource", resource.URI)
	assert.Empty(t, resource.Body) // Body should be empty for HEAD
	assert.Equal(t, "text/plain", resource.ContentType)
	assert.NotEmpty(t, resource.ETag)
}

func TestResourceClient_Head_NotFound(t *testing.T) {
	// Create mock server with no resources
	mockServer := NewMockResourceServer()

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Try to head a non-existent resource
	resource, err := client.Head(ctx, "/nonexistent", nil)
	require.Error(t, err)
	assert.Equal(t, ErrResourceNotFound, err)
	assert.Nil(t, resource)
}

func TestResourceClient_Put(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Create a new resource
	resourceBody := []byte("new resource content")
	result, err := client.Put(ctx, "/new-resource", "text/plain", resourceBody, nil, nil)
	require.NoError(t, err)

	// Verify the result
	require.NotNil(t, result)
	assert.True(t, result.Created)
	assert.Equal(t, http.StatusCreated, result.StatusCode)
	assert.NotEmpty(t, result.ETag)
	assert.NotEmpty(t, result.LastModified)

	// Verify the resource was stored in the mock server
	method, path, _, _ := mockServer.GetRequestInfo()
	assert.Equal(t, "PUT", method)
	assert.Equal(t, "/new-resource", path)
}

func TestResourceClient_Put_WithPreconditions(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Add existing resource
	mockServer.AddResource("/resource", []byte("existing content"), "text/plain", false)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Get the current ETag
	etag, err := client.GetETag(ctx, "/resource", nil)
	require.NoError(t, err)

	// Update with correct If-Match precondition
	preconditions := &types.WritePreconditions{
		IfMatch: []string{etag},
	}

	updatedBody := []byte("updated content")
	result, err := client.Put(ctx, "/resource", "text/plain", updatedBody, preconditions, nil)
	require.NoError(t, err)

	// Verify the result
	require.NotNil(t, result)
	assert.False(t, result.Created) // Updated, not created
	assert.Equal(t, http.StatusOK, result.StatusCode)
	assert.NotEmpty(t, result.ETag)
	assert.NotEqual(t, etag, result.ETag)

	// Test with wrong ETag (should fail)
	wrongPreconditions := &types.WritePreconditions{
		IfMatch: []string{"wrong-etag"},
	}

	_, err = client.Put(ctx, "/resource", "text/plain", updatedBody, wrongPreconditions, nil)
	require.Error(t, err)
	assert.Equal(t, "precondition failed", err.Error())
}

func TestResourceClient_Put_IfNoneMatch(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Put with If-None-Match: * (should succeed for new resource)
	preconditions := &types.WritePreconditions{
		IfNoneMatch: []string{"*"},
	}

	resourceBody := []byte("new resource")
	result, err := client.Put(ctx, "/new-resource", "text/plain", resourceBody, preconditions, nil)
	require.NoError(t, err)
	assert.True(t, result.Created)

	// Try to put again with If-None-Match: * (should fail)
	_, err = client.Put(ctx, "/new-resource", "text/plain", resourceBody, preconditions, nil)
	require.Error(t, err)
	assert.Equal(t, "precondition failed", err.Error())
}

func TestResourceClient_Delete(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Add existing resource
	mockServer.AddResource("/resource", []byte("content"), "text/plain", false)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Get the ETag
	etag, err := client.GetETag(ctx, "/resource", nil)
	require.NoError(t, err)

	// Delete with correct If-Match precondition
	preconditions := &types.WritePreconditions{
		IfMatch: []string{etag},
	}

	err = client.Delete(ctx, "/resource", preconditions, nil)
	require.NoError(t, err)

	// Verify the resource was deleted (try to get it)
	_, err = client.Get(ctx, "/resource", nil)
	require.Error(t, err)
	assert.Equal(t, ErrResourceNotFound, err)
}

func TestResourceClient_Delete_NotFound(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Try to delete non-existent resource
	err := client.Delete(ctx, "/nonexistent", nil, nil)
	require.Error(t, err)
	assert.Equal(t, ErrResourceNotFound, err)
}

func TestResourceClient_Exists(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Add a resource
	mockServer.AddResource("/resource", []byte("content"), "text/plain", false)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Check if resource exists
	exists, err := client.Exists(ctx, "/resource", nil)
	require.NoError(t, err)
	assert.True(t, exists)

	// Check if non-existent resource exists
	exists, err = client.Exists(ctx, "/nonexistent", nil)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestResourceClient_GetETag(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Add a resource
	mockServer.AddResource("/resource", []byte("content"), "text/plain", false)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Get ETag
	etag, err := client.GetETag(ctx, "/resource", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, etag)

	// Get ETag for non-existent resource
	_, err = client.GetETag(ctx, "/nonexistent", nil)
	require.Error(t, err)
	assert.Equal(t, ErrResourceNotFound, err)
}

func TestResourceClient_Create(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Create a new resource
	resourceBody := []byte("new resource")
	result, err := client.Create(ctx, "/new-resource", "text/plain", resourceBody, nil)
	require.NoError(t, err)
	assert.True(t, result.Created)
	assert.Equal(t, http.StatusCreated, result.StatusCode)

	// Try to create again (should fail with precondition failed since If-None-Match: * is used)
	_, err = client.Create(ctx, "/new-resource", "text/plain", resourceBody, nil)
	require.Error(t, err)
	// The error could be either precondition failed or resource already exists depending on implementation
	assert.Contains(t, err.Error(), "precondition")
}

func TestResourceClient_Update(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Add a resource
	mockServer.AddResource("/resource", []byte("original content"), "text/plain", false)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Get the ETag
	etag, err := client.GetETag(ctx, "/resource", nil)
	require.NoError(t, err)

	// Update with correct ETag
	updatedBody := []byte("updated content")
	result, err := client.Update(ctx, "/resource", "text/plain", updatedBody, etag, nil)
	require.NoError(t, err)

	// Verify the result
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ETag)
	assert.NotEqual(t, etag, result.ETag)
}

func TestResourceClient_Patch(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Add a resource
	mockServer.AddResource("/resource", []byte("original content"), "text/plain", false)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Get the ETag
	etag, err := client.GetETag(ctx, "/resource", nil)
	require.NoError(t, err)

	// Patch with correct If-Match precondition
	preconditions := &types.WritePreconditions{
		IfMatch: []string{etag},
	}

	patchQuery := "INSERT DATA { <http://example.org/resource> <http://example.org/property> \"value\" }"
	result, err := client.Patch(ctx, "/resource", patchQuery, preconditions, nil)
	require.NoError(t, err)

	// Verify the result
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ETag)
	assert.NotEqual(t, etag, result.ETag)
}

func TestResourceClient_List(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Add a container
	mockServer.AddResource("/container/", []byte("container"), "text/turtle", true)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// List container
	listResp, err := client.List(ctx, "/container/", nil)
	require.NoError(t, err)
	assert.NotNil(t, listResp)
	// Note: The mock server doesn't fully implement container listing,
	// but the client method should not error
}

func TestResourceClient_ServerError(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Configure server to return error
	mockServer.SetServerError(http.StatusInternalServerError)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Try to get a resource (should fail with server error)
	_, err := client.Get(ctx, "/resource", nil)
	require.Error(t, err)

	// Reset server error
	mockServer.ResetServerError()

	// Should work now (but resource doesn't exist)
	_, err = client.Get(ctx, "/resource", nil)
	require.Error(t, err)
	assert.Equal(t, ErrResourceNotFound, err)
}

func TestResourceClient_CreateContainer(t *testing.T) {
	// Create mock server
	mockServer := NewMockResourceServer()

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestResourceClientWithServer(server)

	ctx := context.Background()

	// Create a new container
	containerType := "http://www.w3.org/ns/ldp#BasicContainer"
	result, err := client.CreateContainer(ctx, "/new-container/", containerType, nil)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Created)
}

func TestResourceClient_NewResourceClient_WithOptions(t *testing.T) {
	options := &ResourceClientOptions{
		BasePath: "/api/v1",
		RequestOptions: &types.RequestOptions{
			Timeout: 10 * time.Second,
		},
	}

	client, err := NewResourceClient("https://example.com", options)
	if err != nil {
		t.Fatalf("NewResourceClient() error = %v", err)
	}

	// The basePath should be normalized
	// We can't directly check basePath as it's private, but we can test functionality
	assert.NotNil(t, client)
}

func TestResourceClient_SetAccessToken(t *testing.T) {
	client := createTestResourceClient()
	client.SetAccessToken("test-token")
	// Can't directly verify token is set as httpClient is private,
	// but method should not panic
	assert.NotNil(t, client)
}

func TestResourceClient_SetDPoPProofFunc(t *testing.T) {
	client := createTestResourceClient()

	// Create a simple DPoP proof function
	proofFunc := func(method, url string) (string, error) {
		return "test-proof", nil
	}

	client.SetDPoPProofFunc(proofFunc)
	// Can't directly verify function is set as dpopProofFunc is private,
	// but method should not panic
	assert.NotNil(t, client)
}
