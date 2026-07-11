// Package clients provides Solid Sidecar client implementations for the Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready - FULLY HARDENED
package clients

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestPolicyClient_GetPolicyURI(t *testing.T) {
	// Create a policy client
	client := createTestPolicyClient()

	tests := []struct {
		name        string
		resourceURI string
		policyType  types.PolicyResourceType
		expected    string
	}{
		{
			name:        "WAC policy",
			resourceURI: "https://example.com/resource",
			policyType:  types.WAC,
			expected:    "https://example.com/resource.acl",
		},
		{
			name:        "ACP policy",
			resourceURI: "https://example.com/resource",
			policyType:  types.ACP,
			expected:    "https://example.com/resource.acp",
		},
		{
			name:        "SAI policy",
			resourceURI: "https://example.com/resource",
			policyType:  types.SAI,
			expected:    "https://example.com/resource.sai",
		},
		{
			name:        "default policy type",
			resourceURI: "https://example.com/resource",
			policyType:  "",
			expected:    "https://example.com/resource.acp", // Should default to ACP
		},
		{
			name:        "resource with trailing slash",
			resourceURI: "https://example.com/resource/",
			policyType:  types.ACP,
			expected:    "https://example.com/resource.acp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.GetPolicyURI(tt.resourceURI, tt.policyType)
			if result != tt.expected {
				t.Errorf("GetPolicyURI() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPolicyClient_SerializeWAC(t *testing.T) {
	client := createTestPolicyClient()

	policy := &types.Policy{
		Type: types.WAC,
		Rules: []types.PolicyRule{
			{
				AccessMode: types.Read,
				Agent:      "https://example.com/agent#me",
				AgentType:  types.AgentTypeAgent,
				Resource:   "https://example.com/resource",
			},
			{
				AccessMode: types.Write,
				Agent:      "https://example.com/agent#me",
				AgentType:  types.AgentTypeAgent,
				Resource:   "https://example.com/resource",
			},
		},
	}

	contentType, body, err := client.serializePolicy(policy)
	if err != nil {
		t.Fatalf("serializePolicy() error = %v", err)
	}

	if contentType != "text/turtle" {
		t.Errorf("serializePolicy() contentType = %v, want %v", contentType, "text/turtle")
	}

	// Check that body contains expected elements
	bodyStr := string(body)
	if !contains(bodyStr, "acl:mode acl:Read") {
		t.Errorf("serializePolicy() body should contain 'acl:mode acl:Read', got %s", bodyStr)
	}
	if !contains(bodyStr, "acl:mode acl:Write") {
		t.Errorf("serializePolicy() body should contain 'acl:mode acl:Write', got %s", bodyStr)
	}
	if !contains(bodyStr, "acl:agent") {
		t.Errorf("serializePolicy() body should contain 'acl:agent', got %s", bodyStr)
	}
}

func TestPolicyClient_SerializeACP(t *testing.T) {
	client := createTestPolicyClient()
	client.SetPolicyType(types.ACP)

	policy := &types.Policy{
		Type: types.ACP,
		Rules: []types.PolicyRule{
			{
				AccessMode: types.Read,
				Agent:      "https://example.com/agent#me",
				AgentType:  types.AgentTypeAgent,
			},
			{
				AccessMode: types.Write,
				Agent:      "https://example.com/agent#me",
				AgentType:  types.AgentTypeAgent,
			},
		},
	}

	contentType, body, err := client.serializePolicy(policy)
	if err != nil {
		t.Fatalf("serializePolicy() error = %v", err)
	}

	if contentType != "application/ld+json" {
		t.Errorf("serializePolicy() contentType = %v, want %v", contentType, "application/ld+json")
	}

	// Check that body contains expected elements
	bodyStr := string(body)
	if !contains(bodyStr, "@context") {
		t.Errorf("serializePolicy() body should contain '@context', got %s", bodyStr)
	}
	if !contains(bodyStr, "rule") {
		t.Errorf("serializePolicy() body should contain 'rule', got %s", bodyStr)
	}
	if !contains(bodyStr, "AccessControl") {
		t.Errorf("serializePolicy() body should contain 'AccessControl', got %s", bodyStr)
	}
}

func TestPolicyClient_AddRule(t *testing.T) {
	// Create a test server with a simple handler
	getCount := 0
	var putBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GET request
		if r.Method == "GET" && r.URL.Path == "/resource.acp" {
			getCount++
			w.Header().Set("Content-Type", "application/ld+json")

			// First GET returns initial policy, second GET returns updated policy
			if getCount == 1 {
				w.Header().Set("ETag", "\"initial-etag\"")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
  "@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
  "@type": "AccessControl",
  "rule": [
    {
      "@type": "AccessGrant",
      "access": "Read",
      "agent": "https://example.com/agent1"
    }
  ]
}`))
			} else {
				// Second GET (after PUT) returns updated policy
				w.Header().Set("ETag", "\"new-etag\"")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
  "@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
  "@type": "AccessControl",
  "rule": [
    {
      "@type": "AccessGrant",
      "access": "Read",
      "agent": "https://example.com/agent1"
    },
    {
      "@type": "AccessGrant",
      "access": "Write",
      "agent": "https://example.com/agent2"
    }
  ]
}`))
			}
			return
		}

		// Handle PUT request (from Update)
		if r.Method == "PUT" && r.URL.Path == "/resource.acp" {
			// Check If-Match header
			ifMatch := r.Header.Get("If-Match")
			if ifMatch != "\"initial-etag\"" {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}

			// Capture the PUT body
			putBody, _ = io.ReadAll(r.Body)

			w.Header().Set("ETag", "\"new-etag\"")
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusOK)
			// Return the same body back
			w.Write(putBody)
			return
		}

		// Handle HEAD request
		if r.Method == "HEAD" {
			if r.URL.Path == "/resource.acp" {
				w.Header().Set("Content-Type", "application/ld+json")
				w.Header().Set("ETag", "\"initial-etag\"")
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)
	client.SetPolicyType(types.ACP)

	ctx := context.Background()

	// Add a new rule
	newRule := types.PolicyRule{
		AccessMode: types.Write,
		Agent:      "https://example.com/agent2",
	}

	// Add the rule
	updatedPolicy, err := client.AddRule(ctx, "/resource.acp", newRule, "\"initial-etag\"", nil)
	require.NoError(t, err)

	// Verify the policy was updated
	require.NotNil(t, updatedPolicy)
	assert.Equal(t, types.ACP, updatedPolicy.Type)
	assert.Equal(t, "\"new-etag\"", updatedPolicy.ETag)
	assert.Len(t, updatedPolicy.Rules, 2)
	assert.Equal(t, types.Read, updatedPolicy.Rules[0].AccessMode)
	assert.Equal(t, types.Write, updatedPolicy.Rules[1].AccessMode)
	assert.Equal(t, "https://example.com/agent1", updatedPolicy.Rules[0].Agent)
	assert.Equal(t, "https://example.com/agent2", updatedPolicy.Rules[1].Agent)

	// Verify that the PUT body contained 2 rules
	assert.True(t, contains(string(putBody), "\"Read\""))
	assert.True(t, contains(string(putBody), "\"Write\""))
	assert.True(t, contains(string(putBody), "https://example.com/agent1"))
	assert.True(t, contains(string(putBody), "https://example.com/agent2"))
}

func TestPolicyClient_RemoveRule(t *testing.T) {
	// Create a test server with a simple handler
	getCount := 0
	var putBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GET request
		if r.Method == "GET" && r.URL.Path == "/resource.acp" {
			getCount++
			w.Header().Set("Content-Type", "application/ld+json")

			// First GET returns initial policy with 3 rules, second GET returns updated policy with 2 rules
			if getCount == 1 {
				w.Header().Set("ETag", "\"initial-etag\"")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
  "@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
  "@type": "AccessControl",
  "rule": [
    {
      "@type": "AccessGrant",
      "access": "Read",
      "agent": "https://example.com/agent1"
    },
    {
      "@type": "AccessGrant",
      "access": "Write",
      "agent": "https://example.com/agent2"
    },
    {
      "@type": "AccessGrant",
      "access": "Control",
      "agent": "https://example.com/agent3"
    }
  ]
}`))
			} else {
				// Second GET (after PUT) returns updated policy with 2 rules (Write rule removed)
				w.Header().Set("ETag", "\"new-etag\"")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
  "@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
  "@type": "AccessControl",
  "rule": [
    {
      "@type": "AccessGrant",
      "access": "Read",
      "agent": "https://example.com/agent1"
    },
    {
      "@type": "AccessGrant",
      "access": "Control",
      "agent": "https://example.com/agent3"
    }
  ]
}`))
			}
			return
		}

		// Handle PUT request (from Update)
		if r.Method == "PUT" && r.URL.Path == "/resource.acp" {
			// Check If-Match header
			ifMatch := r.Header.Get("If-Match")
			if ifMatch != "\"initial-etag\"" {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}

			// Capture the PUT body
			putBody, _ = io.ReadAll(r.Body)

			w.Header().Set("ETag", "\"new-etag\"")
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusOK)
			// Return the same body back
			w.Write(putBody)
			return
		}

		// Handle HEAD request
		if r.Method == "HEAD" {
			if r.URL.Path == "/resource.acp" {
				w.Header().Set("Content-Type", "application/ld+json")
				w.Header().Set("ETag", "\"initial-etag\"")
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)
	client.SetPolicyType(types.ACP)

	ctx := context.Background()

	// Remove rule at index 1 (Write rule)
	updatedPolicy, err := client.RemoveRule(ctx, "/resource.acp", 1, "\"initial-etag\"", nil)
	require.NoError(t, err)

	// Verify the policy was updated
	require.NotNil(t, updatedPolicy)
	assert.Equal(t, types.ACP, updatedPolicy.Type)
	assert.Equal(t, "\"new-etag\"", updatedPolicy.ETag)
	assert.Len(t, updatedPolicy.Rules, 2)
	assert.Equal(t, types.Read, updatedPolicy.Rules[0].AccessMode)
	assert.Equal(t, types.Control, updatedPolicy.Rules[1].AccessMode)
	assert.Equal(t, "https://example.com/agent1", updatedPolicy.Rules[0].Agent)
	assert.Equal(t, "https://example.com/agent3", updatedPolicy.Rules[1].Agent)

	// Verify that the PUT body contained 2 rules (Write rule removed)
	assert.True(t, contains(string(putBody), "\"Read\""))
	assert.True(t, contains(string(putBody), "\"Control\""))
	assert.False(t, contains(string(putBody), "\"Write\""))
}

func TestPolicyClient_RemoveRule_OutOfBounds(t *testing.T) {
	// Create a test server with a simple handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GET request
		if r.Method == "GET" && r.URL.Path == "/resource.acp" {
			w.Header().Set("Content-Type", "application/ld+json")
			w.Header().Set("ETag", "\"initial-etag\"")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
  "@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
  "@type": "AccessControl",
  "rule": [
    {
      "@type": "AccessGrant",
      "access": "Read",
      "agent": "https://example.com/agent1"
    }
  ]
}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)
	client.SetPolicyType(types.ACP)

	ctx := context.Background()

	// Try to remove rule at index 10 (out of bounds)
	// This should fail with "rule index out of bounds" error from the client-side validation
	_, err := client.RemoveRule(ctx, "/resource.acp", 10, "\"initial-etag\"", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule index out of bounds")

	// Try to remove rule at index -1 (negative index)
	_, err = client.RemoveRule(ctx, "/resource.acp", -1, "\"initial-etag\"", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule index out of bounds")
}

func TestPolicyClient_SetPolicyType(t *testing.T) {
	client := createTestPolicyClient()

	// Test default policy type
	if client.policyType != types.ACP {
		t.Errorf("Expected default policy type to be ACP, got %v", client.policyType)
	}

	// Set policy type to WAC
	client.SetPolicyType(types.WAC)
	if client.policyType != types.WAC {
		t.Errorf("Expected policy type to be WAC, got %v", client.policyType)
	}

	// Set policy type to SAI
	client.SetPolicyType(types.SAI)
	if client.policyType != types.SAI {
		t.Errorf("Expected policy type to be SAI, got %v", client.policyType)
	}
}

func TestPolicyClient_NewPolicyClient_WithOptions(t *testing.T) {
	options := &PolicyClientOptions{
		BasePath:   "/api/v1",
		PolicyType: types.WAC,
		RequestOptions: &types.RequestOptions{
			Timeout: 10 * time.Second,
		},
	}

	client, err := NewPolicyClient("https://example.com", options)
	if err != nil {
		t.Fatalf("NewPolicyClient() error = %v", err)
	}

	if client.policyType != types.WAC {
		t.Errorf("Expected policy type to be WAC, got %v", client.policyType)
	}

	if client.basePath != "/api/v1/" {
		t.Errorf("Expected basePath to be '/api/v1/', got %v", client.basePath)
	}
}

// MockPolicyServer provides a mock HTTP server for testing PolicyClient
// This server simulates Solid Sidecar policy endpoints with proper responses
type MockPolicyServer struct {
	// mutex protects concurrent access to server state
	mutex sync.RWMutex

	// policies stores policy resources by URI
	policies map[string]*types.Policy

	// etags stores ETags for each policy URI
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

// NewMockPolicyServer creates a new mock policy server
func NewMockPolicyServer() *MockPolicyServer {
	return &MockPolicyServer{
		policies: make(map[string]*types.Policy),
		etags:    make(map[string]string),
	}
}

// Handler returns the HTTP handler for the mock server
func (s *MockPolicyServer) Handler() http.HandlerFunc {
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
		case "DELETE":
			s.handleDELETE(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// handleGET handles GET requests
func (s *MockPolicyServer) handleGET(w http.ResponseWriter, r *http.Request) {
	policyURI := r.URL.Path

	// Check if policy exists
	if policy, exists := s.policies[policyURI]; exists {
		// Serialize policy based on its type
		var contentType string
		var body []byte
		var err error

		switch policy.Type {
		case types.WAC:
			contentType = "text/turtle"
			body, err = serializeWACForTest(policy)
		case types.ACP:
			contentType = "application/ld+json"
			body, err = serializeACPForTest(policy)
		case types.SAI:
			contentType = "application/ld+json"
			body, err = serializeSAIForTest(policy)
		default:
			contentType = "application/ld+json"
			body, err = serializeACPForTest(policy)
		}

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Set headers
		w.Header().Set("Content-Type", contentType)
		if etag, ok := s.etags[policyURI]; ok {
			w.Header().Set("ETag", etag)
		}
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))

		w.WriteHeader(http.StatusOK)
		w.Write(body)
		return
	}

	// Policy not found
	w.WriteHeader(http.StatusNotFound)
}

// handleHEAD handles HEAD requests
func (s *MockPolicyServer) handleHEAD(w http.ResponseWriter, r *http.Request) {
	policyURI := r.URL.Path

	// Check if policy exists
	if _, exists := s.policies[policyURI]; exists {
		// Set headers
		w.Header().Set("Content-Type", "application/ld+json")
		if etag, ok := s.etags[policyURI]; ok {
			w.Header().Set("ETag", etag)
		}
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))

		w.WriteHeader(http.StatusOK)
		return
	}

	// Policy not found
	w.WriteHeader(http.StatusNotFound)
}

// handlePUT handles PUT requests
func (s *MockPolicyServer) handlePUT(w http.ResponseWriter, r *http.Request) {
	policyURI := r.URL.Path

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
		currentETag := s.etags[policyURI]
		if currentETag != ifMatch {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}

	// Check If-None-Match precondition
	if ifNoneMatch == "*" {
		if _, exists := s.policies[policyURI]; exists {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	} else if ifNoneMatch != "" {
		currentETag := s.etags[policyURI]
		if currentETag == ifNoneMatch {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}

	// Parse the policy from request body
	var policy types.Policy
	contentType := r.Header.Get("Content-Type")

	// Try to parse based on content type
	if strings.Contains(contentType, "json") {
		// Try to parse the client's serialization format first
		var temp struct {
			Type  types.PolicyResourceType `json:"@type"`
			Rules []types.PolicyRule       `json:"rule"`
			URI   string                   `json:"@id,omitempty"`
			ETag  string                   `json:"etag,omitempty"`
		}
		if err := json.Unmarshal(body, &temp); err == nil {
			policy.Type = temp.Type
			policy.Rules = temp.Rules
			policy.URI = temp.URI
			policy.ETag = temp.ETag
		} else {
			// Try standard JSON parsing
			if err := json.Unmarshal(body, &policy); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
	} else {
		// Parse Turtle format (simplified)
		// For testing, we'll just create a basic policy
		policy.Type = types.WAC
		policy.URI = policyURI
		bodyStr := string(body)
		if strings.Contains(bodyStr, "acp:") || strings.Contains(bodyStr, "AccessControl") {
			policy.Type = types.ACP
		}
	}

	// Check if policy already exists
	_, existed := s.policies[policyURI]

	// Generate new ETag
	newETag := fmt.Sprintf("\"etag-%d\"", len(s.policies)+1)

	// Store policy and ETag
	s.policies[policyURI] = &policy
	s.etags[policyURI] = newETag

	// Set response headers
	w.Header().Set("ETag", newETag)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.Header().Set("Location", policyURI)

	// Return appropriate status code
	if !existed {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

// handleDELETE handles DELETE requests
func (s *MockPolicyServer) handleDELETE(w http.ResponseWriter, r *http.Request) {
	policyURI := r.URL.Path

	// Check conditional headers
	ifMatch := r.Header.Get("If-Match")

	// Check If-Match precondition
	if ifMatch != "" && ifMatch != "*" {
		currentETag := s.etags[policyURI]
		if currentETag != ifMatch {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}

	// Check if policy exists
	if _, exists := s.policies[policyURI]; !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Delete the policy
	delete(s.policies, policyURI)
	delete(s.etags, policyURI)

	w.WriteHeader(http.StatusNoContent)
}

// SetConditionalWriteFail enables/disables conditional write failure simulation
func (s *MockPolicyServer) SetConditionalWriteFail(fail bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.conditionalWriteFail = fail
}

// SetServerError configures the server to return an error
func (s *MockPolicyServer) SetServerError(code int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.simulateServerError = true
	s.serverErrorCode = code
}

// ResetServerError clears server error simulation
func (s *MockPolicyServer) ResetServerError() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.simulateServerError = false
	s.serverErrorCode = 0
}

// AddPolicy adds a policy to the mock server
func (s *MockPolicyServer) AddPolicy(policyURI string, policy *types.Policy, etag string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.policies[policyURI] = policy
	if etag != "" {
		s.etags[policyURI] = etag
	} else {
		s.etags[policyURI] = fmt.Sprintf("\"etag-%s\"", policyURI)
	}
}

// GetRequestInfo returns information about the last request
func (s *MockPolicyServer) GetRequestInfo() (method, path string, body []byte, headers http.Header) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.lastMethod, s.lastPath, s.lastBody, s.lastHeaders
}

func TestPolicyClient_Get(t *testing.T) {
	// Create mock server
	mockServer := NewMockPolicyServer()

	// Add a policy
	existingPolicy := &types.Policy{
		Type: types.ACP,
		URI:  "/resource.acp",
		Rules: []types.PolicyRule{
			{AccessMode: types.Read, Agent: "https://example.com/agent1"},
			{AccessMode: types.Write, Agent: "https://example.com/agent2"},
		},
	}
	etag := "\"test-etag-123\""
	mockServer.AddPolicy("/resource.acp", existingPolicy, etag)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)
	client.SetPolicyType(types.ACP)

	ctx := context.Background()

	// Get the policy
	retrievedPolicy, err := client.Get(ctx, "/resource.acp", nil)
	require.NoError(t, err)

	// Verify the policy was retrieved correctly
	require.NotNil(t, retrievedPolicy)
	assert.Equal(t, types.ACP, retrievedPolicy.Type)
	assert.Len(t, retrievedPolicy.Rules, 2)
	assert.Equal(t, types.Read, retrievedPolicy.Rules[0].AccessMode)
	assert.Equal(t, types.Write, retrievedPolicy.Rules[1].AccessMode)
	assert.Equal(t, etag, retrievedPolicy.ETag)
	assert.Equal(t, "/resource.acp", retrievedPolicy.URI)
}

func TestPolicyClient_Get_NotFound(t *testing.T) {
	// Create mock server with no policies
	mockServer := NewMockPolicyServer()

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)

	ctx := context.Background()

	// Try to get a non-existent policy
	policy, err := client.Get(ctx, "/nonexistent.acp", nil)
	require.Error(t, err)
	assert.Equal(t, ErrPolicyNotFound, err)
	assert.Nil(t, policy)
}

func TestPolicyClient_Exists(t *testing.T) {
	// Create mock server
	mockServer := NewMockPolicyServer()

	// Add a policy
	existingPolicy := &types.Policy{
		Type: types.ACP,
		URI:  "/resource.acp",
		Rules: []types.PolicyRule{
			{AccessMode: types.Read, Agent: "https://example.com/agent1"},
		},
	}
	mockServer.AddPolicy("/resource.acp", existingPolicy, "")

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)

	ctx := context.Background()

	// Check if policy exists
	exists, err := client.Exists(ctx, "/resource.acp", nil)
	require.NoError(t, err)
	assert.True(t, exists)

	// Check if non-existent policy exists
	exists, err = client.Exists(ctx, "/nonexistent.acp", nil)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestPolicyClient_Put(t *testing.T) {
	// Create mock server
	mockServer := NewMockPolicyServer()

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)
	client.SetPolicyType(types.ACP)

	ctx := context.Background()

	// Create a new policy to put
	newPolicy := &types.Policy{
		Type: types.ACP,
		Rules: []types.PolicyRule{
			{AccessMode: types.Read, Agent: "https://example.com/agent1"},
			{AccessMode: types.Write, Agent: "https://example.com/agent1"},
		},
	}

	// Put the policy (create)
	result, err := client.Put(ctx, "/new-policy.acp", newPolicy, nil, nil)
	require.NoError(t, err)

	// Verify the result
	require.NotNil(t, result)
	assert.True(t, result.Created)
	assert.Equal(t, http.StatusCreated, result.StatusCode)
	assert.NotEmpty(t, result.ETag)
	assert.NotEmpty(t, result.LastModified)

	// Verify the policy was stored in the mock server
	method, path, _, _ := mockServer.GetRequestInfo()
	assert.Equal(t, "PUT", method)
	assert.Equal(t, "/new-policy.acp", path)
}

func TestPolicyClient_Put_WithPreconditions(t *testing.T) {
	// Create mock server
	mockServer := NewMockPolicyServer()

	// Add existing policy
	existingPolicy := &types.Policy{
		Type: types.ACP,
		URI:  "/resource.acp",
		Rules: []types.PolicyRule{
			{AccessMode: types.Read, Agent: "https://example.com/agent1"},
		},
	}
	existingETag := "\"existing-etag\""
	mockServer.AddPolicy("/resource.acp", existingPolicy, existingETag)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)
	client.SetPolicyType(types.ACP)

	ctx := context.Background()

	// Create updated policy
	updatedPolicy := &types.Policy{
		Type: types.ACP,
		Rules: []types.PolicyRule{
			{AccessMode: types.Read, Agent: "https://example.com/agent1"},
			{AccessMode: types.Write, Agent: "https://example.com/agent1"},
		},
	}

	// Put with correct If-Match precondition
	preconditions := &types.WritePreconditions{
		IfMatch: []string{existingETag},
	}

	result, err := client.Put(ctx, "/resource.acp", updatedPolicy, preconditions, nil)
	require.NoError(t, err)

	// Verify the result
	require.NotNil(t, result)
	assert.False(t, result.Created) // Updated, not created
	assert.Equal(t, http.StatusOK, result.StatusCode)
	assert.NotEmpty(t, result.ETag)
	assert.NotEqual(t, existingETag, result.ETag)

	// Test with wrong ETag (should fail)
	wrongPreconditions := &types.WritePreconditions{
		IfMatch: []string{"\"wrong-etag\""},
	}

	_, err = client.Put(ctx, "/resource.acp", updatedPolicy, wrongPreconditions, nil)
	require.Error(t, err)
	assert.Equal(t, "precondition failed", err.Error())
}

func TestPolicyClient_Delete(t *testing.T) {
	// Create mock server
	mockServer := NewMockPolicyServer()

	// Add existing policy
	existingPolicy := &types.Policy{
		Type: types.ACP,
		URI:  "/resource.acp",
		Rules: []types.PolicyRule{
			{AccessMode: types.Read, Agent: "https://example.com/agent1"},
		},
	}
	existingETag := "\"existing-etag\""
	mockServer.AddPolicy("/resource.acp", existingPolicy, existingETag)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)

	ctx := context.Background()

	// Delete with correct If-Match precondition
	preconditions := &types.WritePreconditions{
		IfMatch: []string{existingETag},
	}

	err := client.Delete(ctx, "/resource.acp", preconditions, nil)
	require.NoError(t, err)

	// Verify the policy was deleted (try to get it)
	_, err = client.Get(ctx, "/resource.acp", nil)
	require.Error(t, err)
	assert.Equal(t, ErrPolicyNotFound, err)
}

func TestPolicyClient_Delete_NotFound(t *testing.T) {
	// Create mock server
	mockServer := NewMockPolicyServer()

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)

	ctx := context.Background()

	// Try to delete non-existent policy
	err := client.Delete(ctx, "/nonexistent.acp", nil, nil)
	require.Error(t, err)
	assert.Equal(t, ErrPolicyNotFound, err)
}

func TestPolicyClient_GetETag(t *testing.T) {
	// Create mock server
	mockServer := NewMockPolicyServer()

	// Add a policy
	existingPolicy := &types.Policy{
		Type: types.ACP,
		URI:  "/resource.acp",
		Rules: []types.PolicyRule{
			{AccessMode: types.Read, Agent: "https://example.com/agent1"},
		},
	}
	etag := "\"test-etag-456\""
	mockServer.AddPolicy("/resource.acp", existingPolicy, etag)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)

	ctx := context.Background()

	// Get ETag
	retrievedETag, err := client.GetETag(ctx, "/resource.acp", nil)
	require.NoError(t, err)
	assert.Equal(t, etag, retrievedETag)

	// Get ETag for non-existent policy
	_, err = client.GetETag(ctx, "/nonexistent.acp", nil)
	require.Error(t, err)
	assert.Equal(t, ErrPolicyNotFound, err)
}

func TestPolicyClient_ServerError(t *testing.T) {
	// Create mock server
	mockServer := NewMockPolicyServer()

	// Configure server to return error
	mockServer.SetServerError(http.StatusInternalServerError)

	// Create test server
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	// Create client
	client := createTestPolicyClientWithServer(server)

	ctx := context.Background()

	// Try to get a policy (should fail with server error)
	_, err := client.Get(ctx, "/resource.acp", nil)
	require.Error(t, err)

	// Reset server error
	mockServer.ResetServerError()

	// Should work now
	mockServer.AddPolicy("/resource.acp", &types.Policy{Type: types.ACP}, "")
	policy, err := client.Get(ctx, "/resource.acp", nil)
	require.NoError(t, err)
	require.NotNil(t, policy)
}

// Helper functions for serialization

func serializeWACForTest(policy *types.Policy) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString("@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n")
	sb.WriteString("@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\n")

	for i, rule := range policy.Rules {
		authNode := fmt.Sprintf("auth-%d", i+1)
		sb.WriteString(fmt.Sprintf("<> acl:Authorization %s ;\n", authNode))
		sb.WriteString(fmt.Sprintf("    acl:mode acl:%s ;\n", rule.AccessMode))
		if rule.Agent != "" {
			sb.WriteString(fmt.Sprintf("    acl:agent <%s> ;\n", rule.Agent))
		} else if rule.AgentType != "" {
			sb.WriteString(fmt.Sprintf("    acl:agentClass <%s> ;\n", rule.AgentType))
		}
		if rule.Resource != "" {
			sb.WriteString(fmt.Sprintf("    acl:accessTo <%s> .\n", rule.Resource))
		}
		sb.WriteString("\n")
	}

	return []byte(sb.String()), nil
}

func serializeACPForTest(policy *types.Policy) ([]byte, error) {
	type acpRule struct {
		Type       string `json:"@type,omitempty"`
		Access     string `json:"access,omitempty"`
		Agent      string `json:"agent,omitempty"`
		AgentClass string `json:"agentClass,omitempty"`
		Resource   string `json:"resource,omitempty"`
	}

	var rules []acpRule
	for _, rule := range policy.Rules {
		access := string(rule.AccessMode)
		// Map to ACP access modes
		if rule.AccessMode == types.Read {
			access = "Read"
		} else if rule.AccessMode == types.Write {
			access = "Write"
		} else if rule.AccessMode == types.Append {
			access = "Append"
		} else if rule.AccessMode == types.Control {
			access = "Control"
		}

		ruleData := acpRule{
			Type:       "AccessGrant",
			Access:     access,
			Agent:      rule.Agent,
			AgentClass: string(rule.AgentType),
			Resource:   rule.Resource,
		}
		rules = append(rules, ruleData)
	}

	policyData := map[string]interface{}{
		"@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
		"@type":    "AccessControl",
		"rule":     rules,
	}

	return json.MarshalIndent(policyData, "", "  ")
}

func serializeSAIForTest(policy *types.Policy) ([]byte, error) {
	type saiRule struct {
		Permission string `json:"permission,omitempty"`
		Agent      string `json:"agent,omitempty"`
		Resource   string `json:"resource,omitempty"`
	}

	var rules []saiRule
	for _, rule := range policy.Rules {
		ruleData := saiRule{
			Permission: string(rule.AccessMode),
			Agent:      rule.Agent,
			Resource:   rule.Resource,
		}
		rules = append(rules, ruleData)
	}

	policyData := map[string]interface{}{
		"@context": "https://solidproject.org/ns/sai",
		"@type":    "Authorization",
		"rule":     rules,
	}

	return json.MarshalIndent(policyData, "", "  ")
}

// Helper functions

func createTestPolicyClient() *PolicyClient {
	// Create a client with a mock base URL
	// Note: This won't make actual HTTP calls in tests
	client, _ := NewPolicyClient("https://example.com", nil)
	return client
}

func createTestPolicyClientWithServer(server *httptest.Server) *PolicyClient {
	client, _ := NewPolicyClient(server.URL, nil)
	return client
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
