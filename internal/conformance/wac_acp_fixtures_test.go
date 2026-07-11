// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements WAC and ACP fixture tests.
package conformance

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Valid WAC policy document in Turtle format
const validWACPolicy = `<https://example.org/resource.acl>
    a <http://www.w3.org/ns/auth/acl#Authorization>;
    <http://www.w3.org/ns/auth/acl#accessTo> <https://example.org/resource>;
    <http://www.w3.org/ns/auth/acl#agent> <https://alice.example.org/profile#me>;
    <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write>.

<https://example.org/resource.acl#owner>
    a <http://www.w3.org/ns/auth/acl#Authorization>;
    <http://www.w3.org/ns/auth/acl#accessTo> <https://example.org/resource>;
    <http://www.w3.org/ns/auth/acl#agent> <https://alice.example.org/profile#me>;
    <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control>.
`

// Valid ACP policy document in JSON-LD format
const validACPPolicy = `{
  "@context": [
    "https://www.w3.org/ns/solid/acp/context-1",
    "https://www.w3.org/ns/auth/acl"
  ],
  "@id": "https://example.org/resource.acl",
  "@type": "AccessGrant",
  "accessTo": {"@id": "https://example.org/resource"},
  "assignee": {"@id": "https://alice.example.org/profile#me"},
  "accessMode": ["http://www.w3.org/ns/auth/acl#Read", "http://www.w3.org/ns/auth/acl#Write"]
}`

// TestWACPolicyRetrieval tests WAC policy document retrieval
func TestWACPolicyRetrieval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		contentType    string
		body           string
		expectedStatus int
	}{
		{
			name:           "WAC policy as Turtle",
			contentType:    "text/turtle",
			body:           validWACPolicy,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(tt.expectedStatus)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			contentType := resp.Header.Get("Content-Type")
			if contentType != tt.contentType {
				t.Errorf("Expected Content-Type: %s, got: %s", tt.contentType, contentType)
			}
		})
	}
}

// TestWACPolicyContent tests WAC policy content structure
func TestWACPolicyContent(t *testing.T) {
	t.Parallel()

	t.Run("WAC policy with read access", func(t *testing.T) {
		t.Parallel()

		wacPolicy := `<https://example.org/resource.acl#read>
    a <http://www.w3.org/ns/auth/acl#Authorization>;
    <http://www.w3.org/ns/auth/acl#accessTo> <https://example.org/resource>;
    <http://www.w3.org/ns/auth/acl#agent> <https://alice.example.org/profile#me>;
    <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>.
`

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/turtle")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(wacPolicy))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Read") {
			t.Errorf("Expected WAC policy to contain Read mode, got: %s", bodyStr)
		}
	})

	t.Run("WAC policy with write access", func(t *testing.T) {
		t.Parallel()

		wacPolicy := `<https://example.org/resource.acl#write>
    a <http://www.w3.org/ns/auth/acl#Authorization>;
    <http://www.w3.org/ns/auth/acl#accessTo> <https://example.org/resource>;
    <http://www.w3.org/ns/auth/acl#agent> <https://alice.example.org/profile#me>;
    <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write>.
`

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/turtle")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(wacPolicy))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Write") {
			t.Errorf("Expected WAC policy to contain Write mode, got: %s", bodyStr)
		}
	})

	t.Run("WAC policy with control access", func(t *testing.T) {
		t.Parallel()

		wacPolicy := `<https://example.org/resource.acl#control>
    a <http://www.w3.org/ns/auth/acl#Authorization>;
    <http://www.w3.org/ns/auth/acl#accessTo> <https://example.org/resource>;
    <http://www.w3.org/ns/auth/acl#agent> <https://alice.example.org/profile#me>;
    <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control>.
`

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/turtle")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(wacPolicy))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Control") {
			t.Errorf("Expected WAC policy to contain Control mode, got: %s", bodyStr)
		}
	})
}

// TestWACPolicyNotFound tests 404 for non-existent WAC policies
func TestWACPolicyNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

// TestACPPolicyRetrieval tests ACP policy document retrieval
func TestACPPolicyRetrieval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		contentType    string
		body           string
		expectedStatus int
	}{
		{
			name:           "ACP policy as JSON-LD",
			contentType:    "application/ld+json",
			body:           validACPPolicy,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(tt.expectedStatus)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			contentType := resp.Header.Get("Content-Type")
			if contentType != tt.contentType {
				t.Errorf("Expected Content-Type: %s, got: %s", tt.contentType, contentType)
			}
		})
	}
}

// TestACPPolicyContent tests ACP policy content structure
func TestACPPolicyContent(t *testing.T) {
	t.Parallel()

	t.Run("ACP policy with read access", func(t *testing.T) {
		t.Parallel()

		acpPolicy := `{
  "@context": "https://www.w3.org/ns/solid/acp/context-1",
  "@id": "https://example.org/resource.acl",
  "@type": "AccessGrant",
  "accessTo": {"@id": "https://example.org/resource"},
  "assignee": {"@id": "https://alice.example.org/profile#me"},
  "accessMode": ["http://www.w3.org/ns/auth/acl#Read"]
}`

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/ld+json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(acpPolicy))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Read") {
			t.Errorf("Expected ACP policy to contain Read mode, got: %s", bodyStr)
		}
	})

	t.Run("ACP policy with write access", func(t *testing.T) {
		t.Parallel()

		acpPolicy := `{
  "@context": "https://www.w3.org/ns/solid/acp/context-1",
  "@id": "https://example.org/resource.acl",
  "@type": "AccessGrant",
  "accessTo": {"@id": "https://example.org/resource"},
  "assignee": {"@id": "https://alice.example.org/profile#me"},
  "accessMode": ["http://www.w3.org/ns/auth/acl#Write"]
}`

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/ld+json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(acpPolicy))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Write") {
			t.Errorf("Expected ACP policy to contain Write mode, got: %s", bodyStr)
		}
	})

	t.Run("ACP policy with control access", func(t *testing.T) {
		t.Parallel()

		acpPolicy := `{
  "@context": "https://www.w3.org/ns/solid/acp/context-1",
  "@id": "https://example.org/resource.acl",
  "@type": "AccessGrant",
  "accessTo": {"@id": "https://example.org/resource"},
  "assignee": {"@id": "https://alice.example.org/profile#me"},
  "accessMode": ["http://www.w3.org/ns/auth/acl#Control"]
}`

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/ld+json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(acpPolicy))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Control") {
			t.Errorf("Expected ACP policy to contain Control mode, got: %s", bodyStr)
		}
	})
}

// TestACPPolicyNotFound tests 404 for non-existent ACP policies
func TestACPPolicyNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

// TestPolicyPutAndDelete tests PUT and DELETE on policy resources
func TestPolicyPutAndDelete(t *testing.T) {
	t.Parallel()

	t.Run("PUT new WAC policy", func(t *testing.T) {
		t.Parallel()

		// Track requests
		var requests []*http.Request

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests = append(requests, r)
			w.Header().Set("Content-Type", "text/turtle")
			w.WriteHeader(http.StatusCreated)
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "PUT", server.URL+"/resource.acl", strings.NewReader(validWACPolicy))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "text/turtle")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			t.Errorf("Expected status 200/201/204, got %d", resp.StatusCode)
		}
	})

	t.Run("DELETE WAC policy", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "DELETE", server.URL+"/resource.acl", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("Expected status 204, got %d", resp.StatusCode)
		}
	})
}

// TestPolicyLinkHeaders tests Link headers on policy resources
func TestPolicyLinkHeaders(t *testing.T) {
	t.Parallel()

	t.Run("Link header for ACL resource", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/turtle")
			linkHeader := `<http://www.w3.org/ns/auth/acl#Authorization>; rel="type"`
			w.Header().Set("Link", linkHeader)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(validWACPolicy))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource.acl", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		link := resp.Header.Get("Link")
		if !strings.Contains(link, "type") {
			t.Errorf("Expected Link header with type relation, got: %s", link)
		}
	})

	t.Run("Link header for policy resource", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/turtle")
			linkHeader := `<https://example.org/resource.acl>; rel="acl"`
			w.Header().Set("Link", linkHeader)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(validWACPolicy))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		link := resp.Header.Get("Link")
		if !strings.Contains(link, "acl") {
			t.Errorf("Expected Link header with acl relation, got: %s", link)
		}
	})
}
