package safety

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestContainerSlashHandler_RedirectsContainerWithoutSlash tests that container
// paths without trailing slashes are redirected to paths with trailing slashes.
func TestContainerSlashHandler_RedirectsContainerWithoutSlash(t *testing.T) {
	handler := ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name           string
		path           string
		expectedPath   string
		expectedStatus int
	}{
		{"root", "/", "/", http.StatusOK},
		{"container without slash", "/container", "/container/", http.StatusTemporaryRedirect},
		{"nested container", "/a/b/c", "/a/b/c/", http.StatusTemporaryRedirect},
		{"container with existing slash", "/container/", "/container/", http.StatusOK},
		{"deep nested", "/a/b/c/d/e", "/a/b/c/d/e/", http.StatusTemporaryRedirect},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handler returned status %d, want %d", rr.Code, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusTemporaryRedirect {
				location := rr.Header().Get("Location")
				if location != tt.expectedPath {
					t.Errorf("redirect location = %q, want %q", location, tt.expectedPath)
				}
			}
		})
	}
}

// TestContainerSlashHandler_FilePathsNotRedirected tests that file paths
// (with extensions) are not redirected.
func TestContainerSlashHandler_FilePathsNotRedirected(t *testing.T) {
	handler := ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	filePaths := []string{
		"/file.ttl",
		"/data.json",
		"/resource.jsonld",
		"/policy.acl",
		"/document.rdf",
		"/styles.css",
		"/script.js",
		"/image.png",
		"/page.html",
		"/data.xml",
		"/triples.n3",
		"/triples.nt",
		"/readme.md",
		"/readme.txt",
	}

	for _, path := range filePaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("handler redirected file path %q (status %d)", path, rr.Code)
			}

			location := rr.Header().Get("Location")
			if location != "" {
				t.Errorf("handler set Location header for file path %q: %q", path, location)
			}
		})
	}
}

// TestContainerSlashHandler_WriteMethodsNotRedirected tests that write methods
// are not redirected (they should fail or succeed as-is).
func TestContainerSlashHandler_WriteMethodsNotRedirected(t *testing.T) {
	handler := ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	writeMethods := []string{
		http.MethodPut,
		http.MethodPost,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range writeMethods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/container", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned status %d for %s /container, want %d", rr.Code, method, http.StatusOK)
			}

			location := rr.Header().Get("Location")
			if location != "" {
				t.Errorf("handler set Location header for %s /container: %q", method, location)
			}
		})
	}
}

// TestContainerSlashHandler_WithQueryParameters tests that query parameters
// are preserved during redirects.
func TestContainerSlashHandler_WithQueryParameters(t *testing.T) {
	handler := ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name     string
		path     string
		query    string
		expected string
	}{
		{"simple query", "/container", "param=value", "/container/?param=value"},
		{"multiple params", "/container", "a=1&b=2", "/container/?a=1&b=2"},
		{"encoded query", "/container", "q=hello%20world", "/container/?q=hello%20world"},
		{"empty query", "/container", "", "/container/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fullPath := tt.path
			if tt.query != "" {
				fullPath = tt.path + "?" + tt.query
			}
			req := httptest.NewRequest(http.MethodGet, fullPath, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusTemporaryRedirect {
				t.Errorf("handler returned status %d, want %d", rr.Code, http.StatusTemporaryRedirect)
			}

			location := rr.Header().Get("Location")
			if location != tt.expected {
				t.Errorf("redirect location = %q, want %q", location, tt.expected)
			}
		})
	}
}

// TestContainerSlashHandler_HeadMethod tests that HEAD requests are also redirected.
func TestContainerSlashHandler_HeadMethod(t *testing.T) {
	handler := ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodHead, "/container", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("handler returned status %d for HEAD, want %d", rr.Code, http.StatusTemporaryRedirect)
	}

	location := rr.Header().Get("Location")
	if location != "/container/" {
		t.Errorf("redirect location = %q, want %q", location, "/container/")
	}
}

// TestContainerSlashHandler_CustomChecker tests the custom container path checker.
func TestContainerSlashHandler_CustomChecker(t *testing.T) {
	// Custom checker: only "/data" and "/profile" are containers
	customChecker := func(path string) bool {
		return path == "/data" || path == "/profile"
	}

	handler := ContainerSlashMiddlewareWithChecker(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), customChecker)

	tests := []struct {
		name           string
		path           string
		shouldRedirect bool
	}{
		{"data container", "/data", true},
		{"profile container", "/profile", true},
		{"other path", "/other", false},
		{"file.ttl", "/file.ttl", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if tt.shouldRedirect {
				if rr.Code != http.StatusTemporaryRedirect {
					t.Errorf("handler did not redirect for %q (status %d)", tt.path, rr.Code)
				}
			} else {
				if rr.Code != http.StatusOK {
					t.Errorf("handler redirected non-container path %q (status %d)", tt.path, rr.Code)
				}
			}
		})
	}
}

// TestIsContainerPath tests the IsContainerPath helper function.
func TestIsContainerPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/", true},
		{"/", true},
		{"/container/", true},
		{"/a/b/c/", true},
		{"/container", true},
		{"/a/b/c", true},
		{"/file.ttl", false},
		{"/data.json", false},
		{"/policy.acl", false},
		{"/document.html", false},
		{"/image.png", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := IsContainerPath(tt.path)
			if got != tt.expected {
				t.Errorf("IsContainerPath(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

// TestNormalizeContainerPath tests the NormalizeContainerPath helper function.
func TestNormalizeContainerPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/", "/"},
		{"/container", "/container/"},
		{"/container/", "/container/"},
		{"/a/b/c", "/a/b/c/"},
		{"/file.ttl", "/file.ttl"},
		{"/data.json", "/data.json"},
		{"/policy.acl", "/policy.acl"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := NormalizeContainerPath(tt.path)
			if got != tt.expected {
				t.Errorf("NormalizeContainerPath(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

// TestCheckContainerSlashRedirect tests the CheckContainerSlashRedirect function.
func TestCheckContainerSlashRedirect(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		query   string
		wantURL string
	}{
		{"GET container without slash", http.MethodGet, "/container", "", "/container/"},
		{"GET container with slash", http.MethodGet, "/container/", "", ""},
		{"GET root", http.MethodGet, "/", "", ""},
		{"GET file", http.MethodGet, "/file.ttl", "", ""},
		{"POST container", http.MethodPost, "/container", "", ""},
		{"PUT container", http.MethodPut, "/container", "", ""},
		{"DELETE container", http.MethodDelete, "/container", "", ""},
		{"HEAD container without slash", http.MethodHead, "/container", "", "/container/"},
		{"GET with query", http.MethodGet, "/container", "param=value", "/container/?param=value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fullPath := tt.path
			if tt.query != "" {
				fullPath = tt.path + "?" + tt.query
			}
			req := httptest.NewRequest(tt.method, fullPath, nil)
			gotURL := CheckContainerSlashRedirect(req)

			if gotURL != tt.wantURL {
				t.Errorf("CheckContainerSlashRedirect(%s %q) = %q, want %q", tt.method, tt.path, gotURL, tt.wantURL)
			}
		})
	}
}

// TestContainerSlashHandler_MultipleContainers tests redirects for multiple
// container paths in a single request flow.
func TestContainerSlashHandler_MultipleContainers(t *testing.T) {
	nextCalled := false
	nextPath := ""

	handler := ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		nextPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))

	// Test first redirect
	req := httptest.NewRequest(http.MethodGet, "/container1", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("first request should redirect, got status %d", rr.Code)
	}

	// Follow the redirect
	nextCalled = false
	nextPath = ""
	req = httptest.NewRequest(http.MethodGet, "/container1/", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("second request should call next handler")
	}
	if nextPath != "/container1/" {
		t.Errorf("next handler received path %q, want %q", nextPath, "/container1/")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("second request should succeed, got status %d", rr.Code)
	}
}

// TestContainerSlashHandler_CaseSensitive tests that path matching is case-sensitive.
func TestContainerSlashHandler_CaseSensitive(t *testing.T) {
	handler := ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test lowercase
	req := httptest.NewRequest(http.MethodGet, "/container", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("lowercase /container should redirect")
	}

	// Test uppercase (different path, should also redirect)
	handler = ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req = httptest.NewRequest(http.MethodGet, "/Container", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// /Container (uppercase) is also a container without slash, should redirect
	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("uppercase /Container should also redirect")
	}

	location := rr.Header().Get("Location")
	if location != "/Container/" {
		t.Errorf("redirect location = %q, want %q", location, "/Container/")
	}
}

// TestContainerSlashHandler_AdjversarialPaths tests adversarial inputs
// that might cause issues with the container slash handler.
func TestContainerSlashHandler_AdversarialPaths(t *testing.T) {
	handler := ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// These should all be handled safely without panicking
	adversarialPaths := []string{
		"/",
		"//",
		"///",
		"/container//",
		"/.hidden",
		"/.hidden/",
		"/_private",
		"/path%20with%20spaces",
		"/path/../other",
		"/path/./other",
	}

	for _, path := range adversarialPaths {
		t.Run(path, func(t *testing.T) {
			// Just ensure it doesn't panic
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			_ = rr // Use rr to avoid unused variable
			handler.ServeHTTP(rr, req)
			// If we get here without panicking, the test passes
		})
	}
}

// TestContainerSlashHandler_IntegrationWithStorageRoot tests that container
// slash handler works correctly with storage root validation.
func TestContainerSlashHandler_IntegrationWithStorageRoot(t *testing.T) {
	// Create a storage root validator that only allows /data paths
	storageValidator := NewStorageRootValidator([]string{"/data"})

	// Create a container slash handler
	containerHandler := ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Chain them together: first storage validation, then container slash
	handler := storageValidator.Middleware(containerHandler)

	// Test allowed path without trailing slash - should redirect
	req := httptest.NewRequest(http.MethodGet, "/data/container", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should redirect because container doesn't have trailing slash
	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("handler returned status %d, want %d", rr.Code, http.StatusTemporaryRedirect)
	}

	location := rr.Header().Get("Location")
	if location != "/data/container/" {
		t.Errorf("redirect location = %q, want %q", location, "/data/container/")
	}

	// Test disallowed path - should be rejected by storage validator
	req = httptest.NewRequest(http.MethodGet, "/other/container", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("handler returned status %d for disallowed path, want %d", rr.Code, http.StatusForbidden)
	}
}
