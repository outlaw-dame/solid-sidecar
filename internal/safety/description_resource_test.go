package safety

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestParseDescriptionResourceLinks tests parsing Link headers for describedby relations.
func TestParseDescriptionResourceLinks(t *testing.T) {
	tests := []struct {
		name        string
		linkHeaders []string
		resourceURI string
		wantURIs    []string
		wantErr     bool
	}{
		{
			name:        "single describedby link",
			linkHeaders: []string{`<./.meta>; rel="describedby"`},
			resourceURI: "https://pod.example/container",
			wantURIs:    []string{"https://pod.example/container/.meta"},
			wantErr:     false,
		},
		{
			name:        "describedby with absolute URI",
			linkHeaders: []string{`<https://pod.example/meta>; rel="describedby"`},
			resourceURI: "https://pod.example/container",
			wantURIs:    []string{"https://pod.example/meta"},
			wantErr:     false,
		},
		{
			name: "multiple describedby links",
			linkHeaders: []string{
				`<./.meta>; rel="describedby"`,
				`<https://pod.example/meta>; rel="describedby"`,
			},
			resourceURI: "https://pod.example/container",
			wantURIs:    []string{"https://pod.example/container/.meta", "https://pod.example/meta"},
			wantErr:     false,
		},
		{
			name:        "no describedby link",
			linkHeaders: []string{`</style.css>; rel="stylesheet"`},
			resourceURI: "https://pod.example/container",
			wantURIs:    []string{},
			wantErr:     false,
		},
		{
			name:        "empty link header",
			linkHeaders: []string{},
			resourceURI: "https://pod.example/container",
			wantURIs:    []string{},
			wantErr:     false,
		},
		{
			name:        "malformed link header",
			linkHeaders: []string{"not-a-link"},
			resourceURI: "https://pod.example/container",
			wantURIs:    []string{},
			wantErr:     false,
		},
		{
			name:        "relative path",
			linkHeaders: []string{`<../.meta>; rel="describedby"`},
			resourceURI: "https://pod.example/container/sub",
			wantURIs:    []string{"https://pod.example/container/.meta"},
			wantErr:     false,
		},
		{
			name:        "describedby with type",
			linkHeaders: []string{`<./.meta>; rel="describedby"; type="text/turtle"`},
			resourceURI: "https://pod.example/container",
			wantURIs:    []string{"https://pod.example/container/.meta"},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDescriptionResourceLinks(tt.linkHeaders, tt.resourceURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDescriptionResourceLinks() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != len(tt.wantURIs) {
				t.Errorf("ParseDescriptionResourceLinks() returned %d URIs, want %d", len(got), len(tt.wantURIs))
				return
			}
			for i, uri := range got {
				if uri != tt.wantURIs[i] {
					t.Errorf("ParseDescriptionResourceLinks()[%d] = %q, want %q", i, uri, tt.wantURIs[i])
				}
			}
		})
	}
}

// TestExtractDescriptionResourceURI tests extracting a single description resource URI.
func TestExtractDescriptionResourceURI(t *testing.T) {
	tests := []struct {
		name        string
		linkHeader  string
		resourceURI string
		wantURI     string
	}{
		{
			name:        "single describedby",
			linkHeader:  `<./.meta>; rel="describedby"`,
			resourceURI: "https://pod.example/container",
			wantURI:     "https://pod.example/container/.meta",
		},
		{
			name:        "no describedby",
			linkHeader:  `</style.css>; rel="stylesheet"`,
			resourceURI: "https://pod.example/container",
			wantURI:     "",
		},
		{
			name:        "empty link header",
			linkHeader:  "",
			resourceURI: "https://pod.example/container",
			wantURI:     "",
		},
		{
			name:        "multiple links - return first",
			linkHeader:  `<./first.meta>; rel="describedby", <./second.meta>; rel="describedby"`,
			resourceURI: "https://pod.example/container",
			wantURI:     "https://pod.example/container/first.meta",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractDescriptionResourceURI(tt.linkHeader, tt.resourceURI)
			if got != tt.wantURI {
				t.Errorf("ExtractDescriptionResourceURI() = %q, want %q", got, tt.wantURI)
			}
		})
	}
}

// TestHasDescriptionResourceLink tests checking for describedby in Link headers.
func TestHasDescriptionResourceLink(t *testing.T) {
	tests := []struct {
		name       string
		linkHeader string
		want       bool
	}{
		{
			name:       "has describedby",
			linkHeader: `</container/.meta>; rel="describedby"`,
			want:       true,
		},
		{
			name:       "has describedby single quotes",
			linkHeader: `<https://pod.example/meta>; rel='describedby'`,
			want:       true,
		},
		{
			name:       "has describedby no quotes",
			linkHeader: `<https://pod.example/meta>; rel=describedby`,
			want:       true,
		},
		{
			name:       "no describedby",
			linkHeader: `</style.css>; rel="stylesheet"`,
			want:       false,
		},
		{
			name:       "empty link header",
			linkHeader: "",
			want:       false,
		},
		{
			name:       "multiple relations",
			linkHeader: `</meta>; rel="describedby acl"`,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasDescriptionResourceLink(tt.linkHeader)
			if got != tt.want {
				t.Errorf("HasDescriptionResourceLink() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetContainerDescriptionPath tests getting the description path for a container.
func TestGetContainerDescriptionPath(t *testing.T) {
	tests := []struct {
		name          string
		containerPath string
		want          string
	}{
		{
			name:          "root container",
			containerPath: "/",
			want:          "/.meta",
		},
		{
			name:          "container without slash",
			containerPath: "/container",
			want:          "/container/.meta",
		},
		{
			name:          "container with slash",
			containerPath: "/container/",
			want:          "/container/.meta",
		},
		{
			name:          "nested container without slash",
			containerPath: "/a/b/c",
			want:          "/a/b/c/.meta",
		},
		{
			name:          "nested container with slash",
			containerPath: "/a/b/c/",
			want:          "/a/b/c/.meta",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetContainerDescriptionPath(tt.containerPath)
			if got != tt.want {
				t.Errorf("GetContainerDescriptionPath(%q) = %q, want %q", tt.containerPath, got, tt.want)
			}
		})
	}
}

// TestGetWellKnownSolidPath tests getting the well-known Solid path.
func TestGetWellKnownSolidPath(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		want     string
	}{
		{
			name:     "root",
			basePath: "/",
			want:     "/.well-known/solid",
		},
		{
			name:     "base without slash",
			basePath: "/container",
			want:     "/container/.well-known/solid",
		},
		{
			name:     "base with slash",
			basePath: "/container/",
			want:     "/container/.well-known/solid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetWellKnownSolidPath(tt.basePath)
			if got != tt.want {
				t.Errorf("GetWellKnownSolidPath(%q) = %q, want %q", tt.basePath, got, tt.want)
			}
		})
	}
}

// TestDescriptionResourceMiddleware_PassThrough tests that the middleware
// currently passes through without processing.
func TestDescriptionResourceMiddleware_PassThrough(t *testing.T) {
	nextCalled := false

	handler := DescriptionResourceMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/container", nil)
	req.Header.Set("Link", `</container/.meta>; rel="describedby"`)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("next handler should be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("handler returned status %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestDescriptionResourceHandlerWithOptions tests custom options.
func TestDescriptionResourceHandlerWithOptions(t *testing.T) {
	nextCalled := false

	handler := DescriptionResourceMiddlewareWithOptions(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		}),
		DescriptionResourceOptions{
			AllowedRelations:         []string{"describedby", "metadata"},
			DescriptionResourcePaths: []string{".meta", ".well-known/solid"},
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/container", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("next handler should be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("handler returned status %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestParseDescriptionResourceLinks_Adversarial tests adversarial inputs.
func TestParseDescriptionResourceLinks_Adversarial(t *testing.T) {
	adversarialTests := []struct {
		name        string
		linkHeader  string
		resourceURI string
	}{
		{
			name:        "null byte in target",
			linkHeader:  `</path\x00/meta>; rel="describedby"`,
			resourceURI: "https://pod.example/container",
		},
		{
			name: "newline in target",
			linkHeader: `</path
/meta>; rel="describedby"`,
			resourceURI: "https://pod.example/container",
		},
		{
			name:        "carriage return in target",
			linkHeader:  `</path\r/meta>; rel="describedby"`,
			resourceURI: "https://pod.example/container",
		},
		{
			name:        "fragment in target",
			linkHeader:  `</path#fragment>; rel="describedby"`,
			resourceURI: "https://pod.example/container",
		},
		{
			name:        "empty angle brackets",
			linkHeader:  `<>; rel="describedby"`,
			resourceURI: "https://pod.example/container",
		},
		{
			name:        "only angle brackets",
			linkHeader:  `<>`,
			resourceURI: "https://pod.example/container",
		},
		{
			name:        "malformed URI",
			linkHeader:  `<://invalid>; rel="describedby"`,
			resourceURI: "https://pod.example/container",
		},
		{
			name:        "very long URI",
			linkHeader:  `<` + strings.Repeat("a", 10000) + `>; rel="describedby"`,
			resourceURI: "https://pod.example/container",
		},
	}

	for _, tt := range adversarialTests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			_, err := ParseDescriptionResourceLinks([]string{tt.linkHeader}, tt.resourceURI)
			// We don't care about the error, just that it doesn't panic
			_ = err
		})
	}
}

// TestParseDescriptionResourceLinks_MultipleHeaders tests parsing multiple Link headers.
func TestParseDescriptionResourceLinks_MultipleHeaders(t *testing.T) {
	linkHeaders := []string{
		`<./.meta>; rel="describedby"`, // Relative to the resource URI
		`<https://pod.example/global-meta>; rel="describedby"`,
	}

	got, err := ParseDescriptionResourceLinks(linkHeaders, "https://pod.example/container")
	if err != nil {
		t.Fatalf("ParseDescriptionResourceLinks() error = %v", err)
	}

	if len(got) != 2 {
		t.Errorf("ParseDescriptionResourceLinks() returned %d URIs, want 2", len(got))
	}

	// Check that both URIs are resolved correctly
	expected := []string{
		"https://pod.example/container/.meta",
		"https://pod.example/global-meta",
	}
	for i, uri := range got {
		if uri != expected[i] {
			t.Errorf("ParseDescriptionResourceLinks()[%d] = %q, want %q", i, uri, expected[i])
		}
	}
}

// TestParseDescriptionResourceLinks_RealWorld tests with real-world Link header examples.
func TestParseDescriptionResourceLinks_RealWorld(t *testing.T) {
	// Example from a Solid container
	linkHeader := `<https://pod.example/alice/.meta>; rel="describedby"; type="text/turtle", <https://pod.example/alice/.acl>; rel="acl"; type="text/turtle"`

	got, err := ParseDescriptionResourceLinks([]string{linkHeader}, "https://pod.example/alice")
	if err != nil {
		t.Fatalf("ParseDescriptionResourceLinks() error = %v", err)
	}

	// Should only return the describedby link, not the acl link
	if len(got) != 1 {
		t.Errorf("ParseDescriptionResourceLinks() returned %d URIs, want 1", len(got))
	}

	if got[0] != "https://pod.example/alice/.meta" {
		t.Errorf("ParseDescriptionResourceLinks()[0] = %q, want %q", got[0], "https://pod.example/alice/.meta")
	}
}

// TestDescriptionResourceHandler_Integration tests integration with other handlers.
func TestDescriptionResourceHandler_Integration(t *testing.T) {
	// Create a chain of handlers
	storageValidator := NewStorageRootValidator([]string{"/data"})
	containerSlashHandler := ContainerSlashMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Description resource handler should work with other handlers
	descriptionHandler := DescriptionResourceMiddleware(storageValidator.Middleware(containerSlashHandler))

	// Test that it passes through correctly
	req := httptest.NewRequest(http.MethodGet, "/data/container/", nil)
	rr := httptest.NewRecorder()
	descriptionHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("integration handler returned status %d, want %d", rr.Code, http.StatusOK)
	}
}
