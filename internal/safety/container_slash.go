// Package safety provides middleware for request validation and security.
package safety

import (
	"net/http"
	"strings"
)

// ContainerSlashHandler handles container (directory) slash redirects.
// In Solid, containers are typically accessed with a trailing slash.
// This middleware checks if a request path refers to a container without a trailing slash
// and redirects to the same URL with a trailing slash appended.
//
// This is important for Solid containers because:
// 1. It ensures consistent container URL representation
// 2. It prevents ambiguous paths (e.g., /container vs /container/)
// 3. It matches CSS behavior for container resources
//
// Note: This middleware should only redirect GET and HEAD requests.
// Write requests to containers should already have the trailing slash.
type ContainerSlashHandler struct {
	// next is the handler to call after slash normalization
	next http.Handler
	// containerPathChecker is a function that determines if a path refers to a container
	// If nil, all paths without trailing slashes are assumed to be containers
	containerPathChecker func(path string) bool
}

// NewContainerSlashHandler creates a new container slash redirect handler.
// It redirects requests to paths without trailing slashes to the same path with a trailing slash,
// but only for GET and HEAD requests ( Solid containers are typically accessed via GET).
func NewContainerSlashHandler(next http.Handler) *ContainerSlashHandler {
	return &ContainerSlashHandler{
		next:                 next,
		containerPathChecker: nil, // Default: all paths without trailing slash are containers
	}
}

// NewContainerSlashHandlerWithChecker creates a container slash handler with a custom
// container path checker function.
func NewContainerSlashHandlerWithChecker(next http.Handler, checker func(path string) bool) *ContainerSlashHandler {
	return &ContainerSlashHandler{
		next:                 next,
		containerPathChecker: checker,
	}
}

// ServeHTTP implements http.Handler.
func (h *ContainerSlashHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only redirect GET and HEAD requests
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.next.ServeHTTP(w, r)
		return
	}

	// Get the request path
	path := r.URL.EscapedPath()

	// Skip if path already has trailing slash or is root
	if path == "/" || strings.HasSuffix(path, "/") {
		h.next.ServeHTTP(w, r)
		return
	}

	// Check if this path refers to a container
	if h.containerPathChecker != nil && !h.containerPathChecker(path) {
		h.next.ServeHTTP(w, r)
		return
	}

	// Default behavior: assume all non-file paths are containers
	// In practice, paths with extensions are likely files, not containers
	if isLikelyFilePath(path) {
		h.next.ServeHTTP(w, r)
		return
	}

	// Redirect to path with trailing slash
	newURL := *r.URL
	newURL.Path = path + "/"
	newURL.RawPath = r.URL.RawPath + "/"

	// Preserve query parameters
	if r.URL.RawQuery != "" {
		newURL.RawQuery = r.URL.RawQuery
	}

	// Use 307 Temporary Redirect to preserve method (though we only do GET/HEAD)
	// 307 is appropriate because it tells clients to use the same method on the new URL
	http.Redirect(w, r, newURL.String(), http.StatusTemporaryRedirect)
}

// isLikelyFilePath returns true if the path looks like a file (has an extension).
// This is a heuristic to avoid redirecting file URLs.
func isLikelyFilePath(path string) bool {
	// Common RDF and Solid file extensions
	fileExtensions := []string{
		".ttl",    // Turtle
		".json",   // JSON
		".jsonld", // JSON-LD
		".rdf",    // RDF/XML
		".xml",    // XML
		".n3",     // Notation3
		".nt",     // N-Triples
		".acl",    // WAC ACL
		".meta",   // Metadata
		".html",   // HTML
		".css",    // CSS
		".js",     // JavaScript
		".png",    // PNG
		".jpg",    // JPG
		".jpeg",   // JPEG
		".gif",    // GIF
		".svg",    // SVG
		".webp",   // WebP
		".txt",    // Text
		".md",     // Markdown
	}

	for _, ext := range fileExtensions {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}

	return false
}

// ContainerSlashMiddleware is a convenience function to create container slash redirect middleware.
func ContainerSlashMiddleware(next http.Handler) http.Handler {
	return NewContainerSlashHandler(next)
}

// ContainerSlashMiddlewareWithChecker creates middleware with a custom container checker.
func ContainerSlashMiddlewareWithChecker(next http.Handler, checker func(path string) bool) http.Handler {
	return NewContainerSlashHandlerWithChecker(next, checker)
}

// IsContainerPath is a helper function that checks if a path is likely a container.
// This uses the same heuristic as isLikelyFilePath but inverted.
func IsContainerPath(path string) bool {
	// Root is always a container
	if path == "/" {
		return true
	}

	// Paths with trailing slash are containers
	if strings.HasSuffix(path, "/") {
		return true
	}

	// Paths with file extensions are not containers
	return !isLikelyFilePath(path)
}

// NormalizeContainerPath returns the normalized container path.
// If the path is a container without trailing slash, it adds one.
// Otherwise, it returns the path unchanged.
func NormalizeContainerPath(path string) string {
	if path == "/" {
		return "/"
	}

	// If already has trailing slash, return as-is
	if strings.HasSuffix(path, "/") {
		return path
	}

	// If it's a file path, don't add trailing slash
	if isLikelyFilePath(path) {
		return path
	}

	// Add trailing slash for container paths
	return path + "/"
}

// CheckContainerSlashRedirect checks if a redirect should be performed for container slash.
// Returns the redirect URL if a redirect is needed, or empty string if not.
func CheckContainerSlashRedirect(r *http.Request) string {
	// Only redirect GET and HEAD requests
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return ""
	}

	path := r.URL.EscapedPath()

	// Skip if path already has trailing slash or is root
	if path == "/" || strings.HasSuffix(path, "/") {
		return ""
	}

	// Skip if it's likely a file
	if isLikelyFilePath(path) {
		return ""
	}

	// Build redirect URL
	newURL := *r.URL
	newURL.Path = path + "/"
	newURL.RawPath = r.URL.RawPath + "/"

	// Preserve query parameters
	if r.URL.RawQuery != "" {
		newURL.RawQuery = r.URL.RawQuery
	}

	return newURL.String()
}
