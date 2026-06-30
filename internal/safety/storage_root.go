// Package safety provides middleware for request validation and security.
package safety

import (
	"fmt"
	"net/http"
	"path"
	"strings"
)

// StorageRootValidator validates that requests are within allowed storage root paths.
// This is a security measure to prevent path traversal attacks and ensure requests
// stay within the intended storage boundaries.
type StorageRootValidator struct {
	// allowedRoots is a list of allowed storage root paths.
	// Each request path must start with one of these roots.
	allowedRoots []string
	// requireRoot checks if the path must exactly match or be within a root.
	// If true, paths not starting with any allowed root are rejected.
	// If false, all paths are allowed (permissive mode).
	requireRoot bool
}

// NewStorageRootValidator creates a new storage root validator.
// If allowedRoots is empty, it returns a validator that allows all paths (permissive mode).
func NewStorageRootValidator(allowedRoots []string) *StorageRootValidator {
	// Normalize roots: ensure they start with / and don't end with / (except for "/")
	normalized := make([]string, 0, len(allowedRoots))
	for _, root := range allowedRoots {
		normalized = append(normalized, normalizeStorageRoot(root))
	}
	return &StorageRootValidator{
		allowedRoots: normalized,
		requireRoot:  len(normalized) > 0,
	}
}

// normalizeStorageRoot normalizes a storage root path.
func normalizeStorageRoot(root string) string {
	if root == "" || root == "/" {
		return "/"
	}
	// Clean the path first to normalize multiple slashes
	root = path.Clean(root)
	root = strings.TrimPrefix(root, "/")
	root = strings.TrimSuffix(root, "/")
	return "/" + root
}

// Validate checks if the request path is within an allowed storage root.
// Returns nil if the path is allowed, or an error if it's outside all allowed roots.
func (v *StorageRootValidator) Validate(r *http.Request) error {
	if !v.requireRoot {
		return nil
	}

	requestPath := r.URL.EscapedPath()
	if requestPath == "" {
		return fmt.Errorf("missing request path")
	}

	for _, root := range v.allowedRoots {
		if isWithinRoot(requestPath, root) {
			return nil
		}
	}

	return fmt.Errorf("request path %q is not within any allowed storage root", requestPath)
}

// isWithinRoot checks if a request path is within or equal to a storage root.
func isWithinRoot(requestPath, root string) bool {
	// Normalize both paths for comparison
	requestPath = path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	root = path.Clean(root)

	// Exact match
	if requestPath == root {
		return true
	}

	// Special case: if root is "/", all paths are within it
	if root == "/" {
		return true
	}

	// Check if request path starts with root followed by a slash or is exactly root
	if strings.HasPrefix(requestPath, root+"/") {
		return true
	}

	return false
}

// Middleware returns an HTTP middleware that validates storage root paths.
func (v *StorageRootValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := v.Validate(r); err != nil {
			http.Error(w, "storage root validation failed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewStorageRootMiddleware is a convenience function to create storage root validation middleware.
func NewStorageRootMiddleware(allowedRoots []string, next http.Handler) http.Handler {
	return NewStorageRootValidator(allowedRoots).Middleware(next)
}

// ParseStorageRootsFromConfig parses storage roots from a configuration.
// This is a helper for integration with the config package.
func ParseStorageRootsFromConfig(configRoots []string) []string {
	// For now, just return the roots as-is.
	// In the future, this could fetch roots from a configuration file or service.
	return configRoots
}

// DefaultStorageRoots returns the default storage roots for Solid.
// These are common well-known paths used in Solid servers.
func DefaultStorageRoots() []string {
	return []string{
		"/", // Allow all paths by default
	}
}
