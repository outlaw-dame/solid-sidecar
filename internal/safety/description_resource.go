// Package safety provides middleware for request validation and security.
package safety

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
)

// DescriptionResourceHandler handles Link headers with rel="describedby" for Solid resources.
// In Solid, containers and resources can have associated description resources
// (metadata) linked via the describedby relation in the Link header.
//
// This middleware extracts and validates description resource links from responses
// and can optionally fetch and cache them for authorization decisions.
//
// For Phase 2, this handler focuses on:
// 1. Parsing Link headers for describedby relations
// 2. Validating description resource URIs
// 3. Normalizing description resource paths
//
// Note: The actual fetching and caching of description resources is part of
// Phase 3 (Live policy discovery).
type DescriptionResourceHandler struct {
	// next is the handler to call
	next http.Handler
	// allowedRelations is the list of allowed Link relations to process
	// Defaults to ["describedby"] if empty
	allowedRelations []string
	// descriptionResourcePath is the path segment for description resources
	// Common Solid patterns: ".meta", ".well-known/solid"
	// Defaults to [".meta"] if empty
	descriptionResourcePaths []string
}

// NewDescriptionResourceHandler creates a new description resource handler.
func NewDescriptionResourceHandler(next http.Handler) *DescriptionResourceHandler {
	return &DescriptionResourceHandler{
		next:                     next,
		allowedRelations:         []string{"describedby"},
		descriptionResourcePaths: []string{".meta"},
	}
}

// NewDescriptionResourceHandlerWithOptions creates a description resource handler
// with custom options.
func NewDescriptionResourceHandlerWithOptions(next http.Handler, options DescriptionResourceOptions) *DescriptionResourceHandler {
	return &DescriptionResourceHandler{
		next:                     next,
		allowedRelations:         options.AllowedRelations,
		descriptionResourcePaths: options.DescriptionResourcePaths,
	}
}

// DescriptionResourceOptions configures the description resource handler.
type DescriptionResourceOptions struct {
	AllowedRelations         []string
	DescriptionResourcePaths []string
}

// ServeHTTP implements http.Handler.
// This middleware currently passes through to the next handler but will be extended
// in Phase 3 to actually process description resource links.
func (h *DescriptionResourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// For Phase 2, we just pass through
	// The actual description resource processing will be added in Phase 3
	h.next.ServeHTTP(w, r)
}

// ParseDescriptionResourceLinks parses Link headers and extracts description resource URIs.
// This function is exported for use in tests and other packages.
func ParseDescriptionResourceLinks(linkHeaders []string, resourceURI string) ([]string, error) {
	var descriptionResources []string

	allowed := make(map[string]struct{})
	for _, rel := range []string{"describedby"} {
		allowed[strings.ToLower(rel)] = struct{}{}
	}

	for _, header := range linkHeaders {
		parts := splitLinkHeader(header)
		for _, part := range parts {
			source, ok, err := parseDescriptionResourceFromLinkValue(part, resourceURI, allowed)
			if err != nil {
				// Skip malformed links
				continue
			}
			if ok {
				descriptionResources = append(descriptionResources, source)
			}
		}
	}

	return descriptionResources, nil
}

// parseDescriptionResourceFromLinkValue parses a single Link header value and extracts
// the description resource URI if it has a recognized relation.
func parseDescriptionResourceFromLinkValue(value string, baseURI string, allowed map[string]struct{}) (string, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false, nil
	}

	if !strings.HasPrefix(value, "<") {
		return "", false, nil
	}

	end := strings.Index(value, ">")
	if end <= 1 {
		return "", false, nil
	}

	target := strings.TrimSpace(value[1:end])
	attrs := parseLinkAttributes(value[end+1:])

	if !isDescriptionResourceRelation(attrs["rel"], allowed) {
		return "", false, nil
	}

	// Resolve the target relative to the base URI
	resolved, err := resolveDescriptionResourceTarget(baseURI, target)
	if err != nil {
		return "", false, err
	}

	return resolved, true, nil
}

// isDescriptionResourceRelation checks if the Link relation indicates a description resource.
func isDescriptionResourceRelation(relValue string, allowed map[string]struct{}) bool {
	if len(allowed) == 0 {
		return false
	}

	for _, rel := range strings.Fields(strings.ToLower(relValue)) {
		if _, ok := allowed[rel]; ok {
			return true
		}
	}
	return false
}

// resolveDescriptionResourceTarget resolves a description resource target relative to a base URI.
func resolveDescriptionResourceTarget(baseURI string, target string) (string, error) {
	// Check for control characters
	if strings.ContainsAny(target, "\x00\r\n") || strings.Contains(target, "#") {
		return "", fmt.Errorf("unsafe description resource target: %s", target)
	}

	// Parse base URI
	parsedBase, err := parseBaseURI(baseURI)
	if err != nil {
		return "", err
	}

	// Parse target
	parsedTarget, err := parseURITarget(target)
	if err != nil {
		return "", err
	}

	// Resolve the target
	// Go's ResolveReference has issues with relative paths like "../.meta"
	// We'll use manual path resolution for relative paths
	if parsedTarget.Scheme != "" || parsedTarget.Host != "" {
		// Absolute URL - use ResolveReference
		resolved := parsedBase.ResolveReference(parsedTarget)
		resolved.Fragment = ""
		if !isValidDescriptionResourceURI(resolved.String()) {
			return "", fmt.Errorf("invalid resolved description resource URI: %s", resolved.String())
		}
		return resolved.String(), nil
	} else {
		// Relative path - use filepath.Join which handles .. correctly
		// filepath.Join treats all paths as relative and joins them properly
		basePath := parsedBase.Path
		targetPath := parsedTarget.Path

		// Use filepath.Join to handle relative paths correctly
		// This handles cases like "../.meta" properly
		resolvedPath := filepath.Join(basePath, targetPath)

		// Clean to normalize
		resolvedPath = filepath.Clean(resolvedPath)

		// Ensure it starts with / (filepath.Join on Unix strips leading / if base doesn't have it)
		if !strings.HasPrefix(resolvedPath, "/") {
			resolvedPath = "/" + resolvedPath
		}

		// Build the full URL
		resolved := *parsedBase
		resolved.Path = resolvedPath
		resolved.Fragment = ""

		if !isValidDescriptionResourceURI(resolved.String()) {
			return "", fmt.Errorf("invalid resolved description resource URI: %s", resolved.String())
		}

		return resolved.String(), nil
	}
}

// parseBaseURI parses a base URI string into a url.URL.
func parseBaseURI(uri string) (*url.URL, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return nil, fmt.Errorf("empty base URI")
	}

	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	parsed.Fragment = ""
	return parsed, nil
}

// parseURITarget parses a URI target from a Link header.
func parseURITarget(target string) (*url.URL, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	return parsed, nil
}

// isValidDescriptionResourceURI validates a description resource URI.
func isValidDescriptionResourceURI(uri string) bool {
	if uri == "" {
		return false
	}

	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}

	// Must have a path
	if parsed.Path == "" {
		return false
	}

	// Must not have fragment
	if parsed.Fragment != "" {
		return false
	}

	return true
}

// DescriptionResourceMiddleware is a convenience function to create description resource middleware.
func DescriptionResourceMiddleware(next http.Handler) http.Handler {
	return NewDescriptionResourceHandler(next)
}

// DescriptionResourceMiddlewareWithOptions creates middleware with custom options.
func DescriptionResourceMiddlewareWithOptions(next http.Handler, options DescriptionResourceOptions) http.Handler {
	return NewDescriptionResourceHandlerWithOptions(next, options)
}

// ExtractDescriptionResourceURI extracts the description resource URI from a Link header.
// Returns the first description resource found, or empty string if none.
func ExtractDescriptionResourceURI(linkHeader string, resourceURI string) string {
	if linkHeader == "" {
		return ""
	}

	descriptionResources, err := ParseDescriptionResourceLinks([]string{linkHeader}, resourceURI)
	if err != nil || len(descriptionResources) == 0 {
		return ""
	}

	return descriptionResources[0]
}

// HasDescriptionResourceLink checks if a Link header contains a describedby relation.
func HasDescriptionResourceLink(linkHeader string) bool {
	if linkHeader == "" {
		return false
	}

	// Check for describedby in any form (quoted, unquoted, different quotes)
	lowerHeader := strings.ToLower(linkHeader)

	// Check for various forms
	if strings.Contains(lowerHeader, `rel="describedby"`) ||
		strings.Contains(lowerHeader, `rel='describedby'`) ||
		strings.Contains(lowerHeader, `;rel=describedby`) ||
		strings.Contains(lowerHeader, `rel=describedby,`) ||
		strings.Contains(lowerHeader, `rel=describedby;`) {
		return true
	}

	// Also check if it's part of a space-separated list
	parts := splitLinkHeader(linkHeader)
	for _, part := range parts {
		attrs := parseLinkAttributes(part)
		if rel, ok := attrs["rel"]; ok {
			for _, r := range strings.Fields(strings.ToLower(rel)) {
				if r == "describedby" {
					return true
				}
			}
		}
	}

	return false
}

// GetContainerDescriptionPath returns the likely description resource path for a container.
// In Solid, containers typically have a .meta description resource.
func GetContainerDescriptionPath(containerPath string) string {
	if containerPath == "/" {
		return "/.meta"
	}

	// Ensure container path ends with /
	normalized := containerPath
	if !strings.HasSuffix(normalized, "/") {
		normalized = normalized + "/"
	}

	// Return the .meta path
	return normalized + ".meta"
}

// GetWellKnownSolidPath returns the well-known Solid description resource path.
func GetWellKnownSolidPath(basePath string) string {
	if basePath == "/" {
		return "/.well-known/solid"
	}

	// Ensure base path ends with /
	normalized := basePath
	if !strings.HasSuffix(normalized, "/") {
		normalized = normalized + "/"
	}

	return normalized + ".well-known/solid"
}

// splitLinkHeader is a helper to split Link header values.
// This is duplicated from policy_discovery.go for isolation but could be shared.
func splitLinkHeader(header string) []string {
	var out []string
	var current strings.Builder
	inQuote := false
	for _, r := range header {
		switch r {
		case '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case ',':
			if inQuote {
				current.WriteRune(r)
				continue
			}
			out = append(out, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	out = append(out, current.String())
	return out
}

// parseLinkAttributes is a helper to parse Link header attributes.
// This is duplicated from policy_discovery.go for isolation but could be shared.
func parseLinkAttributes(value string) map[string]string {
	attrs := make(map[string]string)
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, raw, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		raw = strings.TrimSpace(raw)
		if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
			raw = raw[1 : len(raw)-1]
		}
		attrs[key] = raw
	}
	return attrs
}
