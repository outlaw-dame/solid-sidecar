package safety

import (
	"fmt"
	"net/http"
	"strings"
)

// AllowedWriteMethods defines the HTTP methods that are considered write operations
// in the Solid protocol context. These methods may create, modify, or delete resources.
var AllowedWriteMethods = map[string]bool{
	"PUT":    true,
	"POST":   true,
	"PATCH":  true,
	"DELETE": true,
}

// allowedWriteContentTypePrefixes defines valid Content-Type prefix patterns for
// write requests in Solid. These are checked as prefixes to allow for parameters
// (e.g., "application/ld+json; charset=utf-8").
var allowedWriteContentTypePrefixes = []string{
	"text/turtle",
	"application/ld+json",
	"application/json",
	"application/n-triples",
	"application/rdf+xml",
	"application/sparql-results+json",
	"application/octet-stream",
	"multipart/form-data",
}

// disallowedWriteContentTypes defines Content-Type values that should never be
// accepted for write requests due to security concerns.
var disallowedWriteContentTypes = []string{
	"text/html",
	"text/javascript",
	"application/javascript",
	"application/x-javascript",
	"application/ecmascript",
}

// ValidateWriteRequest checks if a write request (PUT, POST, PATCH, DELETE) has
// an acceptable Content-Type header. It returns nil if the request is valid,
// or an error describing why it was rejected.
//
// This validation is intentionally conservative: it only rejects requests that
// are clearly malicious or non-conformant. Unknown content types are allowed
// through to maintain CSS compatibility.
func ValidateWriteRequest(r *http.Request) error {
	// Only validate write methods
	if !IsWriteMethod(r.Method) {
		return nil
	}

	// DELETE requests don't require a body or Content-Type
	if r.Method == "DELETE" {
		return nil
	}

	// GET/HEAD/OPTIONS with body are unusual but not our concern here
	// We only care about write methods with bodies

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		// No Content-Type header - allow through to CSS
		// CSS may have its own requirements
		return nil
	}

	// Trim whitespace and parameters
	contentType = strings.TrimSpace(strings.Split(contentType, ";")[0])

	// Check against disallowed content types
	for _, disallowed := range disallowedWriteContentTypes {
		if strings.EqualFold(contentType, disallowed) {
			return fmt.Errorf("write request with disallowed content type: %s", contentType)
		}
	}

	// Check if it matches any allowed prefix
	for _, prefix := range allowedWriteContentTypePrefixes {
		if strings.HasPrefix(strings.ToLower(contentType), strings.ToLower(prefix)) {
			return nil
		}
	}

	// Unknown content type - allow through to CSS for compatibility
	// This ensures we don't break existing Solid clients
	return nil
}

// IsWriteMethod returns true if the given HTTP method is a write operation.
func IsWriteMethod(method string) bool {
	return AllowedWriteMethods[strings.ToUpper(method)]
}

// ValidateMethodTarget checks if the HTTP method is appropriate for the
// request target path. This is a security measure to prevent method/path
// combinations that are known to be problematic.
func ValidateMethodTarget(r *http.Request) error {
	// Currently, we don't have specific method/path restrictions
	// beyond what ValidateRequest already checks (dot segments, etc.)
	// This is a placeholder for future method/target validation
	return nil
}
