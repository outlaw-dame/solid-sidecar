// Package clients provides Solid Sidecar client implementations for the Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready
package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/types"
	"github.com/outlaw-dame/solid-sidecar/sdk/go/pkg/utils"
)

// ErrResourceExists represents a resource already exists error
var ErrResourceExists = errors.New("resource already exists")

// ErrResourceNotFound represents a resource not found error
var ErrResourceNotFound = errors.New("resource not found")

// ErrResourceModified represents a resource was modified error
var ErrResourceModified = errors.New("resource was modified")

// ResourceClient provides operations for managing Solid resources.
type ResourceClient struct {
	// httpClient is the underlying HTTP client
	httpClient *utils.HTTPClient

	// basePath is the base path for resource operations
	basePath string

	// dpopProofFunc is the function to generate DPoP proofs
	dpopProofFunc func(method, url string) (string, error)
}

// ResourceClientOptions contains options for creating a ResourceClient.
type ResourceClientOptions struct {
	// BasePath is the base path for resource operations (defaults to "/")
	BasePath string

	// RequestOptions contains HTTP request options
	RequestOptions *types.RequestOptions
}

// NewResourceClient creates a new ResourceClient.
//
// Parameters:
//   - baseURL: The base URL of the Solid Sidecar instance
//   - options: Optional client options (can be nil for defaults)
//
// Returns:
//   - A new ResourceClient instance
//   - Error if creation fails
func NewResourceClient(baseURL string, options *ResourceClientOptions) (*ResourceClient, error) {
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

	return &ResourceClient{
		httpClient: httpClient,
		basePath:   basePath,
	}, nil
}

// SetAccessToken sets the access token for authentication.
func (c *ResourceClient) SetAccessToken(token string) {
	c.httpClient.SetAccessToken(token)
}

// SetDPoPProofFunc sets the function to generate DPoP proofs.
func (c *ResourceClient) SetDPoPProofFunc(fn func(method, url string) (string, error)) {
	c.dpopProofFunc = fn
	c.httpClient.SetDPoPProofFunc(fn)
}

// buildResourcePath builds the full path for a resource URI.
func (c *ResourceClient) buildResourcePath(resourceURI string) string {
	// If resourceURI already contains scheme, use as-is
	if strings.Contains(resourceURI, "://") {
		return resourceURI
	}

	// Remove leading slash from basePath and resourceURI
	base := strings.TrimRight(c.basePath, "/")
	resource := strings.TrimLeft(resourceURI, "/")

	return base + "/" + resource
}

// Get retrieves a resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource to retrieve
//   - options: Request options (can be nil)
//
// Returns:
//   - The Resource
//   - Error if the request fails
func (c *ResourceClient) Get(
	ctx context.Context,
	resourceURI string,
	options *types.RequestOptions,
) (*types.Resource, error) {
	path := c.buildResourcePath(resourceURI)

	body, statusCode, headers, err := c.httpClient.Do(
		ctx,
		"GET",
		path,
		nil,
		nil,
		options,
	)
	if err != nil {
		return nil, err
	}

	// Check for errors
	if err := utils.CheckHTTPError(statusCode, body); err != nil {
		if statusCode == 404 {
			return nil, ErrResourceNotFound
		}
		return nil, err
	}

	// Parse resource
	resource := &types.Resource{
		URI:   resourceURI,
		Links: make(map[string]string),
	}

	// Extract content type
	if ct, ok := headers["Content-Type"]; ok {
		resource.ContentType = ct
	}

	// Extract ETag
	if etag, ok := headers["ETag"]; ok {
		resource.ETag = etag
	}

	// Extract Last-Modified
	if lm, ok := headers["Last-Modified"]; ok {
		if t, err := http.ParseTime(lm); err == nil {
			resource.LastModified = t
		}
	}

	// Extract Link headers
	if link, ok := headers["Link"]; ok {
		resource.Links = parseLinkHeader(link)
	}

	// Set body
	if len(body) > 0 {
		resource.Body = body
	}

	// Check if it's a container
	if ct, ok := resource.Links["type"]; ok {
		if ct == "http://www.w3.org/ns/ldp#BasicContainer" ||
			ct == "http://www.w3.org/ns/ldp#DirectContainer" ||
			ct == "http://www.w3.org/ns/ldp#Container" {
			resource.IsContainer = true
		}
	}

	return resource, nil
}

// Head retrieves resource metadata without the body.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource
//   - options: Request options (can be nil)
//
// Returns:
//   - The Resource (without body)
//   - Error if the request fails
func (c *ResourceClient) Head(
	ctx context.Context,
	resourceURI string,
	options *types.RequestOptions,
) (*types.Resource, error) {
	path := c.buildResourcePath(resourceURI)

	body, statusCode, headers, err := c.httpClient.Do(
		ctx,
		"HEAD",
		path,
		nil,
		nil,
		options,
	)
	if err != nil {
		return nil, err
	}

	// Check for errors
	if err := utils.CheckHTTPError(statusCode, body); err != nil {
		if statusCode == 404 {
			return nil, ErrResourceNotFound
		}
		return nil, err
	}

	// Parse resource metadata
	resource := &types.Resource{
		URI:   resourceURI,
		Links: make(map[string]string),
	}

	// Extract content type
	if ct, ok := headers["Content-Type"]; ok {
		resource.ContentType = ct
	}

	// Extract ETag
	if etag, ok := headers["ETag"]; ok {
		resource.ETag = etag
	}

	// Extract Last-Modified
	if lm, ok := headers["Last-Modified"]; ok {
		if t, err := http.ParseTime(lm); err == nil {
			resource.LastModified = t
		}
	}

	// Extract Content-Length
	if cl, ok := headers["Content-Length"]; ok {
		// Could parse and set size, but not storing in Resource struct for now
		_ = cl
	}

	// Extract Link headers
	if link, ok := headers["Link"]; ok {
		resource.Links = parseLinkHeader(link)
	}

	// Check if it's a container
	if ct, ok := resource.Links["type"]; ok {
		if ct == "http://www.w3.org/ns/ldp#BasicContainer" ||
			ct == "http://www.w3.org/ns/ldp#DirectContainer" ||
			ct == "http://www.w3.org/ns/ldp#Container" {
			resource.IsContainer = true
		}
	}

	return resource, nil
}

// Put creates or replaces a resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource
//   - contentType: The content type of the resource
//   - body: The resource content
//   - preconditions: Optional preconditions for conditional write
//   - options: Request options (can be nil)
//
// Returns:
//   - The WriteResult
//   - Error if the request fails
func (c *ResourceClient) Put(
	ctx context.Context,
	resourceURI string,
	contentType string,
	body []byte,
	preconditions *types.WritePreconditions,
	options *types.RequestOptions,
) (*types.WriteResult, error) {
	path := c.buildResourcePath(resourceURI)

	// Build headers
	headers := types.HTTPHeaders{
		"Content-Type": contentType,
	}

	// Add conditional headers
	if preconditions != nil {
		if len(preconditions.IfMatch) > 0 {
			// Use first If-Match value
			headers["If-Match"] = preconditions.IfMatch[0]
		}
		if len(preconditions.IfNoneMatch) > 0 {
			// Use first If-None-Match value
			headers["If-None-Match"] = preconditions.IfNoneMatch[0]
		}
	}

	respBody, statusCode, respHeaders, err := c.httpClient.Do(
		ctx,
		"PUT",
		path,
		body,
		headers,
		options,
	)
	if err != nil {
		return nil, err
	}

	// Parse response
	result := &types.WriteResult{
		StatusCode: statusCode,
	}

	// Extract ETag
	if etag, ok := respHeaders["ETag"]; ok {
		result.ETag = etag
	}

	// Extract Last-Modified
	if lm, ok := respHeaders["Last-Modified"]; ok {
		if t, err := http.ParseTime(lm); err == nil {
			result.LastModified = t
		}
	}

	// Extract Location
	if loc, ok := respHeaders["Location"]; ok {
		result.Location = loc
	}

	// Set Created based on status code
	result.Created = statusCode == 201

	// Check for errors based on expectations
	if statusCode == 412 {
		return result, utils.ErrPreconditionFailed
	}

	if statusCode == 409 {
		return result, ErrResourceExists
	}

	if statusCode == 404 {
		// Resource not found (for parent container)
		return result, ErrResourceNotFound
	}

	if err := utils.CheckHTTPError(statusCode, respBody); err != nil {
		return result, err
	}

	return result, nil
}

// PutConditional creates or updates a resource with conditional writes.
// This is the recommended method for preventing lost updates.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource
//   - contentType: The content type of the resource
//   - body: The resource content
//   - ifMatch: ETag to match for update (nil or empty string to skip)
//   - ifNoneMatch: ETag to not match or "*" for create-only (nil or empty string to skip)
//   - options: Request options (can be nil)
//
// Returns:
//   - The WriteResult
//   - Error if the request fails
func (c *ResourceClient) PutConditional(
	ctx context.Context,
	resourceURI string,
	contentType string,
	body []byte,
	ifMatch string,
	ifNoneMatch string,
	options *types.RequestOptions,
) (*types.WriteResult, error) {
	preconditions := &types.WritePreconditions{}

	if ifMatch != "" {
		preconditions.IfMatch = []string{ifMatch}
	}
	if ifNoneMatch != "" {
		preconditions.IfNoneMatch = []string{ifNoneMatch}
	}

	return c.Put(ctx, resourceURI, contentType, body, preconditions, options)
}

// Create creates a new resource (fails if already exists).
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource
//   - contentType: The content type of the resource
//   - body: The resource content
//   - options: Request options (can be nil)
//
// Returns:
//   - The WriteResult
//   - Error if the request fails
func (c *ResourceClient) Create(
	ctx context.Context,
	resourceURI string,
	contentType string,
	body []byte,
	options *types.RequestOptions,
) (*types.WriteResult, error) {
	// Use If-None-Match: * to ensure create-only
	preconditions := &types.WritePreconditions{
		IfNoneMatch: []string{"*"},
	}

	result, err := c.Put(ctx, resourceURI, contentType, body, preconditions, options)
	if err != nil {
		return result, err
	}

	// If we got 200 instead of 201, it means the resource already existed
	if result.StatusCode == 200 {
		return result, ErrResourceExists
	}

	return result, nil
}

// Update updates an existing resource (fails if not exists or modified).
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource
//   - contentType: The content type of the resource
//   - body: The resource content
//   - currentETag: The current ETag of the resource (for If-Match)
//   - options: Request options (can be nil)
//
// Returns:
//   - The WriteResult
//   - Error if the request fails
func (c *ResourceClient) Update(
	ctx context.Context,
	resourceURI string,
	contentType string,
	body []byte,
	currentETag string,
	options *types.RequestOptions,
) (*types.WriteResult, error) {
	if currentETag == "" {
		return nil, errors.New("currentETag is required for Update")
	}

	preconditions := &types.WritePreconditions{
		IfMatch: []string{currentETag},
	}

	return c.Put(ctx, resourceURI, contentType, body, preconditions, options)
}

// Delete deletes a resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource to delete
//   - preconditions: Optional preconditions for conditional delete
//   - options: Request options (can be nil)
//
// Returns:
//   - Error if the request fails
func (c *ResourceClient) Delete(
	ctx context.Context,
	resourceURI string,
	preconditions *types.WritePreconditions,
	options *types.RequestOptions,
) error {
	path := c.buildResourcePath(resourceURI)

	// Build headers
	headers := types.HTTPHeaders{}

	// Add conditional headers
	if preconditions != nil {
		if len(preconditions.IfMatch) > 0 {
			// Use first If-Match value
			headers["If-Match"] = preconditions.IfMatch[0]
		}
	}

	_, statusCode, _, err := c.httpClient.Do(
		ctx,
		"DELETE",
		path,
		nil,
		headers,
		options,
	)
	if err != nil {
		return err
	}

	// Check for errors
	if statusCode == 404 {
		return ErrResourceNotFound
	}

	if statusCode == 412 {
		return ErrResourceModified
	}

	if err := utils.CheckHTTPError(statusCode, nil); err != nil {
		return err
	}

	return nil
}

// DeleteConditional deletes a resource with conditional check.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource to delete
//   - currentETag: The current ETag of the resource (for If-Match)
//   - options: Request options (can be nil)
//
// Returns:
//   - Error if the request fails
func (c *ResourceClient) DeleteConditional(
	ctx context.Context,
	resourceURI string,
	currentETag string,
	options *types.RequestOptions,
) error {
	if currentETag == "" {
		return errors.New("currentETag is required for DeleteConditional")
	}

	preconditions := &types.WritePreconditions{
		IfMatch: []string{currentETag},
	}

	return c.Delete(ctx, resourceURI, preconditions, options)
}

// List lists the contents of a container.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - containerURI: The URI of the container
//   - options: Request options (can be nil)
//
// Returns:
//   - The ListResponse
//   - Error if the request fails
func (c *ResourceClient) List(
	ctx context.Context,
	containerURI string,
	options *types.RequestOptions,
) (*types.ListResponse, error) {
	path := c.buildResourcePath(containerURI)

	body, statusCode, headers, err := c.httpClient.Do(
		ctx,
		"GET",
		path,
		nil,
		map[string]string{"Accept": "text/turtle"},
		options,
	)
	if err != nil {
		return nil, err
	}

	// Check for errors
	if err := utils.CheckHTTPError(statusCode, body); err != nil {
		if statusCode == 404 {
			return nil, ErrResourceNotFound
		}
		return nil, err
	}

	// Parse response
	response := &types.ListResponse{
		Resources:  []string{},
		Containers: []string{},
	}

	// Extract ETag
	if etag, ok := headers["ETag"]; ok {
		response.ETag = etag
	}

	// Extract Last-Modified
	if lm, ok := headers["Last-Modified"]; ok {
		if t, err := http.ParseTime(lm); err == nil {
			response.LastModified = t
		}
	}

	// Parse body to extract resource URIs
	if len(body) > 0 {
		// Parse as Turtle or JSON-LD to extract resource URIs
		uris := parseContainerBody(body, headers["Content-Type"])

		// Separate resources and containers
		for _, uri := range uris {
			if isContainerURI(uri) {
				response.Containers = append(response.Containers, uri)
			} else {
				response.Resources = append(response.Resources, uri)
			}
		}
	}

	return response, nil
}

// Exists checks if a resource exists.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource
//   - options: Request options (can be nil)
//
// Returns:
//   - true if the resource exists
//   - Error if the request fails
func (c *ResourceClient) Exists(
	ctx context.Context,
	resourceURI string,
	options *types.RequestOptions,
) (bool, error) {
	_, err := c.Head(ctx, resourceURI, options)
	if err == ErrResourceNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetETag retrieves the ETag of a resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource
//   - options: Request options (can be nil)
//
// Returns:
//   - The ETag string
//   - Error if the request fails
func (c *ResourceClient) GetETag(
	ctx context.Context,
	resourceURI string,
	options *types.RequestOptions,
) (string, error) {
	resource, err := c.Head(ctx, resourceURI, options)
	if err != nil {
		return "", err
	}
	return resource.ETag, nil
}

// Patch performs a partial update on a resource using SPARQL Update.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource to patch
//   - sparqlUpdate: The SPARQL Update query
//   - preconditions: Optional preconditions for conditional update
//   - options: Request options (can be nil)
//
// Returns:
//   - The WriteResult
//   - Error if the request fails
func (c *ResourceClient) Patch(
	ctx context.Context,
	resourceURI string,
	sparqlUpdate string,
	preconditions *types.WritePreconditions,
	options *types.RequestOptions,
) (*types.WriteResult, error) {
	path := c.buildResourcePath(resourceURI)

	// Build headers
	headers := types.HTTPHeaders{
		"Content-Type": "application/sparql-update",
	}

	// Add conditional headers
	if preconditions != nil {
		if len(preconditions.IfMatch) > 0 {
			headers["If-Match"] = preconditions.IfMatch[0]
		}
	}

	respBody, statusCode, respHeaders, err := c.httpClient.Do(
		ctx,
		"PATCH",
		path,
		[]byte(sparqlUpdate),
		headers,
		options,
	)
	if err != nil {
		return nil, err
	}

	// Parse response
	result := &types.WriteResult{
		StatusCode: statusCode,
	}

	// Extract ETag
	if etag, ok := respHeaders["ETag"]; ok {
		result.ETag = etag
	}

	// Extract Last-Modified
	if lm, ok := respHeaders["Last-Modified"]; ok {
		if t, err := http.ParseTime(lm); err == nil {
			result.LastModified = t
		}
	}

	// Check for errors
	if statusCode == 412 {
		return result, utils.ErrPreconditionFailed
	}

	if err := utils.CheckHTTPError(statusCode, respBody); err != nil {
		return result, err
	}

	return result, nil
}

// parseLinkHeader parses a Link header into a map.
func parseLinkHeader(header string) map[string]string {
	result := make(map[string]string)

	// Split by comma
	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split by ; to get URI and parameters
		uriPart := part
		rel := ""

		// Find rel parameter
		if idx := strings.Index(part, ";"); idx >= 0 {
			uriPart = strings.TrimSpace(part[:idx])
			params := part[idx+1:]

			// Parse parameters
			paramParts := strings.Split(params, ";")
			for _, param := range paramParts {
				param = strings.TrimSpace(param)
				if strings.HasPrefix(param, "rel=\"") || strings.HasPrefix(param, "rel='") {
					rel = strings.TrimPrefix(param, "rel=\"")
					rel = strings.TrimPrefix(rel, "rel='")
					rel = strings.TrimSuffix(rel, "\"")
					rel = strings.TrimSuffix(rel, "'")
					break
				}
			}
		}

		// Remove angle brackets from URI
		uri := strings.TrimPrefix(uriPart, "<")
		uri = strings.TrimSuffix(uri, ">")
		uri = strings.TrimSpace(uri)

		if rel != "" && uri != "" {
			result[rel] = uri
		}
	}

	return result
}

// parseContainerBody parses a container body to extract resource URIs.
func parseContainerBody(body []byte, contentType string) []string {
	uris := []string{}
	bodyStr := string(body)

	// Handle Turtle format
	if strings.Contains(contentType, "turtle") || strings.Contains(contentType, "text/turtle") {
		// Simple parser for Turtle container listing
		lines := strings.Split(bodyStr, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "@") || strings.HasPrefix(line, "<> ") {
				continue
			}

			// Look for lines that look like URIs
			if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
				// Extract URI
				uri := strings.TrimPrefix(line, "<")
				uri = strings.TrimSuffix(uri, ">")
				uri = strings.TrimSpace(uri)

				// Skip if it's a predicate
				if !strings.Contains(uri, " ") && !strings.Contains(uri, "\t") {
					uris = append(uris, uri)
				}
			}
		}
	} else if strings.Contains(contentType, "json") {
		// Try to parse as JSON-LD
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err == nil {
			// Look for @graph or other container properties
			if graph, ok := data["@graph"].([]interface{}); ok {
				for _, item := range graph {
					if itemMap, ok := item.(map[string]interface{}); ok {
						if id, ok := itemMap["@id"].(string); ok {
							uris = append(uris, id)
						}
					}
				}
			}
		}
	}

	return uris
}

// isContainerURI checks if a URI represents a container.
func isContainerURI(uri string) bool {
	// Check common container URI patterns
	containerTypes := []string{
		"http://www.w3.org/ns/ldp#BasicContainer",
		"http://www.w3.org/ns/ldp#DirectContainer",
		"http://www.w3.org/ns/ldp#Container",
		"http://www.w3.org/ns/ldp#IndirectContainer",
	}

	// Check if URI ends with / (common for containers)
	if strings.HasSuffix(uri, "/") {
		return true
	}

	// Check if URI is in container types
	for _, ct := range containerTypes {
		if strings.Contains(uri, ct) {
			return true
		}
	}

	return false
}

// CreateContainer creates a new container.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - containerURI: The URI of the container to create
//   - containerType: The type of container (e.g., "http://www.w3.org/ns/ldp#BasicContainer")
//   - options: Request options (can be nil)
//
// Returns:
//   - The WriteResult
//   - Error if the request fails
func (c *ResourceClient) CreateContainer(
	ctx context.Context,
	containerURI string,
	containerType string,
	options *types.RequestOptions,
) (*types.WriteResult, error) {
	// Container description in Turtle format
	turtleBody := fmt.Sprintf(`<> a <%s> .`, containerType)

	// Set Link header for container type
	headers := types.HTTPHeaders{
		"Content-Type": "text/turtle",
		"Link":         fmt.Sprintf(`<%s>; rel="type"`, containerType),
	}

	preconditions := &types.WritePreconditions{
		IfNoneMatch: []string{"*"}, // Create only
	}

	// Use a simple body
	body := []byte(turtleBody)

	return c.Put(ctx, containerURI, "text/turtle", body, preconditions, &types.RequestOptions{
		Headers: headers,
	})
}
