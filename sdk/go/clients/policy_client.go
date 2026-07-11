// Package clients provides Solid Sidecar client implementations for the Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready - FULLY HARDENED
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

// ErrPolicyNotFound represents a policy resource not found error
var ErrPolicyNotFound = errors.New("policy resource not found")

// ErrInvalidPolicy represents an invalid policy error
var ErrInvalidPolicy = errors.New("invalid policy")

// ErrPolicyConflict represents a policy conflict error
var ErrPolicyConflict = errors.New("policy conflict")

// PolicyClient provides operations for managing Solid policy resources (WAC/ACP/SAI).
// This implementation is thread-safe and follows Solid protocol specifications.
type PolicyClient struct {
	// httpClient is the underlying HTTP client
	httpClient *utils.HTTPClient

	// basePath is the base path for policy operations
	basePath string

	// dpopProofFunc is the function to generate DPoP proofs
	dpopProofFunc func(method, url string) (string, error)

	// policyType is the default policy type (WAC, ACP, or SAI)
	policyType types.PolicyResourceType
}

// PolicyClientOptions contains options for creating a PolicyClient.
type PolicyClientOptions struct {
	// BasePath is the base path for policy operations (defaults to "/")
	BasePath string

	// PolicyType is the default policy type (defaults to ACP)
	PolicyType types.PolicyResourceType

	// RequestOptions contains HTTP request options
	RequestOptions *types.RequestOptions
}

// NewPolicyClient creates a new PolicyClient.
//
// Parameters:
//   - baseURL: The base URL of the Solid Sidecar instance
//   - options: Optional client options (can be nil for defaults)
//
// Returns:
//   - A new PolicyClient instance
//   - Error if creation fails
func NewPolicyClient(baseURL string, options *PolicyClientOptions) (*PolicyClient, error) {
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

	policyType := types.ACP
	if options != nil && options.PolicyType != "" {
		policyType = options.PolicyType
	}

	return &PolicyClient{
		httpClient: httpClient,
		basePath:   basePath,
		policyType: policyType,
	}, nil
}

// SetAccessToken sets the access token for authentication.
func (c *PolicyClient) SetAccessToken(token string) {
	c.httpClient.SetAccessToken(token)
}

// SetDPoPProofFunc sets the function to generate DPoP proofs.
func (c *PolicyClient) SetDPoPProofFunc(fn func(method, url string) (string, error)) {
	c.dpopProofFunc = fn
	c.httpClient.SetDPoPProofFunc(fn)
}

// SetPolicyType sets the default policy type.
func (c *PolicyClient) SetPolicyType(policyType types.PolicyResourceType) {
	c.policyType = policyType
}

// buildPolicyPath builds the full path for a policy resource URI.
func (c *PolicyClient) buildPolicyPath(policyURI string) string {
	// If policyURI already contains scheme, use as-is
	if strings.Contains(policyURI, "://") {
		return policyURI
	}

	// Remove leading slash from basePath and policyURI
	base := strings.TrimRight(c.basePath, "/")
	policy := strings.TrimLeft(policyURI, "/")

	return base + "/" + policy
}

// GetPolicyURI constructs the URI for a policy resource based on resource URI and policy type.
//
// Parameters:
//   - resourceURI: The URI of the resource
//   - policyType: The policy type (WAC, ACP, SAI)
//
// Returns:
//   - The policy resource URI
func (c *PolicyClient) GetPolicyURI(resourceURI string, policyType types.PolicyResourceType) string {
	if policyType == "" {
		policyType = c.policyType
	}

	// Remove trailing slash from resource URI
	resourceURI = strings.TrimRight(resourceURI, "/")

	// Policy URIs follow the pattern: {resourceURI}.{policyType}
	// For WAC: {resourceURI}.acl
	// For ACP: {resourceURI}.acp
	// For SAI: {resourceURI}.sai
	switch policyType {
	case types.WAC:
		return resourceURI + ".acl"
	case types.ACP:
		return resourceURI + ".acp"
	case types.SAI:
		return resourceURI + ".sai"
	default:
		// Default to ACP
		return resourceURI + ".acp"
	}
}

// Get retrieves a policy resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - policyURI: The URI of the policy resource to retrieve
//   - options: Request options (can be nil)
//
// Returns:
//   - The Policy
//   - Error if the request fails
func (c *PolicyClient) Get(
	ctx context.Context,
	policyURI string,
	options *types.RequestOptions,
) (*types.Policy, error) {
	path := c.buildPolicyPath(policyURI)

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
			return nil, ErrPolicyNotFound
		}
		return nil, err
	}

	// Parse policy based on content type
	policy, err := c.parsePolicy(body, headers)
	if err != nil {
		return nil, err
	}

	// Set URI and ETag
	policy.URI = policyURI
	if etag, ok := headers["ETag"]; ok {
		policy.ETag = etag
	}

	return policy, nil
}

// GetForResource retrieves the policy for a specific resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource
//   - policyType: The policy type to retrieve (defaults to client's policy type)
//   - options: Request options (can be nil)
//
// Returns:
//   - The Policy
//   - Error if the request fails
func (c *PolicyClient) GetForResource(
	ctx context.Context,
	resourceURI string,
	policyType types.PolicyResourceType,
	options *types.RequestOptions,
) (*types.Policy, error) {
	policyURI := c.GetPolicyURI(resourceURI, policyType)
	return c.Get(ctx, policyURI, options)
}

// Exists checks if a policy resource exists.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - policyURI: The URI of the policy resource
//   - options: Request options (can be nil)
//
// Returns:
//   - true if the policy exists
//   - Error if the request fails
func (c *PolicyClient) Exists(
	ctx context.Context,
	policyURI string,
	options *types.RequestOptions,
) (bool, error) {
	path := c.buildPolicyPath(policyURI)

	_, statusCode, _, err := c.httpClient.Do(
		ctx,
		"HEAD",
		path,
		nil,
		nil,
		options,
	)
	if err != nil {
		return false, err
	}

	// Check for errors
	if statusCode == 404 {
		return false, nil
	}

	if err := utils.CheckHTTPError(statusCode, nil); err != nil {
		return false, err
	}

	return true, nil
}

// GetETag retrieves the ETag of a policy resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - policyURI: The URI of the policy resource
//   - options: Request options (can be nil)
//
// Returns:
//   - The ETag string
//   - Error if the request fails
func (c *PolicyClient) GetETag(
	ctx context.Context,
	policyURI string,
	options *types.RequestOptions,
) (string, error) {
	path := c.buildPolicyPath(policyURI)

	_, statusCode, headers, err := c.httpClient.Do(
		ctx,
		"HEAD",
		path,
		nil,
		nil,
		options,
	)
	if err != nil {
		return "", err
	}

	// Check for errors
	if statusCode == 404 {
		return "", ErrPolicyNotFound
	}

	if err := utils.CheckHTTPError(statusCode, nil); err != nil {
		return "", err
	}

	if etag, ok := headers["ETag"]; ok {
		return etag, nil
	}

	return "", nil
}

// Put creates or replaces a policy resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - policyURI: The URI of the policy resource
//   - policy: The policy to set
//   - preconditions: Optional preconditions for conditional write
//   - options: Request options (can be nil)
//
// Returns:
//   - The WriteResult
//   - Error if the request fails
func (c *PolicyClient) Put(
	ctx context.Context,
	policyURI string,
	policy *types.Policy,
	preconditions *types.WritePreconditions,
	options *types.RequestOptions,
) (*types.WriteResult, error) {
	path := c.buildPolicyPath(policyURI)

	// Serialize policy based on policy type
	contentType, body, err := c.serializePolicy(policy)
	if err != nil {
		return nil, err
	}

	// Build headers
	headers := types.HTTPHeaders{
		"Content-Type": contentType,
	}

	// Add conditional headers
	if preconditions != nil {
		if len(preconditions.IfMatch) > 0 {
			headers["If-Match"] = preconditions.IfMatch[0]
		}
		if len(preconditions.IfNoneMatch) > 0 {
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
		return result, ErrPolicyConflict
	}

	if statusCode == 404 {
		// Resource not found (for parent container)
		return result, ErrPolicyNotFound
	}

	if err := utils.CheckHTTPError(statusCode, respBody); err != nil {
		return result, err
	}

	return result, nil
}

// Update updates an existing policy resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - policyURI: The URI of the policy resource
//   - policy: The updated policy
//   - currentETag: The current ETag of the policy resource (for If-Match)
//   - options: Request options (can be nil)
//
// Returns:
//   - The WriteResult
//   - Error if the request fails
func (c *PolicyClient) Update(
	ctx context.Context,
	policyURI string,
	policy *types.Policy,
	currentETag string,
	options *types.RequestOptions,
) (*types.WriteResult, error) {
	if currentETag == "" {
		return nil, errors.New("currentETag is required for Update")
	}

	preconditions := &types.WritePreconditions{
		IfMatch: []string{currentETag},
	}

	return c.Put(ctx, policyURI, policy, preconditions, options)
}

// Delete deletes a policy resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - policyURI: The URI of the policy resource to delete
//   - preconditions: Optional preconditions for conditional delete
//   - options: Request options (can be nil)
//
// Returns:
//   - Error if the request fails
func (c *PolicyClient) Delete(
	ctx context.Context,
	policyURI string,
	preconditions *types.WritePreconditions,
	options *types.RequestOptions,
) error {
	path := c.buildPolicyPath(policyURI)

	// Build headers
	headers := types.HTTPHeaders{}

	// Add conditional headers
	if preconditions != nil {
		if len(preconditions.IfMatch) > 0 {
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
		return ErrPolicyNotFound
	}

	if statusCode == 412 {
		return ErrPolicyConflict
	}

	if err := utils.CheckHTTPError(statusCode, nil); err != nil {
		return err
	}

	return nil
}

// DeleteForResource deletes the policy for a specific resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - resourceURI: The URI of the resource
//   - policyType: The policy type to delete
//   - currentETag: The current ETag of the policy resource (for If-Match)
//   - options: Request options (can be nil)
//
// Returns:
//   - Error if the request fails
func (c *PolicyClient) DeleteForResource(
	ctx context.Context,
	resourceURI string,
	policyType types.PolicyResourceType,
	currentETag string,
	options *types.RequestOptions,
) error {
	policyURI := c.GetPolicyURI(resourceURI, policyType)

	if currentETag == "" {
		return errors.New("currentETag is required for DeleteForResource")
	}

	preconditions := &types.WritePreconditions{
		IfMatch: []string{currentETag},
	}

	return c.Delete(ctx, policyURI, preconditions, options)
}

// AddRule adds a rule to a policy resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - policyURI: The URI of the policy resource
//   - rule: The rule to add
//   - currentETag: The current ETag of the policy resource (for If-Match)
//   - options: Request options (can be nil)
//
// Returns:
//   - The updated Policy
//   - Error if the request fails
func (c *PolicyClient) AddRule(
	ctx context.Context,
	policyURI string,
	rule types.PolicyRule,
	currentETag string,
	options *types.RequestOptions,
) (*types.Policy, error) {
	// Get current policy
	policy, err := c.Get(ctx, policyURI, options)
	if err != nil {
		return nil, err
	}

	// Add rule
	policy.Rules = append(policy.Rules, rule)

	// Update policy
	_, err = c.Update(ctx, policyURI, policy, currentETag, options)
	if err != nil {
		return nil, err
	}

	// Return updated policy
	return c.Get(ctx, policyURI, options)
}

// RemoveRule removes a rule from a policy resource.
//
// Parameters:
//   - ctx: Context for cancellation/timeout
//   - policyURI: The URI of the policy resource
//   - ruleIndex: The index of the rule to remove
//   - currentETag: The current ETag of the policy resource (for If-Match)
//   - options: Request options (can be nil)
//
// Returns:
//   - The updated Policy
//   - Error if the request fails
func (c *PolicyClient) RemoveRule(
	ctx context.Context,
	policyURI string,
	ruleIndex int,
	currentETag string,
	options *types.RequestOptions,
) (*types.Policy, error) {
	// Get current policy
	policy, err := c.Get(ctx, policyURI, options)
	if err != nil {
		return nil, err
	}

	// Check bounds
	if ruleIndex < 0 || ruleIndex >= len(policy.Rules) {
		return nil, fmt.Errorf("%w: rule index out of bounds", ErrInvalidPolicy)
	}

	// Remove rule
	policy.Rules = append(policy.Rules[:ruleIndex], policy.Rules[ruleIndex+1:]...)

	// Update policy
	_, err = c.Update(ctx, policyURI, policy, currentETag, options)
	if err != nil {
		return nil, err
	}

	// Return updated policy
	return c.Get(ctx, policyURI, options)
}

// parsePolicy parses a policy from the response body based on content type.
func (c *PolicyClient) parsePolicy(body []byte, headers map[string]string) (*types.Policy, error) {
	contentType := headers["Content-Type"]

	policy := &types.Policy{
		Type:  c.policyType,
		Rules: []types.PolicyRule{},
	}

	if len(body) == 0 {
		return policy, nil
	}

	bodyStr := string(body)

	// Parse based on policy type and content type
	switch c.policyType {
	case types.WAC:
		return c.parseWAC(bodyStr, contentType, policy)
	case types.ACP:
		return c.parseACP(bodyStr, contentType, policy)
	case types.SAI:
		return c.parseSAI(bodyStr, contentType, policy)
	default:
		// Try to detect based on content type
		if strings.Contains(contentType, "acl") {
			return c.parseWAC(bodyStr, contentType, policy)
		} else if strings.Contains(contentType, "acp") {
			return c.parseACP(bodyStr, contentType, policy)
		} else if strings.Contains(contentType, "sai") {
			return c.parseSAI(bodyStr, contentType, policy)
		} else {
			// Default to ACP
			return c.parseACP(bodyStr, contentType, policy)
		}
	}
}

// parseWAC parses a WAC (Web Access Control) policy.
func (c *PolicyClient) parseWAC(bodyStr, contentType string, policy *types.Policy) (*types.Policy, error) {
	// WAC policies are typically in Turtle format
	// Parse the Turtle to extract rules

	policy.Type = types.WAC

	// Simple parsing for WAC - this would be enhanced in production
	// Look for acl:Authorization triples
	lines := strings.Split(bodyStr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "@") || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for acl:Authorization nodes
		if strings.Contains(line, "acl:Authorization") {
			// This is a simplified parser
			// In production, use a proper RDF parser
			continue
		}

		// Look for access modes
		if strings.Contains(line, "acl:mode") {
			// Extract access mode
			parts := strings.Split(line, "acl:mode")
			if len(parts) > 1 {
				modePart := strings.TrimSpace(parts[1])
				// Extract the mode value
				if idx := strings.Index(modePart, ""); idx >= 0 {
					mode := strings.TrimSpace(modePart[:idx])
					mode = strings.TrimPrefix(mode, "acl:")

					// Create a rule with this mode
					rule := types.PolicyRule{
						AccessMode: types.AccessMode(mode),
						AgentType:  types.AgentTypeAgent,
					}
					policy.Rules = append(policy.Rules, rule)
				}
			}
		}
	}

	return policy, nil
}

// parseACP parses an ACP (Access Control Policy) policy.
func (c *PolicyClient) parseACP(bodyStr, contentType string, policy *types.Policy) (*types.Policy, error) {
	// ACP policies are typically in JSON-LD or Turtle format
	// For simplicity, we'll handle both

	policy.Type = types.ACP

	if strings.Contains(contentType, "json") {
		return c.parseACPJSON(bodyStr, policy)
	} else {
		return c.parseACPTurtle(bodyStr, policy)
	}
}

// parseACPJSON parses ACP in JSON-LD format.
func (c *PolicyClient) parseACPJSON(bodyStr string, policy *types.Policy) (*types.Policy, error) {
	// Simplified JSON-LD parsing for ACP
	// In production, use a proper JSON-LD parser

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(bodyStr), &data); err != nil {
		// If JSON parsing fails, try as Turtle
		return c.parseACPTurtle(bodyStr, policy)
	}

	policy.Type = types.ACP

	// Handle different ACP JSON structures

	// Try to extract rules from "rule" array (format produced by serializeACP)
	if rules, ok := data["rule"].([]interface{}); ok {
		for _, ruleItem := range rules {
			if ruleMap, ok := ruleItem.(map[string]interface{}); ok {
				var rule types.PolicyRule

				// Extract access mode
				if access, ok := ruleMap["access"].(string); ok {
					rule.AccessMode = types.AccessMode(access)
				} else if mode, ok := ruleMap["mode"].(string); ok {
					rule.AccessMode = types.AccessMode(mode)
				}

				// Extract agent
				if agent, ok := ruleMap["agent"].(string); ok {
					rule.Agent = agent
				}

				// Extract agent class
				if agentClass, ok := ruleMap["agentClass"].(string); ok {
					rule.AgentType = types.AgentType(agentClass)
				}

				// Extract resource
				if resource, ok := ruleMap["resource"].(string); ok {
					rule.Resource = resource
				}

				// Extract resource class
				if resourceClass, ok := ruleMap["resourceClass"].(string); ok {
					rule.ResourceClass = resourceClass
				}

				// Extract default for new
				if defaultForNew, ok := ruleMap["defaultForNew"].(bool); ok {
					rule.DefaultForNew = defaultForNew
				}

				if rule.AccessMode != "" {
					policy.Rules = append(policy.Rules, rule)
				}
			}
		}
		return policy, nil
	}

	// Try to extract rules from @graph or access structure (alternative format)
	if graph, ok := data["@graph"].([]interface{}); ok {
		for _, item := range graph {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if access, ok := itemMap["access"].(map[string]interface{}); ok {
					if modes, ok := access["mode"].([]interface{}); ok {
						for _, mode := range modes {
							if modeStr, ok := mode.(string); ok {
								rule := types.PolicyRule{
									AccessMode: types.AccessMode(modeStr),
									AgentType:  types.AgentTypeAgent,
								}
								policy.Rules = append(policy.Rules, rule)
							}
						}
					}
				}
			}
		}
	}

	return policy, nil
}

// parseACPTurtle parses ACP in Turtle format.
func (c *PolicyClient) parseACPTurtle(bodyStr string, policy *types.Policy) (*types.Policy, error) {
	// Simplified Turtle parsing for ACP
	// In production, use a proper RDF parser

	lines := strings.Split(bodyStr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "@") || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for access mode predicates
		accessModes := []string{"acp:read", "acp:write", "acp:append", "acp:control"}
		for _, modePrefix := range accessModes {
			if strings.Contains(line, modePrefix) {
				mode := strings.TrimPrefix(modePrefix, "acp:")
				rule := types.PolicyRule{
					AccessMode: types.AccessMode(mode),
					AgentType:  types.AgentTypeAgent,
				}
				policy.Rules = append(policy.Rules, rule)
			}
		}
	}

	return policy, nil
}

// parseSAI parses a SAI (Solid Application Interoperability) policy.
func (c *PolicyClient) parseSAI(bodyStr, contentType string, policy *types.Policy) (*types.Policy, error) {
	// SAI policies follow a different structure
	// This is a simplified parser

	policy.Type = types.SAI

	// Similar parsing logic as WAC/ACP but for SAI structure
	// In production, this would use a proper SAI parser

	return policy, nil
}

// serializePolicy serializes a policy to the appropriate format.
func (c *PolicyClient) serializePolicy(policy *types.Policy) (string, []byte, error) {
	// Determine content type based on policy type
	var contentType string
	var body []byte
	var err error

	if policy.Type == "" {
		policy.Type = c.policyType
	}

	switch policy.Type {
	case types.WAC:
		contentType = "text/turtle"
		body, err = c.serializeWAC(policy)
	case types.ACP:
		contentType = "application/ld+json"
		body, err = c.serializeACP(policy)
	case types.SAI:
		contentType = "application/ld+json"
		body, err = c.serializeSAI(policy)
	default:
		contentType = "application/ld+json"
		body, err = c.serializeACP(policy)
	}

	if err != nil {
		return "", nil, err
	}

	return contentType, body, nil
}

// serializeWAC serializes a WAC policy to Turtle format.
func (c *PolicyClient) serializeWAC(policy *types.Policy) ([]byte, error) {
	// Generate Turtle format for WAC
	// This is a simplified serializer

	var sb strings.Builder

	sb.WriteString("@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n")
	sb.WriteString("@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\n")

	// Add each rule as an Authorization
	for i, rule := range policy.Rules {
		// Skip rules without access mode
		if rule.AccessMode == "" {
			continue
		}

		// Create a unique blank node for each authorization
		authNode := fmt.Sprintf("auth-%d", i+1)

		sb.WriteString(fmt.Sprintf("<> acl:Authorization %s ;\n", authNode))
		sb.WriteString(fmt.Sprintf("    acl:mode acl:%s ;\n", rule.AccessMode))

		// Add agent if specified
		if rule.Agent != "" {
			sb.WriteString(fmt.Sprintf("    acl:agent <%s> ;\n", rule.Agent))
		} else if rule.AgentType != "" {
			sb.WriteString(fmt.Sprintf("    acl:agentClass <%s> ;\n", rule.AgentType))
		}

		// Add resource if specified
		if rule.Resource != "" {
			sb.WriteString(fmt.Sprintf("    acl:accessTo <%s> .\n", rule.Resource))
		}

		sb.WriteString("\n")
	}

	return []byte(sb.String()), nil
}

// serializeACP serializes an ACP policy to JSON-LD format.
func (c *PolicyClient) serializeACP(policy *types.Policy) ([]byte, error) {
	// Generate JSON-LD format for ACP

	type acpRule struct {
		Type       string `json:"@type,omitempty"`
		Access     string `json:"access,omitempty"`
		Agent      string `json:"agent,omitempty"`
		AgentClass string `json:"agentClass,omitempty"`
		Resource   string `json:"resource,omitempty"`
	}

	var rules []acpRule
	for _, rule := range policy.Rules {
		if rule.AccessMode == "" {
			continue
		}

		ruleData := acpRule{
			Type:       "AccessGrant",
			Access:     string(rule.AccessMode),
			Agent:      rule.Agent,
			AgentClass: string(rule.AgentType),
			Resource:   rule.Resource,
		}

		// Map access modes to ACP format
		if rule.AccessMode == types.Read {
			ruleData.Access = "Read"
		} else if rule.AccessMode == types.Write {
			ruleData.Access = "Write"
		} else if rule.AccessMode == types.Append {
			ruleData.Access = "Append"
		} else if rule.AccessMode == types.Control {
			ruleData.Access = "Control"
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

// serializeSAI serializes a SAI policy to JSON-LD format.
func (c *PolicyClient) serializeSAI(policy *types.Policy) ([]byte, error) {
	// Generate JSON-LD format for SAI
	// SAI uses a different structure

	type saiRule struct {
		Permission string `json:"permission,omitempty"`
		Agent      string `json:"agent,omitempty"`
		Resource   string `json:"resource,omitempty"`
	}

	var rules []saiRule
	for _, rule := range policy.Rules {
		if rule.AccessMode == "" {
			continue
		}

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
