// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 5: Policy engine layer.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// PolicyEngineLayer implements Layer 5: Policy engine
// This layer provides authorization policy evaluation for the Solid runtime.
//
// Key principles:
// - Fixture-backed policy evaluation (deterministic, testable)
// - Support for WAC, ACP, and SAI policy formats
// - Shadow mode operation until enforcement is enabled
// - Privacy-safe policy evaluation (no policy body leakage)
// - Efficient policy caching and invalidation
type PolicyEngineLayer struct {
	mu sync.RWMutex

	config PolicyEngineConfig

	// Policy store (URI -> policy document)
	policies map[string]*PolicyDocument

	// Policy evaluation cache
	evaluationCache map[string]*PolicyEvaluationResult

	// Policy statistics
	metrics PolicyEngineMetrics

	// Logger
	logger *slog.Logger

	// Close state
	closeChan chan struct{}
	closed    bool
}

// PolicyEngineConfig holds configuration for the policy engine layer
type PolicyEngineConfig struct {
	// ShadowMode determines if policy evaluation is in shadow mode
	ShadowMode bool

	// MaxPolicySize is the maximum size of a policy document in bytes
	MaxPolicySize int

	// MaxCacheSize is the maximum number of cached evaluation results
	MaxCacheSize int

	// CacheTTL is the time-to-live for cached evaluations
	CacheTTL time.Duration

	// EnableACPSupport enables ACP policy evaluation
	EnableACPSupport bool

	// EnableSAISupport enables SAI policy evaluation
	EnableSAISupport bool

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultPolicyEngineConfig returns a safe default configuration
func DefaultPolicyEngineConfig() PolicyEngineConfig {
	return PolicyEngineConfig{
		ShadowMode:       true,        // Always start in shadow mode
		MaxPolicySize:    1024 * 1024, // 1MB
		MaxCacheSize:     1000,
		CacheTTL:         5 * time.Minute,
		EnableACPSupport: true,
		EnableSAISupport: true,
		Logger:           nil,
	}
}

// PolicyEngineMetrics holds metrics for the policy engine layer
type PolicyEngineMetrics struct {
	mu sync.RWMutex

	// Policy operations
	TotalEvaluations int64
	CacheHits        int64
	CacheMisses      int64

	// Policy types
	WACEvaluations int64
	ACPEvaluations int64
	SAIEvaluations int64

	// Results
	AllowResults   int64
	DenyResults    int64
	AbstainResults int64

	// Shadow mode results
	ShadowAllows   int64
	ShadowDenies   int64
	ShadowAbstains int64
}

// RecordEvaluation records a policy evaluation
func (m *PolicyEngineMetrics) RecordEvaluation(policyType string, result PolicyDecision, shadow bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalEvaluations++

	switch policyType {
	case "WAC":
		m.WACEvaluations++
	case "ACP":
		m.ACPEvaluations++
	case "SAI":
		m.SAIEvaluations++
	}

	switch result {
	case PolicyDecisionAllow:
		m.AllowResults++
		if shadow {
			m.ShadowAllows++
		}
	case PolicyDecisionDeny:
		m.DenyResults++
		if shadow {
			m.ShadowDenies++
		}
	case PolicyDecisionAbstain:
		m.AbstainResults++
		if shadow {
			m.ShadowAbstains++
		}
	}
}

// RecordCacheHit records a cache hit
func (m *PolicyEngineMetrics) RecordCacheHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheHits++
}

// RecordCacheMiss records a cache miss
func (m *PolicyEngineMetrics) RecordCacheMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheMisses++
}

// PolicyDecision represents the result of a policy evaluation
type PolicyDecision string

const (
	PolicyDecisionAllow   PolicyDecision = "allow"
	PolicyDecisionDeny    PolicyDecision = "deny"
	PolicyDecisionAbstain PolicyDecision = "abstain"
	PolicyDecisionUnknown PolicyDecision = "unknown"
)

// PolicyDocument represents a parsed policy document
type PolicyDocument struct {
	// URI is the policy document URI
	URI string

	// Format is the policy format (WAC, ACP, SAI)
	Format PolicyFormat

	// RawContent is the raw content of the policy document
	RawContent []byte

	// ContentType is the MIME type of the policy document
	ContentType string

	// ParsedRules are the parsed policy rules
	ParsedRules []PolicyRule

	// Hash is a content hash for cache invalidation
	Hash string

	// LastModified is when the policy was last modified
	LastModified time.Time

	// Valid indicates if the policy was successfully parsed
	Valid bool

	// ParseError contains any parsing error
	ParseError error
}

// PolicyFormat represents supported policy formats
type PolicyFormat string

const (
	PolicyFormatWAC     PolicyFormat = "WAC"
	PolicyFormatACP     PolicyFormat = "ACP"
	PolicyFormatSAI     PolicyFormat = "SAI"
	PolicyFormatUnknown PolicyFormat = "Unknown"
)

// PolicyRule represents a single policy rule
type PolicyRule struct {
	// RuleType is the type of rule (grant, deny, etc.)
	RuleType string

	// Agent is the agent this rule applies to
	Agent string

	// AgentType is the type of agent (WebID, group, class, etc.)
	AgentType PolicyAgentType

	// AccessModes are the access modes granted/denied
	AccessModes []AccessMode

	// Resource is the resource this rule applies to
	Resource string

	// Conditions are additional conditions for the rule
	Conditions []PolicyCondition

	// ValidFrom is when the rule becomes valid
	ValidFrom time.Time

	// ValidUntil is when the rule expires
	ValidUntil time.Time
}

// PolicyAgentType represents the type of agent in a policy rule
type PolicyAgentType string

const (
	PolicyAgentTypeWebID         PolicyAgentType = "WebID"
	PolicyAgentTypeGroup         PolicyAgentType = "Group"
	PolicyAgentTypeClass         PolicyAgentType = "Class"
	PolicyAgentTypeAgent         PolicyAgentType = "Agent"
	PolicyAgentTypePublic        PolicyAgentType = "Public"
	PolicyAgentTypeAuthenticated PolicyAgentType = "Authenticated"
)

// AccessMode represents the type of access granted/denied
type AccessMode string

const (
	AccessModeRead    AccessMode = "Read"
	AccessModeWrite   AccessMode = "Write"
	AccessModeAppend  AccessMode = "Append"
	AccessModeControl AccessMode = "Control"
	AccessModeAll     AccessMode = "All"
)

// PolicyCondition represents a condition for a policy rule
type PolicyCondition struct {
	// Type is the type of condition
	Type string

	// Value is the condition value
	Value string

	// Operator is the condition operator
	Operator string
}

// PolicyEvaluationContext represents the context for policy evaluation
type PolicyEvaluationContext struct {
	// RequestURI is the URI being accessed
	RequestURI string

	// Method is the HTTP method (GET, POST, etc.)
	Method string

	// Agent is the agent making the request
	Agent string

	// AgentType is the type of the agent
	AgentType PolicyAgentType

	// ClientID is the client identifier
	ClientID string

	// ResourceType is the type of the resource being accessed
	ResourceType string

	// Container is the container containing the resource
	Container string

	// Timestamp is when the evaluation is being performed
	Timestamp time.Time
}

// PolicyEvaluationResult represents the result of a policy evaluation
type PolicyEvaluationResult struct {
	// Decision is the final access decision
	Decision PolicyDecision

	// RulesEvaluated is the number of rules evaluated
	RulesEvaluated int

	// MatchingRules are the rules that matched the request
	MatchingRules []*PolicyRule

	// AllowingRules are the rules that allow access
	AllowingRules []*PolicyRule

	// DenyingRules are the rules that deny access
	DenyingRules []*PolicyRule

	// Shadow indicates if this evaluation was in shadow mode
	Shadow bool

	// PolicyURIs are the URIs of policies that were evaluated
	PolicyURIs []string

	// EvaluationTimestamp is when the evaluation was performed
	EvaluationTimestamp time.Time

	// CacheKey is the cache key for this evaluation
	CacheKey string

	// Explanation provides a human-readable explanation of the decision
	Explanation string
}

// NewPolicyEngineLayer creates a new policy engine layer
func NewPolicyEngineLayer(config PolicyEngineConfig) *PolicyEngineLayer {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	layer := &PolicyEngineLayer{
		config:          config,
		policies:        make(map[string]*PolicyDocument),
		evaluationCache: make(map[string]*PolicyEvaluationResult),
		logger:          config.Logger,
		closeChan:       make(chan struct{}),
		closed:          false,
		metrics:         PolicyEngineMetrics{},
	}

	config.Logger.Info("Policy engine layer initialized",
		"shadow_mode", config.ShadowMode,
		"max_policy_size", config.MaxPolicySize,
		"max_cache_size", config.MaxCacheSize,
		"cache_ttl", config.CacheTTL,
		"enable_acp", config.EnableACPSupport,
		"enable_sai", config.EnableSAISupport,
	)

	return layer
}

// LoadPolicy loads a policy document from content
func (p *PolicyEngineLayer) LoadPolicy(ctx context.Context, uri string, content []byte, contentType string) (*PolicyDocument, error) {
	// Validate URI to prevent injection attacks and path traversal
	if err := ValidateURI(uri); err != nil {
		return nil, fmt.Errorf("invalid policy URI: %w", err)
	}
	
	// Validate content type to prevent injection
	if err := ValidateContentType(contentType); err != nil {
		return nil, fmt.Errorf("invalid content type: %w", err)
	}
	
	// Validate content size to prevent DoS attacks
	if err := ValidateResourceSize(int64(len(content))); err != nil {
		return nil, fmt.Errorf("policy content validation failed: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, errors.New("policy engine layer is closed")
	}

	// Check size limits (additional layer-specific limit)
	if len(content) > p.config.MaxPolicySize {
		return nil, fmt.Errorf("policy exceeds maximum size: %d > %d", len(content), p.config.MaxPolicySize)
	}

	// Detect format
	format := detectPolicyFormat(uri, contentType, content)

	// Create policy document
	policy := &PolicyDocument{
		URI:          uri,
		Format:       format,
		RawContent:   content,
		ContentType:  contentType,
		LastModified: time.Now().UTC(),
		Hash:         hashContent(content),
	}

	// Parse based on format
	var parseErr error
	policy.ParsedRules, parseErr = p.parsePolicy(format, uri, content)

	if parseErr != nil {
		policy.Valid = false
		policy.ParseError = parseErr
		p.logger.Warn("Policy parsing failed",
			"uri", uri,
			"format", format,
			"error", parseErr,
		)
	} else {
		policy.Valid = true
		p.logger.Debug("Policy loaded and parsed",
			"uri", uri,
			"format", format,
			"rule_count", len(policy.ParsedRules),
		)
	}

	// Store the policy
	p.policies[uri] = policy

	// Invalidate cache for this policy
	p.invalidatePolicyCache(uri)

	return policy, nil
}

// detectPolicyFormat detects the policy format from URI, content type, and content
func detectPolicyFormat(uri string, contentType string, content []byte) PolicyFormat {
	contentType = strings.ToLower(contentType)
	uri = strings.ToLower(uri)

	// Check by content type
	switch {
	case strings.Contains(contentType, "acl"):
		return PolicyFormatWAC
	case strings.Contains(contentType, "access"):
		return PolicyFormatACP
	case strings.Contains(contentType, "sai"):
		return PolicyFormatSAI
	}

	// Check by URI
	if strings.Contains(uri, ".acl") || strings.Contains(uri, "acl") {
		return PolicyFormatWAC
	}
	if strings.Contains(uri, ".access") || strings.Contains(uri, "access") {
		return PolicyFormatACP
	}
	if strings.Contains(uri, ".sai") || strings.Contains(uri, "sai") {
		return PolicyFormatSAI
	}

	// Check content for WAC patterns
	contentStr := string(content)
	if strings.Contains(contentStr, "acl:Authorization") || strings.Contains(contentStr, "acl:accessTo") {
		return PolicyFormatWAC
	}
	if strings.Contains(contentStr, "acp:AccessControl") || strings.Contains(contentStr, "acp:Policy") {
		return PolicyFormatACP
	}
	if strings.Contains(contentStr, "sai:") || strings.Contains(contentStr, "SolidAuthorization") {
		return PolicyFormatSAI
	}

	// Default to WAC for Solid
	return PolicyFormatWAC
}

// parsePolicy parses a policy document based on its format
func (p *PolicyEngineLayer) parsePolicy(format PolicyFormat, uri string, content []byte) ([]PolicyRule, error) {
	var rules []PolicyRule
	var err error

	switch format {
	case PolicyFormatWAC:
		rules, err = p.parseWAC(uri, content)
	case PolicyFormatACP:
		if p.config.EnableACPSupport {
			rules, err = p.parseACP(uri, content)
		} else {
			return nil, fmt.Errorf("ACP support is disabled")
		}
	case PolicyFormatSAI:
		if p.config.EnableSAISupport {
			rules, err = p.parseSAI(uri, content)
		} else {
			return nil, fmt.Errorf("SAI support is disabled")
		}
	default:
		return nil, fmt.Errorf("unsupported policy format: %s", format)
	}

	return rules, err
}

// parseWAC parses a WAC policy document
func (p *PolicyEngineLayer) parseWAC(uri string, content []byte) ([]PolicyRule, error) {
	// Simplified WAC parser for demonstration
	// In production, this would use the Rust parser boundary or a proper WAC parser

	var rules []PolicyRule
	contentStr := string(content)

	// Look for common WAC patterns
	// This is a very basic implementation - real parsing would be much more sophisticated

	// Check if this looks like a valid WAC document
	if !strings.Contains(contentStr, "acl:Authorization") {
		p.logger.Warn("WAC document may be invalid", "uri", uri)
	}

	// Extract rules based on common patterns
	// This would be replaced with proper RDF parsing
	lines := strings.Split(contentStr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Very basic pattern matching (demonstration only)
		if strings.Contains(line, "acl:agent") || strings.Contains(line, "acl:agentClass") {
			var rule PolicyRule

			// Determine agent type
			if strings.Contains(line, "acl:agentClass") {
				rule.AgentType = PolicyAgentTypeClass
			} else if strings.Contains(line, "acl:agentGroup") {
				rule.AgentType = PolicyAgentTypeGroup
			} else {
				rule.AgentType = PolicyAgentTypeWebID
			}

			// Extract agent (simplified)
			if strings.Contains(line, "<") && strings.Contains(line, ">") {
				start := strings.Index(line, "<")
				end := strings.LastIndex(line, ">")
				if start >= 0 && end > start {
					rule.Agent = line[start+1 : end]
				}
			}

			// Extract access modes (simplified)
			if strings.Contains(line, "acl:Read") {
				rule.AccessModes = append(rule.AccessModes, AccessModeRead)
			}
			if strings.Contains(line, "acl:Write") {
				rule.AccessModes = append(rule.AccessModes, AccessModeWrite)
			}
			if strings.Contains(line, "acl:Append") {
				rule.AccessModes = append(rule.AccessModes, AccessModeAppend)
			}
			if strings.Contains(line, "acl:Control") {
				rule.AccessModes = append(rule.AccessModes, AccessModeControl)
			}

			// Set resource
			rule.Resource = uri
			rule.RuleType = "grant"
			rule.ValidFrom = time.Now().UTC()

			// Only add if we have at least some information
			if rule.Agent != "" && len(rule.AccessModes) > 0 {
				rules = append(rules, rule)
			}
		}
	}

	return rules, nil
}

// parseACP parses an ACP policy document
func (p *PolicyEngineLayer) parseACP(uri string, content []byte) ([]PolicyRule, error) {
	// ACP parsing would go here
	// For now, return empty rules as ACP is not fully implemented yet
	p.logger.Warn("ACP parsing not fully implemented", "uri", uri)
	return []PolicyRule{}, nil
}

// parseSAI parses an SAI policy document
func (p *PolicyEngineLayer) parseSAI(uri string, content []byte) ([]PolicyRule, error) {
	// SAI parsing would go here
	// For now, return empty rules as SAI is not fully implemented yet
	p.logger.Warn("SAI parsing not fully implemented", "uri", uri)
	return []PolicyRule{}, nil
}

// hashContent creates a hash of content for cache invalidation
func hashContent(content []byte) string {
	if len(content) == 0 {
		return ""
	}
	// Simple hash for demonstration
	// In production, use proper cryptographic hash
	result := fmt.Sprintf("%d-%d", len(content), content[0])
	return result
}

// Evaluate evaluates access for a given context
func (p *PolicyEngineLayer) Evaluate(ctx context.Context, evaluationCtx *PolicyEvaluationContext) (*PolicyEvaluationResult, error) {
	if evaluationCtx == nil {
		return nil, errors.New("evaluation context cannot be nil")
	}

	// Validate all URIs and identifiers in the evaluation context
	if err := ValidateURI(evaluationCtx.RequestURI); err != nil {
		return nil, fmt.Errorf("invalid request URI: %w", err)
	}
	
	if evaluationCtx.Agent != "" {
		if err := ValidateWebID(evaluationCtx.Agent); err != nil {
			return nil, fmt.Errorf("invalid agent WebID: %w", err)
		}
	}
	
	if evaluationCtx.ClientID != "" {
		// Client IDs should be URIs
		if err := ValidateURI(evaluationCtx.ClientID); err != nil {
			return nil, fmt.Errorf("invalid client ID: %w", err)
		}
	}
	
	if evaluationCtx.ResourceType != "" {
		if err := ValidateContentType(evaluationCtx.ResourceType); err != nil {
			return nil, fmt.Errorf("invalid resource type: %w", err)
		}
	}
	
	if evaluationCtx.Container != "" {
		if err := ValidateContainerURI(evaluationCtx.Container); err != nil {
			return nil, fmt.Errorf("invalid container URI: %w", err)
		}
	}

	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, errors.New("policy engine layer is closed")
	}

	// Generate cache key
	cacheKey := p.generateCacheKey(evaluationCtx)

	// Check cache first
	if cached, ok := p.evaluationCache[cacheKey]; ok {
		p.metrics.RecordCacheHit()
		p.logger.Debug("Policy evaluation cache hit", "cache_key", cacheKey)
		return cached, nil
	}

	p.metrics.RecordCacheMiss()

	// Find applicable policies
	policies, err := p.findApplicablePolicies(evaluationCtx)
	if err != nil {
		return nil, fmt.Errorf("find applicable policies: %w", err)
	}

	// Initialize result
	result := &PolicyEvaluationResult{
		Decision:            PolicyDecisionAbstain,
		Shadow:              p.config.ShadowMode,
		PolicyURIs:          policies,
		EvaluationTimestamp: time.Now().UTC(),
		CacheKey:            cacheKey,
		Explanation:         "No matching rules found",
	}

	// Evaluate each applicable policy
	for _, policyURI := range policies {
		policy, exists := p.policies[policyURI]
		if !exists || !policy.Valid {
			continue
		}

		// Evaluate rules in this policy
		for i, rule := range policy.ParsedRules {
			result.RulesEvaluated++

			// Check if rule applies to this context
			if p.ruleApplies(&rule, evaluationCtx) {
				result.MatchingRules = append(result.MatchingRules, &policy.ParsedRules[i])

				// Check access modes
				for _, mode := range rule.AccessModes {
					if p.modeMatches(methodToAccessMode(evaluationCtx.Method), mode) {
						if rule.RuleType == "grant" || rule.RuleType == "allow" {
							result.AllowingRules = append(result.AllowingRules, &policy.ParsedRules[i])
						} else if rule.RuleType == "deny" {
							result.DenyingRules = append(result.DenyingRules, &policy.ParsedRules[i])
						}
					}
				}
			}
		}
	}

	// Determine final decision
	if len(result.AllowingRules) > 0 && len(result.DenyingRules) == 0 {
		result.Decision = PolicyDecisionAllow
		result.Explanation = "Access allowed by matching grant rules"
	} else if len(result.DenyingRules) > 0 {
		result.Decision = PolicyDecisionDeny
		result.Explanation = "Access denied by matching deny rules"
	} else {
		result.Decision = PolicyDecisionAbstain
		result.Explanation = "No matching rules found, abstaining"
	}

	// Record metrics - use WAC as default policy type for now
	policyType := "WAC"
	if len(result.PolicyURIs) > 0 {
		if policy, err := p.GetPolicy(result.PolicyURIs[0]); err == nil && policy != nil {
			policyType = string(policy.Format)
		}
	}
	p.metrics.RecordEvaluation(policyType, result.Decision, p.config.ShadowMode)

	// Cache the result
	p.cacheEvaluationResult(cacheKey, result)

	return result, nil
}

// ruleApplies checks if a rule applies to the given context
func (p *PolicyEngineLayer) ruleApplies(rule *PolicyRule, ctx *PolicyEvaluationContext) bool {
	// Check agent match
	if !p.agentMatches(rule, ctx) {
		return false
	}

	// Check resource match
	if rule.Resource != "" && rule.Resource != ctx.RequestURI {
		// Check if rule resource is a container of the request URI
		if !strings.HasSuffix(ctx.RequestURI, rule.Resource) && ctx.RequestURI != rule.Resource {
			return false
		}
	}

	// Check conditions
	for _, condition := range rule.Conditions {
		if !p.conditionMatches(&condition, ctx) {
			return false
		}
	}

	// Check time validity
	now := time.Now().UTC()
	if !rule.ValidFrom.IsZero() && now.Before(rule.ValidFrom) {
		return false
	}
	if !rule.ValidUntil.IsZero() && now.After(rule.ValidUntil) {
		return false
	}

	return true
}

// agentMatches checks if the agent in the rule matches the context agent
func (p *PolicyEngineLayer) agentMatches(rule *PolicyRule, ctx *PolicyEvaluationContext) bool {
	// Direct match
	if rule.Agent == ctx.Agent {
		return true
	}

	// Type-based matching
	switch rule.AgentType {
	case PolicyAgentTypePublic:
		return true // Public always matches
	case PolicyAgentTypeAuthenticated:
		return ctx.Agent != "" // Any authenticated user matches
	case PolicyAgentTypeClass:
		// Check if context agent is of this class
		// This would require additional logic to determine agent class
		return true // Simplified for now
	case PolicyAgentTypeGroup:
		// Check if context agent is in this group
		// This would require group membership checking
		return true // Simplified for now
	}

	return false
}

// conditionMatches checks if a condition matches the context
func (p *PolicyEngineLayer) conditionMatches(condition *PolicyCondition, ctx *PolicyEvaluationContext) bool {
	// Simple condition matching
	switch condition.Type {
	case "method":
		return strings.EqualFold(condition.Value, ctx.Method)
	case "resourceType":
		return strings.EqualFold(condition.Value, ctx.ResourceType)
	case "container":
		return strings.EqualFold(condition.Value, ctx.Container)
	default:
		return true // Unknown conditions pass by default
	}
}

// modeMatches checks if the request mode matches the rule mode
func (p *PolicyEngineLayer) modeMatches(requestMode AccessMode, ruleMode AccessMode) bool {
	// Direct match
	if requestMode == ruleMode {
		return true
	}

	// All matches everything
	if ruleMode == AccessModeAll {
		return true
	}

	// Specific mode matching
	switch ruleMode {
	case AccessModeRead:
		return requestMode == AccessModeRead || requestMode == AccessModeAll
	case AccessModeWrite:
		return requestMode == AccessModeWrite || requestMode == AccessModeAll
	case AccessModeAppend:
		return requestMode == AccessModeAppend || requestMode == AccessModeAll
	case AccessModeControl:
		return requestMode == AccessModeControl || requestMode == AccessModeAll
	}

	return false
}

// methodToAccessMode converts HTTP method to access mode
func methodToAccessMode(method string) AccessMode {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return AccessModeRead
	case "POST":
		return AccessModeAppend
	case "PUT", "PATCH":
		return AccessModeWrite
	case "DELETE":
		return AccessModeControl
	default:
		return AccessModeRead
	}
}

// findApplicablePolicies finds policies that apply to the given context
func (p *PolicyEngineLayer) findApplicablePolicies(ctx *PolicyEvaluationContext) ([]string, error) {
	var applicablePolicies []string

	// Look for policies that match the resource
	for policyURI := range p.policies {
		// Check if this policy applies to the resource
		if p.policyAppliesToResource(policyURI, ctx.RequestURI) {
			applicablePolicies = append(applicablePolicies, policyURI)
		}
	}

	return applicablePolicies, nil
}

// policyAppliesToResource checks if a policy applies to a resource
func (p *PolicyEngineLayer) policyAppliesToResource(policyURI string, resourceURI string) bool {
	// Direct match
	if policyURI == resourceURI {
		return true
	}

	// Container policies apply to their contents
	if strings.HasSuffix(resourceURI, policyURI) {
		// Make sure it's a proper container relationship
		container := extractContainerURI(resourceURI)
		if container == policyURI || strings.HasSuffix(container, policyURI) {
			return true
		}
	}

	// Check if policy URI is a container of the resource
	if strings.HasPrefix(resourceURI, policyURI) {
		return true
	}

	return false
}

// generateCacheKey generates a cache key for evaluation results
func (p *PolicyEngineLayer) generateCacheKey(ctx *PolicyEvaluationContext) string {
	// Create a hash-based cache key from the context
	key := fmt.Sprintf("%s|%s|%s|%s|%s",
		ctx.RequestURI,
		ctx.Method,
		ctx.Agent,
		ctx.AgentType,
		ctx.ResourceType,
	)
	return key
}

// cacheEvaluationResult caches an evaluation result
func (p *PolicyEngineLayer) cacheEvaluationResult(key string, result *PolicyEvaluationResult) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	// Check cache size limit
	if len(p.evaluationCache) >= p.config.MaxCacheSize {
		// Remove oldest entries (simple approach)
		for k := range p.evaluationCache {
			delete(p.evaluationCache, k)
			break
		}
	}

	p.evaluationCache[key] = result
	p.logger.Debug("Policy evaluation result cached", "cache_key", key)
}

// invalidatePolicyCache invalidates cache entries for a specific policy
func (p *PolicyEngineLayer) invalidatePolicyCache(policyURI string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	// In a more sophisticated implementation, we would track which cache entries
	// depend on which policies and only invalidate those
	// For now, we'll do a full cache invalidation
	p.evaluationCache = make(map[string]*PolicyEvaluationResult)
	p.logger.Debug("Policy cache invalidated")
}

// InvalidateAllCache invalidates all cached evaluation results
func (p *PolicyEngineLayer) InvalidateAllCache() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	p.evaluationCache = make(map[string]*PolicyEvaluationResult)
	p.logger.Info("All policy evaluation cache invalidated")
}

// GetMetrics returns the current metrics
func (p *PolicyEngineLayer) GetMetrics() *PolicyEngineMetrics {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return &p.metrics
}

// GetPolicy returns a policy by URI
func (p *PolicyEngineLayer) GetPolicy(uri string) (*PolicyDocument, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return nil, errors.New("policy engine layer is closed")
	}

	policy, exists := p.policies[uri]
	if !exists {
		return nil, fmt.Errorf("policy %q not found", uri)
	}

	// Return a copy for thread safety
	return p.copyPolicy(policy), nil
}

// copyPolicy creates a copy of a policy document
func (p *PolicyEngineLayer) copyPolicy(policy *PolicyDocument) *PolicyDocument {
	if policy == nil {
		return nil
	}

	copiedRules := make([]PolicyRule, len(policy.ParsedRules))
	for i, rule := range policy.ParsedRules {
		copiedConditions := make([]PolicyCondition, len(rule.Conditions))
		for j, condition := range rule.Conditions {
			copiedConditions[j] = PolicyCondition{
				Type:     condition.Type,
				Value:    condition.Value,
				Operator: condition.Operator,
			}
		}

		copiedAccessModes := make([]AccessMode, len(rule.AccessModes))
		copy(copiedAccessModes, rule.AccessModes)

		copiedRules[i] = PolicyRule{
			RuleType:    rule.RuleType,
			Agent:       rule.Agent,
			AgentType:   rule.AgentType,
			AccessModes: copiedAccessModes,
			Resource:    rule.Resource,
			Conditions:  copiedConditions,
			ValidFrom:   rule.ValidFrom,
			ValidUntil:  rule.ValidUntil,
		}
	}

	return &PolicyDocument{
		URI:          policy.URI,
		Format:       policy.Format,
		RawContent:   append([]byte(nil), policy.RawContent...),
		ContentType:  policy.ContentType,
		ParsedRules:  copiedRules,
		Hash:         policy.Hash,
		LastModified: policy.LastModified,
		Valid:        policy.Valid,
		ParseError:   policy.ParseError,
	}
}

// ListPolicies returns a list of all loaded policy URIs
func (p *PolicyEngineLayer) ListPolicies() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return []string{}
	}

	uris := make([]string, 0, len(p.policies))
	for uri := range p.policies {
		uris = append(uris, uri)
	}
	return uris
}

// RemovePolicy removes a policy from the engine
func (p *PolicyEngineLayer) RemovePolicy(uri string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return errors.New("policy engine layer is closed")
	}

	delete(p.policies, uri)
	p.invalidatePolicyCache(uri)
	p.logger.Info("Policy removed", "uri", uri)
	return nil
}

// Size returns the current number of policies and cache entries
func (p *PolicyEngineLayer) Size() (int, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.policies), len(p.evaluationCache)
}

// Close closes the policy engine layer
func (p *PolicyEngineLayer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	close(p.closeChan)

	// Clear all data
	p.policies = nil
	p.evaluationCache = nil

	p.logger.Info("Policy engine layer closed")
	return nil
}

// IsClosed returns true if the layer is closed
func (p *PolicyEngineLayer) IsClosed() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}
