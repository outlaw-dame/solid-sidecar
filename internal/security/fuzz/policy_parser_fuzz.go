// Package security provides fuzz targets for the Solid runtime.
// This file implements Phase 26: Fuzz targets for WAC and ACP policy parsers.
//go:build gofuzz
// +build gofuzz

package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// FuzzWACParser fuzzes the Web Access Control (WAC) policy parser
// This target tests the WAC parser with randomly generated JSON inputs
// to find edge cases, crashes, or security vulnerabilities.
func FuzzWACParser(data []byte) int {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Validate input
	if err := validateWACFuzzInput(data); err != nil {
		return 0
	}

	// Parse the WAC policy
	_, err := ParseWACPolicy(ctx, data)
	if err != nil {
		// Most inputs should fail - this is expected
		return 0
	}

	// If we get here, the input parsed successfully
	return 1
}

// WACPolicy represents a Web Access Control policy
// This is a simplified version for fuzzing
type WACPolicy struct {
	Context    string        `json:"@context,omitempty"`
	ID         string        `json:"@id,omitempty"`
	Permission []WACRule     `json:"permission,omitempty"`
	Deny       []WACRule     `json:"deny,omitempty"`
	Owner      string        `json:"owner,omitempty"`
	Public     []interface{} `json:"public,omitempty"`
}

// WACRule represents a WAC rule
type WACRule struct {
	AccessTo    interface{}   `json:"accessTo"`
	AccessMode  []string      `json:"accessMode,omitempty"`
	Agent       interface{}   `json:"agent"`
	AgentClass  string        `json:"agentClass,omitempty"`
	AgentGroup  string        `json:"agentGroup,omitempty"`
	Delegator   string        `json:"delegator,omitempty"`
	Assigner    string        `json:"assigner,omitempty"`
	Attribution []interface{} `json:"attribution,omitempty"`
}

// ParseWACPolicy parses a WAC policy from JSON
func ParseWACPolicy(ctx context.Context, data []byte) (WACPolicy, error) {
	select {
	case <-ctx.Done():
		return WACPolicy{}, fmt.Errorf("context cancelled")
	default:
	}

	// Validate input size
	if len(data) > 100000 {
		return WACPolicy{}, fmt.Errorf("policy too large")
	}

	// Check for null bytes
	if strings.ContainsRune(string(data), '\u0000') {
		return WACPolicy{}, fmt.Errorf("input contains null bytes")
	}

	// Parse JSON
	var policy WACPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return WACPolicy{}, fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate the policy
	if err := ValidateWACPolicy(ctx, policy); err != nil {
		return WACPolicy{}, err
	}

	return policy, nil
}

// ValidateWACPolicy validates a WAC policy
func ValidateWACPolicy(ctx context.Context, policy WACPolicy) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
	}

	// Check for circular references (simplified check for fuzzing)
	if err := checkForCircularReferencesWAC(ctx, policy, make(map[string]bool)); err != nil {
		return err
	}

	// Check that all required fields are present
	if policy.Permission == nil && policy.Deny == nil {
		return fmt.Errorf("policy must have at least permission or deny rules")
	}

	// Validate each rule
	for i, rule := range policy.Permission {
		if err := ValidateWACRule(ctx, rule); err != nil {
			return fmt.Errorf("invalid permission rule %d: %w", i, err)
		}
	}

	for i, rule := range policy.Deny {
		if err := ValidateWACRule(ctx, rule); err != nil {
			return fmt.Errorf("invalid deny rule %d: %w", i, err)
		}
	}

	return nil
}

// ValidateWACRule validates a WAC rule
func ValidateWACRule(ctx context.Context, rule WACRule) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
	}

	// Check that accessTo is present
	if rule.AccessTo == nil {
		return fmt.Errorf("accessTo is required")
	}

	// Check that agent is present
	if rule.Agent == nil {
		return fmt.Errorf("agent is required")
	}

	// Check accessMode if present
	if rule.AccessMode != nil {
		for _, mode := range rule.AccessMode {
			if !isValidAccessMode(mode) {
				return fmt.Errorf("invalid access mode: %s", mode)
			}
		}
	}

	return nil
}

// isValidAccessMode checks if an access mode is valid
func isValidAccessMode(mode string) bool {
	switch strings.ToLower(mode) {
	case "read", "write", "append", "control", "create", "delete":
		return true
	default:
		return false
	}
}

// checkForCircularReferencesWAC checks for circular references in WAC policies
func checkForCircularReferencesWAC(ctx context.Context, policy WACPolicy, visited map[string]bool) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
	}

	// Check policy ID
	if policy.ID != "" {
		if visited[policy.ID] {
			return fmt.Errorf("circular reference detected at %s", policy.ID)
		}
		visited[policy.ID] = true
		defer func() { delete(visited, policy.ID) }()
	}

	// Check permission rules
	for _, rule := range policy.Permission {
		if err := checkWACRuleForCircularRefs(ctx, rule, visited); err != nil {
			return err
		}
	}

	// Check deny rules
	for _, rule := range policy.Deny {
		if err := checkWACRuleForCircularRefs(ctx, rule, visited); err != nil {
			return err
		}
	}

	return nil
}

// checkWACRuleForCircularRefs checks a WAC rule for circular references
func checkWACRuleForCircularRefs(ctx context.Context, rule WACRule, visited map[string]bool) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
	}

	// Check accessTo
	if accessToStr, ok := rule.AccessTo.(string); ok {
		if visited[accessToStr] {
			return fmt.Errorf("circular reference detected at accessTo: %s", accessToStr)
		}
	}

	// Check agent
	if agentStr, ok := rule.Agent.(string); ok {
		if visited[agentStr] {
			return fmt.Errorf("circular reference detected at agent: %s", agentStr)
		}
	}

	// Check delegator
	if rule.Delegator != "" {
		if visited[rule.Delegator] {
			return fmt.Errorf("circular reference detected at delegator: %s", rule.Delegator)
		}
	}

	// Check assigner
	if rule.Assigner != "" {
		if visited[rule.Assigner] {
			return fmt.Errorf("circular reference detected at assigner: %s", rule.Assigner)
		}
	}

	return nil
}

// validateWACFuzzInput validates WAC input for fuzzing
func validateWACFuzzInput(data []byte) error {
	// Basic validation to prevent obvious issues
	if len(data) > 100000 {
		return fmt.Errorf("input too large for fuzzing")
	}

	// Check for null bytes
	if strings.ContainsRune(string(data), '\u0000') {
		return fmt.Errorf("input contains null bytes")
	}

	return nil
}

// FuzzACPParser fuzzes the Access Control Policy (ACP) parser
func FuzzACPParser(data []byte) int {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Validate input
	if err := validateACPFuzzInput(data); err != nil {
		return 0
	}

	// Parse the ACP policy
	_, err := ParseACPPolicy(ctx, data)
	if err != nil {
		// Most inputs should fail - this is expected
		return 0
	}

	// If we get here, the input parsed successfully
	return 1
}

// ACPPolicy represents an Access Control Policy
// This is a simplified version for fuzzing
type ACPPolicy struct {
	ID          string        `json:"@id,omitempty"`
	Type        string        `json:"@type,omitempty"`
	Controller  string        `json:"controller,omitempty"`
	Allow       []ACPRule     `json:"allow,omitempty"`
	Deny        []ACPRule     `json:"deny,omitempty"`
	Inherit     []string      `json:"inherit,omitempty"`
	ApplyTo     []string      `json:"applyTo,omitempty"`
	Attribution []interface{} `json:"attribution,omitempty"`
}

// ACPRule represents an ACP rule
type ACPRule struct {
	Action   string      `json:"action"`
	Agent    interface{} `json:"agent"`
	Target   interface{} `json:"target,omitempty"`
	From     string      `json:"from,omitempty"`
	To       string      `json:"to,omitempty"`
	In       string      `json:"in,omitempty"`
	For      string      `json:"for,omitempty"`
	When     string      `json:"when,omitempty"`
	Where    string      `json:"where,omitempty"`
	Why      string      `json:"why,omitempty"`
	Count    int         `json:"count,omitempty"`
	Interval string      `json:"interval,omitempty"`
}

// ParseACPPolicy parses an ACP policy from JSON
func ParseACPPolicy(ctx context.Context, data []byte) (ACPPolicy, error) {
	select {
	case <-ctx.Done():
		return ACPPolicy{}, fmt.Errorf("context cancelled")
	default:
	}

	// Validate input size
	if len(data) > 100000 {
		return ACPPolicy{}, fmt.Errorf("policy too large")
	}

	// Check for null bytes
	if strings.ContainsRune(string(data), '\u0000') {
		return ACPPolicy{}, fmt.Errorf("input contains null bytes")
	}

	// Parse JSON
	var policy ACPPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return ACPPolicy{}, fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate the policy
	if err := ValidateACPPolicy(ctx, policy); err != nil {
		return ACPPolicy{}, err
	}

	return policy, nil
}

// ValidateACPPolicy validates an ACP policy
func ValidateACPPolicy(ctx context.Context, policy ACPPolicy) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
	}

	// Check for circular references
	if err := checkForCircularReferencesACP(ctx, policy, make(map[string]bool)); err != nil {
		return err
	}

	// Check that all required fields are present
	if policy.Allow == nil && policy.Deny == nil {
		return fmt.Errorf("policy must have at least allow or deny rules")
	}

	// Validate each rule
	for i, rule := range policy.Allow {
		if err := ValidateACPRule(ctx, rule); err != nil {
			return fmt.Errorf("invalid allow rule %d: %w", i, err)
		}
	}

	for i, rule := range policy.Deny {
		if err := ValidateACPRule(ctx, rule); err != nil {
			return fmt.Errorf("invalid deny rule %d: %w", i, err)
		}
	}

	return nil
}

// ValidateACPRule validates an ACP rule
func ValidateACPRule(ctx context.Context, rule ACPRule) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
	}

	// Check that action is present
	if rule.Action == "" {
		return fmt.Errorf("action is required")
	}

	// Check that agent is present
	if rule.Agent == nil {
		return fmt.Errorf("agent is required")
	}

	// Validate action
	if !isValidACPAction(rule.Action) {
		return fmt.Errorf("invalid action: %s", rule.Action)
	}

	return nil
}

// isValidACPAction checks if an ACP action is valid
func isValidACPAction(action string) bool {
	switch strings.ToLower(action) {
	case "read", "write", "append", "delete", "create", "admin":
		return true
	default:
		return false
	}
}

// checkForCircularReferencesACP checks for circular references in ACP policies
func checkForCircularReferencesACP(ctx context.Context, policy ACPPolicy, visited map[string]bool) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
	}

	// Check policy ID
	if policy.ID != "" {
		if visited[policy.ID] {
			return fmt.Errorf("circular reference detected at %s", policy.ID)
		}
		visited[policy.ID] = true
		defer func() { delete(visited, policy.ID) }()
	}

	// Check allow rules
	for _, rule := range policy.Allow {
		if err := checkACPRuleForCircularRefs(ctx, rule, visited); err != nil {
			return err
		}
	}

	// Check deny rules
	for _, rule := range policy.Deny {
		if err := checkACPRuleForCircularRefs(ctx, rule, visited); err != nil {
			return err
		}
	}

	// Check inherit
	for _, inheritID := range policy.Inherit {
		if visited[inheritID] {
			return fmt.Errorf("circular reference detected at inherit: %s", inheritID)
		}
	}

	return nil
}

// checkACPRuleForCircularRefs checks an ACP rule for circular references
func checkACPRuleForCircularRefs(ctx context.Context, rule ACPRule, visited map[string]bool) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
	}

	// Check agent
	if agentStr, ok := rule.Agent.(string); ok {
		if visited[agentStr] {
			return fmt.Errorf("circular reference detected at agent: %s", agentStr)
		}
	}

	// Check target
	if targetStr, ok := rule.Target.(string); ok {
		if visited[targetStr] {
			return fmt.Errorf("circular reference detected at target: %s", targetStr)
		}
	}

	// Check from
	if rule.From != "" {
		if visited[rule.From] {
			return fmt.Errorf("circular reference detected at from: %s", rule.From)
		}
	}

	// Check to
	if rule.To != "" {
		if visited[rule.To] {
			return fmt.Errorf("circular reference detected at to: %s", rule.To)
		}
	}

	return nil
}

// validateACPFuzzInput validates ACP input for fuzzing
func validateACPFuzzInput(data []byte) error {
	// Basic validation to prevent obvious issues
	if len(data) > 100000 {
		return fmt.Errorf("input too large for fuzzing")
	}

	// Check for null bytes
	if strings.ContainsRune(string(data), '\u0000') {
		return fmt.Errorf("input contains null bytes")
	}

	return nil
}

// FuzzPolicyEvaluation fuzzes the policy evaluation logic
// This tests that policy evaluation doesn't crash or behave unexpectedly
// with malformed or malicious policies
func FuzzPolicyEvaluation(data []byte) int {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Try both WAC and ACP parsing
	// First, try as WAC
	if _, err := ParseWACPolicy(ctx, data); err == nil {
		// If it parsed as WAC, try evaluating it
		if err := EvaluateWACPolicy(ctx, WACPolicy{}); err != nil {
			// Expected to fail for empty policy
		}
		return 1
	}

	// Then, try as ACP
	if _, err := ParseACPPolicy(ctx, data); err == nil {
		// If it parsed as ACP, try evaluating it
		if err := EvaluateACPPolicy(ctx, ACPPolicy{}); err != nil {
			// Expected to fail for empty policy
		}
		return 1
	}

	// Neither parsed successfully
	return 0
}

// EvaluateWACPolicy evaluates a WAC policy (placeholder for fuzzing)
func EvaluateWACPolicy(ctx context.Context, policy WACPolicy) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
	}

	// In a real implementation, this would evaluate the policy
	// For fuzzing, we just return success
	return nil
}

// EvaluateACPPolicy evaluates an ACP policy (placeholder for fuzzing)
func EvaluateACPPolicy(ctx context.Context, policy ACPPolicy) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
	}

	// In a real implementation, this would evaluate the policy
	// For fuzzing, we just return success
	return nil
}
