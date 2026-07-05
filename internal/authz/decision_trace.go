package authz

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// DecisionReason represents the reason for an authorization decision
type DecisionReason string

const (
	// Allow reasons
	ReasonAllowedByPolicy       DecisionReason = "allowed_by_policy"
	ReasonAllowedByOwner        DecisionReason = "allowed_by_owner"
	ReasonAllowedByPublicAccess DecisionReason = "allowed_by_public_access"
	ReasonAllowedByACL          DecisionReason = "allowed_by_acl"
	ReasonAllowedByACP          DecisionReason = "allowed_by_acp"
	ReasonAllowedByWAC          DecisionReason = "allowed_by_wac"
	ReasonAllowedBySAI          DecisionReason = "allowed_by_sai"

	// Deny reasons
	ReasonDeniedByPolicy       DecisionReason = "denied_by_policy"
	ReasonDeniedNoMatchingRule DecisionReason = "denied_no_matching_rule"
	ReasonDeniedByOrigin       DecisionReason = "denied_by_origin"
	ReasonDeniedByMethod       DecisionReason = "denied_by_method"
	ReasonDeniedByResourceType DecisionReason = "denied_by_resource_type"
	ReasonDeniedByAgent        DecisionReason = "denied_by_agent"
	ReasonDeniedByACL          DecisionReason = "denied_by_acl"
	ReasonDeniedByACP          DecisionReason = "denied_by_acp"
	ReasonDeniedByWAC          DecisionReason = "denied_by_wac"
	ReasonDeniedBySAI          DecisionReason = "denied_by_sai"

	// Abstain reasons
	ReasonAbstainedParserError    DecisionReason = "abstained_parser_error"
	ReasonAbstainedNoPolicy       DecisionReason = "abstained_no_policy"
	ReasonAbstainedShadowMode     DecisionReason = "abstained_shadow_mode"
	ReasonAbstainedNotImplemented DecisionReason = "abstained_not_implemented"

	// Error reasons
	ReasonErrorInternal    DecisionReason = "error_internal"
	ReasonErrorTimeout     DecisionReason = "error_timeout"
	ReasonErrorPolicyFetch DecisionReason = "error_policy_fetch"
	ReasonErrorValidation  DecisionReason = "error_validation"
)

// DecisionTraceID is a unique identifier for tracking authorization decisions
type DecisionTraceID string

// traceIDCounter is used for generating unique trace IDs
var traceIDCounter uint64

// GenerateDecisionTraceID generates a unique trace ID for a decision
func GenerateDecisionTraceID() DecisionTraceID {
	// Generate random bytes for uniqueness
	var randomBytes [8]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		// Fallback to counter if random fails
		counter := atomic.AddUint64(&traceIDCounter, 1)
		return DecisionTraceID(fmt.Sprintf("trace-%d-%d", time.Now().UnixNano(), counter))
	}

	counter := atomic.AddUint64(&traceIDCounter, 1)
	return DecisionTraceID(fmt.Sprintf("trace-%x-%d-%d", randomBytes, time.Now().UnixNano(), counter))
}

// DecisionResult represents the result of an authorization decision
type DecisionResult string

const (
	DecisionResultAllow   DecisionResult = "allow"
	DecisionResultDeny    DecisionResult = "deny"
	DecisionResultAbstain DecisionResult = "abstain"
	DecisionResultError   DecisionResult = "error"
)

// AuthorizationDecision represents a complete authorization decision with traceability
type AuthorizationDecision struct {
	// TraceID is the unique identifier for this decision
	TraceID DecisionTraceID

	// Result is the decision result (allow, deny, abstain, error)
	Result DecisionResult

	// Reason is the primary reason for the decision
	Reason DecisionReason

	// ReasonDetail provides additional context about the reason
	ReasonDetail string

	// Resource is the resource URI being accessed
	Resource string

	// Method is the HTTP method
	Method string

	// Agent is the agent (WebID) making the request
	Agent string

	// Timestamp is when the decision was made
	Timestamp time.Time

	// PolicySource is the URI of the policy document used (if any)
	PolicySource string

	// PolicyVersion is the version of the policy document (if any)
	PolicyVersion string

	// StrictMode indicates whether strict fail-closed mode was used
	StrictMode bool

	// FallbackToCSS indicates whether CSS fallback was used
	FallbackToCSS bool

	// EnforcementMode is the current enforcement mode
	EnforcementMode EnforcementMode

	// AuthorityMode is the current authority mode
	AuthorityMode string
}

// NewAuthorizationDecision creates a new decision with traceability
func NewAuthorizationDecision() *AuthorizationDecision {
	return &AuthorizationDecision{
		TraceID:       GenerateDecisionTraceID(),
		Timestamp:     time.Now().UTC(),
		Result:        DecisionResultAbstain,
		Reason:        ReasonAbstainedNotImplemented,
		StrictMode:    true, // Default to strict (fail-closed)
		FallbackToCSS: false,
	}
}

// Allow sets the decision to allow with the given reason
func (d *AuthorizationDecision) Allow(reason DecisionReason, detail string) {
	d.Result = DecisionResultAllow
	d.Reason = reason
	d.ReasonDetail = detail
}

// Deny sets the decision to deny with the given reason
func (d *AuthorizationDecision) Deny(reason DecisionReason, detail string) {
	d.Result = DecisionResultDeny
	d.Reason = reason
	d.ReasonDetail = detail
}

// Abstain sets the decision to abstain with the given reason
func (d *AuthorizationDecision) Abstain(reason DecisionReason, detail string) {
	d.Result = DecisionResultAbstain
	d.Reason = reason
	d.ReasonDetail = detail
}

// Error sets the decision to error with the given reason
func (d *AuthorizationDecision) Error(reason DecisionReason, detail string) {
	d.Result = DecisionResultError
	d.Reason = reason
	d.ReasonDetail = detail
}

// IsAllow returns true if the decision is to allow
func (d *AuthorizationDecision) IsAllow() bool {
	return d.Result == DecisionResultAllow
}

// IsDeny returns true if the decision is to deny
func (d *AuthorizationDecision) IsDeny() bool {
	return d.Result == DecisionResultDeny
}

// IsAbstain returns true if the decision is to abstain
func (d *AuthorizationDecision) IsAbstain() bool {
	return d.Result == DecisionResultAbstain
}

// IsError returns true if the decision is an error
func (d *AuthorizationDecision) IsError() bool {
	return d.Result == DecisionResultError
}

// IsSafeForAudit returns true if the decision can be safely logged for audit
func (d *AuthorizationDecision) IsSafeForAudit() bool {
	// All decision results are safe for audit
	// The actual sensitive data (resource content, etc.) is not in the decision
	return true
}

// DecisionReasonTaxonomy provides safe classification of decision reasons
type DecisionReasonTaxonomy struct {
	// Category classifies the reason into a high-level category
	Category string
	// Severity indicates the security severity level
	Severity string
	// Actionable indicates whether this is actionable by operators
	Actionable bool
	// ClientFacing indicates whether this reason can be shown to clients
	ClientFacing bool
}

// GetReasonTaxonomy returns the taxonomy for a decision reason
func GetReasonTaxonomy(reason DecisionReason) DecisionReasonTaxonomy {
	switch reason {
	// Allow reasons
	case ReasonAllowedByPolicy, ReasonAllowedByOwner, ReasonAllowedByPublicAccess,
		ReasonAllowedByACL, ReasonAllowedByACP, ReasonAllowedByWAC, ReasonAllowedBySAI:
		return DecisionReasonTaxonomy{
			Category:     "access_granted",
			Severity:     "info",
			Actionable:   false,
			ClientFacing: true,
		}

	// Deny reasons
	case ReasonDeniedByPolicy, ReasonDeniedNoMatchingRule, ReasonDeniedByOrigin,
		ReasonDeniedByMethod, ReasonDeniedByResourceType, ReasonDeniedByAgent,
		ReasonDeniedByACL, ReasonDeniedByACP, ReasonDeniedByWAC, ReasonDeniedBySAI:
		return DecisionReasonTaxonomy{
			Category:     "access_denied",
			Severity:     "warning",
			Actionable:   true,
			ClientFacing: true,
		}

	// Abstain reasons
	case ReasonAbstainedParserError, ReasonAbstainedNoPolicy, ReasonAbstainedShadowMode,
		ReasonAbstainedNotImplemented:
		return DecisionReasonTaxonomy{
			Category:     "decision_abstained",
			Severity:     "debug",
			Actionable:   true,
			ClientFacing: false,
		}

	// Error reasons
	case ReasonErrorInternal, ReasonErrorTimeout, ReasonErrorPolicyFetch, ReasonErrorValidation:
		return DecisionReasonTaxonomy{
			Category:     "decision_error",
			Severity:     "error",
			Actionable:   true,
			ClientFacing: false,
		}

	default:
		return DecisionReasonTaxonomy{
			Category:     "unknown",
			Severity:     "debug",
			Actionable:   false,
			ClientFacing: false,
		}
	}
}

// FailClosedPolicy represents the fail-closed/fail-open policy configuration
type FailClosedPolicy struct {
	// Enabled determines whether to fail closed (deny) or fail open (allow) on errors
	Enabled bool

	// DenyOnError controls whether to deny requests when an error occurs
	// If true, errors result in deny; if false, errors may result in allow or pass-through
	DenyOnError bool

	// DenyOnTimeout controls whether to deny requests on timeout
	DenyOnTimeout bool

	// DenyOnPolicyFetchError controls whether to deny requests when policy fetch fails
	DenyOnPolicyFetchError bool

	// DenyOnParserError controls whether to deny requests when policy parsing fails
	DenyOnParserError bool

	// PerEndpointClass allows different policies for different endpoint classes
	PerEndpointClass map[string]FailClosedPolicy
}

// DefaultFailClosedPolicy returns the default fail-closed policy (safety-first)
func DefaultFailClosedPolicy() FailClosedPolicy {
	return FailClosedPolicy{
		Enabled:                true,
		DenyOnError:            true,
		DenyOnTimeout:          true,
		DenyOnPolicyFetchError: true,
		DenyOnParserError:      true,
		PerEndpointClass:       make(map[string]FailClosedPolicy),
	}
}

// ShouldDenyOnError returns whether to deny based on fail-closed policy and error type
func (p *FailClosedPolicy) ShouldDenyOnError(err error) bool {
	if !p.Enabled {
		return false // Fail-open
	}

	// Check for specific transport errors using errors.Is
	if p.DenyOnPolicyFetchError && errors.Is(err, ErrTransportConnectionFailed) {
		return true
	}
	if p.DenyOnParserError && errors.Is(err, ErrTransportInvalidPath) {
		return true
	}

	// Default: deny on error when fail-closed is enabled
	return p.DenyOnError
}

// ShouldDenyOnTimeout returns whether to deny on timeout
func (p *FailClosedPolicy) ShouldDenyOnTimeout() bool {
	if !p.Enabled {
		return false
	}
	return p.DenyOnTimeout
}

// ShouldDenyOnPolicyFetchError returns whether to deny when policy fetch fails
func (p *FailClosedPolicy) ShouldDenyOnPolicyFetchError() bool {
	if !p.Enabled {
		return false
	}
	return p.DenyOnPolicyFetchError
}

// ShouldDenyOnParserError returns whether to deny when parsing fails
func (p *FailClosedPolicy) ShouldDenyOnParserError() bool {
	if !p.Enabled {
		return false
	}
	return p.DenyOnParserError
}
