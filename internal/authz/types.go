package authz

const SchemaVersion = "authz.v1"

type AccessMode string

const (
	AccessModeRead    AccessMode = "read"
	AccessModeAppend  AccessMode = "append"
	AccessModeWrite   AccessMode = "write"
	AccessModeControl AccessMode = "control"
)

// ModesMatch checks if the granted modes satisfy all requested modes
func ModesMatch(granted []AccessMode, requested []AccessMode) bool {
	if len(requested) == 0 {
		return true
	}
	grantedSet := make(map[AccessMode]bool)
	for _, m := range granted {
		grantedSet[m] = true
	}
	for _, m := range requested {
		if !grantedSet[m] {
			return false
		}
	}
	return true
}

type DecisionValue string

const (
	DecisionAllow   DecisionValue = "allow"
	DecisionDeny    DecisionValue = "deny"
	DecisionAbstain DecisionValue = "abstain"
)

type ReasonCode string

const (
	ReasonKernelAbstainShadowMode ReasonCode = "kernel_abstain_shadow_mode"
	ReasonInvalidRequest          ReasonCode = "invalid_request"
	ReasonUnsupportedSchema       ReasonCode = "unsupported_schema_version"
	ReasonMissingRequestedModes   ReasonCode = "missing_requested_modes"
	ReasonUnsafeResourceURI       ReasonCode = "unsafe_resource_uri"
	ReasonPolicyNotLoaded         ReasonCode = "policy_not_loaded"
	ReasonPolicyAllow             ReasonCode = "policy_allow"
	ReasonPolicyDeny              ReasonCode = "policy_deny"
	ReasonKernelError             ReasonCode = "kernel_error"
)

type PolicyDocument struct {
	URI         string `json:"uri"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type"`
	Content     []byte `json:"content,omitempty"` // Optional: actual policy content
}

type Request struct {
	SchemaVersion    string            `json:"schema_version"`
	RequestID        string            `json:"request_id"`
	Method           string            `json:"method"`
	ResourceURI      string            `json:"resource_uri"`
	AgentWebID       string            `json:"agent_webid,omitempty"`
	ClientID         string            `json:"client_id,omitempty"`
	Issuer           string            `json:"issuer,omitempty"`
	Origin           string            `json:"origin,omitempty"`
	RequestedModes   []AccessMode      `json:"requested_modes"`
	ResourceVersion  string            `json:"resource_version,omitempty"`
	PolicyVersion    string            `json:"policy_version,omitempty"`
	ResourceMetadata map[string]string `json:"resource_metadata,omitempty"`
	PolicyDocuments  []PolicyDocument  `json:"policy_documents,omitempty"`
	NowUnix          int64             `json:"now_unix"`
}

type AuditFields struct {
	RequestHash string `json:"request_hash"`
	PolicyHash  string `json:"policy_hash"`
}

type Decision struct {
	SchemaVersion   string        `json:"schema_version"`
	RequestID       string        `json:"request_id"`
	Decision        DecisionValue `json:"decision"`
	ReasonCode      ReasonCode    `json:"reason_code"`
	StatusHint      int           `json:"status_hint,omitempty"`
	CacheTTLSeconds int           `json:"cache_ttl_seconds"`
	PolicyVersion   string        `json:"policy_version,omitempty"`
	ResourceVersion string        `json:"resource_version,omitempty"`
	Audit           AuditFields   `json:"audit"`
	// Operator-visible decision trace ID for Phase 19
	TraceID string `json:"trace_id,omitempty"`
	// Authority mode indicates whether decision was made by native authority or CSS
	AuthorityMode string `json:"authority_mode,omitempty"`
	// Enforcement mode indicates the current enforcement state
	EnforcementMode string `json:"enforcement_mode,omitempty"`
	// Strict mode indicates whether fail-closed policy was applied
	StrictMode bool `json:"strict_mode,omitempty"`
	// FallbackToCSS indicates whether CSS fallback was used
	FallbackToCSS bool `json:"fallback_to_css,omitempty"`
}
