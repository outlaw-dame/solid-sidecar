package authz

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	ErrInvalidRequest  = errors.New("invalid authz request")
	ErrInvalidDecision = errors.New("invalid authz decision")
)

func ValidateRequest(request Request) error {
	if request.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema version", ErrInvalidRequest)
	}
	if !validToken(request.RequestID, 128) {
		return fmt.Errorf("%w: invalid request id", ErrInvalidRequest)
	}
	if _, err := modesForMethod(request.Method); err != nil {
		return fmt.Errorf("%w: unsupported method", ErrInvalidRequest)
	}
	if !validResourceURI(request.ResourceURI) {
		return fmt.Errorf("%w: invalid resource uri", ErrInvalidRequest)
	}
	if len(request.RequestedModes) == 0 {
		return fmt.Errorf("%w: requested modes are required", ErrInvalidRequest)
	}
	seenModes := make(map[AccessMode]struct{}, len(request.RequestedModes))
	for _, mode := range request.RequestedModes {
		if !validAccessMode(mode) {
			return fmt.Errorf("%w: invalid requested mode", ErrInvalidRequest)
		}
		if _, exists := seenModes[mode]; exists {
			return fmt.Errorf("%w: duplicate requested mode", ErrInvalidRequest)
		}
		seenModes[mode] = struct{}{}
	}
	if request.NowUnix < 0 {
		return fmt.Errorf("%w: now_unix must be non-negative", ErrInvalidRequest)
	}
	for _, policyDocument := range request.PolicyDocuments {
		if err := validatePolicyDocument(policyDocument); err != nil {
			return err
		}
	}
	return nil
}

func ValidateDecision(decision Decision) error {
	if decision.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema version", ErrInvalidDecision)
	}
	if !validToken(decision.RequestID, 128) {
		return fmt.Errorf("%w: invalid request id", ErrInvalidDecision)
	}
	if !validDecisionValue(decision.Decision) {
		return fmt.Errorf("%w: invalid decision", ErrInvalidDecision)
	}
	if !validReasonCode(decision.ReasonCode) {
		return fmt.Errorf("%w: invalid reason code", ErrInvalidDecision)
	}
	if decision.StatusHint != 0 && (decision.StatusHint < 100 || decision.StatusHint > 599) {
		return fmt.Errorf("%w: invalid status hint", ErrInvalidDecision)
	}
	if decision.CacheTTLSeconds < 0 || decision.CacheTTLSeconds > 300 {
		return fmt.Errorf("%w: invalid cache ttl", ErrInvalidDecision)
	}
	if !validSHA256Hex(decision.Audit.RequestHash) {
		return fmt.Errorf("%w: invalid request hash", ErrInvalidDecision)
	}
	if !validSHA256Hex(decision.Audit.PolicyHash) {
		return fmt.Errorf("%w: invalid policy hash", ErrInvalidDecision)
	}
	return nil
}

func validatePolicyDocument(policyDocument PolicyDocument) error {
	if !validResourceURI(policyDocument.URI) {
		return fmt.Errorf("%w: invalid policy document uri", ErrInvalidRequest)
	}
	if !validSHA256Hex(policyDocument.SHA256) {
		return fmt.Errorf("%w: invalid policy document hash", ErrInvalidRequest)
	}
	if strings.TrimSpace(policyDocument.ContentType) == "" {
		return fmt.Errorf("%w: policy document content type is required", ErrInvalidRequest)
	}
	return nil
}

func validResourceURI(value string) bool {
	if value == "" || len(value) > 4096 {
		return false
	}
	if strings.ContainsAny(value, "\x00\r\n\\#") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func validToken(value string, maxLen int) bool {
	if value == "" || len(value) > maxLen {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func validAccessMode(mode AccessMode) bool {
	switch mode {
	case AccessModeRead, AccessModeAppend, AccessModeWrite, AccessModeControl:
		return true
	default:
		return false
	}
}

func validDecisionValue(value DecisionValue) bool {
	switch value {
	case DecisionAllow, DecisionDeny, DecisionAbstain:
		return true
	default:
		return false
	}
}

func validReasonCode(value ReasonCode) bool {
	switch value {
	case ReasonKernelAbstainShadowMode,
		ReasonInvalidRequest,
		ReasonUnsupportedSchema,
		ReasonMissingRequestedModes,
		ReasonUnsafeResourceURI,
		ReasonPolicyNotLoaded,
		ReasonPolicyAllow,
		ReasonPolicyDeny,
		ReasonKernelError:
		return true
	default:
		return false
	}
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}
