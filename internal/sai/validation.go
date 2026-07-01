// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ErrSAIValidation is the base error type for SAI validation failures
var ErrSAIValidation = errors.New("SAI validation failed")

// ValidateApplication validates an Application structure
func ValidateApplication(app *Application) error {
	if app == nil {
		return fmt.Errorf("%w: application cannot be nil", ErrSAIValidation)
	}

	// Validate ID (WebID)
	if err := ValidateWebID(app.ID); err != nil {
		return fmt.Errorf("%w: invalid application ID: %v", ErrSAIValidation, err)
	}

	// Validate name
	if err := ValidateApplicationName(app.ApplicationName); err != nil {
		return fmt.Errorf("%w: invalid application name: %v", ErrSAIValidation, err)
	}

	// Validate description
	if err := ValidateDescription(app.ApplicationDescription); err != nil {
		return fmt.Errorf("%w: invalid application description: %v", ErrSAIValidation, err)
	}

	// Validate author
	if app.ApplicationAuthor != "" {
		if err := ValidateWebID(app.ApplicationAuthor); err != nil {
			return fmt.Errorf("%w: invalid application author: %v", ErrSAIValidation, err)
		}
	}

	// Validate thumbnail URL
	if app.ApplicationThumbnail != "" {
		if err := ValidateURL(app.ApplicationThumbnail); err != nil {
			return fmt.Errorf("%w: invalid application thumbnail: %v", ErrSAIValidation, err)
		}
	}

	// Validate access need groups
	for i, group := range app.HasAccessNeedGroup {
		if err := ValidateAccessNeedGroup(&group); err != nil {
			return fmt.Errorf("%w: invalid access need group at index %d: %v", ErrSAIValidation, i, err)
		}
	}

	// Validate callback endpoint
	if app.HasAuthorizationCallbackEndpoint != "" {
		if err := ValidateURL(app.HasAuthorizationCallbackEndpoint); err != nil {
			return fmt.Errorf("%w: invalid callback endpoint: %v", ErrSAIValidation, err)
		}
	}

	return nil
}

// ValidateApplicationName validates an application name
func ValidateApplicationName(name string) error {
	if name == "" {
		return fmt.Errorf("application name cannot be empty")
	}
	if len(name) > SAIMaxApplicationNameLength {
		return fmt.Errorf("application name exceeds maximum length of %d characters", SAIMaxApplicationNameLength)
	}
	// Check for control characters
	for _, r := range name {
		if r < 0x20 || r > 0x7E {
			return fmt.Errorf("application name contains invalid characters")
		}
	}
	return nil
}

// ValidateDescription validates a description
func ValidateDescription(desc string) error {
	if len(desc) > SAIMaxDescriptionLength {
		return fmt.Errorf("description exceeds maximum length of %d characters", SAIMaxDescriptionLength)
	}
	// Check for control characters (allow empty description)
	for _, r := range desc {
		if r < 0x20 || r > 0x7E {
			return fmt.Errorf("description contains invalid characters")
		}
	}
	return nil
}

// ValidateWebID validates a WebID URL
func ValidateWebID(webID string) error {
	if webID == "" {
		return fmt.Errorf("WebID cannot be empty")
	}
	if len(webID) > SAIMaxIRILength {
		return fmt.Errorf("WebID exceeds maximum length of %d characters", SAIMaxIRILength)
	}

	// WebID must be a valid URL with a fragment
	parsed, err := url.Parse(webID)
	if err != nil {
		return fmt.Errorf("invalid WebID URL: %v", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("WebID must use http or https scheme")
	}

	if parsed.Fragment == "" {
		return fmt.Errorf("WebID must have a fragment identifier")
	}

	// Validate fragment is a valid WebID fragment
	fragment := parsed.Fragment
	if !isValidWebIDFragment(fragment) {
		return fmt.Errorf("invalid WebID fragment: %s", fragment)
	}

	return nil
}

// isValidWebIDFragment checks if a fragment is a valid WebID fragment
func isValidWebIDFragment(fragment string) bool {
	// WebID fragments typically identify agents like #me, #id, #webid, etc.
	// They should be non-empty and not contain certain problematic characters
	if fragment == "" {
		return false
	}

	// Check for control characters
	for _, r := range fragment {
		if r < 0x21 || r > 0x7E {
			return false
		}
	}

	return true
}

// ValidateURL validates a URL
func ValidateURL(u string) error {
	if u == "" {
		return nil // Empty URLs are allowed (optional fields)
	}

	if len(u) > SAIMaxIRILength {
		return fmt.Errorf("URL exceeds maximum length of %d characters", SAIMaxIRILength)
	}

	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("URL must use http or https scheme")
	}

	// Validate host
	if parsed.Host == "" {
		return fmt.Errorf("URL must have a host")
	}

	// Check for potentially dangerous characters in host
	if strings.Contains(parsed.Host, "\n") || strings.Contains(parsed.Host, "\r") {
		return fmt.Errorf("URL contains invalid characters")
	}

	return nil
}

// ValidateAccessNeedGroup validates an AccessNeedGroup
func ValidateAccessNeedGroup(group *AccessNeedGroup) error {
	if group == nil {
		return fmt.Errorf("access need group cannot be nil")
	}

	// Validate ID
	if err := ValidateIRI(group.ID); err != nil {
		return fmt.Errorf("invalid access need group ID: %v", err)
	}

	// Validate access necessity
	if err := ValidateAccessNecessity(group.AccessNecessity); err != nil {
		return fmt.Errorf("invalid access necessity: %v", err)
	}

	// Validate access scenario
	if err := ValidateAccessScenario(group.AccessScenario); err != nil {
		return fmt.Errorf("invalid access scenario: %v", err)
	}

	// Validate access needs
	for i, need := range group.HasAccessNeed {
		if err := ValidateAccessNeed(&need); err != nil {
			return fmt.Errorf("invalid access need at index %d: %v", i, err)
		}
	}

	return nil
}

// ValidateIRI validates an IRI (Internationalized Resource Identifier)
func ValidateIRI(iri string) error {
	if iri == "" {
		return fmt.Errorf("IRI cannot be empty")
	}

	if len(iri) > SAIMaxIRILength {
		return fmt.Errorf("IRI exceeds maximum length of %d characters", SAIMaxIRILength)
	}

	// Check for control characters
	for _, r := range iri {
		if r < 0x20 || r > 0x7E {
			return fmt.Errorf("IRI contains invalid characters")
		}
	}

	// Try to parse as URL first
	if parsed, err := url.Parse(iri); err == nil {
		// If it's a URL, validate it
		if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
			// Could be a URN or other IRI scheme
			if !isValidIRIScheme(parsed.Scheme) {
				return fmt.Errorf("invalid IRI scheme: %s", parsed.Scheme)
			}
		}
		return nil
	}

	// If not a URL, it might be a blank node or other IRI format
	// For now, we'll accept it if it doesn't contain invalid characters
	return nil
}

// isValidIRIScheme checks if a scheme is valid for SAI IRIs
func isValidIRIScheme(scheme string) bool {
	// Common IRI schemes in Solid/SAI context
	validSchemes := []string{
		"http", "https", "urn", "", // blank for relative IRIs
		"pm", "solid", "interop", "shapetrees", "solidshapes", "shape",
		"uuid", "ldp", "acl", "foaf", "rdf", "rdfs", "xsd",
		"solidtrees", // Shape Trees namespace
		"projectron", // Example namespace from SAI spec
	}

	for _, valid := range validSchemes {
		if scheme == valid {
			return true
		}
	}

	return false
}

// ValidateAccessNecessity validates an AccessNecessity value
func ValidateAccessNecessity(necessity AccessNecessity) error {
	switch necessity {
	case AccessNecessityRequired, AccessNecessityOptional, AccessNecessityProhibited:
		return nil
	default:
		return fmt.Errorf("invalid access necessity: %s", necessity)
	}
}

// ValidateAccessScenario validates an AccessScenario value
func ValidateAccessScenario(scenario AccessScenario) error {
	switch scenario {
	case AccessScenarioPersonalAccess, AccessScenarioCollaborativeAccess,
		AccessScenarioPublicAccess, AccessScenarioEmergencyAccess:
		return nil
	default:
		return fmt.Errorf("invalid access scenario: %s", scenario)
	}
}

// ValidateAccessNeed validates an AccessNeed
func ValidateAccessNeed(need *AccessNeed) error {
	if need == nil {
		return fmt.Errorf("access need cannot be nil")
	}

	// Validate ID
	if err := ValidateIRI(need.ID); err != nil {
		return fmt.Errorf("invalid access need ID: %v", err)
	}

	// Validate shape tree
	if err := ValidateIRI(need.RegisteredShapeTree); err != nil {
		return fmt.Errorf("invalid registered shape tree: %v", err)
	}

	// Validate access modes
	for i, mode := range need.AccessMode {
		if err := ValidateACLMode(mode); err != nil {
			return fmt.Errorf("invalid access mode at index %d: %v", i, err)
		}
	}

	// Validate access necessity
	if err := ValidateAccessNecessity(need.AccessNecessity); err != nil {
		return fmt.Errorf("invalid access necessity: %v", err)
	}

	// Validate inherits from need (if present)
	if need.InheritsFromNeed != "" {
		if err := ValidateIRI(need.InheritsFromNeed); err != nil {
			return fmt.Errorf("invalid inherits from need: %v", err)
		}
	}

	return nil
}

// ValidateACLMode validates an ACLMode value
func ValidateACLMode(mode ACLMode) error {
	switch mode {
	case ACLModeRead, ACLModeWrite, ACLModeAppend, ACLModeControl:
		return nil
	default:
		return fmt.Errorf("invalid ACL mode: %s", mode)
	}
}

// ValidateApplicationRegistration validates an ApplicationRegistration
func ValidateApplicationRegistration(reg *ApplicationRegistration) error {
	if reg == nil {
		return fmt.Errorf("application registration cannot be nil")
	}

	// Validate ID
	if err := ValidateIRI(reg.ID); err != nil {
		return fmt.Errorf("invalid registration ID: %v", err)
	}

	// Validate registered by
	if err := ValidateWebID(reg.RegisteredBy); err != nil {
		return fmt.Errorf("invalid registered by: %v", err)
	}

	// Validate registered with
	if err := ValidateURL(reg.RegisteredWith); err != nil {
		return fmt.Errorf("invalid registered with: %v", err)
	}

	// Validate registered agent
	if err := ValidateWebID(reg.RegisteredAgent); err != nil {
		return fmt.Errorf("invalid registered agent: %v", err)
	}

	// Validate timestamps
	if reg.RegisteredAt.IsZero() {
		return fmt.Errorf("registered at timestamp cannot be zero")
	}

	// Validate has access grant (if present)
	if reg.HasAccessGrant != "" {
		if err := ValidateIRI(reg.HasAccessGrant); err != nil {
			return fmt.Errorf("invalid has access grant: %v", err)
		}
	}

	return nil
}

// ValidateAccessGrant validates an AccessGrant
func ValidateAccessGrant(grant *AccessGrant) error {
	if grant == nil {
		return fmt.Errorf("access grant cannot be nil")
	}

	// Validate ID
	if err := ValidateIRI(grant.ID); err != nil {
		return fmt.Errorf("invalid grant ID: %v", err)
	}

	// Validate granted by
	if err := ValidateWebID(grant.GrantedBy); err != nil {
		return fmt.Errorf("invalid granted by: %v", err)
	}

	// Validate granted with
	if err := ValidateURL(grant.GrantedWith); err != nil {
		return fmt.Errorf("invalid granted with: %v", err)
	}

	// Validate from agent
	if err := ValidateWebID(grant.FromAgent); err != nil {
		return fmt.Errorf("invalid from agent: %v", err)
	}

	// Validate timestamps
	if grant.GrantedAt.IsZero() {
		return fmt.Errorf("granted at timestamp cannot be zero")
	}

	if grant.ProvidedAt.IsZero() {
		return fmt.Errorf("provided at timestamp cannot be zero")
	}

	// Validate access grant subject
	if err := ValidateAccessGrantSubject(&grant.HasAccessGrantSubject); err != nil {
		return fmt.Errorf("invalid access grant subject: %v", err)
	}

	// Validate access need groups (references only)
	for i, needGroupID := range grant.HasAccessNeedGroup {
		if err := ValidateIRI(needGroupID); err != nil {
			return fmt.Errorf("invalid access need group at index %d: %v", i, err)
		}
	}

	// Validate data grants (references only)
	for i, dataGrantID := range grant.HasDataGrant {
		if err := ValidateIRI(dataGrantID); err != nil {
			return fmt.Errorf("invalid data grant at index %d: %v", i, err)
		}
	}

	return nil
}

// ValidateAccessGrantSubject validates an AccessGrantSubject
func ValidateAccessGrantSubject(subject *AccessGrantSubject) error {
	if subject == nil {
		return fmt.Errorf("access grant subject cannot be nil")
	}

	// Validate ID
	if err := ValidateIRI(subject.ID); err != nil {
		return fmt.Errorf("invalid subject ID: %v", err)
	}

	// Validate access by agent
	if err := ValidateWebID(subject.AccessByAgent); err != nil {
		return fmt.Errorf("invalid access by agent: %v", err)
	}

	// Validate access by application
	if err := ValidateWebID(subject.AccessByApplication); err != nil {
		return fmt.Errorf("invalid access by application: %v", err)
	}

	return nil
}

// ValidateDataGrant validates a DataGrant
func ValidateDataGrant(grant *DataGrant) error {
	if grant == nil {
		return fmt.Errorf("data grant cannot be nil")
	}

	// Validate ID
	if err := ValidateIRI(grant.ID); err != nil {
		return fmt.Errorf("invalid data grant ID: %v", err)
	}

	// Validate data owner
	if err := ValidateWebID(grant.DataOwner); err != nil {
		return fmt.Errorf("invalid data owner: %v", err)
	}

	// Validate granted by
	if err := ValidateWebID(grant.GrantedBy); err != nil {
		return fmt.Errorf("invalid granted by: %v", err)
	}

	// Validate shape tree
	if err := ValidateIRI(grant.RegisteredShapeTree); err != nil {
		return fmt.Errorf("invalid registered shape tree: %v", err)
	}

	// Validate has data registration
	if err := ValidateIRI(grant.HasDataRegistration); err != nil {
		return fmt.Errorf("invalid has data registration: %v", err)
	}

	// Validate access modes
	for i, mode := range grant.AccessMode {
		if err := ValidateACLMode(mode); err != nil {
			return fmt.Errorf("invalid access mode at index %d: %v", i, err)
		}
	}

	// Validate scope of grant
	if err := ValidateScopeOfGrant(grant.ScopeOfGrant); err != nil {
		return fmt.Errorf("invalid scope of grant: %v", err)
	}

	// Validate data instances (references only)
	for i, instanceID := range grant.HasDataInstance {
		if err := ValidateIRI(instanceID); err != nil {
			return fmt.Errorf("invalid data instance at index %d: %v", i, err)
		}
	}

	// Validate inheritance references (if present)
	if grant.InheritsFromGrant != "" {
		if err := ValidateIRI(grant.InheritsFromGrant); err != nil {
			return fmt.Errorf("invalid inherits from grant: %v", err)
		}
	}

	// Validate delegation reference (if present)
	if grant.DelegationOfGrant != "" {
		if err := ValidateIRI(grant.DelegationOfGrant); err != nil {
			return fmt.Errorf("invalid delegation of grant: %v", err)
		}
	}

	return nil
}

// ValidateScopeOfGrant validates a ScopeOfGrant value
func ValidateScopeOfGrant(scope ScopeOfGrant) error {
	switch scope {
	case ScopeOfGrantAllFromRegistry, ScopeOfGrantSelectedFromRegistry, ScopeOfGrantInherited:
		return nil
	default:
		return fmt.Errorf("invalid scope of grant: %s", scope)
	}
}

// ValidateDataRegistration validates a DataRegistration
func ValidateDataRegistration(reg *DataRegistration) error {
	if reg == nil {
		return fmt.Errorf("data registration cannot be nil")
	}

	// Validate ID
	if err := ValidateIRI(reg.ID); err != nil {
		return fmt.Errorf("invalid registration ID: %v", err)
	}

	// Validate shape tree
	if err := ValidateIRI(reg.RegisteredShapeTree); err != nil {
		return fmt.Errorf("invalid registered shape tree: %v", err)
	}

	// Validate registered by
	if err := ValidateWebID(reg.RegisteredBy); err != nil {
		return fmt.Errorf("invalid registered by: %v", err)
	}

	// Validate registered with
	if err := ValidateWebID(reg.RegisteredWith); err != nil {
		return fmt.Errorf("invalid registered with: %v", err)
	}

	// Validate timestamp
	if reg.RegisteredAt.IsZero() {
		return fmt.Errorf("registered at timestamp cannot be zero")
	}

	// Validate IRI prefix
	if err := ValidateURL(reg.IRIPrefix); err != nil {
		return fmt.Errorf("invalid IRI prefix: %v", err)
	}

	// Validate contains (references only)
	for i, instanceID := range reg.Contains {
		if err := ValidateIRI(instanceID); err != nil {
			return fmt.Errorf("invalid contains entry at index %d: %v", i, err)
		}
	}

	return nil
}

// ValidateDataInstance validates a DataInstance
func ValidateDataInstance(instance *DataInstance) error {
	if instance == nil {
		return fmt.Errorf("data instance cannot be nil")
	}

	// Validate ID
	if err := ValidateIRI(instance.ID); err != nil {
		return fmt.Errorf("invalid instance ID: %v", err)
	}

	// Validate type (if present)
	if instance.Type != "" {
		if err := ValidateIRI(instance.Type); err != nil {
			return fmt.Errorf("invalid type: %v", err)
		}
	}

	// Validate shape tree (if present)
	if instance.ShapeTree != "" {
		if err := ValidateIRI(instance.ShapeTree); err != nil {
			return fmt.Errorf("invalid shape tree: %v", err)
		}
	}

	// Validate data size
	if len(instance.Data) > SAIMaxInputSize {
		return fmt.Errorf("data exceeds maximum size of %d bytes", SAIMaxInputSize)
	}

	// Validate content type
	if instance.ContentType == "" {
		return fmt.Errorf("content type cannot be empty")
	}

	return nil
}

// ValidateShapeTree validates a ShapeTree
func ValidateShapeTree(tree *ShapeTree) error {
	if tree == nil {
		return fmt.Errorf("shape tree cannot be nil")
	}

	// Validate ID
	if err := ValidateIRI(tree.ID); err != nil {
		return fmt.Errorf("invalid shape tree ID: %v", err)
	}

	// Validate expects type
	if err := ValidateIRI(tree.ExpectsType); err != nil {
		return fmt.Errorf("invalid expects type: %v", err)
	}

	// Validate shape
	if err := ValidateIRI(tree.Shape); err != nil {
		return fmt.Errorf("invalid shape: %v", err)
	}

	// Validate references
	for i, ref := range tree.References {
		if err := ValidateShapeTreeReference(&ref); err != nil {
			return fmt.Errorf("invalid reference at index %d: %v", i, err)
		}
	}

	return nil
}

// ValidateShapeTreeReference validates a ShapeTreeReference
func ValidateShapeTreeReference(ref *ShapeTreeReference) error {
	if ref == nil {
		return fmt.Errorf("shape tree reference cannot be nil")
	}

	// Validate has shape tree
	if err := ValidateIRI(ref.HasShapeTree); err != nil {
		return fmt.Errorf("invalid has shape tree: %v", err)
	}

	// Validate via shape path (if present)
	if ref.ViaShapePath != "" {
		// Shape paths should be valid RDF paths
		if err := ValidateShapePath(ref.ViaShapePath); err != nil {
			return fmt.Errorf("invalid via shape path: %v", err)
		}
	}

	return nil
}

// ValidateShapePath validates an RDF shape path
func ValidateShapePath(path string) error {
	if path == "" {
		return nil // Empty paths are allowed (direct references)
	}

	// Shape paths use RDF property paths with specific syntax
	// For now, we'll do basic validation
	if len(path) > SAIMaxIRILength {
		return fmt.Errorf("shape path exceeds maximum length")
	}

	// Check for invalid characters
	invalidChars := regexp.MustCompile(`[<>"'{}|\\^\x00-\x1F\x7F]`)
	if invalidChars.MatchString(path) {
		return fmt.Errorf("shape path contains invalid characters")
	}

	return nil
}

// ValidateAuthorizationAgent validates an AuthorizationAgent
func ValidateAuthorizationAgent(agent *AuthorizationAgent) error {
	if agent == nil {
		return fmt.Errorf("authorization agent cannot be nil")
	}

	// Validate ID (URL) - required field
	if agent.ID == "" {
		return fmt.Errorf("authorization agent ID cannot be empty")
	}
	if err := ValidateURL(agent.ID); err != nil {
		return fmt.Errorf("invalid authorization agent ID: %v", err)
	}

	// Validate agent registry sets
	for i, registryID := range agent.AgentRegistrySet {
		if err := ValidateIRI(registryID); err != nil {
			return fmt.Errorf("invalid agent registry set at index %d: %v", i, err)
		}
	}

	return nil
}

// ValidateTimestamp validates a timestamp is recent and reasonable
func ValidateTimestamp(t time.Time) error {
	if t.IsZero() {
		return fmt.Errorf("timestamp cannot be zero")
	}

	// Check if timestamp is in the future (allow some clock skew)
	now := time.Now().UTC()
	if t.After(now.Add(5 * time.Minute)) {
		return fmt.Errorf("timestamp is too far in the future")
	}

	// Check if timestamp is too far in the past
	if t.Before(now.Add(-24 * time.Hour * 365)) {
		return fmt.Errorf("timestamp is too far in the past")
	}

	return nil
}
