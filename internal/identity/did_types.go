// Package identity provides DID (Decentralized Identifier) parsing, resolution, and validation for Solid.
package identity

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DID method constants
const (
	DIDMethodSolid = "solid"
	DIDPrefix      = "did:"
)

// Errors for DID operations
var (
	ErrInvalidDID                = errors.New("invalid DID")
	ErrInvalidDIDMethod          = errors.New("invalid DID method")
	ErrInvalidMethodSpecificID   = errors.New("invalid method-specific ID")
	ErrDIDTooLong                = errors.New("DID too long")
	ErrUnsafeDID                 = errors.New("DID contains unsafe characters")
	ErrDIDBindingFailed          = errors.New("DID binding validation failed")
	ErrWebIDBacklinkMissing      = errors.New("WebID backlink missing or invalid")
	ErrVerificationMethodInvalid = errors.New("verification method invalid")
)

// MaxDIDLength is the maximum allowed length for a DID string
const MaxDIDLength = 1024

// MaxMethodSpecificIDLength is the maximum allowed length for the method-specific ID
const MaxMethodSpecificIDLength = 512

// didRegex matches a valid DID string
// Format: did:<method>:<method-specific-id>
var didRegex = regexp.MustCompile(`^did:([a-zA-Z0-9]+):([a-zA-Z0-9\-._]+)$`)

// hostLikeIDRegex matches host-like method-specific IDs (DNS-style)
// Format: lowercase alphanumeric with hyphens and dots, no leading/trailing hyphens
var hostLikeIDRegex = regexp.MustCompile(`^[a-z0-9]+([a-z0-9\-]*[a-z0-9]+)*(\.[a-z0-9]+([a-z0-9\-]*[a-z0-9]+)*)*$`)

// DID represents a parsed Decentralized Identifier
type DID struct {
	// Method is the DID method (e.g., "solid")
	Method string
	// MethodSpecificID is the method-specific identifier
	MethodSpecificID string
	// Original is the original DID string
	Original string
}

// String returns the DID as a string
func (d DID) String() string {
	return fmt.Sprintf("did:%s:%s", d.Method, d.MethodSpecificID)
}

// NormalizedString returns the normalized DID string (lowercase method and method-specific ID)
func (d DID) NormalizedString() string {
	return fmt.Sprintf("did:%s:%s", strings.ToLower(d.Method), strings.ToLower(d.MethodSpecificID))
}

// IsSolidDID returns true if this is a did:solid DID
func (d DID) IsSolidDID() bool {
	return strings.ToLower(d.Method) == DIDMethodSolid
}

// DIDURL represents a DID URL (DID with path, query, or fragment)
type DIDURL struct {
	DID      DID
	Path     string
	Query    string
	Fragment string
}

// String returns the DID URL as a string
func (du DIDURL) String() string {
	var b strings.Builder
	b.WriteString(du.DID.String())
	if du.Path != "" {
		b.WriteString(du.Path)
	}
	if du.Query != "" {
		b.WriteString("?")
		b.WriteString(du.Query)
	}
	if du.Fragment != "" {
		b.WriteString("#")
		b.WriteString(du.Fragment)
	}
	return b.String()
}

// VerificationMethod represents a DID verification method
type VerificationMethod struct {
	// ID is the DID URL of this verification method
	ID string
	// Type is the verification method type (e.g., "Ed25519VerificationKey2020", "Multikey")
	Type string
	// Controller is the DID that controls this verification method
	Controller string
	// PublicKeyMultibase is the public key in multibase format
	PublicKeyMultibase string
	// PublicKeyJWK is the public key in JWK format (alternative to PublicKeyMultibase)
	PublicKeyJWK string
}

// IsValid checks if the verification method has all required fields
func (vm VerificationMethod) IsValid() bool {
	if vm.ID == "" || vm.Type == "" || vm.Controller == "" {
		return false
	}
	return vm.PublicKeyMultibase != "" || vm.PublicKeyJWK != ""
}

// Service represents a DID service endpoint
type Service struct {
	// ID is the DID URL of this service
	ID string
	// Type is the service type (e.g., "SolidStorage", "SolidWebID", "SolidOIDCIssuer")
	Type string
	// ServiceEndpoint is the URL of the service endpoint
	ServiceEndpoint string
}

// IsValid checks if the service has all required fields
func (s Service) IsValid() bool {
	return s.ID != "" && s.Type != "" && s.ServiceEndpoint != ""
}

// IsHTTPS checks if the service endpoint uses HTTPS
func (s Service) IsHTTPS() bool {
	u, err := url.Parse(s.ServiceEndpoint)
	if err != nil {
		return false
	}
	return strings.ToLower(u.Scheme) == "https"
}

// DIDDocument represents a DID document
type DIDDocument struct {
	// Context is the JSON-LD context
	Context []string
	// ID is the DID this document describes
	ID string
	// VerificationMethod contains the verification methods
	VerificationMethod []VerificationMethod
	// Authentication contains the authentication methods (references to verification methods)
	Authentication []string
	// AssertionMethod contains the assertion methods (references to verification methods)
	AssertionMethod []string
	// KeyAgreement contains the key agreement methods (references to verification methods)
	KeyAgreement []string
	// Service contains the service endpoints
	Service []Service
	// Created is the creation timestamp (RFC3339)
	Created *time.Time
	// Updated is the last update timestamp (RFC3339)
	Updated *time.Time
	// Deactivated indicates if the DID is deactivated
	Deactivated bool
}

// IsValid checks if the DID document has all required fields
func (doc DIDDocument) IsValid() bool {
	if doc.ID == "" {
		return false
	}
	if len(doc.VerificationMethod) == 0 {
		return false
	}
	for _, vm := range doc.VerificationMethod {
		if !vm.IsValid() {
			return false
		}
	}
	return true
}

// GetSolidStorageService returns the first SolidStorage service if it exists
func (doc DIDDocument) GetSolidStorageService() *Service {
	for i := range doc.Service {
		if strings.EqualFold(doc.Service[i].Type, "SolidStorage") {
			return &doc.Service[i]
		}
	}
	return nil
}

// GetSolidWebIDService returns the first SolidWebID service if it exists
func (doc DIDDocument) GetSolidWebIDService() *Service {
	for i := range doc.Service {
		if strings.EqualFold(doc.Service[i].Type, "SolidWebID") ||
			strings.EqualFold(doc.Service[i].Type, "WebID") {
			return &doc.Service[i]
		}
	}
	return nil
}

// GetSolidOIDCIssuerService returns the first SolidOIDCIssuer service if it exists
func (doc DIDDocument) GetSolidOIDCIssuerService() *Service {
	for i := range doc.Service {
		if strings.EqualFold(doc.Service[i].Type, "SolidOIDCIssuer") ||
			strings.EqualFold(doc.Service[i].Type, "OpenIDProvider") {
			return &doc.Service[i]
		}
	}
	return nil
}

// HasAuthentication returns true if there is at least one authentication method
func (doc DIDDocument) HasAuthentication() bool {
	return len(doc.Authentication) > 0
}

// GetAuthenticationVerificationMethods returns the verification methods referenced by authentication
func (doc DIDDocument) GetAuthenticationVerificationMethods() []VerificationMethod {
	var result []VerificationMethod
	for _, authRef := range doc.Authentication {
		for _, vm := range doc.VerificationMethod {
			if vm.ID == authRef {
				result = append(result, vm)
				break
			}
		}
	}
	return result
}

// WebIDBacklinkPredicate is the predicate used for DID-to-WebID binding
// This is the project-defined predicate as documented in did-solid-method.md
const WebIDBacklinkPredicate = "https://solidproject.org/ns/did#controller"

// ResolverOptions configures the DID resolver
type ResolverOptions struct {
	// Enabled determines if the resolver is active
	Enabled bool
	// DefaultMappingEnabled determines if the default host-like mapping is used
	DefaultMappingEnabled bool
	// AllowedResolvers is a list of allowed resolver types ("local", "https")
	AllowedResolvers []string
	// MaxDocumentBytes is the maximum size of a DID document in bytes
	MaxDocumentBytes int
	// CacheTTLSeconds is the TTL for cached DID documents
	CacheTTLSeconds int
	// TimeoutSeconds is the timeout for resolution requests
	TimeoutSeconds int
	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultResolverOptions returns safe default options
func DefaultResolverOptions() ResolverOptions {
	return ResolverOptions{
		Enabled:               false, // Disabled by default for safety
		DefaultMappingEnabled: false, // Disabled by default for safety
		AllowedResolvers:      []string{"local"},
		MaxDocumentBytes:      65536, // 64 KiB
		CacheTTLSeconds:       300,   // 5 minutes
		TimeoutSeconds:        10,    // 10 seconds
	}
}

// IsResolverAllowed checks if a resolver type is in the allowed list
func (o ResolverOptions) IsResolverAllowed(resolverType string) bool {
	for _, allowed := range o.AllowedResolvers {
		if allowed == resolverType {
			return true
		}
	}
	return false
}
