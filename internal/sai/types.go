// Package sai implements Solid Application Interoperability (SAI) support.
// This is the official Solid SAI specification from solidproject.org/TR/sai-primer-application
// which focuses on application registration, authorization flows, and data interoperability.
package sai

import (
	"time"
)

// Namespace constants for SAI vocabulary
type Namespace string

const (
	// SAI namespace
	SAINamespace        = "http://www.w3.org/ns/solid/interop#"
	InteropNamespace    = "http://www.w3.org/ns/solid/interop#"
	RDFNamespace        = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	XSDNamespace        = "http://www.w3.org/2001/XMLSchema#"
	ACLNamespace        = "http://www.w3.org/ns/auth/acl#"
	LDPNamespace        = "http://www.w3.org/ns/ldp#"
	SHAPETREESNamespace = "https://w3id.org/shapetrees#"
)

// Application represents a Solid Application that can request access to user data
type Application struct {
	// ID is the application's WebID
	ID string
	// ApplicationName is the human-readable name of the application
	ApplicationName string
	// ApplicationDescription describes what the application does
	ApplicationDescription string
	// ApplicationAuthor is the creator of the application
	ApplicationAuthor string
	// ApplicationThumbnail is an image URL for the application
	ApplicationThumbnail string
	// HasAccessNeedGroup contains groups of access needs
	HasAccessNeedGroup []AccessNeedGroup
	// HasAuthorizationCallbackEndpoint is where the Authorization Agent redirects after consent
	HasAuthorizationCallbackEndpoint string
	// AuthenticatesAs indicates the authentication method
	AuthenticatesAs string
}

// AccessNeedGroup represents a group of related access needs
type AccessNeedGroup struct {
	// ID is the identifier for this access need group
	ID string
	// AccessNecessity indicates whether this access is required or optional
	AccessNecessity AccessNecessity
	// AccessScenario describes when this access is needed
	AccessScenario AccessScenario
	// AuthenticatesAs indicates the authentication method for this group
	AuthenticatesAs string
	// HasAccessNeed contains the individual access needs
	HasAccessNeed []AccessNeed
	// HasAccessDecoratorIndex points to decorators for this group
	HasAccessDecoratorIndex string
}

// AccessNecessity defines how necessary the access is
type AccessNecessity string

const (
	AccessNecessityRequired   AccessNecessity = "http://www.w3.org/ns/solid/interop#accessRequired"
	AccessNecessityOptional   AccessNecessity = "http://www.w3.org/ns/solid/interop#accessOptional"
	AccessNecessityProhibited AccessNecessity = "http://www.w3.org/ns/solid/interop#accessProhibited"
)

// AccessScenario defines when access is needed
type AccessScenario string

const (
	AccessScenarioPersonalAccess      AccessScenario = "http://www.w3.org/ns/solid/interop#PersonalAccess"
	AccessScenarioCollaborativeAccess AccessScenario = "http://www.w3.org/ns/solid/interop#CollaborativeAccess"
	AccessScenarioPublicAccess        AccessScenario = "http://www.w3.org/ns/solid/interop#PublicAccess"
	AccessScenarioEmergencyAccess     AccessScenario = "http://www.w3.org/ns/solid/interop#EmergencyAccess"
)

// AccessNeed defines what kind of data an application needs access to
type AccessNeed struct {
	// ID is the identifier for this access need
	ID string
	// RegisteredShapeTree points to the Shape Tree that defines the data structure
	RegisteredShapeTree string
	// AccessMode defines what operations are allowed (read, write, etc.)
	AccessMode []ACLMode
	// AccessNecessity indicates whether this access is required or optional
	AccessNecessity AccessNecessity
	// InheritsFromNeed points to parent access need if this inherits permissions
	InheritsFromNeed string
}

// ACLMode represents access modes from ACL specification
type ACLMode string

const (
	ACLModeRead    ACLMode = "http://www.w3.org/ns/auth/acl#Read"
	ACLModeWrite   ACLMode = "http://www.w3.org/ns/auth/acl#Write"
	ACLModeAppend  ACLMode = "http://www.w3.org/ns/auth/acl#Append"
	ACLModeControl ACLMode = "http://www.w3.org/ns/auth/acl#Control"
)

// ApplicationRegistration represents an application's registration with a user
type ApplicationRegistration struct {
	// ID is the unique identifier for this registration
	ID string
	// RegisteredBy is the WebID of the user who registered the application
	RegisteredBy string
	// RegisteredWith is the Authorization Agent that registered the application
	RegisteredWith string
	// RegisteredAt is when the registration occurred
	RegisteredAt time.Time
	// UpdatedAt is when the registration was last updated
	UpdatedAt time.Time
	// RegisteredAgent is the application being registered
	RegisteredAgent string
	// HasAccessGrant points to the access grant for this registration
	HasAccessGrant string
}

// AccessGrant represents the access permissions granted to an application
type AccessGrant struct {
	// ID is the unique identifier for this access grant
	ID string
	// GrantedBy is the WebID of the user who granted access
	GrantedBy string
	// GrantedWith is the Authorization Agent that granted access
	GrantedWith string
	// GrantedAt is when access was granted
	GrantedAt time.Time
	// ProvidedAt is when the grant was provided to the application
	ProvidedAt time.Time
	// UpdatedAt is when the grant was last updated
	UpdatedAt time.Time
	// FromAgent is the user who owns the data
	FromAgent string
	// ViaAgent is the agent through which access was granted
	ViaAgent string
	// HasAccessGrantSubject contains the subject of the grant
	HasAccessGrantSubject AccessGrantSubject
	// HasAccessNeedGroup contains the access need groups being granted
	HasAccessNeedGroup []string
	// HasDataGrant contains the data grants
	HasDataGrant []string
}

// AccessGrantSubject represents who the access grant applies to
type AccessGrantSubject struct {
	// ID is the identifier for this subject
	ID string
	// AccessByAgent is the WebID of the agent accessing the data
	AccessByAgent string
	// AccessByApplication is the application accessing the data
	AccessByApplication string
}

// DataGrant represents access to specific data instances
type DataGrant struct {
	// ID is the unique identifier for this data grant
	ID string
	// DataOwner is the WebID of the user who owns the data
	DataOwner string
	// GrantedBy is the WebID of the user who granted access
	GrantedBy string
	// RegisteredShapeTree is the Shape Tree for the data
	RegisteredShapeTree string
	// HasDataRegistration points to the data registration
	HasDataRegistration string
	// AccessMode defines what operations are allowed
	AccessMode []ACLMode
	// ScopeOfGrant defines which instances are accessible
	ScopeOfGrant ScopeOfGrant
	// HasDataInstance points to specific data instances (if SelectedFromRegistry)
	HasDataInstance []string
	// InheritsFromGrant points to parent grant for inheritance
	InheritsFromGrant string
	// DelegationOfGrant points to original grant if delegated
	DelegationOfGrant string
}

// ScopeOfGrant defines which data instances are accessible
type ScopeOfGrant string

const (
	ScopeOfGrantAllFromRegistry      ScopeOfGrant = "http://www.w3.org/ns/solid/interop#AllFromRegistry"
	ScopeOfGrantSelectedFromRegistry ScopeOfGrant = "http://www.w3.org/ns/solid/interop#SelectedFromRegistry"
	ScopeOfGrantInherited            ScopeOfGrant = "http://www.w3.org/ns/solid/interop#Inherited"
)

// DataRegistration represents registration of data instances with Shape Trees
type DataRegistration struct {
	// ID is the unique identifier for this data registration
	ID string
	// RegisteredShapeTree is the Shape Tree that defines the data structure
	RegisteredShapeTree string
	// RegisteredAt is when the registration occurred
	RegisteredAt time.Time
	// RegisteredBy is the WebID of the user who registered the data
	RegisteredBy string
	// RegisteredWith is the application or agent that registered the data
	RegisteredWith string
	// IRIPrefix is the base IRI for creating new data instance IRIs
	IRIPrefix string
	// Contains lists the data instances in this registration
	Contains []string
}

// AuthorizationAgent represents an agent that manages authorization for users
type AuthorizationAgent struct {
	// ID is the URL/URI of the authorization agent
	ID string
	// AgentRegistrySet contains the registry sets managed by this agent
	AgentRegistrySet []string
}

// AgentRegistry represents a registry of agent registrations
type AgentRegistry struct {
	// ID is the unique identifier for this registry
	ID string
	// Contains lists the agent registrations in this registry
	Contains []string
}

// DataInstance represents a specific data instance with its type and properties
type DataInstance struct {
	// ID is the unique identifier for this data instance
	ID string
	// Type defines what kind of data this is (e.g., pm:Project, pm:Task)
	Type string
	// ShapeTree points to the Shape Tree that validates this instance
	ShapeTree string
	// Data is the actual RDF data of the instance
	Data []byte
	// ContentType is the MIME type of the data
	ContentType string
}

// ShapeTree represents a shape tree definition for data validation
type ShapeTree struct {
	// ID is the unique identifier for this shape tree
	ID string
	// ExpectsType defines what type of resource this applies to
	ExpectsType string
	// Shape defines the shape for validation
	Shape string
	// References contains child shape tree references
	References []ShapeTreeReference
}

// ShapeTreeReference defines how child data is referenced
type ShapeTreeReference struct {
	// HasShapeTree points to the child shape tree
	HasShapeTree string
	// ViaShapePath defines the path to the child data
	ViaShapePath string
}

// Error types for SAI operations
var (
	ErrSAIInvalidApplication      = "sai: invalid application registration"
	ErrSAIApplicationNotFound     = "sai: application not found"
	ErrSAIAuthorizationFailed     = "sai: authorization failed"
	ErrSAIDataRegistrationFailed  = "sai: data registration failed"
	ErrSAIAccessGrantFailed       = "sai: access grant failed"
	ErrSAIInvalidDataInstance     = "sai: invalid data instance"
	ErrSAIShapeTreeNotFound       = "sai: shape tree not found"
	ErrSAIInsufficientPermissions = "sai: insufficient permissions"
	ErrSAIInvalidScope            = "sai: invalid scope"
)

// Constants for SAI content types
const (
	ContentTypeApplicationJSON      = "application/json"
	ContentTypeApplicationLDJSON    = "application/ld+json"
	ContentTypeTextTurtle           = "text/turtle"
	ContentTypeSAIApplicationJSON   = "application/sai+json"
	ContentTypeSAIApplicationLDJSON = "application/sai+ld+json"
)

// Constants for SAI limits and defaults
const (
	// SAIMaxApplicationNameLength is the maximum length for application names
	SAIMaxApplicationNameLength = 256
	// SAIMaxDescriptionLength is the maximum length for descriptions
	SAIMaxDescriptionLength = 1024
	// SAIMaxIRILength is the maximum length for IRIs
	SAIMaxIRILength = 2048
	// SAIMaxDataGrantCount is the maximum number of data grants per access grant
	SAIMaxDataGrantCount = 100
	// SAIMaxDataInstanceCount is the maximum number of data instances per registration
	SAIMaxDataInstanceCount = 1000
	// SAIDefaultTimeout is the default timeout for SAI operations
	SAIDefaultTimeout = 30 * time.Second
	// SAIMaxTimeout is the maximum timeout for SAI operations
	SAIMaxTimeout = 300 * time.Second
	// SAIMaxInputSize is the maximum size for SAI input data
	SAIMaxInputSize = 1024 * 1024 // 1 MB
)
