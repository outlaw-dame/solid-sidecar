// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"
)

// ErrSAIService is the base error type for SAI service failures
var ErrSAIService = errors.New("SAI service failed")

// SAIServiceOptions configures the SAI service
type SAIServiceOptions struct {
	// Logger is the logger to use
	Logger *slog.Logger
	// Timeout is the timeout for SAI operations
	Timeout time.Duration
	// MaxRetries is the maximum number of retries for failed operations
	MaxRetries int
	// BaseURL is the base URL for the SAI service
	BaseURL string
	// Storage is the storage backend for SAI data
	Storage SAIStorage
	// AuthorizationAgentURL is the URL of the authorization agent
	AuthorizationAgentURL string
}

// DefaultSAIServiceOptions returns safe default options
func DefaultSAIServiceOptions() SAIServiceOptions {
	return SAIServiceOptions{
		Logger:                nil,
		Timeout:               SAIDefaultTimeout,
		MaxRetries:            3,
		BaseURL:               "",
		Storage:               nil,
		AuthorizationAgentURL: "",
	}
}

// SAIService is the main service for Solid Application Interoperability
type SAIService struct {
	options SAIServiceOptions
	storage SAIStorage
	logger  *slog.Logger
}

// SAIStorage defines the interface for SAI data storage
type SAIStorage interface {
	// Application operations
	StoreApplication(ctx context.Context, app *Application) error
	GetApplication(ctx context.Context, id string) (*Application, error)
	ListApplications(ctx context.Context, owner string) ([]*Application, error)
	DeleteApplication(ctx context.Context, id string) error

	// Application Registration operations
	StoreApplicationRegistration(ctx context.Context, reg *ApplicationRegistration) error
	GetApplicationRegistration(ctx context.Context, id string) (*ApplicationRegistration, error)
	ListApplicationRegistrations(ctx context.Context, userID string) ([]*ApplicationRegistration, error)
	DeleteApplicationRegistration(ctx context.Context, id string) error

	// Access Grant operations
	StoreAccessGrant(ctx context.Context, grant *AccessGrant) error
	GetAccessGrant(ctx context.Context, id string) (*AccessGrant, error)
	ListAccessGrants(ctx context.Context, userID string) ([]*AccessGrant, error)
	DeleteAccessGrant(ctx context.Context, id string) error

	// Data Registration operations
	StoreDataRegistration(ctx context.Context, reg *DataRegistration) error
	GetDataRegistration(ctx context.Context, id string) (*DataRegistration, error)
	ListDataRegistrations(ctx context.Context, userID string) ([]*DataRegistration, error)
	DeleteDataRegistration(ctx context.Context, id string) error

	// Data Grant operations
	StoreDataGrant(ctx context.Context, grant *DataGrant) error
	GetDataGrant(ctx context.Context, id string) (*DataGrant, error)
	ListDataGrants(ctx context.Context, accessGrantID string) ([]*DataGrant, error)
	DeleteDataGrant(ctx context.Context, id string) error

	// Data Instance operations
	StoreDataInstance(ctx context.Context, instance *DataInstance) error
	GetDataInstance(ctx context.Context, id string) (*DataInstance, error)
	ListDataInstances(ctx context.Context, registrationID string) ([]*DataInstance, error)
	DeleteDataInstance(ctx context.Context, id string) error

	// Shape Tree operations
	StoreShapeTree(ctx context.Context, tree *ShapeTree) error
	GetShapeTree(ctx context.Context, id string) (*ShapeTree, error)
	ListShapeTrees(ctx context.Context) ([]*ShapeTree, error)
	DeleteShapeTree(ctx context.Context, id string) error

	// Authorization Agent operations
	StoreAuthorizationAgent(ctx context.Context, agent *AuthorizationAgent) error
	GetAuthorizationAgent(ctx context.Context, id string) (*AuthorizationAgent, error)
	ListAuthorizationAgents(ctx context.Context) ([]*AuthorizationAgent, error)
	DeleteAuthorizationAgent(ctx context.Context, id string) error
}

// NewSAIService creates a new SAI service
func NewSAIService(options SAIServiceOptions) (*SAIService, error) {
	if options.Timeout <= 0 {
		options.Timeout = SAIDefaultTimeout
	}
	if options.MaxRetries <= 0 {
		options.MaxRetries = 3
	}

	// If no storage is provided, use a default in-memory storage
	if options.Storage == nil {
		options.Storage = NewInMemorySAIStorage()
	}

	service := &SAIService{
		options: options,
		storage: options.Storage,
		logger:  options.Logger,
	}

	return service, nil
}

// logError logs an error if a logger is configured
func (s *SAIService) logError(msg string, args ...any) {
	if s.logger != nil {
		s.logger.Error(msg, args...)
	}
}

// logWarn logs a warning if a logger is configured
func (s *SAIService) logWarn(msg string, args ...any) {
	if s.logger != nil {
		s.logger.Warn(msg, args...)
	}
}

// logInfo logs info if a logger is configured
func (s *SAIService) logInfo(msg string, args ...any) {
	if s.logger != nil {
		s.logger.Info(msg, args...)
	}
}

// =============================================================================
// Application Registration Service
// =============================================================================

// RegisterApplication registers a new application with a user
type RegisterApplicationRequest struct {
	// Application is the application to register
	Application Application
	// UserID is the WebID of the user registering the application
	UserID string
	// AuthorizationAgentURL is the URL of the authorization agent
	AuthorizationAgentURL string
}

// RegisterApplicationResponse contains the registration result
type RegisterApplicationResponse struct {
	// ApplicationRegistration is the created registration
	ApplicationRegistration ApplicationRegistration
	// Application is the registered application
	Application Application
}

// RegisterApplication registers an application with a user
func (s *SAIService) RegisterApplication(ctx context.Context, req RegisterApplicationRequest) (*RegisterApplicationResponse, error) {
	// Validate context
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	// Validate request
	if err := s.validateRegisterApplicationRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSAIService, err)
	}

	// Store the application
	if err := s.storage.StoreApplication(ctx, &req.Application); err != nil {
		return nil, fmt.Errorf("%w: failed to store application: %v", ErrSAIService, err)
	}

	// Create the registration
	now := time.Now().UTC()
	registration := ApplicationRegistration{
		ID:              generateSAIID("registration"),
		RegisteredBy:    req.UserID,
		RegisteredWith:  req.AuthorizationAgentURL,
		RegisteredAt:    now,
		UpdatedAt:       now,
		RegisteredAgent: req.Application.ID,
		HasAccessGrant:  "", // Will be set when access is granted
	}

	// Store the registration
	if err := s.storage.StoreApplicationRegistration(ctx, &registration); err != nil {
		return nil, fmt.Errorf("%w: failed to store application registration: %v", ErrSAIService, err)
	}

	s.logInfo("Application registered",
		"application_id", req.Application.ID,
		"registration_id", registration.ID,
		"user_id", req.UserID)

	return &RegisterApplicationResponse{
		ApplicationRegistration: registration,
		Application:             req.Application,
	}, nil
}

// validateRegisterApplicationRequest validates a RegisterApplicationRequest
func (s *SAIService) validateRegisterApplicationRequest(req RegisterApplicationRequest) error {
	// Validate user ID
	if err := ValidateWebID(req.UserID); err != nil {
		return fmt.Errorf("invalid user ID: %v", err)
	}

	// Validate authorization agent URL
	if err := ValidateURL(req.AuthorizationAgentURL); err != nil {
		return fmt.Errorf("invalid authorization agent URL: %v", err)
	}

	// Validate application
	if err := ValidateApplication(&req.Application); err != nil {
		return fmt.Errorf("invalid application: %v", err)
	}

	return nil
}

// =============================================================================
// Authorization Agent Discovery Service
// =============================================================================

// DiscoverAuthorizationAgentRequest contains parameters for discovering an authorization agent
type DiscoverAuthorizationAgentRequest struct {
	// UserID is the WebID of the user
	UserID string
}

// DiscoverAuthorizationAgentResponse contains the discovered authorization agent
type DiscoverAuthorizationAgentResponse struct {
	// AuthorizationAgent is the discovered authorization agent
	AuthorizationAgent AuthorizationAgent
	// ApplicationRegistrationID is the registration ID if the application is already registered
	ApplicationRegistrationID string
	// HasExistingGrant indicates if there's already an access grant
	HasExistingGrant bool
}

// DiscoverAuthorizationAgent discovers the authorization agent for a user
// This implements the discovery flow from the SAI spec section 4.1
func (s *SAIService) DiscoverAuthorizationAgent(ctx context.Context, req DiscoverAuthorizationAgentRequest) (*DiscoverAuthorizationAgentResponse, error) {
	// Validate context
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	// Validate user ID
	if err := ValidateWebID(req.UserID); err != nil {
		return nil, fmt.Errorf("%w: invalid user ID: %v", ErrSAIService, err)
	}

	// For now, we'll return a default authorization agent
	// In a real implementation, this would discover the agent from the user's WebID profile
	// by looking for interop:hasAuthorizationAgent predicate

	// Check if user has existing registrations
	registrations, err := s.storage.ListApplicationRegistrations(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list application registrations: %v", ErrSAIService, err)
	}

	// Check if there are any existing access grants
	grants, err := s.storage.ListAccessGrants(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list access grants: %v", ErrSAIService, err)
	}

	// Create default authorization agent
	// In production, this would be discovered from the user's WebID profile
	authorizationAgent := AuthorizationAgent{
		ID: s.options.AuthorizationAgentURL,
	}

	// If we have an authorization agent URL from config, use it
	if s.options.AuthorizationAgentURL != "" {
		authorizationAgent.ID = s.options.AuthorizationAgentURL
	}

	response := &DiscoverAuthorizationAgentResponse{
		AuthorizationAgent: authorizationAgent,
		HasExistingGrant:   len(grants) > 0,
	}

	// If there are registrations, return the first one's ID
	if len(registrations) > 0 {
		response.ApplicationRegistrationID = registrations[0].ID
	}

	s.logInfo("Authorization agent discovered",
		"user_id", req.UserID,
		"authorization_agent", authorizationAgent.ID,
		"has_existing_grant", response.HasExistingGrant)

	return response, nil
}

// =============================================================================
// Authorization Flow Service
// =============================================================================

// InitiateAuthorizationFlowRequest contains parameters for initiating an authorization flow
type InitiateAuthorizationFlowRequest struct {
	// ApplicationID is the WebID of the application
	ApplicationID string
	// UserID is the WebID of the user
	UserID string
	// CallbackURL is where to redirect after consent
	CallbackURL string
	// AccessNeedGroupIDs are the access need groups being requested
	AccessNeedGroupIDs []string
	// ResourceIndication is an optional resource being shared (for resource-specific flows)
	ResourceIndication string
}

// InitiateAuthorizationFlowResponse contains the result of initiating an authorization flow
type InitiateAuthorizationFlowResponse struct {
	// AuthorizationURL is the URL to redirect the user to for consent
	AuthorizationURL string
	// FlowID is a unique identifier for this authorization flow
	FlowID string
	// State is a CSRF protection token
	State string
}

// InitiateAuthorizationFlow initiates the authorization flow for an application
// This implements the flow from SAI spec section 4.3
func (s *SAIService) InitiateAuthorizationFlow(ctx context.Context, req InitiateAuthorizationFlowRequest) (*InitiateAuthorizationFlowResponse, error) {
	// Validate context
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	// Validate request
	if err := s.validateInitiateAuthorizationFlowRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSAIService, err)
	}

	// Discover authorization agent
	discoveryReq := DiscoverAuthorizationAgentRequest{
		UserID: req.UserID,
	}
	discoveryResp, err := s.DiscoverAuthorizationAgent(ctx, discoveryReq)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to discover authorization agent: %v", ErrSAIService, err)
	}

	// Generate flow ID and state for CSRF protection
	flowID := generateSAIID("flow")
	state := generateSAIID("state")

	// Create authorization URL
	// In a real implementation, this would redirect to the authorization agent
	// with appropriate parameters
	authURL, err := s.createAuthorizationURL(discoveryResp.AuthorizationAgent.ID, req, flowID, state)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create authorization URL: %v", ErrSAIService, err)
	}

	s.logInfo("Authorization flow initiated",
		"flow_id", flowID,
		"application_id", req.ApplicationID,
		"user_id", req.UserID,
		"authorization_url", authURL)

	return &InitiateAuthorizationFlowResponse{
		AuthorizationURL: authURL,
		FlowID:           flowID,
		State:            state,
	}, nil
}

// validateInitiateAuthorizationFlowRequest validates an InitiateAuthorizationFlowRequest
func (s *SAIService) validateInitiateAuthorizationFlowRequest(req InitiateAuthorizationFlowRequest) error {
	// Validate application ID
	if err := ValidateWebID(req.ApplicationID); err != nil {
		return fmt.Errorf("invalid application ID: %v", err)
	}

	// Validate user ID
	if err := ValidateWebID(req.UserID); err != nil {
		return fmt.Errorf("invalid user ID: %v", err)
	}

	// Validate callback URL
	if err := ValidateURL(req.CallbackURL); err != nil {
		return fmt.Errorf("invalid callback URL: %v", err)
	}

	// Validate access need group IDs
	for i, id := range req.AccessNeedGroupIDs {
		if err := ValidateIRI(id); err != nil {
			return fmt.Errorf("invalid access need group ID at index %d: %v", i, err)
		}
	}

	return nil
}

// createAuthorizationURL creates the authorization URL for the flow
func (s *SAIService) createAuthorizationURL(agentURL string, req InitiateAuthorizationFlowRequest, flowID, state string) (string, error) {
	// Parse the authorization agent URL
	baseURL, err := url.Parse(agentURL)
	if err != nil {
		return "", fmt.Errorf("invalid authorization agent URL: %v", err)
	}

	// Create query parameters
	params := url.Values{}
	params.Set("application_id", req.ApplicationID)
	params.Set("user_id", req.UserID)
	params.Set("callback_url", req.CallbackURL)
	params.Set("flow_id", flowID)
	params.Set("state", state)

	// Add access need groups
	for _, groupID := range req.AccessNeedGroupIDs {
		params.Add("access_need_group", groupID)
	}

	// Add resource indication if present
	if req.ResourceIndication != "" {
		params.Set("resource_indication", req.ResourceIndication)
	}

	// Create the final URL
	baseURL.Path = "/authorize"
	baseURL.RawQuery = params.Encode()

	return baseURL.String(), nil
}

// =============================================================================
// Access Grant Service
// =============================================================================

// CreateAccessGrantRequest contains parameters for creating an access grant
type CreateAccessGrantRequest struct {
	// UserID is the WebID of the user granting access
	UserID string
	// ApplicationID is the WebID of the application
	ApplicationID string
	// AccessNeedGroupIDs are the access need groups being granted
	AccessNeedGroupIDs []string
	// DataGrants are the data grants being created
	DataGrants []DataGrant
	// AuthorizationAgentURL is the URL of the authorization agent
	AuthorizationAgentURL string
}

// CreateAccessGrantResponse contains the created access grant
type CreateAccessGrantResponse struct {
	// AccessGrant is the created access grant
	AccessGrant AccessGrant
	// ApplicationRegistration is the updated application registration
	ApplicationRegistration ApplicationRegistration
}

// CreateAccessGrant creates an access grant for an application
func (s *SAIService) CreateAccessGrant(ctx context.Context, req CreateAccessGrantRequest) (*CreateAccessGrantResponse, error) {
	// Validate context
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	// Validate request
	if err := s.validateCreateAccessGrantRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSAIService, err)
	}

	now := time.Now().UTC()

	// Create the access grant subject
	grantSubject := AccessGrantSubject{
		ID:                  generateSAIID("grant-subject"),
		AccessByAgent:       req.UserID,
		AccessByApplication: req.ApplicationID,
	}

	// Create the access grant
	accessGrant := AccessGrant{
		ID:                    generateSAIID("access-grant"),
		GrantedBy:             req.UserID,
		GrantedWith:           req.AuthorizationAgentURL,
		GrantedAt:             now,
		ProvidedAt:            now,
		UpdatedAt:             now,
		FromAgent:             req.UserID,
		ViaAgent:              req.UserID,
		HasAccessGrantSubject: grantSubject,
		HasAccessNeedGroup:    req.AccessNeedGroupIDs,
		HasDataGrant:          make([]string, len(req.DataGrants)),
	}

	// Store the data grants and collect their IDs
	for i, dataGrant := range req.DataGrants {
		// Set the data grant ID if not already set
		if dataGrant.ID == "" {
			dataGrant.ID = generateSAIID("data-grant")
		}

		// Store the data grant
		if err := s.storage.StoreDataGrant(ctx, &dataGrant); err != nil {
			return nil, fmt.Errorf("%w: failed to store data grant: %v", ErrSAIService, err)
		}

		accessGrant.HasDataGrant[i] = dataGrant.ID
	}

	// Store the access grant
	if err := s.storage.StoreAccessGrant(ctx, &accessGrant); err != nil {
		return nil, fmt.Errorf("%w: failed to store access grant: %v", ErrSAIService, err)
	}

	// Find and update the application registration
	registrations, err := s.storage.ListApplicationRegistrations(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list application registrations: %v", ErrSAIService, err)
	}

	var updatedRegistration ApplicationRegistration
	found := false

	// Find the registration for this application
	for _, reg := range registrations {
		if reg.RegisteredAgent == req.ApplicationID {
			updatedRegistration = *reg
			updatedRegistration.HasAccessGrant = accessGrant.ID
			updatedRegistration.UpdatedAt = now
			found = true
			break
		}
	}

	// If no existing registration, create one
	if !found {
		updatedRegistration = ApplicationRegistration{
			ID:              generateSAIID("registration"),
			RegisteredBy:    req.UserID,
			RegisteredWith:  req.AuthorizationAgentURL,
			RegisteredAt:    now,
			UpdatedAt:       now,
			RegisteredAgent: req.ApplicationID,
			HasAccessGrant:  accessGrant.ID,
		}
	}

	// Store the registration
	if err := s.storage.StoreApplicationRegistration(ctx, &updatedRegistration); err != nil {
		return nil, fmt.Errorf("%w: failed to store application registration: %v", ErrSAIService, err)
	}

	s.logInfo("Access grant created",
		"access_grant_id", accessGrant.ID,
		"user_id", req.UserID,
		"application_id", req.ApplicationID,
		"data_grant_count", len(accessGrant.HasDataGrant))

	return &CreateAccessGrantResponse{
		AccessGrant:             accessGrant,
		ApplicationRegistration: updatedRegistration,
	}, nil
}

// validateCreateAccessGrantRequest validates a CreateAccessGrantRequest
func (s *SAIService) validateCreateAccessGrantRequest(req CreateAccessGrantRequest) error {
	// Validate user ID
	if err := ValidateWebID(req.UserID); err != nil {
		return fmt.Errorf("invalid user ID: %v", err)
	}

	// Validate application ID
	if err := ValidateWebID(req.ApplicationID); err != nil {
		return fmt.Errorf("invalid application ID: %v", err)
	}

	// Validate authorization agent URL
	if err := ValidateURL(req.AuthorizationAgentURL); err != nil {
		return fmt.Errorf("invalid authorization agent URL: %v", err)
	}

	// Validate access need group IDs
	for i, id := range req.AccessNeedGroupIDs {
		if err := ValidateIRI(id); err != nil {
			return fmt.Errorf("invalid access need group ID at index %d: %v", i, err)
		}
	}

	// Validate data grants
	for i, grant := range req.DataGrants {
		if err := ValidateDataGrant(&grant); err != nil {
			return fmt.Errorf("invalid data grant at index %d: %v", i, err)
		}
	}

	return nil
}

// =============================================================================
// Data Registration Service
// =============================================================================

// RegisterDataRequest contains parameters for registering data
type RegisterDataRequest struct {
	// UserID is the WebID of the user registering the data
	UserID string
	// ApplicationID is the WebID of the application
	ApplicationID string
	// ShapeTreeID is the ID of the shape tree for this data
	ShapeTreeID string
	// IRIPrefix is the base IRI for new data instances
	IRIPrefix string
	// InitialDataInstances are the initial data instances
	InitialDataInstances []DataInstance
}

// RegisterDataResponse contains the result of registering data
type RegisterDataResponse struct {
	// DataRegistration is the created registration
	DataRegistration DataRegistration
	// DataInstances are the stored data instances
	DataInstances []DataInstance
}

// RegisterData registers data with a shape tree
func (s *SAIService) RegisterData(ctx context.Context, req RegisterDataRequest) (*RegisterDataResponse, error) {
	// Validate context
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	// Validate request
	if err := s.validateRegisterDataRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSAIService, err)
	}

	now := time.Now().UTC()

	// Create the data registration
	registration := DataRegistration{
		ID:                  generateSAIID("data-registration"),
		RegisteredShapeTree: req.ShapeTreeID,
		RegisteredAt:        now,
		RegisteredBy:        req.UserID,
		RegisteredWith:      req.ApplicationID,
		IRIPrefix:           req.IRIPrefix,
		Contains:            make([]string, len(req.InitialDataInstances)),
	}

	// Store the data instances and collect their IDs
	for i, instance := range req.InitialDataInstances {
		// Set the instance ID if not already set
		if instance.ID == "" {
			instance.ID = s.generateDataInstanceID(registration.IRIPrefix)
		}

		// Validate the instance
		if err := ValidateDataInstance(&instance); err != nil {
			return nil, fmt.Errorf("%w: invalid data instance at index %d: %v", ErrSAIService, i, err)
		}

		// Store the data instance
		if err := s.storage.StoreDataInstance(ctx, &instance); err != nil {
			return nil, fmt.Errorf("%w: failed to store data instance: %v", ErrSAIService, err)
		}

		registration.Contains[i] = instance.ID
	}

	// Store the registration
	if err := s.storage.StoreDataRegistration(ctx, &registration); err != nil {
		return nil, fmt.Errorf("%w: failed to store data registration: %v", ErrSAIService, err)
	}

	s.logInfo("Data registered",
		"registration_id", registration.ID,
		"user_id", req.UserID,
		"application_id", req.ApplicationID,
		"shape_tree_id", req.ShapeTreeID,
		"data_instance_count", len(registration.Contains))

	// Retrieve the stored data instances for the response
	storedInstances := make([]DataInstance, len(registration.Contains))
	for i, instanceID := range registration.Contains {
		instance, err := s.storage.GetDataInstance(ctx, instanceID)
		if err != nil {
			// This shouldn't happen since we just stored them, but handle it gracefully
			s.logError("Failed to retrieve stored data instance", "instance_id", instanceID, "error", err)
			continue
		}
		storedInstances[i] = *instance
	}

	return &RegisterDataResponse{
		DataRegistration: registration,
		DataInstances:    storedInstances,
	}, nil
}

// validateRegisterDataRequest validates a RegisterDataRequest
func (s *SAIService) validateRegisterDataRequest(req RegisterDataRequest) error {
	// Validate user ID
	if err := ValidateWebID(req.UserID); err != nil {
		return fmt.Errorf("invalid user ID: %v", err)
	}

	// Validate application ID
	if err := ValidateWebID(req.ApplicationID); err != nil {
		return fmt.Errorf("invalid application ID: %v", err)
	}

	// Validate shape tree ID
	if err := ValidateIRI(req.ShapeTreeID); err != nil {
		return fmt.Errorf("invalid shape tree ID: %v", err)
	}

	// Validate IRI prefix
	if err := ValidateURL(req.IRIPrefix); err != nil {
		return fmt.Errorf("invalid IRI prefix: %v", err)
	}

	// Validate initial data instances
	for i, instance := range req.InitialDataInstances {
		if err := ValidateDataInstance(&instance); err != nil {
			return fmt.Errorf("invalid data instance at index %d: %v", i, err)
		}
	}

	return nil
}

// generateDataInstanceID generates a unique ID for a data instance
func (s *SAIService) generateDataInstanceID(prefix string) string {
	// Generate a hash-based ID using the prefix and current time
	hash := sha256.Sum256([]byte(prefix + time.Now().Format(time.RFC3339Nano)))
	return prefix + hex.EncodeToString(hash[:])[:16]
}

// =============================================================================
// Utility Functions
// =============================================================================

// generateSAIID generates a unique ID for SAI entities
func generateSAIID(prefix string) string {
	hash := sha256.Sum256([]byte(prefix + time.Now().Format(time.RFC3339Nano)))
	return "urn:sai:" + prefix + ":" + hex.EncodeToString(hash[:])[:24]
}

// ParseAuthorizationAgentFromWebID parses an authorization agent URL from a user's WebID profile
// This would typically fetch the WebID document and look for interop:hasAuthorizationAgent
func (s *SAIService) ParseAuthorizationAgentFromWebID(ctx context.Context, webID string) (string, error) {
	// For now, return the configured authorization agent URL
	// In a real implementation, this would:
	// 1. Fetch the WebID document
	// 2. Parse it as RDF
	// 3. Look for triples with predicate interop:hasAuthorizationAgent
	// 4. Return the object of such triples

	if s.options.AuthorizationAgentURL != "" {
		return s.options.AuthorizationAgentURL, nil
	}

	return "", fmt.Errorf("authorization agent URL not configured")
}

// GetApplicationRegistration retrieves an application registration by ID
func (s *SAIService) GetApplicationRegistration(ctx context.Context, id string) (*ApplicationRegistration, error) {
	if err := ValidateIRI(id); err != nil {
		return nil, fmt.Errorf("%w: invalid registration ID: %v", ErrSAIService, err)
	}

	return s.storage.GetApplicationRegistration(ctx, id)
}

// GetAccessGrant retrieves an access grant by ID
func (s *SAIService) GetAccessGrant(ctx context.Context, id string) (*AccessGrant, error) {
	if err := ValidateIRI(id); err != nil {
		return nil, fmt.Errorf("%w: invalid grant ID: %v", ErrSAIService, err)
	}

	return s.storage.GetAccessGrant(ctx, id)
}

// ListAccessGrantsForUser lists all access grants for a user
func (s *SAIService) ListAccessGrantsForUser(ctx context.Context, userID string) ([]*AccessGrant, error) {
	if err := ValidateWebID(userID); err != nil {
		return nil, fmt.Errorf("%w: invalid user ID: %v", ErrSAIService, err)
	}

	return s.storage.ListAccessGrants(ctx, userID)
}

// ListDataRegistrationsForUser lists all data registrations for a user
func (s *SAIService) ListDataRegistrationsForUser(ctx context.Context, userID string) ([]*DataRegistration, error) {
	if err := ValidateWebID(userID); err != nil {
		return nil, fmt.Errorf("%w: invalid user ID: %v", ErrSAIService, err)
	}

	return s.storage.ListDataRegistrations(ctx, userID)
}

// =============================================================================
// Application Service Methods
// =============================================================================

// GetApplication retrieves an application by ID
func (s *SAIService) GetApplication(ctx context.Context, id string) (*Application, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	if err := ValidateIRI(id); err != nil {
		return nil, fmt.Errorf("%w: invalid application ID: %v", ErrSAIService, err)
	}

	return s.storage.GetApplication(ctx, id)
}

// ListApplications lists all applications for a specific owner
func (s *SAIService) ListApplications(ctx context.Context, owner string) ([]*Application, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	if err := ValidateWebID(owner); err != nil {
		return nil, fmt.Errorf("%w: invalid owner ID: %v", ErrSAIService, err)
	}

	return s.storage.ListApplications(ctx, owner)
}

// =============================================================================
// Shape Tree Service Methods
// =============================================================================

// StoreShapeTree stores a shape tree definition
func (s *SAIService) StoreShapeTree(ctx context.Context, tree *ShapeTree) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	if tree == nil {
		return fmt.Errorf("%w: shape tree cannot be nil", ErrSAIService)
	}

	if err := ValidateIRI(tree.ID); err != nil {
		return fmt.Errorf("%w: invalid shape tree ID: %v", ErrSAIService, err)
	}

	return s.storage.StoreShapeTree(ctx, tree)
}

// GetShapeTree retrieves a shape tree by ID
func (s *SAIService) GetShapeTree(ctx context.Context, id string) (*ShapeTree, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	if err := ValidateIRI(id); err != nil {
		return nil, fmt.Errorf("%w: invalid shape tree ID: %v", ErrSAIService, err)
	}

	return s.storage.GetShapeTree(ctx, id)
}

// ListShapeTrees lists all available shape trees
func (s *SAIService) ListShapeTrees(ctx context.Context) ([]*ShapeTree, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	return s.storage.ListShapeTrees(ctx)
}

// =============================================================================
// Data Registration Service Methods
// =============================================================================

// GetDataRegistration retrieves a data registration by ID
func (s *SAIService) GetDataRegistration(ctx context.Context, id string) (*DataRegistration, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: context cancelled: %v", ErrSAIService, err)
	}

	if err := ValidateIRI(id); err != nil {
		return nil, fmt.Errorf("%w: invalid data registration ID: %v", ErrSAIService, err)
	}

	return s.storage.GetDataRegistration(ctx, id)
}

// =============================================================================
// HTTP Handler Integration
// =============================================================================

// HTTPHandler creates an HTTP handler for the SAI service
// Note: HTTP endpoint implementations are provided in handler.go
