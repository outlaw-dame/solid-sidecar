// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"context"
	"errors"
	"testing"
	"time"
)

// MockSAIStorage implements SAIStorage for testing
// Note: This is a simplified version. In a real implementation, you might want to use
// a more sophisticated mocking framework or the actual in-memory storage.
type MockSAIStorage struct {
	applications             map[string]*Application
	applicationRegistrations map[string]*ApplicationRegistration
	accessGrants             map[string]*AccessGrant
	dataRegistrations        map[string]*DataRegistration
	dataGrants               map[string]*DataGrant
	dataInstances            map[string]*DataInstance
	shapeTrees               map[string]*ShapeTree
	authorizationAgents      map[string]*AuthorizationAgent

	// Errors to simulate
	storeApplicationError  error
	getApplicationError    error
	listApplicationsError  error
	deleteApplicationError error

	storeApplicationRegistrationError  error
	getApplicationRegistrationError    error
	listApplicationRegistrationsError  error
	deleteApplicationRegistrationError error

	storeAccessGrantError  error
	getAccessGrantError    error
	listAccessGrantsError  error
	deleteAccessGrantError error

	storeDataRegistrationError  error
	getDataRegistrationError    error
	listDataRegistrationsError  error
	deleteDataRegistrationError error

	storeDataGrantError  error
	getDataGrantError    error
	listDataGrantsError  error
	deleteDataGrantError error

	storeDataInstanceError  error
	getDataInstanceError    error
	listDataInstancesError  error
	deleteDataInstanceError error

	storeShapeTreeError  error
	getShapeTreeError    error
	listShapeTreesError  error
	deleteShapeTreeError error

	storeAuthorizationAgentError  error
	getAuthorizationAgentError    error
	listAuthorizationAgentsError  error
	deleteAuthorizationAgentError error
}

// NewMockSAIStorage creates a new mock SAI storage
func NewMockSAIStorage() *MockSAIStorage {
	return &MockSAIStorage{
		applications:             make(map[string]*Application),
		applicationRegistrations: make(map[string]*ApplicationRegistration),
		accessGrants:             make(map[string]*AccessGrant),
		dataRegistrations:        make(map[string]*DataRegistration),
		dataGrants:               make(map[string]*DataGrant),
		dataInstances:            make(map[string]*DataInstance),
		shapeTrees:               make(map[string]*ShapeTree),
		authorizationAgents:      make(map[string]*AuthorizationAgent),
	}
}

// SetStoreApplicationError sets an error for StoreApplication
func (m *MockSAIStorage) SetStoreApplicationError(err error) {
	m.storeApplicationError = err
}

// ResetErrors resets all error conditions
func (m *MockSAIStorage) ResetErrors() {
	m.storeApplicationError = nil
	m.getApplicationError = nil
	m.listApplicationsError = nil
	m.deleteApplicationError = nil
	m.storeApplicationRegistrationError = nil
	m.getApplicationRegistrationError = nil
	m.listApplicationRegistrationsError = nil
	m.deleteApplicationRegistrationError = nil
	m.storeAccessGrantError = nil
	m.getAccessGrantError = nil
	m.listAccessGrantsError = nil
	m.deleteAccessGrantError = nil
	m.storeDataRegistrationError = nil
	m.getDataRegistrationError = nil
	m.listDataRegistrationsError = nil
	m.deleteDataRegistrationError = nil
	m.storeDataGrantError = nil
	m.getDataGrantError = nil
	m.listDataGrantsError = nil
	m.deleteDataGrantError = nil
	m.storeDataInstanceError = nil
	m.getDataInstanceError = nil
	m.listDataInstancesError = nil
	m.deleteDataInstanceError = nil
	m.storeShapeTreeError = nil
	m.getShapeTreeError = nil
	m.listShapeTreesError = nil
	m.deleteShapeTreeError = nil
	m.storeAuthorizationAgentError = nil
	m.getAuthorizationAgentError = nil
	m.listAuthorizationAgentsError = nil
	m.deleteAuthorizationAgentError = nil
}

// =============================================================================
// Mock Storage Methods
// =============================================================================

func (m *MockSAIStorage) StoreApplication(ctx context.Context, app *Application) error {
	if m.storeApplicationError != nil {
		return m.storeApplicationError
	}
	m.applications[app.ID] = app
	return nil
}

func (m *MockSAIStorage) GetApplication(ctx context.Context, id string) (*Application, error) {
	if m.getApplicationError != nil {
		return nil, m.getApplicationError
	}
	app, exists := m.applications[id]
	if !exists {
		return nil, ErrSAINotFound
	}
	return app, nil
}

func (m *MockSAIStorage) ListApplications(ctx context.Context, owner string) ([]*Application, error) {
	if m.listApplicationsError != nil {
		return nil, m.listApplicationsError
	}
	var result []*Application
	for _, app := range m.applications {
		result = append(result, app)
	}
	return result, nil
}

func (m *MockSAIStorage) DeleteApplication(ctx context.Context, id string) error {
	if m.deleteApplicationError != nil {
		return m.deleteApplicationError
	}
	delete(m.applications, id)
	return nil
}

func (m *MockSAIStorage) StoreApplicationRegistration(ctx context.Context, reg *ApplicationRegistration) error {
	if m.storeApplicationRegistrationError != nil {
		return m.storeApplicationRegistrationError
	}
	m.applicationRegistrations[reg.ID] = reg
	return nil
}

func (m *MockSAIStorage) GetApplicationRegistration(ctx context.Context, id string) (*ApplicationRegistration, error) {
	if m.getApplicationRegistrationError != nil {
		return nil, m.getApplicationRegistrationError
	}
	reg, exists := m.applicationRegistrations[id]
	if !exists {
		return nil, ErrSAINotFound
	}
	return reg, nil
}

func (m *MockSAIStorage) ListApplicationRegistrations(ctx context.Context, userID string) ([]*ApplicationRegistration, error) {
	if m.listApplicationRegistrationsError != nil {
		return nil, m.listApplicationRegistrationsError
	}
	var result []*ApplicationRegistration
	for _, reg := range m.applicationRegistrations {
		if reg.RegisteredBy == userID {
			result = append(result, reg)
		}
	}
	return result, nil
}

func (m *MockSAIStorage) DeleteApplicationRegistration(ctx context.Context, id string) error {
	if m.deleteApplicationRegistrationError != nil {
		return m.deleteApplicationRegistrationError
	}
	delete(m.applicationRegistrations, id)
	return nil
}

func (m *MockSAIStorage) StoreAccessGrant(ctx context.Context, grant *AccessGrant) error {
	if m.storeAccessGrantError != nil {
		return m.storeAccessGrantError
	}
	m.accessGrants[grant.ID] = grant
	return nil
}

func (m *MockSAIStorage) GetAccessGrant(ctx context.Context, id string) (*AccessGrant, error) {
	if m.getAccessGrantError != nil {
		return nil, m.getAccessGrantError
	}
	grant, exists := m.accessGrants[id]
	if !exists {
		return nil, ErrSAINotFound
	}
	return grant, nil
}

func (m *MockSAIStorage) ListAccessGrants(ctx context.Context, userID string) ([]*AccessGrant, error) {
	if m.listAccessGrantsError != nil {
		return nil, m.listAccessGrantsError
	}
	var result []*AccessGrant
	for _, grant := range m.accessGrants {
		if grant.FromAgent == userID {
			result = append(result, grant)
		}
	}
	return result, nil
}

func (m *MockSAIStorage) DeleteAccessGrant(ctx context.Context, id string) error {
	if m.deleteAccessGrantError != nil {
		return m.deleteAccessGrantError
	}
	delete(m.accessGrants, id)
	return nil
}

func (m *MockSAIStorage) StoreDataRegistration(ctx context.Context, reg *DataRegistration) error {
	if m.storeDataRegistrationError != nil {
		return m.storeDataRegistrationError
	}
	m.dataRegistrations[reg.ID] = reg
	return nil
}

func (m *MockSAIStorage) GetDataRegistration(ctx context.Context, id string) (*DataRegistration, error) {
	if m.getDataRegistrationError != nil {
		return nil, m.getDataRegistrationError
	}
	reg, exists := m.dataRegistrations[id]
	if !exists {
		return nil, ErrSAINotFound
	}
	return reg, nil
}

func (m *MockSAIStorage) ListDataRegistrations(ctx context.Context, userID string) ([]*DataRegistration, error) {
	if m.listDataRegistrationsError != nil {
		return nil, m.listDataRegistrationsError
	}
	var result []*DataRegistration
	for _, reg := range m.dataRegistrations {
		if reg.RegisteredBy == userID {
			result = append(result, reg)
		}
	}
	return result, nil
}

func (m *MockSAIStorage) DeleteDataRegistration(ctx context.Context, id string) error {
	if m.deleteDataRegistrationError != nil {
		return m.deleteDataRegistrationError
	}
	delete(m.dataRegistrations, id)
	return nil
}

func (m *MockSAIStorage) StoreDataGrant(ctx context.Context, grant *DataGrant) error {
	if m.storeDataGrantError != nil {
		return m.storeDataGrantError
	}
	m.dataGrants[grant.ID] = grant
	return nil
}

func (m *MockSAIStorage) GetDataGrant(ctx context.Context, id string) (*DataGrant, error) {
	if m.getDataGrantError != nil {
		return nil, m.getDataGrantError
	}
	grant, exists := m.dataGrants[id]
	if !exists {
		return nil, ErrSAINotFound
	}
	return grant, nil
}

func (m *MockSAIStorage) ListDataGrants(ctx context.Context, accessGrantID string) ([]*DataGrant, error) {
	if m.listDataGrantsError != nil {
		return nil, m.listDataGrantsError
	}
	// Simple implementation: return all data grants
	var result []*DataGrant
	for _, grant := range m.dataGrants {
		result = append(result, grant)
	}
	return result, nil
}

func (m *MockSAIStorage) DeleteDataGrant(ctx context.Context, id string) error {
	if m.deleteDataGrantError != nil {
		return m.deleteDataGrantError
	}
	delete(m.dataGrants, id)
	return nil
}

func (m *MockSAIStorage) StoreDataInstance(ctx context.Context, instance *DataInstance) error {
	if m.storeDataInstanceError != nil {
		return m.storeDataInstanceError
	}
	m.dataInstances[instance.ID] = instance
	return nil
}

func (m *MockSAIStorage) GetDataInstance(ctx context.Context, id string) (*DataInstance, error) {
	if m.getDataInstanceError != nil {
		return nil, m.getDataInstanceError
	}
	instance, exists := m.dataInstances[id]
	if !exists {
		return nil, ErrSAINotFound
	}
	return instance, nil
}

func (m *MockSAIStorage) ListDataInstances(ctx context.Context, registrationID string) ([]*DataInstance, error) {
	if m.listDataInstancesError != nil {
		return nil, m.listDataInstancesError
	}
	// Simple implementation: return all data instances
	var result []*DataInstance
	for _, instance := range m.dataInstances {
		result = append(result, instance)
	}
	return result, nil
}

func (m *MockSAIStorage) DeleteDataInstance(ctx context.Context, id string) error {
	if m.deleteDataInstanceError != nil {
		return m.deleteDataInstanceError
	}
	delete(m.dataInstances, id)
	return nil
}

func (m *MockSAIStorage) StoreShapeTree(ctx context.Context, tree *ShapeTree) error {
	if m.storeShapeTreeError != nil {
		return m.storeShapeTreeError
	}
	m.shapeTrees[tree.ID] = tree
	return nil
}

func (m *MockSAIStorage) GetShapeTree(ctx context.Context, id string) (*ShapeTree, error) {
	if m.getShapeTreeError != nil {
		return nil, m.getShapeTreeError
	}
	tree, exists := m.shapeTrees[id]
	if !exists {
		return nil, ErrSAINotFound
	}
	return tree, nil
}

func (m *MockSAIStorage) ListShapeTrees(ctx context.Context) ([]*ShapeTree, error) {
	if m.listShapeTreesError != nil {
		return nil, m.listShapeTreesError
	}
	var result []*ShapeTree
	for _, tree := range m.shapeTrees {
		result = append(result, tree)
	}
	return result, nil
}

func (m *MockSAIStorage) DeleteShapeTree(ctx context.Context, id string) error {
	if m.deleteShapeTreeError != nil {
		return m.deleteShapeTreeError
	}
	delete(m.shapeTrees, id)
	return nil
}

func (m *MockSAIStorage) StoreAuthorizationAgent(ctx context.Context, agent *AuthorizationAgent) error {
	if m.storeAuthorizationAgentError != nil {
		return m.storeAuthorizationAgentError
	}
	m.authorizationAgents[agent.ID] = agent
	return nil
}

func (m *MockSAIStorage) GetAuthorizationAgent(ctx context.Context, id string) (*AuthorizationAgent, error) {
	if m.getAuthorizationAgentError != nil {
		return nil, m.getAuthorizationAgentError
	}
	agent, exists := m.authorizationAgents[id]
	if !exists {
		return nil, ErrSAINotFound
	}
	return agent, nil
}

func (m *MockSAIStorage) ListAuthorizationAgents(ctx context.Context) ([]*AuthorizationAgent, error) {
	if m.listAuthorizationAgentsError != nil {
		return nil, m.listAuthorizationAgentsError
	}
	var result []*AuthorizationAgent
	for _, agent := range m.authorizationAgents {
		result = append(result, agent)
	}
	return result, nil
}

func (m *MockSAIStorage) DeleteAuthorizationAgent(ctx context.Context, id string) error {
	if m.deleteAuthorizationAgentError != nil {
		return m.deleteAuthorizationAgentError
	}
	delete(m.authorizationAgents, id)
	return nil
}

// =============================================================================
// Service Tests
// =============================================================================

// TestSAIServiceCreation tests SAI service creation
func TestSAIServiceCreation(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		options := DefaultSAIServiceOptions()
		if options.Timeout <= 0 {
			t.Errorf("expected positive timeout, got %v", options.Timeout)
		}
		if options.MaxRetries <= 0 {
			t.Errorf("expected positive max retries, got %v", options.MaxRetries)
		}
	})

	t.Run("create service with default storage", func(t *testing.T) {
		options := DefaultSAIServiceOptions()
		service, err := NewSAIService(options)
		if err != nil {
			t.Fatalf("failed to create SAI service: %v", err)
		}
		if service == nil {
			t.Fatal("expected non-nil service")
		}
		// Service should be created successfully
		t.Log("SAI service created with default storage")
	})

	t.Run("create service with mock storage", func(t *testing.T) {
		mockStorage := NewMockSAIStorage()
		options := SAIServiceOptions{
			Storage:    mockStorage,
			Timeout:    time.Second * 10,
			MaxRetries: 2,
		}
		service, err := NewSAIService(options)
		if err != nil {
			t.Fatalf("failed to create SAI service: %v", err)
		}
		if service == nil {
			t.Fatal("expected non-nil service")
		}
		t.Log("SAI service created with mock storage")
	})
}

// TestRegisterApplication tests application registration
func TestRegisterApplication(t *testing.T) {
	ctx := context.Background()
	mockStorage := NewMockSAIStorage()

	options := SAIServiceOptions{
		Storage: mockStorage,
		Timeout: time.Second * 10,
	}

	service, err := NewSAIService(options)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	t.Run("valid application registration", func(t *testing.T) {
		req := RegisterApplicationRequest{
			Application: Application{
				ID:                               "https://projectron.example/#app",
				ApplicationName:                  "Projectron",
				ApplicationDescription:           "Manage projects with ease",
				ApplicationAuthor:                "https://acme.example/#corp",
				HasAuthorizationCallbackEndpoint: "https://projectron.example/callback",
				AuthenticatesAs:                  "https://projectron.example/#app",
				HasAccessNeedGroup:               []AccessNeedGroup{},
			},
			UserID:                "https://alice.example/#id",
			AuthorizationAgentURL: "https://auth.example.com",
		}

		resp, err := service.RegisterApplication(ctx, req)
		if err != nil {
			t.Fatalf("failed to register application: %v", err)
		}

		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		if resp.ApplicationRegistration.ID == "" {
			t.Error("expected non-empty registration ID")
		}

		if resp.ApplicationRegistration.RegisteredBy != req.UserID {
			t.Errorf("expected registered by to be %s, got %s", req.UserID, resp.ApplicationRegistration.RegisteredBy)
		}

		if resp.ApplicationRegistration.RegisteredAgent != req.Application.ID {
			t.Errorf("expected registered agent to be %s, got %s", req.Application.ID, resp.ApplicationRegistration.RegisteredAgent)
		}

		if resp.ApplicationRegistration.RegisteredWith != req.AuthorizationAgentURL {
			t.Errorf("expected registered with to be %s, got %s", req.AuthorizationAgentURL, resp.ApplicationRegistration.RegisteredWith)
		}

		t.Log("Application registered successfully")
	})

	t.Run("invalid application registration - invalid user ID", func(t *testing.T) {
		req := RegisterApplicationRequest{
			Application: Application{
				ID:                     "https://projectron.example/#app",
				ApplicationName:        "Projectron",
				ApplicationDescription: "Manage projects with ease",
			},
			UserID:                "invalid-webid", // Missing fragment
			AuthorizationAgentURL: "https://auth.example.com",
		}

		_, err := service.RegisterApplication(ctx, req)
		if err == nil {
			t.Error("expected error for invalid user ID")
		}
	})

	t.Run("invalid application registration - invalid authorization agent URL", func(t *testing.T) {
		req := RegisterApplicationRequest{
			Application: Application{
				ID:                     "https://projectron.example/#app",
				ApplicationName:        "Projectron",
				ApplicationDescription: "Manage projects with ease",
			},
			UserID:                "https://alice.example/#id",
			AuthorizationAgentURL: "invalid-url",
		}

		_, err := service.RegisterApplication(ctx, req)
		if err == nil {
			t.Error("expected error for invalid authorization agent URL")
		}
	})

	t.Run("invalid application registration - invalid application", func(t *testing.T) {
		req := RegisterApplicationRequest{
			Application: Application{
				ID:              "", // Empty ID
				ApplicationName: "Projectron",
			},
			UserID:                "https://alice.example/#id",
			AuthorizationAgentURL: "https://auth.example.com",
		}

		_, err := service.RegisterApplication(ctx, req)
		if err == nil {
			t.Error("expected error for invalid application")
		}
	})
}

// TestDiscoverAuthorizationAgent tests authorization agent discovery
func TestDiscoverAuthorizationAgent(t *testing.T) {
	ctx := context.Background()
	mockStorage := NewMockSAIStorage()

	options := SAIServiceOptions{
		Storage:               mockStorage,
		AuthorizationAgentURL: "https://auth.example.com",
		Timeout:               time.Second * 10,
	}

	service, err := NewSAIService(options)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	t.Run("discover authorization agent", func(t *testing.T) {
		req := DiscoverAuthorizationAgentRequest{
			UserID: "https://alice.example/#id",
		}

		resp, err := service.DiscoverAuthorizationAgent(ctx, req)
		if err != nil {
			t.Fatalf("failed to discover authorization agent: %v", err)
		}

		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		if resp.AuthorizationAgent.ID != "https://auth.example.com" {
			t.Errorf("expected authorization agent ID to be %s, got %s", "https://auth.example.com", resp.AuthorizationAgent.ID)
		}

		t.Log("Authorization agent discovered successfully")
	})

	t.Run("discover with existing registration", func(t *testing.T) {
		// First, create a registration
		regReq := RegisterApplicationRequest{
			Application: Application{
				ID:              "https://projectron.example/#app",
				ApplicationName: "Projectron",
			},
			UserID:                "https://alice.example/#id",
			AuthorizationAgentURL: "https://auth.example.com",
		}
		_, err := service.RegisterApplication(ctx, regReq)
		if err != nil {
			t.Fatalf("failed to create registration: %v", err)
		}

		// Now discover
		req := DiscoverAuthorizationAgentRequest{
			UserID: "https://alice.example/#id",
		}

		resp, err := service.DiscoverAuthorizationAgent(ctx, req)
		if err != nil {
			t.Fatalf("failed to discover authorization agent: %v", err)
		}

		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		if resp.ApplicationRegistrationID == "" {
			t.Error("expected non-empty registration ID")
		}

		t.Log("Authorization agent discovered with existing registration")
	})

	t.Run("discover with invalid user ID", func(t *testing.T) {
		req := DiscoverAuthorizationAgentRequest{
			UserID: "invalid-webid",
		}

		_, err := service.DiscoverAuthorizationAgent(ctx, req)
		if err == nil {
			t.Error("expected error for invalid user ID")
		}
	})
}

// TestInitiateAuthorizationFlow tests authorization flow initiation
func TestInitiateAuthorizationFlow(t *testing.T) {
	ctx := context.Background()
	mockStorage := NewMockSAIStorage()

	options := SAIServiceOptions{
		Storage:               mockStorage,
		AuthorizationAgentURL: "https://auth.example.com",
		Timeout:               time.Second * 10,
	}

	service, err := NewSAIService(options)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	t.Run("initiate authorization flow", func(t *testing.T) {
		req := InitiateAuthorizationFlowRequest{
			ApplicationID:      "https://projectron.example/#app",
			UserID:             "https://alice.example/#id",
			CallbackURL:        "https://projectron.example/callback",
			AccessNeedGroupIDs: []string{"https://projectron.example/#need-group-pm"},
			ResourceIndication: "",
		}

		resp, err := service.InitiateAuthorizationFlow(ctx, req)
		if err != nil {
			t.Fatalf("failed to initiate authorization flow: %v", err)
		}

		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		if resp.AuthorizationURL == "" {
			t.Error("expected non-empty authorization URL")
		}

		if resp.FlowID == "" {
			t.Error("expected non-empty flow ID")
		}

		if resp.State == "" {
			t.Error("expected non-empty state")
		}

		// Check that the URL contains the expected parameters
		if !contains(resp.AuthorizationURL, "application_id=https%3A%2F%2Fprojectron.example%2F%23app") {
			t.Errorf("expected application ID in URL, got %s", resp.AuthorizationURL)
		}

		t.Log("Authorization flow initiated successfully")
	})

	t.Run("initiate with resource indication", func(t *testing.T) {
		req := InitiateAuthorizationFlowRequest{
			ApplicationID:      "https://projectron.example/#app",
			UserID:             "https://alice.example/#id",
			CallbackURL:        "https://projectron.example/callback",
			AccessNeedGroupIDs: []string{"https://projectron.example/#need-group-pm"},
			ResourceIndication: "https://pro.alice.example/project1",
		}

		resp, err := service.InitiateAuthorizationFlow(ctx, req)
		if err != nil {
			t.Fatalf("failed to initiate authorization flow: %v", err)
		}

		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		if !contains(resp.AuthorizationURL, "resource_indication=https%3A%2F%2Fpro.alice.example%2Fproject1") {
			t.Errorf("expected resource indication in URL, got %s", resp.AuthorizationURL)
		}

		t.Log("Authorization flow initiated with resource indication")
	})

	t.Run("initiate with invalid application ID", func(t *testing.T) {
		req := InitiateAuthorizationFlowRequest{
			ApplicationID:      "invalid-webid",
			UserID:             "https://alice.example/#id",
			CallbackURL:        "https://projectron.example/callback",
			AccessNeedGroupIDs: []string{"https://projectron.example/#need-group-pm"},
		}

		_, err := service.InitiateAuthorizationFlow(ctx, req)
		if err == nil {
			t.Error("expected error for invalid application ID")
		}
	})
}

// TestCreateAccessGrant tests access grant creation
func TestCreateAccessGrant(t *testing.T) {
	ctx := context.Background()
	mockStorage := NewMockSAIStorage()

	options := SAIServiceOptions{
		Storage:               mockStorage,
		AuthorizationAgentURL: "https://auth.example.com",
		Timeout:               time.Second * 10,
	}

	service, err := NewSAIService(options)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	t.Run("create access grant", func(t *testing.T) {
		// First, create a data grant
		dataGrant := DataGrant{
			ID:                  "urn:sai:data-grant:test1",
			DataOwner:           "https://alice.example/#id",
			GrantedBy:           "https://alice.example/#id",
			RegisteredShapeTree: "solidtrees:Project",
			HasDataRegistration: "urn:sai:data-registration:test1",
			AccessMode:          []ACLMode{ACLModeRead, ACLModeWrite},
			ScopeOfGrant:        ScopeOfGrantAllFromRegistry,
			HasDataInstance:     []string{"https://pro.alice.example/project1"},
		}

		// Store the data grant directly in mock
		mockStorage.dataGrants[dataGrant.ID] = &dataGrant

		req := CreateAccessGrantRequest{
			UserID:                "https://alice.example/#id",
			ApplicationID:         "https://projectron.example/#app",
			AccessNeedGroupIDs:    []string{"https://projectron.example/#need-group-pm"},
			DataGrants:            []DataGrant{dataGrant},
			AuthorizationAgentURL: "https://auth.example.com",
		}

		resp, err := service.CreateAccessGrant(ctx, req)
		if err != nil {
			t.Fatalf("failed to create access grant: %v", err)
		}

		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		if resp.AccessGrant.ID == "" {
			t.Error("expected non-empty access grant ID")
		}

		if len(resp.AccessGrant.HasDataGrant) != 1 {
			t.Errorf("expected 1 data grant, got %d", len(resp.AccessGrant.HasDataGrant))
		}

		if resp.ApplicationRegistration.RegisteredAgent != req.ApplicationID {
			t.Errorf("expected registered agent to be %s, got %s", req.ApplicationID, resp.ApplicationRegistration.RegisteredAgent)
		}

		t.Log("Access grant created successfully")
	})

	t.Run("create access grant with invalid user ID", func(t *testing.T) {
		req := CreateAccessGrantRequest{
			UserID:                "invalid-webid",
			ApplicationID:         "https://projectron.example/#app",
			AccessNeedGroupIDs:    []string{"https://projectron.example/#need-group-pm"},
			DataGrants:            []DataGrant{},
			AuthorizationAgentURL: "https://auth.example.com",
		}

		_, err := service.CreateAccessGrant(ctx, req)
		if err == nil {
			t.Error("expected error for invalid user ID")
		}
	})

	t.Run("create access grant with invalid data grant", func(t *testing.T) {
		req := CreateAccessGrantRequest{
			UserID:             "https://alice.example/#id",
			ApplicationID:      "https://projectron.example/#app",
			AccessNeedGroupIDs: []string{"https://projectron.example/#need-group-pm"},
			DataGrants: []DataGrant{
				{
					ID:                  "", // Invalid: empty ID
					DataOwner:           "https://alice.example/#id",
					GrantedBy:           "https://alice.example/#id",
					RegisteredShapeTree: "solidtrees:Project",
					HasDataRegistration: "urn:sai:data-registration:test1",
					AccessMode:          []ACLMode{ACLModeRead, ACLModeWrite},
					ScopeOfGrant:        ScopeOfGrantAllFromRegistry,
				},
			},
			AuthorizationAgentURL: "https://auth.example.com",
		}

		_, err := service.CreateAccessGrant(ctx, req)
		if err == nil {
			t.Error("expected error for invalid data grant")
		}
	})
}

// TestRegisterData tests data registration
func TestRegisterData(t *testing.T) {
	ctx := context.Background()
	mockStorage := NewMockSAIStorage()

	options := SAIServiceOptions{
		Storage: mockStorage,
		Timeout: time.Second * 10,
	}

	service, err := NewSAIService(options)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	t.Run("register data", func(t *testing.T) {
		instance := DataInstance{
			ID:          "https://pro.alice.example/project1",
			Type:        "pm:Project",
			ShapeTree:   "solidtrees:Project",
			Data:        []byte(`{"name": "Test Project"}`),
			ContentType: "application/json",
		}

		req := RegisterDataRequest{
			UserID:               "https://alice.example/#id",
			ApplicationID:        "https://projectron.example/#app",
			ShapeTreeID:          "solidtrees:Project",
			IRIPrefix:            "https://pro.alice.example/",
			InitialDataInstances: []DataInstance{instance},
		}

		resp, err := service.RegisterData(ctx, req)
		if err != nil {
			t.Fatalf("failed to register data: %v", err)
		}

		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		if resp.DataRegistration.ID == "" {
			t.Error("expected non-empty data registration ID")
		}

		if len(resp.DataInstances) != 1 {
			t.Errorf("expected 1 data instance, got %d", len(resp.DataInstances))
		}

		if resp.DataRegistration.RegisteredShapeTree != req.ShapeTreeID {
			t.Errorf("expected shape tree %s, got %s", req.ShapeTreeID, resp.DataRegistration.RegisteredShapeTree)
		}

		t.Log("Data registered successfully")
	})

	t.Run("register data with invalid user ID", func(t *testing.T) {
		req := RegisterDataRequest{
			UserID:               "invalid-webid",
			ApplicationID:        "https://projectron.example/#app",
			ShapeTreeID:          "solidtrees:Project",
			IRIPrefix:            "https://pro.alice.example/",
			InitialDataInstances: []DataInstance{},
		}

		_, err := service.RegisterData(ctx, req)
		if err == nil {
			t.Error("expected error for invalid user ID")
		}
	})

	t.Run("register data with invalid shape tree ID", func(t *testing.T) {
		req := RegisterDataRequest{
			UserID:               "https://alice.example/#id",
			ApplicationID:        "https://projectron.example/#app",
			ShapeTreeID:          "", // Empty
			IRIPrefix:            "https://pro.alice.example/",
			InitialDataInstances: []DataInstance{},
		}

		_, err := service.RegisterData(ctx, req)
		if err == nil {
			t.Error("expected error for invalid shape tree ID")
		}
	})
}

// TestServiceErrorHandling tests error handling in the service
func TestServiceErrorHandling(t *testing.T) {
	ctx := context.Background()
	mockStorage := NewMockSAIStorage()

	options := SAIServiceOptions{
		Storage: mockStorage,
		Timeout: time.Second * 10,
	}

	service, err := NewSAIService(options)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	t.Run("service handles storage errors gracefully", func(t *testing.T) {
		// Set storage to return an error
		mockStorage.SetStoreApplicationError(errors.New("storage error"))

		req := RegisterApplicationRequest{
			Application: Application{
				ID:              "https://projectron.example/#app",
				ApplicationName: "Projectron",
			},
			UserID:                "https://alice.example/#id",
			AuthorizationAgentURL: "https://auth.example.com",
		}

		_, err := service.RegisterApplication(ctx, req)
		if err == nil {
			t.Error("expected error when storage fails")
		}

		// Reset the error
		mockStorage.ResetErrors()
	})

	t.Run("service handles context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		req := RegisterApplicationRequest{
			Application: Application{
				ID:              "https://projectron.example/#app",
				ApplicationName: "Projectron",
			},
			UserID:                "https://alice.example/#id",
			AuthorizationAgentURL: "https://auth.example.com",
		}

		_, err := service.RegisterApplication(ctx, req)
		if err == nil {
			t.Error("expected error for cancelled context")
		}
	})
}

// TestIDGeneration tests ID generation
func TestIDGeneration(t *testing.T) {
	t.Run("generate IDs with correct format", func(t *testing.T) {
		id1 := generateSAIID("test")

		// IDs should contain the prefix
		if !contains(id1, "test") {
			t.Errorf("ID should contain prefix, got %s", id1)
		}

		// IDs should start with urn:sai:
		if !contains(id1, "urn:sai:") {
			t.Errorf("ID should be a URN, got %s", id1)
		}

		// IDs should contain a colon after the prefix
		if !contains(id1, "test:") {
			t.Errorf("ID should contain prefix followed by colon, got %s", id1)
		}
	})

	t.Run("different prefixes produce different ID formats", func(t *testing.T) {
		id1 := generateSAIID("app")
		id2 := generateSAIID("data")

		// Different prefixes should produce IDs with different prefixes
		if !contains(id1, "app") || !contains(id2, "data") {
			t.Error("IDs should contain their respective prefixes")
		}

		// Both should be URNs
		if !contains(id1, "urn:sai:") || !contains(id2, "urn:sai:") {
			t.Error("Both IDs should be URNs")
		}
	})

	t.Run("IDs are not empty", func(t *testing.T) {
		id := generateSAIID("test")
		if id == "" {
			t.Error("generated ID should not be empty")
		}
		if len(id) < 10 {
			t.Errorf("generated ID should have reasonable length, got %d", len(id))
		}
	})
}

// Helper function for tests
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
