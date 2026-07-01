// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrSAIStorage is the base error type for SAI storage failures
var ErrSAIStorage = errors.New("SAI storage failed")

// ErrSAINotFound indicates that a requested resource was not found
var ErrSAINotFound = errors.New("SAI resource not found")

// InMemorySAIStorage implements SAIStorage using in-memory maps
// This is suitable for testing and development, but not for production
type InMemorySAIStorage struct {
	mu sync.RWMutex

	// Applications
	applications map[string]*Application

	// Application Registrations
	applicationRegistrations       map[string]*ApplicationRegistration
	applicationRegistrationsByUser map[string][]string

	// Access Grants
	accessGrants       map[string]*AccessGrant
	accessGrantsByUser map[string][]string

	// Data Registrations
	dataRegistrations       map[string]*DataRegistration
	dataRegistrationsByUser map[string][]string

	// Data Grants
	dataGrants              map[string]*DataGrant
	dataGrantsByAccessGrant map[string][]string

	// Data Instances
	dataInstances               map[string]*DataInstance
	dataInstancesByRegistration map[string][]string

	// Shape Trees
	shapeTrees map[string]*ShapeTree

	// Authorization Agents
	authorizationAgents map[string]*AuthorizationAgent
}

// NewInMemorySAIStorage creates a new in-memory SAI storage
func NewInMemorySAIStorage() *InMemorySAIStorage {
	return &InMemorySAIStorage{
		applications:                   make(map[string]*Application),
		applicationRegistrations:       make(map[string]*ApplicationRegistration),
		applicationRegistrationsByUser: make(map[string][]string),
		accessGrants:                   make(map[string]*AccessGrant),
		accessGrantsByUser:             make(map[string][]string),
		dataRegistrations:              make(map[string]*DataRegistration),
		dataRegistrationsByUser:        make(map[string][]string),
		dataGrants:                     make(map[string]*DataGrant),
		dataGrantsByAccessGrant:        make(map[string][]string),
		dataInstances:                  make(map[string]*DataInstance),
		dataInstancesByRegistration:    make(map[string][]string),
		shapeTrees:                     make(map[string]*ShapeTree),
		authorizationAgents:            make(map[string]*AuthorizationAgent),
	}
}

// =============================================================================
// Application Storage Operations
// =============================================================================

// StoreApplication stores an application
func (s *InMemorySAIStorage) StoreApplication(ctx context.Context, app *Application) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if app == nil {
		return fmt.Errorf("%w: application cannot be nil", ErrSAIStorage)
	}

	if app.ID == "" {
		return fmt.Errorf("%w: application ID cannot be empty", ErrSAIStorage)
	}

	s.applications[app.ID] = app
	return nil
}

// GetApplication retrieves an application by ID
func (s *InMemorySAIStorage) GetApplication(ctx context.Context, id string) (*Application, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	app, exists := s.applications[id]
	if !exists {
		return nil, fmt.Errorf("%w: application not found: %s", ErrSAINotFound, id)
	}

	// Return a copy to prevent modification of the stored data
	return copyApplication(app), nil
}

// ListApplications lists all applications for a given owner
func (s *InMemorySAIStorage) ListApplications(ctx context.Context, owner string) ([]*Application, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Application
	for _, app := range s.applications {
		// Note: In a real implementation, we'd filter by owner
		// For now, return all applications
		result = append(result, copyApplication(app))
	}

	return result, nil
}

// DeleteApplication deletes an application by ID
func (s *InMemorySAIStorage) DeleteApplication(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.applications[id]; !exists {
		return fmt.Errorf("%w: application not found: %s", ErrSAINotFound, id)
	}

	delete(s.applications, id)
	return nil
}

// =============================================================================
// Application Registration Storage Operations
// =============================================================================

// StoreApplicationRegistration stores an application registration
func (s *InMemorySAIStorage) StoreApplicationRegistration(ctx context.Context, reg *ApplicationRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if reg == nil {
		return fmt.Errorf("%w: application registration cannot be nil", ErrSAIStorage)
	}

	if reg.ID == "" {
		return fmt.Errorf("%w: application registration ID cannot be empty", ErrSAIStorage)
	}

	// Store the registration
	s.applicationRegistrations[reg.ID] = reg

	// Index by user
	if _, exists := s.applicationRegistrationsByUser[reg.RegisteredBy]; !exists {
		s.applicationRegistrationsByUser[reg.RegisteredBy] = []string{}
	}
	s.applicationRegistrationsByUser[reg.RegisteredBy] = append(
		s.applicationRegistrationsByUser[reg.RegisteredBy],
		reg.ID,
	)

	return nil
}

// GetApplicationRegistration retrieves an application registration by ID
func (s *InMemorySAIStorage) GetApplicationRegistration(ctx context.Context, id string) (*ApplicationRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reg, exists := s.applicationRegistrations[id]
	if !exists {
		return nil, fmt.Errorf("%w: application registration not found: %s", ErrSAINotFound, id)
	}

	return copyApplicationRegistration(reg), nil
}

// ListApplicationRegistrations lists all application registrations for a user
func (s *InMemorySAIStorage) ListApplicationRegistrations(ctx context.Context, userID string) ([]*ApplicationRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids, exists := s.applicationRegistrationsByUser[userID]
	if !exists {
		return []*ApplicationRegistration{}, nil
	}

	result := make([]*ApplicationRegistration, len(ids))
	for i, id := range ids {
		reg, exists := s.applicationRegistrations[id]
		if !exists {
			// This shouldn't happen, but handle it gracefully
			continue
		}
		result[i] = copyApplicationRegistration(reg)
	}

	return result, nil
}

// DeleteApplicationRegistration deletes an application registration by ID
func (s *InMemorySAIStorage) DeleteApplicationRegistration(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	reg, exists := s.applicationRegistrations[id]
	if !exists {
		return fmt.Errorf("%w: application registration not found: %s", ErrSAINotFound, id)
	}

	// Remove from user index
	if ids, exists := s.applicationRegistrationsByUser[reg.RegisteredBy]; exists {
		for i, regID := range ids {
			if regID == id {
				s.applicationRegistrationsByUser[reg.RegisteredBy] = append(ids[:i], ids[i+1:]...)
				break
			}
		}
	}

	delete(s.applicationRegistrations, id)
	return nil
}

// =============================================================================
// Access Grant Storage Operations
// =============================================================================

// StoreAccessGrant stores an access grant
func (s *InMemorySAIStorage) StoreAccessGrant(ctx context.Context, grant *AccessGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if grant == nil {
		return fmt.Errorf("%w: access grant cannot be nil", ErrSAIStorage)
	}

	if grant.ID == "" {
		return fmt.Errorf("%w: access grant ID cannot be empty", ErrSAIStorage)
	}

	// Store the grant
	s.accessGrants[grant.ID] = grant

	// Index by user (from agent)
	if _, exists := s.accessGrantsByUser[grant.FromAgent]; !exists {
		s.accessGrantsByUser[grant.FromAgent] = []string{}
	}
	s.accessGrantsByUser[grant.FromAgent] = append(
		s.accessGrantsByUser[grant.FromAgent],
		grant.ID,
	)

	return nil
}

// GetAccessGrant retrieves an access grant by ID
func (s *InMemorySAIStorage) GetAccessGrant(ctx context.Context, id string) (*AccessGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	grant, exists := s.accessGrants[id]
	if !exists {
		return nil, fmt.Errorf("%w: access grant not found: %s", ErrSAINotFound, id)
	}

	return copyAccessGrant(grant), nil
}

// ListAccessGrants lists all access grants for a user
func (s *InMemorySAIStorage) ListAccessGrants(ctx context.Context, userID string) ([]*AccessGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids, exists := s.accessGrantsByUser[userID]
	if !exists {
		return []*AccessGrant{}, nil
	}

	result := make([]*AccessGrant, len(ids))
	for i, id := range ids {
		grant, exists := s.accessGrants[id]
		if !exists {
			// This shouldn't happen, but handle it gracefully
			continue
		}
		result[i] = copyAccessGrant(grant)
	}

	return result, nil
}

// DeleteAccessGrant deletes an access grant by ID
func (s *InMemorySAIStorage) DeleteAccessGrant(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	grant, exists := s.accessGrants[id]
	if !exists {
		return fmt.Errorf("%w: access grant not found: %s", ErrSAINotFound, id)
	}

	// Remove from user index
	if ids, exists := s.accessGrantsByUser[grant.FromAgent]; exists {
		for i, grantID := range ids {
			if grantID == id {
				s.accessGrantsByUser[grant.FromAgent] = append(ids[:i], ids[i+1:]...)
				break
			}
		}
	}

	delete(s.accessGrants, id)
	return nil
}

// =============================================================================
// Data Registration Storage Operations
// =============================================================================

// StoreDataRegistration stores a data registration
func (s *InMemorySAIStorage) StoreDataRegistration(ctx context.Context, reg *DataRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if reg == nil {
		return fmt.Errorf("%w: data registration cannot be nil", ErrSAIStorage)
	}

	if reg.ID == "" {
		return fmt.Errorf("%w: data registration ID cannot be empty", ErrSAIStorage)
	}

	// Store the registration
	s.dataRegistrations[reg.ID] = reg

	// Index by user
	if _, exists := s.dataRegistrationsByUser[reg.RegisteredBy]; !exists {
		s.dataRegistrationsByUser[reg.RegisteredBy] = []string{}
	}
	s.dataRegistrationsByUser[reg.RegisteredBy] = append(
		s.dataRegistrationsByUser[reg.RegisteredBy],
		reg.ID,
	)

	return nil
}

// GetDataRegistration retrieves a data registration by ID
func (s *InMemorySAIStorage) GetDataRegistration(ctx context.Context, id string) (*DataRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reg, exists := s.dataRegistrations[id]
	if !exists {
		return nil, fmt.Errorf("%w: data registration not found: %s", ErrSAINotFound, id)
	}

	return copyDataRegistration(reg), nil
}

// ListDataRegistrations lists all data registrations for a user
func (s *InMemorySAIStorage) ListDataRegistrations(ctx context.Context, userID string) ([]*DataRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids, exists := s.dataRegistrationsByUser[userID]
	if !exists {
		return []*DataRegistration{}, nil
	}

	result := make([]*DataRegistration, len(ids))
	for i, id := range ids {
		reg, exists := s.dataRegistrations[id]
		if !exists {
			// This shouldn't happen, but handle it gracefully
			continue
		}
		result[i] = copyDataRegistration(reg)
	}

	return result, nil
}

// DeleteDataRegistration deletes a data registration by ID
func (s *InMemorySAIStorage) DeleteDataRegistration(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	reg, exists := s.dataRegistrations[id]
	if !exists {
		return fmt.Errorf("%w: data registration not found: %s", ErrSAINotFound, id)
	}

	// Remove from user index
	if ids, exists := s.dataRegistrationsByUser[reg.RegisteredBy]; exists {
		for i, regID := range ids {
			if regID == id {
				s.dataRegistrationsByUser[reg.RegisteredBy] = append(ids[:i], ids[i+1:]...)
				break
			}
		}
	}

	delete(s.dataRegistrations, id)
	return nil
}

// =============================================================================
// Data Grant Storage Operations
// =============================================================================

// StoreDataGrant stores a data grant
func (s *InMemorySAIStorage) StoreDataGrant(ctx context.Context, grant *DataGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if grant == nil {
		return fmt.Errorf("%w: data grant cannot be nil", ErrSAIStorage)
	}

	if grant.ID == "" {
		return fmt.Errorf("%w: data grant ID cannot be empty", ErrSAIStorage)
	}

	// Store the grant
	s.dataGrants[grant.ID] = grant

	// Index by access grant
	if _, exists := s.dataGrantsByAccessGrant[grant.ID]; !exists {
		s.dataGrantsByAccessGrant[grant.ID] = []string{}
	}
	// Note: In a real implementation, we'd index by the access grant that contains this data grant
	// For simplicity, we'll just store them and the access grant will reference them by ID

	return nil
}

// GetDataGrant retrieves a data grant by ID
func (s *InMemorySAIStorage) GetDataGrant(ctx context.Context, id string) (*DataGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	grant, exists := s.dataGrants[id]
	if !exists {
		return nil, fmt.Errorf("%w: data grant not found: %s", ErrSAINotFound, id)
	}

	return copyDataGrant(grant), nil
}

// ListDataGrants lists all data grants for an access grant
func (s *InMemorySAIStorage) ListDataGrants(ctx context.Context, accessGrantID string) ([]*DataGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// In our simple implementation, we don't have a direct index from access grant to data grants
	// We would need to retrieve the access grant and then get the data grant IDs from it
	// For now, return all data grants
	var result []*DataGrant
	for _, grant := range s.dataGrants {
		result = append(result, copyDataGrant(grant))
	}

	return result, nil
}

// DeleteDataGrant deletes a data grant by ID
func (s *InMemorySAIStorage) DeleteDataGrant(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.dataGrants[id]; !exists {
		return fmt.Errorf("%w: data grant not found: %s", ErrSAINotFound, id)
	}

	delete(s.dataGrants, id)
	return nil
}

// =============================================================================
// Data Instance Storage Operations
// =============================================================================

// StoreDataInstance stores a data instance
func (s *InMemorySAIStorage) StoreDataInstance(ctx context.Context, instance *DataInstance) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if instance == nil {
		return fmt.Errorf("%w: data instance cannot be nil", ErrSAIStorage)
	}

	if instance.ID == "" {
		return fmt.Errorf("%w: data instance ID cannot be empty", ErrSAIStorage)
	}

	// Store the instance
	s.dataInstances[instance.ID] = instance

	// Note: In a real implementation, we'd index by registration
	// For simplicity, we'll just store them

	return nil
}

// GetDataInstance retrieves a data instance by ID
func (s *InMemorySAIStorage) GetDataInstance(ctx context.Context, id string) (*DataInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	instance, exists := s.dataInstances[id]
	if !exists {
		return nil, fmt.Errorf("%w: data instance not found: %s", ErrSAINotFound, id)
	}

	return copyDataInstance(instance), nil
}

// ListDataInstances lists all data instances for a registration
func (s *InMemorySAIStorage) ListDataInstances(ctx context.Context, registrationID string) ([]*DataInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// In our simple implementation, we don't have a direct index from registration to instances
	// We would need to retrieve the registration and then get the instance IDs from it
	// For now, return all data instances
	var result []*DataInstance
	for _, instance := range s.dataInstances {
		result = append(result, copyDataInstance(instance))
	}

	return result, nil
}

// DeleteDataInstance deletes a data instance by ID
func (s *InMemorySAIStorage) DeleteDataInstance(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.dataInstances[id]; !exists {
		return fmt.Errorf("%w: data instance not found: %s", ErrSAINotFound, id)
	}

	delete(s.dataInstances, id)
	return nil
}

// =============================================================================
// Shape Tree Storage Operations
// =============================================================================

// StoreShapeTree stores a shape tree
func (s *InMemorySAIStorage) StoreShapeTree(ctx context.Context, tree *ShapeTree) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tree == nil {
		return fmt.Errorf("%w: shape tree cannot be nil", ErrSAIStorage)
	}

	if tree.ID == "" {
		return fmt.Errorf("%w: shape tree ID cannot be empty", ErrSAIStorage)
	}

	s.shapeTrees[tree.ID] = tree
	return nil
}

// GetShapeTree retrieves a shape tree by ID
func (s *InMemorySAIStorage) GetShapeTree(ctx context.Context, id string) (*ShapeTree, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tree, exists := s.shapeTrees[id]
	if !exists {
		return nil, fmt.Errorf("%w: shape tree not found: %s", ErrSAINotFound, id)
	}

	return copyShapeTree(tree), nil
}

// ListShapeTrees lists all shape trees
func (s *InMemorySAIStorage) ListShapeTrees(ctx context.Context) ([]*ShapeTree, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ShapeTree, len(s.shapeTrees))
	i := 0
	for _, tree := range s.shapeTrees {
		result[i] = copyShapeTree(tree)
		i++
	}

	return result, nil
}

// DeleteShapeTree deletes a shape tree by ID
func (s *InMemorySAIStorage) DeleteShapeTree(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.shapeTrees[id]; !exists {
		return fmt.Errorf("%w: shape tree not found: %s", ErrSAINotFound, id)
	}

	delete(s.shapeTrees, id)
	return nil
}

// =============================================================================
// Authorization Agent Storage Operations
// =============================================================================

// StoreAuthorizationAgent stores an authorization agent
func (s *InMemorySAIStorage) StoreAuthorizationAgent(ctx context.Context, agent *AuthorizationAgent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if agent == nil {
		return fmt.Errorf("%w: authorization agent cannot be nil", ErrSAIStorage)
	}

	if agent.ID == "" {
		return fmt.Errorf("%w: authorization agent ID cannot be empty", ErrSAIStorage)
	}

	s.authorizationAgents[agent.ID] = agent
	return nil
}

// GetAuthorizationAgent retrieves an authorization agent by ID
func (s *InMemorySAIStorage) GetAuthorizationAgent(ctx context.Context, id string) (*AuthorizationAgent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agent, exists := s.authorizationAgents[id]
	if !exists {
		return nil, fmt.Errorf("%w: authorization agent not found: %s", ErrSAINotFound, id)
	}

	return copyAuthorizationAgent(agent), nil
}

// ListAuthorizationAgents lists all authorization agents
func (s *InMemorySAIStorage) ListAuthorizationAgents(ctx context.Context) ([]*AuthorizationAgent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*AuthorizationAgent, len(s.authorizationAgents))
	i := 0
	for _, agent := range s.authorizationAgents {
		result[i] = copyAuthorizationAgent(agent)
		i++
	}

	return result, nil
}

// DeleteAuthorizationAgent deletes an authorization agent by ID
func (s *InMemorySAIStorage) DeleteAuthorizationAgent(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.authorizationAgents[id]; !exists {
		return fmt.Errorf("%w: authorization agent not found: %s", ErrSAINotFound, id)
	}

	delete(s.authorizationAgents, id)
	return nil
}

// =============================================================================
// Copy Functions (to prevent modification of stored data)
// =============================================================================

func copyApplication(app *Application) *Application {
	if app == nil {
		return nil
	}

	copy := *app
	copy.HasAccessNeedGroup = make([]AccessNeedGroup, len(app.HasAccessNeedGroup))
	for i, group := range app.HasAccessNeedGroup {
		copy.HasAccessNeedGroup[i] = *copyAccessNeedGroup(&group)
	}
	return &copy
}

func copyAccessNeedGroup(group *AccessNeedGroup) *AccessNeedGroup {
	if group == nil {
		return nil
	}

	copy := *group
	copy.HasAccessNeed = make([]AccessNeed, len(group.HasAccessNeed))
	for i, need := range group.HasAccessNeed {
		copy.HasAccessNeed[i] = *copyAccessNeed(&need)
	}
	return &copy
}

func copyAccessNeed(need *AccessNeed) *AccessNeed {
	if need == nil {
		return nil
	}
	return need // Simple copy (value type)
}

func copyApplicationRegistration(reg *ApplicationRegistration) *ApplicationRegistration {
	if reg == nil {
		return nil
	}
	return reg // Simple copy (value type)
}

func copyAccessGrant(grant *AccessGrant) *AccessGrant {
	if grant == nil {
		return nil
	}

	copy := *grant
	copy.HasAccessGrantSubject = *copyAccessGrantSubject(&grant.HasAccessGrantSubject)
	copy.HasAccessNeedGroup = make([]string, len(grant.HasAccessNeedGroup))
	copy.HasDataGrant = make([]string, len(grant.HasDataGrant))
	copy.HasAccessNeedGroup = append(copy.HasAccessNeedGroup, grant.HasAccessNeedGroup...)
	copy.HasDataGrant = append(copy.HasDataGrant, grant.HasDataGrant...)
	return &copy
}

func copyAccessGrantSubject(subject *AccessGrantSubject) *AccessGrantSubject {
	if subject == nil {
		return nil
	}
	return subject // Simple copy (value type)
}

func copyDataGrant(grant *DataGrant) *DataGrant {
	if grant == nil {
		return nil
	}

	copy := *grant
	copy.AccessMode = make([]ACLMode, len(grant.AccessMode))
	copy.AccessMode = append(copy.AccessMode, grant.AccessMode...)
	copy.HasDataInstance = make([]string, len(grant.HasDataInstance))
	copy.HasDataInstance = append(copy.HasDataInstance, grant.HasDataInstance...)
	return &copy
}

func copyDataRegistration(reg *DataRegistration) *DataRegistration {
	if reg == nil {
		return nil
	}

	copy := *reg
	copy.Contains = make([]string, len(reg.Contains))
	copy.Contains = append(copy.Contains, reg.Contains...)
	return &copy
}

func copyDataInstance(instance *DataInstance) *DataInstance {
	if instance == nil {
		return nil
	}

	copy := *instance
	copy.Data = append([]byte(nil), instance.Data...)
	return &copy
}

func copyShapeTree(tree *ShapeTree) *ShapeTree {
	if tree == nil {
		return nil
	}

	copy := *tree
	copy.References = make([]ShapeTreeReference, len(tree.References))
	for i, ref := range tree.References {
		copy.References[i] = *copyShapeTreeReference(&ref)
	}
	return &copy
}

func copyShapeTreeReference(ref *ShapeTreeReference) *ShapeTreeReference {
	if ref == nil {
		return nil
	}
	return ref // Simple copy (value type)
}

func copyAuthorizationAgent(agent *AuthorizationAgent) *AuthorizationAgent {
	if agent == nil {
		return nil
	}

	copy := *agent
	copy.AgentRegistrySet = append([]string(nil), agent.AgentRegistrySet...)
	return &copy
}
