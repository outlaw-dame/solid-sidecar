// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 7: Multi-storage/multi-tenant runtime.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// MultiStorageLayer implements Layer 7: Multi-storage/multi-tenant runtime
// This layer provides support for multiple storage backends and tenants
// in the Solid runtime.
//
// Key principles:
// - Multiple storage backends can be managed simultaneously
// - Tenant isolation and resource separation
// - Efficient routing of requests to appropriate storage
// - Health monitoring and failover support
// - Integration with existing storage abstraction layer
type MultiStorageLayer struct {
	mu sync.RWMutex

	config MultiStorageConfig

	// Storage routing configuration
	storageRoutes map[string]*StorageRoute

	// Tenant management
	tenants map[string]*TenantConfig

	// Tenant storage mapping
	tenantStorage map[string]string // tenant -> storage backend name

	// Storage layer reference
	storage *StorageAbstractionLayer

	// Health status
	healthStatus map[string]TenantHealthStatus

	// Metrics
	metrics MultiStorageMetrics

	// Logger
	logger *slog.Logger

	// Close state
	closeChan chan struct{}
	closed    bool
}

// MultiStorageConfig holds configuration for the multi-storage layer
type MultiStorageConfig struct {
	// DefaultStorage is the default storage backend to use
	DefaultStorage string

	// DefaultTenant is the default tenant
	DefaultTenant string

	// EnableTenantIsolation enables tenant isolation
	EnableTenantIsolation bool

	// EnableHealthMonitoring enables health monitoring of storage backends
	EnableHealthMonitoring bool

	// HealthCheckInterval is how often to check backend health
	HealthCheckInterval int // seconds

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultMultiStorageConfig returns a safe default configuration
func DefaultMultiStorageConfig() MultiStorageConfig {
	return MultiStorageConfig{
		DefaultStorage:         "default",
		DefaultTenant:          "default",
		EnableTenantIsolation:  true,
		EnableHealthMonitoring: true,
		HealthCheckInterval:    60, // 60 seconds
		Logger:                 nil,
	}
}

// MultiStorageMetrics holds metrics for the multi-storage layer
type MultiStorageMetrics struct {
	mu sync.RWMutex

	// Request routing
	TotalRequests  int64
	RoutedRequests int64
	FailedRequests int64

	// Storage routing
	StorageRoutings  int64
	StorageFailovers int64

	// Tenant operations
	TenantLookups   int64
	TenantCreations int64
	TenantUpdates   int64
	TenantDeletions int64

	// Health checks
	HealthChecks        int64
	HealthCheckFailures int64

	// Backend statistics
	BackendOperations map[string]int64
}

// RecordRequest records a request being processed
func (m *MultiStorageMetrics) RecordRequest(routed, failed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalRequests++
	if routed {
		m.RoutedRequests++
	}
	if failed {
		m.FailedRequests++
	}
}

// RecordStorageRouting records a storage routing
func (m *MultiStorageMetrics) RecordStorageRouting() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StorageRoutings++
}

// RecordStorageFailover records a storage failover
func (m *MultiStorageMetrics) RecordStorageFailover() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StorageFailovers++
}

// RecordTenantOperation records a tenant operation
func (m *MultiStorageMetrics) RecordTenantOperation(operation string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch operation {
	case "lookup":
		m.TenantLookups++
	case "create":
		m.TenantCreations++
	case "update":
		m.TenantUpdates++
	case "delete":
		m.TenantDeletions++
	}
}

// RecordHealthCheck records a health check
func (m *MultiStorageMetrics) RecordHealthCheck(failed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.HealthChecks++
	if failed {
		m.HealthCheckFailures++
	}
}

// StorageRoute defines routing rules for storage backends
type StorageRoute struct {
	// RouteID is a unique identifier for this route
	RouteID string

	// Pattern is the URI pattern to match
	Pattern string

	// StorageBackend is the storage backend to use for this route
	StorageBackend string

	// Tenant is the tenant associated with this route (optional)
	Tenant string

	// Priority is the route priority (higher = higher priority)
	Priority int

	// Conditions are additional conditions for this route
	Conditions map[string]string
}

// TenantConfig holds configuration for a tenant
type TenantConfig struct {
	// TenantID is the unique identifier for this tenant
	TenantID string

	// StorageBackend is the default storage backend for this tenant
	StorageBackend string

	// AllowedStorageBackends are the storage backends this tenant can use
	AllowedStorageBackends []string

	// ResourceQuotas define resource limits for this tenant
	ResourceQuotas TenantQuotas

	// ACLConfig defines access control configuration for this tenant
	ACLConfig TenantACLConfig

	// Metadata contains additional tenant metadata
	Metadata map[string]string

	// Created is when the tenant was created
	Created string

	// Modified is when the tenant was last modified
	Modified string

	// Enabled indicates if the tenant is enabled
	Enabled bool
}

// TenantQuotas defines resource quotas for a tenant
type TenantQuotas struct {
	// MaxResources is the maximum number of resources
	MaxResources int64

	// MaxStorage is the maximum storage in bytes
	MaxStorage int64

	// MaxBandwidth is the maximum bandwidth in bytes per second
	MaxBandwidth int64

	// MaxRequestsPerSecond is the maximum requests per second
	MaxRequestsPerSecond int

	// CurrentUsage tracks current usage
	CurrentUsage TenantUsage
}

// TenantUsage tracks current usage for a tenant
type TenantUsage struct {
	// ResourceCount is the current number of resources
	ResourceCount int64

	// StorageUsed is the current storage used in bytes
	StorageUsed int64

	// LastRequestTime is when the last request was made
	LastRequestTime string
}

// TenantACLConfig defines access control configuration for a tenant
type TenantACLConfig struct {
	// DefaultAccess is the default access level for new resources
	DefaultAccess string

	// InheritACL indicates if ACLs should be inherited from parent containers
	InheritACL bool

	// PublicReadEnabled indicates if public read access is enabled by default
	PublicReadEnabled bool
}

// TenantHealthStatus represents the health status of a tenant
type TenantHealthStatus struct {
	// TenantID is the tenant identifier
	TenantID string

	// StorageBackend is the storage backend being used
	StorageBackend string

	// Healthy indicates if the tenant's storage is healthy
	Healthy bool

	// LastHealthCheck is when the last health check was performed
	LastHealthCheck string

	// LastError contains the last error encountered
	LastError string

	// ResponseTime is the average response time
	ResponseTime float64
}

// NewMultiStorageLayer creates a new multi-storage layer
func NewMultiStorageLayer(config MultiStorageConfig) *MultiStorageLayer {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Validate default tenant
	if err := ValidateTenantID(config.DefaultTenant); err != nil {
		config.Logger.Error("Invalid default tenant ID", "error", err)
		// Use a safe default
		config.DefaultTenant = "default"
	}

	// Validate default storage backend name
	if config.DefaultStorage == "" {
		config.DefaultStorage = "default"
	}
	if len(config.DefaultStorage) > 256 {
		config.Logger.Error("Default storage backend name exceeds maximum length")
		config.DefaultStorage = "default"
	}

	// Validate health check interval
	if config.HealthCheckInterval <= 0 {
		config.HealthCheckInterval = 60 // Default to 60 seconds
	}
	if config.HealthCheckInterval > 86400 {
		config.HealthCheckInterval = 86400 // Maximum 24 hours
	}

	layer := &MultiStorageLayer{
		config:        config,
		storageRoutes: make(map[string]*StorageRoute),
		tenants:       make(map[string]*TenantConfig),
		tenantStorage: make(map[string]string),
		healthStatus:  make(map[string]TenantHealthStatus),
		logger:        config.Logger,
		closeChan:     make(chan struct{}),
		closed:        false,
		metrics: MultiStorageMetrics{
			BackendOperations: make(map[string]int64),
		},
	}

	config.Logger.Info("Multi-storage layer initialized",
		"default_storage", config.DefaultStorage,
		"default_tenant", config.DefaultTenant,
		"enable_tenant_isolation", config.EnableTenantIsolation,
		"enable_health_monitoring", config.EnableHealthMonitoring,
		"health_check_interval", config.HealthCheckInterval,
	)

	// Set up default storage route
	layer.AddStorageRoute(&StorageRoute{
		RouteID:        "default",
		Pattern:        "*",
		StorageBackend: config.DefaultStorage,
		Priority:       0,
		Conditions:     make(map[string]string),
	})

	// Set up default tenant
	layer.AddTenant(&TenantConfig{
		TenantID:               config.DefaultTenant,
		StorageBackend:         config.DefaultStorage,
		AllowedStorageBackends: []string{config.DefaultStorage},
		ResourceQuotas: TenantQuotas{
			MaxResources:         -1, // Unlimited
			MaxStorage:           -1, // Unlimited
			MaxBandwidth:         -1, // Unlimited
			MaxRequestsPerSecond: -1, // Unlimited
		},
		ACLConfig: TenantACLConfig{
			DefaultAccess:     "private",
			InheritACL:        true,
			PublicReadEnabled: false,
		},
		Metadata: make(map[string]string),
		Created:  time.Now().Format(time.RFC3339),
		Modified: time.Now().Format(time.RFC3339),
		Enabled:  true,
	})

	// Start health monitoring if enabled
	if config.EnableHealthMonitoring && config.HealthCheckInterval > 0 {
		go layer.startHealthMonitoring()
	}

	return layer
}

// startHealthMonitoring starts the health monitoring goroutine
func (m *MultiStorageLayer) startHealthMonitoring() {
	interval := time.Duration(m.config.HealthCheckInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.performHealthChecks()
		case <-m.closeChan:
			m.logger.Info("Multi-storage health monitoring stopped")
			return
		}
	}
}

// performHealthChecks performs health checks on all storage backends
func (m *MultiStorageLayer) performHealthChecks() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return
	}

	// Check each tenant's storage backend
	for tenantID, storageBackend := range m.tenantStorage {
		m.checkStorageHealth(tenantID, storageBackend)
	}

	// Also check all storage backends used in routes
	for _, route := range m.storageRoutes {
		m.checkStorageHealth(route.Tenant, route.StorageBackend)
	}
}

// checkStorageHealth checks the health of a specific storage backend
func (m *MultiStorageLayer) checkStorageHealth(tenantID string, storageBackend string) {
	if m.storage == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthResults := m.storage.HealthCheck(ctx)

	// Check if our specific storage backend is healthy
	backendErr := healthResults[storageBackend]

	status := TenantHealthStatus{
		TenantID:        tenantID,
		StorageBackend:  storageBackend,
		LastHealthCheck: time.Now().Format(time.RFC3339),
		Healthy:         backendErr == nil,
		ResponseTime:    0, // Would be measured in real implementation
	}

	if backendErr != nil {
		status.LastError = backendErr.Error()
		m.logger.Warn("Storage health check failed",
			"tenant", tenantID,
			"storage", storageBackend,
			"error", backendErr,
		)
		m.metrics.RecordHealthCheck(true)
	} else {
		m.logger.Debug("Storage health check passed",
			"tenant", tenantID,
			"storage", storageBackend,
		)
		m.metrics.RecordHealthCheck(false)
	}

	m.healthStatus[tenantID] = status
}

// SetStorageLayer sets the storage layer reference
func (m *MultiStorageLayer) SetStorageLayer(storage *StorageAbstractionLayer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}

	m.storage = storage
	m.logger.Info("Storage layer set for multi-storage layer")
}

// AddStorageRoute adds a storage route to the routing table
func (m *MultiStorageLayer) AddStorageRoute(route *StorageRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("multi-storage layer is closed")
	}

	if route == nil {
		return errors.New("route cannot be nil")
	}

	if route.RouteID == "" {
		return errors.New("route ID cannot be empty")
	}

	if route.StorageBackend == "" {
		return errors.New("storage backend cannot be empty")
	}

	if _, exists := m.storageRoutes[route.RouteID]; exists {
		return fmt.Errorf("route with ID %q already exists", route.RouteID)
	}

	m.storageRoutes[route.RouteID] = route
	m.logger.Info("Storage route added",
		"route_id", route.RouteID,
		"pattern", route.Pattern,
		"storage_backend", route.StorageBackend,
		"priority", route.Priority,
	)

	return nil
}

// RemoveStorageRoute removes a storage route from the routing table
func (m *MultiStorageLayer) RemoveStorageRoute(routeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("multi-storage layer is closed")
	}

	if _, exists := m.storageRoutes[routeID]; !exists {
		return fmt.Errorf("route with ID %q not found", routeID)
	}

	delete(m.storageRoutes, routeID)
	m.logger.Info("Storage route removed", "route_id", routeID)
	return nil
}

// GetStorageRoute returns a storage route by ID
func (m *MultiStorageLayer) GetStorageRoute(routeID string) (*StorageRoute, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("multi-storage layer is closed")
	}

	route, exists := m.storageRoutes[routeID]
	if !exists {
		return nil, fmt.Errorf("route with ID %q not found", routeID)
	}

	// Return a copy for thread safety
	return m.copyStorageRoute(route), nil
}

// copyStorageRoute creates a copy of a storage route
func (m *MultiStorageLayer) copyStorageRoute(route *StorageRoute) *StorageRoute {
	if route == nil {
		return nil
	}

	copiedConditions := make(map[string]string, len(route.Conditions))
	for k, v := range route.Conditions {
		copiedConditions[k] = v
	}

	return &StorageRoute{
		RouteID:        route.RouteID,
		Pattern:        route.Pattern,
		StorageBackend: route.StorageBackend,
		Tenant:         route.Tenant,
		Priority:       route.Priority,
		Conditions:     copiedConditions,
	}
}

// ListStorageRoutes returns a list of all storage routes
func (m *MultiStorageLayer) ListStorageRoutes() []*StorageRoute {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return []*StorageRoute{}
	}

	routes := make([]*StorageRoute, 0, len(m.storageRoutes))
	for _, route := range m.storageRoutes {
		routes = append(routes, m.copyStorageRoute(route))
	}
	return routes
}

// AddTenant adds a tenant to the tenant management system
func (m *MultiStorageLayer) AddTenant(tenant *TenantConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("multi-storage layer is closed")
	}

	if tenant == nil {
		return errors.New("tenant cannot be nil")
	}

	if tenant.TenantID == "" {
		return errors.New("tenant ID cannot be empty")
	}

	if _, exists := m.tenants[tenant.TenantID]; exists {
		return fmt.Errorf("tenant with ID %q already exists", tenant.TenantID)
	}

	// Set current timestamp if not set
	if tenant.Created == "" {
		tenant.Created = time.Now().Format(time.RFC3339)
	}
	if tenant.Modified == "" {
		tenant.Modified = time.Now().Format(time.RFC3339)
	}

	m.tenants[tenant.TenantID] = tenant
	m.tenantStorage[tenant.TenantID] = tenant.StorageBackend

	m.logger.Info("Tenant added",
		"tenant_id", tenant.TenantID,
		"storage_backend", tenant.StorageBackend,
		"enabled", tenant.Enabled,
	)

	return nil
}

// UpdateTenant updates an existing tenant
func (m *MultiStorageLayer) UpdateTenant(tenant *TenantConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("multi-storage layer is closed")
	}

	if tenant == nil {
		return errors.New("tenant cannot be nil")
	}

	if tenant.TenantID == "" {
		return errors.New("tenant ID cannot be empty")
	}

	existing, exists := m.tenants[tenant.TenantID]
	if !exists {
		return fmt.Errorf("tenant with ID %q not found", tenant.TenantID)
	}

	// Preserve creation time
	if existing.Created != "" && tenant.Created == "" {
		tenant.Created = existing.Created
	}

	tenant.Modified = time.Now().Format(time.RFC3339)
	m.tenants[tenant.TenantID] = tenant
	m.tenantStorage[tenant.TenantID] = tenant.StorageBackend

	m.logger.Info("Tenant updated",
		"tenant_id", tenant.TenantID,
		"storage_backend", tenant.StorageBackend,
	)

	return nil
}

// GetTenant returns a tenant by ID
func (m *MultiStorageLayer) GetTenant(tenantID string) (*TenantConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("multi-storage layer is closed")
	}

	tenant, exists := m.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant with ID %q not found", tenantID)
	}

	// Return a copy for thread safety
	return m.copyTenant(tenant), nil
}

// copyTenant creates a copy of a tenant configuration
func (m *MultiStorageLayer) copyTenant(tenant *TenantConfig) *TenantConfig {
	if tenant == nil {
		return nil
	}

	copiedAllowedBackends := make([]string, len(tenant.AllowedStorageBackends))
	copy(copiedAllowedBackends, tenant.AllowedStorageBackends)

	copiedMetadata := make(map[string]string, len(tenant.Metadata))
	for k, v := range tenant.Metadata {
		copiedMetadata[k] = v
	}

	return &TenantConfig{
		TenantID:               tenant.TenantID,
		StorageBackend:         tenant.StorageBackend,
		AllowedStorageBackends: copiedAllowedBackends,
		ResourceQuotas:         tenant.ResourceQuotas,
		ACLConfig:              tenant.ACLConfig,
		Metadata:               copiedMetadata,
		Created:                tenant.Created,
		Modified:               tenant.Modified,
		Enabled:                tenant.Enabled,
	}
}

// RemoveTenant removes a tenant from the system
func (m *MultiStorageLayer) RemoveTenant(tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("multi-storage layer is closed")
	}

	if _, exists := m.tenants[tenantID]; !exists {
		return fmt.Errorf("tenant with ID %q not found", tenantID)
	}

	delete(m.tenants, tenantID)
	delete(m.tenantStorage, tenantID)
	delete(m.healthStatus, tenantID)

	m.logger.Info("Tenant removed", "tenant_id", tenantID)
	return nil
}

// ListTenants returns a list of all tenants
func (m *MultiStorageLayer) ListTenants() []*TenantConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return []*TenantConfig{}
	}

	tenants := make([]*TenantConfig, 0, len(m.tenants))
	for _, tenant := range m.tenants {
		tenants = append(tenants, m.copyTenant(tenant))
	}
	return tenants
}

// GetTenantStorage returns the storage backend for a tenant
func (m *MultiStorageLayer) GetTenantStorage(tenantID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return "", errors.New("multi-storage layer is closed")
	}

	storage, exists := m.tenantStorage[tenantID]
	if !exists {
		// Return default storage
		return m.config.DefaultStorage, nil
	}

	return storage, nil
}

// ResolveStorageBackend resolves the appropriate storage backend for a resource URI
func (m *MultiStorageLayer) ResolveStorageBackend(resourceURI string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return "", errors.New("multi-storage layer is closed")
	}

	// Try to match routes by priority (highest first)
	var bestRoute *StorageRoute
	for _, route := range m.storageRoutes {
		if m.routeMatches(route, resourceURI) {
			if bestRoute == nil || route.Priority > bestRoute.Priority {
				bestRoute = route
			}
		}
	}

	if bestRoute != nil {
		m.metrics.RecordStorageRouting()
		return bestRoute.StorageBackend, nil
	}

	// Fall back to default storage
	return m.config.DefaultStorage, nil
}

// routeMatches checks if a route matches a resource URI
func (m *MultiStorageLayer) routeMatches(route *StorageRoute, resourceURI string) bool {
	// Simple pattern matching
	if route.Pattern == "*" {
		return true
	}

	// Exact match
	if route.Pattern == resourceURI {
		return true
	}

	// Prefix match
	if strings.HasPrefix(resourceURI, route.Pattern) {
		return true
	}

	// More sophisticated pattern matching could be added here
	return false
}

// GetHealthStatus returns the health status for a tenant
func (m *MultiStorageLayer) GetHealthStatus(tenantID string) (*TenantHealthStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("multi-storage layer is closed")
	}

	status, exists := m.healthStatus[tenantID]
	if !exists {
		// Return default healthy status
		return &TenantHealthStatus{
			TenantID:        tenantID,
			StorageBackend:  m.config.DefaultStorage,
			Healthy:         true,
			LastHealthCheck: time.Now().Format(time.RFC3339),
		}, nil
	}

	// Return a copy for thread safety
	return &TenantHealthStatus{
		TenantID:        status.TenantID,
		StorageBackend:  status.StorageBackend,
		Healthy:         status.Healthy,
		LastHealthCheck: status.LastHealthCheck,
		LastError:       status.LastError,
		ResponseTime:    status.ResponseTime,
	}, nil
}

// GetMetrics returns the current metrics
func (m *MultiStorageLayer) GetMetrics() *MultiStorageMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &m.metrics
}

// Size returns the current number of routes and tenants
func (m *MultiStorageLayer) Size() (int, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.storageRoutes), len(m.tenants)
}

// Close closes the multi-storage layer
func (m *MultiStorageLayer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	close(m.closeChan)

	// Clear all data
	m.storageRoutes = nil
	m.tenants = nil
	m.tenantStorage = nil
	m.healthStatus = nil

	m.logger.Info("Multi-storage layer closed")
	return nil
}

// IsClosed returns true if the layer is closed
func (m *MultiStorageLayer) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}
