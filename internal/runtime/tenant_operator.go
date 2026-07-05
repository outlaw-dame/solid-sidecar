// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements the operator API for tenant lifecycle operations.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OperatorAPI provides HTTP endpoints for tenant lifecycle operations
// This API requires explicit admin authentication/authorization
type OperatorAPI struct {
	mu sync.RWMutex

	// multiStorage is the multi-storage layer
	multiStorage *MultiStorageLayer

	// adminAuth is the admin authentication handler
	adminAuth AdminAuthHandler

	// logger is the logger for this API
	logger *slog.Logger

	// config is the operator API configuration
	config OperatorAPIConfig

	// close state
	closeChan chan struct{}
	closed    bool
}

// OperatorAPIConfig holds configuration for the operator API
type OperatorAPIConfig struct {
	// BasePath is the base URL path for the operator API
	BasePath string

	// AdminAPIKey is the API key required for admin operations
	// If empty, admin authentication is disabled (not recommended for production)
	AdminAPIKey string

	// EnableTenantCreation enables the tenant creation endpoint
	EnableTenantCreation bool

	// EnableTenantDeletion enables the tenant deletion endpoint
	// This is a sensitive operation and should be carefully controlled
	EnableTenantDeletion bool

	// MaxTenants is the maximum number of tenants allowed (0 = unlimited)
	MaxTenants int

	// Logger is the logger for this API
	Logger *slog.Logger
}

// DefaultOperatorAPIConfig returns a safe default configuration
func DefaultOperatorAPIConfig() OperatorAPIConfig {
	return OperatorAPIConfig{
		BasePath:             "/admin/api/v1",
		AdminAPIKey:          "", // Must be explicitly set
		EnableTenantCreation: true,
		EnableTenantDeletion: false, // Disabled by default for safety
		MaxTenants:           0,     // Unlimited
		Logger:               nil,
	}
}

// AdminAuthHandler is a function that handles admin authentication
type AdminAuthHandler func(w http.ResponseWriter, r *http.Request) bool

// DefaultAdminAuthHandler is the default admin authentication handler
func DefaultAdminAuthHandler(apiKey string) AdminAuthHandler {
	return func(w http.ResponseWriter, r *http.Request) bool {
		if apiKey == "" {
			// No API key configured, deny all requests
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin API"`)
			http.Error(w, "Admin authentication required but no API key configured", http.StatusUnauthorized)
			return false
		}

		// Check for Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin API"`)
			http.Error(w, "Admin authentication required", http.StatusUnauthorized)
			return false
		}

		// Simple API key authentication (Bearer token)
		// Expected format: "Bearer <api-key>"
		const bearerPrefix = "Bearer "
		if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin API"`)
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return false
		}

		providedKey := authHeader[len(bearerPrefix):]
		if providedKey != apiKey {
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin API"`)
			http.Error(w, "Invalid API key", http.StatusUnauthorized)
			return false
		}

		return true
	}
}

// NewOperatorAPI creates a new operator API
func NewOperatorAPI(multiStorage *MultiStorageLayer, config OperatorAPIConfig) *OperatorAPI {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	api := &OperatorAPI{
		multiStorage: multiStorage,
		adminAuth:    DefaultAdminAuthHandler(config.AdminAPIKey),
		logger:       config.Logger,
		config:       config,
		closeChan:    make(chan struct{}),
		closed:       false,
	}

	config.Logger.Info("Operator API initialized",
		"base_path", config.BasePath,
		"admin_auth_enabled", config.AdminAPIKey != "",
		"tenant_creation_enabled", config.EnableTenantCreation,
		"tenant_deletion_enabled", config.EnableTenantDeletion,
		"max_tenants", config.MaxTenants,
	)

	return api
}

// SetAdminAuthHandler sets a custom admin authentication handler
func (api *OperatorAPI) SetAdminAuthHandler(handler AdminAuthHandler) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.adminAuth = handler
}

// RegisterRoutes registers the operator API routes with a router
func (api *OperatorAPI) RegisterRoutes(mux *http.ServeMux) {
	api.mu.RLock()
	defer api.mu.RUnlock()

	if api.closed {
		return
	}

	basePath := api.config.BasePath

	// List tenants
	mux.HandleFunc(basePath+"/tenants", api.handleListTenants)

	// Create tenant
	if api.config.EnableTenantCreation {
		mux.HandleFunc(basePath+"/tenants", api.handleCreateTenant)
	}

	// Get tenant
	mux.HandleFunc(basePath+"/tenants/", api.handleGetTenant)

	// Update tenant
	mux.HandleFunc(basePath+"/tenants/", api.handleUpdateTenant)

	// Delete tenant
	if api.config.EnableTenantDeletion {
		mux.HandleFunc(basePath+"/tenants/", api.handleDeleteTenant)
	}

	// Tenant health status
	mux.HandleFunc(basePath+"/tenants/", api.handleGetTenantHealth)

	// Tenant auth config
	mux.HandleFunc(basePath+"/tenants/", api.handleGetTenantAuthConfig)

	// Update tenant auth config
	mux.HandleFunc(basePath+"/tenants/", api.handleUpdateTenantAuthConfig)

	// Tenant storage config
	mux.HandleFunc(basePath+"/tenants/", api.handleGetTenantStorageConfig)

	api.logger.Info("Operator API routes registered", "base_path", basePath)
}

// Close closes the operator API
func (api *OperatorAPI) Close() error {
	api.mu.Lock()
	defer api.mu.Unlock()

	if api.closed {
		return nil
	}

	api.closed = true
	close(api.closeChan)
	api.logger.Info("Operator API closed")
	return nil
}

// IsClosed returns true if the API is closed
func (api *OperatorAPI) IsClosed() bool {
	api.mu.RLock()
	defer api.mu.RUnlock()
	return api.closed
}

// handleListTenants handles GET /tenants - list all tenants
func (api *OperatorAPI) handleListTenants(w http.ResponseWriter, r *http.Request) {
	if !api.adminAuth(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	if api.closed {
		http.Error(w, "Operator API is closed", http.StatusServiceUnavailable)
		return
	}

	if api.multiStorage == nil {
		http.Error(w, "Multi-storage layer not available", http.StatusInternalServerError)
		return
	}

	tenants := api.multiStorage.ListTenants()

	// Create a safe response that doesn't expose sensitive information
	tenantSummaries := make([]TenantSummary, 0, len(tenants))
	for _, tenant := range tenants {
		tenantSummaries = append(tenantSummaries, TenantSummary{
			TenantID:       tenant.TenantID,
			StorageBackend: tenant.StorageBackend,
			Enabled:        tenant.Enabled,
			Created:        tenant.Created,
			Modified:       tenant.Modified,
			// Don't expose quotas or other sensitive info in list
		})
	}

	// Set privacy-safe headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	if err := json.NewEncoder(w).Encode(TenantListResponse{
		Tenants: tenantSummaries,
		Count:   len(tenantSummaries),
	}); err != nil {
		api.logger.Error("Failed to encode tenant list response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Tenant list requested", "count", len(tenantSummaries))
}

// handleCreateTenant handles POST /tenants - create a new tenant
func (api *OperatorAPI) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	if !api.adminAuth(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	if api.closed {
		http.Error(w, "Operator API is closed", http.StatusServiceUnavailable)
		return
	}

	if api.multiStorage == nil {
		http.Error(w, "Multi-storage layer not available", http.StatusInternalServerError)
		return
	}

	// Check max tenants limit
	if api.config.MaxTenants > 0 {
		currentCount, _ := api.multiStorage.Size()
		if currentCount >= api.config.MaxTenants {
			http.Error(w, fmt.Sprintf("Maximum tenants limit reached (%d)", api.config.MaxTenants), http.StatusForbidden)
			return
		}
	}

	// Parse request body
	var request TenantCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.logger.Error("Failed to decode tenant create request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate tenant ID
	if err := ValidateTenantID(request.TenantID); err != nil {
		api.logger.Error("Invalid tenant ID in create request", "tenant_id", request.TenantID, "error", err)
		http.Error(w, fmt.Sprintf("Invalid tenant ID: %v", err), http.StatusBadRequest)
		return
	}

	// Check if tenant already exists
	if _, err := api.multiStorage.GetTenant(request.TenantID); err == nil {
		http.Error(w, fmt.Sprintf("Tenant %s already exists", request.TenantID), http.StatusConflict)
		return
	}

	// Create tenant config
	now := time.Now().Format(time.RFC3339)
	tenantConfig := &TenantConfig{
		TenantID:               request.TenantID,
		StorageRoot:            request.StorageRoot,
		StorageBackend:         request.StorageBackend,
		AllowedStorageBackends: request.AllowedStorageBackends,
		ResourceQuotas:         request.ResourceQuotas,
		ACLConfig:              request.ACLConfig,
		AuthConfig:             request.AuthConfig,
		Metadata:               request.Metadata,
		Created:                now,
		Modified:               now,
		Enabled:                request.Enabled,
	}

	// Set defaults if not provided
	if tenantConfig.StorageRoot == "" {
		tenantConfig.StorageRoot = "/"
	}
	if tenantConfig.StorageBackend == "" {
		tenantConfig.StorageBackend = api.multiStorage.config.DefaultStorage
	}
	if len(tenantConfig.AllowedStorageBackends) == 0 {
		tenantConfig.AllowedStorageBackends = []string{tenantConfig.StorageBackend}
	}
	if tenantConfig.AuthConfig == nil {
		tenantConfig.AuthConfig = DefaultTenantAuthConfig()
	}

	// Add tenant to multi-storage layer
	if err := api.multiStorage.AddTenant(tenantConfig); err != nil {
		api.logger.Error("Failed to add tenant", "tenant_id", request.TenantID, "error", err)
		http.Error(w, fmt.Sprintf("Failed to create tenant: %v", err), http.StatusInternalServerError)
		return
	}

	// Add tenant auth config if provided
	if request.AuthConfig != nil {
		if err := api.multiStorage.AddTenantAuthConfig(request.TenantID, request.AuthConfig); err != nil {
			api.logger.Error("Failed to add tenant auth config", "tenant_id", request.TenantID, "error", err)
			// Rollback tenant creation
			api.multiStorage.RemoveTenant(request.TenantID)
			http.Error(w, fmt.Sprintf("Failed to create tenant auth config: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Set privacy-safe headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", fmt.Sprintf("%s/tenants/%s", api.config.BasePath, request.TenantID))

	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(TenantCreateResponse{
		TenantID:       request.TenantID,
		Message:        "Tenant created successfully",
		Created:        now,
		StorageBackend: tenantConfig.StorageBackend,
	}); err != nil {
		api.logger.Error("Failed to encode tenant create response", "error", err)
	}

	api.logger.Info("Tenant created", "tenant_id", request.TenantID)
}

// handleGetTenant handles GET /tenants/{tenantID} - get tenant details
func (api *OperatorAPI) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	if !api.adminAuth(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	if api.closed {
		http.Error(w, "Operator API is closed", http.StatusServiceUnavailable)
		return
	}

	if api.multiStorage == nil {
		http.Error(w, "Multi-storage layer not available", http.StatusInternalServerError)
		return
	}

	// Extract tenant ID from path
	tenantID := extractTenantIDFromPath(r.URL.Path, api.config.BasePath)
	if tenantID == "" {
		http.Error(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	// Get tenant
	tenant, err := api.multiStorage.GetTenant(tenantID)
	if err != nil {
		api.logger.Error("Tenant not found", "tenant_id", tenantID, "error", err)
		http.Error(w, fmt.Sprintf("Tenant %s not found", tenantID), http.StatusNotFound)
		return
	}

	// Set privacy-safe headers
	w.Header().Set("Content-Type", "application/json")

	// Return tenant details (exclude sensitive information)
	if err := json.NewEncoder(w).Encode(TenantDetailResponse{
		TenantID:               tenant.TenantID,
		StorageBackend:         tenant.StorageBackend,
		AllowedStorageBackends: tenant.AllowedStorageBackends,
		ResourceQuotas:         tenant.ResourceQuotas,
		ACLConfig:              tenant.ACLConfig,
		// Don't expose AuthConfig in detail response for privacy
		Metadata: tenant.Metadata,
		Created:  tenant.Created,
		Modified: tenant.Modified,
		Enabled:  tenant.Enabled,
	}); err != nil {
		api.logger.Error("Failed to encode tenant detail response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Tenant details requested", "tenant_id", tenantID)
}

// handleUpdateTenant handles PUT /tenants/{tenantID} - update tenant
func (api *OperatorAPI) handleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	if !api.adminAuth(w, r) {
		return
	}

	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	if api.closed {
		http.Error(w, "Operator API is closed", http.StatusServiceUnavailable)
		return
	}

	if api.multiStorage == nil {
		http.Error(w, "Multi-storage layer not available", http.StatusInternalServerError)
		return
	}

	// Extract tenant ID from path
	tenantID := extractTenantIDFromPath(r.URL.Path, api.config.BasePath)
	if tenantID == "" {
		http.Error(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	// Check if tenant exists
	if _, err := api.multiStorage.GetTenant(tenantID); err != nil {
		api.logger.Error("Tenant not found for update", "tenant_id", tenantID, "error", err)
		http.Error(w, fmt.Sprintf("Tenant %s not found", tenantID), http.StatusNotFound)
		return
	}

	// Parse request body
	var request TenantUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.logger.Error("Failed to decode tenant update request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get existing tenant
	existingTenant, err := api.multiStorage.GetTenant(tenantID)
	if err != nil {
		api.logger.Error("Failed to get existing tenant", "tenant_id", tenantID, "error", err)
		http.Error(w, "Failed to retrieve tenant", http.StatusInternalServerError)
		return
	}

	// Update tenant config
	updatedTenant := *existingTenant
	updatedTenant.Modified = time.Now().Format(time.RFC3339)

	// Update fields if provided in request
	if request.StorageRoot != "" {
		updatedTenant.StorageRoot = request.StorageRoot
	}
	if request.StorageBackend != "" {
		updatedTenant.StorageBackend = request.StorageBackend
	}
	if len(request.AllowedStorageBackends) > 0 {
		updatedTenant.AllowedStorageBackends = request.AllowedStorageBackends
	}
	if request.ResourceQuotas != (TenantQuotas{}) {
		updatedTenant.ResourceQuotas = request.ResourceQuotas
	}
	if request.ACLConfig != (TenantACLConfig{}) {
		updatedTenant.ACLConfig = request.ACLConfig
	}
	if request.Metadata != nil {
		updatedTenant.Metadata = request.Metadata
	}
	if request.Enabled != updatedTenant.Enabled {
		updatedTenant.Enabled = request.Enabled
	}

	// Update tenant in multi-storage layer
	if err := api.multiStorage.UpdateTenant(&updatedTenant); err != nil {
		api.logger.Error("Failed to update tenant", "tenant_id", tenantID, "error", err)
		http.Error(w, fmt.Sprintf("Failed to update tenant: %v", err), http.StatusInternalServerError)
		return
	}

	// Set privacy-safe headers
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(TenantUpdateResponse{
		TenantID:       tenantID,
		Message:        "Tenant updated successfully",
		Modified:       updatedTenant.Modified,
		StorageBackend: updatedTenant.StorageBackend,
	}); err != nil {
		api.logger.Error("Failed to encode tenant update response", "error", err)
	}

	api.logger.Info("Tenant updated", "tenant_id", tenantID)
}

// handleDeleteTenant handles DELETE /tenants/{tenantID} - delete tenant
func (api *OperatorAPI) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	if !api.adminAuth(w, r) {
		return
	}

	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	if api.closed {
		http.Error(w, "Operator API is closed", http.StatusServiceUnavailable)
		return
	}

	if api.multiStorage == nil {
		http.Error(w, "Multi-storage layer not available", http.StatusInternalServerError)
		return
	}

	// Extract tenant ID from path
	tenantID := extractTenantIDFromPath(r.URL.Path, api.config.BasePath)
	if tenantID == "" {
		http.Error(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	// Check if tenant exists
	if _, err := api.multiStorage.GetTenant(tenantID); err != nil {
		api.logger.Error("Tenant not found for deletion", "tenant_id", tenantID, "error", err)
		http.Error(w, fmt.Sprintf("Tenant %s not found", tenantID), http.StatusNotFound)
		return
	}

	// Delete tenant
	if err := api.multiStorage.RemoveTenant(tenantID); err != nil {
		api.logger.Error("Failed to delete tenant", "tenant_id", tenantID, "error", err)
		http.Error(w, fmt.Sprintf("Failed to delete tenant: %v", err), http.StatusInternalServerError)
		return
	}

	// Also remove tenant auth config
	api.multiStorage.RemoveTenantAuthConfig(tenantID)

	// Set privacy-safe headers
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusNoContent)

	api.logger.Info("Tenant deleted", "tenant_id", tenantID)
}

// handleGetTenantHealth handles GET /tenants/{tenantID}/health - get tenant health status
func (api *OperatorAPI) handleGetTenantHealth(w http.ResponseWriter, r *http.Request) {
	if !api.adminAuth(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	if api.closed {
		http.Error(w, "Operator API is closed", http.StatusServiceUnavailable)
		return
	}

	if api.multiStorage == nil {
		http.Error(w, "Multi-storage layer not available", http.StatusInternalServerError)
		return
	}

	// Extract tenant ID from path
	tenantID := extractTenantIDFromPath(r.URL.Path, api.config.BasePath)
	if tenantID == "" {
		http.Error(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	// Get tenant health status
	healthStatus, err := api.multiStorage.GetHealthStatus(tenantID)
	if err != nil {
		api.logger.Error("Failed to get tenant health status", "tenant_id", tenantID, "error", err)
		http.Error(w, fmt.Sprintf("Failed to get health status: %v", err), http.StatusInternalServerError)
		return
	}

	// Set privacy-safe headers
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(TenantHealthResponse{
		TenantID:        tenantID,
		StorageBackend:  healthStatus.StorageBackend,
		Healthy:         healthStatus.Healthy,
		LastHealthCheck: healthStatus.LastHealthCheck,
		ResponseTime:    healthStatus.ResponseTime,
		// Don't expose LastError in response for privacy
	}); err != nil {
		api.logger.Error("Failed to encode tenant health response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Tenant health status requested", "tenant_id", tenantID)
}

// handleGetTenantAuthConfig handles GET /tenants/{tenantID}/auth - get tenant auth config
func (api *OperatorAPI) handleGetTenantAuthConfig(w http.ResponseWriter, r *http.Request) {
	if !api.adminAuth(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	if api.closed {
		http.Error(w, "Operator API is closed", http.StatusServiceUnavailable)
		return
	}

	if api.multiStorage == nil {
		http.Error(w, "Multi-storage layer not available", http.StatusInternalServerError)
		return
	}

	// Extract tenant ID from path
	tenantID := extractTenantIDFromPath(r.URL.Path, api.config.BasePath)
	if tenantID == "" {
		http.Error(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	// Get tenant auth config
	authConfig, err := api.multiStorage.GetTenantAuthConfig(tenantID)
	if err != nil {
		api.logger.Error("Failed to get tenant auth config", "tenant_id", tenantID, "error", err)
		http.Error(w, fmt.Sprintf("Failed to get auth config: %v", err), http.StatusInternalServerError)
		return
	}

	// Set privacy-safe headers
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(TenantAuthConfigResponse{
		TenantID:   tenantID,
		AuthConfig: authConfig,
	}); err != nil {
		api.logger.Error("Failed to encode tenant auth config response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Tenant auth config requested", "tenant_id", tenantID)
}

// handleUpdateTenantAuthConfig handles PUT /tenants/{tenantID}/auth - update tenant auth config
func (api *OperatorAPI) handleUpdateTenantAuthConfig(w http.ResponseWriter, r *http.Request) {
	if !api.adminAuth(w, r) {
		return
	}

	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	if api.closed {
		http.Error(w, "Operator API is closed", http.StatusServiceUnavailable)
		return
	}

	if api.multiStorage == nil {
		http.Error(w, "Multi-storage layer not available", http.StatusInternalServerError)
		return
	}

	// Extract tenant ID from path
	tenantID := extractTenantIDFromPath(r.URL.Path, api.config.BasePath)
	if tenantID == "" {
		http.Error(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	// Parse request body
	var request TenantAuthConfigUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.logger.Error("Failed to decode tenant auth config update request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate the auth config
	if err := ValidateTenantAuthConfig(&request.AuthConfig); err != nil {
		api.logger.Error("Invalid tenant auth config", "tenant_id", tenantID, "error", err)
		http.Error(w, fmt.Sprintf("Invalid auth config: %v", err), http.StatusBadRequest)
		return
	}

	// Update tenant auth config
	if err := api.multiStorage.UpdateTenantAuthConfig(tenantID, &request.AuthConfig); err != nil {
		api.logger.Error("Failed to update tenant auth config", "tenant_id", tenantID, "error", err)
		http.Error(w, fmt.Sprintf("Failed to update auth config: %v", err), http.StatusInternalServerError)
		return
	}

	// Set privacy-safe headers
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(TenantAuthConfigUpdateResponse{
		TenantID: tenantID,
		Message:  "Tenant auth config updated successfully",
	}); err != nil {
		api.logger.Error("Failed to encode tenant auth config update response", "error", err)
	}

	api.logger.Info("Tenant auth config updated", "tenant_id", tenantID)
}

// handleGetTenantStorageConfig handles GET /tenants/{tenantID}/storage - get tenant storage config
func (api *OperatorAPI) handleGetTenantStorageConfig(w http.ResponseWriter, r *http.Request) {
	if !api.adminAuth(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	if api.closed {
		http.Error(w, "Operator API is closed", http.StatusServiceUnavailable)
		return
	}

	if api.multiStorage == nil {
		http.Error(w, "Multi-storage layer not available", http.StatusInternalServerError)
		return
	}

	// Extract tenant ID from path
	tenantID := extractTenantIDFromPath(r.URL.Path, api.config.BasePath)
	if tenantID == "" {
		http.Error(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	// Get tenant storage
	storage, err := api.multiStorage.GetTenantStorage(tenantID)
	if err != nil {
		api.logger.Error("Failed to get tenant storage", "tenant_id", tenantID, "error", err)
		http.Error(w, fmt.Sprintf("Failed to get storage: %v", err), http.StatusInternalServerError)
		return
	}

	// Set privacy-safe headers
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(TenantStorageConfigResponse{
		TenantID:       tenantID,
		StorageBackend: storage,
	}); err != nil {
		api.logger.Error("Failed to encode tenant storage config response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Tenant storage config requested", "tenant_id", tenantID)
}

// extractTenantIDFromPath extracts tenant ID from URL path
func extractTenantIDFromPath(path, basePath string) string {
	// Remove base path from the beginning
	prefix := basePath + "/tenants/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}

	suffix := path[len(prefix):]
	// Find the end of the tenant ID (either end of string or next /)
	endIndex := strings.Index(suffix, "/")
	if endIndex == -1 {
		endIndex = len(suffix)
	}

	return suffix[:endIndex]
}

// Response types for the operator API

type TenantListResponse struct {
	Tenants []TenantSummary `json:"tenants"`
	Count   int             `json:"count"`
}

type TenantSummary struct {
	TenantID       string `json:"tenant_id"`
	StorageBackend string `json:"storage_backend"`
	Enabled        bool   `json:"enabled"`
	Created        string `json:"created"`
	Modified       string `json:"modified"`
}

type TenantDetailResponse struct {
	TenantID               string            `json:"tenant_id"`
	StorageBackend         string            `json:"storage_backend"`
	AllowedStorageBackends []string          `json:"allowed_storage_backends"`
	ResourceQuotas         TenantQuotas      `json:"resource_quotas"`
	ACLConfig              TenantACLConfig   `json:"acl_config"`
	Metadata               map[string]string `json:"metadata"`
	Created                string            `json:"created"`
	Modified               string            `json:"modified"`
	Enabled                bool              `json:"enabled"`
}

type TenantCreateRequest struct {
	TenantID               string            `json:"tenant_id"`
	StorageRoot            string            `json:"storage_root"`
	StorageBackend         string            `json:"storage_backend"`
	AllowedStorageBackends []string          `json:"allowed_storage_backends"`
	ResourceQuotas         TenantQuotas      `json:"resource_quotas"`
	ACLConfig              TenantACLConfig   `json:"acl_config"`
	AuthConfig             *TenantAuthConfig `json:"auth_config"`
	Metadata               map[string]string `json:"metadata"`
	Enabled                bool              `json:"enabled"`
}

type TenantCreateResponse struct {
	TenantID       string `json:"tenant_id"`
	Message        string `json:"message"`
	Created        string `json:"created"`
	StorageBackend string `json:"storage_backend"`
}

type TenantUpdateRequest struct {
	StorageRoot            string            `json:"storage_root"`
	StorageBackend         string            `json:"storage_backend"`
	AllowedStorageBackends []string          `json:"allowed_storage_backends"`
	ResourceQuotas         TenantQuotas      `json:"resource_quotas"`
	ACLConfig              TenantACLConfig   `json:"acl_config"`
	Metadata               map[string]string `json:"metadata"`
	Enabled                bool              `json:"enabled"`
}

type TenantUpdateResponse struct {
	TenantID       string `json:"tenant_id"`
	Message        string `json:"message"`
	Modified       string `json:"modified"`
	StorageBackend string `json:"storage_backend"`
}

type TenantHealthResponse struct {
	TenantID        string  `json:"tenant_id"`
	StorageBackend  string  `json:"storage_backend"`
	Healthy         bool    `json:"healthy"`
	LastHealthCheck string  `json:"last_health_check"`
	ResponseTime    float64 `json:"response_time_ms"`
}

type TenantAuthConfigResponse struct {
	TenantID   string            `json:"tenant_id"`
	AuthConfig *TenantAuthConfig `json:"auth_config"`
}

type TenantAuthConfigUpdateRequest struct {
	AuthConfig TenantAuthConfig `json:"auth_config"`
}

type TenantAuthConfigUpdateResponse struct {
	TenantID string `json:"tenant_id"`
	Message  string `json:"message"`
}

type TenantStorageConfigResponse struct {
	TenantID       string `json:"tenant_id"`
	StorageBackend string `json:"storage_backend"`
}

// Context key for tenant ID in requests
type contextKey string

const tenantIDContextKey contextKey = "tenant_id"

// WithTenantID adds tenant ID to context
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDContextKey, tenantID)
}

// GetTenantIDFromContext gets tenant ID from context
func GetTenantIDFromContext(ctx context.Context) (string, bool) {
	tenantID, ok := ctx.Value(tenantIDContextKey).(string)
	return tenantID, ok
}
