// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"encoding/json"
	"net/http"
)

// Handler provides HTTP endpoints for SAI operations
type Handler struct {
	service *SAIService
}

// NewHandler creates a new SAI HTTP handler
func NewHandler(service *SAIService) *Handler {
	return &Handler{
		service: service,
	}
}

// RegisterRoutes registers SAI routes with the provided ServeMux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Application Registration endpoints
	mux.Handle("POST /sai/applications", http.HandlerFunc(h.handleRegisterApplication))
	mux.Handle("GET /sai/applications/{id}", http.HandlerFunc(h.handleGetApplication))
	mux.Handle("GET /sai/users/{userId}/applications", http.HandlerFunc(h.handleListUserApplications))

	// Authorization Agent discovery
	mux.Handle("POST /sai/discover", http.HandlerFunc(h.handleDiscoverAuthorizationAgent))

	// Authorization Flow endpoints
	mux.Handle("POST /sai/authorize", http.HandlerFunc(h.handleInitiateAuthorizationFlow))

	// Access Grant endpoints
	mux.Handle("POST /sai/grants", http.HandlerFunc(h.handleCreateAccessGrant))
	mux.Handle("GET /sai/grants/{id}", http.HandlerFunc(h.handleGetAccessGrant))

	// Data Registration endpoints
	mux.Handle("POST /sai/data-registrations", http.HandlerFunc(h.handleRegisterData))
	mux.Handle("GET /sai/data-registrations/{id}", http.HandlerFunc(h.handleGetDataRegistration))

	// Shape Tree endpoints
	mux.Handle("POST /sai/shape-trees", http.HandlerFunc(h.handleStoreShapeTree))
	mux.Handle("GET /sai/shape-trees/{id}", http.HandlerFunc(h.handleGetShapeTree))
	mux.Handle("GET /sai/shape-trees", http.HandlerFunc(h.handleListShapeTrees))
}

// Application Registration Handlers

func (h *Handler) handleRegisterApplication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterApplicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	response, err := h.service.RegisterApplication(r.Context(), req)
	if err != nil {
		http.Error(w, "Failed to register application: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) handleGetApplication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "Application ID is required", http.StatusBadRequest)
		return
	}

	app, err := h.service.GetApplication(r.Context(), id)
	if err != nil {
		if err.Error() == ErrSAIApplicationNotFound {
			http.Error(w, "Application not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to get application: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(app); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) handleListUserApplications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.PathValue("userId")
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	applications, err := h.service.ListApplications(r.Context(), userID)
	if err != nil {
		http.Error(w, "Failed to list applications: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(applications); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// Authorization Agent Discovery Handlers

func (h *Handler) handleDiscoverAuthorizationAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DiscoverAuthorizationAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	response, err := h.service.DiscoverAuthorizationAgent(r.Context(), req)
	if err != nil {
		http.Error(w, "Failed to discover authorization agent: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// Authorization Flow Handlers

func (h *Handler) handleInitiateAuthorizationFlow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req InitiateAuthorizationFlowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	response, err := h.service.InitiateAuthorizationFlow(r.Context(), req)
	if err != nil {
		http.Error(w, "Failed to initiate authorization flow: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// Access Grant Handlers

func (h *Handler) handleCreateAccessGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateAccessGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	response, err := h.service.CreateAccessGrant(r.Context(), req)
	if err != nil {
		http.Error(w, "Failed to create access grant: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) handleGetAccessGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "Grant ID is required", http.StatusBadRequest)
		return
	}

	grant, err := h.service.GetAccessGrant(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to get access grant: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(grant); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// Data Registration Handlers

func (h *Handler) handleRegisterData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterDataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	response, err := h.service.RegisterData(r.Context(), req)
	if err != nil {
		http.Error(w, "Failed to register data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) handleGetDataRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "Registration ID is required", http.StatusBadRequest)
		return
	}

	registration, err := h.service.GetDataRegistration(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to get data registration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(registration); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// Shape Tree Handlers

func (h *Handler) handleStoreShapeTree(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tree ShapeTree
	if err := json.NewDecoder(r.Body).Decode(&tree); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.service.StoreShapeTree(r.Context(), &tree); err != nil {
		http.Error(w, "Failed to store shape tree: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(tree); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) handleGetShapeTree(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "Shape Tree ID is required", http.StatusBadRequest)
		return
	}

	tree, err := h.service.GetShapeTree(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to get shape tree: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(tree); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) handleListShapeTrees(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	trees, err := h.service.ListShapeTrees(r.Context())
	if err != nil {
		http.Error(w, "Failed to list shape trees: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	if err := json.NewEncoder(w).Encode(trees); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
