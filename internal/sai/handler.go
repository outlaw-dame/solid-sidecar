// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

// Handler provides HTTP endpoints for SAI operations
type Handler struct {
	service       *SAIService
	logger        *slog.Logger
	rateLimiter   *RateLimiter
	authenticator Authenticator
	maxBodySize   int64
}

// HandlerOptions configures the SAI handler
type HandlerOptions struct {
	Logger        *slog.Logger
	RateLimiter   *RateLimiter
	Authenticator Authenticator
	// MaxBodySize is the maximum request body size (default: 1 MiB)
	MaxBodySize int64
}

// NewHandler creates a new SAI HTTP handler with optional configuration
func NewHandler(service *SAIService, options HandlerOptions) *Handler {
	// Use defaults if not provided
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.RateLimiter == nil {
		// Default: 100 requests per minute
		options.RateLimiter = NewRateLimiter(DefaultSAIRateLimitRequestsPerWindow, DefaultSAIRateLimitWindow)
	}
	if options.Authenticator == nil {
		// Default: deny all (fail-secure) - no identity verifier configured
		options.Authenticator = NewDefaultAuthenticator(options.Logger, nil)
	}
	if options.MaxBodySize <= 0 {
		options.MaxBodySize = DefaultMaxSAIRequestBodySize
	}

	return &Handler{
		service:       service,
		logger:        options.Logger,
		rateLimiter:   options.RateLimiter,
		authenticator: options.Authenticator,
		maxBodySize:   options.MaxBodySize,
	}
}

// RegisterRoutes registers SAI routes with the provided ServeMux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Application Registration endpoints
	mux.Handle("POST /sai/applications", withSAISecurityMiddleware(h, h.handleRegisterApplication))
	mux.Handle("GET /sai/applications/{id}", withSAISecurityMiddleware(h, h.handleGetApplication))
	mux.Handle("GET /sai/users/{userId}/applications", withSAISecurityMiddleware(h, h.handleListUserApplications))

	// Authorization Agent discovery
	mux.Handle("POST /sai/discover", withSAISecurityMiddleware(h, h.handleDiscoverAuthorizationAgent))

	// Authorization Flow endpoints
	mux.Handle("POST /sai/authorize", withSAISecurityMiddleware(h, h.handleInitiateAuthorizationFlow))

	// Access Grant endpoints
	mux.Handle("POST /sai/grants", withSAISecurityMiddleware(h, h.handleCreateAccessGrant))
	mux.Handle("GET /sai/grants/{id}", withSAISecurityMiddleware(h, h.handleGetAccessGrant))

	// Data Registration endpoints
	mux.Handle("POST /sai/data-registrations", withSAISecurityMiddleware(h, h.handleRegisterData))
	mux.Handle("GET /sai/data-registrations/{id}", withSAISecurityMiddleware(h, h.handleGetDataRegistration))

	// Shape Tree endpoints
	mux.Handle("POST /sai/shape-trees", withSAISecurityMiddleware(h, h.handleStoreShapeTree))
	mux.Handle("GET /sai/shape-trees/{id}", withSAISecurityMiddleware(h, h.handleGetShapeTree))
	mux.Handle("GET /sai/shape-trees", withSAISecurityMiddleware(h, h.handleListShapeTrees))
}

// withSAISecurityMiddleware creates a middleware chain for SAI handlers
func withSAISecurityMiddleware(h *Handler, next http.HandlerFunc) http.HandlerFunc {
	// Build the middleware chain from outer to inner:
	// 1. Rate Limiting -> 2. Security Headers -> 3. Resource Validation -> 4. Authentication

	return func(w http.ResponseWriter, r *http.Request) {
		// Apply rate limiting
		if !h.rateLimiter.Allow() {
			writeSAIError(w, http.StatusTooManyRequests, SAIError{
				Code:    ErrCodeRateLimitExceeded,
				Message: "Rate limit exceeded. Please try again later.",
			})
			return
		}

		// Apply resource validation
		id := r.PathValue("id")
		if id != "" {
			if err := sanitizeID(id); err != nil {
				writeSAIError(w, http.StatusBadRequest, SAIError{
					Code:    ErrCodeInvalidRequest,
					Message: "Invalid resource ID",
				})
				return
			}
		}

		userID := r.PathValue("userId")
		if userID != "" {
			if err := sanitizeWebID(userID); err != nil {
				writeSAIError(w, http.StatusBadRequest, SAIError{
					Code:    ErrCodeInvalidRequest,
					Message: "Invalid user ID",
				})
				return
			}
		}

		// Apply authentication (skip for OPTIONS preflight)
		if r.Method != http.MethodOptions {
			authUserID, err := h.authenticator.Authenticate(r)
			if err != nil {
				// Log authentication failure for security auditing
				if h.logger != nil {
					h.logger.Warn("SAI authentication failed",
						"error", err.Error(),
						"path", r.URL.Path,
						"method", r.Method)
				}
				writeSAIError(w, http.StatusUnauthorized, SAIError{
					Code:    ErrCodeUnauthorized,
					Message: "Authentication required",
				})
				return
			}

			// Add user to context
			ctx := context.WithValue(r.Context(), contextKeyUserID, authUserID)
			r = r.WithContext(ctx)
		}

		// Add security headers to response
		for k, v := range securityHeaders {
			w.Header().Set(k, v)
		}

		// Call the next handler
		next(w, r)
	}
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
