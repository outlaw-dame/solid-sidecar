// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Security headers to add to all SAI responses
var securityHeaders = map[string]string{
	"X-Content-Type-Options":    "nosniff",
	"X-Frame-Options":           "DENY",
	"X-XSS-Protection":          "1; mode=block",
	"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
	"Content-Security-Policy":   "default-src 'self'; frame-ancestors 'none'",
	"Referrer-Policy":           "strict-origin-when-cross-origin",
	"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
}

// Maximum request body size for SAI endpoints (1 MB)
const MaxSAIRequestBodySize = 1 << 20 // 1 MiB

// SAIError is a structured error that can be safely returned to clients
type SAIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes for SAI operations
const (
	ErrCodeInvalidRequest    = "sai_invalid_request"
	ErrCodeUnauthorized      = "sai_unauthorized"
	ErrCodeForbidden         = "sai_forbidden"
	ErrCodeNotFound          = "sai_not_found"
	ErrCodeRateLimitExceeded = "sai_rate_limit_exceeded"
	ErrCodeInternalError     = "sai_internal_error"
)

// writeSAIError writes a structured SAI error response
func writeSAIError(w http.ResponseWriter, statusCode int, saiError SAIError) {
	w.Header().Set("Content-Type", ContentTypeSAIApplicationJSON)
	for k, v := range securityHeaders {
		w.Header().Set(k, v)
	}
	w.WriteHeader(statusCode)
	// Don't expose internal error details to clients - only structured error
	_ = json.NewEncoder(w).Encode(saiError)
}

// RateLimiter provides rate limiting for SAI endpoints
type RateLimiter struct {
	maxRequests int
	window      time.Duration
	lastRequest time.Time
	requests    int
	mu          chan struct{} // Used as a mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		maxRequests: maxRequests,
		window:      window,
		lastRequest: time.Now(),
		mu:          make(chan struct{}, 1),
	}
}

// Allow checks if a request is allowed
func (rl *RateLimiter) Allow() bool {
	rl.mu <- struct{}{}
	defer func() { <-rl.mu }()

	now := time.Now()
	if now.Sub(rl.lastRequest) > rl.window {
		rl.requests = 0
		rl.lastRequest = now
	}

	rl.requests++
	return rl.requests <= rl.maxRequests
}

// Reset resets the rate limiter
func (rl *RateLimiter) Reset() {
	rl.mu <- struct{}{}
	defer func() { <-rl.mu }()
	rl.requests = 0
	rl.lastRequest = time.Now()
}

// Authenticator defines the interface for SAI authentication
type Authenticator interface {
	// Authenticate verifies the request and returns the authenticated user WebID
	Authenticate(r *http.Request) (string, error)
	// Authorize checks if the user has access to the specified resource
	Authorize(userID, resourceID, action string) error
}

// DefaultAuthenticator is a simple WebID-based authenticator for SAI
type DefaultAuthenticator struct {
	logger *slog.Logger
}

// NewDefaultAuthenticator creates a new default authenticator
func NewDefaultAuthenticator(logger *slog.Logger) *DefaultAuthenticator {
	return &DefaultAuthenticator{
		logger: logger,
	}
}

// Authenticate verifies the request and extracts the user WebID
func (a *DefaultAuthenticator) Authenticate(r *http.Request) (string, error) {
	// Extract WebID from the request (e.g., from DPoP token, Authorization header, or Solid-OIDC)
	// For now, this is a placeholder that should be integrated with the existing authn package

	// Check for Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing authorization")
	}

	// Extract Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization header format")
	}

	// TODO: Integrate with existing authn package to validate the token
	// and extract the WebID. For now, return an error indicating
	// authentication is not yet fully integrated.
	return "", errors.New("SAI authentication not yet integrated with authn package")
}

// Authorize checks if the user has access to the resource
func (a *DefaultAuthenticator) Authorize(userID, resourceID, action string) error {
	// Check for ownership or explicit access grants
	// This is a critical security check to prevent IDOR vulnerabilities

	// For now, we'll implement a simple ownership check
	// In a real implementation, this would check:
	// 1. If the user owns the resource
	// 2. If the user has an access grant for the resource
	// 3. If the action is allowed by the grant

	// TODO: Implement proper authorization logic
	// For now, deny all access to prevent IDOR until proper authz is implemented
	return fmt.Errorf("SAI authorization not yet implemented - access denied")
}

// validateContentType checks that the request has the correct Content-Type
func validateContentType(r *http.Request) error {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return errors.New("Content-Type header is required")
	}

	// Accept application/json or application/ld+json
	if !strings.HasPrefix(contentType, "application/json") &&
		!strings.HasPrefix(contentType, "application/ld+json") {
		return fmt.Errorf("unsupported Content-Type: %s", contentType)
	}

	return nil
}

// limitBodySize limits the request body size
func limitBodySize(r *http.Request, maxBytes int64) (io.ReadCloser, error) {
	if r.Body == nil {
		return nil, errors.New("request body is nil")
	}

	// Create a limited reader that wraps the body
	return &limitedReadCloser{
		Reader: io.LimitReader(r.Body, maxBytes+1),
		body:   r.Body,
	}, nil
}

// limitedReadCloser wraps an io.Reader with a Close method
type limitedReadCloser struct {
	io.Reader
	body io.ReadCloser
}

func (l *limitedReadCloser) Close() error {
	return l.body.Close()
}

// checkBodySizeNotExceeded checks if the body size was exceeded after reading
func checkBodySizeNotExceeded(n int64, maxBytes int64) error {
	if n > maxBytes {
		return fmt.Errorf("request body too large: %d bytes (max: %d)", n, maxBytes)
	}
	return nil
}

// readAndValidateBody reads and validates the request body
func readAndValidateBody(r *http.Request, maxBytes int64, dest interface{}) error {
	// Validate content type
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		if err := validateContentType(r); err != nil {
			return err
		}

		// Limit body size
		limitedBody, err := limitBodySize(r, maxBytes)
		if err != nil {
			return err
		}
		defer limitedBody.Close()

		// Read body
		body, err := io.ReadAll(limitedBody)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}

		// Check size
		if err := checkBodySizeNotExceeded(int64(len(body)), maxBytes); err != nil {
			return err
		}

		// Decode JSON
		if err := json.Unmarshal(body, dest); err != nil {
			return fmt.Errorf("failed to decode request body: %w", err)
		}
	}

	return nil
}

// sanitizeID sanitizes resource IDs to prevent injection attacks
func sanitizeID(id string) error {
	if id == "" {
		return errors.New("ID cannot be empty")
	}

	// Check for path traversal attempts (.. and backslash)
	// Note: Forward slashes are allowed in IRIs as they are part of the URL structure
	if strings.Contains(id, "..") || strings.Contains(id, "\\") {
		return errors.New("ID contains invalid characters")
	}

	// Check length
	if len(id) > 2048 {
		return errors.New("ID too long")
	}

	// Validate IRI format
	if err := ValidateIRI(id); err != nil {
		return fmt.Errorf("invalid ID format: %w", err)
	}

	return nil
}

// sanitizeWebID sanitizes WebID values
func sanitizeWebID(webID string) error {
	if webID == "" {
		return errors.New("WebID cannot be empty")
	}

	if len(webID) > 2048 {
		return errors.New("WebID too long")
	}

	if err := ValidateWebID(webID); err != nil {
		return fmt.Errorf("invalid WebID format: %w", err)
	}

	return nil
}

// withSAISecurityHeaders adds security headers to responses
func withSAISecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range securityHeaders {
			w.Header().Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}

// withSAIRateLimiting adds rate limiting to SAI endpoints
func withSAIRateLimiting(limiter *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			writeSAIError(w, http.StatusTooManyRequests, SAIError{
				Code:    ErrCodeRateLimitExceeded,
				Message: "Rate limit exceeded. Please try again later.",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withSAIAuthentication adds authentication to SAI endpoints
func withSAIAuthentication(authenticator Authenticator, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for OPTIONS requests (CORS preflight)
		if r.Method == http.MethodOptions {
			next(w, r)
			return
		}

		// Authenticate the request
		userID, err := authenticator.Authenticate(r)
		if err != nil {
			writeSAIError(w, http.StatusUnauthorized, SAIError{
				Code:    ErrCodeUnauthorized,
				Message: "Authentication required",
			})
			return
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
		next(w, r.WithContext(ctx))
	}
}

// withSAIAuthorization adds authorization checks to SAI endpoints
func withSAIAuthorization(authenticator Authenticator, resourceType string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip authorization for OPTIONS requests
		if r.Method == http.MethodOptions {
			next(w, r)
			return
		}

		// Get user from context
		userID, ok := r.Context().Value(contextKeyUserID).(string)
		if !ok || userID == "" {
			writeSAIError(w, http.StatusUnauthorized, SAIError{
				Code:    ErrCodeUnauthorized,
				Message: "Authentication required",
			})
			return
		}

		// Get resource ID from path
		resourceID := r.PathValue("id")
		if resourceID == "" {
			resourceID = r.PathValue("applicationId")
		}
		if resourceID == "" {
			resourceID = r.PathValue("userId")
		}

		// Check authorization
		// Determine action based on method
		action := "read"
		if r.Method == http.MethodPost {
			action = "create"
		} else if r.Method == http.MethodPut {
			action = "update"
		} else if r.Method == http.MethodDelete {
			action = "delete"
		}

		if err := authenticator.Authorize(userID, resourceID, action); err != nil {
			writeSAIError(w, http.StatusForbidden, SAIError{
				Code:    ErrCodeForbidden,
				Message: "Access denied",
			})
			return
		}

		next(w, r)
	}
}

// withSAIResourceValidation adds resource ID validation
func withSAIResourceValidation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract and validate ID from path
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

		// Validate user ID if present
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

		next(w, r)
	}
}

// withSAIRequestValidation adds request validation for write operations
func withSAIRequestValidation(maxBodySize int64, dest interface{}, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			if err := readAndValidateBody(r, maxBodySize, dest); err != nil {
				writeSAIError(w, http.StatusBadRequest, SAIError{
					Code:    ErrCodeInvalidRequest,
					Message: "Invalid request: " + err.Error(),
				})
				return
			}
		}

		next(w, r)
	}
}

// contextKeyUserID is the context key for storing the authenticated user ID
type contextKey string

const contextKeyUserID contextKey = "sai_user_id"

// GetUserIDFromContext retrieves the user ID from the context
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(contextKeyUserID).(string)
	return userID, ok
}
