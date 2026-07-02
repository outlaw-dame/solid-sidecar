// Package health provides health monitoring and state management for the Solid runtime.
// This file implements structured health states as required by Phase 17.
package health

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HealthState represents the overall health state of the runtime
type HealthState string

const (
	// HealthStateHealthy indicates all systems are operating normally
	HealthStateHealthy HealthState = "healthy"

	// HealthStateDegraded indicates some systems are not operating at full capacity
	HealthStateDegraded HealthState = "degraded"

	// HealthStateShadowOnly indicates the runtime is operating in shadow mode only
	HealthStateShadowOnly HealthState = "shadow-only"

	// HealthStateEnforcing indicates the runtime is actively enforcing policies
	HealthStateEnforcing HealthState = "enforcing"

	// HealthStateBypassed indicates the runtime has been bypassed and is using CSS directly
	HealthStateBypassed HealthState = "bypassed"
)

// ComponentHealth represents the health status of a single component
type ComponentHealth struct {
	// Name is the component name
	Name string `json:"name"`

	// State is the current health state
	State HealthState `json:"state"`

	// Healthy is true if the component is fully operational
	Healthy bool `json:"healthy"`

	// Details provides additional information about the component status
	Details map[string]interface{} `json:"details,omitempty"`

	// LastUpdated is when the health was last updated
	LastUpdated time.Time `json:"last_updated"`

	// LastError contains the last error if any
	LastError string `json:"last_error,omitempty"`

	// ErrorCount is the number of consecutive errors
	ErrorCount int `json:"error_count,omitempty"`
}

// RuntimeHealth represents the overall health of the Solid runtime
type RuntimeHealth struct {
	mu sync.RWMutex

	// OverallState is the aggregated health state
	OverallState HealthState `json:"overall_state"`

	// Components contains health information for all components
	Components map[string]*ComponentHealth `json:"components"`

	// Timestamp is when the health was last evaluated
	Timestamp time.Time `json:"timestamp"`

	// Uptime is how long the runtime has been running
	Uptime time.Duration `json:"uptime"`

	// Version is the runtime version
	Version string `json:"version"`

	// Environment is the runtime environment (dev, staging, prod)
	Environment string `json:"environment"`

	// StartedAt is when the runtime was started
	StartedAt time.Time `json:"started_at"`

	// LastUpdated is when the health was last updated
	LastUpdated time.Time `json:"last_updated"`
}

// NewRuntimeHealth creates a new runtime health monitor
func NewRuntimeHealth(version, environment string) *RuntimeHealth {
	return &RuntimeHealth{
		OverallState: HealthStateHealthy,
		Components:   make(map[string]*ComponentHealth),
		Timestamp:    time.Now(),
		Version:      version,
		Environment:  environment,
		StartedAt:    time.Now(),
		LastUpdated:  time.Now(),
	}
}

// UpdateOverallState updates the overall health state based on component states
func (r *RuntimeHealth) UpdateOverallState() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Start with healthy
	newState := HealthStateHealthy

	// If any component is bypassed, overall state is bypassed
	for _, component := range r.Components {
		if component.State == HealthStateBypassed {
			newState = HealthStateBypassed
			break
		}
	}

	// If any component is enforcing, overall state is enforcing
	if newState == HealthStateHealthy {
		for _, component := range r.Components {
			if component.State == HealthStateEnforcing {
				newState = HealthStateEnforcing
				break
			}
		}
	}

	// If any component is shadow-only, overall state is shadow-only
	if newState == HealthStateHealthy {
		for _, component := range r.Components {
			if component.State == HealthStateShadowOnly {
				newState = HealthStateShadowOnly
				break
			}
		}
	}

	// If any component is degraded, overall state is degraded
	if newState == HealthStateHealthy {
		for _, component := range r.Components {
			if component.State == HealthStateDegraded {
				newState = HealthStateDegraded
				break
			}
		}
	}

	// If any component is unhealthy, overall state is degraded
	if newState == HealthStateHealthy {
		for _, component := range r.Components {
			if !component.Healthy {
				newState = HealthStateDegraded
				break
			}
		}
	}

	r.OverallState = newState
	r.LastUpdated = time.Now()
	r.Timestamp = time.Now()
	r.Uptime = time.Since(r.StartedAt)
}

// UpdateComponentHealth updates the health of a specific component
func (r *RuntimeHealth) UpdateComponentHealth(componentName string, state HealthState, healthy bool, details map[string]interface{}, lastError string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	component, exists := r.Components[componentName]
	if !exists {
		component = &ComponentHealth{
			Name:        componentName,
			State:       state,
			Healthy:     healthy,
			Details:     make(map[string]interface{}),
			LastUpdated: time.Now(),
		}
		r.Components[componentName] = component
	}

	component.State = state
	component.Healthy = healthy
	component.LastUpdated = time.Now()

	// Update details
	if details != nil {
		for key, value := range details {
			component.Details[key] = value
		}
	}

	// Update error information
	if lastError != "" {
		component.LastError = lastError
		component.ErrorCount++
	} else {
		component.LastError = ""
		component.ErrorCount = 0
	}

	// Update overall state
	r.UpdateOverallState()
}

// GetHealth returns the current health status
func (r *RuntimeHealth) GetHealth() *RuntimeHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to avoid race conditions
	health := &RuntimeHealth{
		OverallState: r.OverallState,
		Components:   make(map[string]*ComponentHealth),
		Timestamp:    r.Timestamp,
		Uptime:       r.Uptime,
		Version:      r.Version,
		Environment:  r.Environment,
		StartedAt:    r.StartedAt,
		LastUpdated:  r.LastUpdated,
	}

	for name, component := range r.Components {
		health.Components[name] = &ComponentHealth{
			Name:        component.Name,
			State:       component.State,
			Healthy:     component.Healthy,
			Details:     make(map[string]interface{}),
			LastUpdated: component.LastUpdated,
			LastError:   component.LastError,
			ErrorCount:  component.ErrorCount,
		}
		// Copy details map
		for k, v := range component.Details {
			health.Components[name].Details[k] = v
		}
	}

	return health
}

// HealthHandler returns an HTTP handler for health checks
func (r *RuntimeHealth) HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		health := r.GetHealth()

		// Set appropriate status code based on health state
		statusCode := http.StatusOK
		switch health.OverallState {
		case HealthStateHealthy:
			statusCode = http.StatusOK
		case HealthStateDegraded, HealthStateShadowOnly:
			statusCode = http.StatusOK // Still return 200 for degraded/shadow
		case HealthStateEnforcing:
			statusCode = http.StatusOK
		case HealthStateBypassed:
			statusCode = http.StatusOK // Bypassed is still operational
		}

		// For non-healthy states, consider if we should return different status codes
		// For now, we return 200 with the health information in the body

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		// Create response with health details
		response := map[string]interface{}{
			"status":         health.OverallState,
			"healthy":        health.OverallState == HealthStateHealthy,
			"version":        health.Version,
			"environment":    health.Environment,
			"uptime":         health.Uptime.String(),
			"uptime_seconds": health.Uptime.Seconds(),
			"timestamp":      health.Timestamp.Format(time.RFC3339),
			"started_at":     health.StartedAt.Format(time.RFC3339),
			"components":     health.Components,
		}

		json.NewEncoder(w).Encode(response)
	})
}

// ReadinessHandler returns an HTTP handler for readiness checks
// Readiness indicates whether the runtime can accept traffic
func (r *RuntimeHealth) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		health := r.GetHealth()

		// Check if runtime is ready to accept traffic
		// Ready means healthy or enforcing (can accept traffic)
		// Not ready means degraded, shadow-only, or bypassed might indicate issues
		ready := health.OverallState == HealthStateHealthy ||
			health.OverallState == HealthStateEnforcing

		statusCode := http.StatusOK
		if !ready {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		response := map[string]interface{}{
			"ready":     ready,
			"status":    health.OverallState,
			"reason":    getReadinessReason(health),
			"timestamp": health.Timestamp.Format(time.RFC3339),
		}

		json.NewEncoder(w).Encode(response)
	})
}

// LivenessHandler returns an HTTP handler for liveness checks
// Liveness indicates whether the runtime is running at all
func (r *RuntimeHealth) LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Runtime is always considered live if this handler is running
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		health := r.GetHealth()
		response := map[string]interface{}{
			"live":      true,
			"status":    health.OverallState,
			"timestamp": health.Timestamp.Format(time.RFC3339),
		}

		json.NewEncoder(w).Encode(response)
	})
}

// getReadinessReason returns a human-readable reason for readiness state
func getReadinessReason(health *RuntimeHealth) string {
	switch health.OverallState {
	case HealthStateHealthy:
		return "runtime is healthy and ready to accept traffic"
	case HealthStateEnforcing:
		return "runtime is enforcing policies and ready to accept traffic"
	case HealthStateDegraded:
		return fmt.Sprintf("runtime is degraded: %d components not healthy", countUnhealthyComponents(health))
	case HealthStateShadowOnly:
		return "runtime is operating in shadow mode only - not enforcing policies"
	case HealthStateBypassed:
		return "runtime is bypassed - using CSS directly"
	default:
		return "unknown state"
	}
}

// countUnhealthyComponents counts components that are not healthy
func countUnhealthyComponents(health *RuntimeHealth) int {
	count := 0
	for _, component := range health.Components {
		if !component.Healthy {
			count++
		}
	}
	return count
}

// ShadowModeHandler returns an HTTP handler for shadow mode status
func (r *RuntimeHealth) ShadowModeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		health := r.GetHealth()

		// Check if any components are in shadow mode
		shadowComponents := []string{}
		for name, component := range health.Components {
			if component.State == HealthStateShadowOnly {
				shadowComponents = append(shadowComponents, name)
			}
		}

		isShadowMode := len(shadowComponents) > 0

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]interface{}{
			"shadow_mode":       isShadowMode,
			"overall_state":     health.OverallState,
			"shadow_components": shadowComponents,
			"timestamp":         health.Timestamp.Format(time.RFC3339),
			"explanation":       getShadowModeExplanation(health, shadowComponents),
		}

		json.NewEncoder(w).Encode(response)
	})
}

// getShadowModeExplanation returns an explanation of shadow mode status
func getShadowModeExplanation(health *RuntimeHealth, shadowComponents []string) string {
	if len(shadowComponents) == 0 {
		return "runtime is not in shadow mode"
	}

	if len(shadowComponents) == 1 {
		return fmt.Sprintf("only %s is in shadow mode", shadowComponents[0])
	}

	return fmt.Sprintf("%d components are in shadow mode: %v", len(shadowComponents), shadowComponents)
}

// EnforcementHandler returns an HTTP handler for enforcement status
func (r *RuntimeHealth) EnforcementHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		health := r.GetHealth()

		// Check enforcement status
		enforcingComponents := []string{}
		shadowComponents := []string{}

		for name, component := range health.Components {
			if component.State == HealthStateEnforcing {
				enforcingComponents = append(enforcingComponents, name)
			} else if component.State == HealthStateShadowOnly {
				shadowComponents = append(shadowComponents, name)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]interface{}{
			"enforcing":            len(enforcingComponents) > 0,
			"overall_state":        health.OverallState,
			"enforcing_components": enforcingComponents,
			"shadow_components":    shadowComponents,
			"timestamp":            health.Timestamp.Format(time.RFC3339),
			"enforcement_status":   getEnforcementStatus(health, enforcingComponents, shadowComponents),
		}

		json.NewEncoder(w).Encode(response)
	})
}

// getEnforcementStatus returns an explanation of enforcement status
func getEnforcementStatus(health *RuntimeHealth, enforcingComponents, shadowComponents []string) string {
	if health.OverallState == HealthStateEnforcing {
		if len(enforcingComponents) == 0 {
			return "runtime is configured for enforcement but no components are currently enforcing"
		}
		return fmt.Sprintf("runtime is enforcing policies (%d components)", len(enforcingComponents))
	}

	if health.OverallState == HealthStateShadowOnly {
		return fmt.Sprintf("runtime is in shadow mode (%d components)", len(shadowComponents))
	}

	if len(enforcingComponents) > 0 && len(shadowComponents) > 0 {
		return fmt.Sprintf("mixed mode: %d components enforcing, %d components in shadow",
			len(enforcingComponents), len(shadowComponents))
	}

	if len(enforcingComponents) > 0 {
		return fmt.Sprintf("%d components are enforcing policies", len(enforcingComponents))
	}

	if len(shadowComponents) > 0 {
		return fmt.Sprintf("%d components are in shadow mode", len(shadowComponents))
	}

	return "runtime is not enforcing any policies"
}
