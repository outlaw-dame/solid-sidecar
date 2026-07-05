// Package security provides threat modeling and security hardening for the Solid runtime.
// This file contains shared severity constants used throughout the security package.
package security

// Severity represents the severity level of an issue (invariant violation, vulnerability, etc.)
type Severity string

// Severity constants for classifying security issues
const (
	// SeverityCritical represents critical severity issues that must be addressed immediately
	SeverityCritical Severity = "critical"
	// SeverityHigh represents high severity issues that should be addressed urgently
	SeverityHigh Severity = "high"
	// SeverityMedium represents medium severity issues that should be addressed
	SeverityMedium Severity = "medium"
	// SeverityLow represents low severity issues that are nice to fix
	SeverityLow Severity = "low"
	// SeverityUnknown represents issues with unknown severity
	SeverityUnknown Severity = "unknown"
)

// InvariantSeverity is an alias for Severity for backward compatibility with existing code
type InvariantSeverity = Severity

// VulnerabilitySeverity is an alias for Severity for backward compatibility with existing code
type VulnerabilitySeverity = Severity
