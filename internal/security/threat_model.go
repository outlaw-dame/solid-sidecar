// Package security provides threat modeling and security hardening for the Solid runtime.
// This file implements Phase 26: Security audit and formal hardening - Complete threat model.
package security

import (
	"fmt"
	"strings"
	"time"
)

// ThreatModel represents a comprehensive threat model for a component
// Implements STRIDE methodology: Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege
type ThreatModel struct {
	// Component is the name of the component being modeled
	Component string

	// Description describes the component's purpose and boundaries
	Description string

	// Assets are the valuable resources protected by this component
	Assets []Asset

	// Threats are the identified threats using STRIDE methodology
	Threats []Threat

	// Mitigations are the security controls in place
	Mitigations []Mitigation

	// RiskAssessment is the current risk level
	RiskAssessment RiskAssessment

	// LastUpdated is when the threat model was last updated
	LastUpdated time.Time

	// Version is the version of this threat model
	Version string
}

// Asset represents a valuable resource that needs protection
type Asset struct {
	// Name is the name of the asset
	Name string

	// Description describes the asset
	Description string

	// Classification is the data classification level
	Classification DataClassification

	// Confidentiality is the confidentiality requirement
	Confidentiality ConfidentialityLevel

	// Integrity is the integrity requirement
	Integrity IntegrityLevel

	// Availability is the availability requirement
	Availability AvailabilityLevel
}

// DataClassification represents the classification level of data
type DataClassification string

const (
	ClassificationPublic       DataClassification = "public"
	ClassificationInternal     DataClassification = "internal"
	ClassificationConfidential DataClassification = "confidential"
	ClassificationRestricted   DataClassification = "restricted"
)

// ConfidentialityLevel represents confidentiality requirements
type ConfidentialityLevel string

const (
	ConfidentialityLow      ConfidentialityLevel = "low"
	ConfidentialityMedium   ConfidentialityLevel = "medium"
	ConfidentialityHigh     ConfidentialityLevel = "high"
	ConfidentialityCritical ConfidentialityLevel = "critical"
)

// IntegrityLevel represents integrity requirements
type IntegrityLevel string

const (
	IntegrityLow      IntegrityLevel = "low"
	IntegrityMedium   IntegrityLevel = "medium"
	IntegrityHigh     IntegrityLevel = "high"
	IntegrityCritical IntegrityLevel = "critical"
)

// AvailabilityLevel represents availability requirements
type AvailabilityLevel string

const (
	AvailabilityLow      AvailabilityLevel = "low"
	AvailabilityMedium   AvailabilityLevel = "medium"
	AvailabilityHigh     AvailabilityLevel = "high"
	AvailabilityCritical AvailabilityLevel = "critical"
)

// Threat represents an identified threat using STRIDE methodology
type Threat struct {
	// ID is a unique identifier for this threat
	ID string

	// Category is the STRIDE category
	Category STRIDECategory

	// Title is a short title for the threat
	Title string

	// Description describes the threat in detail
	Description string

	// Likelihood is the probability of this threat occurring
	Likelihood LikelihoodLevel

	// Impact is the potential impact if this threat is realized
	Impact ImpactLevel

	// AffectedAssets lists the assets affected by this threat
	AffectedAssets []string

	// AttackVectors describes how this threat could be exploited
	AttackVectors []AttackVector

	// References contains links to relevant standards or documentation
	References []string
}

// STRIDECategory represents the STRIDE threat category
type STRIDECategory string

const (
	STRIDESpoofing              STRIDECategory = "spoofing"
	STRIDETampering             STRIDECategory = "tampering"
	STRIDERepudiation           STRIDECategory = "repudiation"
	STRIDEInformationDisclosure STRIDECategory = "information_disclosure"
	STRIDEDenialOfService       STRIDECategory = "denial_of_service"
	STRIDEElevationOfPrivilege  STRIDECategory = "elevation_of_privilege"
)

// LikelihoodLevel represents the likelihood of a threat occurring
type LikelihoodLevel string

const (
	LikelihoodVeryLow  LikelihoodLevel = "very_low"
	LikelihoodLow      LikelihoodLevel = "low"
	LikelihoodMedium   LikelihoodLevel = "medium"
	LikelihoodHigh     LikelihoodLevel = "high"
	LikelihoodVeryHigh LikelihoodLevel = "very_high"
)

// ImpactLevel represents the impact level of a threat
type ImpactLevel string

const (
	ImpactVeryLow  ImpactLevel = "very_low"
	ImpactLow      ImpactLevel = "low"
	ImpactMedium   ImpactLevel = "medium"
	ImpactHigh     ImpactLevel = "high"
	ImpactVeryHigh ImpactLevel = "very_high"
)

// AttackVector represents a method by which a threat could be exploited
type AttackVector struct {
	// Description describes the attack vector
	Description string

	// Complexity is the complexity of executing this attack
	Complexity AttackComplexity

	// Requirements lists prerequisites for this attack
	Requirements []string

	// Example contains an example scenario
	Example string
}

// AttackComplexity represents the complexity of an attack
type AttackComplexity string

const (
	ComplexityVeryLow  AttackComplexity = "very_low"
	ComplexityLow      AttackComplexity = "low"
	ComplexityMedium   AttackComplexity = "medium"
	ComplexityHigh     AttackComplexity = "high"
	ComplexityVeryHigh AttackComplexity = "very_high"
)

// Mitigation represents a security control that mitigates one or more threats
type Mitigation struct {
	// ID is a unique identifier for this mitigation
	ID string

	// Title is a short title for the mitigation
	Title string

	// Description describes the mitigation in detail
	Description string

	// Type is the type of mitigation
	Type MitigationType

	// MitigatedThreats lists the threat IDs this mitigation addresses
	MitigatedThreats []string

	// ImplementationStatus is the current implementation status
	ImplementationStatus ImplementationStatus

	// Priority is the priority for implementing this mitigation
	Priority PriorityLevel

	// References contains links to relevant standards or documentation
	References []string
}

// MitigationType represents the type of security control
type MitigationType string

const (
	MitigationPreventive   MitigationType = "preventive"
	MitigationDetective    MitigationType = "detective"
	MitigationCorrective   MitigationType = "corrective"
	MitigationDeterrent    MitigationType = "deterrent"
	MitigationCompensating MitigationType = "compensating"
	MitigationPhysical     MitigationType = "physical"
)

// ImplementationStatus represents the current status of a mitigation
type ImplementationStatus string

const (
	StatusNotImplemented       ImplementationStatus = "not_implemented"
	StatusPartiallyImplemented ImplementationStatus = "partially_implemented"
	StatusImplemented          ImplementationStatus = "implemented"
	StatusTested               ImplementationStatus = "tested"
	StatusMonitored            ImplementationStatus = "monitored"
)

// PriorityLevel represents the priority level for implementing a mitigation
type PriorityLevel string

const (
	PriorityVeryLow  PriorityLevel = "very_low"
	PriorityLow      PriorityLevel = "low"
	PriorityMedium   PriorityLevel = "medium"
	PriorityHigh     PriorityLevel = "high"
	PriorityCritical PriorityLevel = "critical"
)

// RiskAssessment represents the overall risk assessment for a component
type RiskAssessment struct {
	// OverallRisk is the overall risk level
	OverallRisk RiskLevel

	// RiskByCategory breaks down risk by STRIDE category
	RiskByCategory map[STRIDECategory]RiskLevel

	// RiskMatrix provides a matrix of likelihood vs impact
	RiskMatrix map[LikelihoodLevel]map[ImpactLevel]int

	// HighRiskThreats lists threats with high or very high risk
	HighRiskThreats []string

	// Recommendations provides actionable security recommendations
	Recommendations []string
}

// RiskLevel represents the overall risk level
type RiskLevel string

const (
	RiskVeryLow  RiskLevel = "very_low"
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskVeryHigh RiskLevel = "very_high"
)

// AuthnThreatModel provides the threat model for authentication components
func AuthnThreatModel() *ThreatModel {
	return &ThreatModel{
		Component:   "Authentication (Authn)",
		Description: "Authentication components handle DPoP proof validation, JWT verification, WebID validation, and issuer trust. This is the first line of defense against unauthorized access.",
		Version:     "1.0",
		LastUpdated: time.Now(),

		Assets: []Asset{
			{
				Name:            "DPoP Proofs",
				Description:     "DPoP proof tokens containing client key binding information",
				Classification:  ClassificationConfidential,
				Confidentiality: ConfidentialityHigh,
				Integrity:       IntegrityCritical,
				Availability:    AvailabilityMedium,
			},
			{
				Name:            "JWT Tokens",
				Description:     "JSON Web Tokens containing identity claims and authorization information",
				Classification:  ClassificationConfidential,
				Confidentiality: ConfidentialityHigh,
				Integrity:       IntegrityCritical,
				Availability:    AvailabilityMedium,
			},
			{
				Name:            "WebID Profiles",
				Description:     "User profile data including public keys and identity information",
				Classification:  ClassificationInternal,
				Confidentiality: ConfidentialityMedium,
				Integrity:       IntegrityCritical,
				Availability:    AvailabilityHigh,
			},
			{
				Name:            "Issuer Metadata",
				Description:     "OIDC issuer metadata and configuration",
				Classification:  ClassificationInternal,
				Confidentiality: ConfidentialityMedium,
				Integrity:       IntegrityHigh,
				Availability:    AvailabilityHigh,
			},
			{
				Name:            "Session State",
				Description:     "Active authentication sessions and their state",
				Classification:  ClassificationConfidential,
				Confidentiality: ConfidentialityHigh,
				Integrity:       IntegrityCritical,
				Availability:    AvailabilityHigh,
			},
		},

		Threats: []Threat{
			// Spoofing threats
			{
				ID:             "AUTHN-001",
				Category:       STRIDESpoofing,
				Title:          "Token Spoofing",
				Description:    "An attacker presents a forged or stolen JWT token to impersonate a legitimate user.",
				Likelihood:     LikelihoodHigh,
				Impact:         ImpactVeryHigh,
				AffectedAssets: []string{"JWT Tokens", "Session State"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker steals a valid JWT token from a legitimate user",
						Complexity:   ComplexityLow,
						Requirements: []string{"Access to stolen token"},
						Example:      "Token stolen via XSS, MITM, or database compromise",
					},
					{
						Description:  "Attacker crafts a JWT token with forged claims",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Knowledge of signing algorithm", "Access to signing key or vulnerability"},
						Example:      "None algorithm attack, weak key exploitation",
					},
				},
				References: []string{"RFC 8725 (DPoP)", "RFC 7519 (JWT)", "OWASP JWT Cheat Sheet"},
			},
			{
				ID:             "AUTHN-002",
				Category:       STRIDESpoofing,
				Title:          "DPoP Proof Replay",
				Description:    "An attacker reuses a valid DPoP proof to bypass authentication.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactHigh,
				AffectedAssets: []string{"DPoP Proofs", "Session State"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker captures and replays a valid DPoP proof",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Access to network traffic", "Valid proof capture"},
						Example:      "Replay attack on captured DPoP proof",
					},
				},
				References: []string{"RFC 8725 Section 5.3 (Replay Prevention)"},
			},
			{
				ID:             "AUTHN-003",
				Category:       STRIDESpoofing,
				Title:          "WebID Spoofing",
				Description:    "An attacker claims a WebID that doesn't belong to them or manipulates WebID discovery.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactHigh,
				AffectedAssets: []string{"WebID Profiles"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker hosts a malicious WebID profile",
						Complexity:   ComplexityLow,
						Requirements: []string{"Control of a web server"},
						Example:      "Hosting a fake WebID profile at attacker-controlled domain",
					},
					{
						Description:  "Attacker manipulates WebID discovery to point to their profile",
						Complexity:   ComplexityMedium,
						Requirements: []string{"DNS manipulation", "HTTP redirection control"},
						Example:      "DNS poisoning to redirect WebID discovery",
					},
				},
				References: []string{"Solid-OIDC specification", "WebID specification"},
			},
			{
				ID:             "AUTHN-004",
				Category:       STRIDESpoofing,
				Title:          "Issuer Impersonation",
				Description:    "An attacker sets up a malicious OIDC issuer to issue fraudulent tokens.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactVeryHigh,
				AffectedAssets: []string{"Issuer Metadata", "JWT Tokens"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker hosts a malicious OIDC issuer",
						Complexity:   ComplexityLow,
						Requirements: []string{"Control of a web server", "OIDC implementation"},
						Example:      "Hosting malicious OIDC provider that issues arbitrary tokens",
					},
					{
						Description:  "Attacker manipulates issuer metadata discovery",
						Complexity:   ComplexityMedium,
						Requirements: []string{"DNS manipulation", "Well-known URL control"},
						Example:      "Redirecting issuer discovery to attacker-controlled endpoint",
					},
				},
				References: []string{"OpenID Connect Discovery 1.0", "RFC 8414 (OAuth 2.0 Authorization Server Metadata)"},
			},

			// Tampering threats
			{
				ID:             "AUTHN-010",
				Category:       STRIDETampering,
				Title:          "Token Tampering",
				Description:    "An attacker modifies a valid token to change its claims or extend its validity.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactHigh,
				AffectedAssets: []string{"JWT Tokens"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker modifies JWT payload without re-signing",
						Complexity:   ComplexityLow,
						Requirements: []string{"None algorithm", "Weak signature verification"},
						Example:      "Changing 'none' algorithm JWT payload",
					},
					{
						Description:  "Attacker exploits weak signing key",
						Complexity:   ComplexityHigh,
						Requirements: []string{"Key compromise", "Cryptographic weakness"},
						Example:      "Brute force attack on weak RSA key",
					},
				},
				References: []string{"JWT.io Security Considerations", "CWE-287: Improper Authentication"},
			},
			{
				ID:             "AUTHN-011",
				Category:       STRIDETampering,
				Title:          "DPoP Proof Tampering",
				Description:    "An attacker modifies a DPoP proof to change its nonce, timestamp, or other bound values.",
				Likelihood:     LikelihoodLow,
				Impact:         ImpactHigh,
				AffectedAssets: []string{"DPoP Proofs"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker modifies DPoP proof JWT claims",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Proof interception", "Signature compromise"},
						Example:      "Modifying nonce to bypass replay protection",
					},
				},
				References: []string{"RFC 8725 Section 4 (DPoP Proof JWT)"},
			},

			// Information Disclosure threats
			{
				ID:             "AUTHN-020",
				Category:       STRIDEInformationDisclosure,
				Title:          "Token Information Leakage",
				Description:    "JWT tokens or DPoP proofs contain sensitive information that could be leaked in logs or error messages.",
				Likelihood:     LikelihoodHigh,
				Impact:         ImpactHigh,
				AffectedAssets: []string{"JWT Tokens", "DPoP Proofs"},
				AttackVectors: []AttackVector{
					{
						Description:  "Tokens logged in server logs",
						Complexity:   ComplexityLow,
						Requirements: []string{"Debug logging enabled", "Token access"},
						Example:      "Access token logged in HTTP request debugging",
					},
					{
						Description:  "Tokens exposed in error messages",
						Complexity:   ComplexityLow,
						Requirements: []string{"Verbose error reporting"},
						Example:      "Invalid token error includes full token in response",
					},
				},
				References: []string{"OWASP Logging Cheat Sheet", "CWE-532: Insertion of Sensitive Information into Log File"},
			},
			{
				ID:             "AUTHN-021",
				Category:       STRIDEInformationDisclosure,
				Title:          "Timing Attacks",
				Description:    "Authentication operations leak information through timing differences.",
				Likelihood:     LikelihoodLow,
				Impact:         ImpactMedium,
				AffectedAssets: []string{"Session State"},
				AttackVectors: []AttackVector{
					{
						Description:  "Token validation time varies based on content",
						Complexity:   ComplexityHigh,
						Requirements: []string{"Precise timing measurement", "Network access"},
						Example:      "Measuring JWT signature verification time to infer key",
					},
				},
				References: []string{"CWE-208: Observable Timing Discrepancy"},
			},

			// Denial of Service threats
			{
				ID:             "AUTHN-030",
				Category:       STRIDEDenialOfService,
				Title:          "Token Flooding",
				Description:    "An attacker sends a large number of authentication requests to exhaust server resources.",
				Likelihood:     LikelihoodHigh,
				Impact:         ImpactHigh,
				AffectedAssets: []string{"Session State"},
				AttackVectors: []AttackVector{
					{
						Description:  "High volume of authentication requests",
						Complexity:   ComplexityLow,
						Requirements: []string{"Network access", "Botnet"},
						Example:      "DDoS attack with authentication requests",
					},
					{
						Description:  "Large JWT tokens",
						Complexity:   ComplexityLow,
						Requirements: []string{"Token size limit not enforced"},
						Example:      "Sending JWT with 1MB payload",
					},
				},
				References: []string{"OWASP DoS Cheat Sheet", "CWE-770: Allocation of Resources Without Limits"},
			},
			{
				ID:             "AUTHN-031",
				Category:       STRIDEDenialOfService,
				Title:          "Resource Exhaustion via DPoP Proofs",
				Description:    "An attacker sends DPoP proofs with expensive cryptographic operations to exhaust CPU resources.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactHigh,
				AffectedAssets: []string{"DPoP Proofs", "Session State"},
				AttackVectors: []AttackVector{
					{
						Description:  "DPoP proofs with large RSA keys",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Key size not limited"},
						Example:      "DPoP proof with 8192-bit RSA key",
					},
					{
						Description:  "Multiple nested JWTs",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Nested JWT support"},
						Example:      "JWT containing another JWT in payload",
					},
				},
				References: []string{"CWE-339: Small Key Space"},
			},

			// Repudiation threats
			{
				ID:             "AUTHN-040",
				Category:       STRIDERepudiation,
				Title:          "Lack of Non-Repudiation",
				Description:    "Users can deny having performed actions due to insufficient audit logging.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactMedium,
				AffectedAssets: []string{"Session State"},
				AttackVectors: []AttackVector{
					{
						Description:  "User denies performing an action",
						Complexity:   ComplexityLow,
						Requirements: []string{"Insufficient audit logs"},
						Example:      "User claims they didn't make a request that they did",
					},
				},
				References: []string{"CWE-284: Improper Access Control"},
			},

			// Elevation of Privilege threats
			{
				ID:             "AUTHN-050",
				Category:       STRIDEElevationOfPrivilege,
				Title:          "Privilege Escalation via Token Manipulation",
				Description:    "An attacker modifies a token to gain higher privileges than they should have.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactVeryHigh,
				AffectedAssets: []string{"JWT Tokens", "Session State"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker modifies scope or roles in JWT",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Weak signature", "Algorithm confusion"},
						Example:      "Changing 'user' scope to 'admin' in JWT",
					},
					{
						Description:  "Attacker uses a token from a privileged user",
						Complexity:   ComplexityLow,
						Requirements: []string{"Token theft"},
						Example:      "Using stolen admin token",
					},
				},
				References: []string{"CWE-269: Improper Privilege Management"},
			},
		},

		Mitigations: []Mitigation{
			// Preventive mitigations
			{
				ID:                   "AUTHN-MIT-001",
				Title:                "Strong Token Validation",
				Description:          "Implement strict JWT validation including signature verification, algorithm checking, and claim validation.",
				Type:                 MitigationPreventive,
				MitigatedThreats:     []string{"AUTHN-001", "AUTHN-010", "AUTHN-050"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityCritical,
				References:           []string{"RFC 7515 (JWS)", "RFC 7519 (JWT)"},
			},
			{
				ID:                   "AUTHN-MIT-002",
				Title:                "DPoP Proof Validation",
				Description:          "Validate DPoP proofs including nonce, timestamp freshness, and key binding to the access token.",
				Type:                 MitigationPreventive,
				MitigatedThreats:     []string{"AUTHN-002", "AUTHN-011"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityCritical,
				References:           []string{"RFC 8725 (DPoP)"},
			},
			{
				ID:                   "AUTHN-MIT-003",
				Title:                "Issuer Trust Validation",
				Description:          "Maintain a trusted issuer list and validate all tokens come from trusted issuers.",
				Type:                 MitigationPreventive,
				MitigatedThreats:     []string{"AUTHN-004"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityCritical,
				References:           []string{"OpenID Connect Discovery 1.0"},
			},
			{
				ID:                   "AUTHN-MIT-004",
				Title:                "WebID Ownership Verification",
				Description:          "Verify that the WebID in a token is actually owned by the presenting party through cryptographic proof.",
				Type:                 MitigationPreventive,
				MitigatedThreats:     []string{"AUTHN-003"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityHigh,
				References:           []string{"Solid-OIDC specification"},
			},

			// Detective mitigations
			{
				ID:                   "AUTHN-MIT-010",
				Title:                "Token Logging Redaction",
				Description:          "Ensure tokens, proofs, and sensitive claims are never logged in plaintext.",
				Type:                 MitigationDetective,
				MitigatedThreats:     []string{"AUTHN-020"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityCritical,
				References:           []string{"OWASP Logging Cheat Sheet"},
			},
			{
				ID:                   "AUTHN-MIT-011",
				Title:                "Anomaly Detection",
				Description:          "Monitor for unusual authentication patterns (high volume, failed attempts, etc.).",
				Type:                 MitigationDetective,
				MitigatedThreats:     []string{"AUTHN-030", "AUTHN-031"},
				ImplementationStatus: StatusPartiallyImplemented,
				Priority:             PriorityMedium,
				References:           []string{"OWASP Monitoring Cheat Sheet"},
			},

			// Corrective mitigations
			{
				ID:                   "AUTHN-MIT-020",
				Title:                "Rate Limiting",
				Description:          "Implement rate limiting on authentication endpoints to prevent DoS attacks.",
				Type:                 MitigationCorrective,
				MitigatedThreats:     []string{"AUTHN-030"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityHigh,
				References:           []string{"OWASP Rate Limiting Cheat Sheet"},
			},
			{
				ID:                   "AUTHN-MIT-021",
				Title:                "Audit Logging",
				Description:          "Maintain comprehensive audit logs of all authentication decisions with non-repudiable timestamps.",
				Type:                 MitigationCorrective,
				MitigatedThreats:     []string{"AUTHN-040"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityHigh,
				References:           []string{"CIS Controls v8"},
			},

			// Compensating mitigations
			{
				ID:                   "AUTHN-MIT-030",
				Title:                "Defense in Depth",
				Description:          "Multiple layers of authentication validation (DPoP + JWT + WebID + Issuer Trust).",
				Type:                 MitigationCompensating,
				MitigatedThreats:     []string{"AUTHN-001", "AUTHN-002", "AUTHN-003", "AUTHN-004"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityCritical,
				References:           []string{"NIST SP 800-53 (Defense in Depth)"},
			},
		},

		RiskAssessment: RiskAssessment{
			OverallRisk: RiskMedium,
			RiskByCategory: map[STRIDECategory]RiskLevel{
				STRIDESpoofing:              RiskMedium,
				STRIDETampering:             RiskMedium,
				STRIDEInformationDisclosure: RiskMedium,
				STRIDEDenialOfService:       RiskMedium,
				STRIDERepudiation:           RiskLow,
				STRIDEElevationOfPrivilege:  RiskHigh,
			},
			RiskMatrix: map[LikelihoodLevel]map[ImpactLevel]int{
				LikelihoodVeryLow: {
					ImpactVeryLow:  0,
					ImpactLow:      0,
					ImpactMedium:   0,
					ImpactHigh:     0,
					ImpactVeryHigh: 0,
				},
				LikelihoodLow: {
					ImpactVeryLow:  0,
					ImpactLow:      0,
					ImpactMedium:   1,
					ImpactHigh:     2,
					ImpactVeryHigh: 0,
				},
				LikelihoodMedium: {
					ImpactVeryLow:  0,
					ImpactLow:      0,
					ImpactMedium:   2,
					ImpactHigh:     3,
					ImpactVeryHigh: 1,
				},
				LikelihoodHigh: {
					ImpactVeryLow:  0,
					ImpactLow:      0,
					ImpactMedium:   0,
					ImpactHigh:     1,
					ImpactVeryHigh: 1,
				},
				LikelihoodVeryHigh: {
					ImpactVeryLow:  0,
					ImpactLow:      0,
					ImpactMedium:   0,
					ImpactHigh:     0,
					ImpactVeryHigh: 0,
				},
			},
			HighRiskThreats: []string{"AUTHN-001", "AUTHN-004", "AUTHN-020", "AUTHN-030", "AUTHN-050"},
			Recommendations: []string{
				"Implement token binding to DPoP proofs to prevent token theft",
				"Add WebID-to-Issuer mapping validation",
				"Implement constant-time token validation to prevent timing attacks",
				"Add anomaly detection for authentication patterns",
				"Regular security audits of authentication components",
			},
		},
	}
}

// AuthzThreatModel provides the threat model for authorization components
func AuthzThreatModel() *ThreatModel {
	return &ThreatModel{
		Component:   "Authorization (Authz)",
		Description: "Authorization components handle policy discovery, evaluation, and access control decisions based on WAC, ACP, and other authorization frameworks.",
		Version:     "1.0",
		LastUpdated: time.Now(),

		Assets: []Asset{
			{
				Name:            "Policy Documents",
				Description:     "WAC and ACP policy documents that define access control rules",
				Classification:  ClassificationConfidential,
				Confidentiality: ConfidentialityHigh,
				Integrity:       IntegrityCritical,
				Availability:    AvailabilityHigh,
			},
			{
				Name:            "Access Decisions",
				Description:     "The allow/deny decisions made by the authorization engine",
				Classification:  ClassificationInternal,
				Confidentiality: ConfidentialityMedium,
				Integrity:       IntegrityCritical,
				Availability:    AvailabilityCritical,
			},
			{
				Name:            "Policy Cache",
				Description:     "Cached policy documents and parsed representations",
				Classification:  ClassificationInternal,
				Confidentiality: ConfidentialityMedium,
				Integrity:       IntegrityHigh,
				Availability:    AvailabilityHigh,
			},
			{
				Name:            "Decision Cache",
				Description:     "Cached authorization decisions for performance",
				Classification:  ClassificationInternal,
				Confidentiality: ConfidentialityMedium,
				Integrity:       IntegrityHigh,
				Availability:    AvailabilityHigh,
			},
			{
				Name:            "Agent Identity",
				Description:     "Identity information for agents making requests",
				Classification:  ClassificationConfidential,
				Confidentiality: ConfidentialityHigh,
				Integrity:       IntegrityCritical,
				Availability:    AvailabilityMedium,
			},
		},

		Threats: []Threat{
			// Spoofing threats
			{
				ID:             "AUTHZ-001",
				Category:       STRIDESpoofing,
				Title:          "Agent Identity Spoofing",
				Description:    "An attacker presents a forged agent identity to bypass authorization checks.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactVeryHigh,
				AffectedAssets: []string{"Agent Identity", "Access Decisions"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker uses stolen or forged WebID",
						Complexity:   ComplexityLow,
						Requirements: []string{"Access to stolen WebID", "Token theft"},
						Example:      "Using stolen access token with different WebID",
					},
					{
						Description:  "Attacker forges WebID profile with malicious public keys",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Control of WebID hosting", "Knowledge of profile format"},
						Example:      "Hosting a WebID profile with attacker's public key",
					},
				},
				References: []string{"Solid-OIDC specification", "CWE-290: Authentication Bypass by Spoofing"},
			},

			// Tampering threats
			{
				ID:             "AUTHZ-010",
				Category:       STRIDETampering,
				Title:          "Policy Tampering",
				Description:    "An attacker modifies policy documents to grant themselves unauthorized access.",
				Likelihood:     LikelihoodHigh,
				Impact:         ImpactVeryHigh,
				AffectedAssets: []string{"Policy Documents", "Access Decisions"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker directly modifies policy files on server",
						Complexity:   ComplexityLow,
						Requirements: []string{"Server access", "File system write permissions"},
						Example:      "Modifying ACL file to grant admin access",
					},
					{
						Description:  "Attacker exploits weak policy storage to modify policies",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Weak access controls on policy storage"},
						Example:      "Exploiting misconfigured storage permissions",
					},
					{
						Description:  "Attacker performs MITM attack on policy retrieval",
						Complexity:   ComplexityHigh,
						Requirements: []string{"Network MITM capability", "No TLS"},
						Example:      "Modifying policies in transit",
					},
				},
				References: []string{"WAC specification", "ACP specification", "CWE-264: Permissions, Privileges, and Access Controls"},
			},
			{
				ID:             "AUTHZ-011",
				Category:       STRIDETampering,
				Title:          "Cache Poisoning",
				Description:    "An attacker poisons the policy or decision cache with malicious data.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactHigh,
				AffectedAssets: []string{"Policy Cache", "Decision Cache", "Access Decisions"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker causes cache to store malicious policy data",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Cache write access", "Policy modification capability"},
						Example:      "Cache poisoning through crafted requests",
					},
					{
						Description:  "Attacker exploits cache invalidation race conditions",
						Complexity:   ComplexityHigh,
						Requirements: []string{"Race condition vulnerability"},
						Example:      "TOCTOU attack on cache invalidation",
					},
				},
				References: []string{"CWE-441: Unintended Proxy or Intermediary (Cache Poisoning)"},
			},

			// Information Disclosure threats
			{
				ID:             "AUTHZ-020",
				Category:       STRIDEInformationDisclosure,
				Title:          "Policy Information Leakage",
				Description:    "Policy documents contain sensitive information that could be leaked.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactHigh,
				AffectedAssets: []string{"Policy Documents"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker enumerates all policies to understand access patterns",
						Complexity:   ComplexityLow,
						Requirements: []string{"Read access to policy storage", "No access controls on policy enumeration"},
						Example:      "Listing all ACL files to find weak policies",
					},
					{
						Description:  "Policy documents logged in error messages or debug output",
						Complexity:   ComplexityLow,
						Requirements: []string{"Verbose logging", "Debug mode enabled"},
						Example:      "Policy document content in error response",
					},
				},
				References: []string{"OWASP Information Exposure"},
			},
			{
				ID:             "AUTHZ-021",
				Category:       STRIDEInformationDisclosure,
				Title:          "Decision Information Leakage",
				Description:    "Authorization decisions leak information about resource existence or access patterns.",
				Likelihood:     LikelihoodHigh,
				Impact:         ImpactMedium,
				AffectedAssets: []string{"Access Decisions"},
				AttackVectors: []AttackVector{
					{
						Description:  "Detailed deny messages reveal resource existence or access requirements",
						Complexity:   ComplexityLow,
						Requirements: []string{"Verbose error messages"},
						Example:      "403 response includes policy details",
					},
					{
						Description:  "Timing differences reveal access decision results",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Precise timing measurement"},
						Example:      "Measuring time difference between allow and deny",
					},
				},
				References: []string{"CWE-209: Information Exposure Through Error Message"},
			},

			// Denial of Service threats
			{
				ID:             "AUTHZ-030",
				Category:       STRIDEDenialOfService,
				Title:          "Policy Evaluation DoS",
				Description:    "An attacker causes policy evaluation to consume excessive resources.",
				Likelihood:     LikelihoodHigh,
				Impact:         ImpactHigh,
				AffectedAssets: []string{"Policy Documents", "Access Decisions"},
				AttackVectors: []AttackVector{
					{
						Description:  "Complex policy documents with many rules and conditions",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Policy upload capability", "No complexity limits"},
						Example:      "Uploading a policy with 10,000 rules",
					},
					{
						Description:  "Recursive or circular policy references",
						Complexity:   ComplexityHigh,
						Requirements: []string{"Circular reference support", "No depth limits"},
						Example:      "Policy A references Policy B which references Policy A",
					},
					{
						Description:  "Policy evaluation on every request to expensive resources",
						Complexity:   ComplexityLow,
						Requirements: []string{"High request volume"},
						Example:      "DDoS attack triggering policy evaluation",
					},
				},
				References: []string{"CWE-770: Allocation of Resources Without Limits"},
			},

			// Repudiation threats
			{
				ID:             "AUTHZ-040",
				Category:       STRIDERepudiation,
				Title:          "Lack of Audit Trail",
				Description:    "Authorization decisions are not properly logged, making it difficult to audit access.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactMedium,
				AffectedAssets: []string{"Access Decisions"},
				AttackVectors: []AttackVector{
					{
						Description:  "User denies having accessed a resource",
						Complexity:   ComplexityLow,
						Requirements: []string{"Insufficient logging"},
						Example:      "No logs of who accessed a sensitive resource",
					},
				},
				References: []string{"CWE-778: Insufficient Logging"},
			},

			// Elevation of Privilege threats
			{
				ID:             "AUTHZ-050",
				Category:       STRIDEElevationOfPrivilege,
				Title:          "Policy Bypass",
				Description:    "An attacker finds a way to bypass authorization policies to access resources they shouldn't.",
				Likelihood:     LikelihoodHigh,
				Impact:         ImpactVeryHigh,
				AffectedAssets: []string{"Policy Documents", "Access Decisions"},
				AttackVectors: []AttackVector{
					{
						Description:  "Exploiting logic errors in policy evaluation",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Policy evaluation bugs"},
						Example:      "Policy allows access if (user == admin || user == user) where user is empty",
					},
					{
						Description:  "Exploiting precedence errors in multiple policies",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Multiple applicable policies", "Precedence logic bugs"},
						Example:      "Deny policy overridden by less restrictive allow policy",
					},
					{
						Description:  "Exploiting race conditions in policy updates",
						Complexity:   ComplexityHigh,
						Requirements: []string{"Concurrent policy updates", "TOCTOU vulnerability"},
						Example:      "Access granted between policy update and cache invalidation",
					},
				},
				References: []string{"CWE-264: Permissions, Privileges, and Access Controls"},
			},
			{
				ID:             "AUTHZ-051",
				Category:       STRIDEElevationOfPrivilege,
				Title:          "Privilege Escalation through Policy Manipulation",
				Description:    "An attacker manipulates policies to grant themselves higher privileges.",
				Likelihood:     LikelihoodMedium,
				Impact:         ImpactVeryHigh,
				AffectedAssets: []string{"Policy Documents", "Access Decisions"},
				AttackVectors: []AttackVector{
					{
						Description:  "Attacker modifies their own ACL to grant admin access",
						Complexity:   ComplexityMedium,
						Requirements: []string{"Policy write access", "Weak access controls on policy modification"},
						Example:      "User adds themselves to admin group in their ACL",
					},
				},
				References: []string{"CWE-269: Improper Privilege Management"},
			},
		},

		Mitigations: []Mitigation{
			// Preventive mitigations
			{
				ID:                   "AUTHZ-MIT-001",
				Title:                "Strict Policy Parsing",
				Description:          "Implement strict parsing of policy documents with validation of all fields and values.",
				Type:                 MitigationPreventive,
				MitigatedThreats:     []string{"AUTHZ-010", "AUTHZ-011", "AUTHZ-050", "AUTHZ-051"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityCritical,
				References:           []string{"WAC specification", "ACP specification"},
			},
			{
				ID:                   "AUTHZ-MIT-002",
				Title:                "Agent Identity Validation",
				Description:          "Validate that agent identities are cryptographically bound to the presenting party.",
				Type:                 MitigationPreventive,
				MitigatedThreats:     []string{"AUTHZ-001"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityCritical,
				References:           []string{"Solid-OIDC specification"},
			},
			{
				ID:                   "AUTHZ-MIT-003",
				Title:                "Policy Complexity Limits",
				Description:          "Enforce limits on policy complexity (max rules, max depth, etc.) to prevent DoS.",
				Type:                 MitigationPreventive,
				MitigatedThreats:     []string{"AUTHZ-030"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityHigh,
				References:           []string{"OWASP DoS Cheat Sheet"},
			},
			{
				ID:                   "AUTHZ-MIT-004",
				Title:                "Secure Policy Storage",
				Description:          "Store policies with proper access controls and integrity protection.",
				Type:                 MitigationPreventive,
				MitigatedThreats:     []string{"AUTHZ-010"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityHigh,
				References:           []string{"CIS Controls v8"},
			},

			// Detective mitigations
			{
				ID:                   "AUTHZ-MIT-010",
				Title:                "Policy Logging Redaction",
				Description:          "Ensure policy documents and sensitive policy data are never logged in plaintext.",
				Type:                 MitigationDetective,
				MitigatedThreats:     []string{"AUTHZ-020"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityHigh,
				References:           []string{"OWASP Logging Cheat Sheet"},
			},
			{
				ID:                   "AUTHZ-MIT-011",
				Title:                "Decision Logging Sanitization",
				Description:          "Sanitize authorization decision logs to prevent information leakage.",
				Type:                 MitigationDetective,
				MitigatedThreats:     []string{"AUTHZ-021"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityHigh,
				References:           []string{"OWASP Logging Cheat Sheet"},
			},

			// Corrective mitigations
			{
				ID:                   "AUTHZ-MIT-020",
				Title:                "Comprehensive Audit Logging",
				Description:          "Log all authorization decisions with sufficient detail for auditing.",
				Type:                 MitigationCorrective,
				MitigatedThreats:     []string{"AUTHZ-040"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityHigh,
				References:           []string{"CIS Controls v8"},
			},
			{
				ID:                   "AUTHZ-MIT-021",
				Title:                "Constant-Time Decision Making",
				Description:          "Ensure authorization decisions take consistent time regardless of result to prevent timing attacks.",
				Type:                 MitigationCorrective,
				MitigatedThreats:     []string{"AUTHZ-021"},
				ImplementationStatus: StatusPartiallyImplemented,
				Priority:             PriorityMedium,
				References:           []string{"CWE-208: Observable Timing Discrepancy"},
			},

			// Compensating mitigations
			{
				ID:                   "AUTHZ-MIT-030",
				Title:                "Defense in Depth",
				Description:          "Multiple layers of authorization validation (WAC + ACP + CSS comparison).",
				Type:                 MitigationCompensating,
				MitigatedThreats:     []string{"AUTHZ-050", "AUTHZ-051"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityCritical,
				References:           []string{"NIST SP 800-53 (Defense in Depth)"},
			},
			{
				ID:                   "AUTHZ-MIT-031",
				Title:                "Shadow Mode Evaluation",
				Description:          "Run authorization evaluation in shadow mode to compare with CSS before enforcement.",
				Type:                 MitigationCompensating,
				MitigatedThreats:     []string{"AUTHZ-050"},
				ImplementationStatus: StatusImplemented,
				Priority:             PriorityCritical,
				References:           []string{"Phase 3: Live policy discovery in shadow mode"},
			},
		},

		RiskAssessment: RiskAssessment{
			OverallRisk: RiskMedium,
			RiskByCategory: map[STRIDECategory]RiskLevel{
				STRIDESpoofing:              RiskMedium,
				STRIDETampering:             RiskHigh,
				STRIDEInformationDisclosure: RiskMedium,
				STRIDEDenialOfService:       RiskHigh,
				STRIDERepudiation:           RiskLow,
				STRIDEElevationOfPrivilege:  RiskHigh,
			},
			RiskMatrix: map[LikelihoodLevel]map[ImpactLevel]int{
				LikelihoodVeryLow: {
					ImpactVeryLow:  0,
					ImpactLow:      0,
					ImpactMedium:   0,
					ImpactHigh:     0,
					ImpactVeryHigh: 0,
				},
				LikelihoodLow: {
					ImpactVeryLow:  0,
					ImpactLow:      0,
					ImpactMedium:   1,
					ImpactHigh:     0,
					ImpactVeryHigh: 1,
				},
				LikelihoodMedium: {
					ImpactVeryLow:  0,
					ImpactLow:      0,
					ImpactMedium:   1,
					ImpactHigh:     2,
					ImpactVeryHigh: 2,
				},
				LikelihoodHigh: {
					ImpactVeryLow:  0,
					ImpactLow:      0,
					ImpactMedium:   0,
					ImpactHigh:     1,
					ImpactVeryHigh: 1,
				},
				LikelihoodVeryHigh: {
					ImpactVeryLow:  0,
					ImpactLow:      0,
					ImpactMedium:   0,
					ImpactHigh:     0,
					ImpactVeryHigh: 0,
				},
			},
			HighRiskThreats: []string{"AUTHZ-010", "AUTHZ-030", "AUTHZ-050", "AUTHZ-051"},
			Recommendations: []string{
				"Implement formal proof of policy equivalence between WAC and ACP",
				"Add automated testing for policy evaluation edge cases",
				"Implement policy versioning and rollback capabilities",
				"Add support for signed policies with integrity verification",
				"Regular security audits of authorization components",
			},
		},
	}
}

// GetThreatModel returns the threat model for a specific component
func GetThreatModel(component string) *ThreatModel {
	switch strings.ToLower(component) {
	case "authn", "authentication":
		return AuthnThreatModel()
	case "authz", "authorization":
		return AuthzThreatModel()
	default:
		return nil
	}
}

// GetAllThreatModels returns all available threat models
func GetAllThreatModels() []*ThreatModel {
	return []*ThreatModel{
		AuthnThreatModel(),
		AuthzThreatModel(),
		// Additional threat models would be added here
	}
}

// String returns a string representation of the threat model
func (tm *ThreatModel) String() string {
	return fmt.Sprintf("ThreatModel[%s v%s] - Risk: %s", tm.Component, tm.Version, tm.RiskAssessment.OverallRisk)
}
