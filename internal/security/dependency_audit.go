// Package security provides threat modeling and security hardening for the Solid runtime.
// This file implements Phase 26: Dependency audit and supply-chain policy.
package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// DependencyAudit provides dependency vulnerability scanning and SBOM generation
// for supply-chain security in the Solid runtime.
type DependencyAudit struct {
	mu sync.RWMutex

	// Config holds audit configuration
	config DependencyAuditConfig

	// KnownVulnerabilities holds cached vulnerability data
	knownVulnerabilities map[string][]Vulnerability

	// SBOM holds the current software bill of materials
	sbom *SBOM

	// Policy holds the supply-chain security policy
	policy SupplyChainPolicy

	// Logger for audit events (would use slog.Logger in real implementation)
	logger AuditLogger

	// LastScan holds the timestamp of the last scan
	lastScan time.Time

	// LastSBOMGeneration holds the timestamp of the last SBOM generation
	lastSBOMGeneration time.Time
}

// AuditLogger interface for logging audit events
type AuditLogger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// NoOpLogger is a no-op logger implementation
type NoOpLogger struct{}

func (n *NoOpLogger) Info(msg string, args ...any)  {}
func (n *NoOpLogger) Warn(msg string, args ...any)  {}
func (n *NoOpLogger) Error(msg string, args ...any) {}

// DependencyAuditConfig holds configuration for dependency auditing
type DependencyAuditConfig struct {
	// GoBinary is the path to the Go binary (defaults to "go")
	GoBinary string

	// GoModPath is the path to the go.mod file (defaults to "./go.mod")
	GoModPath string

	// VulnerabilityDatabases is a list of vulnerability databases to check
	// Supported: "OSV", "NVD", "GitHub", "GoVuln"
	VulnerabilityDatabases []string

	// SBOMFormats is a list of SBOM formats to generate
	// Supported: "SPDX", "CycloneDX", "SWID"
	SBOMFormats []string

	// MaxConcurrentScans is the maximum number of concurrent dependency scans
	MaxConcurrentScans int

	// ScanTimeout is the timeout for individual dependency scans
	ScanTimeout time.Duration

	// OfflineMode enables offline scanning (uses cached vulnerability data)
	OfflineMode bool

	// CacheDir is the directory for caching vulnerability databases
	CacheDir string

	// FailOnCritical fails the audit if critical vulnerabilities are found
	FailOnCritical bool

	// FailOnHigh fails the audit if high vulnerabilities are found
	FailOnHigh bool

	// IgnorePattern is a regex pattern for dependencies to ignore
	IgnorePattern *regexp.Regexp

	// AllowList is a list of known-safe dependency patterns
	AllowList []string
}

// DefaultDependencyAuditConfig returns a safe default configuration
func DefaultDependencyAuditConfig() DependencyAuditConfig {
	return DependencyAuditConfig{
		GoBinary:               "go",
		GoModPath:              "./go.mod",
		VulnerabilityDatabases: []string{"OSV", "GoVuln", "GitHub"},
		SBOMFormats:            []string{"SPDX", "CycloneDX"},
		MaxConcurrentScans:     4,
		ScanTimeout:            30 * time.Second,
		OfflineMode:            false,
		CacheDir:               "./.cache/security",
		FailOnCritical:         true,
		FailOnHigh:             false,
		IgnorePattern:          nil,
		AllowList:              []string{},
	}
}

// Vulnerability represents a known vulnerability in a dependency
type Vulnerability struct {
	// ID is the vulnerability identifier (e.g., "CVE-2023-1234", "GO-2023-1234")
	ID string

	// Summary is a brief description of the vulnerability
	Summary string

	// Details contains detailed information about the vulnerability
	Details string

	// Severity is the severity level of the vulnerability
	Severity VulnerabilitySeverity

	// CVSSScore is the CVSS score (0.0 - 10.0)
	CVSSScore float64

	// CVSSVector is the CVSS vector string
	CVSSVector string

	// AffectedVersions is a list of affected version ranges
	AffectedVersions []VersionRange

	// FixedVersion is the version that fixes the vulnerability (if any)
	FixedVersion string

	// References contains links to vulnerability references
	References []string

	// PublishedAt is when the vulnerability was published
	PublishedAt time.Time

	// ModifiedAt is when the vulnerability was last modified
	ModifiedAt time.Time

	// Source is the source of the vulnerability data
	Source string
}

// VersionRange represents a range of affected versions
type VersionRange struct {
	// Start is the start of the range (exclusive, empty means unbounded)
	Start string

	// End is the end of the range (inclusive, empty means unbounded)
	End string

	// IntroducedIn is the version where the vulnerability was introduced
	IntroducedIn string

	// FixedIn is the version where the vulnerability was fixed
	FixedIn string
}

// Dependency represents a project dependency
type Dependency struct {
	// Name is the module name (e.g., "github.com/gorilla/mux")
	Name string

	// Version is the version of the dependency
	Version string

	// Indirect indicates if this is an indirect dependency
	Indirect bool

	// Sum is the checksum from go.sum
	Sum string

	// License is the detected license (if any)
	License string

	// Homepage is the project homepage (if known)
	Homepage string

	// Description is the project description (if known)
	Description string

	// Vulnerabilities contains vulnerabilities affecting this dependency
	Vulnerabilities []Vulnerability
}

// NewDependencyAudit creates a new dependency audit instance
func NewDependencyAudit(config DependencyAuditConfig, logger AuditLogger) (*DependencyAudit, error) {
	if logger == nil {
		logger = &NoOpLogger{}
	}

	audit := &DependencyAudit{
		config:               config,
		knownVulnerabilities: make(map[string][]Vulnerability),
		sbom:                 nil,
		policy:               DefaultSupplyChainPolicy(),
		logger:               logger,
	}

	// Initialize cache directory
	if err := audit.initializeCache(); err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Load known vulnerabilities from cache
	if err := audit.loadCachedVulnerabilities(); err != nil {
		logger.Warn("Failed to load cached vulnerabilities", "error", err)
	}

	return audit, nil
}

// initializeCache initializes the cache directory for vulnerability data
func (a *DependencyAudit) initializeCache() error {
	if a.config.CacheDir == "" {
		return nil
	}

	if err := os.MkdirAll(a.config.CacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	return nil
}

// loadCachedVulnerabilities loads known vulnerabilities from the cache
func (a *DependencyAudit) loadCachedVulnerabilities() error {
	if a.config.CacheDir == "" {
		return nil
	}

	cacheFile := filepath.Join(a.config.CacheDir, "vulnerabilities.json")
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // Cache doesn't exist yet
		}
		return fmt.Errorf("failed to read cache file: %w", err)
	}

	var cached map[string][]Vulnerability
	if err := json.Unmarshal(data, &cached); err != nil {
		return fmt.Errorf("failed to parse cached vulnerabilities: %w", err)
	}

	a.mu.Lock()
	a.knownVulnerabilities = cached
	a.mu.Unlock()

	return nil
}

// saveCachedVulnerabilities saves known vulnerabilities to the cache
func (a *DependencyAudit) saveCachedVulnerabilities() error {
	if a.config.CacheDir == "" {
		return nil
	}

	a.mu.RLock()
	cached := a.knownVulnerabilities
	a.mu.RUnlock()

	cacheFile := filepath.Join(a.config.CacheDir, "vulnerabilities.json")
	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerabilities: %w", err)
	}

	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

// ScanDependencies scans project dependencies for vulnerabilities
func (a *DependencyAudit) ScanDependencies(ctx context.Context) ([]Dependency, error) {
	// First, get the dependency list
	deps, err := a.getDependencies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get dependencies: %w", err)
	}

	// Check for vulnerabilities in each dependency
	var wg sync.WaitGroup
	scanChan := make(chan Dependency, a.config.MaxConcurrentScans)
	resultChan := make(chan Dependency, len(deps))

	// Start worker goroutines
	for i := 0; i < a.config.MaxConcurrentScans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dep := range scanChan {
				checkedDep := a.checkDependencyVulnerabilities(dep)
				resultChan <- checkedDep
			}
		}()
	}

	// Send dependencies to workers
	go func() {
		for _, dep := range deps {
			scanChan <- dep
		}
		close(scanChan)
	}()

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var results []Dependency
	for result := range resultChan {
		results = append(results, result)
	}

	// Sort by name for deterministic output
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	a.lastScan = time.Now()

	return results, nil
}

// getDependencies retrieves the project dependencies using go list
func (a *DependencyAudit) getDependencies(ctx context.Context) ([]Dependency, error) {
	cmd := exec.CommandContext(ctx, a.config.GoBinary, "list", "-m", "-json", "all")
	cmd.Dir = filepath.Dir(a.config.GoModPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list dependencies: %w (output: %s)", err, string(output))
	}

	return a.parseDependencyOutput(output)
}

// parseDependencyOutput parses the JSON output from go list -m -json
func (a *DependencyAudit) parseDependencyOutput(output []byte) ([]Dependency, error) {
	var deps []Dependency
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		var dep struct {
			Path     string `json:"Path"`
			Version  string `json:"Version"`
			Indirect bool   `json:"Indirect"`
			Sum      string `json:"Sum"`
			Dir      string `json:"Dir"`
		}

		if err := json.Unmarshal([]byte(line), &dep); err != nil {
			// Try to handle potential malformed lines
			continue
		}

		// Skip if ignored
		if a.config.IgnorePattern != nil && a.config.IgnorePattern.MatchString(dep.Path) {
			continue
		}

		// Check allow list
		if a.isInAllowList(dep.Path) {
			continue
		}

		deps = append(deps, Dependency{
			Name:     dep.Path,
			Version:  dep.Version,
			Indirect: dep.Indirect,
			Sum:      dep.Sum,
		})
	}

	return deps, nil
}

// isInAllowList checks if a dependency is in the allow list
func (a *DependencyAudit) isInAllowList(path string) bool {
	for _, pattern := range a.config.AllowList {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

// checkDependencyVulnerabilities checks a single dependency for known vulnerabilities
func (a *DependencyAudit) checkDependencyVulnerabilities(dep Dependency) Dependency {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Check against known vulnerabilities
	for vulnID, vulns := range a.knownVulnerabilities {
		for _, vuln := range vulns {
			if a.vulnerabilityAffectsDependency(vuln, dep) {
				dep.Vulnerabilities = append(dep.Vulnerabilities, vuln)
				// Add source reference
				vulnCopy := vuln
				vulnCopy.Source = vulnID
				dep.Vulnerabilities[len(dep.Vulnerabilities)-1] = vulnCopy
			}
		}
	}

	return dep
}

// vulnerabilityAffectsDependency checks if a vulnerability affects a specific dependency
func (a *DependencyAudit) vulnerabilityAffectsDependency(vuln Vulnerability, dep Dependency) bool {
	// Check if the vulnerability affects this module
	for _, rangeSpec := range vuln.AffectedVersions {
		if a.versionInRange(dep.Version, rangeSpec) {
			return true
		}
	}

	return false
}

// versionInRange checks if a version is in a given range
func (a *DependencyAudit) versionInRange(version string, rangeSpec VersionRange) bool {
	// Implement version comparison logic
	// This is a simplified implementation

	// If no start, assume version 0
	if rangeSpec.Start == "" {
		// Version is >= start
		return version >= rangeSpec.End
	}

	if rangeSpec.End == "" {
		// Version is <= end (unbounded)
		return true
	}

	// Simple string comparison (would use semantic versioning in production)
	return version >= rangeSpec.Start && version <= rangeSpec.End
}

// UpdateVulnerabilityDatabase updates the vulnerability database from configured sources
func (a *DependencyAudit) UpdateVulnerabilityDatabase(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(a.config.VulnerabilityDatabases))

	for _, db := range a.config.VulnerabilityDatabases {
		wg.Add(1)
		go func(database string) {
			defer wg.Done()
			if err := a.updateFromSource(ctx, database); err != nil {
				errChan <- fmt.Errorf("%s: %w", database, err)
			}
		}(db)
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		// Save what we have
		if err := a.saveCachedVulnerabilities(); err != nil {
			a.logger.Warn("Failed to save vulnerabilities", "error", err)
		}
		return fmt.Errorf("errors updating vulnerability databases: %v", errors)
	}

	// Save updated vulnerabilities
	return a.saveCachedVulnerabilities()
}

// updateFromSource updates vulnerabilities from a specific source
func (a *DependencyAudit) updateFromSource(ctx context.Context, source string) error {
	switch strings.ToUpper(source) {
	case "OSV":
		return a.updateFromOSV(ctx)
	case "NVD":
		return a.updateFromNVD(ctx)
	case "GITHUB":
		return a.updateFromGitHub(ctx)
	case "GOVULN":
		return a.updateFromGoVuln(ctx)
	default:
		return fmt.Errorf("unknown vulnerability source: %s", source)
	}
}

// updateFromOSV updates vulnerabilities from OSV.dev
func (a *DependencyAudit) updateFromOSV(ctx context.Context) error {
	// OSV.dev API endpoint for Go vulnerabilities
	// This would make an HTTP request to OSV.dev
	// For now, we'll simulate with a placeholder
	a.logger.Info("Updating vulnerabilities from OSV.dev")

	// Placeholder: In real implementation, we would:
	// 1. Query OSV.dev API for Go ecosystem vulnerabilities
	// 2. Parse the response
	// 3. Update knownVulnerabilities map

	return nil
}

// updateFromNVD updates vulnerabilities from NVD
func (a *DependencyAudit) updateFromNVD(ctx context.Context) error {
	a.logger.Info("Updating vulnerabilities from NVD")
	// Placeholder implementation
	return nil
}

// updateFromGitHub updates vulnerabilities from GitHub Advisory Database
func (a *DependencyAudit) updateFromGitHub(ctx context.Context) error {
	a.logger.Info("Updating vulnerabilities from GitHub Advisory Database")
	// Placeholder implementation
	return nil
}

// updateFromGoVuln updates vulnerabilities from Go Vulnerability Database
func (a *DependencyAudit) updateFromGoVuln(ctx context.Context) error {
	// Use go vuln command if available
	cmd := exec.CommandContext(ctx, a.config.GoBinary, "vuln", "check", "-json", "-mode=mod")
	cmd.Dir = filepath.Dir(a.config.GoModPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// go vuln might not be available
		a.logger.Warn("go vuln command not available", "error", err)
		return nil
	}

	// Parse output
	var results []struct {
		VulnID    string  `json:"ID"`
		Summary   string  `json:"Summary"`
		Severity  string  `json:"Severity"`
		CVSSScore float64 `json:"CVSSScore"`
		Module    string  `json:"Module"`
		Version   string  `json:"Version"`
	}

	if err := json.Unmarshal(output, &results); err != nil {
		return fmt.Errorf("failed to parse go vuln output: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, result := range results {
		vuln := Vulnerability{
			ID:        result.VulnID,
			Summary:   result.Summary,
			Severity:  VulnerabilitySeverity(result.Severity),
			CVSSScore: result.CVSSScore,
			AffectedVersions: []VersionRange{
				{
					FixedIn: result.Version,
				},
			},
			Source: "go-vuln",
		}

		if _, exists := a.knownVulnerabilities[result.Module]; !exists {
			a.knownVulnerabilities[result.Module] = []Vulnerability{vuln}
		} else {
			a.knownVulnerabilities[result.Module] = append(a.knownVulnerabilities[result.Module], vuln)
		}
	}

	return nil
}

// SBOM represents a Software Bill of Materials
type SBOM struct {
	// ID is a unique identifier for this SBOM
	ID string

	// Name is the name of the project
	Name string

	// Version is the version of the project
	Version string

	// Format is the SBOM format (SPDX, CycloneDX, SWID)
	Format string

	// GeneratedAt is when the SBOM was generated
	GeneratedAt time.Time

	// Components is a list of all components in the project
	Components []SBOMComponent

	// Relationships describes relationships between components
	Relationships []SBOMRelationship

	// Metadata contains additional SBOM metadata
	Metadata SBOMMetadata
}

// SBOMComponent represents a component in the SBOM
type SBOMComponent struct {
	// ID is a unique identifier for this component
	ID string

	// Name is the name of the component
	Name string

	// Version is the version of the component
	Version string

	// Type is the type of component (library, framework, application, etc.)
	Type string

	// License is the license of the component
	License string

	// Licenses is a list of all licenses (for SPDX)
	Licenses []string

	// PURL is the Package URL for the component
	PURL string

	// Description is a description of the component
	Description string

	// Homepage is the homepage URL for the component
	Homepage string

	// Supplier is the supplier of the component
	Supplier string

	// ExternalReferences contains external references
	ExternalReferences []SBOMExternalReference

	// Vulnerabilities contains known vulnerabilities for this component
	Vulnerabilities []Vulnerability

	// Checksums contains checksums for the component
	Checksums map[string]string
}

// SBOMExternalReference represents an external reference for a component
type SBOMExternalReference struct {
	// Category is the category of the reference
	Category string

	// Type is the type of the reference
	Type string

	// Locale is the locale of the reference
	Locale string

	// Value is the value of the reference
	Value string
}

// SBOMRelationship represents a relationship between components
type SBOMRelationship struct {
	// From is the source component ID
	From string

	// To is the target component ID
	To string

	// RelationshipType is the type of relationship
	RelationshipType string
}

// SBOMMetadata contains SBOM metadata
type SBOMMetadata struct {
	// Tools contains information about the tools used to generate the SBOM
	Tools []SBOMTool

	// CreationInfo contains information about the SBOM creation
	CreationInfo SBOMCreationInfo
}

// SBOMTool represents a tool used to generate the SBOM
type SBOMTool struct {
	// Name is the name of the tool
	Name string

	// Version is the version of the tool
	Version string

	// Vendor is the vendor of the tool
	Vendor string
}

// SBOMCreationInfo contains information about the SBOM creation
type SBOMCreationInfo struct {
	// Created is when the SBOM was created
	Created time.Time

	// Creators contains information about the creators
	Creators []string

	// LicenseListVersion is the version of the license list used
	LicenseListVersion string
}

// GenerateSBOM generates an SBOM for the project
func (a *DependencyAudit) GenerateSBOM(ctx context.Context, format string) (*SBOM, error) {
	// Get dependencies
	deps, err := a.ScanDependencies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to scan dependencies: %w", err)
	}

	// Create SBOM components from dependencies
	var components []SBOMComponent
	for _, dep := range deps {
		component := SBOMComponent{
			ID:              fmt.Sprintf("pkg:golang/%s@%s", dep.Name, dep.Version),
			Name:            dep.Name,
			Version:         dep.Version,
			Type:            "library",
			PURL:            fmt.Sprintf("pkg:golang/%s@%s", dep.Name, dep.Version),
			Vulnerabilities: dep.Vulnerabilities,
			Checksums: map[string]string{
				"sha256": dep.Sum,
			},
		}

		// Try to get license information
		if license := a.getLicenseForDependency(dep.Name); license != "" {
			component.License = license
			component.Licenses = []string{license}
		}

		components = append(components, component)
	}

	// Create SBOM
	sbom := &SBOM{
		ID:          fmt.Sprintf("sbom-%s-%d", a.config.GoModPath, time.Now().Unix()),
		Name:        filepath.Base(filepath.Dir(a.config.GoModPath)),
		Version:     "0.0.0", // Would be read from go.mod
		Format:      format,
		GeneratedAt: time.Now(),
		Components:  components,
		Metadata: SBOMMetadata{
			Tools: []SBOMTool{
				{
					Name:    "solid-sidecar",
					Version: "0.0.0",
					Vendor:  "Solid Sidecar",
				},
			},
			CreationInfo: SBOMCreationInfo{
				Created:  time.Now(),
				Creators: []string{"solid-sidecar"},
			},
		},
	}

	a.sbom = sbom
	a.lastSBOMGeneration = time.Now()

	return sbom, nil
}

// getLicenseForDependency attempts to get license information for a dependency
func (a *DependencyAudit) getLicenseForDependency(module string) string {
	// Try to read from go.mod or other sources
	// This is a simplified implementation

	// Common Go module licenses
	licenseMap := map[string]string{
		"github.com/stretchr/testify":         "MIT",
		"github.com/gorilla/mux":              "BSD-3-Clause",
		"golang.org/x/crypto":                 "BSD-3-Clause",
		"github.com/aws/aws-sdk-go-v2":        "Apache-2.0",
		"github.com/pkg/sftp":                 "BSD-2-Clause",
		"golang.org/x/oauth2":                 "BSD-3-Clause",
		"github.com/google/uuid":              "BSD-3-Clause",
		"github.com/prometheus/client_golang": "Apache-2.0",
	}

	if license, ok := licenseMap[module]; ok {
		return license
	}

	return "UNKNOWN"
}

// ExportSBOM exports the SBOM to a file in the specified format
func (a *DependencyAudit) ExportSBOM(ctx context.Context, format, outputPath string) error {
	sbom, err := a.GenerateSBOM(ctx, format)
	if err != nil {
		return fmt.Errorf("failed to generate SBOM: %w", err)
	}

	var data []byte
	switch strings.ToUpper(format) {
	case "SPDX":
		data, err = a.exportSPDX(sbom)
	case "CYCLONEDX":
		data, err = a.exportCycloneDX(sbom)
	case "SWID":
		data, err = a.exportSWID(sbom)
	default:
		return fmt.Errorf("unsupported SBOM format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to export SBOM: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write SBOM file: %w", err)
	}

	a.logger.Info("SBOM exported", "format", format, "path", outputPath, "components", len(sbom.Components))

	return nil
}

// exportSPDX exports the SBOM in SPDX format
func (a *DependencyAudit) exportSPDX(sbom *SBOM) ([]byte, error) {
	// SPDX format implementation
	// This is a simplified implementation

	var sb strings.Builder
	sb.WriteString("SPDXVersion: SPDX-2.3\n")
	sb.WriteString(fmt.Sprintf("DataLicense: CC0-1.0\n"))
	sb.WriteString(fmt.Sprintf("SPDXID: SPDXRef-DOCUMENT\n"))
	sb.WriteString(fmt.Sprintf("DocumentName: %s\n", sbom.Name))
	sb.WriteString(fmt.Sprintf("DocumentNamespace: https://spdx.org/spdxdocs/%s\n", sbom.ID))
	sb.WriteString(fmt.Sprintf("CreationInfo: Created: %s\n", sbom.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString("\n")

	// Write package information
	for i, comp := range sbom.Components {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i)
		sb.WriteString(fmt.Sprintf("Package: %s\n", comp.Name))
		sb.WriteString(fmt.Sprintf("SPDXID: %s\n", spdxID))
		sb.WriteString(fmt.Sprintf("PackageVersion: %s\n", comp.Version))
		sb.WriteString(fmt.Sprintf("PackageDownloadLocation: NOASSERTION\n"))
		sb.WriteString(fmt.Sprintf("FilesAnalyzed: false\n"))
		if comp.License != "" {
			sb.WriteString(fmt.Sprintf("PackageLicenseConcluded: %s\n", comp.License))
			sb.WriteString(fmt.Sprintf("PackageLicenseDeclared: %s\n", comp.License))
		} else {
			sb.WriteString("PackageLicenseConcluded: NOASSERTION\n")
			sb.WriteString("PackageLicenseDeclared: NOASSERTION\n")
		}
		sb.WriteString(fmt.Sprintf("PackageCopyrightText: NOASSERTION\n"))
		sb.WriteString(fmt.Sprintf("ExternalRef: PACKAGE-MANAGER purl %s\n", comp.PURL))
		sb.WriteString("\n")
	}

	return []byte(sb.String()), nil
}

// exportCycloneDX exports the SBOM in CycloneDX format
func (a *DependencyAudit) exportCycloneDX(sbom *SBOM) ([]byte, error) {
	// CycloneDX format implementation
	// Define types in dependency order (no forward references)
	type LicenseRef struct {
		License struct {
			ID string `json:"id"`
		} `json:"license"`
	}

	type ExternalRef struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}

	type Tool struct {
		Vendor  string `json:"vendor"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	type Component struct {
		Type               string        `json:"type"`
		BOMRef             string        `json:"bom-ref"`
		Name               string        `json:"name"`
		Version            string        `json:"version"`
		PURL               string        `json:"purl"`
		Licenses           []LicenseRef  `json:"licenses"`
		ExternalReferences []ExternalRef `json:"externalReferences"`
	}

	type DependencyRef struct {
		Ref string `json:"ref"`
	}

	type Metadata struct {
		Timestamp string    `json:"timestamp"`
		Tools     []Tool    `json:"tools"`
		Component Component `json:"component"`
	}

	type CycloneDXSBOM struct {
		BOMFormat    string          `json:"bomFormat"`
		SpecVersion  string          `json:"specVersion"`
		Version      int             `json:"version"`
		Metadata     Metadata        `json:"metadata"`
		Components   []Component     `json:"components"`
		Dependencies []DependencyRef `json:"dependencies"`
	}

	cdx := CycloneDXSBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
		Metadata: Metadata{
			Timestamp: sbom.GeneratedAt.Format(time.RFC3339),
			Tools: []Tool{
				{Vendor: "Solid Sidecar", Name: "solid-sidecar", Version: "0.0.0"},
			},
			Component: Component{
				Type:    "application",
				BOMRef:  "root",
				Name:    sbom.Name,
				Version: sbom.Version,
			},
		},
	}

	for i, comp := range sbom.Components {
		component := Component{
			Type:    "library",
			BOMRef:  fmt.Sprintf("pkg-%d", i),
			Name:    comp.Name,
			Version: comp.Version,
			PURL:    comp.PURL,
		}

		if comp.License != "" && comp.License != "UNKNOWN" {
			component.Licenses = []LicenseRef{
				{License: struct {
					ID string `json:"id"`
				}{ID: comp.License}},
			}
		}

		component.ExternalReferences = []ExternalRef{
			{Type: "website", URL: comp.Homepage},
		}

		cdx.Components = append(cdx.Components, component)
	}

	return json.MarshalIndent(cdx, "", "  ")
}

// exportSWID exports the SBOM in SWID format
func (a *DependencyAudit) exportSWID(sbom *SBOM) ([]byte, error) {
	// SWID format implementation
	// This is a simplified implementation

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"))
	sb.WriteString(fmt.Sprintf("<SoftwareIdentity name=\"%s\" version=\"%s\" versionScheme=\"semver\">\n", sbom.Name, sbom.Version))
	sb.WriteString(fmt.Sprintf("  <Meta tagName=\"created\" tagValue=\"%s\"/>\n", sbom.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString("  <Entities>\n")

	for i, comp := range sbom.Components {
		sb.WriteString(fmt.Sprintf("    <Entity name=\"%s\" regid=\"%s\" role=\"component\">\n", comp.Name, comp.ID))
		sb.WriteString(fmt.Sprintf("      <Meta tagName=\"version\" tagValue=\"%s\"/>\n", comp.Version))
		if comp.PURL != "" {
			sb.WriteString(fmt.Sprintf("      <Meta tagName=\"purl\" tagValue=\"%s\"/>\n", comp.PURL))
		}
		if comp.License != "" {
			sb.WriteString(fmt.Sprintf("      <Meta tagName=\"license\" tagValue=\"%s\"/>\n", comp.License))
		}
		sb.WriteString("    </Entity>\n")
		_ = i // Avoid unused variable
	}

	sb.WriteString("  </Entities>\n")
	sb.WriteString("</SoftwareIdentity>\n")

	return []byte(sb.String()), nil
}

// GetAuditSummary returns a summary of the current audit state
func (a *DependencyAudit) GetAuditSummary() DependencyAuditSummary {
	a.mu.RLock()
	defer a.mu.RUnlock()

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, vulns := range a.knownVulnerabilities {
		for _, vuln := range vulns {
			switch vuln.Severity {
			case SeverityCritical:
				criticalCount++
			case SeverityHigh:
				highCount++
			case SeverityMedium:
				mediumCount++
			case SeverityLow:
				lowCount++
			}
		}
	}

	return DependencyAuditSummary{
		LastScan:                a.lastScan,
		LastSBOMGeneration:      a.lastSBOMGeneration,
		KnownVulnerabilities:    len(a.knownVulnerabilities),
		CriticalVulnerabilities: criticalCount,
		HighVulnerabilities:     highCount,
		MediumVulnerabilities:   mediumCount,
		LowVulnerabilities:      lowCount,
		SBOMComponents:          len(a.sbom.Components) / len(a.config.SBOMFormats),
	}
}

// DependencyAuditSummary contains a summary of the dependency audit state
type DependencyAuditSummary struct {
	LastScan                time.Time
	LastSBOMGeneration      time.Time
	KnownVulnerabilities    int
	CriticalVulnerabilities int
	HighVulnerabilities     int
	MediumVulnerabilities   int
	LowVulnerabilities      int
	SBOMComponents          int
}

// SupplyChainPolicy defines supply-chain security policies
type SupplyChainPolicy struct {
	// AllowedLicenses is a list of allowed licenses
	AllowedLicenses []string

	// ForbiddenLicenses is a list of forbidden licenses
	ForbiddenLicenses []string

	// AllowedLicenseCategories is a list of allowed license categories
	AllowedLicenseCategories []LicenseCategory

	// MaximumSeverity is the maximum allowed vulnerability severity
	MaximumSeverity VulnerabilitySeverity

	// MaximumCVSSScore is the maximum allowed CVSS score
	MaximumCVSSScore float64

	// RequireSBOMGeneration requires SBOM generation
	RequireSBOMGeneration bool

	// RequireVulnerabilityScanning requires vulnerability scanning
	RequireVulnerabilityScanning bool

	// RequireSignatureVerification requires signature verification
	RequireSignatureVerification bool

	// TrustedRepositories is a list of trusted repository prefixes
	TrustedRepositories []string

	// AllowIndirectDependencies allows indirect dependencies
	AllowIndirectDependencies bool
}

// LicenseCategory represents a category of licenses
type LicenseCategory string

const (
	LicenseCategoryPermissive     LicenseCategory = "permissive"
	LicenseCategoryWeakCopyleft   LicenseCategory = "weak-copyleft"
	LicenseCategoryStrongCopyleft LicenseCategory = "strong-copyleft"
	LicenseCategoryProprietary    LicenseCategory = "proprietary"
	LicenseCategoryUnknown        LicenseCategory = "unknown"
)

// DefaultSupplyChainPolicy returns a safe default supply-chain policy
func DefaultSupplyChainPolicy() SupplyChainPolicy {
	return SupplyChainPolicy{
		AllowedLicenses: []string{
			"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "Unlicense", "CC0-1.0",
			"MPL-2.0", "LGPL-2.1", "LGPL-3.0", "GPL-2.0", "GPL-3.0",
		},
		ForbiddenLicenses: []string{
			"AGPL-3.0", // AGPL might be too restrictive
		},
		AllowedLicenseCategories: []LicenseCategory{
			LicenseCategoryPermissive,
			LicenseCategoryWeakCopyleft,
		},
		MaximumSeverity:              SeverityHigh,
		MaximumCVSSScore:             7.0,
		RequireSBOMGeneration:        true,
		RequireVulnerabilityScanning: true,
		RequireSignatureVerification: false,
		TrustedRepositories: []string{
			"golang.org/x/",
			"github.com/golang/",
			"github.com/google/",
			"github.com/stretchr/",
		},
		AllowIndirectDependencies: true,
	}
}

// CheckPolicyCompliance checks if the current state complies with the supply-chain policy
func (a *DependencyAudit) CheckPolicyCompliance() ([]PolicyViolation, error) {
	var violations []PolicyViolation

	// Get current state
	deps, err := a.ScanDependencies(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to scan dependencies: %w", err)
	}

	// Check each dependency against policy
	for _, dep := range deps {
		// Check license
		if violation := a.checkLicensePolicy(dep); violation != nil {
			violations = append(violations, *violation)
		}

		// Check vulnerabilities
		if violation := a.checkVulnerabilityPolicy(dep); violation != nil {
			violations = append(violations, *violation)
		}

		// Check trusted repository
		if violation := a.checkRepositoryPolicy(dep); violation != nil {
			violations = append(violations, *violation)
		}
	}

	// Check SBOM policy
	if a.policy.RequireSBOMGeneration && a.sbom == nil {
		violations = append(violations, PolicyViolation{
			Type:     "sbom",
			Message:  "SBOM generation is required but no SBOM has been generated",
			Severity: SeverityHigh,
		})
	}

	return violations, nil
}

// PolicyViolation represents a violation of the supply-chain policy
type PolicyViolation struct {
	Type       string
	Message    string
	Severity   VulnerabilitySeverity
	Dependency string
	Details    string
}

// checkLicensePolicy checks if a dependency's license complies with policy
func (a *DependencyAudit) checkLicensePolicy(dep Dependency) *PolicyViolation {
	license := a.getLicenseForDependency(dep.Name)

	// Check forbidden licenses
	for _, forbidden := range a.policy.ForbiddenLicenses {
		if strings.EqualFold(license, forbidden) {
			return &PolicyViolation{
				Type:       "license",
				Message:    fmt.Sprintf("Dependency %s uses forbidden license: %s", dep.Name, license),
				Severity:   SeverityHigh,
				Dependency: dep.Name,
				Details:    fmt.Sprintf("License %s is in the forbidden licenses list", license),
			}
		}
	}

	// Check allowed licenses (if list is not empty)
	if len(a.policy.AllowedLicenses) > 0 {
		allowed := false
		for _, allowedLicense := range a.policy.AllowedLicenses {
			if strings.EqualFold(license, allowedLicense) {
				allowed = true
				break
			}
		}
		if !allowed && license != "UNKNOWN" {
			return &PolicyViolation{
				Type:       "license",
				Message:    fmt.Sprintf("Dependency %s uses license not in allowed list: %s", dep.Name, license),
				Severity:   SeverityMedium,
				Dependency: dep.Name,
				Details:    fmt.Sprintf("License %s is not in the allowed licenses list", license),
			}
		}
	}

	return nil
}

// checkVulnerabilityPolicy checks if a dependency has vulnerabilities that violate policy
func (a *DependencyAudit) checkVulnerabilityPolicy(dep Dependency) *PolicyViolation {
	if len(dep.Vulnerabilities) == 0 {
		return nil
	}

	for _, vuln := range dep.Vulnerabilities {
		// Check severity
		severityOrder := map[VulnerabilitySeverity]int{
			SeverityCritical: 4,
			SeverityHigh:     3,
			SeverityMedium:   2,
			SeverityLow:      1,
			SeverityUnknown:  0,
		}

		if severityOrder[vuln.Severity] > severityOrder[a.policy.MaximumSeverity] {
			return &PolicyViolation{
				Type: "vulnerability",
				Message: fmt.Sprintf("Dependency %s has vulnerability %s with severity %s (max allowed: %s)",
					dep.Name, vuln.ID, vuln.Severity, a.policy.MaximumSeverity),
				Severity:   vuln.Severity,
				Dependency: dep.Name,
				Details:    vuln.Summary,
			}
		}

		// Check CVSS score
		if vuln.CVSSScore > a.policy.MaximumCVSSScore {
			return &PolicyViolation{
				Type: "vulnerability",
				Message: fmt.Sprintf("Dependency %s has vulnerability %s with CVSS score %.1f (max allowed: %.1f)",
					dep.Name, vuln.ID, vuln.CVSSScore, a.policy.MaximumCVSSScore),
				Severity:   vuln.Severity,
				Dependency: dep.Name,
				Details:    vuln.Summary,
			}
		}
	}

	return nil
}

// checkRepositoryPolicy checks if a dependency is from a trusted repository
func (a *DependencyAudit) checkRepositoryPolicy(dep Dependency) *PolicyViolation {
	if len(a.policy.TrustedRepositories) == 0 {
		return nil
	}

	for _, trustedPrefix := range a.policy.TrustedRepositories {
		if strings.HasPrefix(dep.Name, trustedPrefix) {
			return nil
		}
	}

	return &PolicyViolation{
		Type:       "repository",
		Message:    fmt.Sprintf("Dependency %s is not from a trusted repository", dep.Name),
		Severity:   SeverityMedium,
		Dependency: dep.Name,
		Details:    "Dependency repository is not in the trusted repositories list",
	}
}

// RedactSecrets redacts sensitive information from dependency data
func (a *DependencyAudit) RedactSecrets(input string) string {
	// Redact common sensitive patterns
	secretsToRedact := []*regexp.Regexp{
		// AWS access keys
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		// Generic API keys
		regexp.MustCompile(`[a-zA-Z0-9]{32,}`),
		// Passwords in URLs
		regexp.MustCompile(`://[^:]+:[^@]+@`),
		// Bearer tokens
		regexp.MustCompile(`Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`),
		// Private keys
		regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`),
		// Generic secrets
		regexp.MustCompile(`(secret|token|key|password|credentials?)\s*[=:]\s*['\"]?[^'"\s]+['\"]?`),
	}

	result := input
	for _, pattern := range secretsToRedact {
		result = pattern.ReplaceAllString(result, "[REDACTED]")
	}

	return result
}

// ScanWorkspace scans the entire workspace for secrets and sensitive files
func (a *DependencyAudit) ScanWorkspace(ctx context.Context, root string) ([]SecretFinding, error) {
	var findings []SecretFinding

	// Walk the filesystem
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors, continue walking
		}

		// Skip directories we don't want to scan
		if d.IsDir() {
			skipDirs := []string{".git", ".vscode", "node_modules", "vendor", ".cache", "bin", "tmp"}
			for _, skip := range skipDirs {
				if strings.Contains(path, skip) {
					return fs.SkipDir
				}
			}
			return nil
		}

		// Only scan Go files, JSON, YAML, and text files
		if !a.isScannableFile(path) {
			return nil
		}

		// Read file content
		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files we can't read
		}

		// Check for secrets
		fileFindings := a.scanFileForSecrets(path, string(contentBytes))
		findings = append(findings, fileFindings...)

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to walk workspace: %w", err)
	}

	return findings, nil
}

// isScannableFile checks if a file should be scanned for secrets
func (a *DependencyAudit) isScannableFile(path string) bool {
	scannableExtensions := []string{".go", ".json", ".yaml", ".yml", ".toml", ".env", ".txt", ".md", "Dockerfile", "Makefile", ".sh"}
	for _, ext := range scannableExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// SecretFinding represents a found secret or sensitive data
type SecretFinding struct {
	// File is the file where the secret was found
	File string

	// Line is the line number (if available)
	Line int

	// SecretType is the type of secret found
	SecretType string

	// Severity is the severity of the finding
	Severity VulnerabilitySeverity

	// Description describes the finding
	Description string

	// MatchedText is the text that matched (redacted in output)
	MatchedText string

	// RedactedMatchedText is the redacted version of matched text
	RedactedMatchedText string

	// Recommendation is the recommended action
	Recommendation string

	// Detector is the name of the detector that found the secret
	Detector string

	// Timestamp is when the secret was found
	Timestamp time.Time

	// Vulnerabilities contains related vulnerabilities
	Vulnerabilities []Vulnerability
}

// scanFileForSecrets scans a file for secrets
func (a *DependencyAudit) scanFileForSecrets(path, content string) []SecretFinding {
	var findings []SecretFinding

	// Secret detection patterns
	secretPatterns := []struct {
		name           string
		pattern        *regexp.Regexp
		severity       VulnerabilitySeverity
		recommendation string
	}{
		{
			name:           "AWS Access Key",
			pattern:        regexp.MustCompile(`(?i)(aws\_access\_key\_id|access\_key|aws\_key)\s*[=:]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?`),
			severity:       SeverityCritical,
			recommendation: "Rotate AWS access keys immediately and use IAM roles or temporary credentials",
		},
		{
			name:           "AWS Secret Key",
			pattern:        regexp.MustCompile(`(?i)(aws\_secret\_access\_key|secret\_key|aws\_secret)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?`),
			severity:       SeverityCritical,
			recommendation: "Rotate AWS secret keys immediately and use IAM roles or temporary credentials",
		},
		{
			name:           "Generic API Key",
			pattern:        regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?[a-zA-Z0-9\-_,]{32,}['\"]?`),
			severity:       SeverityHigh,
			recommendation: "Rotate API keys and use environment variables or secret management systems",
		},
		{
			name:           "Password",
			pattern:        regexp.MustCompile(`(?i)(password|passwd|pwd|secret)\s*[=:]\s*['\"]?[^'"\s,;]{8,}['\"]?`),
			severity:       SeverityHigh,
			recommendation: "Use environment variables or secret management systems for passwords",
		},
		{
			name:           "Bearer Token",
			pattern:        regexp.MustCompile(`(?i)(bearer\s+[a-zA-Z0-9\-_.]+|Authorization\s*[=:]\s*['\"]?Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+['\"]?)`),
			severity:       SeverityCritical,
			recommendation: "Rotate tokens immediately and use short-lived tokens",
		},
		{
			name:           "Private Key",
			pattern:        regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`),
			severity:       SeverityCritical,
			recommendation: "Rotate private keys immediately and use proper key management",
		},
		{
			name:           "JWT Token",
			pattern:        regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`),
			severity:       SeverityHigh,
			recommendation: "Rotate JWT tokens and use short expiration times",
		},
		{
			name:           "Database Connection String",
			pattern:        regexp.MustCompile(`(?i)(connection[_-]?string|db[_-]?url|database[_-]?url)\s*[=:]\s*['\"]?[^'"\s]+://[^'"\s]+:[^'"\s]+@[^'"\s]+['\"]?`),
			severity:       SeverityHigh,
			recommendation: "Use environment variables or secret management for database connection strings",
		},
		{
			name:           "Basic Auth Credentials",
			pattern:        regexp.MustCompile(`(?i)://[^:]+:[^@]+@`),
			severity:       SeverityHigh,
			recommendation: "Use token-based authentication or environment variables for credentials",
		},
		{
			name:           "GitHub Token",
			pattern:        regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}`),
			severity:       SeverityCritical,
			recommendation: "Rotate GitHub tokens immediately and use fine-grained tokens with minimal permissions",
		},
		{
			name:           "Slack Token",
			pattern:        regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]+`),
			severity:       SeverityHigh,
			recommendation: "Rotate Slack tokens immediately",
		},
		{
			name:           "Stripe API Key",
			pattern:        regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}|sk_test_[0-9a-zA-Z]{24}`),
			severity:       SeverityHigh,
			recommendation: "Rotate Stripe API keys immediately",
		},
	}

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		for _, pattern := range secretPatterns {
			matches := pattern.pattern.FindStringSubmatch(line)
			if len(matches) > 0 {
				// Extract the actual secret (first capture group or full match)
				var secretText string
				if len(matches) > 1 {
					secretText = matches[1]
				} else {
					secretText = matches[0]
				}

				// Redact the secret
				redacted := a.RedactSecrets(secretText)

				finding := SecretFinding{
					File:                path,
					Line:                lineNum + 1,
					SecretType:          pattern.name,
					Severity:            pattern.severity,
					Description:         fmt.Sprintf("Found %s in file", pattern.name),
					MatchedText:         secretText,
					RedactedMatchedText: redacted,
					Recommendation:      pattern.recommendation,
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// GetDependencyGraph returns the dependency graph
func (a *DependencyAudit) GetDependencyGraph(ctx context.Context) (map[string][]string, error) {
	cmd := exec.CommandContext(ctx, a.config.GoBinary, "mod", "graph")
	cmd.Dir = filepath.Dir(a.config.GoModPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get dependency graph: %w", err)
	}

	graph := make(map[string][]string)
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) >= 2 {
			from := parts[0]
			to := parts[1]
			graph[from] = append(graph[from], to)
		}
	}

	return graph, nil
}

// Cleanup removes temporary files and cached data
func (a *DependencyAudit) Cleanup() error {
	// Remove cache directory
	if a.config.CacheDir != "" {
		if err := os.RemoveAll(a.config.CacheDir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to remove cache directory: %w", err)
		}
	}

	return nil
}
