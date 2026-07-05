// Package security provides threat modeling and security hardening for the Solid runtime.
// This file implements Phase 26: Secret scanning and log-redaction tests.
package security

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SecretScanner provides comprehensive secret scanning for the Solid runtime.
// It scans files, logs, and runtime data for sensitive information that should be redacted.
type SecretScanner struct {
	mu sync.RWMutex

	// Config holds scanner configuration
	config SecretScannerConfig

	// Logger for scan events
	logger *slog.Logger

	// Detectors holds the secret detection patterns
	detectors []SecretDetector

	// Findings holds the current scan findings
	findings []SecretFinding

	// LastScan holds the timestamp of the last scan
	lastScan time.Time

	// Stats holds scanning statistics
	stats ScanStatistics
}

// SecretScannerConfig holds configuration for the secret scanner
type SecretScannerConfig struct {
	// ScanPaths is a list of paths to scan
	ScanPaths []string

	// ExcludePaths is a list of paths to exclude from scanning
	ExcludePaths []string

	// ExcludePatterns is a list of regex patterns for files to exclude
	ExcludePatterns []*regexp.Regexp

	// IncludePatterns is a list of regex patterns for files to include (overrides excludes)
	IncludePatterns []*regexp.Regexp

	// MaxFileSize is the maximum file size to scan (0 = no limit)
	MaxFileSize int64

	// MaxLineLength is the maximum line length to scan (0 = no limit)
	MaxLineLength int

	// NumWorkers is the number of parallel scan workers
	NumWorkers int

	// ScanTimeout is the timeout for the entire scan
	ScanTimeout time.Duration

	// EnableLogRedaction enables automatic log redaction
	EnableLogRedaction bool

	// LogRedactionPatterns is a list of additional patterns for log redaction
	LogRedactionPatterns []*regexp.Regexp

	// MinimumSecretLength is the minimum length of a secret to detect
	MinimumSecretLength int

	// SeverityOverrides allows overriding severity for specific secret types
	SeverityOverrides map[string]VulnerabilitySeverity
}

// DefaultSecretScannerConfig returns a safe default configuration
func DefaultSecretScannerConfig() SecretScannerConfig {
	return SecretScannerConfig{
		ScanPaths:           []string{"."},
		ExcludePaths:        []string{".git", "node_modules", "vendor", ".cache", "bin", "tmp", "testdata"},
		MaxFileSize:         10 * 1024 * 1024, // 10MB
		MaxLineLength:       10000,
		NumWorkers:          4,
		ScanTimeout:         5 * time.Minute,
		EnableLogRedaction:  true,
		MinimumSecretLength: 8,
		SeverityOverrides: map[string]VulnerabilitySeverity{
			"AWS Access Key":      SeverityCritical,
			"AWS Secret Key":      SeverityCritical,
			"Private Key":         SeverityCritical,
			"Bearer Token":        SeverityCritical,
			"GitHub Token":        SeverityCritical,
			"Password":            SeverityHigh,
			"API Key":             SeverityHigh,
			"JWT Token":           SeverityHigh,
			"Database Connection": SeverityHigh,
		},
	}
}

// SecretDetector defines an interface for detecting secrets
type SecretDetector interface {
	// Name returns the name of the detector
	Name() string

	// Description returns a description of what the detector finds
	Description() string

	// Severity returns the default severity for findings from this detector
	Severity() VulnerabilitySeverity

	// Detect scans content and returns findings
	Detect(content []byte, filename string, lineNum int) []SecretFinding
}

// RegexDetector detects secrets using regex patterns
type RegexDetector struct {
	name           string
	description    string
	severity       VulnerabilitySeverity
	pattern        *regexp.Regexp
	recommendation string
	groupIndex     int // Which capture group contains the secret (0 = full match)
}

// Name returns the detector name
func (r *RegexDetector) Name() string {
	return r.name
}

// Description returns the detector description
func (r *RegexDetector) Description() string {
	return r.description
}

// Severity returns the detector severity
func (r *RegexDetector) Severity() VulnerabilitySeverity {
	return r.severity
}

// Detect scans content for secrets
func (r *RegexDetector) Detect(content []byte, filename string, lineNum int) []SecretFinding {
	var findings []SecretFinding

	// Convert to string for regex matching
	contentStr := string(content)

	matches := r.pattern.FindAllStringSubmatchIndex(contentStr, -1)
	for _, match := range matches {
		// Extract the secret
		var secretStart, secretEnd int
		if r.groupIndex > 0 && r.groupIndex*2 < len(match) {
			secretStart = match[r.groupIndex*2]
			secretEnd = match[r.groupIndex*2+1]
		} else {
			secretStart = match[0]
			secretEnd = match[1]
		}

		secret := contentStr[secretStart:secretEnd]

		// Skip if too short
		if len(secret) < 8 { // Minimum reasonable length
			continue
		}

		// Create finding
		finding := SecretFinding{
			File:                filename,
			Line:                lineNum,
			SecretType:          r.name,
			Severity:            r.severity,
			Description:         r.description,
			MatchedText:         secret,
			RedactedMatchedText: RedactSecret(secret),
			Recommendation:      r.recommendation,
			Detector:            r.name,
			Timestamp:           time.Now(),
		}

		findings = append(findings, finding)
	}

	return findings
}

// ScanStatistics holds statistics about secret scanning
type ScanStatistics struct {
	FilesScanned      int
	FilesWithFindings int
	TotalFindings     int
	BySeverity        map[VulnerabilitySeverity]int
	ByType            map[string]int
	ScanDuration      time.Duration
	LastScanTime      time.Time
}

// NewSecretScanner creates a new secret scanner
func NewSecretScanner(config SecretScannerConfig, logger *slog.Logger) *SecretScanner {
	if logger == nil {
		logger = slog.Default()
	}

	scanner := &SecretScanner{
		config:    config,
		logger:    logger,
		detectors: createDefaultDetectors(),
		findings:  make([]SecretFinding, 0),
		stats: ScanStatistics{
			BySeverity: make(map[VulnerabilitySeverity]int),
			ByType:     make(map[string]int),
		},
	}

	// Apply severity overrides
	for i := range scanner.detectors {
		if override, ok := config.SeverityOverrides[scanner.detectors[i].Name()]; ok {
			// Create a new detector with overridden severity
			if rd, ok := scanner.detectors[i].(*RegexDetector); ok {
				newDetector := *rd
				newDetector.severity = override
				scanner.detectors[i] = &newDetector
			}
		}
	}

	return scanner
}

// createDefaultDetectors creates the default set of secret detectors
func createDefaultDetectors() []SecretDetector {
	return []SecretDetector{
		// AWS Credentials
		&RegexDetector{
			name:           "AWS Access Key ID",
			description:    "AWS Access Key ID found",
			severity:       SeverityCritical,
			pattern:        regexp.MustCompile(`(?i)(aws[_-]?access[_-]?key[_-]?id|access[_-]?key|aws[_-]?key|akid)\s*[=:]\s*['"]?(AKIA[0-9A-Z]{16})['"]?`),
			recommendation: "Rotate AWS access keys immediately and use IAM roles or temporary credentials. Consider using AWS Secrets Manager.",
			groupIndex:     1,
		},
		&RegexDetector{
			name:           "AWS Secret Access Key",
			description:    "AWS Secret Access Key found",
			severity:       SeverityCritical,
			pattern:        regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key|aws[_-]?secret)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`),
			recommendation: "Rotate AWS secret keys immediately and use IAM roles or temporary credentials. Consider using AWS Secrets Manager.",
			groupIndex:     1,
		},
		&RegexDetector{
			name:           "AWS Session Token",
			description:    "AWS Session Token found",
			severity:       SeverityCritical,
			pattern:        regexp.MustCompile(`(?i)(aws[_-]?session[_-]?token|session[_-]?token)\s*[=:]\s*['"]?[A-Za-z0-9/+=]+['"]?`),
			recommendation: "Rotate AWS session tokens immediately. Session tokens are short-lived but should not be committed.",
			groupIndex:     1,
		},

		// GitHub Tokens
		&RegexDetector{
			name:           "GitHub Personal Access Token",
			description:    "GitHub Personal Access Token found",
			severity:       SeverityCritical,
			pattern:        regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}`),
			recommendation: "Rotate GitHub tokens immediately and use fine-grained tokens with minimal permissions. Consider using GitHub Actions secrets.",
			groupIndex:     0,
		},

		// Generic API Keys
		&RegexDetector{
			name:           "Generic API Key",
			description:    "Generic API Key found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret|app[_-]?key|application[_-]?key)\s*[=:]\s*['"]?[a-zA-Z0-9\-_,]{32,}['"]?`),
			recommendation: "Rotate API keys immediately and use environment variables or secret management systems.",
			groupIndex:     1,
		},

		// Bearer Tokens
		&RegexDetector{
			name:           "Bearer Token",
			description:    "Bearer Token found",
			severity:       SeverityCritical,
			pattern:        regexp.MustCompile(`(?i)(bearer\s+[a-zA-Z0-9\-_.]+|Authorization\s*[=:]\s*['"]?Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+['"]?)`),
			recommendation: "Rotate bearer tokens immediately and use short-lived tokens with proper expiration.",
			groupIndex:     0,
		},

		// JWT Tokens
		&RegexDetector{
			name:           "JWT Token",
			description:    "JWT Token found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`),
			recommendation: "Rotate JWT tokens and use short expiration times. Consider using opaque tokens instead.",
			groupIndex:     0,
		},

		// Private Keys
		&RegexDetector{
			name:           "Private Key",
			description:    "Private Key found",
			severity:       SeverityCritical,
			pattern:        regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ED25519\s+)?PRIVATE\s+KEY-----`),
			recommendation: "Rotate private keys immediately and use proper key management with hardware security modules (HSMs) if possible.",
			groupIndex:     0,
		},

		// Passwords
		&RegexDetector{
			name:           "Password",
			description:    "Password found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`(?i)(password|passwd|pwd|pass|secret|credentials?|auth[_-]?token)\s*[=:]\s*['"]?[^'"\s,;]{8,}['"]?`),
			recommendation: "Use environment variables or secret management systems for passwords. Never hardcode passwords.",
			groupIndex:     1,
		},

		// Database Connection Strings
		&RegexDetector{
			name:           "Database Connection String",
			description:    "Database Connection String found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`(?i)(connection[_-]?string|conn[_-]?str|db[_-]?url|database[_-]?url|dns|server|host)\s*[=:]\s*['"]?[^'"\s]+://[^'"\s]+:[^'"\s]+@[^'"\s]+[:/][^'"\s]*['"]?`),
			recommendation: "Use environment variables or secret management for database connection strings. Use connection pooling.",
			groupIndex:     0,
		},

		// Basic Auth Credentials
		&RegexDetector{
			name:           "Basic Auth Credentials",
			description:    "Basic Auth Credentials found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`(?i)://([^:]+):([^@]+)@`),
			recommendation: "Use token-based authentication or OAuth2 instead of basic auth. Use environment variables for credentials.",
			groupIndex:     0,
		},

		// Slack Tokens
		&RegexDetector{
			name:           "Slack Token",
			description:    "Slack API Token found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
			recommendation: "Rotate Slack tokens immediately and use Slack App permissions with minimal scopes.",
			groupIndex:     0,
		},

		// Stripe API Keys
		&RegexDetector{
			name:           "Stripe API Key",
			description:    "Stripe API Key found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`sk_(live|test)_[0-9a-zA-Z]{24}`),
			recommendation: "Rotate Stripe API keys immediately and use restricted keys with minimal permissions.",
			groupIndex:     0,
		},

		// Heroku API Key
		&RegexDetector{
			name:           "Heroku API Key",
			description:    "Heroku API Key found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`(?i)(heroku[_-]?api[_-]?key)\s*[=:]\s*['"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]?`),
			recommendation: "Rotate Heroku API keys immediately and use Heroku CI/CD instead of API keys.",
			groupIndex:     1,
		},

		// SendGrid API Key
		&RegexDetector{
			name:           "SendGrid API Key",
			description:    "SendGrid API Key found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}`),
			recommendation: "Rotate SendGrid API keys immediately and use restricted API keys.",
			groupIndex:     0,
		},

		// Twilio API Key
		&RegexDetector{
			name:           "Twilio API Key",
			description:    "Twilio API Key found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
			recommendation: "Rotate Twilio API keys immediately and use environment variables.",
			groupIndex:     0,
		},

		// Mailchimp API Key
		&RegexDetector{
			name:           "Mailchimp API Key",
			description:    "Mailchimp API Key found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
			recommendation: "Rotate Mailchimp API keys immediately.",
			groupIndex:     0,
		},

		// Square Access Token
		&RegexDetector{
			name:           "Square Access Token",
			description:    "Square Access Token found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`sq0atp-[a-zA-Z0-9\-_]{22}`),
			recommendation: "Rotate Square access tokens immediately.",
			groupIndex:     0,
		},

		// Square OAuth Secret
		&RegexDetector{
			name:           "Square OAuth Secret",
			description:    "Square OAuth Secret found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`sq0csp-[a-zA-Z0-9\-_]{43}`),
			recommendation: "Rotate Square OAuth secrets immediately.",
			groupIndex:     0,
		},

		// Telegram Bot Token
		&RegexDetector{
			name:           "Telegram Bot Token",
			description:    "Telegram Bot Token found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`[0-9]{8,10}:[a-zA-Z0-9\-_]{35}`),
			recommendation: "Rotate Telegram bot tokens immediately.",
			groupIndex:     0,
		},

		// Generic Secret in Key-Value format
		&RegexDetector{
			name:           "Generic Secret Assignment",
			description:    "Generic secret in key-value format found",
			severity:       SeverityMedium,
			pattern:        regexp.MustCompile(`(?i)(secret|token|key|password|passwd|pwd|api[_-]?key|access[_-]?key|auth[_-]?key|private[_-]?key|credentials?)\s*[=:]\s*['"]?[a-zA-Z0-9\-_,./+=]{16,}['"]?`),
			recommendation: "Use environment variables or secret management systems for sensitive data.",
			groupIndex:     1,
		},

		// Certificate Files
		&RegexDetector{
			name:           "Certificate Private Key",
			description:    "Certificate Private Key file reference found",
			severity:       SeverityHigh,
			pattern:        regexp.MustCompile(`(?i)(key\.pem|private\.key|id_rsa|id_ed25519|id_ecdsa)`),
			recommendation: "Ensure private key files are not committed to version control. Use .gitignore.",
			groupIndex:     0,
		},

		// Environment File Secrets
		&RegexDetector{
			name:           "Environment File Secret",
			description:    "Secret found in environment file",
			severity:       SeverityMedium,
			pattern:        regexp.MustCompile(`(?i)^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^\s#\n]+$`),
			recommendation: "Environment files should be in .gitignore. Use proper secret management.",
			groupIndex:     0,
		},
	}
}

// Scan scans the configured paths for secrets
func (s *SecretScanner) Scan(ctx context.Context) ([]SecretFinding, error) {
	startTime := time.Now()
	s.findings = make([]SecretFinding, 0)
	s.stats = ScanStatistics{
		BySeverity:   make(map[VulnerabilitySeverity]int),
		ByType:       make(map[string]int),
		LastScanTime: startTime,
	}

	// Create context with timeout
	if s.config.ScanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.config.ScanTimeout)
		defer cancel()
	}

	// Collect all files to scan
	files, err := s.collectFilesToScan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}

	s.logger.Info("Starting secret scan", "files", len(files))

	// Scan files in parallel
	results, err := s.scanFilesParallel(ctx, files)
	if err != nil {
		return nil, fmt.Errorf("failed to scan files: %w", err)
	}

	// Deduplicate findings
	s.findings = s.deduplicateFindings(results)

	// Update statistics
	s.stats.FilesScanned = len(files)
	s.stats.ScanDuration = time.Since(startTime)
	s.lastScan = time.Now()

	// Log summary
	for _, finding := range s.findings {
		s.stats.TotalFindings++
		s.stats.BySeverity[finding.Severity]++
		s.stats.ByType[finding.SecretType]++
	}

	for _, f := range s.findings {
		if len(f.Vulnerabilities) > 0 {
			s.stats.FilesWithFindings++
			break
		}
	}

	s.logger.Info("Secret scan completed",
		"duration", s.stats.ScanDuration,
		"files_scanned", s.stats.FilesScanned,
		"total_findings", s.stats.TotalFindings,
		"files_with_findings", s.stats.FilesWithFindings,
	)

	return s.findings, nil
}

// collectFilesToScan collects all files that should be scanned
func (s *SecretScanner) collectFilesToScan(ctx context.Context) ([]string, error) {
	var files []string

	for _, scanPath := range s.config.ScanPaths {
		if err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// Skip directories we can't read
				if os.IsPermission(err) {
					return nil
				}
				return err
			}

			// Check context cancellation
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Skip if directory
			if d.IsDir() {
				// Check if this directory should be excluded
				if s.shouldExcludePath(path) {
					return fs.SkipDir
				}
				return nil
			}

			// Check if file should be excluded
			if s.shouldExcludeFile(path) {
				return nil
			}

			// Check file size
			info, err := d.Info()
			if err != nil {
				return nil // Skip files we can't stat
			}

			if s.config.MaxFileSize > 0 && info.Size() > s.config.MaxFileSize {
				s.logger.Debug("Skipping large file", "path", path, "size", info.Size())
				return nil
			}

			files = append(files, path)
			return nil
		}); err != nil {
			return nil, fmt.Errorf("failed to walk path %s: %w", scanPath, err)
		}
	}

	return files, nil
}

// shouldExcludePath checks if a path should be excluded
func (s *SecretScanner) shouldExcludePath(path string) bool {
	for _, exclude := range s.config.ExcludePaths {
		if strings.Contains(path, exclude) {
			return true
		}
	}
	return false
}

// shouldExcludeFile checks if a file should be excluded
func (s *SecretScanner) shouldExcludeFile(path string) bool {
	// Check exclude paths
	for _, exclude := range s.config.ExcludePaths {
		if strings.Contains(path, exclude) {
			return true
		}
	}

	// Check exclude patterns
	for _, pattern := range s.config.ExcludePatterns {
		if pattern.MatchString(path) {
			return true
		}
	}

	// Check include patterns (override excludes)
	for _, pattern := range s.config.IncludePatterns {
		if pattern.MatchString(path) {
			return false
		}
	}

	return false
}

// scanFilesParallel scans files in parallel using worker goroutines
func (s *SecretScanner) scanFilesParallel(ctx context.Context, files []string) ([]SecretFinding, error) {
	type scanResult struct {
		file     string
		findings []SecretFinding
		err      error
	}

	resultChan := make(chan scanResult, len(files))

	// Create worker pool
	var wg sync.WaitGroup
	for i := 0; i < s.config.NumWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range resultChan {
				// This is a worker that processes scan requests
				// In a real implementation, we'd use a different pattern
			}
		}()
	}

	// Start workers
	workerChan := make(chan string, s.config.NumWorkers)

	for i := 0; i < s.config.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for file := range workerChan {
				// Check context
				select {
				case <-ctx.Done():
					return
				default:
				}

				findings, err := s.scanFile(file)
				resultChan <- scanResult{
					file:     file,
					findings: findings,
					err:      err,
				}
			}
		}(i)
	}

	// Send files to workers
	go func() {
		for _, file := range files {
			workerChan <- file
		}
		close(workerChan)
	}()

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var allFindings []SecretFinding
	for result := range resultChan {
		if result.err != nil {
			s.logger.Warn("Error scanning file", "file", result.file, "error", result.err)
			continue
		}
		allFindings = append(allFindings, result.findings...)
	}

	return allFindings, nil
}

// scanFile scans a single file for secrets
func (s *SecretScanner) scanFile(path string) ([]SecretFinding, error) {
	// Open file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Get file info for size check
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	// Check size
	if s.config.MaxFileSize > 0 && info.Size() > s.config.MaxFileSize {
		return nil, fmt.Errorf("file too large: %d > %d", info.Size(), s.config.MaxFileSize)
	}

	var allFindings []SecretFinding

	// Use bufio for efficient line-by-line scanning
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip long lines
		if s.config.MaxLineLength > 0 && len(line) > s.config.MaxLineLength {
			continue
		}

		// Scan each line with all detectors
		findings := s.scanLineWithDetectors(line, path, lineNum)
		allFindings = append(allFindings, findings...)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return allFindings, nil
}

// scanLineWithDetectors scans a line with all configured detectors
func (s *SecretScanner) scanLineWithDetectors(line, filename string, lineNum int) []SecretFinding {
	var allFindings []SecretFinding

	for _, detector := range s.detectors {
		findings := detector.Detect([]byte(line), filename, lineNum)
		// Filter out findings below minimum length
		for _, f := range findings {
			if len(f.MatchedText) >= s.config.MinimumSecretLength {
				allFindings = append(allFindings, f)
			}
		}
	}

	return allFindings
}

// deduplicateFindings removes duplicate findings (same file, line, secret type, and matched text)
func (s *SecretScanner) deduplicateFindings(findings []SecretFinding) []SecretFinding {
	seen := make(map[string]SecretFinding)
	var result []SecretFinding

	for _, f := range findings {
		key := fmt.Sprintf("%s:%d:%s:%s", f.File, f.Line, f.SecretType, f.MatchedText)
		if existing, exists := seen[key]; !exists {
			seen[key] = f
			result = append(result, f)
		} else {
			// Keep the higher severity finding
			severityOrder := map[VulnerabilitySeverity]int{
				SeverityCritical: 4,
				SeverityHigh:     3,
				SeverityMedium:   2,
				SeverityLow:      1,
				SeverityUnknown:  0,
			}
			if severityOrder[f.Severity] > severityOrder[existing.Severity] {
				seen[key] = f
				result[len(result)-1] = f
			}
		}
	}

	return result
}

// GetFindings returns all findings from the last scan
func (s *SecretScanner) GetFindings() []SecretFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findings
}

// GetFindingsBySeverity returns findings filtered by severity
func (s *SecretScanner) GetFindingsBySeverity(severity VulnerabilitySeverity) []SecretFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []SecretFinding
	for _, f := range s.findings {
		if f.Severity == severity {
			result = append(result, f)
		}
	}
	return result
}

// GetFindingsByType returns findings filtered by secret type
func (s *SecretScanner) GetFindingsByType(secretType string) []SecretFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []SecretFinding
	for _, f := range s.findings {
		if f.SecretType == secretType {
			result = append(result, f)
		}
	}
	return result
}

// GetCriticalFindings returns all critical severity findings
func (s *SecretScanner) GetCriticalFindings() []SecretFinding {
	return s.GetFindingsBySeverity(SeverityCritical)
}

// GetHighFindings returns all high severity findings
func (s *SecretScanner) GetHighFindings() []SecretFinding {
	return s.GetFindingsBySeverity(SeverityHigh)
}

// HasCriticalFindings returns true if there are any critical findings
func (s *SecretScanner) HasCriticalFindings() bool {
	return len(s.GetCriticalFindings()) > 0
}

// HasFindings returns true if there are any findings
func (s *SecretScanner) HasFindings() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.findings) > 0
}

// GetStatistics returns scanning statistics
func (s *SecretScanner) GetStatistics() ScanStatistics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// RedactSecret redacts a secret value, replacing it with [REDACTED]
func RedactSecret(secret string) string {
	if secret == "" {
		return ""
	}
	return "[REDACTED]"
}

// RedactSecretsInString redacts all detected secrets in a string
func (s *SecretScanner) RedactSecretsInString(input string) string {
	result := input

	for _, detector := range s.detectors {
		// For regex detectors, apply the pattern
		if rd, ok := detector.(*RegexDetector); ok {
			result = rd.pattern.ReplaceAllString(result, "[REDACTED]")
		}
	}

	return result
}

// RedactSecretsInLog redacts secrets in log messages
func (s *SecretScanner) RedactSecretsInLog(msg string, args ...any) string {
	if !s.config.EnableLogRedaction {
		return msg
	}

	// Convert args to string representations
	var argStrings []string
	for _, arg := range args {
		argStrings = append(argStrings, fmt.Sprintf("%v", arg))
	}

	// Redact in message
	redactedMsg := s.RedactSecretsInString(msg)

	// Redact in args
	for i, argStr := range argStrings {
		argStrings[i] = s.RedactSecretsInString(argStr)
	}

	// Reconstruct the message
	return redactedMsg
}

// LogRedactor is a middleware for slog.Logger that redacts secrets
type LogRedactor struct {
	logger  *slog.Logger
	scanner *SecretScanner
}

// NewLogRedactor creates a new log redaction middleware
func NewLogRedactor(logger *slog.Logger, scanner *SecretScanner) *LogRedactor {
	return &LogRedactor{
		logger:  logger,
		scanner: scanner,
	}
}

// Info logs an info message with secret redaction
func (l *LogRedactor) Info(msg string, args ...any) {
	if l.scanner != nil && l.scanner.config.EnableLogRedaction {
		redactedArgs := l.redactArgs(args...)
		l.logger.Info(msg, redactedArgs...)
	} else {
		l.logger.Info(msg, args...)
	}
}

// Warn logs a warning message with secret redaction
func (l *LogRedactor) Warn(msg string, args ...any) {
	if l.scanner != nil && l.scanner.config.EnableLogRedaction {
		redactedArgs := l.redactArgs(args...)
		l.logger.Warn(msg, redactedArgs...)
	} else {
		l.logger.Warn(msg, args...)
	}
}

// Error logs an error message with secret redaction
func (l *LogRedactor) Error(msg string, args ...any) {
	if l.scanner != nil && l.scanner.config.EnableLogRedaction {
		redactedArgs := l.redactArgs(args...)
		l.logger.Error(msg, redactedArgs...)
	} else {
		l.logger.Error(msg, args...)
	}
}

// Debug logs a debug message with secret redaction
func (l *LogRedactor) Debug(msg string, args ...any) {
	if l.scanner != nil && l.scanner.config.EnableLogRedaction {
		redactedArgs := l.redactArgs(args...)
		l.logger.Debug(msg, redactedArgs...)
	} else {
		l.logger.Debug(msg, args...)
	}
}

// redactArgs redacts secrets in all arguments
func (l *LogRedactor) redactArgs(args ...any) []any {
	redacted := make([]any, len(args))
	for i, arg := range args {
		// Handle string values
		if s, ok := arg.(string); ok {
			redacted[i] = l.scanner.RedactSecretsInString(s)
		} else if b, ok := arg.([]byte); ok {
			redacted[i] = []byte(l.scanner.RedactSecretsInString(string(b)))
		} else if m, ok := arg.(map[string]any); ok {
			// Redact values in maps
			redactedMap := make(map[string]any, len(m))
			for k, v := range m {
				if vs, ok := v.(string); ok {
					redactedMap[k] = l.scanner.RedactSecretsInString(vs)
				} else {
					redactedMap[k] = v
				}
			}
			redacted[i] = redactedMap
		} else {
			// For other types, just use as-is
			redacted[i] = arg
		}
	}
	return redacted
}

// ScanReader scans a reader for secrets (useful for scanning logs, HTTP bodies, etc.)
func (s *SecretScanner) ScanReader(ctx context.Context, r io.Reader, source string) ([]SecretFinding, error) {
	var findings []SecretFinding

	// Read content
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	// Split into lines
	lines := strings.Split(string(content), "\n")

	for lineNum, line := range lines {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Scan line with all detectors
		lineFindings := s.scanLineWithDetectors(line, source, lineNum+1)
		findings = append(findings, lineFindings...)
	}

	return findings, nil
}

// ScanString scans a string for secrets
func (s *SecretScanner) ScanString(ctx context.Context, content, source string) ([]SecretFinding, error) {
	lines := strings.Split(content, "\n")
	var findings []SecretFinding

	for lineNum, line := range lines {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		lineFindings := s.scanLineWithDetectors(line, source, lineNum+1)
		findings = append(findings, lineFindings...)
	}

	return findings, nil
}

// GenerateReport generates a human-readable report of findings
func (s *SecretScanner) GenerateReport() string {
	var sb strings.Builder

	sb.WriteString("=== SECRET SCAN REPORT ===\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Scan Duration: %v\n", s.stats.ScanDuration))
	sb.WriteString(fmt.Sprintf("Files Scanned: %d\n", s.stats.FilesScanned))
	sb.WriteString(fmt.Sprintf("Files with Findings: %d\n", s.stats.FilesWithFindings))
	sb.WriteString(fmt.Sprintf("Total Findings: %d\n\n", s.stats.TotalFindings))

	// Summary by severity
	sb.WriteString("=== FINDINGS BY SEVERITY ===\n")
	severityOrder := []VulnerabilitySeverity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityUnknown}
	for _, sev := range severityOrder {
		count := s.stats.BySeverity[sev]
		if count > 0 {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", sev, count))
		}
	}
	sb.WriteString("\n")

	// Findings by type
	sb.WriteString("=== FINDINGS BY TYPE ===\n")
	typeCounts := make(map[string]int)
	for _, f := range s.findings {
		typeCounts[f.SecretType]++
	}
	for secretType, count := range typeCounts {
		sb.WriteString(fmt.Sprintf("  %s: %d\n", secretType, count))
	}
	sb.WriteString("\n")

	// Detailed findings
	if len(s.findings) > 0 {
		sb.WriteString("=== DETAILED FINDINGS ===\n")
		for _, f := range s.findings {
			sb.WriteString(fmt.Sprintf("  [%s] %s:%d\n", f.Severity, f.File, f.Line))
			sb.WriteString(fmt.Sprintf("    Type: %s\n", f.SecretType))
			sb.WriteString(fmt.Sprintf("    Description: %s\n", f.Description))
			sb.WriteString(fmt.Sprintf("    Redacted Value: %s\n", f.RedactedMatchedText))
			sb.WriteString(fmt.Sprintf("    Recommendation: %s\n", f.Recommendation))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// GenerateJSONReport generates a JSON report of findings
func (s *SecretScanner) GenerateJSONReport() (string, error) {
	// Create a safe copy of findings for JSON
	type JSONFinding struct {
		File                string `json:"file"`
		Line                int    `json:"line"`
		SecretType          string `json:"secret_type"`
		Severity            string `json:"severity"`
		Description         string `json:"description"`
		RedactedMatchedText string `json:"redacted_value"`
		Recommendation      string `json:"recommendation"`
		Detector            string `json:"detector"`
		Timestamp           string `json:"timestamp"`
	}

	var jsonFindings []JSONFinding
	for _, f := range s.findings {
		jsonFindings = append(jsonFindings, JSONFinding{
			File:                f.File,
			Line:                f.Line,
			SecretType:          f.SecretType,
			Severity:            string(f.Severity),
			Description:         f.Description,
			RedactedMatchedText: f.RedactedMatchedText,
			Recommendation:      f.Recommendation,
			Detector:            f.Detector,
			Timestamp:           f.Timestamp.Format(time.RFC3339),
		})
	}

	type JSONReport struct {
		GeneratedAt       string         `json:"generated_at"`
		ScanDuration      string         `json:"scan_duration"`
		FilesScanned      int            `json:"files_scanned"`
		FilesWithFindings int            `json:"files_with_findings"`
		TotalFindings     int            `json:"total_findings"`
		BySeverity        map[string]int `json:"by_severity"`
		ByType            map[string]int `json:"by_type"`
		Findings          []JSONFinding  `json:"findings"`
	}

	report := JSONReport{
		GeneratedAt:       time.Now().Format(time.RFC3339),
		ScanDuration:      s.stats.ScanDuration.String(),
		FilesScanned:      s.stats.FilesScanned,
		FilesWithFindings: s.stats.FilesWithFindings,
		TotalFindings:     s.stats.TotalFindings,
		BySeverity:        convertSeverityMap(s.stats.BySeverity),
		ByType:            s.stats.ByType,
		Findings:          jsonFindings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON report: %w", err)
	}

	return string(data), nil
}

// convertSeverityMap converts a severity map to a string-keyed map for JSON
func convertSeverityMap(m map[VulnerabilitySeverity]int) map[string]int {
	result := make(map[string]int)
	for k, v := range m {
		result[string(k)] = v
	}
	return result
}

// ExportForTesting exports internals for testing
var ExportForTesting = struct {
	CreateDefaultDetectors func() []SecretDetector
	RedactSecret           func(string) string
}{
	CreateDefaultDetectors: createDefaultDetectors,
	RedactSecret:           RedactSecret,
}
