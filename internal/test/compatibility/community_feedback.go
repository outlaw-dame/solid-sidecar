// Package compatibility provides community feedback incorporation mechanisms
package compatibility

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CommunityFeedback represents feedback from the Solid community
type CommunityFeedback struct {
	ID             string            `json:"id"`
	Type           FeedbackType      `json:"type"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	Source         string            `json:"source"`
	Severity       FeedbackSeverity  `json:"severity"`
	Status         FeedbackStatus    `json:"status"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	RelatedSpec    string            `json:"related_spec,omitempty"`
	AffectedClient string            `json:"affected_client,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	Priority       int               `json:"priority"`
	Resolution     string            `json:"resolution,omitempty"`
	ResolvedAt     *time.Time        `json:"resolved_at,omitempty"`
	Assignee       string            `json:"assignee,omitempty"`
}

// FeedbackType defines the type of feedback
type FeedbackType string

const (
	FeedbackTypeBug          FeedbackType = "bug"
	FeedbackTypeFeature      FeedbackType = "feature-request"
	FeedbackTypeCompatibility FeedbackType = "compatibility-issue"
	FeedbackTypeEnhancement  FeedbackType = "enhancement"
	FeedbackTypeQuestion     FeedbackType = "question"
	FeedbackTypePerformance  FeedbackType = "performance"
)

// FeedbackSeverity defines the severity of feedback
type FeedbackSeverity string

const (
	SeverityCritical FeedbackSeverity = "critical"
	SeverityHigh     FeedbackSeverity = "high"
	SeverityMedium   FeedbackSeverity = "medium"
	SeverityLow      FeedbackSeverity = "low"
	SeverityInfo     FeedbackSeverity = "info"
)

// FeedbackStatus defines the current status of feedback
type FeedbackStatus string

const (
	StatusNew        FeedbackStatus = "new"
	StatusAcknowledged FeedbackStatus = "acknowledged"
	StatusInProgress  FeedbackStatus = "in-progress"
	StatusResolved    FeedbackStatus = "resolved"
	StatusWontFix     FeedbackStatus = "wont-fix"
	StatusDuplicate   FeedbackStatus = "duplicate"
)

// CommunityFeedbackRegistry manages community feedback
type CommunityFeedbackRegistry struct {
	feedback   []CommunityFeedback
	mu         sync.RWMutex
	feedbackDir string
	nextID     int
}

// NewCommunityFeedbackRegistry creates a new feedback registry
func NewCommunityFeedbackRegistry(feedbackDir string) *CommunityFeedbackRegistry {
	registry := &CommunityFeedbackRegistry{
		feedback:   make([]CommunityFeedback, 0),
		feedbackDir: feedbackDir,
		nextID:     1,
	}

	// Ensure feedback directory exists
	if feedbackDir != "" {
		os.MkdirAll(feedbackDir, 0755)
	}

	return registry
}

// AddFeedback adds new feedback to the registry
func (r *CommunityFeedbackRegistry) AddFeedback(feedback *CommunityFeedback) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if feedback.ID == "" {
		feedback.ID = fmt.Sprintf("FEEDBACK-%d", r.nextID)
		r.nextID++
	}

	if feedback.CreatedAt.IsZero() {
		feedback.CreatedAt = time.Now()
	}
	feedback.UpdatedAt = feedback.CreatedAt

	if feedback.Status == "" {
		feedback.Status = StatusNew
	}

	r.feedback = append(r.feedback, *feedback)
	return nil

	// Save to file if directory is configured
	if r.feedbackDir != "" {
		return r.saveFeedbackToFile(*feedback)
	}

	return nil
}

// saveFeedbackToFile saves feedback to a JSON file
func (r *CommunityFeedbackRegistry) saveFeedbackToFile(feedback CommunityFeedback) error {
	filename := filepath.Join(r.feedbackDir, fmt.Sprintf("%s.json", feedback.ID))
	
	data, err := json.MarshalIndent(feedback, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal feedback: %v", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write feedback file: %v", err)
	}

	return nil
}

// GetFeedback returns feedback by ID
func (r *CommunityFeedbackRegistry) GetFeedback(id string) (*CommunityFeedback, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i, feedback := range r.feedback {
		if feedback.ID == id {
			return &r.feedback[i], nil
		}
	}

	return nil, fmt.Errorf("feedback not found: %s", id)
}

// GetAllFeedback returns all feedback
func (r *CommunityFeedbackRegistry) GetAllFeedback() []CommunityFeedback {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]CommunityFeedback, len(r.feedback))
	copy(result, r.feedback)
	return result
}

// GetFeedbackByStatus returns feedback filtered by status
func (r *CommunityFeedbackRegistry) GetFeedbackByStatus(status FeedbackStatus) []CommunityFeedback {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]CommunityFeedback, 0)
	for _, feedback := range r.feedback {
		if feedback.Status == status {
			result = append(result, feedback)
		}
	}
	return result
}

// GetFeedbackBySeverity returns feedback filtered by severity
func (r *CommunityFeedbackRegistry) GetFeedbackBySeverity(severity FeedbackSeverity) []CommunityFeedback {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]CommunityFeedback, 0)
	for _, feedback := range r.feedback {
		if feedback.Severity == severity {
			result = append(result, feedback)
		}
	}
	return result
}

// GetFeedbackByType returns feedback filtered by type
func (r *CommunityFeedbackRegistry) GetFeedbackByType(fbType FeedbackType) []CommunityFeedback {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]CommunityFeedback, 0)
	for _, feedback := range r.feedback {
		if feedback.Type == fbType {
			result = append(result, feedback)
		}
	}
	return result
}

// UpdateFeedbackStatus updates the status of a feedback item
func (r *CommunityFeedbackRegistry) UpdateFeedbackStatus(id string, status FeedbackStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, feedback := range r.feedback {
		if feedback.ID == id {
			r.feedback[i].Status = status
			r.feedback[i].UpdatedAt = time.Now()

			if status == StatusResolved {
				tnow := time.Now()
				r.feedback[i].ResolvedAt = &tnow
			}

			// Update file if directory is configured
			if r.feedbackDir != "" {
				return r.saveFeedbackToFile(r.feedback[i])
			}

			return nil
		}
	}

	return fmt.Errorf("feedback not found: %s", id)
}

// UpdateFeedback adds or updates feedback in the registry
func (r *CommunityFeedbackRegistry) UpdateFeedback(feedback CommunityFeedback) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Find existing feedback
	for i, existing := range r.feedback {
		if existing.ID == feedback.ID {
			feedback.CreatedAt = existing.CreatedAt
			if feedback.UpdatedAt.IsZero() {
				feedback.UpdatedAt = time.Now()
			}

			r.feedback[i] = feedback

			// Update file if directory is configured
			if r.feedbackDir != "" {
				return r.saveFeedbackToFile(feedback)
			}

			return nil
		}
	}

	// If not found, add as new feedback
	return r.AddFeedback(&feedback)
}

// LoadFeedbackFromFile loads feedback from a JSON file
func (r *CommunityFeedbackRegistry) LoadFeedbackFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read feedback file: %v", err)
	}

	var feedback CommunityFeedback
	err = json.Unmarshal(data, &feedback)
	if err != nil {
		return fmt.Errorf("failed to unmarshal feedback: %v", err)
	}

	err = r.AddFeedback(&feedback)
	if err != nil {
		return fmt.Errorf("failed to add feedback: %v", err)
	}

	return nil
}

// LoadAllFeedbackFromDirectory loads all feedback from a directory
func (r *CommunityFeedbackRegistry) LoadAllFeedbackFromDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read feedback directory: %v", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			filename := filepath.Join(dir, entry.Name())
			err = r.LoadFeedbackFromFile(filename)
			if err != nil {
				// Continue on error, don't stop loading
				continue
			}
		}
	}

	return nil
}

// FeedbackSummary provides a summary of all feedback
func (r *CommunityFeedbackRegistry) FeedbackSummary() FeedbackSummary {
	r.mu.RLock()
	defer r.mu.RUnlock()

	summary := FeedbackSummary{
		Total:          len(r.feedback),
		ByStatus:       make(map[FeedbackStatus]int),
		BySeverity:     make(map[FeedbackSeverity]int),
		ByType:         make(map[FeedbackType]int),
		OpenIssues:     0,
		CriticalIssues: 0,
	}

	for _, feedback := range r.feedback {
		summary.ByStatus[feedback.Status]++
		summary.BySeverity[feedback.Severity]++
		summary.ByType[feedback.Type]++

		if feedback.Status != StatusResolved && feedback.Status != StatusWontFix {
			summary.OpenIssues++
		}

		if feedback.Severity == SeverityCritical && feedback.Status != StatusResolved {
			summary.CriticalIssues++
		}
	}

	return summary
}

// FeedbackSummary contains summary statistics about feedback
type FeedbackSummary struct {
	Total          int                    `json:"total"`
	OpenIssues     int                    `json:"open_issues"`
	CriticalIssues int                    `json:"critical_issues"`
	ByStatus       map[FeedbackStatus]int `json:"by_status"`
	BySeverity     map[FeedbackSeverity]int `json:"by_severity"`
	ByType         map[FeedbackType]int    `json:"by_type"`
}

// CommunityFeedbackIntegration provides integration with community feedback systems
type CommunityFeedbackIntegration struct {
	registry       *CommunityFeedbackRegistry
	githubIssues   bool
	w3cDiscussions bool
	communityForums bool
}

// NewCommunityFeedbackIntegration creates a new community feedback integration
func NewCommunityFeedbackIntegration(feedbackDir string) *CommunityFeedbackIntegration {
	return &CommunityFeedbackIntegration{
		registry:       NewCommunityFeedbackRegistry(feedbackDir),
		githubIssues:   true,
		w3cDiscussions: true,
		communityForums: true,
	}
}

// AddCompatibilityFeedback adds feedback specifically related to compatibility
func (c *CommunityFeedbackIntegration) AddCompatibilityFeedback(title, description, affectedClient, relatedSpec string, severity FeedbackSeverity) (*CommunityFeedback, error) {
	feedback := CommunityFeedback{
		Type:           FeedbackTypeCompatibility,
		Title:          title,
		Description:    description,
		Source:         "internal",
		Severity:       severity,
		Status:         StatusNew,
		AffectedClient: affectedClient,
		RelatedSpec:    relatedSpec,
		Tags:           []string{"compatibility", "testing"},
		Priority:       severityToPriority(severity),
	}

	// Add feedback to registry - this will set the ID and timestamps
	err := c.registry.AddFeedback(&feedback)
	if err != nil {
		return nil, err
	}

	// Get the most recently added feedback (which should be ours)
	allFeedback := c.registry.GetAllFeedback()
	if len(allFeedback) == 0 {
		return nil, fmt.Errorf("no feedback found after adding")
	}

	// Return the last added feedback
	return &allFeedback[len(allFeedback)-1], nil
}

// severityToPriority converts severity to priority
func severityToPriority(severity FeedbackSeverity) int {
	switch severity {
	case SeverityCritical:
		return 1
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 4
	case SeverityInfo:
		return 5
	default:
		return 3
	}
}

// MarkFeedbackAsAddressed marks feedback as addressed with a resolution
func (c *CommunityFeedbackIntegration) MarkFeedbackAsAddressed(id, resolution string) error {
	feedback, err := c.registry.GetFeedback(id)
	if err != nil {
		return err
	}

	feedback.Resolution = resolution
	feedback.Status = StatusResolved
	feedback.UpdatedAt = time.Now()
	
	return c.registry.UpdateFeedback(*feedback)
}

// GetCompatibilityFeedback returns all compatibility-related feedback
func (c *CommunityFeedbackIntegration) GetCompatibilityFeedback() []CommunityFeedback {
	allFeedback := c.registry.GetAllFeedback()
	compatibilityFeedback := make([]CommunityFeedback, 0)

	for _, feedback := range allFeedback {
		if feedback.Type == FeedbackTypeCompatibility {
			compatibilityFeedback = append(compatibilityFeedback, feedback)
		}
	}

	return compatibilityFeedback
}

// GenerateCompatibilityReport generates a report of compatibility issues
func (c *CommunityFeedbackIntegration) GenerateCompatibilityReport() CompatibilityFeedbackReport {
	compatibilityFeedback := c.GetCompatibilityFeedback()

	report := CompatibilityFeedbackReport{
		GeneratedAt:     time.Now(),
		TotalIssues:     len(compatibilityFeedback),
		OpenIssues:      0,
		CriticalIssues:  0,
		HighIssues:      0,
		IssuesByClient:  make(map[string]int),
		IssuesBySpec:    make(map[string]int),
		Feedback:        compatibilityFeedback,
	}

	for _, feedback := range compatibilityFeedback {
		if feedback.Status != StatusResolved && feedback.Status != StatusWontFix {
			report.OpenIssues++
			if feedback.Severity == SeverityCritical {
				report.CriticalIssues++
			} else if feedback.Severity == SeverityHigh {
				report.HighIssues++
			}
		}

		if feedback.AffectedClient != "" {
			report.IssuesByClient[feedback.AffectedClient]++
		}
		if feedback.RelatedSpec != "" {
			report.IssuesBySpec[feedback.RelatedSpec]++
		}
	}

	return report
}

// CompatibilityFeedbackReport contains a comprehensive report of compatibility issues
type CompatibilityFeedbackReport struct {
	GeneratedAt     time.Time             `json:"generated_at"`
	TotalIssues     int                  `json:"total_issues"`
	OpenIssues      int                  `json:"open_issues"`
	CriticalIssues  int                  `json:"critical_issues"`
	HighIssues      int                  `json:"high_issues"`
	IssuesByClient  map[string]int        `json:"issues_by_client"`
	IssuesBySpec    map[string]int        `json:"issues_by_spec"`
	Feedback        []CommunityFeedback   `json:"feedback"`
}

// ExportToJSON exports the report to JSON
func (r *CompatibilityFeedbackReport) ExportToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// SaveReportToFile saves the report to a file
func (r *CompatibilityFeedbackReport) SaveReportToFile(filename string) error {
	data, err := r.ExportToJSON()
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// SolidEcosystemCompatibility tracks compatibility with the broader Solid ecosystem
type SolidEcosystemCompatibility struct {
	CSSVersion        string            `json:"css_version"`
	SolidServers      []SolidServerInfo `json:"solid_servers"`
	ClientLibraries    []ClientLibrary   `json:"client_libraries"`
	SupportedSpecs    []string          `json:"supported_specs"`
	CompatibilityNotes string            `json:"compatibility_notes"`
	LastUpdated        time.Time         `json:"last_updated"`
}

// SolidServerInfo contains information about a Solid server
type SolidServerInfo struct {
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	URL            string    `json:"url,omitempty"`
	Compatible     bool      `json:"compatible"`
	CompatibilityScore float64 `json:"compatibility_score"`
	Notes          string    `json:"notes,omitempty"`
}

// ClientLibrary contains information about a Solid client library
type ClientLibrary struct {
	Name           string    `json:"name"`
	Language       string    `json:"language"`
	Version        string    `json:"version"`
	Compatible     bool      `json:"compatible"`
	CompatibilityScore float64 `json:"compatibility_score"`
	Notes          string    `json:"notes,omitempty"`
}

// NewSolidEcosystemCompatibility creates a new ecosystem compatibility tracker
func NewSolidEcosystemCompatibility() *SolidEcosystemCompatibility {
	return &SolidEcosystemCompatibility{
		SolidServers: []SolidServerInfo{
			{Name: "CSS", Version: "7.0.0", Compatible: true, CompatibilityScore: 1.0, Notes: "Community Solid Server - Primary reference implementation"},
			{Name: "NSS", Version: "5.0.0", Compatible: true, CompatibilityScore: 0.95, Notes: "Node Solid Server"},
			{Name: "Gold", Version: "3.0.0", Compatible: true, CompatibilityScore: 0.85, Notes: "Go-based Solid Server"},
		},
		ClientLibraries: []ClientLibrary{
			{Name: "RDFLib.js", Language: "JavaScript", Version: "2.0.0", Compatible: true, CompatibilityScore: 0.98, Notes: "Comprehensive RDF library for JavaScript"},
			{Name: "Mashlib", Language: "TypeScript", Version: "1.0.0", Compatible: true, CompatibilityScore: 0.95, Notes: "Solid client library for TypeScript"},
			{Name: "Solid File Client", Language: "JavaScript", Version: "2.0.0", Compatible: true, CompatibilityScore: 0.92, Notes: "File management for Solid"},
			{Name: "Inrupt Solid Client Libraries", Language: "TypeScript", Version: "2.0.0", Compatible: true, CompatibilityScore: 0.90, Notes: "Enterprise Solid client libraries"},
		},
		SupportedSpecs: []string{
			"Solid Protocol 2023",
			"Web Access Control",
			"Access Control Policy",
			"Solid Application Interoperability",
			"WebID",
			"Solid-OIDC",
			"DPoP",
		},
		CSSVersion: "7.0.0",
		LastUpdated: time.Now(),
	}
}

// AddCompatibilityTestResult adds a compatibility test result to the ecosystem tracker
func (s *SolidEcosystemCompatibility) AddCompatibilityTestResult(serverName, clientName, specName string, score float64, notes string) {
	// Update server compatibility
	for i, server := range s.SolidServers {
		if server.Name == serverName {
			s.SolidServers[i].CompatibilityScore = score
			s.SolidServers[i].Notes += " | " + notes
			break
		}
	}

	// Update client compatibility
	for i, client := range s.ClientLibraries {
		if client.Name == clientName {
			s.ClientLibraries[i].CompatibilityScore = score
			s.ClientLibraries[i].Notes += " | " + notes
			break
		}
	}

	// Ensure spec is tracked
	found := false
	for _, spec := range s.SupportedSpecs {
		if spec == specName {
			found = true
			break
		}
	}
	if !found {
		s.SupportedSpecs = append(s.SupportedSpecs, specName)
	}

	s.LastUpdated = time.Now()
}

// GenerateEcosystemReport generates a comprehensive ecosystem compatibility report
func (s *SolidEcosystemCompatibility) GenerateEcosystemReport() SolidEcosystemReport {
	return SolidEcosystemReport{
		SolidEcosystemCompatibility: *s,
		GeneratedAt:                 time.Now(),
		OverallScore:               s.calculateOverallScore(),
		Recommendations:            s.generateRecommendations(),
	}
}

// calculateOverallScore calculates the overall compatibility score
func (s *SolidEcosystemCompatibility) calculateOverallScore() float64 {
	if len(s.SolidServers) == 0 {
		return 0
	}

	totalScore := 0.0
	for _, server := range s.SolidServers {
		if server.Compatible {
			totalScore += server.CompatibilityScore
		}
	}

	return totalScore / float64(len(s.SolidServers))
}

// generateRecommendations generates compatibility recommendations
func (s *SolidEcosystemCompatibility) generateRecommendations() []string {
	recommendations := []string{}

	// Check for low compatibility scores
	for _, server := range s.SolidServers {
		if server.CompatibilityScore < 0.8 {
			recommendations = append(recommendations, fmt.Sprintf("Improve compatibility with %s (current score: %.2f)", server.Name, server.CompatibilityScore))
		}
	}

	for _, client := range s.ClientLibraries {
		if client.CompatibilityScore < 0.8 {
			recommendations = append(recommendations, fmt.Sprintf("Improve compatibility with %s (current score: %.2f)", client.Name, client.CompatibilityScore))
		}
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "All ecosystem compatibility scores are good!")
	}

	return recommendations
}

// SolidEcosystemReport contains a comprehensive ecosystem compatibility report
type SolidEcosystemReport struct {
	SolidEcosystemCompatibility
	GeneratedAt    time.Time  `json:"generated_at"`
	OverallScore   float64    `json:"overall_score"`
	Recommendations []string   `json:"recommendations"`
}

// ExportToJSON exports the ecosystem report to JSON
func (r *SolidEcosystemReport) ExportToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// SaveReportToFile saves the ecosystem report to a file
func (r *SolidEcosystemReport) SaveReportToFile(filename string) error {
	data, err := r.ExportToJSON()
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
