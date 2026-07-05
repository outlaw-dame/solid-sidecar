// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements tenant-specific audit logging with partitioning and retention.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuditLogRetentionPolicy defines retention policy for audit logs
type AuditLogRetentionPolicy struct {
	// MaxAge is the maximum age of audit log entries to retain
	MaxAge time.Duration

	// MaxSize is the maximum total size of audit log entries to retain (0 = unlimited)
	MaxSize int64

	// MaxEntries is the maximum number of audit log entries to retain (0 = unlimited)
	MaxEntries int

	// RetentionCheckInterval is how often to check for entries to remove
	RetentionCheckInterval time.Duration

	// CompressionEnabled enables compression of audit log files
	CompressionEnabled bool

	// EncryptionEnabled enables encryption of audit log files (requires key configuration)
	EncryptionEnabled bool

	// PartitionStrategy defines how audit logs are partitioned
	PartitionStrategy AuditLogPartitionStrategy
}

// AuditLogPartitionStrategy defines how audit logs are partitioned
type AuditLogPartitionStrategy string

const (
	// AuditLogPartitionByTenant partitions audit logs by tenant
	AuditLogPartitionByTenant AuditLogPartitionStrategy = "by_tenant"

	// AuditLogPartitionByDay partitions audit logs by day
	AuditLogPartitionByDay AuditLogPartitionStrategy = "by_day"

	// AuditLogPartitionByHour partitions audit logs by hour
	AuditLogPartitionByHour AuditLogPartitionStrategy = "by_hour"

	// AuditLogPartitionByTenantAndDay partitions audit logs by tenant and day
	AuditLogPartitionByTenantAndDay AuditLogPartitionStrategy = "by_tenant_and_day"

	// AuditLogPartitionNone uses a single log file (not recommended for multi-tenant)
	AuditLogPartitionNone AuditLogPartitionStrategy = "none"
)

// DefaultAuditLogRetentionPolicy returns a safe default retention policy
func DefaultAuditLogRetentionPolicy() AuditLogRetentionPolicy {
	return AuditLogRetentionPolicy{
		MaxAge:                 90 * 24 * time.Hour, // 90 days
		MaxSize:                10 * 1024 * 1024 * 1024, // 10 GB
		MaxEntries:             1000000, // 1 million entries
		RetentionCheckInterval: 24 * time.Hour, // Check daily
		CompressionEnabled:     true,
		EncryptionEnabled:      false,
		PartitionStrategy:      AuditLogPartitionByTenantAndDay,
	}
}

// AuditLogEntry represents a single audit log entry
type AuditLogEntry struct {
	// ID is a unique identifier for this entry
	ID string

	// Timestamp is when the event occurred
	Timestamp time.Time

	// TenantID is the tenant associated with this event (empty for system events)
	TenantID string

	// UserID is the user who performed the action (if applicable)
	UserID string

	// Action is the type of action performed
	Action AuditLogAction

	// ResourceType is the type of resource affected
	ResourceType string

	// ResourceURI is the URI of the resource affected
	ResourceURI string

	// Status indicates success or failure
	Status AuditLogStatus

	// Details contains additional event-specific information
	Details map[string]interface{}

	// IPAddress is the IP address of the client
	IPAddress string

	// UserAgent is the user agent of the client
	UserAgent string

	// SessionID is the session identifier (if applicable)
	SessionID string

	// RequestID is a correlation ID for tracing
	RequestID string
}

// AuditLogAction represents the type of action performed
type AuditLogAction string

const (
	// AuditLogActionCreate represents resource creation
	AuditLogActionCreate AuditLogAction = "CREATE"

	// AuditLogActionRead represents resource read/access
	AuditLogActionRead AuditLogAction = "READ"

	// AuditLogActionUpdate represents resource update/modification
	AuditLogActionUpdate AuditLogAction = "UPDATE"

	// AuditLogActionDelete represents resource deletion
	AuditLogActionDelete AuditLogAction = "DELETE"

	// AuditLogActionLogin represents user authentication
	AuditLogActionLogin AuditLogAction = "LOGIN"

	// AuditLogActionLogout represents user logout
	AuditLogActionLogout AuditLogAction = "LOGOUT"

	// AuditLogActionAdmin represents administrative action
	AuditLogActionAdmin AuditLogAction = "ADMIN"

	// AuditLogActionConfig represents configuration change
	AuditLogActionConfig AuditLogAction = "CONFIG"

	// AuditLogActionSecurity represents security-related event
	AuditLogActionSecurity AuditLogAction = "SECURITY"

	// AuditLogActionAccessDenied represents an access denied event
	AuditLogActionAccessDenied AuditLogAction = "ACCESS_DENIED"
)

// AuditLogStatus represents the status of the action
type AuditLogStatus string

const (
	// AuditLogStatusSuccess indicates the action was successful
	AuditLogStatusSuccess AuditLogStatus = "SUCCESS"

	// AuditLogStatusFailure indicates the action failed
	AuditLogStatusFailure AuditLogStatus = "FAILURE"

	// AuditLogStatusPartial indicates the action partially succeeded
	AuditLogStatusPartial AuditLogStatus = "PARTIAL"
)

// TenantAuditLogger provides tenant-specific audit logging with partitioning and retention
type TenantAuditLogger struct {
	mu sync.RWMutex

	// logger is the underlying logger
	logger *slog.Logger

	// retentionPolicy defines the retention policy
	retentionPolicy AuditLogRetentionPolicy

	// logDir is the directory for audit log files
	logDir string

	// entries is an in-memory buffer of recent entries
	entries []AuditLogEntry

	// entryIndex maps entry IDs to their position in entries
	entryIndex map[string]int

	// partitionWriters maps partition keys to file writers
	partitionWriters map[string]*auditLogWriter

	// close state
	closeChan chan struct{}
	closed    bool

	// metrics
	entriesLogged int64
	entriesRemoved int64
}

// auditLogWriter handles writing to a specific audit log file
type auditLogWriter struct {
	file     *os.File
	encoder  *json.Encoder
	filePath string
	size     int64
	entryCount int
}

// TenantAuditLoggerConfig holds configuration for the tenant audit logger
type TenantAuditLoggerConfig struct {
	// LogDir is the directory for audit log files
	LogDir string

	// RetentionPolicy defines the retention policy
	RetentionPolicy AuditLogRetentionPolicy

	// Logger is the logger for audit logging
	Logger *slog.Logger

	// EnableInMemoryBuffer enables in-memory buffering of recent entries
	EnableInMemoryBuffer bool

	// InMemoryBufferSize is the maximum number of entries to keep in memory
	InMemoryBufferSize int
}

// DefaultTenantAuditLoggerConfig returns a safe default configuration
func DefaultTenantAuditLoggerConfig() TenantAuditLoggerConfig {
	return TenantAuditLoggerConfig{
		LogDir:              "./var/log/audit",
		RetentionPolicy:     DefaultAuditLogRetentionPolicy(),
		Logger:              nil,
		EnableInMemoryBuffer: true,
		InMemoryBufferSize:   1000,
	}
}

// NewTenantAuditLogger creates a new tenant audit logger
func NewTenantAuditLogger(config TenantAuditLoggerConfig) *TenantAuditLogger {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	logger := &TenantAuditLogger{
		logger:           config.Logger,
		retentionPolicy: config.RetentionPolicy,
		logDir:          config.LogDir,
		entries:         make([]AuditLogEntry, 0, config.InMemoryBufferSize),
		entryIndex:      make(map[string]int),
		partitionWriters: make(map[string]*auditLogWriter),
		closeChan:       make(chan struct{}),
		closed:          false,
	}

	// Ensure log directory exists
	if err := os.MkdirAll(config.LogDir, 0750); err != nil {
		config.Logger.Error("Failed to create audit log directory", "error", err, "directory", config.LogDir)
	}

	// Start retention checker
	if config.RetentionPolicy.RetentionCheckInterval > 0 {
		go logger.runRetentionChecker()
	}

	config.Logger.Info("Tenant audit logger initialized",
		"log_dir", config.LogDir,
		"retention_policy", config.RetentionPolicy,
		"in_memory_buffer_enabled", config.EnableInMemoryBuffer,
		"in_memory_buffer_size", config.InMemoryBufferSize,
	)

	return logger
}

// runRetentionChecker runs the periodic retention check
func (al *TenantAuditLogger) runRetentionChecker() {
	ticker := time.NewTicker(al.retentionPolicy.RetentionCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := al.cleanupOldEntries(); err != nil {
				al.logger.Error("Failed to clean up old audit log entries", "error", err)
			}
		case <-al.closeChan:
			al.logger.Info("Audit log retention checker stopped")
			return
		}
	}
}

// cleanupOldEntries removes audit log entries that exceed the retention policy
func (al *TenantAuditLogger) cleanupOldEntries() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.closed {
		return errors.New("audit logger is closed")
	}

	cutoffTime := time.Now().Add(-al.retentionPolicy.MaxAge)
	var entriesToRemove []int

	// Find entries to remove from in-memory buffer
	for i, entry := range al.entries {
		if entry.Timestamp.Before(cutoffTime) {
			entriesToRemove = append(entriesToRemove, i)
		}
	}

	// Remove old entries from the end of the buffer (oldest entries)
	// We remove from the end because we append new entries to the end
	if len(entriesToRemove) > 0 {
		// Sort in reverse order to avoid index shifting issues
		sort.Sort(sort.Reverse(sort.IntSlice(entriesToRemove)))

		for _, index := range entriesToRemove {
			if index < len(al.entries) {
				entry := al.entries[index]
				delete(al.entryIndex, entry.ID)
				al.entries = append(al.entries[:index], al.entries[index+1:]...)
				al.entriesRemoved++
			}
		}

		al.logger.Info("Cleaned up audit log entries",
			"count", len(entriesToRemove),
			"cutoff_time", cutoffTime.Format(time.RFC3339),
		)
	}

	// Also clean up old files based on partition strategy
	if err := al.cleanupOldFiles(cutoffTime); err != nil {
		al.logger.Error("Failed to clean up old audit log files", "error", err)
		// Don't return error to continue with in-memory cleanup
	}

	return nil
}

// cleanupOldFiles removes old audit log files based on retention policy
func (al *TenantAuditLogger) cleanupOldFiles(cutoffTime time.Time) error {
	// Get all files in the log directory
	entries, err := os.ReadDir(al.logDir)
	if err != nil {
		return fmt.Errorf("failed to read audit log directory: %w", err)
	}

	var filesRemoved int

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Check if file is an audit log file
		if !strings.HasSuffix(entry.Name(), ".json") && !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}

		// Get file info to check modification time
		filePath := filepath.Join(al.logDir, entry.Name())
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		// Remove files older than cutoff
		if fileInfo.ModTime().Before(cutoffTime) {
			if err := os.Remove(filePath); err != nil {
				al.logger.Error("Failed to remove old audit log file",
					"file", filePath,
					"error", err)
			} else {
				filesRemoved++
				// Also remove from partition writers if present
				partitionKey := al.getPartitionKeyFromFilename(entry.Name())
				if partitionKey != "" {
					delete(al.partitionWriters, partitionKey)
				}
			}
		}
	}

	if filesRemoved > 0 {
		al.logger.Info("Cleaned up audit log files",
			"count", filesRemoved,
			"cutoff_time", cutoffTime.Format(time.RFC3339),
		)
	}

	return nil
}

// getPartitionKeyFromFilename extracts partition key from filename
func (al *TenantAuditLogger) getPartitionKeyFromFilename(filename string) string {
	// Remove file extension
	baseName := strings.TrimSuffix(filename, ".json")
	baseName = strings.TrimSuffix(baseName, ".log")

	// Split by separator
	parts := strings.Split(baseName, "_")
	if len(parts) >= 2 {
		return strings.Join(parts[:len(parts)-1], "_")
	}

	return baseName
}

// Log records an audit log entry
func (al *TenantAuditLogger) Log(entry AuditLogEntry) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.closed {
		return errors.New("audit logger is closed")
	}

	// Generate ID if not provided
	if entry.ID == "" {
		entry.ID = al.generateEntryID()
	}

	// Set timestamp if not provided
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Add to in-memory buffer if enabled
	if len(al.entries) < cap(al.entries) {
		al.entries = append(al.entries, entry)
		al.entryIndex[entry.ID] = len(al.entries) - 1
		al.entriesLogged++
	} else {
		// Buffer is full, remove oldest entry
		if len(al.entries) > 0 {
			oldestEntry := al.entries[0]
			delete(al.entryIndex, oldestEntry.ID)
			al.entries = al.entries[1:]
		}
		// Add new entry
		al.entries = append(al.entries, entry)
		al.entryIndex[entry.ID] = len(al.entries) - 1
		al.entriesLogged++
	}

	// Write to partition file
	if err := al.writeToPartition(entry); err != nil {
		al.logger.Error("Failed to write audit log entry to partition",
			"entry_id", entry.ID,
			"tenant_id", entry.TenantID,
			"error", err)
		// Don't return error to ensure entry is logged in memory
	}

	return nil
}

// generateEntryID generates a unique entry ID
func (al *TenantAuditLogger) generateEntryID() string {
	return fmt.Sprintf("audit-%s-%d",
		time.Now().UTC().Format("20060102-150405.999999"),
		al.entriesLogged+1)
}

// writeToPartition writes an entry to the appropriate partition file
func (al *TenantAuditLogger) writeToPartition(entry AuditLogEntry) error {
	// Determine partition key based on strategy
	partitionKey := al.getPartitionKey(entry)

	// Get or create writer for this partition
	writer, exists := al.partitionWriters[partitionKey]
	if !exists {
		var err error
		writer, err = al.createPartitionWriter(partitionKey)
		if err != nil {
			return fmt.Errorf("failed to create partition writer: %w", err)
		}
		al.partitionWriters[partitionKey] = writer
	}

	// Write entry
	if err := writer.encoder.Encode(entry); err != nil {
		return fmt.Errorf("failed to encode audit log entry: %w", err)
	}

	// Flush to ensure data is written
	if err := writer.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync audit log file: %w", err)
	}

	writer.entryCount++
	writer.size += estimateEntrySize(entry)

	return nil
}

// getPartitionKey determines the partition key for an entry
func (al *TenantAuditLogger) getPartitionKey(entry AuditLogEntry) string {
	switch al.retentionPolicy.PartitionStrategy {
	case AuditLogPartitionByTenant:
		return entry.TenantID

	case AuditLogPartitionByDay:
		return entry.Timestamp.UTC().Format("2006-01-02")

	case AuditLogPartitionByHour:
		return entry.Timestamp.UTC().Format("2006-01-02-15")

	case AuditLogPartitionByTenantAndDay:
		if entry.TenantID != "" {
			return fmt.Sprintf("%s_%s", entry.TenantID, entry.Timestamp.UTC().Format("2006-01-02"))
		}
		return entry.Timestamp.UTC().Format("2006-01-02")

	case AuditLogPartitionNone:
		return "audit"

	default:
		return "audit"
	}
}

// createPartitionWriter creates a writer for a specific partition
func (al *TenantAuditLogger) createPartitionWriter(partitionKey string) (*auditLogWriter, error) {
	// Sanitize partition key for use in filename
	safeKey := sanitizePartitionKey(partitionKey)
	filename := fmt.Sprintf("%s.json", safeKey)
	filePath := filepath.Join(al.logDir, filename)

	// Open file in append mode
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	// Get current file size
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat audit log file: %w", err)
	}

	// Count existing entries (approximate)
	entryCount := 0
	if fileInfo.Size() > 0 {
		// Estimate entry count based on average entry size
		// This is an approximation for metrics purposes
		entryCount = int(fileInfo.Size() / 512) // Approximate 512 bytes per entry
	}

	writer := &auditLogWriter{
		file:      file,
		encoder:   json.NewEncoder(file),
		filePath:  filePath,
		size:      fileInfo.Size(),
		entryCount: entryCount,
	}

	al.logger.Debug("Created audit log partition writer",
		"partition_key", partitionKey,
		"file_path", filePath,
		"existing_size", fileInfo.Size(),
		"existing_entries", entryCount,
	)

	return writer, nil
}

// sanitizePartitionKey sanitizes a partition key for use in a filename
func sanitizePartitionKey(key string) string {
	// Replace characters that are not safe for filenames
	key = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, key)

	// Limit length
	if len(key) > 100 {
		key = key[:100]
	}

	return key
}

// estimateEntrySize estimates the size of an audit log entry in bytes
func estimateEntrySize(entry AuditLogEntry) int64 {
	// Rough estimate based on typical entry size
	baseSize := 200 // Base size for fixed fields
	
	// Add size for variable fields
	baseSize += len(entry.TenantID) * 2
	baseSize += len(entry.UserID) * 2
	baseSize += len(entry.Action) * 2
	baseSize += len(entry.ResourceType) * 2
	baseSize += len(entry.ResourceURI) * 2
	baseSize += len(entry.Status) * 2
	baseSize += len(entry.IPAddress) * 2
	baseSize += len(entry.UserAgent) * 2
	baseSize += len(entry.SessionID) * 2
	baseSize += len(entry.RequestID) * 2
	
	// Add size for details (estimate)
	baseSize += 100 // Estimated size for details
	
	return int64(baseSize)
}

// Query retrieves audit log entries matching the specified criteria
func (al *TenantAuditLogger) Query(ctx context.Context, query AuditLogQuery) ([]AuditLogEntry, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if al.closed {
		return nil, errors.New("audit logger is closed")
	}

	var results []AuditLogEntry

	// Search in-memory buffer first
	for _, entry := range al.entries {
		if al.matchQuery(entry, query) {
			results = append(results, entry)
		}
	}

	// If we need more results or if in-memory buffer is disabled, search files
	// For now, we only return in-memory results
	// In a production implementation, this would also search the partition files

	return results, nil
}

// matchQuery checks if an entry matches the query criteria
func (al *TenantAuditLogger) matchQuery(entry AuditLogEntry, query AuditLogQuery) bool {
	// Match tenant ID
	if query.TenantID != "" && entry.TenantID != query.TenantID {
		return false
	}

	// Match user ID
	if query.UserID != "" && entry.UserID != query.UserID {
		return false
	}

	// Match action
	if query.Action != "" && entry.Action != query.Action {
		return false
	}

	// Match resource type
	if query.ResourceType != "" && entry.ResourceType != query.ResourceType {
		return false
	}

	// Match resource URI (prefix match)
	if query.ResourceURI != "" && !strings.HasPrefix(entry.ResourceURI, query.ResourceURI) {
		return false
	}

	// Match status
	if query.Status != "" && entry.Status != query.Status {
		return false
	}

	// Match time range
	if !query.StartTime.IsZero() && entry.Timestamp.Before(query.StartTime) {
		return false
	}

	if !query.EndTime.IsZero() && entry.Timestamp.After(query.EndTime) {
		return false
	}

	// Match IP address
	if query.IPAddress != "" && entry.IPAddress != query.IPAddress {
		return false
	}

	return true
}

// AuditLogQuery defines criteria for querying audit logs
type AuditLogQuery struct {
	// TenantID filters by tenant
	TenantID string

	// UserID filters by user
	UserID string

	// Action filters by action type
	Action AuditLogAction

	// ResourceType filters by resource type
	ResourceType string

	// ResourceURI filters by resource URI (prefix match)
	ResourceURI string

	// Status filters by status
	Status AuditLogStatus

	// StartTime filters entries after this time
	StartTime time.Time

	// EndTime filters entries before this time
	EndTime time.Time

	// IPAddress filters by client IP address
	IPAddress string

	// MaxEntries limits the number of results
	MaxEntries int

	// PageToken for pagination
	PageToken string
}

// Close closes the audit logger
func (al *TenantAuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.closed {
		return nil
	}

	al.closed = true
	close(al.closeChan)

	// Close all partition writers
	for _, writer := range al.partitionWriters {
		if err := writer.file.Close(); err != nil {
			al.logger.Error("Failed to close audit log partition file", "error", err)
		}
	}

	al.partitionWriters = make(map[string]*auditLogWriter)
	al.entries = nil
	al.entryIndex = make(map[string]int)

	al.logger.Info("Tenant audit logger closed",
		"entries_logged", al.entriesLogged,
		"entries_removed", al.entriesRemoved,
	)

	return nil
}

// IsClosed returns true if the logger is closed
func (al *TenantAuditLogger) IsClosed() bool {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return al.closed
}

// ExportTenantAuditLogs exports audit logs for a specific tenant
func (al *TenantAuditLogger) ExportTenantAuditLogs(tenantID string, writer io.Writer, startTime, endTime time.Time) error {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if al.closed {
		return errors.New("audit logger is closed")
	}

	// Find all files for this tenant
	entries, err := os.ReadDir(al.logDir)
	if err != nil {
		return fmt.Errorf("failed to read audit log directory: %w", err)
	}

	// Determine partition key pattern for this tenant
	partitionPrefix := sanitizePartitionKey(tenantID) + "_"

	// Export entries from in-memory buffer
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")

	// First, export entries from in-memory buffer
	for _, entry := range al.entries {
		if entry.TenantID == tenantID {
			if (startTime.IsZero() || !entry.Timestamp.Before(startTime)) &&
				(endTime.IsZero() || !entry.Timestamp.After(endTime)) {
				if err := encoder.Encode(entry); err != nil {
					return fmt.Errorf("failed to encode audit log entry: %w", err)
				}
			}
		}
	}

	// Then export from files
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if !strings.Contains(filename, partitionPrefix) && !strings.HasPrefix(filename, partitionPrefix) {
			continue
		}

		filePath := filepath.Join(al.logDir, filename)
		file, err := os.Open(filePath)
		if err != nil {
			continue
		}

		// Read and write file contents
		if _, err := io.Copy(writer, file); err != nil {
			file.Close()
			continue
		}

		file.Close()
	}

	return nil
}

// DeleteTenantAuditLogs deletes audit logs for a specific tenant
func (al *TenantAuditLogger) DeleteTenantAuditLogs(tenantID string) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.closed {
		return errors.New("audit logger is closed")
	}

	// Determine partition key pattern for this tenant
	partitionPrefix := sanitizePartitionKey(tenantID)

	// Get all files in the log directory
	entries, err := os.ReadDir(al.logDir)
	if err != nil {
		return fmt.Errorf("failed to read audit log directory: %w", err)
	}

	var filesRemoved int

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if strings.Contains(filename, partitionPrefix) || strings.HasPrefix(filename, partitionPrefix) {
			filePath := filepath.Join(al.logDir, filename)
			if err := os.Remove(filePath); err != nil {
				al.logger.Error("Failed to remove audit log file",
					"file", filePath,
					"error", err)
			} else {
				filesRemoved++
				// Remove from partition writers
				partitionKey := al.getPartitionKeyFromFilename(filename)
				delete(al.partitionWriters, partitionKey)
			}
		}
	}

	// Remove from in-memory buffer
	var newEntries []AuditLogEntry
	for _, entry := range al.entries {
		if entry.TenantID != tenantID {
			newEntries = append(newEntries, entry)
		}
	}
	al.entries = newEntries

	// Rebuild entry index
	al.entryIndex = make(map[string]int)
	for i, entry := range al.entries {
		al.entryIndex[entry.ID] = i
	}

	al.logger.Info("Deleted tenant audit logs",
		"tenant_id", tenantID,
		"files_removed", filesRemoved,
	)

	return nil
}

// GetMetrics returns metrics about the audit logger
func (al *TenantAuditLogger) GetMetrics() TenantAuditMetrics {
	al.mu.RLock()
	defer al.mu.RUnlock()

	return TenantAuditMetrics{
		EntriesLogged:   al.entriesLogged,
		EntriesRemoved:  al.entriesRemoved,
		InMemoryCount:   int64(len(al.entries)),
		PartitionCount:  int64(len(al.partitionWriters)),
		RetentionPolicy: al.retentionPolicy,
	}
}

// TenantAuditMetrics holds metrics about tenant audit logging
type TenantAuditMetrics struct {
	// EntriesLogged is the total number of entries logged
	EntriesLogged int64

	// EntriesRemoved is the total number of entries removed by retention
	EntriesRemoved int64

	// InMemoryCount is the current number of entries in the in-memory buffer
	InMemoryCount int64

	// PartitionCount is the number of active partitions
	PartitionCount int64

	// RetentionPolicy is the current retention policy
	RetentionPolicy AuditLogRetentionPolicy
}

// LogTenantAccessDenied logs an access denied event for a tenant
func (al *TenantAuditLogger) LogTenantAccessDenied(tenantID, userID, resourceURI, reason string, details map[string]interface{}) error {
	entry := AuditLogEntry{
		TenantID:    tenantID,
		UserID:      userID,
		Action:      AuditLogActionAccessDenied,
		ResourceURI: resourceURI,
		Status:      AuditLogStatusFailure,
		Details:     details,
	}

	// Add reason to details
	if entry.Details == nil {
		entry.Details = make(map[string]interface{})
	}
	entry.Details["reason"] = reason

	return al.Log(entry)
}

// LogTenantResourceAccess logs resource access for a tenant
func (al *TenantAuditLogger) LogTenantResourceAccess(tenantID, userID, action, resourceType, resourceURI, status string) error {
	entry := AuditLogEntry{
		TenantID:     tenantID,
		UserID:       userID,
		Action:       AuditLogAction(action),
		ResourceType: resourceType,
		ResourceURI:  resourceURI,
		Status:       AuditLogStatus(status),
	}

	return al.Log(entry)
}

// LogTenantAdminAction logs an administrative action for a tenant
func (al *TenantAuditLogger) LogTenantAdminAction(tenantID, adminUserID, action, details string) error {
	entry := AuditLogEntry{
		TenantID:   tenantID,
		UserID:     adminUserID,
		Action:     AuditLogActionAdmin,
		Status:     AuditLogStatusSuccess,
		Details: map[string]interface{}{
			"action":  action,
			"details": details,
		},
	}

	return al.Log(entry)
}

// LogTenantConfigChange logs a configuration change for a tenant
func (al *TenantAuditLogger) LogTenantConfigChange(tenantID, adminUserID, changeType, oldValue, newValue string) error {
	entry := AuditLogEntry{
		TenantID:   tenantID,
		UserID:     adminUserID,
		Action:     AuditLogActionConfig,
		Status:     AuditLogStatusSuccess,
		Details: map[string]interface{}{
			"change_type": changeType,
			"old_value":   oldValue,
			"new_value":   newValue,
		},
	}

	return al.Log(entry)
}

// LogTenantAuthEvent logs an authentication event for a tenant
func (al *TenantAuditLogger) LogTenantAuthEvent(tenantID, userID, action string, success bool, failureReason string) error {
	entry := AuditLogEntry{
		TenantID:   tenantID,
		UserID:     userID,
		Action:     AuditLogAction(action),
		Status:     AuditLogStatusSuccess,
		Details:    make(map[string]interface{}),
	}

	if !success {
		entry.Status = AuditLogStatusFailure
		entry.Details["reason"] = failureReason
	}

	return al.Log(entry)
}