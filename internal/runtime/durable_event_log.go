// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 6.6: Durable event log for Phase 24 notifications productionization.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrDurableLogClosed is returned when the durable log is closed
var ErrDurableLogClosed = errors.New("durable event log is closed")

// ErrEventNotFound is returned when an event is not found in the log
var ErrEventNotFound = errors.New("event not found")

// ErrLogCorruption is returned when the log file is corrupted
var ErrLogCorruption = errors.New("log file corruption detected")

// ErrStorageFull is returned when storage limits are reached
var ErrStorageFull = errors.New("storage limits reached")

// ErrInvalidConfig is returned when the configuration is invalid
var ErrInvalidConfig = errors.New("invalid configuration")

// validateDurableLogConfig validates the durable event log configuration
func validateDurableLogConfig(config *DurableEventLogConfig) error {
	// Validate log directory
	if config.LogDirectory == "" {
		return fmt.Errorf("%w: log directory cannot be empty", ErrInvalidConfig)
	}

	// Validate sizes are positive
	if config.MaxLogSize <= 0 {
		return fmt.Errorf("%w: max log size must be positive", ErrInvalidConfig)
	}

	if config.MaxTotalSize <= 0 {
		return fmt.Errorf("%w: max total size must be positive", ErrInvalidConfig)
	}

	// Validate max log size is not larger than max total size
	if config.MaxLogSize > config.MaxTotalSize {
		return fmt.Errorf("%w: max log size cannot be larger than max total size", ErrInvalidConfig)
	}

	// Validate retention time is positive
	if config.RetentionTime <= 0 {
		return fmt.Errorf("%w: retention time must be positive", ErrInvalidConfig)
	}

	// Validate flush interval is positive
	if config.FlushInterval <= 0 {
		return fmt.Errorf("%w: flush interval must be positive", ErrInvalidConfig)
	}

	// Validate max events per file is positive
	if config.MaxEventsPerFile <= 0 {
		return fmt.Errorf("%w: max events per file must be positive", ErrInvalidConfig)
	}

	// Security: Validate log directory path
	cleanedPath := filepath.Clean(config.LogDirectory)
	if filepath.IsAbs(cleanedPath) && !strings.HasPrefix(cleanedPath, "/var") && !strings.HasPrefix(cleanedPath, "/tmp") && !strings.HasPrefix(cleanedPath, "/opt") {
		return fmt.Errorf("%w: log directory must be in a safe location", ErrInvalidConfig)
	}

	return nil
}

// DurableEventLogConfig holds configuration for the durable event log
type DurableEventLogConfig struct {
	// LogDirectory is the directory where log files are stored
	LogDirectory string

	// MaxLogSize is the maximum size of each log file in bytes
	MaxLogSize int64

	// MaxTotalSize is the maximum total size of all log files in bytes
	MaxTotalSize int64

	// RetentionTime is how long to keep log files
	RetentionTime time.Duration

	// FlushInterval is how often to flush to disk
	FlushInterval time.Duration

	// SyncWrites enables synchronous writes (slower but more durable)
	SyncWrites bool

	// EnableCompression enables log file compression
	EnableCompression bool

	// MaxEventsPerFile is the maximum number of events per log file
	MaxEventsPerFile int

	// EnableEncryption enables log file encryption at rest
	EnableEncryption bool

	// Logger is the logger for this component
	Logger *slog.Logger
}

// DefaultDurableEventLogConfig returns a safe default configuration
func DefaultDurableEventLogConfig() DurableEventLogConfig {
	return DurableEventLogConfig{
		LogDirectory:      "/var/lib/solid-sidecar/events",
		MaxLogSize:        100 * 1024 * 1024,       // 100MB per file
		MaxTotalSize:      10 * 1024 * 1024 * 1024, // 10GB total
		RetentionTime:     7 * 24 * time.Hour,      // 7 days
		FlushInterval:     5 * time.Second,
		SyncWrites:        false,
		EnableCompression: false,
		MaxEventsPerFile:  100000,
		EnableEncryption:  false,
		Logger:            nil,
	}
}

// LogEntry represents a single entry in the durable event log
type LogEntry struct {
	// EventID is the unique identifier for this event
	EventID string

	// EventType is the type of event
	EventType NotificationEventType

	// ResourceURI is the URI of the affected resource
	ResourceURI string

	// ContainerURI is the URI of the container containing the resource
	ContainerURI string

	// Timestamp is when the event occurred
	Timestamp time.Time

	// Agent is the agent that caused the event
	Agent string

	// AgentType is the type of agent
	AgentType PolicyAgentType

	// Action is the specific action that occurred
	Action string

	// Metadata contains additional event metadata
	Metadata map[string]string

	// SequenceNumber is the global sequence number
	SequenceNumber int64

	// StreamTimestamp is when the event was logged
	StreamTimestamp time.Time

	// PrivacyLevel indicates the privacy sensitivity
	PrivacyLevel PrivacyLevel

	// Checksum is a checksum for data integrity verification
	Checksum string
}

// DurableEventLog implements a durable event log for Solid notifications
type DurableEventLog struct {
	mu sync.RWMutex

	config DurableEventLogConfig

	// Current write position
	currentFile       *os.File
	currentFilePath   string
	currentFileSize   int64
	currentEventCount int

	// Log file metadata
	logFiles []LogFileInfo

	// Event counter for sequence numbers
	sequenceCounter int64

	// Index for fast lookup (eventID -> file offset)
	index map[string]EventIndexEntry

	// Logger
	logger *slog.Logger

	// Close state
	closeChan chan struct{}
	closed    bool

	// Background processes
	cleanupTicker *time.Ticker
	flushTicker   *time.Ticker

	// Metrics
	metrics DurableLogMetrics
}

// LogFileInfo holds information about a log file
type LogFileInfo struct {
	FilePath   string
	FileSize   int64
	EventCount int
	FirstSeq   int64
	LastSeq    int64
	Created    time.Time
}

// EventIndexEntry holds indexing information for an event
type EventIndexEntry struct {
	FilePath string
	Offset   int64
	Size     int64
	Sequence int64
}

// DurableLogMetrics holds metrics for the durable event log
type DurableLogMetrics struct {
	mu sync.RWMutex

	TotalEventsLogged  int64
	TotalEventsRead    int64
	WriteOperations    int64
	ReadOperations     int64
	FileRotations      int64
	CleanupOperations  int64
	CorruptionDetected int64
	StorageFullErrors  int64
	IndexHits          int64
	IndexMisses        int64
}

// DurableLogMetricsSnapshot is a copy of metrics values without the mutex
type DurableLogMetricsSnapshot struct {
	TotalEventsLogged  int64
	TotalEventsRead    int64
	WriteOperations    int64
	ReadOperations     int64
	FileRotations      int64
	CleanupOperations  int64
	CorruptionDetected int64
	StorageFullErrors  int64
	IndexHits          int64
	IndexMisses        int64
}

// RecordWrite records a write operation
func (m *DurableLogMetrics) RecordWrite() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.WriteOperations++
}

// RecordRead records a read operation
func (m *DurableLogMetrics) RecordRead() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ReadOperations++
}

// RecordEventLogged records an event being logged
func (m *DurableLogMetrics) RecordEventLogged() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalEventsLogged++
}

// RecordEventRead records an event being read
func (m *DurableLogMetrics) RecordEventRead() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalEventsRead++
}

// RecordFileRotation records a file rotation
func (m *DurableLogMetrics) RecordFileRotation() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FileRotations++
}

// RecordCorruption records a corruption detection
func (m *DurableLogMetrics) RecordCorruption() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CorruptionDetected++
}

// RecordStorageFull records a storage full error
func (m *DurableLogMetrics) RecordStorageFull() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StorageFullErrors++
}

// RecordIndexHit records an index hit
func (m *DurableLogMetrics) RecordIndexHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.IndexHits++
}

// RecordIndexMiss records an index miss
func (m *DurableLogMetrics) RecordIndexMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.IndexMisses++
}

// GetMetrics returns a snapshot of the current metrics
func (m *DurableLogMetrics) GetMetrics() DurableLogMetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return DurableLogMetricsSnapshot{
		TotalEventsLogged:  m.TotalEventsLogged,
		TotalEventsRead:    m.TotalEventsRead,
		WriteOperations:    m.WriteOperations,
		ReadOperations:     m.ReadOperations,
		FileRotations:      m.FileRotations,
		CleanupOperations:  m.CleanupOperations,
		CorruptionDetected: m.CorruptionDetected,
		StorageFullErrors:  m.StorageFullErrors,
		IndexHits:          m.IndexHits,
		IndexMisses:        m.IndexMisses,
	}
}

// NewDurableEventLog creates a new durable event log
func NewDurableEventLog(config DurableEventLogConfig) (*DurableEventLog, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Validate configuration
	if err := validateDurableLogConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	log := &DurableEventLog{
		config:          config,
		index:           make(map[string]EventIndexEntry),
		logger:          config.Logger,
		closeChan:       make(chan struct{}),
		sequenceCounter: 0,
		metrics:         DurableLogMetrics{},
	}

	// Ensure log directory exists
	if err := os.MkdirAll(config.LogDirectory, 0750); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Load existing log files and build index
	if err := log.loadExistingFiles(); err != nil {
		config.Logger.Warn("Failed to load existing log files, starting fresh", "error", err)
		// Continue with empty log - this is acceptable for startup
	}

	// Create new log file
	if err := log.createNewFile(); err != nil {
		return nil, fmt.Errorf("failed to create initial log file: %w", err)
	}

	// Start background processes
	log.startBackgroundProcesses()

	config.Logger.Info("Durable event log initialized",
		"log_directory", config.LogDirectory,
		"max_log_size", config.MaxLogSize,
		"max_total_size", config.MaxTotalSize,
		"retention_time", config.RetentionTime,
		"sync_writes", config.SyncWrites,
	)

	return log, nil
}

// loadExistingFiles loads existing log files and builds the index
func (l *DurableEventLog) loadExistingFiles() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return ErrDurableLogClosed
	}

	// Get all log files in the directory
	entries, err := os.ReadDir(l.config.LogDirectory)
	if err != nil {
		return fmt.Errorf("failed to read log directory: %w", err)
	}

	var maxSequence int64 = -1

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(l.config.LogDirectory, entry.Name())
		if !isLogFile(entry.Name()) {
			continue
		}

		fileInfo, err := entry.Info()
		if err != nil {
			l.logger.Warn("Failed to get file info", "file", filePath, "error", err)
			continue
		}

		// Build index for this file (for now, skip - we'll build index on demand)
		// if err := l.buildIndexForFile(filePath, fileInfo.Size()); err != nil {
		// 	l.logger.Warn("Failed to index log file", "file", filePath, "error", err)
		// 	// Mark as corrupted but continue
		// 	continue
		// }

		// Track sequence numbers
		if fileInfo.Size() > 0 {
			// Read the last entry to get the sequence number
			lastEvent, err := l.readLastEventFromFile(filePath)
			if err == nil && lastEvent.SequenceNumber > maxSequence {
				maxSequence = lastEvent.SequenceNumber
			}
		}

		logFileInfo := LogFileInfo{
			FilePath:   filePath,
			FileSize:   fileInfo.Size(),
			Created:    fileInfo.ModTime(),
			FirstSeq:   0, // Will be updated when we read the file
			LastSeq:    0, // Will be updated when we read the file
			EventCount: 0, // Will be updated when we read the file
		}

		// Try to get better metadata from filename if available
		if firstSeq, lastSeq, count, ok := parseLogFileMetadata(entry.Name()); ok {
			logFileInfo.FirstSeq = firstSeq
			logFileInfo.LastSeq = lastSeq
			logFileInfo.EventCount = count
		}

		l.logFiles = append(l.logFiles, logFileInfo)
	}

	// Set the sequence counter to the maximum found + 1
	// If no existing files, maxSequence is -1, so sequenceCounter becomes 0
	l.sequenceCounter = maxSequence + 1

	l.logger.Info("Loaded existing log files", "count", len(l.logFiles), "max_sequence", l.sequenceCounter)

	return nil
}

// isLogFile checks if a filename is a log file
func isLogFile(name string) bool {
	return len(name) >= 4 && (name[:4] == "log-" || name[:4] == "evt-") &&
		(name[len(name)-4:] == ".log" || name[len(name)-5:] == ".log.gz")
}

// parseLogFileMetadata parses metadata from log filename
func parseLogFileMetadata(filename string) (firstSeq, lastSeq int64, count int, ok bool) {
	// Expected format: log-{firstSeq}-{lastSeq}-{count}-{timestamp}.log
	// or: evt-{firstSeq}-{lastSeq}-{count}.log

	// For now, return false - we'll implement proper parsing later
	return 0, 0, 0, false
}

// createNewFile creates a new log file for writing
func (l *DurableEventLog) createNewFile() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return ErrDurableLogClosed
	}

	// Close current file if open
	if l.currentFile != nil {
		if err := l.currentFile.Close(); err != nil {
			l.logger.Warn("Failed to close current log file", "file", l.currentFilePath, "error", err)
		}
		l.currentFile = nil
	}

	// Generate new filename with metadata
	timestamp := time.Now().UnixNano()
	filename := fmt.Sprintf("evt-%d-%d-%d-%d.log", l.sequenceCounter, l.sequenceCounter, 0, timestamp)
	l.currentFilePath = filepath.Join(l.config.LogDirectory, filename)

	// Create new file with exclusive access
	file, err := os.OpenFile(l.currentFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY|os.O_EXCL, 0640)
	if err != nil {
		// Try without O_EXCL in case file exists (race condition)
		file, err = os.OpenFile(l.currentFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return fmt.Errorf("failed to create log file: %w", err)
		}
	}

	l.currentFile = file
	l.currentFileSize = 0
	l.currentEventCount = 0

	l.logger.Info("Created new log file", "file", l.currentFilePath)

	return nil
}

// startBackgroundProcesses starts the background cleanup and flush processes
func (l *DurableEventLog) startBackgroundProcesses() {
	// Start cleanup ticker
	if l.config.RetentionTime > 0 {
		l.cleanupTicker = time.NewTicker(l.config.RetentionTime / 2)
		go l.cleanupLoop()
	}

	// Start flush ticker
	if l.config.FlushInterval > 0 {
		l.flushTicker = time.NewTicker(l.config.FlushInterval)
		go l.flushLoop()
	}
}

// cleanupLoop handles periodic cleanup of old log files
func (l *DurableEventLog) cleanupLoop() {
	for {
		select {
		case <-l.cleanupTicker.C:
			l.cleanupOldFiles()
		case <-l.closeChan:
			l.logger.Info("Cleanup loop stopped")
			return
		}
	}
}

// flushLoop handles periodic flushing to disk
func (l *DurableEventLog) flushLoop() {
	for {
		select {
		case <-l.flushTicker.C:
			l.flushToDisk()
		case <-l.closeChan:
			l.logger.Info("Flush loop stopped")
			return
		}
	}
}

// cleanupOldFiles removes log files that exceed the retention period
func (l *DurableEventLog) cleanupOldFiles() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return
	}

	cutoff := time.Now().Add(-l.config.RetentionTime)
	var removedFiles []string

	for i := 0; i < len(l.logFiles); i++ {
		fileInfo := &l.logFiles[i]
		if fileInfo.Created.Before(cutoff) {
			// Remove from filesystem
			if err := os.Remove(fileInfo.FilePath); err != nil {
				l.logger.Warn("Failed to remove old log file", "file", fileInfo.FilePath, "error", err)
			} else {
				// Remove from index
				removedFiles = append(removedFiles, fileInfo.FilePath)
				// Remove entries from index that belong to this file
				l.removeIndexEntriesForFile(fileInfo.FilePath)
			}
		}
	}

	// Remove from logFiles slice (backwards to avoid index issues)
	for i := len(l.logFiles) - 1; i >= 0; i-- {
		for _, removedFile := range removedFiles {
			if l.logFiles[i].FilePath == removedFile {
				l.logFiles = append(l.logFiles[:i], l.logFiles[i+1:]...)
				break
			}
		}
	}

	if len(removedFiles) > 0 {
		l.logger.Info("Cleaned up old log files", "count", len(removedFiles))
	}
}

// removeIndexEntriesForFile removes index entries that belong to a specific file
func (l *DurableEventLog) removeIndexEntriesForFile(filePath string) {
	for eventID, entry := range l.index {
		if entry.FilePath == filePath {
			delete(l.index, eventID)
		}
	}
}

// flushToDisk flushes the current file to disk
func (l *DurableEventLog) flushToDisk() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed || l.currentFile == nil {
		return
	}

	if err := l.currentFile.Sync(); err != nil {
		l.logger.Warn("Failed to sync log file to disk", "file", l.currentFilePath, "error", err)
	} else {
		l.logger.Debug("Flushed log file to disk", "file", l.currentFilePath)
	}
}

// readLastEventFromFile reads the last event from a log file
func (l *DurableEventLog) readLastEventFromFile(filePath string) (*LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if fileInfo.Size() == 0 {
		return nil, nil
	}

	// Read from the end backwards to find the last complete entry
	// For now, we'll just read the whole file and parse the last entry
	// In a production implementation, this would be optimized
	data := make([]byte, fileInfo.Size())
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse the last entry
	var lastEntry LogEntry
	if err := json.Unmarshal(data, &lastEntry); err == nil {
		return &lastEntry, nil
	}

	// Try to find the last newline-separated entry
	// This is a simplified approach - real implementation would need proper parsing
	parts := strings.Split(string(data), "\n")
	if len(parts) == 0 {
		return nil, nil
	}

	// Try to parse the last non-empty line
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.TrimSpace(parts[i]) == "" {
			continue
		}
		if err := json.Unmarshal([]byte(parts[i]), &lastEntry); err == nil {
			return &lastEntry, nil
		}
	}

	return nil, fmt.Errorf("failed to parse last entry")
}

// WriteEvent writes an event to the durable log
func (l *DurableEventLog) WriteEvent(event StreamEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return ErrDurableLogClosed
	}

	// Validate event before writing
	if err := l.ValidateEvent(event); err != nil {
		l.logger.Warn("Event validation failed", "event_id", event.EventID, "error", err)
		return fmt.Errorf("event validation failed: %w", err)
	}

	// Check storage limits first
	if l.config.MaxTotalSize > 0 && l.getTotalSize() >= l.config.MaxTotalSize {
		l.metrics.RecordStorageFull()
		return ErrStorageFull
	}

	// Convert to log entry
	logEntry := LogEntry{
		EventID:         event.EventID,
		EventType:       event.EventType,
		ResourceURI:     event.ResourceURI,
		ContainerURI:    event.ContainerURI,
		Timestamp:       event.Timestamp,
		Agent:           event.Agent,
		AgentType:       event.AgentType,
		Action:          event.Action,
		Metadata:        event.Metadata,
		SequenceNumber:  l.sequenceCounter,
		StreamTimestamp: time.Now().UTC(),
		PrivacyLevel:    event.PrivacyLevel,
	}

	// Generate checksum
	logEntry.Checksum = l.generateChecksum(logEntry)

	// Serialize to JSON
	data, err := json.Marshal(logEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Add newline for JSON Lines format
	data = append(data, '\n')

	// Check if we need to rotate the file
	if l.config.MaxLogSize > 0 && l.currentFileSize+int64(len(data)) > l.config.MaxLogSize {
		if err := l.rotateFile(); err != nil {
			return fmt.Errorf("failed to rotate file: %w", err)
		}
	}

	// Check event count limit
	if l.config.MaxEventsPerFile > 0 && l.currentEventCount >= l.config.MaxEventsPerFile {
		if err := l.rotateFile(); err != nil {
			return fmt.Errorf("failed to rotate file: %w", err)
		}
	}

	// Write to current file
	n, err := l.currentFile.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write event to log: %w", err)
	}

	// Update file info
	l.currentFileSize += int64(n)
	l.currentEventCount++

	// Update sequence counter
	l.sequenceCounter++

	// Update index
	l.index[logEntry.EventID] = EventIndexEntry{
		FilePath: l.currentFilePath,
		Offset:   l.currentFileSize - int64(n),
		Size:     int64(n),
		Sequence: logEntry.SequenceNumber,
	}

	// Update metrics
	l.metrics.RecordWrite()
	l.metrics.RecordEventLogged()

	// Flush if sync writes are enabled
	if l.config.SyncWrites {
		if err := l.currentFile.Sync(); err != nil {
			l.logger.Warn("Failed to sync after write", "error", err)
			// Don't return error for sync failures - the write succeeded
		}
	}

	return nil
}

// rotateFile rotates to a new log file
func (l *DurableEventLog) rotateFile() error {
	// Close current file
	if l.currentFile != nil {
		if err := l.currentFile.Close(); err != nil {
			l.logger.Warn("Failed to close file during rotation", "error", err)
		}
		l.currentFile = nil
	}

	// Create new file
	if err := l.createNewFile(); err != nil {
		return err
	}

	// Update metrics
	l.metrics.RecordFileRotation()

	l.logger.Info("Rotated to new log file", "new_file", l.currentFilePath)

	return nil
}

// getTotalSize returns the total size of all log files
func (l *DurableEventLog) getTotalSize() int64 {
	total := l.currentFileSize
	for _, fileInfo := range l.logFiles {
		total += fileInfo.FileSize
	}
	return total
}

// ReadEvent reads an event from the log by EventID
func (l *DurableEventLog) ReadEvent(eventID string) (*LogEntry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return nil, ErrDurableLogClosed
	}

	// Check index first
	if entry, exists := l.index[eventID]; exists {
		l.metrics.RecordIndexHit()
		return l.readEventFromFile(entry.FilePath, entry.Offset, entry.Size)
	}

	l.metrics.RecordIndexMiss()

	// Search all files if not in index
	for _, fileInfo := range l.logFiles {
		event, err := l.findEventInFile(fileInfo.FilePath, eventID)
		if err == nil && event != nil {
			return event, nil
		}
	}

	return nil, ErrEventNotFound
}

// readEventFromFile reads an event from a specific file at a specific offset
func (l *DurableEventLog) readEventFromFile(filePath string, offset, size int64) (*LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data := make([]byte, size)
	if _, err := file.ReadAt(data, offset); err != nil {
		return nil, fmt.Errorf("failed to read at offset: %w", err)
	}

	var event LogEntry
	if err := json.Unmarshal(data, &event); err != nil {
		l.metrics.RecordCorruption()
		return nil, fmt.Errorf("%w: %v", ErrLogCorruption, err)
	}

	// Verify checksum if present
	if event.Checksum != "" && l.generateChecksum(event) != event.Checksum {
		l.metrics.RecordCorruption()
		return nil, fmt.Errorf("%w: checksum mismatch", ErrLogCorruption)
	}

	l.metrics.RecordRead()
	l.metrics.RecordEventRead()

	return &event, nil
}

// findEventInFile searches for an event in a file
func (l *DurableEventLog) findEventInFile(filePath string, eventID string) (*LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if fileInfo.Size() == 0 {
		return nil, nil
	}

	// Read the entire file (for now - optimize later)
	data := make([]byte, fileInfo.Size())
	if _, err := file.Read(data); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to parse as JSON Lines
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var event LogEntry
		if err := json.Unmarshal([]byte(line), &event); err == nil {
			if event.EventID == eventID {
				// Verify checksum
				if event.Checksum != "" && l.generateChecksum(event) != event.Checksum {
					l.metrics.RecordCorruption()
					return nil, fmt.Errorf("%w: checksum mismatch", ErrLogCorruption)
				}
				l.metrics.RecordRead()
				l.metrics.RecordEventRead()
				return &event, nil
			}
		}
	}

	return nil, nil
}

// ReadEventsSince reads all events since a given sequence number
func (l *DurableEventLog) ReadEventsSince(fromSequence int64, limit int) ([]LogEntry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return nil, ErrDurableLogClosed
	}

	var events []LogEntry

	// For now, just read all events and filter - optimize later
	// In a production implementation, we'd use the index for faster lookup
	for _, fileInfo := range l.logFiles {
		fileEvents, err := l.readEventsFromFile(fileInfo.FilePath)
		if err != nil {
			l.logger.Warn("Failed to read events from file", "file", fileInfo.FilePath, "error", err)
			continue
		}

		for _, event := range fileEvents {
			if event.SequenceNumber >= fromSequence {
				events = append(events, event)
				if limit > 0 && len(events) >= limit {
					return events, nil
				}
			}
		}
	}

	// Also check current file if it has events
	if l.currentFilePath != "" {
		currentEvents, err := l.readEventsFromFile(l.currentFilePath)
		if err == nil {
			for _, event := range currentEvents {
				if event.SequenceNumber >= fromSequence {
					events = append(events, event)
					if limit > 0 && len(events) >= limit {
						return events, nil
					}
				}
			}
		}
	}

	return events, nil
}

// readEventsFromFile reads all events from a file
func (l *DurableEventLog) readEventsFromFile(filePath string) ([]LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if fileInfo.Size() == 0 {
		return []LogEntry{}, nil
	}

	data := make([]byte, fileInfo.Size())
	if _, err := file.Read(data); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var events []LogEntry
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var event LogEntry
		if err := json.Unmarshal([]byte(line), &event); err == nil {
			// Verify checksum if present
			if event.Checksum != "" && l.generateChecksum(event) != event.Checksum {
				l.metrics.RecordCorruption()
				return nil, fmt.Errorf("%w: checksum mismatch for event %s", ErrLogCorruption, event.EventID)
			}
			events = append(events, event)
		} else {
			// Log corruption but continue with other events
			l.metrics.RecordCorruption()
			l.logger.Warn("Failed to parse event in file", "file", filePath, "error", err)
		}
	}

	return events, nil
}

// GetCursor returns the current cursor (last sequence number) for the log
func (l *DurableEventLog) GetCursor() int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return -1
	}

	return l.sequenceCounter - 1
}

// GetCursorByEventID returns the sequence number for a specific event ID
func (l *DurableEventLog) GetCursorByEventID(eventID string) (int64, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return -1, ErrDurableLogClosed
	}

	if entry, exists := l.index[eventID]; exists {
		return entry.Sequence, nil
	}

	// Search all files
	for _, fileInfo := range l.logFiles {
		events, err := l.readEventsFromFile(fileInfo.FilePath)
		if err != nil {
			continue
		}

		for _, event := range events {
			if event.EventID == eventID {
				return event.SequenceNumber, nil
			}
		}
	}

	return -1, ErrEventNotFound
}

// generateChecksum generates a simple checksum for data integrity verification
func (l *DurableEventLog) generateChecksum(entry LogEntry) string {
	// Create a deterministic representation for checksum
	checksumData := fmt.Sprintf("%s|%s|%s|%s|%d|%s",
		entry.EventID,
		entry.EventType,
		entry.ResourceURI,
		entry.Agent,
		entry.SequenceNumber,
		entry.Timestamp.Format(time.RFC3339Nano),
	)

	// Simple hash - in production, use a proper hash function
	var sum uint32
	for _, b := range []byte(checksumData) {
		sum = sum*31 + uint32(b)
	}

	return fmt.Sprintf("%08x", sum)
}

// Close closes the durable event log
func (l *DurableEventLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true
	close(l.closeChan)

	// Close current file
	if l.currentFile != nil {
		if err := l.currentFile.Close(); err != nil {
			l.logger.Warn("Failed to close current file", "error", err)
		}
		l.currentFile = nil
	}

	// Stop tickers
	if l.cleanupTicker != nil {
		l.cleanupTicker.Stop()
	}
	if l.flushTicker != nil {
		l.flushTicker.Stop()
	}

	// Clear resources
	l.logFiles = nil
	l.index = nil

	l.logger.Info("Durable event log closed")

	return nil
}

// IsClosed returns true if the log is closed
func (l *DurableEventLog) IsClosed() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.closed
}

// GetMetrics returns the current metrics
func (l *DurableEventLog) GetMetrics() DurableLogMetricsSnapshot {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.metrics.GetMetrics()
}

// ValidateEvent validates an event for privacy and safety before logging
func (l *DurableEventLog) ValidateEvent(event StreamEvent) error {
	// Validate event ID
	if event.EventID == "" {
		return fmt.Errorf("event ID cannot be empty")
	}

	// Validate event ID length and format
	if len(event.EventID) > 256 {
		return fmt.Errorf("event ID too long (max 256 characters)")
	}

	// Validate privacy level
	if event.PrivacyLevel == "" {
		event.PrivacyLevel = PrivacyLevelMetadata // Default to metadata level
	}

	// Validate privacy level is a valid value
	validPrivacyLevels := []PrivacyLevel{
		PrivacyLevelPublic,
		PrivacyLevelMetadata,
		PrivacyLevelSensitive,
		PrivacyLevelPrivate,
	}
	isValidPrivacyLevel := false
	for _, level := range validPrivacyLevels {
		if event.PrivacyLevel == level {
			isValidPrivacyLevel = true
			break
		}
	}
	if !isValidPrivacyLevel {
		return fmt.Errorf("invalid privacy level: %s", event.PrivacyLevel)
	}

	// Check for private data in metadata
	for key, value := range event.Metadata {
		// Validate key length
		if len(key) > 128 {
			return fmt.Errorf("metadata key too long (max 128 characters): %s", key)
		}
		// Validate value length
		if len(value) > 1024 {
			return fmt.Errorf("metadata value too long (max 1024 characters) for key: %s", key)
		}

		// Check for sensitive keys
		if isSensitiveMetadataKey(key) {
			return fmt.Errorf("sensitive metadata key not allowed: %s", key)
		}

		// Check value for sensitive patterns
		lowerValue := strings.ToLower(value)
		sensitivePatterns := []string{
			"authorization:", "bearer ", "token:", "password:", "secret:",
			"api_key", "access_token", "refresh_token", "private_key", "session",
		}
		for _, pattern := range sensitivePatterns {
			if strings.Contains(lowerValue, pattern) {
				return fmt.Errorf("sensitive data detected in metadata value for key: %s", key)
			}
		}
	}

	// Validate resource URI
	if err := ValidateURI(event.ResourceURI); err != nil {
		return fmt.Errorf("invalid resource URI: %w", err)
	}

	// Validate resource URI length
	if len(event.ResourceURI) > 2048 {
		return fmt.Errorf("resource URI too long (max 2048 characters)")
	}

	// Validate container URI if present
	if event.ContainerURI != "" {
		if err := ValidateContainerURI(event.ContainerURI); err != nil {
			return fmt.Errorf("invalid container URI: %w", err)
		}
		if len(event.ContainerURI) > 2048 {
			return fmt.Errorf("container URI too long (max 2048 characters)")
		}
	}

	// Validate agent if present
	if event.Agent != "" {
		if err := ValidateWebID(event.Agent); err != nil {
			return fmt.Errorf("invalid agent WebID: %w", err)
		}
		if len(event.Agent) > 512 {
			return fmt.Errorf("agent WebID too long (max 512 characters)")
		}
	}

	// Validate agent type if present
	if event.AgentType != "" {
		validAgentTypes := []PolicyAgentType{
			PolicyAgentTypeWebID,
			PolicyAgentTypeGroup,
			PolicyAgentTypeClass,
			PolicyAgentTypeAgent,
			PolicyAgentTypePublic,
			PolicyAgentTypeAuthenticated,
		}
		isValidAgentType := false
		for _, agentType := range validAgentTypes {
			if event.AgentType == agentType {
				isValidAgentType = true
				break
			}
		}
		if !isValidAgentType {
			return fmt.Errorf("invalid agent type: %s", event.AgentType)
		}
	}

	// Validate action length
	if len(event.Action) > 64 {
		return fmt.Errorf("action too long (max 64 characters)")
	}

	// Validate event type
	if event.EventType != "" {
		validEventTypes := []NotificationEventType{
			EventTypeCreate, EventTypeUpdate, EventTypeDelete, EventTypeMove,
			EventTypeCopy, EventTypeAccess, EventTypePolicy, EventTypeContainer, EventTypeCustom,
		}
		isValidEventType := false
		for _, eventType := range validEventTypes {
			if event.EventType == eventType {
				isValidEventType = true
				break
			}
		}
		if !isValidEventType {
			return fmt.Errorf("invalid event type: %s", event.EventType)
		}
	}

	return nil
}

// SubscribeToEvents subscribes to events with cursor-based resume support
func (l *DurableEventLog) SubscribeToEvents(ctx context.Context, cursor int64, filter StreamFilter) (<-chan LogEntry, error) {
	// Create event channel
	eventChannel := make(chan LogEntry, 100)

	// Start subscription goroutine
	go l.subscriptionLoop(ctx, cursor, filter, eventChannel)

	return eventChannel, nil
}

// subscriptionLoop handles event subscription with cursor support
func (l *DurableEventLog) subscriptionLoop(ctx context.Context, cursor int64, filter StreamFilter, eventChannel chan<- LogEntry) {
	defer close(eventChannel)

	// Track the last cursor sent to avoid duplicates
	lastCursor := cursor
	if cursor >= 0 {
		events, err := l.ReadEventsSince(cursor, 0) // 0 means no limit
		if err != nil {
			l.logger.Warn("Failed to read historical events", "cursor", cursor, "error", err)
		} else {
			for _, event := range events {
				if l.eventMatchesFilter(LogEntryToStreamEvent(event), &filter) {
					select {
					case eventChannel <- event:
						lastCursor = event.SequenceNumber
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}

	// Then send new events as they arrive
	// For now, this is a simplified implementation
	// In a production system, we'd have a proper pub/sub mechanism
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check for new events
			currentCursor := l.GetCursor()
			if currentCursor > lastCursor {
				events, err := l.ReadEventsSince(lastCursor, 0)
				if err != nil {
					l.logger.Warn("Failed to read new events", "last_cursor", lastCursor, "current_cursor", currentCursor, "error", err)
				} else {
					for _, event := range events {
						if event.SequenceNumber > lastCursor {
							if l.eventMatchesFilter(LogEntryToStreamEvent(event), &filter) {
								select {
								case eventChannel <- event:
									lastCursor = event.SequenceNumber
								case <-ctx.Done():
									return
								}
							}
						}
					}
				}
			}
		case <-l.closeChan:
			return
		}
	}
}

// eventMatchesFilter checks if a stream event matches the filter
func (l *DurableEventLog) eventMatchesFilter(event StreamEvent, filter *StreamFilter) bool {
	if filter == nil {
		return true
	}

	// Check event types
	if len(filter.EventTypes) > 0 {
		matches := false
		for _, eventType := range filter.EventTypes {
			if eventType == event.EventType {
				matches = true
				break
			}
		}
		if !matches {
			return false
		}
	}

	// Check resource URIs
	if len(filter.ResourceURIs) > 0 {
		matches := false
		for _, uri := range filter.ResourceURIs {
			if uri == event.ResourceURI {
				matches = true
				break
			}
		}
		if !matches {
			return false
		}
	}

	// Check privacy level
	if filter.MinPrivacyLevel != "" && event.PrivacyLevel < filter.MinPrivacyLevel {
		return false
	}

	return true
}

// LogEntryToStreamEvent converts a LogEntry to a StreamEvent
func LogEntryToStreamEvent(entry LogEntry) StreamEvent {
	return StreamEvent{
		EventID:         entry.EventID,
		EventType:       entry.EventType,
		ResourceURI:     entry.ResourceURI,
		ContainerURI:    entry.ContainerURI,
		Timestamp:       entry.Timestamp,
		Agent:           entry.Agent,
		AgentType:       entry.AgentType,
		Action:          entry.Action,
		Metadata:        entry.Metadata,
		SequenceNumber:  entry.SequenceNumber,
		StreamTimestamp: entry.StreamTimestamp,
		PrivacyLevel:    entry.PrivacyLevel,
	}
}

// VerifyIntegrity verifies the integrity of the entire log
func (l *DurableEventLog) VerifyIntegrity() (int, int, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return 0, 0, ErrDurableLogClosed
	}

	corruptedCount := 0
	checkedCount := 0

	// Check all files
	allFiles := append(l.logFiles, LogFileInfo{FilePath: l.currentFilePath})

	for _, logFileInfo := range allFiles {
		if logFileInfo.FilePath == "" {
			continue
		}

		file, err := os.Open(logFileInfo.FilePath)
		if err != nil {
			l.logger.Warn("Failed to open file for integrity check", "file", logFileInfo.FilePath, "error", err)
			continue
		}

		fileStat, err := file.Stat()
		if err != nil {
			file.Close()
			continue
		}

		if fileStat.Size() == 0 {
			file.Close()
			continue
		}

		data := make([]byte, fileStat.Size())
		if _, err := file.Read(data); err != nil {
			file.Close()
			continue
		}
		file.Close()

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}

			var entry LogEntry
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				corruptedCount++
				continue
			}

			checkedCount++

			// Verify checksum
			if entry.Checksum != "" && l.generateChecksum(entry) != entry.Checksum {
				corruptedCount++
				l.logger.Warn("Checksum mismatch detected", "event_id", entry.EventID, "file", logFileInfo.FilePath)
			}
		}
	}

	return checkedCount, corruptedCount, nil
}

// GetTotalEventCount returns the total number of events across all files
func (l *DurableEventLog) GetTotalEventCount() int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()

	total := int64(l.currentEventCount)
	for _, fileInfo := range l.logFiles {
		total += int64(fileInfo.EventCount)
	}
	return total
}
