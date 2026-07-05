// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements tenant-safe configuration reload functionality.
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
	"sync"
	"time"
)

// ConfigReloadError represents an error during configuration reload
type ConfigReloadError struct {
	Message string
	Errors  []string
}

func (e *ConfigReloadError) Error() string {
	return fmt.Sprintf("%s: %v", e.Message, e.Errors)
}

// TenantConfigLoader handles loading tenant configurations from external sources
type TenantConfigLoader struct {
	mu sync.RWMutex

	// multiStorage is the multi-storage layer
	multiStorage *MultiStorageLayer

	// configDir is the directory containing tenant configuration files
	configDir string

	// logger is the logger for this loader
	logger *slog.Logger

	// reloadInterval is how often to check for config changes
	reloadInterval time.Duration

	// close state
	closeChan chan struct{}
	closed    bool
}

// TenantConfigLoaderConfig holds configuration for the tenant config loader
type TenantConfigLoaderConfig struct {
	// ConfigDir is the directory containing tenant configuration files
	ConfigDir string

	// ReloadInterval is how often to check for config changes
	ReloadInterval time.Duration

	// Logger is the logger for this loader
	Logger *slog.Logger
}

// DefaultTenantConfigLoaderConfig returns a safe default configuration
func DefaultTenantConfigLoaderConfig() TenantConfigLoaderConfig {
	return TenantConfigLoaderConfig{
		ConfigDir:      "./config/tenants",
		ReloadInterval: 30 * time.Second,
		Logger:         nil,
	}
}

// NewTenantConfigLoader creates a new tenant configuration loader
func NewTenantConfigLoader(multiStorage *MultiStorageLayer, config TenantConfigLoaderConfig) *TenantConfigLoader {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	loader := &TenantConfigLoader{
		multiStorage:   multiStorage,
		configDir:      config.ConfigDir,
		logger:         config.Logger,
		reloadInterval: config.ReloadInterval,
		closeChan:      make(chan struct{}),
		closed:         false,
	}

	// Ensure config directory exists
	if err := os.MkdirAll(config.ConfigDir, 0755); err != nil {
		config.Logger.Error("Failed to create config directory", "error", err, "directory", config.ConfigDir)
	}

	config.Logger.Info("Tenant config loader initialized",
		"config_dir", config.ConfigDir,
		"reload_interval", config.ReloadInterval,
	)

	return loader
}

// Start starts the configuration reloader
func (l *TenantConfigLoader) Start() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return
	}

	// Do initial load
	if err := l.ReloadAll(); err != nil {
		l.logger.Error("Failed initial tenant config load", "error", err)
	}

	// Start periodic reload
	go l.runPeriodicReload()
}

// runPeriodicReload runs the periodic reload loop
func (l *TenantConfigLoader) runPeriodicReload() {
	ticker := time.NewTicker(l.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := l.ReloadAll(); err != nil {
				l.logger.Error("Failed periodic tenant config reload", "error", err)
			}
		case <-l.closeChan:
			l.logger.Info("Tenant config reloader stopped")
			return
		}
	}
}

// ReloadAll reloads all tenant configurations from the config directory
func (l *TenantConfigLoader) ReloadAll() error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return errors.New("tenant config loader is closed")
	}

	// Get list of tenant config files
	entries, err := os.ReadDir(l.configDir)
	if err != nil {
		if os.IsNotExist(err) {
			l.logger.Warn("Config directory does not exist", "directory", l.configDir)
			return nil
		}
		return fmt.Errorf("failed to read config directory: %w", err)
	}

	var reloadErrors []string
	var loadedCount int

	// Process each tenant config file
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process .json files
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		// Extract tenant ID from filename (remove .json extension)
		tenantID := entry.Name()[:len(entry.Name())-5] // Remove ".json"

		// Validate tenant ID
		if err := ValidateTenantID(tenantID); err != nil {
			reloadErrors = append(reloadErrors, fmt.Sprintf("tenant %s: invalid tenant ID: %v", tenantID, err))
			l.logger.Error("Invalid tenant ID in config file", "filename", entry.Name(), "error", err)
			continue
		}

		// Load tenant config
		configPath := filepath.Join(l.configDir, entry.Name())
		if err := l.loadTenantConfig(tenantID, configPath); err != nil {
			reloadErrors = append(reloadErrors, fmt.Sprintf("tenant %s: %v", tenantID, err))
			l.logger.Error("Failed to load tenant config", "tenant_id", tenantID, "file", entry.Name(), "error", err)
			continue
		}

		loadedCount++
	}

	if len(reloadErrors) > 0 {
		return &ConfigReloadError{
			Message: "failed to reload some tenant configurations",
			Errors:  reloadErrors,
		}
	}

	l.logger.Info("Tenant configurations reloaded", "loaded_count", loadedCount)
	return nil
}

// loadTenantConfig loads a tenant configuration from a file
func (l *TenantConfigLoader) loadTenantConfig(tenantID string, configPath string) error {
	// Read the config file
	fileContent, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the JSON content
	var tenantConfig TenantConfig
	if err := json.Unmarshal(fileContent, &tenantConfig); err != nil {
		return fmt.Errorf("failed to parse tenant config JSON: %w", err)
	}

	// Validate tenant ID matches filename
	if tenantConfig.TenantID == "" {
		tenantConfig.TenantID = tenantID
	} else if tenantConfig.TenantID != tenantID {
		return fmt.Errorf("tenant ID in config (%s) does not match filename (%s)", tenantConfig.TenantID, tenantID)
	}

	// Validate tenant ID
	if err := ValidateTenantID(tenantConfig.TenantID); err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Set defaults if not provided
	if tenantConfig.StorageRoot == "" {
		tenantConfig.StorageRoot = "/"
	}
	if tenantConfig.StorageBackend == "" {
		if l.multiStorage != nil {
			tenantConfig.StorageBackend = l.multiStorage.config.DefaultStorage
		} else {
			tenantConfig.StorageBackend = "default"
		}
	}

	if len(tenantConfig.AllowedStorageBackends) == 0 {
		tenantConfig.AllowedStorageBackends = []string{tenantConfig.StorageBackend}
	}

	if tenantConfig.AuthConfig == nil {
		tenantConfig.AuthConfig = DefaultTenantAuthConfig()
	}

	if tenantConfig.Created == "" {
		tenantConfig.Created = time.Now().Format(time.RFC3339)
	}

	// Update modification time to now
	tenantConfig.Modified = time.Now().Format(time.RFC3339)

	// Add or update tenant in multi-storage layer
	if l.multiStorage != nil {
		// Check if tenant exists
		_, err := l.multiStorage.GetTenant(tenantID)
		if err == nil {
			// Tenant exists, update it
			if err := l.multiStorage.UpdateTenant(&tenantConfig); err != nil {
				return fmt.Errorf("failed to update tenant: %w", err)
			}
			l.logger.Info("Tenant config updated from file", "tenant_id", tenantID)
		} else {
			// Tenant doesn't exist, create it
			if err := l.multiStorage.AddTenant(&tenantConfig); err != nil {
				return fmt.Errorf("failed to add tenant: %w", err)
			}
			l.logger.Info("Tenant config loaded from file", "tenant_id", tenantID)
		}

		// Update tenant auth config if provided
		if tenantConfig.AuthConfig != nil {
			if err := l.multiStorage.AddTenantAuthConfig(tenantID, tenantConfig.AuthConfig); err != nil {
				l.logger.Error("Failed to add tenant auth config from file", "tenant_id", tenantID, "error", err)
				// Don't fail the whole reload for auth config issues
			}
		}

		// Update storage mapping
		l.multiStorage.tenantStorage[tenantID] = tenantConfig.StorageBackend
	}

	return nil
}

// SaveTenantConfig saves a tenant configuration to a file
func (l *TenantConfigLoader) SaveTenantConfig(tenantID string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return errors.New("tenant config loader is closed")
	}

	if l.multiStorage == nil {
		return errors.New("multi-storage layer not available")
	}

	// Get tenant config
	tenant, err := l.multiStorage.GetTenant(tenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	// Serialize to JSON
	jsonData, err := json.MarshalIndent(tenant, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize tenant config: %w", err)
	}

	// Create filename
	configPath := filepath.Join(l.configDir, tenantID+".json")

	// Write to file atomically
	tempPath := configPath + ".tmp"
	if err := os.WriteFile(tempPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write tenant config: %w", err)
	}

	// Atomically rename
	if err := os.Rename(tempPath, configPath); err != nil {
		os.Remove(tempPath) // Clean up temp file
		return fmt.Errorf("failed to save tenant config: %w", err)
	}

	l.logger.Info("Tenant config saved to file", "tenant_id", tenantID, "file", configPath)
	return nil
}

// DeleteTenantConfig deletes a tenant configuration file
func (l *TenantConfigLoader) DeleteTenantConfig(tenantID string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return errors.New("tenant config loader is closed")
	}

	// Create filename
	configPath := filepath.Join(l.configDir, tenantID+".json")

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil // File doesn't exist, nothing to delete
	}

	// Delete the file
	if err := os.Remove(configPath); err != nil {
		return fmt.Errorf("failed to delete tenant config file: %w", err)
	}

	l.logger.Info("Tenant config file deleted", "tenant_id", tenantID, "file", configPath)
	return nil
}

// ReloadTenant reloads a specific tenant configuration
func (l *TenantConfigLoader) ReloadTenant(tenantID string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return errors.New("tenant config loader is closed")
	}

	// Create filename
	configPath := filepath.Join(l.configDir, tenantID+".json")

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("tenant config file not found: %w", err)
	}

	return l.loadTenantConfig(tenantID, configPath)
}

// WatchTenantConfig watches a specific tenant configuration file for changes
func (l *TenantConfigLoader) WatchTenantConfig(tenantID string, ctx context.Context) error {
	configPath := filepath.Join(l.configDir, tenantID+".json")

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("tenant config file not found: %w", err)
	}

	// Use filesystem watcher if available, or fall back to periodic checks
	// For now, implement periodic checking
	ticker := time.NewTicker(l.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := l.ReloadTenant(tenantID); err != nil {
				l.logger.Error("Failed to reload tenant config", "tenant_id", tenantID, "error", err)
			}
		case <-ctx.Done():
			l.logger.Info("Tenant config watch stopped", "tenant_id", tenantID)
			return nil
		case <-l.closeChan:
			return nil
		}
	}
}

// Close closes the tenant config loader
func (l *TenantConfigLoader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true
	close(l.closeChan)
	l.logger.Info("Tenant config loader closed")
	return nil
}

// IsClosed returns true if the loader is closed
func (l *TenantConfigLoader) IsClosed() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.closed
}

// ListTenantConfigFiles lists all tenant configuration files
func (l *TenantConfigLoader) ListTenantConfigFiles() ([]string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return nil, errors.New("tenant config loader is closed")
	}

	// Get list of tenant config files
	entries, err := os.ReadDir(l.configDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read config directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) == ".json" {
			files = append(files, entry.Name())
		}
	}

	return files, nil
}

// ValidateTenantConfigFile validates a tenant configuration file
func (l *TenantConfigLoader) ValidateTenantConfigFile(configPath string) error {
	// Read the config file
	fileContent, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the JSON content
	var tenantConfig TenantConfig
	if err := json.Unmarshal(fileContent, &tenantConfig); err != nil {
		return fmt.Errorf("failed to parse tenant config JSON: %w", err)
	}

	// Validate tenant ID
	if err := ValidateTenantID(tenantConfig.TenantID); err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Validate auth config if present
	if tenantConfig.AuthConfig != nil {
		if err := ValidateTenantAuthConfig(tenantConfig.AuthConfig); err != nil {
			return fmt.Errorf("invalid tenant auth config: %w", err)
		}
	}

	return nil
}

// ImportTenantConfig imports a tenant configuration from a reader
func (l *TenantConfigLoader) ImportTenantConfig(tenantID string, reader io.Reader) error {
	// Read the content
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read config content: %w", err)
	}

	// Parse the JSON content
	var tenantConfig TenantConfig
	if err := json.Unmarshal(content, &tenantConfig); err != nil {
		return fmt.Errorf("failed to parse tenant config JSON: %w", err)
	}

	// Validate tenant ID
	if tenantConfig.TenantID == "" {
		tenantConfig.TenantID = tenantID
	}

	if err := ValidateTenantID(tenantConfig.TenantID); err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Set defaults if not provided
	if tenantConfig.StorageBackend == "" {
		if l.multiStorage != nil {
			tenantConfig.StorageBackend = l.multiStorage.config.DefaultStorage
		} else {
			tenantConfig.StorageBackend = "default"
		}
	}

	if tenantConfig.AuthConfig == nil {
		tenantConfig.AuthConfig = DefaultTenantAuthConfig()
	}

	if tenantConfig.Created == "" {
		tenantConfig.Created = time.Now().Format(time.RFC3339)
	}

	tenantConfig.Modified = time.Now().Format(time.RFC3339)

	// Add or update tenant in multi-storage layer
	if l.multiStorage != nil {
		// Check if tenant exists
		_, err := l.multiStorage.GetTenant(tenantConfig.TenantID)
		if err == nil {
			// Tenant exists, update it
			if err := l.multiStorage.UpdateTenant(&tenantConfig); err != nil {
				return fmt.Errorf("failed to update tenant: %w", err)
			}
		} else {
			// Tenant doesn't exist, create it
			if err := l.multiStorage.AddTenant(&tenantConfig); err != nil {
				return fmt.Errorf("failed to add tenant: %w", err)
			}
		}

		// Update tenant auth config
		if err := l.multiStorage.AddTenantAuthConfig(tenantConfig.TenantID, tenantConfig.AuthConfig); err != nil {
			l.logger.Error("Failed to add tenant auth config during import", "tenant_id", tenantConfig.TenantID, "error", err)
			// Don't fail the whole import for auth config issues
		}

		// Save to file
		if err := l.SaveTenantConfig(tenantConfig.TenantID); err != nil {
			l.logger.Error("Failed to save tenant config during import", "tenant_id", tenantConfig.TenantID, "error", err)
			// Don't fail the whole import for save issues
		}
	}

	return nil
}

// ExportTenantConfig exports a tenant configuration to a writer
func (l *TenantConfigLoader) ExportTenantConfig(tenantID string, writer io.Writer) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return errors.New("tenant config loader is closed")
	}

	if l.multiStorage == nil {
		return errors.New("multi-storage layer not available")
	}

	// Get tenant config
	tenant, err := l.multiStorage.GetTenant(tenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	// Serialize to JSON
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(tenant); err != nil {
		return fmt.Errorf("failed to serialize tenant config: %w", err)
	}

	return nil
}

// BackupAllTenantConfigs creates a backup of all tenant configurations
func (l *TenantConfigLoader) BackupAllTenantConfigs(backupDir string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return errors.New("tenant config loader is closed")
	}

	if l.multiStorage == nil {
		return errors.New("multi-storage layer not available")
	}

	// Create backup directory
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Get all tenants
	tenants := l.multiStorage.ListTenants()

	// Backup each tenant config
	for _, tenant := range tenants {
		backupPath := filepath.Join(backupDir, tenant.TenantID+".json")

		// Get tenant config
		tenantConfig, err := l.multiStorage.GetTenant(tenant.TenantID)
		if err != nil {
			l.logger.Error("Failed to get tenant config for backup", "tenant_id", tenant.TenantID, "error", err)
			continue
		}

		// Serialize to JSON
		jsonData, err := json.MarshalIndent(tenantConfig, "", "  ")
		if err != nil {
			l.logger.Error("Failed to serialize tenant config for backup", "tenant_id", tenant.TenantID, "error", err)
			continue
		}

		// Write backup file
		if err := os.WriteFile(backupPath, jsonData, 0644); err != nil {
			l.logger.Error("Failed to write tenant config backup", "tenant_id", tenant.TenantID, "error", err)
			continue
		}

		l.logger.Info("Tenant config backed up", "tenant_id", tenant.TenantID, "backup_file", backupPath)
	}

	return nil
}

// RestoreAllTenantConfigs restores tenant configurations from a backup
func (l *TenantConfigLoader) RestoreAllTenantConfigs(backupDir string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return errors.New("tenant config loader is closed")
	}

	// Get list of backup files
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			l.logger.Warn("Backup directory does not exist", "directory", backupDir)
			return nil
		}
		return fmt.Errorf("failed to read backup directory: %w", err)
	}

	var restoreErrors []string
	var restoredCount int

	// Restore each tenant config
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process .json files
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		// Extract tenant ID from filename
		tenantID := entry.Name()[:len(entry.Name())-5] // Remove ".json"

		// Load backup file
		backupPath := filepath.Join(backupDir, entry.Name())
		fileContent, err := os.ReadFile(backupPath)
		if err != nil {
			restoreErrors = append(restoreErrors, fmt.Sprintf("tenant %s: failed to read backup: %v", tenantID, err))
			continue
		}

		// Parse the JSON content
		var tenantConfig TenantConfig
		if err := json.Unmarshal(fileContent, &tenantConfig); err != nil {
			restoreErrors = append(restoreErrors, fmt.Sprintf("tenant %s: failed to parse backup: %v", tenantID, err))
			continue
		}

		// Validate tenant ID
		if tenantConfig.TenantID == "" {
			tenantConfig.TenantID = tenantID
		}

		if err := ValidateTenantID(tenantConfig.TenantID); err != nil {
			restoreErrors = append(restoreErrors, fmt.Sprintf("tenant %s: invalid tenant ID: %v", tenantID, err))
			continue
		}

		// Set defaults if not provided
		if tenantConfig.StorageBackend == "" {
			if l.multiStorage != nil {
				tenantConfig.StorageBackend = l.multiStorage.config.DefaultStorage
			} else {
				tenantConfig.StorageBackend = "default"
			}
		}

		if tenantConfig.AuthConfig == nil {
			tenantConfig.AuthConfig = DefaultTenantAuthConfig()
		}

		// Update modification time
		tenantConfig.Modified = time.Now().Format(time.RFC3339)

		// Add or update tenant in multi-storage layer
		if l.multiStorage != nil {
			// Check if tenant exists
			_, err := l.multiStorage.GetTenant(tenantConfig.TenantID)
			if err == nil {
				// Tenant exists, update it
				if err := l.multiStorage.UpdateTenant(&tenantConfig); err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("tenant %s: failed to update: %v", tenantID, err))
					continue
				}
			} else {
				// Tenant doesn't exist, create it
				if err := l.multiStorage.AddTenant(&tenantConfig); err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("tenant %s: failed to add: %v", tenantID, err))
					continue
				}
			}

			// Update tenant auth config
			if err := l.multiStorage.AddTenantAuthConfig(tenantConfig.TenantID, tenantConfig.AuthConfig); err != nil {
				l.logger.Error("Failed to add tenant auth config during restore", "tenant_id", tenantConfig.TenantID, "error", err)
				// Don't fail the whole restore for auth config issues
			}

			restoredCount++
		}
	}

	if len(restoreErrors) > 0 {
		return &ConfigReloadError{
			Message: "failed to restore some tenant configurations",
			Errors:  restoreErrors,
		}
	}

	l.logger.Info("Tenant configurations restored", "restored_count", restoredCount, "backup_dir", backupDir)
	return nil
}
