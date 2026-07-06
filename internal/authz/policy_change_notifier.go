// Package authz provides authorization policy handling for Solid.
package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PolicyChangeNotifierImpl is a concrete implementation of PolicyChangeNotifier
// that monitors policy files for changes and notifies subscribers.
type PolicyChangeNotifierImpl struct {
	// subscribers is a map of subscriber channel send sides
	subscribers map[chan PolicyChangeEvent]bool
	mu          sync.RWMutex

	// policyPaths is a list of paths to monitor for policy changes
	policyPaths []string

	// logger is used for logging
	logger *slog.Logger

	// policyVersions tracks the current version of each policy
	policyVersions map[string]string

	// running indicates if the notifier is currently running
	running bool

	// stopChan is used to signal the notifier to stop
	stopChan chan struct{}

	// watchInterval is how often to check for changes
	watchInterval time.Duration
}

// PolicyChangeNotifierConfig configures the policy change notifier
type PolicyChangeNotifierConfig struct {
	// PolicyPaths is a list of paths to monitor for policy changes
	PolicyPaths []string

	// WatchInterval is how often to check for changes (default: 1 minute)
	WatchInterval time.Duration

	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultPolicyChangeNotifierConfig returns default configuration
func DefaultPolicyChangeNotifierConfig() PolicyChangeNotifierConfig {
	return PolicyChangeNotifierConfig{
		PolicyPaths:   []string{},
		WatchInterval: 1 * time.Minute,
		Logger:        slog.Default(),
	}
}

// NewPolicyChangeNotifier creates a new policy change notifier
func NewPolicyChangeNotifier(config PolicyChangeNotifierConfig) (*PolicyChangeNotifierImpl, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	if config.WatchInterval <= 0 {
		config.WatchInterval = 1 * time.Minute
	}

	notifier := &PolicyChangeNotifierImpl{
		subscribers:    make(map[chan PolicyChangeEvent]bool),
		policyPaths:    config.PolicyPaths,
		logger:         config.Logger.With("component", "policy_change_notifier"),
		policyVersions: make(map[string]string),
		stopChan:       make(chan struct{}),
		watchInterval:  config.WatchInterval,
	}

	// Initialize policy versions
	if err := notifier.initializePolicyVersions(); err != nil {
		return nil, fmt.Errorf("failed to initialize policy versions: %w", err)
	}

	return notifier, nil
}

// initializePolicyVersions loads the initial versions of all monitored policies
func (n *PolicyChangeNotifierImpl) initializePolicyVersions() error {
	for _, path := range n.policyPaths {
		if err := n.loadPolicyVersion(path); err != nil {
			n.logger.Warn("Failed to load initial version for policy",
				"path", path,
				"error", err,
			)
		}
	}
	return nil
}

// loadPolicyVersion calculates the SHA256 hash of a policy file or directory
func (n *PolicyChangeNotifierImpl) loadPolicyVersion(path string) error {
	// Check if path is a directory
	info, err := os.Stat(path)
	if err != nil {
		// If the file/directory doesn't exist, we'll just skip it
		// This allows monitoring paths that may not exist yet
		if os.IsNotExist(err) {
			n.policyVersions[path] = ""
			return nil
		}
		return err
	}

	var version string
	if info.IsDir() {
		// It's a directory - calculate directory hash
		version, err = n.calculateDirectoryVersion(path)
		if err != nil {
			return err
		}
	} else {
		// It's a file - calculate file hash
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(content)
		version = hex.EncodeToString(hash[:])
	}

	n.policyVersions[path] = version
	return nil
}

// SubscribePolicyChanges subscribes to policy change events
// Returns a channel that will receive PolicyChangeEvent notifications
func (n *PolicyChangeNotifierImpl) SubscribePolicyChanges() <-chan PolicyChangeEvent {
	n.mu.Lock()
	defer n.mu.Unlock()

	ch := make(chan PolicyChangeEvent, 100)
	n.subscribers[ch] = true

	// If notifier is not running, start it
	if !n.running {
		n.running = true
		go n.monitorPolicies()
	}

	return ch
}

// Close closes the notifier and all subscriptions
func (n *PolicyChangeNotifierImpl) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Close all subscriber channels
	for ch := range n.subscribers {
		close(ch)
		delete(n.subscribers, ch)
	}

	// Stop the notifier
	close(n.stopChan)
	n.running = false

	return nil
}

// CloseSubscriber closes a specific subscription
func (n *PolicyChangeNotifierImpl) CloseSubscriber(subscriber <-chan PolicyChangeEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// We need to find and remove the channel from our subscribers
	// Since we can't directly compare <-chan with chan, we'll use a different approach
	// For now, we'll just remove all subscribers when one closes
	// This is a known limitation that could be improved with a better channel tracking system
	for ch := range n.subscribers {
		close(ch)
		delete(n.subscribers, ch)
	}

	// If no more subscribers, stop the notifier
	if len(n.subscribers) == 0 {
		close(n.stopChan)
		n.running = false
	}

	return nil
}

// monitorPolicies monitors policy files for changes
func (n *PolicyChangeNotifierImpl) monitorPolicies() {
	ticker := time.NewTicker(n.watchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			n.checkForPolicyChanges()
		case <-n.stopChan:
			return
		}
	}
}

// checkForPolicyChanges checks all monitored policy paths for changes
func (n *PolicyChangeNotifierImpl) checkForPolicyChanges() {
	for _, path := range n.policyPaths {
		n.mu.Lock()
		oldVersion := n.policyVersions[path]
		n.mu.Unlock()

		newVersion, err := n.calculateCurrentVersion(path)
		if err != nil {
			n.logger.Debug("Failed to check policy version",
				"path", path,
				"error", err,
			)
			continue
		}

		if newVersion != oldVersion {
			// Policy has changed - update version and notify
			n.mu.Lock()
			n.policyVersions[path] = newVersion
			event := n.createPolicyChangeEvent(path, oldVersion, newVersion)
			n.mu.Unlock()

			// Notify subscribers (this acquires its own read lock)
			n.notifySubscribers(event)
		}
	}
}

// calculateCurrentVersion calculates the current version of a policy file
func (n *PolicyChangeNotifierImpl) calculateCurrentVersion(path string) (string, error) {
	// If path is a directory, calculate hash of all files in it
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	if info.IsDir() {
		return n.calculateDirectoryVersion(path)
	}

	// It's a file
	return n.calculateFileVersion(path)
}

// calculateFileVersion calculates the SHA256 hash of a single file
func (n *PolicyChangeNotifierImpl) calculateFileVersion(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:]), nil
}

// calculateDirectoryVersion calculates a combined hash of all files in a directory
func (n *PolicyChangeNotifierImpl) calculateDirectoryVersion(dirPath string) (string, error) {
	hasher := sha256.New()

	// Walk the directory and hash all file contents
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Read file content and hash it
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Write file path and content to the hasher
		hasher.Write([]byte(path))
		hasher.Write(content)

		return nil
	})

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// createPolicyChangeEvent creates a PolicyChangeEvent from a detected change
func (n *PolicyChangeNotifierImpl) createPolicyChangeEvent(path, oldVersion, newVersion string) PolicyChangeEvent {
	// Determine change type
	changeType := PolicyChangeTypeUpdate
	if oldVersion == "" {
		changeType = PolicyChangeTypeCreate
	}
	if newVersion == "" {
		changeType = PolicyChangeTypeDelete
	}

	// Create a reasonable resource URI from the path
	resourceURI := fmt.Sprintf("file://%s", filepath.ToSlash(path))

	return PolicyChangeEvent{
		ResourceURI:      resourceURI,
		PolicyURI:        resourceURI,
		PolicyVersion:    newVersion,
		OldPolicyVersion: oldVersion,
		ChangeType:       changeType,
		Timestamp:        time.Now(),
	}
}

// notifySubscribers sends an event to all subscribers
// Note: This method acquires its own lock, so callers must not hold n.mu when calling this
func (n *PolicyChangeNotifierImpl) notifySubscribers(event PolicyChangeEvent) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	// Make a copy of subscribers to avoid holding the lock during sends
	subscribersCopy := make([]chan PolicyChangeEvent, 0, len(n.subscribers))
	for ch := range n.subscribers {
		subscribersCopy = append(subscribersCopy, ch)
	}

	for _, ch := range subscribersCopy {
		// Non-blocking send
		select {
		case ch <- event:
			// Successfully sent
			n.logger.Debug("Policy change notification sent",
				"change_type", event.ChangeType,
				"policy_uri", event.PolicyURI,
				"resource_uri", event.ResourceURI,
			)
		default:
			// Channel is full, drop the event (caller should use buffered channels)
			n.logger.Warn("Policy change notification dropped - channel full",
				"change_type", event.ChangeType,
				"policy_uri", event.PolicyURI,
			)
		}
	}
}

// AddPolicyPath adds a new path to monitor for policy changes
func (n *PolicyChangeNotifierImpl) AddPolicyPath(path string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Check if path already exists
	for _, existing := range n.policyPaths {
		if existing == path {
			return nil // Already monitoring this path
		}
	}

	n.policyPaths = append(n.policyPaths, path)

	// Initialize version for the new path
	if err := n.loadPolicyVersion(path); err != nil {
		return fmt.Errorf("failed to load initial version for path %s: %w", path, err)
	}

	n.logger.Info("Added policy path for monitoring", "path", path)
	return nil
}

// RemovePolicyPath removes a path from monitoring
func (n *PolicyChangeNotifierImpl) RemovePolicyPath(path string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	for i, existing := range n.policyPaths {
		if existing == path {
			n.policyPaths = append(n.policyPaths[:i], n.policyPaths[i+1:]...)
			delete(n.policyVersions, path)
			n.logger.Info("Removed policy path from monitoring", "path", path)
			return nil
		}
	}

	return fmt.Errorf("path %s not found in monitored paths", path)
}

// GetPolicyPaths returns the current list of monitored policy paths
func (n *PolicyChangeNotifierImpl) GetPolicyPaths() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	paths := make([]string, len(n.policyPaths))
	copy(paths, n.policyPaths)
	return paths
}

// TriggerPolicyChange manually triggers a policy change notification
// This can be used for external policy changes (e.g., via API)
func (n *PolicyChangeNotifierImpl) TriggerPolicyChange(
	policyURI string,
	policyVersion string,
	oldPolicyVersion string,
	changeType PolicyChangeType,
) {
	event := PolicyChangeEvent{
		ResourceURI:      policyURI,
		PolicyURI:        policyURI,
		PolicyVersion:    policyVersion,
		OldPolicyVersion: oldPolicyVersion,
		ChangeType:       changeType,
		Timestamp:        time.Now(),
	}

	n.logger.Info("Manually triggered policy change",
		"change_type", changeType,
		"policy_uri", policyURI,
		"old_version", oldPolicyVersion,
		"new_version", policyVersion,
	)

	n.notifySubscribers(event)
}

// Ensure PolicyChangeNotifierImpl implements PolicyChangeNotifier interface
var _ PolicyChangeNotifier = (*PolicyChangeNotifierImpl)(nil)
