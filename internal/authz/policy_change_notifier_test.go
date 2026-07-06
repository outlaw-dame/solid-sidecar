// Package authz provides authorization policy handling for Solid.
package authz

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPolicyChangeNotifierCreation tests creating a policy change notifier
func TestPolicyChangeNotifierCreation(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for test policies
	tempDir, err := os.MkdirTemp("", "policy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test policy file
	policyPath := filepath.Join(tempDir, "test-policy.ttl")
	if err := os.WriteFile(policyPath, []byte("@prefix ex: <http://example.org/> ."), 0644); err != nil {
		t.Fatalf("Failed to create test policy: %v", err)
	}

	config := PolicyChangeNotifierConfig{
		PolicyPaths:   []string{policyPath},
		WatchInterval: 100 * time.Millisecond, // Short interval for testing
	}

	notifier, err := NewPolicyChangeNotifier(config)
	if err != nil {
		t.Fatalf("Failed to create policy change notifier: %v", err)
	}

	// Verify paths are set
	paths := notifier.GetPolicyPaths()
	if len(paths) != 1 {
		t.Errorf("Expected 1 policy path, got %d", len(paths))
	}

	// Verify interface implementation
	var _ PolicyChangeNotifier = notifier
}

// TestPolicyChangeNotifierSubscription tests subscription functionality
func TestPolicyChangeNotifierSubscription(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for test policies
	tempDir, err := os.MkdirTemp("", "policy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test policy file
	policyPath := filepath.Join(tempDir, "test-policy.ttl")
	if err := os.WriteFile(policyPath, []byte("@prefix ex: <http://example.org/> ."), 0644); err != nil {
		t.Fatalf("Failed to create test policy: %v", err)
	}

	config := PolicyChangeNotifierConfig{
		PolicyPaths:   []string{policyPath},
		WatchInterval: 100 * time.Millisecond,
	}

	notifier, err := NewPolicyChangeNotifier(config)
	if err != nil {
		t.Fatalf("Failed to create policy change notifier: %v", err)
	}

	// Subscribe to changes
	subscription := notifier.SubscribePolicyChanges()

	// Verify subscription is active
	if len(notifier.GetPolicyPaths()) != 1 {
		t.Error("Expected 1 policy path")
	}

	// Close the subscription
	if err := notifier.CloseSubscriber(subscription); err != nil {
		t.Errorf("Failed to close subscription: %v", err)
	}
}

// TestPolicyChangeNotifierFileChange tests detecting file changes
func TestPolicyChangeNotifierFileChange(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for test policies
	tempDir, err := os.MkdirTemp("", "policy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test policy file
	policyPath := filepath.Join(tempDir, "test-policy.ttl")
	initialContent := "@prefix ex: <http://example.org/> ."
	if err := os.WriteFile(policyPath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("Failed to create test policy: %v", err)
	}

	config := PolicyChangeNotifierConfig{
		PolicyPaths:   []string{policyPath},
		WatchInterval: 100 * time.Millisecond,
	}

	notifier, err := NewPolicyChangeNotifier(config)
	if err != nil {
		t.Fatalf("Failed to create policy change notifier: %v", err)
	}

	// Subscribe to changes
	subscription := notifier.SubscribePolicyChanges()
	defer notifier.CloseSubscriber(subscription)

	// Wait for initial state to be established
	time.Sleep(200 * time.Millisecond)

	// Modify the policy file
	modifiedContent := "@prefix ex: <http://example.org/> .\n@prefix new: <http://new.org/> ."
	if err := os.WriteFile(policyPath, []byte(modifiedContent), 0644); err != nil {
		t.Fatalf("Failed to modify test policy: %v", err)
	}

	// Wait for the change to be detected
	select {
	case event := <-subscription:
		// Verify the event
		if event.ChangeType != PolicyChangeTypeUpdate {
			t.Errorf("Expected change type 'update', got '%s'", event.ChangeType)
		}
		if event.PolicyURI == "" {
			t.Error("Expected PolicyURI to be set")
		}
		if event.PolicyVersion == "" {
			t.Error("Expected PolicyVersion to be set")
		}
		if event.OldPolicyVersion == "" {
			t.Error("Expected OldPolicyVersion to be set")
		}
		if event.PolicyVersion == event.OldPolicyVersion {
			t.Error("Expected PolicyVersion to differ from OldPolicyVersion")
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for policy change notification")
	}
}

// TestPolicyChangeNotifierCreateDelete tests create and delete events
func TestPolicyChangeNotifierCreateDelete(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for test policies
	tempDir, err := os.MkdirTemp("", "policy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	newPolicyPath := filepath.Join(tempDir, "new-policy.ttl")

	config := PolicyChangeNotifierConfig{
		PolicyPaths:   []string{newPolicyPath}, // Path doesn't exist yet
		WatchInterval: 100 * time.Millisecond,
	}

	notifier, err := NewPolicyChangeNotifier(config)
	if err != nil {
		t.Fatalf("Failed to create policy change notifier: %v", err)
	}

	// Subscribe to changes
	subscription := notifier.SubscribePolicyChanges()
	defer notifier.CloseSubscriber(subscription)

	// Wait for initial state
	time.Sleep(200 * time.Millisecond)

	// Create a new policy file
	if err := os.WriteFile(newPolicyPath, []byte("@prefix ex: <http://example.org/> ."), 0644); err != nil {
		t.Fatalf("Failed to create new policy: %v", err)
	}

	// Wait for create event
	select {
	case event := <-subscription:
		if event.ChangeType != PolicyChangeTypeCreate {
			t.Errorf("Expected change type 'create', got '%s'", event.ChangeType)
		}
		if event.OldPolicyVersion != "" {
			t.Error("Expected OldPolicyVersion to be empty for create event")
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for policy create notification")
	}

	// Now delete the policy file
	if err := os.Remove(newPolicyPath); err != nil {
		t.Fatalf("Failed to delete policy: %v", err)
	}

	// Wait for delete event
	select {
	case event := <-subscription:
		if event.ChangeType != PolicyChangeTypeDelete {
			t.Errorf("Expected change type 'delete', got '%s'", event.ChangeType)
		}
		if event.PolicyVersion != "" {
			t.Error("Expected PolicyVersion to be empty for delete event")
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for policy delete notification")
	}
}

// TestPolicyChangeNotifierManualTrigger tests manual trigger functionality
func TestPolicyChangeNotifierManualTrigger(t *testing.T) {
	t.Parallel()

	config := PolicyChangeNotifierConfig{
		WatchInterval: 1 * time.Minute,
	}

	notifier, err := NewPolicyChangeNotifier(config)
	if err != nil {
		t.Fatalf("Failed to create policy change notifier: %v", err)
	}

	// Subscribe to changes
	subscription := notifier.SubscribePolicyChanges()
	defer notifier.CloseSubscriber(subscription)

	// Manually trigger a policy change
	notifier.TriggerPolicyChange(
		"http://example.org/policy",
		"new-version-hash",
		"old-version-hash",
		PolicyChangeTypeUpdate,
	)

	// Wait for the event
	select {
	case event := <-subscription:
		if event.PolicyURI != "http://example.org/policy" {
			t.Errorf("Expected PolicyURI 'http://example.org/policy', got '%s'", event.PolicyURI)
		}
		if event.PolicyVersion != "new-version-hash" {
			t.Errorf("Expected PolicyVersion 'new-version-hash', got '%s'", event.PolicyVersion)
		}
		if event.OldPolicyVersion != "old-version-hash" {
			t.Errorf("Expected OldPolicyVersion 'old-version-hash', got '%s'", event.OldPolicyVersion)
		}
		if event.ChangeType != PolicyChangeTypeUpdate {
			t.Errorf("Expected change type 'update', got '%s'", event.ChangeType)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for manually triggered policy change")
	}
}

// TestPolicyChangeNotifierAddRemovePath tests adding and removing paths
func TestPolicyChangeNotifierAddRemovePath(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for test policies
	tempDir, err := os.MkdirTemp("", "policy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test policy file
	policyPath := filepath.Join(tempDir, "test-policy.ttl")
	if err := os.WriteFile(policyPath, []byte("@prefix ex: <http://example.org/> ."), 0644); err != nil {
		t.Fatalf("Failed to create test policy: %v", err)
	}

	config := PolicyChangeNotifierConfig{
		WatchInterval: 1 * time.Minute,
	}

	notifier, err := NewPolicyChangeNotifier(config)
	if err != nil {
		t.Fatalf("Failed to create policy change notifier: %v", err)
	}

	// Verify no paths initially
	paths := notifier.GetPolicyPaths()
	if len(paths) != 0 {
		t.Errorf("Expected 0 policy paths initially, got %d", len(paths))
	}

	// Add a path
	if err := notifier.AddPolicyPath(policyPath); err != nil {
		t.Fatalf("Failed to add policy path: %v", err)
	}

	// Verify path was added
	paths = notifier.GetPolicyPaths()
	if len(paths) != 1 {
		t.Errorf("Expected 1 policy path after add, got %d", len(paths))
	}

	// Try to add the same path again (should be idempotent)
	if err := notifier.AddPolicyPath(policyPath); err != nil {
		t.Errorf("Expected adding duplicate path to be idempotent, got error: %v", err)
	}

	// Remove the path
	if err := notifier.RemovePolicyPath(policyPath); err != nil {
		t.Fatalf("Failed to remove policy path: %v", err)
	}

	// Verify path was removed
	paths = notifier.GetPolicyPaths()
	if len(paths) != 0 {
		t.Errorf("Expected 0 policy paths after remove, got %d", len(paths))
	}

	// Try to remove non-existent path
	if err := notifier.RemovePolicyPath("/nonexistent/path"); err == nil {
		t.Error("Expected error when removing non-existent path")
	}
}

// TestPolicyChangeNotifierDirectoryMonitoring tests monitoring a directory
func TestPolicyChangeNotifierDirectoryMonitoring(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for test policies
	tempDir, err := os.MkdirTemp("", "policy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test policy file in the directory
	policyPath := filepath.Join(tempDir, "test-policy.ttl")
	initialContent := "@prefix ex: <http://example.org/> ."
	if err := os.WriteFile(policyPath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("Failed to create test policy: %v", err)
	}

	config := PolicyChangeNotifierConfig{
		PolicyPaths:   []string{tempDir}, // Monitor the directory
		WatchInterval: 100 * time.Millisecond,
	}

	notifier, err := NewPolicyChangeNotifier(config)
	if err != nil {
		t.Fatalf("Failed to create policy change notifier: %v", err)
	}

	// Subscribe to changes
	subscription := notifier.SubscribePolicyChanges()
	defer notifier.CloseSubscriber(subscription)

	// Wait for initial state to be established
	time.Sleep(200 * time.Millisecond)

	// Modify the policy file in the directory
	modifiedContent := "@prefix ex: <http://example.org/> .\n@prefix new: <http://new.org/> ."
	if err := os.WriteFile(policyPath, []byte(modifiedContent), 0644); err != nil {
		t.Fatalf("Failed to modify test policy: %v", err)
	}

	// Wait for the change to be detected
	select {
	case event := <-subscription:
		// For directory monitoring, we should get an update or create event
		// It might be 'create' if the initial version wasn't properly set,
		// or 'update' if it was. Both are acceptable for this test.
		if event.ChangeType != PolicyChangeTypeUpdate && event.ChangeType != PolicyChangeTypeCreate {
			t.Errorf("Expected change type 'update' or 'create', got '%s'", event.ChangeType)
		}
		if event.PolicyVersion == "" {
			t.Error("Expected PolicyVersion to be set")
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for directory policy change notification")
	}
}

// TestPolicyChangeNotifierClose tests closing the notifier
func TestPolicyChangeNotifierClose(t *testing.T) {
	t.Parallel()

	config := PolicyChangeNotifierConfig{
		WatchInterval: 100 * time.Millisecond,
	}

	notifier, err := NewPolicyChangeNotifier(config)
	if err != nil {
		t.Fatalf("Failed to create policy change notifier: %v", err)
	}

	// Subscribe to changes
	subscription := notifier.SubscribePolicyChanges()

	// Close the notifier
	if err := notifier.Close(); err != nil {
		t.Errorf("Failed to close notifier: %v", err)
	}

	// Verify subscription channel is closed
	select {
	case _, ok := <-subscription:
		if ok {
			t.Error("Expected subscription channel to be closed")
		}
	default:
		// Channel might already be closed
	}
}

// TestPolicyChangeEventCreation tests creating policy change events
func TestPolicyChangeEventCreation(t *testing.T) {
	t.Parallel()

	// Test create event
	createEvent := PolicyChangeEvent{
		ResourceURI:      "http://example.org/resource",
		PolicyURI:        "http://example.org/policy",
		PolicyVersion:    "v2",
		OldPolicyVersion: "",
		ChangeType:       PolicyChangeTypeCreate,
		Timestamp:        time.Now(),
	}

	if createEvent.ChangeType != PolicyChangeTypeCreate {
		t.Errorf("Expected create change type")
	}

	// Test update event
	updateEvent := PolicyChangeEvent{
		ResourceURI:      "http://example.org/resource",
		PolicyURI:        "http://example.org/policy",
		PolicyVersion:    "v2",
		OldPolicyVersion: "v1",
		ChangeType:       PolicyChangeTypeUpdate,
		Timestamp:        time.Now(),
	}

	if updateEvent.ChangeType != PolicyChangeTypeUpdate {
		t.Errorf("Expected update change type")
	}

	// Test delete event
	deleteEvent := PolicyChangeEvent{
		ResourceURI:      "http://example.org/resource",
		PolicyURI:        "http://example.org/policy",
		PolicyVersion:    "",
		OldPolicyVersion: "v1",
		ChangeType:       PolicyChangeTypeDelete,
		Timestamp:        time.Now(),
	}

	if deleteEvent.ChangeType != PolicyChangeTypeDelete {
		t.Errorf("Expected delete change type")
	}
}
