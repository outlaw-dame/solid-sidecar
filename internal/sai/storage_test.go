// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"context"
	"testing"
	"time"
)

// TestInMemorySAIStorage tests the in-memory SAI storage implementation
func TestInMemorySAIStorage(t *testing.T) {
	t.Run("create in-memory storage", func(t *testing.T) {
		storage := NewInMemorySAIStorage()
		if storage == nil {
			t.Fatal("expected non-nil storage")
		}
		t.Log("In-memory storage created successfully")
	})
}

// TestApplicationStorage tests application storage operations
func TestApplicationStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemorySAIStorage()

	app := &Application{
		ID:                               "https://projectron.example/#app",
		ApplicationName:                  "Projectron",
		ApplicationDescription:           "Manage projects with ease",
		ApplicationAuthor:                "https://acme.example/#corp",
		HasAuthorizationCallbackEndpoint: "https://projectron.example/callback",
		AuthenticatesAs:                  "https://projectron.example/#app",
		HasAccessNeedGroup:               []AccessNeedGroup{},
	}

	t.Run("store and retrieve application", func(t *testing.T) {
		if err := storage.StoreApplication(ctx, app); err != nil {
			t.Fatalf("failed to store application: %v", err)
		}

		retrieved, err := storage.GetApplication(ctx, app.ID)
		if err != nil {
			t.Fatalf("failed to retrieve application: %v", err)
		}

		if retrieved == nil {
			t.Fatal("expected non-nil application")
		}

		if retrieved.ID != app.ID {
			t.Errorf("expected ID %s, got %s", app.ID, retrieved.ID)
		}

		if retrieved.ApplicationName != app.ApplicationName {
			t.Errorf("expected name %s, got %s", app.ApplicationName, retrieved.ApplicationName)
		}

		t.Log("Application stored and retrieved successfully")
	})

	t.Run("list applications", func(t *testing.T) {
		// Store another application
		app2 := &Application{
			ID:                     "https://another.example/#app",
			ApplicationName:        "Another App",
			ApplicationDescription: "Another application",
		}
		if err := storage.StoreApplication(ctx, app2); err != nil {
			t.Fatalf("failed to store second application: %v", err)
		}

		apps, err := storage.ListApplications(ctx, "")
		if err != nil {
			t.Fatalf("failed to list applications: %v", err)
		}

		if len(apps) < 2 {
			t.Errorf("expected at least 2 applications, got %d", len(apps))
		}

		t.Log("Applications listed successfully")
	})

	t.Run("get non-existent application", func(t *testing.T) {
		_, err := storage.GetApplication(ctx, "https://nonexistent.example/#app")
		if err == nil {
			t.Error("expected error for non-existent application")
		}
	})

	t.Run("delete application", func(t *testing.T) {
		if err := storage.DeleteApplication(ctx, app.ID); err != nil {
			t.Fatalf("failed to delete application: %v", err)
		}

		_, err := storage.GetApplication(ctx, app.ID)
		if err == nil {
			t.Error("expected error for deleted application")
		}

		t.Log("Application deleted successfully")
	})

	t.Run("delete non-existent application", func(t *testing.T) {
		if err := storage.DeleteApplication(ctx, "https://nonexistent.example/#app"); err == nil {
			t.Error("expected error for deleting non-existent application")
		}
	})

	t.Run("store nil application", func(t *testing.T) {
		if err := storage.StoreApplication(ctx, nil); err == nil {
			t.Error("expected error for storing nil application")
		}
	})
}

// TestApplicationRegistrationStorage tests application registration storage operations
func TestApplicationRegistrationStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemorySAIStorage()

	userID := "https://alice.example/#id"
	reg := &ApplicationRegistration{
		ID:              "urn:sai:registration:test1",
		RegisteredBy:    userID,
		RegisteredWith:  "https://auth.example.com",
		RegisteredAt:    time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		RegisteredAgent: "https://projectron.example/#app",
		HasAccessGrant:  "",
	}

	t.Run("store and retrieve registration", func(t *testing.T) {
		if err := storage.StoreApplicationRegistration(ctx, reg); err != nil {
			t.Fatalf("failed to store registration: %v", err)
		}

		retrieved, err := storage.GetApplicationRegistration(ctx, reg.ID)
		if err != nil {
			t.Fatalf("failed to retrieve registration: %v", err)
		}

		if retrieved == nil {
			t.Fatal("expected non-nil registration")
		}

		if retrieved.ID != reg.ID {
			t.Errorf("expected ID %s, got %s", reg.ID, retrieved.ID)
		}

		if retrieved.RegisteredBy != reg.RegisteredBy {
			t.Errorf("expected registered by %s, got %s", reg.RegisteredBy, retrieved.RegisteredBy)
		}

		t.Log("Registration stored and retrieved successfully")
	})

	t.Run("list registrations by user", func(t *testing.T) {
		// Store another registration for the same user
		reg2 := &ApplicationRegistration{
			ID:              "urn:sai:registration:test2",
			RegisteredBy:    userID,
			RegisteredWith:  "https://auth.example.com",
			RegisteredAt:    time.Now().UTC(),
			UpdatedAt:       time.Now().UTC(),
			RegisteredAgent: "https://another.example/#app",
		}
		if err := storage.StoreApplicationRegistration(ctx, reg2); err != nil {
			t.Fatalf("failed to store second registration: %v", err)
		}

		// Store a registration for a different user
		reg3 := &ApplicationRegistration{
			ID:              "urn:sai:registration:test3",
			RegisteredBy:    "https://bob.example/#id",
			RegisteredWith:  "https://auth.example.com",
			RegisteredAt:    time.Now().UTC(),
			UpdatedAt:       time.Now().UTC(),
			RegisteredAgent: "https://another.example/#app",
		}
		if err := storage.StoreApplicationRegistration(ctx, reg3); err != nil {
			t.Fatalf("failed to store third registration: %v", err)
		}

		registrations, err := storage.ListApplicationRegistrations(ctx, userID)
		if err != nil {
			t.Fatalf("failed to list registrations: %v", err)
		}

		if len(registrations) != 2 {
			t.Errorf("expected 2 registrations for user %s, got %d", userID, len(registrations))
		}

		t.Log("Registrations listed by user successfully")
	})

	t.Run("list registrations for user with no registrations", func(t *testing.T) {
		registrations, err := storage.ListApplicationRegistrations(ctx, "https://newuser.example/#id")
		if err != nil {
			t.Fatalf("failed to list registrations: %v", err)
		}

		if len(registrations) != 0 {
			t.Errorf("expected 0 registrations, got %d", len(registrations))
		}

		t.Log("Empty registration list returned successfully")
	})

	t.Run("get non-existent registration", func(t *testing.T) {
		_, err := storage.GetApplicationRegistration(ctx, "urn:sai:registration:nonexistent")
		if err == nil {
			t.Error("expected error for non-existent registration")
		}
	})

	t.Run("delete registration", func(t *testing.T) {
		if err := storage.DeleteApplicationRegistration(ctx, reg.ID); err != nil {
			t.Fatalf("failed to delete registration: %v", err)
		}

		_, err := storage.GetApplicationRegistration(ctx, reg.ID)
		if err == nil {
			t.Error("expected error for deleted registration")
		}

		t.Log("Registration deleted successfully")
	})

	t.Run("store nil registration", func(t *testing.T) {
		if err := storage.StoreApplicationRegistration(ctx, nil); err == nil {
			t.Error("expected error for storing nil registration")
		}
	})
}

// TestAccessGrantStorage tests access grant storage operations
func TestAccessGrantStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemorySAIStorage()

	userID := "https://alice.example/#id"
	grant := &AccessGrant{
		ID:          "urn:sai:access-grant:test1",
		GrantedBy:   userID,
		GrantedWith: "https://auth.example.com",
		GrantedAt:   time.Now().UTC(),
		ProvidedAt:  time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		FromAgent:   userID,
		ViaAgent:    userID,
		HasAccessGrantSubject: AccessGrantSubject{
			ID:                  "urn:sai:grant-subject:test1",
			AccessByAgent:       userID,
			AccessByApplication: "https://projectron.example/#app",
		},
		HasAccessNeedGroup: []string{"https://projectron.example/#need-group-pm"},
		HasDataGrant:       []string{"urn:sai:data-grant:test1"},
	}

	t.Run("store and retrieve access grant", func(t *testing.T) {
		if err := storage.StoreAccessGrant(ctx, grant); err != nil {
			t.Fatalf("failed to store access grant: %v", err)
		}

		retrieved, err := storage.GetAccessGrant(ctx, grant.ID)
		if err != nil {
			t.Fatalf("failed to retrieve access grant: %v", err)
		}

		if retrieved == nil {
			t.Fatal("expected non-nil access grant")
		}

		if retrieved.ID != grant.ID {
			t.Errorf("expected ID %s, got %s", grant.ID, retrieved.ID)
		}

		t.Log("Access grant stored and retrieved successfully")
	})

	t.Run("list access grants by user", func(t *testing.T) {
		// Store another grant for the same user
		grant2 := &AccessGrant{
			ID:          "urn:sai:access-grant:test2",
			GrantedBy:   userID,
			GrantedWith: "https://auth.example.com",
			GrantedAt:   time.Now().UTC(),
			ProvidedAt:  time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
			FromAgent:   userID,
			ViaAgent:    userID,
			HasAccessGrantSubject: AccessGrantSubject{
				ID:                  "urn:sai:grant-subject:test2",
				AccessByAgent:       userID,
				AccessByApplication: "https://another.example/#app",
			},
			HasAccessNeedGroup: []string{"https://another.example/#need-group-pm"},
			HasDataGrant:       []string{"urn:sai:data-grant:test2"},
		}
		if err := storage.StoreAccessGrant(ctx, grant2); err != nil {
			t.Fatalf("failed to store second access grant: %v", err)
		}

		grants, err := storage.ListAccessGrants(ctx, userID)
		if err != nil {
			t.Fatalf("failed to list access grants: %v", err)
		}

		if len(grants) != 2 {
			t.Errorf("expected 2 access grants for user %s, got %d", userID, len(grants))
		}

		t.Log("Access grants listed by user successfully")
	})

	t.Run("get non-existent access grant", func(t *testing.T) {
		_, err := storage.GetAccessGrant(ctx, "urn:sai:access-grant:nonexistent")
		if err == nil {
			t.Error("expected error for non-existent access grant")
		}
	})

	t.Run("delete access grant", func(t *testing.T) {
		if err := storage.DeleteAccessGrant(ctx, grant.ID); err != nil {
			t.Fatalf("failed to delete access grant: %v", err)
		}

		_, err := storage.GetAccessGrant(ctx, grant.ID)
		if err == nil {
			t.Error("expected error for deleted access grant")
		}

		t.Log("Access grant deleted successfully")
	})

	t.Run("store nil access grant", func(t *testing.T) {
		if err := storage.StoreAccessGrant(ctx, nil); err == nil {
			t.Error("expected error for storing nil access grant")
		}
	})
}

// TestDataRegistrationStorage tests data registration storage operations
func TestDataRegistrationStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemorySAIStorage()

	userID := "https://alice.example/#id"
	reg := &DataRegistration{
		ID:                  "urn:sai:data-registration:test1",
		RegisteredShapeTree: "solidtrees:Project",
		RegisteredAt:        time.Now().UTC(),
		RegisteredBy:        userID,
		RegisteredWith:      "https://projectron.example/#app",
		IRIPrefix:           "https://pro.alice.example/",
		Contains:            []string{"https://pro.alice.example/project1"},
	}

	t.Run("store and retrieve data registration", func(t *testing.T) {
		if err := storage.StoreDataRegistration(ctx, reg); err != nil {
			t.Fatalf("failed to store data registration: %v", err)
		}

		retrieved, err := storage.GetDataRegistration(ctx, reg.ID)
		if err != nil {
			t.Fatalf("failed to retrieve data registration: %v", err)
		}

		if retrieved == nil {
			t.Fatal("expected non-nil data registration")
		}

		if retrieved.ID != reg.ID {
			t.Errorf("expected ID %s, got %s", reg.ID, retrieved.ID)
		}

		t.Log("Data registration stored and retrieved successfully")
	})

	t.Run("list data registrations by user", func(t *testing.T) {
		// Store another registration for the same user
		reg2 := &DataRegistration{
			ID:                  "urn:sai:data-registration:test2",
			RegisteredShapeTree: "solidtrees:Task",
			RegisteredAt:        time.Now().UTC(),
			RegisteredBy:        userID,
			RegisteredWith:      "https://projectron.example/#app",
			IRIPrefix:           "https://pro.alice.example/",
			Contains:            []string{"https://pro.alice.example/task1"},
		}
		if err := storage.StoreDataRegistration(ctx, reg2); err != nil {
			t.Fatalf("failed to store second data registration: %v", err)
		}

		registrations, err := storage.ListDataRegistrations(ctx, userID)
		if err != nil {
			t.Fatalf("failed to list data registrations: %v", err)
		}

		if len(registrations) != 2 {
			t.Errorf("expected 2 data registrations for user %s, got %d", userID, len(registrations))
		}

		t.Log("Data registrations listed by user successfully")
	})

	t.Run("get non-existent data registration", func(t *testing.T) {
		_, err := storage.GetDataRegistration(ctx, "urn:sai:data-registration:nonexistent")
		if err == nil {
			t.Error("expected error for non-existent data registration")
		}
	})

	t.Run("delete data registration", func(t *testing.T) {
		if err := storage.DeleteDataRegistration(ctx, reg.ID); err != nil {
			t.Fatalf("failed to delete data registration: %v", err)
		}

		_, err := storage.GetDataRegistration(ctx, reg.ID)
		if err == nil {
			t.Error("expected error for deleted data registration")
		}

		t.Log("Data registration deleted successfully")
	})

	t.Run("store nil data registration", func(t *testing.T) {
		if err := storage.StoreDataRegistration(ctx, nil); err == nil {
			t.Error("expected error for storing nil data registration")
		}
	})
}

// TestDataGrantStorage tests data grant storage operations
func TestDataGrantStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemorySAIStorage()

	grant := &DataGrant{
		ID:                  "urn:sai:data-grant:test1",
		DataOwner:           "https://alice.example/#id",
		GrantedBy:           "https://alice.example/#id",
		RegisteredShapeTree: "solidtrees:Project",
		HasDataRegistration: "urn:sai:data-registration:test1",
		AccessMode:          []ACLMode{ACLModeRead, ACLModeWrite},
		ScopeOfGrant:        ScopeOfGrantAllFromRegistry,
		HasDataInstance:     []string{"https://pro.alice.example/project1"},
	}

	t.Run("store and retrieve data grant", func(t *testing.T) {
		if err := storage.StoreDataGrant(ctx, grant); err != nil {
			t.Fatalf("failed to store data grant: %v", err)
		}

		retrieved, err := storage.GetDataGrant(ctx, grant.ID)
		if err != nil {
			t.Fatalf("failed to retrieve data grant: %v", err)
		}

		if retrieved == nil {
			t.Fatal("expected non-nil data grant")
		}

		if retrieved.ID != grant.ID {
			t.Errorf("expected ID %s, got %s", grant.ID, retrieved.ID)
		}

		t.Log("Data grant stored and retrieved successfully")
	})

	t.Run("get non-existent data grant", func(t *testing.T) {
		_, err := storage.GetDataGrant(ctx, "urn:sai:data-grant:nonexistent")
		if err == nil {
			t.Error("expected error for non-existent data grant")
		}
	})

	t.Run("delete data grant", func(t *testing.T) {
		if err := storage.DeleteDataGrant(ctx, grant.ID); err != nil {
			t.Fatalf("failed to delete data grant: %v", err)
		}

		_, err := storage.GetDataGrant(ctx, grant.ID)
		if err == nil {
			t.Error("expected error for deleted data grant")
		}

		t.Log("Data grant deleted successfully")
	})

	t.Run("store nil data grant", func(t *testing.T) {
		if err := storage.StoreDataGrant(ctx, nil); err == nil {
			t.Error("expected error for storing nil data grant")
		}
	})
}

// TestDataInstanceStorage tests data instance storage operations
func TestDataInstanceStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemorySAIStorage()

	instance := &DataInstance{
		ID:          "https://pro.alice.example/project1",
		Type:        "pm:Project",
		ShapeTree:   "solidtrees:Project",
		Data:        []byte(`{"name": "Test Project"}`),
		ContentType: "application/json",
	}

	t.Run("store and retrieve data instance", func(t *testing.T) {
		if err := storage.StoreDataInstance(ctx, instance); err != nil {
			t.Fatalf("failed to store data instance: %v", err)
		}

		retrieved, err := storage.GetDataInstance(ctx, instance.ID)
		if err != nil {
			t.Fatalf("failed to retrieve data instance: %v", err)
		}

		if retrieved == nil {
			t.Fatal("expected non-nil data instance")
		}

		if retrieved.ID != instance.ID {
			t.Errorf("expected ID %s, got %s", instance.ID, retrieved.ID)
		}

		// Note: Data is copied, so we compare content
		if string(retrieved.Data) != string(instance.Data) {
			t.Errorf("expected data %s, got %s", string(instance.Data), string(retrieved.Data))
		}

		t.Log("Data instance stored and retrieved successfully")
	})

	t.Run("list data instances", func(t *testing.T) {
		// Store another instance
		instance2 := &DataInstance{
			ID:          "https://pro.alice.example/task1",
			Type:        "pm:Task",
			ShapeTree:   "solidtrees:Task",
			Data:        []byte(`{"name": "Test Task"}`),
			ContentType: "application/json",
		}
		if err := storage.StoreDataInstance(ctx, instance2); err != nil {
			t.Fatalf("failed to store second data instance: %v", err)
		}

		instances, err := storage.ListDataInstances(ctx, "")
		if err != nil {
			t.Fatalf("failed to list data instances: %v", err)
		}

		if len(instances) < 2 {
			t.Errorf("expected at least 2 data instances, got %d", len(instances))
		}

		t.Log("Data instances listed successfully")
	})

	t.Run("get non-existent data instance", func(t *testing.T) {
		_, err := storage.GetDataInstance(ctx, "https://pro.alice.example/nonexistent")
		if err == nil {
			t.Error("expected error for non-existent data instance")
		}
	})

	t.Run("delete data instance", func(t *testing.T) {
		if err := storage.DeleteDataInstance(ctx, instance.ID); err != nil {
			t.Fatalf("failed to delete data instance: %v", err)
		}

		_, err := storage.GetDataInstance(ctx, instance.ID)
		if err == nil {
			t.Error("expected error for deleted data instance")
		}

		t.Log("Data instance deleted successfully")
	})

	t.Run("store nil data instance", func(t *testing.T) {
		if err := storage.StoreDataInstance(ctx, nil); err == nil {
			t.Error("expected error for storing nil data instance")
		}
	})
}

// TestShapeTreeStorage tests shape tree storage operations
func TestShapeTreeStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemorySAIStorage()

	tree := &ShapeTree{
		ID:          "https://example.com/shape-tree#project",
		ExpectsType: "https://example.com/ns#Resource",
		Shape:       "https://example.com/shapes#Project",
		References: []ShapeTreeReference{
			{
				HasShapeTree: "https://example.com/shape-tree#task",
				ViaShapePath: "@<https://solidshapes.example/shapes/Project>~<https://vocab.example/project-management/hasTask>",
			},
		},
	}

	t.Run("store and retrieve shape tree", func(t *testing.T) {
		if err := storage.StoreShapeTree(ctx, tree); err != nil {
			t.Fatalf("failed to store shape tree: %v", err)
		}

		retrieved, err := storage.GetShapeTree(ctx, tree.ID)
		if err != nil {
			t.Fatalf("failed to retrieve shape tree: %v", err)
		}

		if retrieved == nil {
			t.Fatal("expected non-nil shape tree")
		}

		if retrieved.ID != tree.ID {
			t.Errorf("expected ID %s, got %s", tree.ID, retrieved.ID)
		}

		if len(retrieved.References) != len(tree.References) {
			t.Errorf("expected %d references, got %d", len(tree.References), len(retrieved.References))
		}

		t.Log("Shape tree stored and retrieved successfully")
	})

	t.Run("list shape trees", func(t *testing.T) {
		// Store another tree
		tree2 := &ShapeTree{
			ID:          "https://example.com/shape-tree#task",
			ExpectsType: "https://example.com/ns#Task",
			Shape:       "https://example.com/shapes#Task",
			References:  []ShapeTreeReference{},
		}
		if err := storage.StoreShapeTree(ctx, tree2); err != nil {
			t.Fatalf("failed to store second shape tree: %v", err)
		}

		trees, err := storage.ListShapeTrees(ctx)
		if err != nil {
			t.Fatalf("failed to list shape trees: %v", err)
		}

		if len(trees) != 2 {
			t.Errorf("expected 2 shape trees, got %d", len(trees))
		}

		t.Log("Shape trees listed successfully")
	})

	t.Run("get non-existent shape tree", func(t *testing.T) {
		_, err := storage.GetShapeTree(ctx, "https://example.com/shape-tree:nonexistent")
		if err == nil {
			t.Error("expected error for non-existent shape tree")
		}
	})

	t.Run("delete shape tree", func(t *testing.T) {
		if err := storage.DeleteShapeTree(ctx, tree.ID); err != nil {
			t.Fatalf("failed to delete shape tree: %v", err)
		}

		_, err := storage.GetShapeTree(ctx, tree.ID)
		if err == nil {
			t.Error("expected error for deleted shape tree")
		}

		t.Log("Shape tree deleted successfully")
	})

	t.Run("store nil shape tree", func(t *testing.T) {
		if err := storage.StoreShapeTree(ctx, nil); err == nil {
			t.Error("expected error for storing nil shape tree")
		}
	})
}

// TestAuthorizationAgentStorage tests authorization agent storage operations
func TestAuthorizationAgentStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemorySAIStorage()

	agent := &AuthorizationAgent{
		ID:               "https://auth.example.com",
		AgentRegistrySet: []string{"https://auth.example.com/registry1", "https://auth.example.com/registry2"},
	}

	t.Run("store and retrieve authorization agent", func(t *testing.T) {
		if err := storage.StoreAuthorizationAgent(ctx, agent); err != nil {
			t.Fatalf("failed to store authorization agent: %v", err)
		}

		retrieved, err := storage.GetAuthorizationAgent(ctx, agent.ID)
		if err != nil {
			t.Fatalf("failed to retrieve authorization agent: %v", err)
		}

		if retrieved == nil {
			t.Fatal("expected non-nil authorization agent")
		}

		if retrieved.ID != agent.ID {
			t.Errorf("expected ID %s, got %s", agent.ID, retrieved.ID)
		}

		if len(retrieved.AgentRegistrySet) != len(agent.AgentRegistrySet) {
			t.Errorf("expected %d registry sets, got %d", len(agent.AgentRegistrySet), len(retrieved.AgentRegistrySet))
		}

		t.Log("Authorization agent stored and retrieved successfully")
	})

	t.Run("list authorization agents", func(t *testing.T) {
		// Store another agent
		agent2 := &AuthorizationAgent{
			ID:               "https://auth2.example.com",
			AgentRegistrySet: []string{"https://auth2.example.com/registry"},
		}
		if err := storage.StoreAuthorizationAgent(ctx, agent2); err != nil {
			t.Fatalf("failed to store second authorization agent: %v", err)
		}

		agents, err := storage.ListAuthorizationAgents(ctx)
		if err != nil {
			t.Fatalf("failed to list authorization agents: %v", err)
		}

		if len(agents) != 2 {
			t.Errorf("expected 2 authorization agents, got %d", len(agents))
		}

		t.Log("Authorization agents listed successfully")
	})

	t.Run("get non-existent authorization agent", func(t *testing.T) {
		_, err := storage.GetAuthorizationAgent(ctx, "https://auth-nonexistent.example.com")
		if err == nil {
			t.Error("expected error for non-existent authorization agent")
		}
	})

	t.Run("delete authorization agent", func(t *testing.T) {
		if err := storage.DeleteAuthorizationAgent(ctx, agent.ID); err != nil {
			t.Fatalf("failed to delete authorization agent: %v", err)
		}

		_, err := storage.GetAuthorizationAgent(ctx, agent.ID)
		if err == nil {
			t.Error("expected error for deleted authorization agent")
		}

		t.Log("Authorization agent deleted successfully")
	})

	t.Run("store nil authorization agent", func(t *testing.T) {
		if err := storage.StoreAuthorizationAgent(ctx, nil); err == nil {
			t.Error("expected error for storing nil authorization agent")
		}
	})
}

// TestStorageErrorTypes tests storage error types
func TestStorageErrorTypes(t *testing.T) {
	t.Run("error variables", func(t *testing.T) {
		if ErrSAIStorage == nil {
			t.Error("ErrSAIStorage should not be nil")
		}
		if ErrSAINotFound == nil {
			t.Error("ErrSAINotFound should not be nil")
		}
	})

	t.Run("error messages", func(t *testing.T) {
		if ErrSAIStorage.Error() == "" {
			t.Error("ErrSAIStorage should have an error message")
		}
		if ErrSAINotFound.Error() == "" {
			t.Error("ErrSAINotFound should have an error message")
		}
	})
}

// TestConcurrentAccess tests that the storage is safe for concurrent access
func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemorySAIStorage()

	// Number of goroutines and operations
	const numGoroutines = 10
	const numOperations = 50

	// Channel to collect errors
	errors := make(chan error, numGoroutines*numOperations)

	// Function to perform operations
	worker := func(id int) {
		for i := 0; i < numOperations; i++ {
			// Create unique data for each operation
			app := &Application{
				ID:              "https://example.com/app-" + string(rune('A'+id)) + string(rune('0'+i)),
				ApplicationName: "Test App",
			}

			// Store
			if err := storage.StoreApplication(ctx, app); err != nil {
				errors <- err
				continue
			}

			// Retrieve
			_, err := storage.GetApplication(ctx, app.ID)
			if err != nil {
				errors <- err
				continue
			}

			// List
			_, err = storage.ListApplications(ctx, "")
			if err != nil {
				errors <- err
				continue
			}

			// Delete (delete every other one to avoid conflicts)
			if i%2 == 0 {
				if err := storage.DeleteApplication(ctx, app.ID); err != nil {
					errors <- err
					continue
				}
			}
		}
	}

	// Start all workers
	for i := 0; i < numGoroutines; i++ {
		go worker(i)
	}

	// Wait for all operations to complete and collect errors
	var errs []error
	for i := 0; i < numGoroutines*numOperations; i++ {
		select {
		case err := <-errors:
			errs = append(errs, err)
		default:
			// No more errors or operations
			break
		}
	}

	// Check if any errors occurred
	if len(errs) > 0 {
		for _, err := range errs {
			t.Errorf("concurrent operation failed: %v", err)
		}
	} else {
		t.Log("Concurrent operations completed successfully")
	}
}

// TestDataIntegrity tests that stored data maintains its integrity
func TestDataIntegrity(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemorySAIStorage()

	t.Run("data is not modified after storage", func(t *testing.T) {
		// Create original data
		originalApp := Application{
			ID:                               "https://example.com/app#original",
			ApplicationName:                  "Original Name",
			ApplicationDescription:           "Original Description",
			ApplicationAuthor:                "https://author.example/#me",
			ApplicationThumbnail:             "https://example.com/thumb.png",
			HasAuthorizationCallbackEndpoint: "https://example.com/callback",
			AuthenticatesAs:                  "https://example.com/auth",
			HasAccessNeedGroup: []AccessNeedGroup{
				{
					ID:              "https://example.com/need-group#original",
					AccessNecessity: AccessNecessityRequired,
					AccessScenario:  AccessScenarioPersonalAccess,
					AuthenticatesAs: "https://example.com/auth",
					HasAccessNeed: []AccessNeed{
						{
							ID:                  "https://example.com/need#original",
							RegisteredShapeTree: "solidtrees:Project",
							AccessMode:          []ACLMode{ACLModeRead, ACLModeWrite},
							AccessNecessity:     AccessNecessityRequired,
						},
					},
				},
			},
		}

		// Store the application
		if err := storage.StoreApplication(ctx, &originalApp); err != nil {
			t.Fatalf("failed to store application: %v", err)
		}

		// Retrieve the application
		retrieved, err := storage.GetApplication(ctx, originalApp.ID)
		if err != nil {
			t.Fatalf("failed to retrieve application: %v", err)
		}

		// Check that all fields are preserved
		if retrieved.ID != originalApp.ID {
			t.Errorf("ID was modified: expected %s, got %s", originalApp.ID, retrieved.ID)
		}
		if retrieved.ApplicationName != originalApp.ApplicationName {
			t.Errorf("ApplicationName was modified: expected %s, got %s", originalApp.ApplicationName, retrieved.ApplicationName)
		}
		if retrieved.ApplicationDescription != originalApp.ApplicationDescription {
			t.Errorf("ApplicationDescription was modified: expected %s, got %s", originalApp.ApplicationDescription, retrieved.ApplicationDescription)
		}
		if retrieved.ApplicationAuthor != originalApp.ApplicationAuthor {
			t.Errorf("ApplicationAuthor was modified: expected %s, got %s", originalApp.ApplicationAuthor, retrieved.ApplicationAuthor)
		}

		// Check that nested structures are preserved
		if len(retrieved.HasAccessNeedGroup) != len(originalApp.HasAccessNeedGroup) {
			t.Errorf("HasAccessNeedGroup length was modified: expected %d, got %d", len(originalApp.HasAccessNeedGroup), len(retrieved.HasAccessNeedGroup))
		}

		if len(retrieved.HasAccessNeedGroup) > 0 {
			if retrieved.HasAccessNeedGroup[0].ID != originalApp.HasAccessNeedGroup[0].ID {
				t.Errorf("AccessNeedGroup ID was modified")
			}
			if len(retrieved.HasAccessNeedGroup[0].HasAccessNeed) != len(originalApp.HasAccessNeedGroup[0].HasAccessNeed) {
				t.Errorf("HasAccessNeed length was modified")
			}
		}

		t.Log("Data integrity preserved after storage and retrieval")
	})

	t.Run("modifying retrieved data does not affect stored data", func(t *testing.T) {
		// Store original data
		originalApp := &Application{
			ID:              "https://example.com/app#modify-test",
			ApplicationName: "Original Name",
		}
		if err := storage.StoreApplication(ctx, originalApp); err != nil {
			t.Fatalf("failed to store application: %v", err)
		}

		// Retrieve and modify
		retrieved, err := storage.GetApplication(ctx, originalApp.ID)
		if err != nil {
			t.Fatalf("failed to retrieve application: %v", err)
		}

		// Modify the retrieved data
		retrieved.ApplicationName = "Modified Name"

		// Retrieve again
		retrieved2, err := storage.GetApplication(ctx, originalApp.ID)
		if err != nil {
			t.Fatalf("failed to retrieve application again: %v", err)
		}

		// The stored data should not be affected by the modification
		if retrieved2.ApplicationName != "Original Name" {
			t.Errorf("stored data was affected by modification: expected %s, got %s", "Original Name", retrieved2.ApplicationName)
		}

		t.Log("Retrieved data modification does not affect stored data")
	})
}

// TestCopyFunctions tests that copy functions work correctly
func TestCopyFunctions(t *testing.T) {
	t.Run("copy application", func(t *testing.T) {
		original := &Application{
			ID:              "https://example.com/app#copy-test",
			ApplicationName: "Test App",
			HasAccessNeedGroup: []AccessNeedGroup{
				{
					ID: "https://example.com/need-group#copy-test",
					HasAccessNeed: []AccessNeed{
						{
							ID: "https://example.com/need#copy-test",
						},
					},
				},
			},
		}

		copied := copyApplication(original)

		// Verify it's a deep copy
		if copied == original {
			t.Error("copy should be a different pointer")
		}

		if copied.ID != original.ID {
			t.Error("copy should have same ID")
		}

		// Modify original and check copy is not affected
		original.ApplicationName = "Modified"
		if copied.ApplicationName == "Modified" {
			t.Error("copy should not be affected by original modification")
		}

		// Modify nested structure
		original.HasAccessNeedGroup[0].ID = "Modified"
		if copied.HasAccessNeedGroup[0].ID == "Modified" {
			t.Error("nested copy should not be affected by original modification")
		}

		t.Log("Application copy function works correctly")
	})

	t.Run("copy access grant", func(t *testing.T) {
		original := &AccessGrant{
			ID:                 "urn:sai:access-grant:copy-test",
			HasAccessNeedGroup: []string{"need1", "need2"},
			HasDataGrant:       []string{"grant1", "grant2"},
		}

		copied := copyAccessGrant(original)

		// Verify it's a deep copy
		if copied == original {
			t.Error("copy should be a different pointer")
		}

		// Modify original and check copy is not affected
		original.HasAccessNeedGroup[0] = "modified"
		if copied.HasAccessNeedGroup[0] == "modified" {
			t.Error("copy should not be affected by original modification")
		}

		t.Log("Access grant copy function works correctly")
	})

	t.Run("copy data registration", func(t *testing.T) {
		original := &DataRegistration{
			ID:       "urn:sai:data-registration:copy-test",
			Contains: []string{"instance1", "instance2"},
		}

		copied := copyDataRegistration(original)

		// Verify it's a deep copy
		if copied == original {
			t.Error("copy should be a different pointer")
		}

		// Modify original and check copy is not affected
		original.Contains[0] = "modified"
		if copied.Contains[0] == "modified" {
			t.Error("copy should not be affected by original modification")
		}

		t.Log("Data registration copy function works correctly")
	})

	t.Run("copy data instance", func(t *testing.T) {
		original := &DataInstance{
			ID:          "https://example.com/instance#copy-test",
			Data:        []byte("test data"),
			ContentType: "application/json",
		}

		copied := copyDataInstance(original)

		// Verify it's a deep copy
		if copied == original {
			t.Error("copy should be a different pointer")
		}

		// Modify original and check copy is not affected
		original.Data[0] = 'X'
		if copied.Data[0] == 'X' {
			t.Error("copy should not be affected by original modification")
		}

		t.Log("Data instance copy function works correctly")
	})

	t.Run("copy shape tree", func(t *testing.T) {
		original := &ShapeTree{
			ID: "https://example.com/shape-tree#copy-test",
			References: []ShapeTreeReference{
				{
					HasShapeTree: "https://example.com/child-tree",
					ViaShapePath: "path",
				},
			},
		}

		copied := copyShapeTree(original)

		// Verify it's a deep copy
		if copied == original {
			t.Error("copy should be a different pointer")
		}

		// Modify original and check copy is not affected
		original.References[0].HasShapeTree = "modified"
		if copied.References[0].HasShapeTree == "modified" {
			t.Error("copy should not be affected by original modification")
		}

		t.Log("Shape tree copy function works correctly")
	})

	t.Run("copy authorization agent", func(t *testing.T) {
		original := &AuthorizationAgent{
			ID:               "https://auth.example.com/copy-test",
			AgentRegistrySet: []string{"registry1", "registry2"},
		}

		copied := copyAuthorizationAgent(original)

		// Verify it's a deep copy
		if copied == original {
			t.Error("copy should be a different pointer")
		}

		// Modify original and check copy is not affected
		original.AgentRegistrySet[0] = "modified"
		if copied.AgentRegistrySet[0] == "modified" {
			t.Error("copy should not be affected by original modification")
		}

		t.Log("Authorization agent copy function works correctly")
	})

	t.Run("copy nil values", func(t *testing.T) {
		// These should not panic
		if copyApplication(nil) != nil {
			t.Error("copyApplication(nil) should return nil")
		}
		if copyAccessNeedGroup(nil) != nil {
			t.Error("copyAccessNeedGroup(nil) should return nil")
		}
		if copyAccessNeed(nil) != nil {
			t.Error("copyAccessNeed(nil) should return nil")
		}
		if copyApplicationRegistration(nil) != nil {
			t.Error("copyApplicationRegistration(nil) should return nil")
		}
		if copyAccessGrantSubject(nil) != nil {
			t.Error("copyAccessGrantSubject(nil) should return nil")
		}
		if copyDataGrant(nil) != nil {
			t.Error("copyDataGrant(nil) should return nil")
		}
		if copyDataRegistration(nil) != nil {
			t.Error("copyDataRegistration(nil) should return nil")
		}
		if copyDataInstance(nil) != nil {
			t.Error("copyDataInstance(nil) should return nil")
		}
		if copyShapeTree(nil) != nil {
			t.Error("copyShapeTree(nil) should return nil")
		}
		if copyShapeTreeReference(nil) != nil {
			t.Error("copyShapeTreeReference(nil) should return nil")
		}
		if copyAuthorizationAgent(nil) != nil {
			t.Error("copyAuthorizationAgent(nil) should return nil")
		}
	})
}
