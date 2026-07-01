// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"testing"
	"time"
)

// TestSAIConstants tests that SAI constants are properly defined
func TestSAIConstants(t *testing.T) {
	t.Run("namespace constants", func(t *testing.T) {
		if SAINamespace != "http://www.w3.org/ns/solid/interop#" {
			t.Errorf("expected SAINamespace to be interop namespace, got %s", SAINamespace)
		}
		if InteropNamespace != "http://www.w3.org/ns/solid/interop#" {
			t.Errorf("expected InteropNamespace to be interop namespace, got %s", InteropNamespace)
		}
	})

	t.Run("access necessity constants", func(t *testing.T) {
		expected := []AccessNecessity{
			AccessNecessityRequired,
			AccessNecessityOptional,
			AccessNecessityProhibited,
		}
		for _, nec := range expected {
			if nec == "" {
				t.Error("access necessity constant is empty")
			}
			if !containsAccessNecessity(expected, nec) {
				t.Errorf("access necessity %s not found in expected list", nec)
			}
		}
	})

	t.Run("access scenario constants", func(t *testing.T) {
		expected := []AccessScenario{
			AccessScenarioPersonalAccess,
			AccessScenarioCollaborativeAccess,
			AccessScenarioPublicAccess,
			AccessScenarioEmergencyAccess,
		}
		for _, scenario := range expected {
			if scenario == "" {
				t.Error("access scenario constant is empty")
			}
			if !containsAccessScenario(expected, scenario) {
				t.Errorf("access scenario %s not found in expected list", scenario)
			}
		}
	})

	t.Run("ACL mode constants", func(t *testing.T) {
		expected := []ACLMode{
			ACLModeRead,
			ACLModeWrite,
			ACLModeAppend,
			ACLModeControl,
		}
		for _, mode := range expected {
			if mode == "" {
				t.Error("ACL mode constant is empty")
			}
			if !containsACLMode(expected, mode) {
				t.Errorf("ACL mode %s not found in expected list", mode)
			}
		}
	})

	t.Run("scope of grant constants", func(t *testing.T) {
		expected := []ScopeOfGrant{
			ScopeOfGrantAllFromRegistry,
			ScopeOfGrantSelectedFromRegistry,
			ScopeOfGrantInherited,
		}
		for _, scope := range expected {
			if scope == "" {
				t.Error("scope of grant constant is empty")
			}
			if !containsScopeOfGrant(expected, scope) {
				t.Errorf("scope of grant %s not found in expected list", scope)
			}
		}
	})

	t.Run("limit constants", func(t *testing.T) {
		if SAIMaxApplicationNameLength <= 0 {
			t.Error("SAIMaxApplicationNameLength should be positive")
		}
		if SAIMaxDescriptionLength <= 0 {
			t.Error("SAIMaxDescriptionLength should be positive")
		}
		if SAIMaxIRILength <= 0 {
			t.Error("SAIMaxIRILength should be positive")
		}
		if SAIMaxDataGrantCount <= 0 {
			t.Error("SAIMaxDataGrantCount should be positive")
		}
		if SAIMaxDataInstanceCount <= 0 {
			t.Error("SAIMaxDataInstanceCount should be positive")
		}
		if SAIDefaultTimeout <= 0 {
			t.Error("SAIDefaultTimeout should be positive")
		}
		if SAIMaxTimeout <= 0 {
			t.Error("SAIMaxTimeout should be positive")
		}
		if SAIMaxInputSize <= 0 {
			t.Error("SAIMaxInputSize should be positive")
		}
	})
}

// Helper functions for tests
func containsAccessNecessity(slice []AccessNecessity, item AccessNecessity) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsAccessScenario(slice []AccessScenario, item AccessScenario) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsACLMode(slice []ACLMode, item ACLMode) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsScopeOfGrant(slice []ScopeOfGrant, item ScopeOfGrant) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// TestApplicationStruct tests the Application struct
func TestApplicationStruct(t *testing.T) {
	t.Run("valid application", func(t *testing.T) {
		app := Application{
			ID:                               "https://example.com/app#id",
			ApplicationName:                  "Test App",
			ApplicationDescription:           "A test application",
			ApplicationAuthor:                "https://author.example/#me",
			ApplicationThumbnail:             "https://example.com/thumbnail.png",
			HasAuthorizationCallbackEndpoint: "https://example.com/callback",
			AuthenticatesAs:                  "https://example.com/auth-method",
			HasAccessNeedGroup:               []AccessNeedGroup{},
		}

		if err := ValidateApplication(&app); err != nil {
			t.Errorf("expected valid application, got error: %v", err)
		}
	})

	t.Run("invalid application - nil", func(t *testing.T) {
		if err := ValidateApplication(nil); err == nil {
			t.Error("expected error for nil application")
		}
	})

	t.Run("invalid application - empty ID", func(t *testing.T) {
		app := Application{
			ID: "",
		}
		if err := ValidateApplication(&app); err == nil {
			t.Error("expected error for empty application ID")
		}
	})

	t.Run("invalid application - invalid WebID", func(t *testing.T) {
		app := Application{
			ID: "invalid-webid", // Missing fragment
		}
		if err := ValidateApplication(&app); err == nil {
			t.Error("expected error for invalid WebID")
		}
	})

	t.Run("invalid application - empty name", func(t *testing.T) {
		app := Application{
			ID:              "https://example.com/app#id",
			ApplicationName: "",
		}
		if err := ValidateApplication(&app); err == nil {
			t.Error("expected error for empty application name")
		}
	})

	t.Run("invalid application - name too long", func(t *testing.T) {
		app := Application{
			ID:              "https://example.com/app#id",
			ApplicationName: string(make([]byte, SAIMaxApplicationNameLength+1)),
		}
		if err := ValidateApplication(&app); err == nil {
			t.Error("expected error for name too long")
		}
	})
}

// TestAccessNeedGroupStruct tests the AccessNeedGroup struct
func TestAccessNeedGroupStruct(t *testing.T) {
	t.Run("valid access need group", func(t *testing.T) {
		group := AccessNeedGroup{
			ID:                      "https://example.com/need-group#id",
			AccessNecessity:         AccessNecessityRequired,
			AccessScenario:          AccessScenarioPersonalAccess,
			AuthenticatesAs:         "https://example.com/auth-method",
			HasAccessNeed:           []AccessNeed{},
			HasAccessDecoratorIndex: "",
		}

		if err := ValidateAccessNeedGroup(&group); err != nil {
			t.Errorf("expected valid access need group, got error: %v", err)
		}
	})

	t.Run("invalid access need group - nil", func(t *testing.T) {
		if err := ValidateAccessNeedGroup(nil); err == nil {
			t.Error("expected error for nil access need group")
		}
	})

	t.Run("invalid access need group - empty ID", func(t *testing.T) {
		group := AccessNeedGroup{
			ID: "",
		}
		if err := ValidateAccessNeedGroup(&group); err == nil {
			t.Error("expected error for empty access need group ID")
		}
	})

	t.Run("invalid access need group - invalid access necessity", func(t *testing.T) {
		group := AccessNeedGroup{
			ID:              "https://example.com/need-group#id",
			AccessNecessity: AccessNecessity("invalid"),
			AccessScenario:  AccessScenarioPersonalAccess,
		}
		if err := ValidateAccessNeedGroup(&group); err == nil {
			t.Error("expected error for invalid access necessity")
		}
	})
}

// TestAccessNeedStruct tests the AccessNeed struct
func TestAccessNeedStruct(t *testing.T) {
	t.Run("valid access need", func(t *testing.T) {
		need := AccessNeed{
			ID:                  "https://example.com/need#id",
			RegisteredShapeTree: "https://example.com/shape-tree",
			AccessMode:          []ACLMode{ACLModeRead, ACLModeWrite},
			AccessNecessity:     AccessNecessityRequired,
			InheritsFromNeed:    "",
		}

		if err := ValidateAccessNeed(&need); err != nil {
			t.Errorf("expected valid access need, got error: %v", err)
		}
	})

	t.Run("invalid access need - nil", func(t *testing.T) {
		if err := ValidateAccessNeed(nil); err == nil {
			t.Error("expected error for nil access need")
		}
	})

	t.Run("invalid access need - empty ID", func(t *testing.T) {
		need := AccessNeed{
			ID: "",
		}
		if err := ValidateAccessNeed(&need); err == nil {
			t.Error("expected error for empty access need ID")
		}
	})

	t.Run("invalid access need - empty shape tree", func(t *testing.T) {
		need := AccessNeed{
			ID:                  "https://example.com/need#id",
			RegisteredShapeTree: "",
			AccessMode:          []ACLMode{ACLModeRead},
			AccessNecessity:     AccessNecessityRequired,
		}
		if err := ValidateAccessNeed(&need); err == nil {
			t.Error("expected error for empty shape tree")
		}
	})

	t.Run("invalid access need - invalid access mode", func(t *testing.T) {
		need := AccessNeed{
			ID:                  "https://example.com/need#id",
			RegisteredShapeTree: "https://example.com/shape-tree",
			AccessMode:          []ACLMode{ACLMode("invalid")},
			AccessNecessity:     AccessNecessityRequired,
		}
		if err := ValidateAccessNeed(&need); err == nil {
			t.Error("expected error for invalid access mode")
		}
	})
}

// TestApplicationRegistrationStruct tests the ApplicationRegistration struct
func TestApplicationRegistrationStruct(t *testing.T) {
	t.Run("valid application registration", func(t *testing.T) {
		reg := ApplicationRegistration{
			ID:              "https://example.com/registration#id",
			RegisteredBy:    "https://user.example/#me",
			RegisteredWith:  "https://auth.example.com",
			RegisteredAt:    time.Now().UTC(),
			UpdatedAt:       time.Now().UTC(),
			RegisteredAgent: "https://app.example/#id",
			HasAccessGrant:  "",
		}

		if err := ValidateApplicationRegistration(&reg); err != nil {
			t.Errorf("expected valid application registration, got error: %v", err)
		}
	})

	t.Run("invalid application registration - nil", func(t *testing.T) {
		if err := ValidateApplicationRegistration(nil); err == nil {
			t.Error("expected error for nil application registration")
		}
	})

	t.Run("invalid application registration - empty ID", func(t *testing.T) {
		reg := ApplicationRegistration{
			ID: "",
		}
		if err := ValidateApplicationRegistration(&reg); err == nil {
			t.Error("expected error for empty application registration ID")
		}
	})

	t.Run("invalid application registration - zero timestamp", func(t *testing.T) {
		reg := ApplicationRegistration{
			ID:              "https://example.com/registration#id",
			RegisteredBy:    "https://user.example/#me",
			RegisteredWith:  "https://auth.example.com",
			RegisteredAt:    time.Time{}, // Zero time
			UpdatedAt:       time.Now().UTC(),
			RegisteredAgent: "https://app.example/#id",
		}
		if err := ValidateApplicationRegistration(&reg); err == nil {
			t.Error("expected error for zero timestamp")
		}
	})
}

// TestAccessGrantStruct tests the AccessGrant struct
func TestAccessGrantStruct(t *testing.T) {
	t.Run("valid access grant", func(t *testing.T) {
		grant := AccessGrant{
			ID:          "https://example.com/grant#id",
			GrantedBy:   "https://user.example/#me",
			GrantedWith: "https://auth.example.com",
			GrantedAt:   time.Now().UTC(),
			ProvidedAt:  time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
			FromAgent:   "https://user.example/#me",
			ViaAgent:    "https://user.example/#me",
			HasAccessGrantSubject: AccessGrantSubject{
				ID:                  "https://example.com/subject#id",
				AccessByAgent:       "https://user.example/#me",
				AccessByApplication: "https://app.example/#id",
			},
			HasAccessNeedGroup: []string{"https://example.com/need-group#id"},
			HasDataGrant:       []string{"https://example.com/data-grant#id"},
		}

		if err := ValidateAccessGrant(&grant); err != nil {
			t.Errorf("expected valid access grant, got error: %v", err)
		}
	})

	t.Run("invalid access grant - nil", func(t *testing.T) {
		if err := ValidateAccessGrant(nil); err == nil {
			t.Error("expected error for nil access grant")
		}
	})

	t.Run("invalid access grant - empty ID", func(t *testing.T) {
		grant := AccessGrant{
			ID: "",
		}
		if err := ValidateAccessGrant(&grant); err == nil {
			t.Error("expected error for empty access grant ID")
		}
	})

	t.Run("invalid access grant - zero granted at", func(t *testing.T) {
		grant := AccessGrant{
			ID:          "https://example.com/grant#id",
			GrantedBy:   "https://user.example/#me",
			GrantedWith: "https://auth.example.com",
			GrantedAt:   time.Time{}, // Zero time
			ProvidedAt:  time.Now().UTC(),
			FromAgent:   "https://user.example/#me",
			ViaAgent:    "https://user.example/#me",
		}
		if err := ValidateAccessGrant(&grant); err == nil {
			t.Error("expected error for zero granted at timestamp")
		}
	})
}

// TestDataRegistrationStruct tests the DataRegistration struct
func TestDataRegistrationStruct(t *testing.T) {
	t.Run("valid data registration", func(t *testing.T) {
		reg := DataRegistration{
			ID:                  "https://example.com/data-registration#id",
			RegisteredShapeTree: "https://example.com/shape-tree",
			RegisteredAt:        time.Now().UTC(),
			RegisteredBy:        "https://user.example/#me",
			RegisteredWith:      "https://app.example/#id",
			IRIPrefix:           "https://data.example.com/",
			Contains:            []string{"https://data.example.com/instance1"},
		}

		if err := ValidateDataRegistration(&reg); err != nil {
			t.Errorf("expected valid data registration, got error: %v", err)
		}
	})

	t.Run("invalid data registration - nil", func(t *testing.T) {
		if err := ValidateDataRegistration(nil); err == nil {
			t.Error("expected error for nil data registration")
		}
	})

	t.Run("invalid data registration - empty ID", func(t *testing.T) {
		reg := DataRegistration{
			ID: "",
		}
		if err := ValidateDataRegistration(&reg); err == nil {
			t.Error("expected error for empty data registration ID")
		}
	})

	t.Run("invalid data registration - zero timestamp", func(t *testing.T) {
		reg := DataRegistration{
			ID:                  "https://example.com/data-registration#id",
			RegisteredShapeTree: "https://example.com/shape-tree",
			RegisteredAt:        time.Time{}, // Zero time
			RegisteredBy:        "https://user.example/#me",
			IRIPrefix:           "https://data.example.com/",
		}
		if err := ValidateDataRegistration(&reg); err == nil {
			t.Error("expected error for zero timestamp")
		}
	})
}

// TestDataGrantStruct tests the DataGrant struct
func TestDataGrantStruct(t *testing.T) {
	t.Run("valid data grant", func(t *testing.T) {
		grant := DataGrant{
			ID:                  "https://example.com/data-grant#id",
			DataOwner:           "https://user.example/#me",
			GrantedBy:           "https://user.example/#me",
			RegisteredShapeTree: "https://example.com/shape-tree",
			HasDataRegistration: "https://example.com/data-registration#id",
			AccessMode:          []ACLMode{ACLModeRead, ACLModeWrite},
			ScopeOfGrant:        ScopeOfGrantAllFromRegistry,
			HasDataInstance:     []string{"https://data.example.com/instance1"},
			InheritsFromGrant:   "",
			DelegationOfGrant:   "",
		}

		if err := ValidateDataGrant(&grant); err != nil {
			t.Errorf("expected valid data grant, got error: %v", err)
		}
	})

	t.Run("invalid data grant - nil", func(t *testing.T) {
		if err := ValidateDataGrant(nil); err == nil {
			t.Error("expected error for nil data grant")
		}
	})

	t.Run("invalid data grant - empty ID", func(t *testing.T) {
		grant := DataGrant{
			ID: "",
		}
		if err := ValidateDataGrant(&grant); err == nil {
			t.Error("expected error for empty data grant ID")
		}
	})

	t.Run("invalid data grant - invalid scope", func(t *testing.T) {
		grant := DataGrant{
			ID:                  "https://example.com/data-grant#id",
			DataOwner:           "https://user.example/#me",
			GrantedBy:           "https://user.example/#me",
			RegisteredShapeTree: "https://example.com/shape-tree",
			HasDataRegistration: "https://example.com/data-registration#id",
			AccessMode:          []ACLMode{ACLModeRead},
			ScopeOfGrant:        ScopeOfGrant("invalid"),
		}
		if err := ValidateDataGrant(&grant); err == nil {
			t.Error("expected error for invalid scope of grant")
		}
	})
}

// TestDataInstanceStruct tests the DataInstance struct
func TestDataInstanceStruct(t *testing.T) {
	t.Run("valid data instance", func(t *testing.T) {
		instance := DataInstance{
			ID:          "https://data.example.com/instance1",
			Type:        "https://example.com/ns#Project",
			ShapeTree:   "https://example.com/shape-tree",
			Data:        []byte("test data"),
			ContentType: "application/json",
		}

		if err := ValidateDataInstance(&instance); err != nil {
			t.Errorf("expected valid data instance, got error: %v", err)
		}
	})

	t.Run("invalid data instance - nil", func(t *testing.T) {
		if err := ValidateDataInstance(nil); err == nil {
			t.Error("expected error for nil data instance")
		}
	})

	t.Run("invalid data instance - empty ID", func(t *testing.T) {
		instance := DataInstance{
			ID: "",
		}
		if err := ValidateDataInstance(&instance); err == nil {
			t.Error("expected error for empty data instance ID")
		}
	})

	t.Run("invalid data instance - empty content type", func(t *testing.T) {
		instance := DataInstance{
			ID:          "https://data.example.com/instance1",
			ContentType: "",
		}
		if err := ValidateDataInstance(&instance); err == nil {
			t.Error("expected error for empty content type")
		}
	})

	t.Run("invalid data instance - data too large", func(t *testing.T) {
		instance := DataInstance{
			ID:          "https://data.example.com/instance1",
			ContentType: "application/json",
			Data:        make([]byte, SAIMaxInputSize+1),
		}
		if err := ValidateDataInstance(&instance); err == nil {
			t.Error("expected error for data too large")
		}
	})
}

// TestShapeTreeStruct tests the ShapeTree struct
func TestShapeTreeStruct(t *testing.T) {
	t.Run("valid shape tree", func(t *testing.T) {
		tree := ShapeTree{
			ID:          "https://example.com/shape-tree#id",
			ExpectsType: "https://example.com/ns#Resource",
			Shape:       "https://example.com/shapes#Project",
			References:  []ShapeTreeReference{},
		}

		if err := ValidateShapeTree(&tree); err != nil {
			t.Errorf("expected valid shape tree, got error: %v", err)
		}
	})

	t.Run("invalid shape tree - nil", func(t *testing.T) {
		if err := ValidateShapeTree(nil); err == nil {
			t.Error("expected error for nil shape tree")
		}
	})

	t.Run("invalid shape tree - empty ID", func(t *testing.T) {
		tree := ShapeTree{
			ID: "",
		}
		if err := ValidateShapeTree(&tree); err == nil {
			t.Error("expected error for empty shape tree ID")
		}
	})
}

// TestAuthorizationAgentStruct tests the AuthorizationAgent struct
func TestAuthorizationAgentStruct(t *testing.T) {
	t.Run("valid authorization agent", func(t *testing.T) {
		agent := AuthorizationAgent{
			ID:               "https://auth.example.com",
			AgentRegistrySet: []string{"https://auth.example.com/registry"},
		}

		if err := ValidateAuthorizationAgent(&agent); err != nil {
			t.Errorf("expected valid authorization agent, got error: %v", err)
		}
	})

	t.Run("invalid authorization agent - nil", func(t *testing.T) {
		if err := ValidateAuthorizationAgent(nil); err == nil {
			t.Error("expected error for nil authorization agent")
		}
	})

	t.Run("invalid authorization agent - empty ID", func(t *testing.T) {
		agent := AuthorizationAgent{
			ID: "",
		}
		if err := ValidateAuthorizationAgent(&agent); err == nil {
			t.Error("expected error for empty authorization agent ID")
		}
	})
}

// TestValidationFunctions tests the individual validation functions
func TestValidationFunctions(t *testing.T) {
	t.Run("ValidateWebID", func(t *testing.T) {
		testCases := []struct {
			webID   string
			wantErr bool
		}{
			{"https://example.com/user#me", false},
			{"http://example.com/user#me", false},
			{"https://example.com/user#", true},             // Empty fragment
			{"https://example.com/user", true},              // No fragment
			{"", true},                                      // Empty
			{"ftp://example.com/user#me", true},             // Invalid scheme
			{string(make([]byte, SAIMaxIRILength+1)), true}, // Too long
		}

		for _, tc := range testCases {
			err := ValidateWebID(tc.webID)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateWebID(%q) error = %v, wantErr %v", tc.webID, err, tc.wantErr)
			}
		}
	})

	t.Run("ValidateURL", func(t *testing.T) {
		testCases := []struct {
			url     string
			wantErr bool
		}{
			{"https://example.com", false},
			{"http://example.com", false},
			{"https://example.com/path?query=value", false},
			{"", false},                 // Empty URLs are allowed (optional fields)
			{"ftp://example.com", true}, // Invalid scheme
			{string(make([]byte, SAIMaxIRILength+1)), true}, // Too long
		}

		for _, tc := range testCases {
			err := ValidateURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateURL(%q) error = %v, wantErr %v", tc.url, err, tc.wantErr)
			}
		}
	})

	t.Run("ValidateIRI", func(t *testing.T) {
		testCases := []struct {
			iri     string
			wantErr bool
		}{
			{"https://example.com/resource", false},
			{"http://example.com/resource", false},
			{"urn:uuid:12345678-1234-1234-1234-123456789012", false},
			{"pm:Project", false},
			{"", true},                                      // Empty
			{string(make([]byte, SAIMaxIRILength+1)), true}, // Too long
		}

		for _, tc := range testCases {
			err := ValidateIRI(tc.iri)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateIRI(%q) error = %v, wantErr %v", tc.iri, err, tc.wantErr)
			}
		}
	})

	t.Run("ValidateApplicationName", func(t *testing.T) {
		testCases := []struct {
			name    string
			wantErr bool
		}{
			{"Test App", false},
			{"A", false},
			{"", true}, // Empty
			{string(make([]byte, SAIMaxApplicationNameLength+1)), true}, // Too long
			{"Test\nApp", true}, // Control character
		}

		for _, tc := range testCases {
			err := ValidateApplicationName(tc.name)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateApplicationName(%q) error = %v, wantErr %v", tc.name, err, tc.wantErr)
			}
		}
	})
}

// TestCompleteSAIFlow tests a complete SAI flow from application registration to access grant
func TestCompleteSAIFlow(t *testing.T) {
	t.Run("complete flow", func(t *testing.T) {
		// 1. Create application
		app := Application{
			ID:                               "https://projectron.example/#app",
			ApplicationName:                  "Projectron",
			ApplicationDescription:           "Manage projects with ease",
			ApplicationAuthor:                "https://acme.example/#corp",
			ApplicationThumbnail:             "https://projectron.example/thumb.svg",
			HasAuthorizationCallbackEndpoint: "https://projectron.example/callback",
			AuthenticatesAs:                  "https://projectron.example/#app",
			HasAccessNeedGroup: []AccessNeedGroup{
				{
					ID:              "https://projectron.example/#need-group-pm",
					AccessNecessity: AccessNecessityRequired,
					AccessScenario:  AccessScenarioPersonalAccess,
					AuthenticatesAs: "https://projectron.example/#app",
					HasAccessNeed: []AccessNeed{
						{
							ID:                  "https://projectron.example/#need-project",
							RegisteredShapeTree: "solidtrees:Project",
							AccessMode:          []ACLMode{ACLModeRead, ACLModeWrite},
							AccessNecessity:     AccessNecessityRequired,
						},
					},
				},
			},
		}

		if err := ValidateApplication(&app); err != nil {
			t.Fatalf("Failed to validate application: %v", err)
		}

		// 2. Create application registration
		reg := ApplicationRegistration{
			ID:              "urn:sai:registration:test123",
			RegisteredBy:    "https://alice.example/#id",
			RegisteredWith:  "https://auth.alice.example/",
			RegisteredAt:    time.Now().UTC(),
			UpdatedAt:       time.Now().UTC(),
			RegisteredAgent: "https://projectron.example/#app",
			HasAccessGrant:  "",
		}

		if err := ValidateApplicationRegistration(&reg); err != nil {
			t.Fatalf("Failed to validate application registration: %v", err)
		}

		// 3. Create access grant
		grant := AccessGrant{
			ID:          "urn:sai:access-grant:test456",
			GrantedBy:   "https://alice.example/#id",
			GrantedWith: "https://auth.alice.example/",
			GrantedAt:   time.Now().UTC(),
			ProvidedAt:  time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
			FromAgent:   "https://alice.example/#id",
			ViaAgent:    "https://alice.example/#id",
			HasAccessGrantSubject: AccessGrantSubject{
				ID:                  "urn:sai:grant-subject:test789",
				AccessByAgent:       "https://alice.example/#id",
				AccessByApplication: "https://projectron.example/#app",
			},
			HasAccessNeedGroup: []string{"https://projectron.example/#need-group-pm"},
			HasDataGrant:       []string{"urn:sai:data-grant:test101"},
		}

		if err := ValidateAccessGrant(&grant); err != nil {
			t.Fatalf("Failed to validate access grant: %v", err)
		}

		// 4. Create data registration
		dataReg := DataRegistration{
			ID:                  "urn:sai:data-registration:test202",
			RegisteredShapeTree: "solidtrees:Project",
			RegisteredAt:        time.Now().UTC(),
			RegisteredBy:        "https://alice.example/#id",
			RegisteredWith:      "https://projectron.example/#app",
			IRIPrefix:           "https://pro.alice.example/",
			Contains:            []string{"https://pro.alice.example/ccbd77ae-f769-4e07-b41f-5136501e13e7#project"},
		}

		if err := ValidateDataRegistration(&dataReg); err != nil {
			t.Fatalf("Failed to validate data registration: %v", err)
		}

		// 5. Create data grant
		dataGrant := DataGrant{
			ID:                  "urn:sai:data-grant:test101",
			DataOwner:           "https://alice.example/#id",
			GrantedBy:           "https://alice.example/#id",
			RegisteredShapeTree: "solidtrees:Project",
			HasDataRegistration: "urn:sai:data-registration:test202",
			AccessMode:          []ACLMode{ACLModeRead, ACLModeWrite},
			ScopeOfGrant:        ScopeOfGrantAllFromRegistry,
			HasDataInstance:     []string{"https://pro.alice.example/ccbd77ae-f769-4e07-b41f-5136501e13e7#project"},
		}

		if err := ValidateDataGrant(&dataGrant); err != nil {
			t.Fatalf("Failed to validate data grant: %v", err)
		}

		// All validations passed
		t.Log("Complete SAI flow validation passed")
	})
}

// TestErrorTypes tests that error types are properly defined
func TestErrorTypes(t *testing.T) {
	t.Run("error variables", func(t *testing.T) {
		if ErrSAIInvalidApplication == "" {
			t.Error("ErrSAIInvalidApplication should not be empty")
		}
		if ErrSAIApplicationNotFound == "" {
			t.Error("ErrSAIApplicationNotFound should not be empty")
		}
		if ErrSAIAuthorizationFailed == "" {
			t.Error("ErrSAIAuthorizationFailed should not be empty")
		}
		if ErrSAIDataRegistrationFailed == "" {
			t.Error("ErrSAIDataRegistrationFailed should not be empty")
		}
		if ErrSAIAccessGrantFailed == "" {
			t.Error("ErrSAIAccessGrantFailed should not be empty")
		}
		if ErrSAIInvalidDataInstance == "" {
			t.Error("ErrSAIInvalidDataInstance should not be empty")
		}
		if ErrSAIShapeTreeNotFound == "" {
			t.Error("ErrSAIShapeTreeNotFound should not be empty")
		}
		if ErrSAIInsufficientPermissions == "" {
			t.Error("ErrSAIInsufficientPermissions should not be empty")
		}
		if ErrSAIInvalidScope == "" {
			t.Error("ErrSAIInvalidScope should not be empty")
		}
	})
}

// TestContentTypes tests content type constants
func TestContentTypes(t *testing.T) {
	t.Run("content type constants", func(t *testing.T) {
		expected := []string{
			ContentTypeApplicationJSON,
			ContentTypeApplicationLDJSON,
			ContentTypeTextTurtle,
			ContentTypeSAIApplicationJSON,
			ContentTypeSAIApplicationLDJSON,
		}

		for _, ct := range expected {
			if ct == "" {
				t.Error("content type constant is empty")
			}
		}
	})
}
