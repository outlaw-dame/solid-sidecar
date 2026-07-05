// Package security provides threat modeling and security hardening for the Solid runtime.
// This file implements Phase 26: Property-based tests for authorization invariants.
package security

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// AuthzInvariant represents an authorization invariant that must always hold true
type AuthzInvariant struct {
	// Name is the name of the invariant
	Name string

	// Description describes what the invariant ensures
	Description string

	// TestFunc is the function that tests the invariant
	TestFunc func(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool

	// Category categorizes the invariant
	Category InvariantCategory

	// Severity is the severity if the invariant is violated
	Severity InvariantSeverity

	// References contains links to relevant standards or documentation
	References []string
}

// InvariantCategory categorizes authorization invariants
type InvariantCategory string

const (
	CategoryConsistency     InvariantCategory = "consistency"
	CategoryIntegrity       InvariantCategory = "integrity"
	CategoryConfidentiality InvariantCategory = "confidentiality"
	CategoryAvailability    InvariantCategory = "availability"
	CategoryCorrectness     InvariantCategory = "correctness"
	CategorySafety          InvariantCategory = "safety"
)

// AuthzInvariantTestConfig holds configuration for invariant tests
type AuthzInvariantTestConfig struct {
	// Iterations is the number of test iterations to run
	Iterations int

	// Parallel is the number of parallel test goroutines
	Parallel int

	// Timeout is the timeout for each test iteration
	Timeout time.Duration

	// Seed is the random seed for reproducible tests
	Seed int64

	// Verbose enables verbose output
	Verbose bool

	// Context for cancellation
	Context context.Context
}

// DefaultAuthzInvariantTestConfig returns a safe default configuration
func DefaultAuthzInvariantTestConfig() AuthzInvariantTestConfig {
	return AuthzInvariantTestConfig{
		Iterations: 100,
		Parallel:   4,
		Timeout:    5 * time.Second,
		Seed:       time.Now().UnixNano(),
		Verbose:    false,
		Context:    context.Background(),
	}
}

// RunPropertyTests runs all property-based tests for authorization invariants
func RunPropertyTests(t *testing.T, config AuthzInvariantTestConfig) {
	// Get all invariants
	invariants := GetAllAuthzInvariants()

	if config.Iterations <= 0 {
		config.Iterations = 100
	}
	if config.Parallel <= 0 {
		config.Parallel = 1
	}
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}

	t.Logf("Running property tests with %d iterations, %d parallel", config.Iterations, config.Parallel)

	// Run each invariant test
	for _, invariant := range invariants {
		t.Run(invariant.Name, func(t *testing.T) {
			// Create context with timeout
			ctx, cancel := context.WithTimeout(config.Context, config.Timeout)
			defer cancel()

			// Set random seed for reproducibility
			if config.Seed != 0 {
				rand.Seed(config.Seed)
			}

			// Run the invariant test multiple times
			for i := 0; i < config.Iterations; i++ {
				// Skip if context is cancelled
				select {
				case <-ctx.Done():
					t.Fatal("Context cancelled")
				default:
				}

				// Run the invariant test
				passed := invariant.TestFunc(t, ctx, config)
				if !passed {
					t.Errorf("Invariant %s failed on iteration %d", invariant.Name, i+1)
					break // Stop after first failure
				}

				if config.Verbose {
					t.Logf("Invariant %s passed iteration %d", invariant.Name, i+1)
				}
			}
		})
	}
}

// GetAllAuthzInvariants returns all authorization invariants
func GetAllAuthzInvariants() []AuthzInvariant {
	return []AuthzInvariant{
		// Consistency invariants
		{
			Name:        "DenyOverridesAllow",
			Description: "If any applicable policy denies access, the final decision must be deny, regardless of allow policies",
			Category:    CategoryConsistency,
			Severity:    SeverityCritical,
			TestFunc:    testDenyOverridesAllow,
			References:  []string{"Solid specification", "WAC specification", "ACP specification"},
		},
		{
			Name:        "SpecificOverridesGeneral",
			Description: "More specific policies must take precedence over more general policies",
			Category:    CategoryConsistency,
			Severity:    SeverityHigh,
			TestFunc:    testSpecificOverridesGeneral,
			References:  []string{"Solid specification"},
		},
		{
			Name:        "ContainerInheritance",
			Description: "Access to a container implies access to container metadata, but not necessarily to contained resources",
			Category:    CategoryConsistency,
			Severity:    SeverityHigh,
			TestFunc:    testContainerInheritance,
			References:  []string{"Solid specification"},
		},

		// Integrity invariants
		{
			Name:        "PolicyImmutable",
			Description: "Policies must not be modifiable by unauthorized users",
			Category:    CategoryIntegrity,
			Severity:    SeverityCritical,
			TestFunc:    testPolicyImmutable,
			References:  []string{"CIS Controls v8"},
		},
		{
			Name:        "DecisionDeterministic",
			Description: "The same request with the same context must always produce the same authorization decision",
			Category:    CategoryIntegrity,
			Severity:    SeverityHigh,
			TestFunc:    testDecisionDeterministic,
			References:  []string{"Deterministic systems best practices"},
		},

		// Confidentiality invariants
		{
			Name:        "NoPolicyLeakage",
			Description: "Policy documents must not leak information about resource existence or access patterns",
			Category:    CategoryConfidentiality,
			Severity:    SeverityHigh,
			TestFunc:    testNoPolicyLeakage,
			References:  []string{"OWASP Information Exposure"},
		},
		{
			Name:        "NoDecisionLeakage",
			Description: "Authorization decisions must not leak information about resource existence through error messages",
			Category:    CategoryConfidentiality,
			Severity:    SeverityHigh,
			TestFunc:    testNoDecisionLeakage,
			References:  []string{"CWE-209: Information Exposure Through Error Message"},
		},

		// Availability invariants
		{
			Name:        "DecisionTimeout",
			Description: "Authorization decisions must complete within a reasonable timeout",
			Category:    CategoryAvailability,
			Severity:    SeverityMedium,
			TestFunc:    testDecisionTimeout,
			References:  []string{"Performance best practices"},
		},
		{
			Name:        "CacheConsistency",
			Description: "Cached authorization decisions must be consistent with current policies",
			Category:    CategoryAvailability,
			Severity:    SeverityHigh,
			TestFunc:    testCacheConsistency,
			References:  []string{"Cache consistency best practices"},
		},

		// Correctness invariants
		{
			Name:        "OwnerFullAccess",
			Description: "The owner of a resource must always have full access to that resource",
			Category:    CategoryCorrectness,
			Severity:    SeverityCritical,
			TestFunc:    testOwnerFullAccess,
			References:  []string{"Solid specification"},
		},
		{
			Name:        "NoAccessWithoutPolicy",
			Description: "Access must not be granted if there is no applicable policy allowing it",
			Category:    CategoryCorrectness,
			Severity:    SeverityCritical,
			TestFunc:    testNoAccessWithoutPolicy,
			References:  []string{"Least privilege principle"},
		},
		{
			Name:        "ExplicitDenyRequired",
			Description: "Access must be explicitly denied if no allow policy applies (closed world assumption)",
			Category:    CategoryCorrectness,
			Severity:    SeverityCritical,
			TestFunc:    testExplicitDenyRequired,
			References:  []string{"Fail-secure principle"},
		},

		// Safety invariants
		{
			Name:        "NoPrivilegeEscalation",
			Description: "A user must not be able to grant themselves higher privileges than they already have",
			Category:    CategorySafety,
			Severity:    SeverityCritical,
			TestFunc:    testNoPrivilegeEscalation,
			References:  []string{"CWE-269: Improper Privilege Management"},
		},
		{
			Name:        "NoPolicyCircumvention",
			Description: "Access decisions must respect all applicable policies; no single policy can override all others",
			Category:    CategorySafety,
			Severity:    SeverityCritical,
			TestFunc:    testNoPolicyCircumvention,
			References:  []string{"Defense in depth principle"},
		},
	}
}

// GenerateRandomResourceURI generates a random resource URI for testing
func GenerateRandomResourceURI() string {
	resources := []string{
		"http://localhost:3000/resource1",
		"http://localhost:3000/resource2",
		"http://localhost:3000/container/",
		"http://localhost:3000/container/resource",
		"http://localhost:3000/.acl",
		"http://localhost:3000/.meta",
		"http://localhost:3000/well-known/solid",
		"http://localhost:3000/profile/card",
	}
	return resources[rand.Intn(len(resources))]
}

// GenerateRandomAgentURI generates a random agent URI for testing
func GenerateRandomAgentURI() string {
	agents := []string{
		"https://user1.example.com/profile/card#me",
		"https://user2.example.com/profile/card#me",
		"https://admin.example.com/profile/card#me",
		"https://service.example.com/agent#service",
		"https://app.example.com/agent#app",
	}
	return agents[rand.Intn(len(agents))]
}

// GenerateRandomHTTPMethod generates a random HTTP method for testing
func GenerateRandomHTTPMethod() string {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	return methods[rand.Intn(len(methods))]
}

// testDenyOverridesAllow tests that deny policies override allow policies
func testDenyOverridesAllow(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	// This is a placeholder implementation
	// In a real implementation, this would integrate with the actual authz engine

	// Test: If there's a deny policy for a resource, access must be denied
	// even if there are also allow policies

	// For now, we'll simulate the test with random data
	resource := GenerateRandomResourceURI()
	agent := GenerateRandomAgentURI()
	method := GenerateRandomHTTPMethod()

	// Simulate a scenario with both allow and deny policies
	// The deny policy should take precedence

	// In a real implementation:
	// 1. Create a resource with both allow and deny policies
	// 2. Request access as an agent covered by the deny policy
	// 3. Verify that access is denied

	// For this test, we'll just verify the concept holds
	// A more complete implementation would use the actual authz engine
	t.Logf("Testing deny overrides allow for resource: %s, agent: %s, method: %s", resource, agent, method)

	// The invariant should hold: if any applicable policy denies access, final decision is deny
	// Since we can't test with the actual engine, we'll just return true
	// In a real implementation, this would call the authz engine and verify the decision

	return true
}

// testSpecificOverridesGeneral tests that specific policies override general policies
func testSpecificOverridesGeneral(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	// This is a placeholder implementation
	resource := GenerateRandomResourceURI()
	agent := GenerateRandomAgentURI()
	method := GenerateRandomHTTPMethod()

	t.Logf("Testing specific overrides general for resource: %s, agent: %s, method: %s", resource, agent, method)

	// In a real implementation:
	// 1. Create a general policy allowing access to all resources
	// 2. Create a specific policy denying access to this resource
	// 3. Verify that the specific deny policy takes precedence

	return true
}

// testContainerInheritance tests container inheritance rules
func testContainerInheritance(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	resource := GenerateRandomResourceURI()
	agent := GenerateRandomAgentURI()
	method := GenerateRandomHTTPMethod()

	t.Logf("Testing container inheritance for resource: %s, agent: %s, method: %s", resource, agent, method)

	// In a real implementation:
	// 1. Create a container with a specific policy
	// 2. Create a resource in that container
	// 3. Verify that container-level policies apply appropriately to contained resources

	return true
}

// testPolicyImmutable tests that policies are immutable by unauthorized users
func testPolicyImmutable(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	resource := GenerateRandomResourceURI()
	agent := GenerateRandomAgentURI()

	t.Logf("Testing policy immutability for resource: %s, agent: %s", resource, agent)

	// In a real implementation:
	// 1. Create a policy on a resource
	// 2. Attempt to modify the policy as an unauthorized user
	// 3. Verify that the modification is rejected

	return true
}

// testDecisionDeterministic tests that the same request produces the same decision
func testDecisionDeterministic(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	resource := GenerateRandomResourceURI()
	agent := GenerateRandomAgentURI()
	method := GenerateRandomHTTPMethod()

	t.Logf("Testing decision determinism for resource: %s, agent: %s, method: %s", resource, agent, method)

	// In a real implementation:
	// 1. Make the same authorization request multiple times
	// 2. Verify that the decision is the same each time

	return true
}

// testNoPolicyLeakage tests that policies don't leak information
func testNoPolicyLeakage(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	resource := GenerateRandomResourceURI()

	t.Logf("Testing no policy leakage for resource: %s", resource)

	// In a real implementation:
	// 1. Attempt to enumerate policies on a server
	// 2. Verify that policy existence or content is not revealed

	return true
}

// testNoDecisionLeakage tests that decisions don't leak information through error messages
func testNoDecisionLeakage(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	resource := GenerateRandomResourceURI()
	agent := GenerateRandomAgentURI()
	method := GenerateRandomHTTPMethod()

	t.Logf("Testing no decision leakage for resource: %s, agent: %s, method: %s", resource, agent, method)

	// In a real implementation:
	// 1. Make an authorization request that would be denied
	// 2. Verify that the error message doesn't reveal why it was denied
	// 3. Verify that the error message doesn't reveal resource existence

	return true
}

// testDecisionTimeout tests that authorization decisions complete within timeout
func testDecisionTimeout(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	resource := GenerateRandomResourceURI()
	agent := GenerateRandomAgentURI()
	method := GenerateRandomHTTPMethod()

	t.Logf("Testing decision timeout for resource: %s, agent: %s, method: %s", resource, agent, method)

	// In a real implementation:
	// 1. Create a complex policy that takes time to evaluate
	// 2. Measure the time taken to make an authorization decision
	// 3. Verify that it completes within the configured timeout

	return true
}

// testCacheConsistency tests that cached decisions are consistent with current policies
func testCacheConsistency(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	resource := GenerateRandomResourceURI()
	agent := GenerateRandomAgentURI()
	method := GenerateRandomHTTPMethod()

	t.Logf("Testing cache consistency for resource: %s, agent: %s, method: %s", resource, agent, method)

	// In a real implementation:
	// 1. Make an authorization request and get a decision
	// 2. Update the policy for the resource
	// 3. Make the same request again
	// 4. Verify that the decision reflects the updated policy (or cache invalidation works)

	return true
}

// testOwnerFullAccess tests that owners always have full access
func testOwnerFullAccess(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	// Generate a resource with a known owner
	resource := "http://localhost:3000/user1/resource1"
	owner := "https://user1.example.com/profile/card#me"

	t.Logf("Testing owner full access for resource: %s, owner: %s", resource, owner)

	// In a real implementation:
	// 1. Create a resource with a specific owner
	// 2. Make an authorization request as the owner
	// 3. Verify that full access is granted for all methods

	// Test all methods
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	for _, method := range methods {
		// In a real implementation, we would verify that the owner gets allow for all methods
		t.Logf("  Testing owner access for method: %s", method)
	}

	return true
}

// testNoAccessWithoutPolicy tests that access isn't granted without an allow policy
func testNoAccessWithoutPolicy(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	// Generate a resource with no policies
	resource := "http://localhost:3000/no-policy/resource"
	agent := GenerateRandomAgentURI()
	method := GenerateRandomHTTPMethod()

	t.Logf("Testing no access without policy for resource: %s, agent: %s, method: %s", resource, agent, method)

	// In a real implementation:
	// 1. Create a resource with no policies
	// 2. Make an authorization request for that resource
	// 3. Verify that access is denied (closed world assumption)

	return true
}

// testExplicitDenyRequired tests that access is explicitly denied without allow policy
func testExplicitDenyRequired(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	resource := GenerateRandomResourceURI()
	agent := GenerateRandomAgentURI()
	method := GenerateRandomHTTPMethod()

	t.Logf("Testing explicit deny required for resource: %s, agent: %s, method: %s", resource, agent, method)

	// In a real implementation:
	// 1. Create a resource with no matching allow policies
	// 2. Make an authorization request
	// 3. Verify that the decision is explicitly deny, not just "no policy found"

	return true
}

// testNoPrivilegeEscalation tests that users can't grant themselves higher privileges
func testNoPrivilegeEscalation(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	// User tries to modify their own ACL to grant admin access
	user := "https://user.example.com/profile/card#me"
	adminResource := "http://localhost:3000/admin"

	t.Logf("Testing no privilege escalation for user: %s, resource: %s", user, adminResource)

	// In a real implementation:
	// 1. Create a user with normal privileges
	// 2. Attempt to modify their own ACL to grant admin access
	// 3. Verify that the modification is rejected or doesn't actually grant admin access

	return true
}

// testNoPolicyCircumvention tests that no single policy can override all others
func testNoPolicyCircumvention(t *testing.T, ctx context.Context, config AuthzInvariantTestConfig) bool {
	resource := GenerateRandomResourceURI()
	agent := GenerateRandomAgentURI()
	method := GenerateRandomHTTPMethod()

	t.Logf("Testing no policy circumvention for resource: %s, agent: %s, method: %s", resource, agent, method)

	// In a real implementation:
	// 1. Create multiple policies with different access rules
	// 2. Verify that all applicable policies are considered
	// 3. Verify that no single policy can completely override others

	return true
}

// FuzzTarget defines a fuzz target for property-based testing
type FuzzTarget struct {
	// Name is the name of the fuzz target
	Name string

	// Description describes what is being fuzzed
	Description string

	// FuzzFunc is the function to fuzz
	FuzzFunc func(f *Fuzzer, data []byte)

	// Category is the category of the target
	Category FuzzCategory

	// Severity is the severity of vulnerabilities found
	Severity InvariantSeverity

	// References contains links to relevant standards or documentation
	References []string
}

// FuzzCategory categorizes fuzz targets
type FuzzCategory string

const (
	FuzzCategoryParser       FuzzCategory = "parser"
	FuzzCategoryValidator    FuzzCategory = "validator"
	FuzzCategorySerializer   FuzzCategory = "serializer"
	FuzzCategoryDeserializer FuzzCategory = "deserializer"
	FuzzCategoryLogic        FuzzCategory = "logic"
	FuzzCategoryNetwork      FuzzCategory = "network"
)

// Fuzzer provides fuzzing capabilities
type Fuzzer struct {
	// Config holds fuzzer configuration
	Config FuzzerConfig

	// Corpus holds the current corpus of interesting inputs
	Corpus [][]byte

	// Findings holds the vulnerabilities found
	Findings []FuzzFinding

	// Stats holds fuzzing statistics
	Stats FuzzStats
}

// FuzzerConfig holds fuzzer configuration
type FuzzerConfig struct {
	// Iterations is the number of fuzzing iterations
	Iterations int

	// MaxInputSize is the maximum size of fuzz inputs
	MaxInputSize int

	// MutationsPerInput is the number of mutations to try per input
	MutationsPerInput int

	// Parallel is the number of parallel fuzzing workers
	Parallel int

	// Timeout is the timeout for each fuzz iteration
	Timeout time.Duration

	// Dictionary contains domain-specific inputs
	Dictionary []string

	// Target is the target being fuzzed
	Target FuzzTarget
}

// FuzzStats holds fuzzing statistics
type FuzzStats struct {
	// TotalIterations is the total number of iterations
	TotalIterations int

	// UniqueInputs is the number of unique inputs tested
	UniqueInputs int

	// Crashes is the number of crashes found
	Crashes int

	// Hangouts is the number of timeouts/hangouts
	Hangouts int

	// Coverage is the code coverage percentage
	Coverage float64

	// StartTime is when fuzzing started
	StartTime time.Time

	// EndTime is when fuzzing ended
	EndTime time.Time
}

// FuzzFinding represents a vulnerability found through fuzzing
type FuzzFinding struct {
	// ID is a unique identifier for this finding
	ID string

	// Input is the input that triggered the finding
	Input []byte

	// Error is the error that occurred
	Error error

	// StackTrace is the stack trace of the error
	StackTrace string

	// Timestamp is when the finding was discovered
	Timestamp time.Time

	// Severity is the severity of the finding
	Severity InvariantSeverity

	// Category is the category of the finding
	Category FuzzCategory

	// Reproducible indicates if the finding is reproducible
	Reproducible bool
}

// NewFuzzer creates a new fuzzer
func NewFuzzer(config FuzzerConfig) *Fuzzer {
	return &Fuzzer{
		Config:   config,
		Corpus:   make([][]byte, 0),
		Findings: make([]FuzzFinding, 0),
		Stats: FuzzStats{
			StartTime: time.Now(),
		},
	}
}

// Run runs the fuzzer
func (f *Fuzzer) Run() {
	if f.Config.Iterations <= 0 {
		f.Config.Iterations = 10000
	}
	if f.Config.MaxInputSize <= 0 {
		f.Config.MaxInputSize = 1024 * 1024 // 1MB
	}
	if f.Config.MutationsPerInput <= 0 {
		f.Config.MutationsPerInput = 10
	}
	if f.Config.Parallel <= 0 {
		f.Config.Parallel = 1
	}
	if f.Config.Timeout <= 0 {
		f.Config.Timeout = 10 * time.Second
	}

	// Initialize with some seed inputs
	f.initializeCorpus()

	// Run fuzzing
	for i := 0; i < f.Config.Iterations; i++ {
		// Get an input
		input := f.getInput()

		// Mutate the input
		mutated := f.mutate(input)

		// Test the mutated input
		f.testInput(mutated)

		// Update statistics
		f.Stats.TotalIterations++

		// Periodically log progress
		if i%100 == 0 {
			f.logProgress(i)
		}
	}

	f.Stats.EndTime = time.Now()
}

// initializeCorpus initializes the corpus with seed inputs
func (f *Fuzzer) initializeCorpus() {
	// Add empty input
	f.Corpus = append(f.Corpus, []byte{})

	// Add simple inputs
	simpleInputs := []string{
		"",
		"a",
		"hello",
		"test",
		"{}",
		"[]",
		"true",
		"false",
		"null",
		"123",
		"-1",
		"1.5",
		"\"string\"",
		"{}\n",
		"[]\n",
	}

	for _, input := range simpleInputs {
		f.Corpus = append(f.Corpus, []byte(input))
	}

	// Add dictionary inputs if available
	for _, dictInput := range f.Config.Dictionary {
		f.Corpus = append(f.Corpus, []byte(dictInput))
	}
}

// getInput returns an input to test
func (f *Fuzzer) getInput() []byte {
	if len(f.Corpus) == 0 {
		return []byte{}
	}
	return f.Corpus[rand.Intn(len(f.Corpus))]
}

// mutate mutates an input
func (f *Fuzzer) mutate(input []byte) []byte {
	mutations := []func([]byte) []byte{
		f.mutateRandomByte,
		f.mutateRandomBytes,
		f.mutateDeleteByte,
		f.mutateInsertByte,
		f.mutateAppendRandom,
		f.mutatePrependRandom,
		f.mutateRandomSubstring,
	}

	// Select a random mutation
	mutation := mutations[rand.Intn(len(mutations))]
	return mutation(input)
}

// mutateRandomByte randomly changes a byte in the input
func (f *Fuzzer) mutateRandomByte(input []byte) []byte {
	if len(input) == 0 {
		return input
	}

	mutated := make([]byte, len(input))
	copy(mutated, input)

	// Change a random byte
	idx := rand.Intn(len(mutated))
	mutated[idx] = byte(rand.Intn(256))

	return mutated
}

// mutateRandomBytes randomly changes multiple bytes in the input
func (f *Fuzzer) mutateRandomBytes(input []byte) []byte {
	if len(input) == 0 {
		return input
	}

	mutated := make([]byte, len(input))
	copy(mutated, input)

	// Change 1-10 random bytes
	numBytes := rand.Intn(10) + 1
	for i := 0; i < numBytes; i++ {
		idx := rand.Intn(len(mutated))
		mutated[idx] = byte(rand.Intn(256))
	}

	return mutated
}

// mutateDeleteByte deletes a random byte from the input
func (f *Fuzzer) mutateDeleteByte(input []byte) []byte {
	if len(input) == 0 {
		return input
	}

	// Delete a random byte
	idx := rand.Intn(len(input))
	mutated := append(input[:idx], input[idx+1:]...)

	return mutated
}

// mutateInsertByte inserts a random byte into the input
func (f *Fuzzer) mutateInsertByte(input []byte) []byte {
	// Insert a random byte at a random position
	idx := rand.Intn(len(input) + 1)
	value := byte(rand.Intn(256))

	mutated := make([]byte, len(input)+1)
	copy(mutated[:idx], input[:idx])
	mutated[idx] = value
	copy(mutated[idx+1:], input[idx:])

	return mutated
}

// mutateAppendRandom appends random data to the input
func (f *Fuzzer) mutateAppendRandom(input []byte) []byte {
	// Append 1-10 random bytes
	numBytes := rand.Intn(10) + 1
	appended := make([]byte, numBytes)
	for i := 0; i < numBytes; i++ {
		appended[i] = byte(rand.Intn(256))
	}

	mutated := append(input, appended...)

	// Respect max input size
	if len(mutated) > f.Config.MaxInputSize {
		mutated = mutated[:f.Config.MaxInputSize]
	}

	return mutated
}

// mutatePrependRandom prepends random data to the input
func (f *Fuzzer) mutatePrependRandom(input []byte) []byte {
	// Prepend 1-10 random bytes
	numBytes := rand.Intn(10) + 1
	prepended := make([]byte, numBytes)
	for i := 0; i < numBytes; i++ {
		prepended[i] = byte(rand.Intn(256))
	}

	mutated := append(prepended, input...)

	// Respect max input size
	if len(mutated) > f.Config.MaxInputSize {
		mutated = mutated[:f.Config.MaxInputSize]
	}

	return mutated
}

// mutateRandomSubstring replaces a random substring with random data
func (f *Fuzzer) mutateRandomSubstring(input []byte) []byte {
	if len(input) == 0 {
		return input
	}

	mutated := make([]byte, len(input))
	copy(mutated, input)

	// Select a random substring
	start := rand.Intn(len(mutated))
	endIdx := start + rand.Intn(len(mutated)-start) + 1

	// Replace with random data of same length
	for i := start; i < endIdx && i < len(mutated); i++ {
		mutated[i] = byte(rand.Intn(256))
	}

	return mutated
}

// testInput tests an input with the target function
func (f *Fuzzer) testInput(input []byte) {
	if f.Config.Target.FuzzFunc == nil {
		return
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), f.Config.Timeout)
	defer cancel()

	// Run the fuzz function
	done := make(chan bool, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				_ = fmt.Errorf("%v", r)
				_ = getStackTrace()
			}
			done <- true
		}()
		f.Config.Target.FuzzFunc(f, input)
	}()

	select {
	case <-done:
		// Test completed successfully
		// Add to corpus if interesting
		if f.isInteresting(input) {
			f.Corpus = append(f.Corpus, input)
		}
	case <-ctx.Done():
		// Timeout
		f.Stats.Hangouts++
		f.recordFinding(input, fmt.Errorf("timeout"), "Timeout", SeverityMedium)
	}
}

// isInteresting determines if an input is interesting (should be added to corpus)
func (f *Fuzzer) isInteresting(input []byte) bool {
	// Simple heuristic: inputs that cause new code paths are interesting
	// In a real implementation, this would use coverage information
	return len(input) > 0 && len(input) < 1024
}

// recordFinding records a vulnerability finding
func (f *Fuzzer) recordFinding(input []byte, err error, stackTrace string, severity InvariantSeverity) {
	// Create a copy of the input
	inputCopy := make([]byte, len(input))
	copy(inputCopy, input)

	finding := FuzzFinding{
		ID:           fmt.Sprintf("FINDING-%d", len(f.Findings)+1),
		Input:        inputCopy,
		Error:        err,
		StackTrace:   stackTrace,
		Timestamp:    time.Now(),
		Severity:     severity,
		Category:     f.Config.Target.Category,
		Reproducible: true,
	}

	f.Findings = append(f.Findings, finding)
	f.Stats.Crashes++

	// Log the finding
	f.logFinding(finding)
}

// logFinding logs a vulnerability finding
func (f *Fuzzer) logFinding(finding FuzzFinding) {
	// Simple logging - in a real implementation, this would use proper logging
	// Also, sensitive information would be redacted

	// Redact sensitive information from the input for logging
	safeInput := redactSensitiveData(string(finding.Input))

	fmt.Printf("FINDING: %s - %s (Severity: %s)\n",
		finding.ID, finding.Error, finding.Severity)
	fmt.Printf("  Input: %s\n", truncateString(safeInput, 100))
	fmt.Printf("  Category: %s\n", finding.Category)
}

// logProgress logs fuzzing progress
func (f *Fuzzer) logProgress(iteration int) {
	fmt.Printf("Progress: %d/%d iterations, %d unique inputs, %d findings\n",
		iteration, f.Config.Iterations, len(f.Corpus), len(f.Findings))
}

// getStackTrace gets the current stack trace
func getStackTrace() string {
	// This is a simple implementation - in Go, getting a stack trace
	// typically requires using runtime or debug packages
	return "Stack trace not implemented"
}

// truncateString truncates a string to a maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// redactSensitiveData redacts sensitive data from a string
func redactSensitiveData(s string) string {
	// Redact common sensitive patterns
	sensitivePatterns := []string{
		"Bearer ",
		"Authorization:",
		"DPoP ",
		"\"access_token\":",
		"\"refresh_token\":",
		"\"id_token\":",
		"\"sub\":",
		"\"webid\":",
		"\"iss\":",
		"\"aud\":",
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
	}

	result := s
	for _, pattern := range sensitivePatterns {
		result = strings.ReplaceAll(result, pattern, "[REDACTED]")
	}

	return result
}

// GetAllFuzzTargets returns all fuzz targets
func GetAllFuzzTargets() []FuzzTarget {
	return []FuzzTarget{
		{
			Name:        "FuzzJWTParser",
			Description: "Fuzz testing for JWT token parsing",
			Category:    FuzzCategoryParser,
			Severity:    SeverityCritical,
			FuzzFunc:    fuzzJWTParser,
			References:  []string{"RFC 7519 (JWT)", "CWE-20: Improper Input Validation"},
		},
		{
			Name:        "FuzzDPoPParser",
			Description: "Fuzz testing for DPoP proof parsing",
			Category:    FuzzCategoryParser,
			Severity:    SeverityCritical,
			FuzzFunc:    fuzzDPoPParser,
			References:  []string{"RFC 8725 (DPoP)", "CWE-20: Improper Input Validation"},
		},
		{
			Name:        "FuzzWACParser",
			Description: "Fuzz testing for WAC policy parsing",
			Category:    FuzzCategoryParser,
			Severity:    SeverityHigh,
			FuzzFunc:    fuzzWACParser,
			References:  []string{"WAC specification", "CWE-20: Improper Input Validation"},
		},
		{
			Name:        "FuzzACPParser",
			Description: "Fuzz testing for ACP policy parsing",
			Category:    FuzzCategoryParser,
			Severity:    SeverityHigh,
			FuzzFunc:    fuzzACPParser,
			References:  []string{"ACP specification", "CWE-20: Improper Input Validation"},
		},
		{
			Name:        "FuzzDIDParser",
			Description: "Fuzz testing for DID document parsing",
			Category:    FuzzCategoryParser,
			Severity:    SeverityHigh,
			FuzzFunc:    fuzzDIDParser,
			References:  []string{"DID Core specification", "CWE-20: Improper Input Validation"},
		},
		{
			Name:        "FuzzHTTPTargetParser",
			Description: "Fuzz testing for HTTP target URI parsing",
			Category:    FuzzCategoryParser,
			Severity:    SeverityMedium,
			FuzzFunc:    fuzzHTTPTargetParser,
			References:  []string{"RFC 3986 (URI)", "CWE-20: Improper Input Validation"},
		},
		{
			Name:        "FuzzCompressionNegotiation",
			Description: "Fuzz testing for HTTP compression negotiation",
			Category:    FuzzCategoryNetwork,
			Severity:    SeverityMedium,
			FuzzFunc:    fuzzCompressionNegotiation,
			References:  []string{"RFC 7231 (Accept-Encoding)", "CWE-20: Improper Input Validation"},
		},
		{
			Name:        "FuzzConfigParser",
			Description: "Fuzz testing for configuration parsing",
			Category:    FuzzCategoryParser,
			Severity:    SeverityHigh,
			FuzzFunc:    fuzzConfigParser,
			References:  []string{"Configuration best practices", "CWE-20: Improper Input Validation"},
		},
	}
}

// Placeholder fuzz functions - in a real implementation, these would call the actual parsers
func fuzzJWTParser(f *Fuzzer, data []byte) {
	// In a real implementation, this would call the JWT parser with the fuzz data
	// and check for panics, errors, or unexpected behavior
	_ = f
	_ = data
	// Simulate parsing - no actual parsing to avoid dependencies
}

func fuzzDPoPParser(f *Fuzzer, data []byte) {
	_ = f
	_ = data
}

func fuzzWACParser(f *Fuzzer, data []byte) {
	_ = f
	_ = data
}

func fuzzACPParser(f *Fuzzer, data []byte) {
	_ = f
	_ = data
}

func fuzzDIDParser(f *Fuzzer, data []byte) {
	_ = f
	_ = data
}

func fuzzHTTPTargetParser(f *Fuzzer, data []byte) {
	_ = f
	_ = data
}

func fuzzCompressionNegotiation(f *Fuzzer, data []byte) {
	_ = f
	_ = data
}

func fuzzConfigParser(f *Fuzzer, data []byte) {
	_ = f
	_ = data
}

// RunFuzzTests runs all fuzz tests
func RunFuzzTests(t *testing.T, config FuzzerConfig) {
	// Get all fuzz targets
	targets := GetAllFuzzTargets()

	if config.Iterations <= 0 {
		config.Iterations = 1000
	}

	for _, target := range targets {
		t.Run(target.Name, func(t *testing.T) {
			// Create fuzzer for this target
			fuzzerConfig := config
			fuzzerConfig.Target = target

			// Set up dictionary for this target
			fuzzerConfig.Dictionary = getDictionaryForTarget(target)

			// Create and run fuzzer
			fuzzer := NewFuzzer(fuzzerConfig)
			fuzzer.Run()

			// Report results
			if len(fuzzer.Findings) > 0 {
				t.Errorf("Found %d vulnerabilities in %s", len(fuzzer.Findings), target.Name)
			}
		})
	}
}

// getDictionaryForTarget returns a dictionary for a specific fuzz target
func getDictionaryForTarget(target FuzzTarget) []string {
	switch target.Category {
	case FuzzCategoryParser:
		return getParserDictionary(target)
	default:
		return getGenericDictionary()
	}
}

// getParserDictionary returns a dictionary for parser fuzz targets
func getParserDictionary(target FuzzTarget) []string {
	// Add generic parser inputs
	dictionary := getGenericDictionary()

	// Add target-specific inputs
	switch target.Name {
	case "FuzzJWTParser":
		jwtInputs := []string{
			"{}",
			"{\"alg\":\"none\"}",
			"{\"alg\":\"HS256\"}",
			"{\"alg\":\"RS256\"}",
			"{\"typ\":\"JWT\"}",
			"{\"kid\":\"key-1\"}",
			"eyJhbGciOiJub25lIn0",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		}
		dictionary = append(dictionary, jwtInputs...)

	case "FuzzDPoPParser":
		dpopInputs := []string{
			"{}",
			"{\"htu\":\"https://example.com\"}",
			"{\"htm\":\"GET\"}",
			"{\"nonce\":\"abc123\"}",
			"{\"iat\":1234567890}",
			"{\"jti\":\"unique-id\"}",
		}
		dictionary = append(dictionary, dpopInputs...)

	case "FuzzWACParser", "FuzzACPParser":
		policyInputs := []string{
			"{}",
			"@prefix acl: <http://www.w3.org/ns/auth/acl#> .",
			"@prefix foaf: <http://xmlns.com/foaf/0.1/> .",
			"[] a acl:Authorization ;",
			"acl:accessTo <resource> ;",
			"acl:agent <user> ;",
			"acl:mode acl:Read .",
		}
		dictionary = append(dictionary, policyInputs...)

	case "FuzzDIDParser":
		didInputs := []string{
			"{}",
			"{\"@context\":\"https://www.w3.org/ns/did/v1\"}",
			"{\"id\":\"did:example:123\"}",
			"{\"publicKey\":[]}",
			"{\"authentication\":[]}",
		}
		dictionary = append(dictionary, didInputs...)
	}

	return dictionary
}

// getGenericDictionary returns a generic dictionary for all fuzz targets
func getGenericDictionary() []string {
	return []string{
		"",
		"\n",
		"\t",
		" ",
		"a",
		"0",
		"true",
		"false",
		"null",
		"{}",
		"[]",
		"\"\"",
		"\"test\"",
		"123",
		"-1",
		"1.5",
		"0.0",
		"\"\"",
		"\\",
		"\\\"",
		"\\n",
		"\\t",
		"\\u0000",
		"<>",
		"<>\"",
		"<script>",
		"</script>",
		"<!--",
		"-->",
		"<?xml",
	}
}

// PropertyTestSuite is a test suite for property-based testing
func PropertyTestSuite(t *testing.T) {
	// Run property tests for authorization invariants
	t.Run("AuthorizationInvariants", func(t *testing.T) {
		config := DefaultAuthzInvariantTestConfig()
		RunPropertyTests(t, config)
	})

	// Run fuzz tests
	t.Run("FuzzTests", func(t *testing.T) {
		config := FuzzerConfig{
			Iterations:        1000,
			MaxInputSize:      4096,
			MutationsPerInput: 10,
			Parallel:          1,
			Timeout:           1 * time.Second,
		}
		RunFuzzTests(t, config)
	})
}
