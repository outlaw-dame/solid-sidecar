package authz

import (
	"strings"
	"testing"
	"time"
)

func TestFixtureDistributionConstants(t *testing.T) {
	// Test that constants have expected values
	if FixtureDistributionSchemaVersion != "policy.fixture.distribution.v1" {
		t.Errorf("Expected schema version to be 'policy.fixture.distribution.v1', got '%s'", FixtureDistributionSchemaVersion)
	}

	if MaxDistributionTargetURLLength != 2048 {
		t.Errorf("Expected MaxDistributionTargetURLLength to be 2048, got %d", MaxDistributionTargetURLLength)
	}

	if MaxDistributionIDLength != 256 {
		t.Errorf("Expected MaxDistributionIDLength to be 256, got %d", MaxDistributionIDLength)
	}
}

func TestDistributionStatusConstants(t *testing.T) {
	statuses := []DistributionStatus{
		DistributionStatusPending,
		DistributionStatusInProgress,
		DistributionStatusCompleted,
		DistributionStatusFailed,
		DistributionStatusCancelled,
	}

	expected := []string{"pending", "in_progress", "completed", "failed", "cancelled"}

	for i, status := range statuses {
		if string(status) != expected[i] {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, expected[i], status)
		}
	}
}

func TestDistributionMethodConstants(t *testing.T) {
	methods := []DistributionMethod{
		DistributionMethodHTTPS,
		DistributionMethodLocalFile,
		DistributionMethodS3,
		DistributionMethodSSH,
	}

	expected := []string{"https", "local_file", "s3", "ssh"}

	for i, method := range methods {
		if string(method) != expected[i] {
			t.Errorf("Expected method %d to be '%s', got '%s'", i, expected[i], method)
		}
	}
}

func TestDistributionAuthenticationMethodConstants(t *testing.T) {
	authMethods := []DistributionAuthenticationMethod{
		DistributionAuthNone,
		DistributionAuthBearer,
		DistributionAuthBasic,
		DistributionAuthAPIKey,
	}

	expected := []string{"none", "bearer", "basic", "api_key"}

	for i, authMethod := range authMethods {
		if string(authMethod) != expected[i] {
			t.Errorf("Expected auth method %d to be '%s', got '%s'", i, expected[i], authMethod)
		}
	}
}

func TestNewFixtureDistributionTarget_Valid(t *testing.T) {
	target, err := NewFixtureDistributionTarget(
		"test-target-1",
		"Test Target",
		"https://example.com/api/fixtures",
		DistributionMethodHTTPS,
		DistributionAuthBearer,
		"test-token",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if target.ID != "test-target-1" {
		t.Errorf("Expected ID to be 'test-target-1', got '%s'", target.ID)
	}
	if target.Name != "Test Target" {
		t.Errorf("Expected Name to be 'Test Target', got '%s'", target.Name)
	}
	if target.URL != "https://example.com/api/fixtures" {
		t.Errorf("Expected URL to be 'https://example.com/api/fixtures', got '%s'", target.URL)
	}
	if target.Method != DistributionMethodHTTPS {
		t.Errorf("Expected Method to be HTTPS, got '%s'", target.Method)
	}
	if target.AuthMethod != DistributionAuthBearer {
		t.Errorf("Expected AuthMethod to be Bearer, got '%s'", target.AuthMethod)
	}
	if target.Enabled != true {
		t.Errorf("Expected Enabled to be true, got %v", target.Enabled)
	}
	if target.VerifyTLS != true {
		t.Errorf("Expected VerifyTLS to be true, got %v", target.VerifyTLS)
	}
	if target.TimeoutSeconds != 30 {
		t.Errorf("Expected TimeoutSeconds to be 30, got %d", target.TimeoutSeconds)
	}
	if target.RetryCount != 3 {
		t.Errorf("Expected RetryCount to be 3, got %d", target.RetryCount)
	}
	if target.RetryDelaySeconds != 5 {
		t.Errorf("Expected RetryDelaySeconds to be 5, got %d", target.RetryDelaySeconds)
	}
	if target.TargetHash == "" {
		t.Error("Expected TargetHash to be non-empty")
	}
}

func TestNewFixtureDistributionTarget_EmptyID(t *testing.T) {
	_, err := NewFixtureDistributionTarget(
		"",
		"Test Target",
		"https://example.com/api/fixtures",
		DistributionMethodHTTPS,
		DistributionAuthBearer,
		"test-token",
	)

	if err == nil {
		t.Error("Expected error for empty ID")
	}
	if !strings.Contains(err.Error(), "ID cannot be empty") {
		t.Errorf("Expected error about empty ID, got: %v", err)
	}
}

func TestNewFixtureDistributionTarget_IDTooLong(t *testing.T) {
	longID := strings.Repeat("a", MaxDistributionIDLength+1)
	_, err := NewFixtureDistributionTarget(
		longID,
		"Test Target",
		"https://example.com/api/fixtures",
		DistributionMethodHTTPS,
		DistributionAuthBearer,
		"test-token",
	)

	if err == nil {
		t.Error("Expected error for ID too long")
	}
	if !strings.Contains(err.Error(), "ID too long") {
		t.Errorf("Expected error about ID too long, got: %v", err)
	}
}

func TestNewFixtureDistributionTarget_EmptyURL(t *testing.T) {
	_, err := NewFixtureDistributionTarget(
		"test-target-1",
		"Test Target",
		"",
		DistributionMethodHTTPS,
		DistributionAuthBearer,
		"test-token",
	)

	if err == nil {
		t.Error("Expected error for empty URL")
	}
	if !strings.Contains(err.Error(), "URL cannot be empty") {
		t.Errorf("Expected error about empty URL, got: %v", err)
	}
}

func TestNewFixtureDistributionTarget_URLTooLong(t *testing.T) {
	longURL := strings.Repeat("a", MaxDistributionTargetURLLength+1)
	_, err := NewFixtureDistributionTarget(
		"test-target-1",
		"Test Target",
		longURL,
		DistributionMethodHTTPS,
		DistributionAuthBearer,
		"test-token",
	)

	if err == nil {
		t.Error("Expected error for URL too long")
	}
	if !strings.Contains(err.Error(), "URL too long") {
		t.Errorf("Expected error about URL too long, got: %v", err)
	}
}

func TestNewFixtureDistributionTarget_InvalidHTTPSURL(t *testing.T) {
	_, err := NewFixtureDistributionTarget(
		"test-target-1",
		"Test Target",
		"not-a-valid-url",
		DistributionMethodHTTPS,
		DistributionAuthBearer,
		"test-token",
	)

	if err == nil {
		t.Error("Expected error for invalid HTTPS URL")
	}
	if !strings.Contains(err.Error(), "invalid URL scheme for HTTPS method") {
		t.Errorf("Expected error about invalid URL scheme for HTTPS, got: %v", err)
	}
}

func TestNewFixtureDistributionTarget_ValidS3URL(t *testing.T) {
	target, err := NewFixtureDistributionTarget(
		"test-target-1",
		"Test Target",
		"s3://bucket/path",
		DistributionMethodS3,
		DistributionAuthNone,
		"",
	)

	if err != nil {
		t.Fatalf("Expected no error for valid S3 URL, got: %v", err)
	}
	if target.Method != DistributionMethodS3 {
		t.Errorf("Expected Method to be S3, got '%s'", target.Method)
	}
	if target.URL != "s3://bucket/path" {
		t.Errorf("Expected URL to be 's3://bucket/path', got '%s'", target.URL)
	}
}

func TestNewFixtureDistributionTarget_InvalidMethod(t *testing.T) {
	_, err := NewFixtureDistributionTarget(
		"test-target-1",
		"Test Target",
		"https://example.com/api/fixtures",
		DistributionMethod("invalid-method"),
		DistributionAuthBearer,
		"test-token",
	)

	if err == nil {
		t.Error("Expected error for invalid method")
	}
	if !strings.Contains(err.Error(), "invalid distribution method") {
		t.Errorf("Expected error about invalid distribution method, got: %v", err)
	}
}

func TestNewFixtureDistributionTarget_InvalidAuthMethod(t *testing.T) {
	_, err := NewFixtureDistributionTarget(
		"test-target-1",
		"Test Target",
		"https://example.com/api/fixtures",
		DistributionMethodHTTPS,
		DistributionAuthenticationMethod("invalid-auth"),
		"test-token",
	)

	if err == nil {
		t.Error("Expected error for invalid auth method")
	}
	if !strings.Contains(err.Error(), "invalid authentication method") {
		t.Errorf("Expected error about invalid authentication method, got: %v", err)
	}
}

func TestNewFixtureDistributionJob_Valid(t *testing.T) {
	job, err := NewFixtureDistributionJob(
		"dist-123",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-1", "bundle-2"},
		"manifest-hash-xyz",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if job.DistributionID != "dist-123" {
		t.Errorf("Expected DistributionID to be 'dist-123', got '%s'", job.DistributionID)
	}
	if job.TargetID != "target-1" {
		t.Errorf("Expected TargetID to be 'target-1', got '%s'", job.TargetID)
	}
	if job.CatalogHash != "catalog-hash-abc" {
		t.Errorf("Expected CatalogHash to be 'catalog-hash-abc', got '%s'", job.CatalogHash)
	}
	if len(job.BundleHashes) != 2 {
		t.Errorf("Expected 2 bundle hashes, got %d", len(job.BundleHashes))
	}
	if job.ManifestHash != "manifest-hash-xyz" {
		t.Errorf("Expected ManifestHash to be 'manifest-hash-xyz', got '%s'", job.ManifestHash)
	}
	if job.Status != DistributionStatusPending {
		t.Errorf("Expected Status to be Pending, got '%s'", job.Status)
	}
	if job.CreatedAtUnix <= 0 {
		t.Errorf("Expected CreatedAtUnix to be positive, got %d", job.CreatedAtUnix)
	}
	if job.AttemptCount != 0 {
		t.Errorf("Expected AttemptCount to be 0, got %d", job.AttemptCount)
	}
	if job.JobHash == "" {
		t.Error("Expected JobHash to be non-empty")
	}
}

func TestNewFixtureDistributionJob_EmptyDistributionID(t *testing.T) {
	_, err := NewFixtureDistributionJob(
		"",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-1"},
		"manifest-hash-xyz",
	)

	if err == nil {
		t.Error("Expected error for empty distribution ID")
	}
	if !strings.Contains(err.Error(), "distribution ID cannot be empty") {
		t.Errorf("Expected error about empty distribution ID, got: %v", err)
	}
}

func TestNewFixtureDistributionJob_EmptyTargetID(t *testing.T) {
	_, err := NewFixtureDistributionJob(
		"dist-123",
		"",
		"catalog-hash-abc",
		[]string{"bundle-1"},
		"manifest-hash-xyz",
	)

	if err == nil {
		t.Error("Expected error for empty target ID")
	}
	if !strings.Contains(err.Error(), "target ID cannot be empty") {
		t.Errorf("Expected error about empty target ID, got: %v", err)
	}
}

func TestNewFixtureDistributionJob_NoHashes(t *testing.T) {
	_, err := NewFixtureDistributionJob(
		"dist-123",
		"target-1",
		"",
		[]string{},
		"",
	)

	if err == nil {
		t.Error("Expected error for no hashes")
	}
	if !strings.Contains(err.Error(), "must specify catalog hash or bundle hashes") {
		t.Errorf("Expected error about specifying hashes, got: %v", err)
	}
}

func TestNewFixtureDistributionJob_WithCatalogHashOnly(t *testing.T) {
	job, err := NewFixtureDistributionJob(
		"dist-123",
		"target-1",
		"catalog-hash-abc",
		[]string{},
		"",
	)

	if err != nil {
		t.Fatalf("Expected no error for catalog hash only, got: %v", err)
	}
	if job.CatalogHash != "catalog-hash-abc" {
		t.Errorf("Expected CatalogHash to be 'catalog-hash-abc', got '%s'", job.CatalogHash)
	}
}

func TestNewFixtureDistributionJob_WithBundleHashesOnly(t *testing.T) {
	job, err := NewFixtureDistributionJob(
		"dist-123",
		"target-1",
		"",
		[]string{"bundle-1", "bundle-2"},
		"",
	)

	if err != nil {
		t.Fatalf("Expected no error for bundle hashes only, got: %v", err)
	}
	if len(job.BundleHashes) != 2 {
		t.Errorf("Expected 2 bundle hashes, got %d", len(job.BundleHashes))
	}
}

func TestNewFixtureDistributionReceipt_Valid(t *testing.T) {
	receipt, err := NewFixtureDistributionReceipt(
		"dist-123",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-1", "bundle-2"},
		"verified",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if receipt.DistributionID != "dist-123" {
		t.Errorf("Expected DistributionID to be 'dist-123', got '%s'", receipt.DistributionID)
	}
	if receipt.TargetID != "target-1" {
		t.Errorf("Expected TargetID to be 'target-1', got '%s'", receipt.TargetID)
	}
	if receipt.ReceivedCatalogHash != "catalog-hash-abc" {
		t.Errorf("Expected ReceivedCatalogHash to be 'catalog-hash-abc', got '%s'", receipt.ReceivedCatalogHash)
	}
	if len(receipt.ReceivedBundleHashes) != 2 {
		t.Errorf("Expected 2 received bundle hashes, got %d", len(receipt.ReceivedBundleHashes))
	}
	if receipt.VerificationStatus != "verified" {
		t.Errorf("Expected VerificationStatus to be 'verified', got '%s'", receipt.VerificationStatus)
	}
	if receipt.ReceivedAtUnix <= 0 {
		t.Errorf("Expected ReceivedAtUnix to be positive, got %d", receipt.ReceivedAtUnix)
	}
	if receipt.ReceiptHash == "" {
		t.Error("Expected ReceiptHash to be non-empty")
	}
}

func TestNewFixtureDistributionReceipt_EmptyDistributionID(t *testing.T) {
	_, err := NewFixtureDistributionReceipt(
		"",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-1"},
		"verified",
	)

	if err == nil {
		t.Error("Expected error for empty distribution ID")
	}
	if !strings.Contains(err.Error(), "distribution ID cannot be empty") {
		t.Errorf("Expected error about empty distribution ID, got: %v", err)
	}
}

func TestNewFixtureDistributionIndex_Valid(t *testing.T) {
	distributions := []FixtureDistributionJob{}

	// Create a valid job first
	job1, err := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	if err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}
	job2, err := NewFixtureDistributionJob("dist-2", "target-2", "catalog-2", []string{}, "")
	if err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	distributions = append(distributions, job1, job2)

	targets := []FixtureDistributionTarget{}
	target1, err := NewFixtureDistributionTarget("target-1", "Target 1", "https://example.com", DistributionMethodHTTPS, DistributionAuthNone, "")
	if err != nil {
		t.Fatalf("Failed to create target: %v", err)
	}
	target2, err := NewFixtureDistributionTarget("target-2", "Target 2", "https://example.com", DistributionMethodHTTPS, DistributionAuthNone, "")
	if err != nil {
		t.Fatalf("Failed to create target: %v", err)
	}

	targets = append(targets, target1, target2)

	index, err := NewFixtureDistributionIndex(distributions, targets)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if index.SchemaVersion != FixtureDistributionSchemaVersion {
		t.Errorf("Expected SchemaVersion to be '%s', got '%s'", FixtureDistributionSchemaVersion, index.SchemaVersion)
	}
	if len(index.Distributions) != 2 {
		t.Errorf("Expected 2 distributions, got %d", len(index.Distributions))
	}
	if len(index.Targets) != 2 {
		t.Errorf("Expected 2 targets, got %d", len(index.Targets))
	}
	if index.LastUpdatedUnix <= 0 {
		t.Errorf("Expected LastUpdatedUnix to be positive, got %d", index.LastUpdatedUnix)
	}
	if index.IndexHash == "" {
		t.Error("Expected IndexHash to be non-empty")
	}
}

func TestValidateFixtureDistributionTarget_Valid(t *testing.T) {
	target, err := NewFixtureDistributionTarget(
		"test-target-1",
		"Test Target",
		"https://example.com/api/fixtures",
		DistributionMethodHTTPS,
		DistributionAuthBearer,
		"test-token",
	)

	if err != nil {
		t.Fatalf("Failed to create target: %v", err)
	}

	err = ValidateFixtureDistributionTarget(target)
	if err != nil {
		t.Errorf("Expected validation to pass, got: %v", err)
	}
}

func TestValidateFixtureDistributionTarget_InvalidMethod(t *testing.T) {
	target := FixtureDistributionTarget{
		ID:         "test-target-1",
		Name:       "Test Target",
		URL:        "https://example.com/api/fixtures",
		Method:     DistributionMethod("invalid"),
		AuthMethod: DistributionAuthBearer,
	}

	err := ValidateFixtureDistributionTarget(target)
	if err == nil {
		t.Error("Expected validation to fail for invalid method")
	}
	if !strings.Contains(err.Error(), "invalid distribution method") {
		t.Errorf("Expected error about invalid method, got: %v", err)
	}
}

func TestValidateFixtureDistributionTarget_HashMismatch(t *testing.T) {
	target := FixtureDistributionTarget{
		ID:                "test-target-1",
		Name:              "Test Target",
		URL:               "https://example.com/api/fixtures",
		Method:            DistributionMethodHTTPS,
		AuthMethod:        DistributionAuthBearer,
		TargetHash:        "wrong-hash",
		Enabled:           true,
		VerifyTLS:         true,
		TimeoutSeconds:    30,
		RetryCount:        3,
		RetryDelaySeconds: 5,
	}

	err := ValidateFixtureDistributionTarget(target)
	if err == nil {
		t.Error("Expected validation to fail for hash mismatch")
	}
	if !strings.Contains(err.Error(), "target hash mismatch") {
		t.Errorf("Expected error about hash mismatch, got: %v", err)
	}
}

func TestValidateFixtureDistributionJob_Valid(t *testing.T) {
	job, err := NewFixtureDistributionJob(
		"dist-123",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-1"},
		"manifest-hash-xyz",
	)

	if err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	err = ValidateFixtureDistributionJob(job)
	if err != nil {
		t.Errorf("Expected validation to pass, got: %v", err)
	}
}

func TestValidateFixtureDistributionJob_InvalidStatus(t *testing.T) {
	job := FixtureDistributionJob{
		DistributionID: "dist-123",
		TargetID:       "target-1",
		CatalogHash:    "catalog-hash",
		Status:         DistributionStatus("invalid-status"),
		CreatedAtUnix:  time.Now().Unix(),
		JobHash:        "some-hash",
	}

	err := ValidateFixtureDistributionJob(job)
	if err == nil {
		t.Error("Expected validation to fail for invalid status")
	}
	if !strings.Contains(err.Error(), "invalid distribution status") {
		t.Errorf("Expected error about invalid status, got: %v", err)
	}
}

func TestValidateFixtureDistributionReceipt_Valid(t *testing.T) {
	receipt, err := NewFixtureDistributionReceipt(
		"dist-123",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-1"},
		"verified",
	)

	if err != nil {
		t.Fatalf("Failed to create receipt: %v", err)
	}

	err = ValidateFixtureDistributionReceipt(receipt)
	if err != nil {
		t.Errorf("Expected validation to pass, got: %v", err)
	}
}

func TestValidateFixtureDistributionIndex_Valid(t *testing.T) {
	index, err := NewFixtureDistributionIndex([]FixtureDistributionJob{}, []FixtureDistributionTarget{})

	if err != nil {
		t.Fatalf("Failed to create index: %v", err)
	}

	err = ValidateFixtureDistributionIndex(index)
	if err != nil {
		t.Errorf("Expected validation to pass, got: %v", err)
	}
}

func TestValidateFixtureDistributionIndex_InvalidSchema(t *testing.T) {
	index := FixtureDistributionIndex{
		SchemaVersion:   "invalid-version",
		LastUpdatedUnix: time.Now().Unix(),
		IndexHash:       "some-hash",
	}

	err := ValidateFixtureDistributionIndex(index)
	if err == nil {
		t.Error("Expected validation to fail for invalid schema")
	}
	if !strings.Contains(err.Error(), "unsupported schema version") {
		t.Errorf("Expected error about unsupported schema, got: %v", err)
	}
}

func TestGetFixtureDistributionByID(t *testing.T) {
	job1, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	job2, _ := NewFixtureDistributionJob("dist-2", "target-2", "catalog-2", []string{}, "")

	index, _ := NewFixtureDistributionIndex([]FixtureDistributionJob{job1, job2}, []FixtureDistributionTarget{})

	found, ok := GetFixtureDistributionByID(index, "dist-1")
	if !ok {
		t.Error("Expected to find distribution with ID 'dist-1'")
	}
	if found.DistributionID != "dist-1" {
		t.Errorf("Expected DistributionID to be 'dist-1', got '%s'", found.DistributionID)
	}

	_, ok = GetFixtureDistributionByID(index, "non-existent")
	if ok {
		t.Error("Expected not to find distribution with ID 'non-existent'")
	}
}

func TestGetFixtureDistributionTargetByID(t *testing.T) {
	target1, _ := NewFixtureDistributionTarget("target-1", "Target 1", "https://example.com", DistributionMethodHTTPS, DistributionAuthNone, "")
	target2, _ := NewFixtureDistributionTarget("target-2", "Target 2", "https://example.com", DistributionMethodHTTPS, DistributionAuthNone, "")

	index, _ := NewFixtureDistributionIndex([]FixtureDistributionJob{}, []FixtureDistributionTarget{target1, target2})

	found, ok := GetFixtureDistributionTargetByID(index, "target-1")
	if !ok {
		t.Error("Expected to find target with ID 'target-1'")
	}
	if found.ID != "target-1" {
		t.Errorf("Expected ID to be 'target-1', got '%s'", found.ID)
	}

	_, ok = GetFixtureDistributionTargetByID(index, "non-existent")
	if ok {
		t.Error("Expected not to find target with ID 'non-existent'")
	}
}

func TestGetDistributionsByTargetID(t *testing.T) {
	job1, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	job2, _ := NewFixtureDistributionJob("dist-2", "target-1", "catalog-2", []string{}, "")
	job3, _ := NewFixtureDistributionJob("dist-3", "target-2", "catalog-3", []string{}, "")

	index, _ := NewFixtureDistributionIndex([]FixtureDistributionJob{job1, job2, job3}, []FixtureDistributionTarget{})

	distributions := GetDistributionsByTargetID(index, "target-1")
	if len(distributions) != 2 {
		t.Errorf("Expected 2 distributions for target-1, got %d", len(distributions))
	}

	distributions = GetDistributionsByTargetID(index, "target-2")
	if len(distributions) != 1 {
		t.Errorf("Expected 1 distribution for target-2, got %d", len(distributions))
	}

	distributions = GetDistributionsByTargetID(index, "non-existent")
	if len(distributions) != 0 {
		t.Errorf("Expected 0 distributions for non-existent target, got %d", len(distributions))
	}
}

func TestGetDistributionsByCatalogHash(t *testing.T) {
	job1, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	job2, _ := NewFixtureDistributionJob("dist-2", "target-2", "catalog-1", []string{}, "")
	job3, _ := NewFixtureDistributionJob("dist-3", "target-3", "catalog-2", []string{}, "")

	index, _ := NewFixtureDistributionIndex([]FixtureDistributionJob{job1, job2, job3}, []FixtureDistributionTarget{})

	distributions := GetDistributionsByCatalogHash(index, "catalog-1")
	if len(distributions) != 2 {
		t.Errorf("Expected 2 distributions for catalog-1, got %d", len(distributions))
	}

	distributions = GetDistributionsByCatalogHash(index, "catalog-2")
	if len(distributions) != 1 {
		t.Errorf("Expected 1 distribution for catalog-2, got %d", len(distributions))
	}
}

func TestGetDistributionsByStatus(t *testing.T) {
	job1, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	job2, _ := NewFixtureDistributionJob("dist-2", "target-2", "catalog-2", []string{}, "")
	job2.Status = DistributionStatusCompleted
	job2.JobHash = FixtureDistributionJobHash(job2)

	index, _ := NewFixtureDistributionIndex([]FixtureDistributionJob{job1, job2}, []FixtureDistributionTarget{})

	distributions := GetDistributionsByStatus(index, DistributionStatusPending)
	if len(distributions) != 1 {
		t.Errorf("Expected 1 pending distribution, got %d", len(distributions))
	}

	distributions = GetDistributionsByStatus(index, DistributionStatusCompleted)
	if len(distributions) != 1 {
		t.Errorf("Expected 1 completed distribution, got %d", len(distributions))
	}
}

func TestFixtureDistributionTargetHash_Deterministic(t *testing.T) {
	target1, _ := NewFixtureDistributionTarget(
		"test-target-1",
		"Test Target",
		"https://example.com/api/fixtures",
		DistributionMethodHTTPS,
		DistributionAuthBearer,
		"test-token",
	)
	target2, _ := NewFixtureDistributionTarget(
		"test-target-1",
		"Test Target",
		"https://example.com/api/fixtures",
		DistributionMethodHTTPS,
		DistributionAuthBearer,
		"test-token",
	)

	if target1.TargetHash != target2.TargetHash {
		t.Error("Expected same hash for identical targets")
	}
}

func TestFixtureDistributionJobHash_Deterministic(t *testing.T) {
	job1, _ := NewFixtureDistributionJob(
		"dist-123",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-1", "bundle-2"},
		"manifest-hash-xyz",
	)
	job2, _ := NewFixtureDistributionJob(
		"dist-123",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-1", "bundle-2"},
		"manifest-hash-xyz",
	)

	if job1.JobHash != job2.JobHash {
		t.Error("Expected same hash for identical jobs")
	}
}

func TestFixtureDistributionJobHash_OrderIndependence(t *testing.T) {
	job1, _ := NewFixtureDistributionJob(
		"dist-123",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-1", "bundle-2"},
		"manifest-hash-xyz",
	)
	job2, _ := NewFixtureDistributionJob(
		"dist-123",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-2", "bundle-1"},
		"manifest-hash-xyz",
	)

	if job1.JobHash != job2.JobHash {
		t.Error("Expected same hash for jobs with same bundle hashes in different order")
	}
}

func TestFixtureDistributionIndexHash_Deterministic(t *testing.T) {
	job1, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	job2, _ := NewFixtureDistributionJob("dist-2", "target-2", "catalog-2", []string{}, "")

	target1, _ := NewFixtureDistributionTarget("target-1", "Target 1", "https://example.com", DistributionMethodHTTPS, DistributionAuthNone, "")
	target2, _ := NewFixtureDistributionTarget("target-2", "Target 2", "https://example.com", DistributionMethodHTTPS, DistributionAuthNone, "")

	index1, _ := NewFixtureDistributionIndex([]FixtureDistributionJob{job1, job2}, []FixtureDistributionTarget{target1, target2})
	index2, _ := NewFixtureDistributionIndex([]FixtureDistributionJob{job1, job2}, []FixtureDistributionTarget{target1, target2})

	if index1.IndexHash != index2.IndexHash {
		t.Error("Expected same hash for identical indexes")
	}
}

func TestFixtureDistributionIndexHash_OrderIndependence(t *testing.T) {
	job1, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	job2, _ := NewFixtureDistributionJob("dist-2", "target-2", "catalog-2", []string{}, "")

	target1, _ := NewFixtureDistributionTarget("target-1", "Target 1", "https://example.com", DistributionMethodHTTPS, DistributionAuthNone, "")
	target2, _ := NewFixtureDistributionTarget("target-2", "Target 2", "https://example.com", DistributionMethodHTTPS, DistributionAuthNone, "")

	index1, _ := NewFixtureDistributionIndex([]FixtureDistributionJob{job1, job2}, []FixtureDistributionTarget{target1, target2})
	index2, _ := NewFixtureDistributionIndex([]FixtureDistributionJob{job2, job1}, []FixtureDistributionTarget{target2, target1})

	if index1.IndexHash != index2.IndexHash {
		t.Error("Expected same hash for indexes with same items in different order")
	}
}
