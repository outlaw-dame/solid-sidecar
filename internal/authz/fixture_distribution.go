package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// FixtureDistributionSchemaVersion is the current schema version for fixture distribution records
const FixtureDistributionSchemaVersion = "policy.fixture.distribution.v1"

// MaxDistributionTargetURLLength is the maximum length for a distribution target URL
const MaxDistributionTargetURLLength = 2048

// MaxDistributionIDLength is the maximum length for a distribution ID
const MaxDistributionIDLength = 256

// ErrInvalidFixtureDistribution indicates an invalid fixture distribution configuration
var ErrInvalidFixtureDistribution = errors.New("invalid fixture distribution")

// DistributionStatus represents the status of a fixture distribution
type DistributionStatus string

const (
	// DistributionStatusPending indicates the distribution has been queued but not yet sent
	DistributionStatusPending DistributionStatus = "pending"
	// DistributionStatusInProgress indicates the distribution is currently being sent
	DistributionStatusInProgress DistributionStatus = "in_progress"
	// DistributionStatusCompleted indicates the distribution was successful
	DistributionStatusCompleted DistributionStatus = "completed"
	// DistributionStatusFailed indicates the distribution failed
	DistributionStatusFailed DistributionStatus = "failed"
	// DistributionStatusCancelled indicates the distribution was cancelled
	DistributionStatusCancelled DistributionStatus = "cancelled"
)

// DistributionMethod represents how fixtures are distributed
type DistributionMethod string

const (
	// DistributionMethodHTTPS uses HTTPS POST to distribute fixtures
	DistributionMethodHTTPS DistributionMethod = "https"
	// DistributionMethodLocalFile writes fixtures to local filesystem
	DistributionMethodLocalFile DistributionMethod = "local_file"
	// DistributionMethodS3 distributes fixtures to AWS S3
	DistributionMethodS3 DistributionMethod = "s3"
	// DistributionMethodSSH uses SFTP/SCP to distribute fixtures
	DistributionMethodSSH DistributionMethod = "ssh"
)

// DistributionAuthenticationMethod represents authentication methods for distribution
type DistributionAuthenticationMethod string

const (
	// DistributionAuthNone requires no authentication
	DistributionAuthNone DistributionAuthenticationMethod = "none"
	// DistributionAuthBearer uses Bearer token authentication
	DistributionAuthBearer DistributionAuthenticationMethod = "bearer"
	// DistributionAuthBasic uses Basic authentication
	DistributionAuthBasic DistributionAuthenticationMethod = "basic"
	// DistributionAuthAPIKey uses API key authentication
	DistributionAuthAPIKey DistributionAuthenticationMethod = "api_key"
)

// FixtureDistributionTarget represents a target for fixture distribution
type FixtureDistributionTarget struct {
	// ID is the unique identifier for this distribution target
	ID string
	// Name is a human-readable name for the target
	Name string
	// URL is the target URL or path
	URL string
	// Method is the distribution method to use
	Method DistributionMethod
	// AuthMethod is the authentication method
	AuthMethod DistributionAuthenticationMethod
	// AuthToken contains authentication credentials (sensitive, not logged)
	AuthToken string
	// AllowedCatalogHashes specifies which catalogs can be distributed to this target
	AllowedCatalogHashes []string
	// Enabled controls whether this target is active
	Enabled bool
	// VerifyTLS controls whether TLS certificates are verified
	VerifyTLS bool
	// TimeoutSeconds is the timeout for distribution operations
	TimeoutSeconds int
	// RetryCount is the number of retries on failure
	RetryCount int
	// RetryDelaySeconds is the delay between retries
	RetryDelaySeconds int
	// TargetHash is the deterministic hash of this target configuration
	TargetHash string
}

// FixtureDistributionJob represents a single distribution job
type FixtureDistributionJob struct {
	// DistributionID is the unique identifier for this distribution
	DistributionID string
	// TargetID is the ID of the distribution target
	TargetID string
	// CatalogHash is the hash of the catalog being distributed
	CatalogHash string
	// BundleHashes contains the hashes of bundles being distributed
	BundleHashes []string
	// ManifestHash is the hash of the manifest being distributed (if applicable)
	ManifestHash string
	// Status is the current distribution status
	Status DistributionStatus
	// CreatedAtUnix is when the distribution was created
	CreatedAtUnix int64
	// StartedAtUnix is when the distribution started (if applicable)
	StartedAtUnix int64
	// CompletedAtUnix is when the distribution completed (if applicable)
	CompletedAtUnix int64
	// ErrorMessage contains error details if distribution failed
	ErrorMessage string
	// AttemptCount is the number of attempts made
	AttemptCount int
	// LastAttemptAtUnix is when the last attempt was made
	LastAttemptAtUnix int64
	// JobHash is the deterministic hash of this job
	JobHash string
}

// FixtureDistributionReceipt represents a receipt/acknowledgment of a distribution
type FixtureDistributionReceipt struct {
	// DistributionID is the ID of the distribution being acknowledged
	DistributionID string
	// TargetID is the ID of the target that received the distribution
	TargetID string
	// ReceivedAtUnix is when the distribution was received
	ReceivedAtUnix int64
	// ReceivedCatalogHash is the catalog hash as received
	ReceivedCatalogHash string
	// ReceivedBundleHashes contains the bundle hashes as received
	ReceivedBundleHashes []string
	// VerificationStatus indicates whether the received artifacts match the sent artifacts
	VerificationStatus string
	// ReceiptHash is the deterministic hash of this receipt
	ReceiptHash string
}

// FixtureDistributionIndex represents an index of all distributions
type FixtureDistributionIndex struct {
	// SchemaVersion is the schema version for this index
	SchemaVersion string
	// Distributions contains all distribution jobs
	Distributions []FixtureDistributionJob
	// Targets contains all distribution targets
	Targets []FixtureDistributionTarget
	// IndexHash is the deterministic hash of this index
	IndexHash string
	// LastUpdatedUnix is when the index was last updated
	LastUpdatedUnix int64
}

// NewFixtureDistributionTarget creates a new distribution target with validation
func NewFixtureDistributionTarget(id, name, url string, method DistributionMethod, authMethod DistributionAuthenticationMethod, authToken string) (FixtureDistributionTarget, error) {
	if id == "" {
		return FixtureDistributionTarget{}, fmt.Errorf("%w: ID cannot be empty", ErrInvalidFixtureDistribution)
	}
	if len(id) > MaxDistributionIDLength {
		return FixtureDistributionTarget{}, fmt.Errorf("%w: ID too long", ErrInvalidFixtureDistribution)
	}

	if name == "" {
		return FixtureDistributionTarget{}, fmt.Errorf("%w: name cannot be empty", ErrInvalidFixtureDistribution)
	}

	if url == "" {
		return FixtureDistributionTarget{}, fmt.Errorf("%w: URL cannot be empty", ErrInvalidFixtureDistribution)
	}
	if len(url) > MaxDistributionTargetURLLength {
		return FixtureDistributionTarget{}, fmt.Errorf("%w: URL too long", ErrInvalidFixtureDistribution)
	}

	// Validate URL format based on method
	if method == DistributionMethodHTTPS {
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return FixtureDistributionTarget{}, fmt.Errorf("%w: invalid URL scheme for HTTPS method, must use http:// or https://", ErrInvalidFixtureDistribution)
		}
	} else if method == DistributionMethodS3 {
		if !strings.HasPrefix(url, "s3://") {
			return FixtureDistributionTarget{}, fmt.Errorf("%w: invalid URL scheme for S3 method, must use s3://", ErrInvalidFixtureDistribution)
		}
	} else if method == DistributionMethodSSH {
		if !strings.HasPrefix(url, "ssh://") && !strings.HasPrefix(url, "sftp://") {
			return FixtureDistributionTarget{}, fmt.Errorf("%w: invalid URL scheme for SSH method, must use ssh:// or sftp://", ErrInvalidFixtureDistribution)
		}
	}
	// For local file, no URL scheme validation needed

	// Validate method
	if method != DistributionMethodHTTPS && method != DistributionMethodLocalFile && method != DistributionMethodS3 && method != DistributionMethodSSH {
		return FixtureDistributionTarget{}, fmt.Errorf("%w: invalid distribution method", ErrInvalidFixtureDistribution)
	}

	// Validate auth method
	if authMethod != DistributionAuthNone && authMethod != DistributionAuthBearer && authMethod != DistributionAuthBasic && authMethod != DistributionAuthAPIKey {
		return FixtureDistributionTarget{}, fmt.Errorf("%w: invalid authentication method", ErrInvalidFixtureDistribution)
	}

	target := FixtureDistributionTarget{
		ID:                   id,
		Name:                 name,
		URL:                  url,
		Method:               method,
		AuthMethod:           authMethod,
		AuthToken:            authToken,
		AllowedCatalogHashes: make([]string, 0),
		Enabled:              true,
		VerifyTLS:            true,
		TimeoutSeconds:       30,
		RetryCount:           3,
		RetryDelaySeconds:    5,
	}

	target.TargetHash = FixtureDistributionTargetHash(target)

	if err := ValidateFixtureDistributionTarget(target); err != nil {
		return FixtureDistributionTarget{}, err
	}

	return target, nil
}

// NewFixtureDistributionJob creates a new distribution job
func NewFixtureDistributionJob(distributionID, targetID, catalogHash string, bundleHashes []string, manifestHash string) (FixtureDistributionJob, error) {
	if distributionID == "" {
		return FixtureDistributionJob{}, fmt.Errorf("%w: distribution ID cannot be empty", ErrInvalidFixtureDistribution)
	}
	if len(distributionID) > MaxDistributionIDLength {
		return FixtureDistributionJob{}, fmt.Errorf("%w: distribution ID too long", ErrInvalidFixtureDistribution)
	}

	if targetID == "" {
		return FixtureDistributionJob{}, fmt.Errorf("%w: target ID cannot be empty", ErrInvalidFixtureDistribution)
	}

	if catalogHash == "" && len(bundleHashes) == 0 {
		return FixtureDistributionJob{}, fmt.Errorf("%w: must specify catalog hash or bundle hashes", ErrInvalidFixtureDistribution)
	}

	nowUnix := time.Now().Unix()
	job := FixtureDistributionJob{
		DistributionID: distributionID,
		TargetID:       targetID,
		CatalogHash:    catalogHash,
		BundleHashes:   bundleHashes,
		ManifestHash:   manifestHash,
		Status:         DistributionStatusPending,
		CreatedAtUnix:  nowUnix,
		AttemptCount:   0,
	}

	job.JobHash = FixtureDistributionJobHash(job)

	if err := ValidateFixtureDistributionJob(job); err != nil {
		return FixtureDistributionJob{}, err
	}

	return job, nil
}

// NewFixtureDistributionReceipt creates a new distribution receipt
func NewFixtureDistributionReceipt(distributionID, targetID string, receivedCatalogHash string, receivedBundleHashes []string, verificationStatus string) (FixtureDistributionReceipt, error) {
	if distributionID == "" {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: distribution ID cannot be empty", ErrInvalidFixtureDistribution)
	}
	if targetID == "" {
		return FixtureDistributionReceipt{}, fmt.Errorf("%w: target ID cannot be empty", ErrInvalidFixtureDistribution)
	}

	nowUnix := time.Now().Unix()
	receipt := FixtureDistributionReceipt{
		DistributionID:       distributionID,
		TargetID:             targetID,
		ReceivedAtUnix:       nowUnix,
		ReceivedCatalogHash:  receivedCatalogHash,
		ReceivedBundleHashes: receivedBundleHashes,
		VerificationStatus:   verificationStatus,
	}

	receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

	if err := ValidateFixtureDistributionReceipt(receipt); err != nil {
		return FixtureDistributionReceipt{}, err
	}

	return receipt, nil
}

// NewFixtureDistributionIndex creates a new distribution index
func NewFixtureDistributionIndex(distributions []FixtureDistributionJob, targets []FixtureDistributionTarget) (FixtureDistributionIndex, error) {
	nowUnix := time.Now().Unix()
	index := FixtureDistributionIndex{
		SchemaVersion:   FixtureDistributionSchemaVersion,
		Distributions:   distributions,
		Targets:         targets,
		LastUpdatedUnix: nowUnix,
	}

	index.IndexHash = FixtureDistributionIndexHash(index)

	if err := ValidateFixtureDistributionIndex(index); err != nil {
		return FixtureDistributionIndex{}, err
	}

	return index, nil
}

// FixtureDistributionTargetHash computes a deterministic hash for a distribution target
func FixtureDistributionTargetHash(target FixtureDistributionTarget) string {
	// Create a deterministic representation
	data := fmt.Sprintf("target:%s:%s:%s:%s:%s:%t:%t:%d:%d:%d",
		target.ID,
		target.Name,
		target.URL,
		target.Method,
		target.AuthMethod,
		target.Enabled,
		target.VerifyTLS,
		target.TimeoutSeconds,
		target.RetryCount,
		target.RetryDelaySeconds,
	)
	// Sort allowed catalog hashes for determinism
	sortedHashes := make([]string, len(target.AllowedCatalogHashes))
	copy(sortedHashes, target.AllowedCatalogHashes)
	for i := range sortedHashes {
		for j := i + 1; j < len(sortedHashes); j++ {
			if sortedHashes[i] > sortedHashes[j] {
				sortedHashes[i], sortedHashes[j] = sortedHashes[j], sortedHashes[i]
			}
		}
	}
	data += fmt.Sprintf(":%v", sortedHashes)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// FixtureDistributionJobHash computes a deterministic hash for a distribution job
func FixtureDistributionJobHash(job FixtureDistributionJob) string {
	// Sort bundle hashes for determinism
	sortedHashes := make([]string, len(job.BundleHashes))
	copy(sortedHashes, job.BundleHashes)
	for i := range sortedHashes {
		for j := i + 1; j < len(sortedHashes); j++ {
			if sortedHashes[i] > sortedHashes[j] {
				sortedHashes[i], sortedHashes[j] = sortedHashes[j], sortedHashes[i]
			}
		}
	}

	data := fmt.Sprintf("job:%s:%s:%s:%v:%s:%d:%d:%d:%d:%s:%d",
		job.DistributionID,
		job.TargetID,
		job.CatalogHash,
		sortedHashes,
		job.ManifestHash,
		job.CreatedAtUnix,
		job.StartedAtUnix,
		job.CompletedAtUnix,
		job.AttemptCount,
		job.ErrorMessage,
		job.LastAttemptAtUnix,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// FixtureDistributionReceiptHash computes a deterministic hash for a distribution receipt
func FixtureDistributionReceiptHash(receipt FixtureDistributionReceipt) string {
	// Sort bundle hashes for determinism
	sortedHashes := make([]string, len(receipt.ReceivedBundleHashes))
	copy(sortedHashes, receipt.ReceivedBundleHashes)
	for i := range sortedHashes {
		for j := i + 1; j < len(sortedHashes); j++ {
			if sortedHashes[i] > sortedHashes[j] {
				sortedHashes[i], sortedHashes[j] = sortedHashes[j], sortedHashes[i]
			}
		}
	}

	data := fmt.Sprintf("receipt:%s:%s:%d:%s:%v:%s",
		receipt.DistributionID,
		receipt.TargetID,
		receipt.ReceivedAtUnix,
		receipt.ReceivedCatalogHash,
		sortedHashes,
		receipt.VerificationStatus,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// FixtureDistributionIndexHash computes a deterministic hash for a distribution index
func FixtureDistributionIndexHash(index FixtureDistributionIndex) string {
	// Sort distributions by ID for determinism
	sortedDistributions := make([]FixtureDistributionJob, len(index.Distributions))
	copy(sortedDistributions, index.Distributions)
	for i := range sortedDistributions {
		for j := i + 1; j < len(sortedDistributions); j++ {
			if sortedDistributions[i].DistributionID > sortedDistributions[j].DistributionID {
				sortedDistributions[i], sortedDistributions[j] = sortedDistributions[j], sortedDistributions[i]
			}
		}
	}

	// Sort targets by ID for determinism
	sortedTargets := make([]FixtureDistributionTarget, len(index.Targets))
	copy(sortedTargets, index.Targets)
	for i := range sortedTargets {
		for j := i + 1; j < len(sortedTargets); j++ {
			if sortedTargets[i].ID > sortedTargets[j].ID {
				sortedTargets[i], sortedTargets[j] = sortedTargets[j], sortedTargets[i]
			}
		}
	}

	data := fmt.Sprintf("index:%s:%d:%v:%v",
		index.SchemaVersion,
		index.LastUpdatedUnix,
		sortedDistributions,
		sortedTargets,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ValidateFixtureDistributionTarget validates a distribution target
func ValidateFixtureDistributionTarget(target FixtureDistributionTarget) error {
	if target.ID == "" {
		return fmt.Errorf("%w: ID cannot be empty", ErrInvalidFixtureDistribution)
	}
	if len(target.ID) > MaxDistributionIDLength {
		return fmt.Errorf("%w: ID too long", ErrInvalidFixtureDistribution)
	}

	if target.Name == "" {
		return fmt.Errorf("%w: name cannot be empty", ErrInvalidFixtureDistribution)
	}

	if target.URL == "" {
		return fmt.Errorf("%w: URL cannot be empty", ErrInvalidFixtureDistribution)
	}
	if len(target.URL) > MaxDistributionTargetURLLength {
		return fmt.Errorf("%w: URL too long", ErrInvalidFixtureDistribution)
	}

	// Validate method
	switch target.Method {
	case DistributionMethodHTTPS, DistributionMethodLocalFile, DistributionMethodS3, DistributionMethodSSH:
		// valid
	default:
		return fmt.Errorf("%w: invalid distribution method", ErrInvalidFixtureDistribution)
	}

	// Validate auth method
	switch target.AuthMethod {
	case DistributionAuthNone, DistributionAuthBearer, DistributionAuthBasic, DistributionAuthAPIKey:
		// valid
	default:
		return fmt.Errorf("%w: invalid authentication method", ErrInvalidFixtureDistribution)
	}

	// Validate timing values
	if target.TimeoutSeconds < 0 {
		return fmt.Errorf("%w: timeout cannot be negative", ErrInvalidFixtureDistribution)
	}
	if target.RetryCount < 0 {
		return fmt.Errorf("%w: retry count cannot be negative", ErrInvalidFixtureDistribution)
	}
	if target.RetryDelaySeconds < 0 {
		return fmt.Errorf("%w: retry delay cannot be negative", ErrInvalidFixtureDistribution)
	}

	// Validate target hash
	if target.TargetHash == "" {
		return fmt.Errorf("%w: target hash cannot be empty", ErrInvalidFixtureDistribution)
	}
	computedHash := FixtureDistributionTargetHash(target)
	if target.TargetHash != computedHash {
		return fmt.Errorf("%w: target hash mismatch", ErrInvalidFixtureDistribution)
	}

	return nil
}

// ValidateFixtureDistributionJob validates a distribution job
func ValidateFixtureDistributionJob(job FixtureDistributionJob) error {
	if job.DistributionID == "" {
		return fmt.Errorf("%w: distribution ID cannot be empty", ErrInvalidFixtureDistribution)
	}
	if len(job.DistributionID) > MaxDistributionIDLength {
		return fmt.Errorf("%w: distribution ID too long", ErrInvalidFixtureDistribution)
	}

	if job.TargetID == "" {
		return fmt.Errorf("%w: target ID cannot be empty", ErrInvalidFixtureDistribution)
	}

	// Must have at least one of catalog hash or bundle hashes
	if job.CatalogHash == "" && len(job.BundleHashes) == 0 {
		return fmt.Errorf("%w: must specify catalog hash or bundle hashes", ErrInvalidFixtureDistribution)
	}

	// Validate status
	switch job.Status {
	case DistributionStatusPending, DistributionStatusInProgress, DistributionStatusCompleted, DistributionStatusFailed, DistributionStatusCancelled:
		// valid
	default:
		return fmt.Errorf("%w: invalid distribution status", ErrInvalidFixtureDistribution)
	}

	// Validate timing values
	if job.CreatedAtUnix <= 0 {
		return fmt.Errorf("%w: created time must be positive", ErrInvalidFixtureDistribution)
	}
	if job.StartedAtUnix < 0 && job.StartedAtUnix != 0 {
		return fmt.Errorf("%w: started time cannot be negative", ErrInvalidFixtureDistribution)
	}
	if job.CompletedAtUnix < 0 && job.CompletedAtUnix != 0 {
		return fmt.Errorf("%w: completed time cannot be negative", ErrInvalidFixtureDistribution)
	}
	if job.LastAttemptAtUnix < 0 && job.LastAttemptAtUnix != 0 {
		return fmt.Errorf("%w: last attempt time cannot be negative", ErrInvalidFixtureDistribution)
	}

	// Validate attempt count
	if job.AttemptCount < 0 {
		return fmt.Errorf("%w: attempt count cannot be negative", ErrInvalidFixtureDistribution)
	}

	// Validate job hash
	if job.JobHash == "" {
		return fmt.Errorf("%w: job hash cannot be empty", ErrInvalidFixtureDistribution)
	}
	computedHash := FixtureDistributionJobHash(job)
	if job.JobHash != computedHash {
		return fmt.Errorf("%w: job hash mismatch", ErrInvalidFixtureDistribution)
	}

	return nil
}

// ValidateFixtureDistributionReceipt validates a distribution receipt
func ValidateFixtureDistributionReceipt(receipt FixtureDistributionReceipt) error {
	if receipt.DistributionID == "" {
		return fmt.Errorf("%w: distribution ID cannot be empty", ErrInvalidFixtureDistribution)
	}
	if receipt.TargetID == "" {
		return fmt.Errorf("%w: target ID cannot be empty", ErrInvalidFixtureDistribution)
	}

	// Validate timing
	if receipt.ReceivedAtUnix <= 0 {
		return fmt.Errorf("%w: received time must be positive", ErrInvalidFixtureDistribution)
	}

	// Validate receipt hash
	if receipt.ReceiptHash == "" {
		return fmt.Errorf("%w: receipt hash cannot be empty", ErrInvalidFixtureDistribution)
	}
	computedHash := FixtureDistributionReceiptHash(receipt)
	if receipt.ReceiptHash != computedHash {
		return fmt.Errorf("%w: receipt hash mismatch", ErrInvalidFixtureDistribution)
	}

	return nil
}

// ValidateFixtureDistributionIndex validates a distribution index
func ValidateFixtureDistributionIndex(index FixtureDistributionIndex) error {
	if index.SchemaVersion == "" {
		return fmt.Errorf("%w: schema version cannot be empty", ErrInvalidFixtureDistribution)
	}
	if index.SchemaVersion != FixtureDistributionSchemaVersion {
		return fmt.Errorf("%w: unsupported schema version", ErrInvalidFixtureDistribution)
	}

	// Validate last updated time
	if index.LastUpdatedUnix <= 0 {
		return fmt.Errorf("%w: last updated time must be positive", ErrInvalidFixtureDistribution)
	}

	// Validate index hash
	if index.IndexHash == "" {
		return fmt.Errorf("%w: index hash cannot be empty", ErrInvalidFixtureDistribution)
	}
	computedHash := FixtureDistributionIndexHash(index)
	if index.IndexHash != computedHash {
		return fmt.Errorf("%w: index hash mismatch", ErrInvalidFixtureDistribution)
	}

	return nil
}

// GetFixtureDistributionByID finds a distribution job by its ID
func GetFixtureDistributionByID(index FixtureDistributionIndex, distributionID string) (FixtureDistributionJob, bool) {
	for _, job := range index.Distributions {
		if job.DistributionID == distributionID {
			return job, true
		}
	}
	return FixtureDistributionJob{}, false
}

// GetFixtureDistributionTargetByID finds a distribution target by its ID
func GetFixtureDistributionTargetByID(index FixtureDistributionIndex, targetID string) (FixtureDistributionTarget, bool) {
	for _, target := range index.Targets {
		if target.ID == targetID {
			return target, true
		}
	}
	return FixtureDistributionTarget{}, false
}

// GetDistributionsByTargetID finds all distribution jobs for a specific target
func GetDistributionsByTargetID(index FixtureDistributionIndex, targetID string) []FixtureDistributionJob {
	result := make([]FixtureDistributionJob, 0)
	for _, job := range index.Distributions {
		if job.TargetID == targetID {
			result = append(result, job)
		}
	}
	return result
}

// GetDistributionsByCatalogHash finds all distribution jobs for a specific catalog
func GetDistributionsByCatalogHash(index FixtureDistributionIndex, catalogHash string) []FixtureDistributionJob {
	result := make([]FixtureDistributionJob, 0)
	for _, job := range index.Distributions {
		if job.CatalogHash == catalogHash {
			result = append(result, job)
		}
	}
	return result
}

// GetDistributionsByStatus finds all distribution jobs with a specific status
func GetDistributionsByStatus(index FixtureDistributionIndex, status DistributionStatus) []FixtureDistributionJob {
	result := make([]FixtureDistributionJob, 0)
	for _, job := range index.Distributions {
		if job.Status == status {
			result = append(result, job)
		}
	}
	return result
}
