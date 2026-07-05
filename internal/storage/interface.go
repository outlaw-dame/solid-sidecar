// Package storage provides the production storage engine for the Solid runtime.
// This package implements Phase 18: Production storage engine.
//
// The storage engine provides a unified interface for resource storage that can
// support a native Go/Rust Solid runtime without hard-coding CSS assumptions.
//
// Key principles:
// - Small, Solid-oriented interface
// - Storage adapters are replaceable plugins after core interface is stable
// - Validators and concurrency metadata are storage-layer facts, not HTTP-only decorations
// - Backend-specific behavior is not exposed to authz or HTTP layers
// - Migration-safe with versioned layout
package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

// Errors for the storage package
var (
	ErrNotFound           = errors.New("resource not found")
	ErrAlreadyExists      = errors.New("resource already exists")
	ErrPreconditionFailed = errors.New("precondition failed")
	ErrConflict           = errors.New("conflict")
	ErrQuotaExceeded      = errors.New("quota exceeded")
	ErrStorageClosed      = errors.New("storage is closed")
	ErrInvalidURI         = errors.New("invalid URI")
	ErrInvalidContentType = errors.New("invalid content type")
	ErrInvalidETag        = errors.New("invalid ETag")
	ErrBackendUnavailable = errors.New("backend unavailable")
	ErrIntegrityViolation = errors.New("integrity violation")
	ErrMigrationRequired  = errors.New("migration required")
	ErrTombstoneExists    = errors.New("tombstone exists")
)

// ResourceType defines the type of a resource
type ResourceType string

const (
	ResourceTypeUnknown   ResourceType = "Unknown"
	ResourceTypeResource  ResourceType = "Resource"
	ResourceTypeContainer ResourceType = "Container"
	ResourceTypeACL       ResourceType = "ACL"
	ResourceTypeACP       ResourceType = "ACP"
	ResourceTypeMetadata  ResourceType = "Metadata"
	ResourceTypeBlob      ResourceType = "Blob"
)

// ContentAddress is a content-addressed identifier
type ContentAddress string

// Tombstone represents a deletion marker
type Tombstone struct {
	// URI is the URI of the tombstoned resource
	URI string

	// DeletedAt is when the resource was deleted
	DeletedAt time.Time

	// DeletedBy is who deleted the resource (optional, may be empty for privacy)
	DeletedBy string

	// Reason contains the reason for deletion (optional)
	Reason string

	// RestoreToken is a token that can be used to restore the resource (optional)
	RestoreToken string
}

// QuotaInfo represents quota information for a storage root or tenant
type QuotaInfo struct {
	// StorageRoot is the storage root URI
	StorageRoot string

	// Tenant is the tenant identifier
	Tenant string

	// UsedBytes is the number of bytes used
	UsedBytes int64

	// MaxBytes is the maximum bytes allowed (0 = unlimited)
	MaxBytes int64

	// UsedResources is the number of resources used
	UsedResources int64

	// MaxResources is the maximum number of resources allowed (0 = unlimited)
	MaxResources int64
}

// WritePrecondition defines conditions for a write operation
type WritePrecondition struct {
	// IfMatch requires the resource to have this ETag (or "*" for any ETag)
	IfMatch string

	// IfNoneMatch requires the resource to NOT have this ETag (or "*" for no ETag)
	IfNoneMatch string

	// CompareAndSwap is a storage-level compare-and-swap operation
	// If provided, the write only succeeds if the current value matches ExpectedValue
	CompareAndSwap *CompareAndSwapPrecondition
}

// CompareAndSwapPrecondition defines a storage-level compare-and-swap condition
type CompareAndSwapPrecondition struct {
	// Key is the metadata key to compare
	Key string

	// ExpectedValue is the expected current value
	ExpectedValue string

	// NewValue is the value to set if the comparison succeeds
	NewValue string
}

// StorageLayoutVersion represents the version of the storage layout
type StorageLayoutVersion int

// CurrentStorageLayoutVersion is the current version of the storage layout
const CurrentStorageLayoutVersion StorageLayoutVersion = 1

// MinSupportedStorageLayoutVersion is the minimum supported version
const MinSupportedStorageLayoutVersion StorageLayoutVersion = 1

// Metadata contains all metadata for a resource
type Metadata struct {
	// URI is the resource identifier
	URI string

	// ResourceType is the type of the resource
	ResourceType ResourceType

	// ContentType is the MIME type of the resource
	ContentType string

	// Size is the size of the resource in bytes
	Size int64

	// Digest is the content digest (SHA-256 for content-addressed blobs)
	Digest string

	// LastModified is when the resource was last modified
	LastModified time.Time

	// Created is when the resource was created
	Created time.Time

	// ETag is the entity tag for the resource
	ETag string

	// Owner is the owner of the resource (WebID or DID)
	Owner string

	// StorageRoot is the storage root for the resource
	StorageRoot string

	// Tenant is the tenant identifier
	Tenant string

	// AuxiliaryLinks contains links to auxiliary resources
	AuxiliaryLinks map[string]string

	// PolicyReferences contains references to policy resources
	PolicyReferences []string

	// ValidatorState contains state for validators
	ValidatorState map[string]string

	// ContentAddress is the content address for immutable blobs
	ContentAddress ContentAddress

	// LayoutVersion is the storage layout version used for this resource
	LayoutVersion StorageLayoutVersion

	// Custom contains additional custom metadata
	Custom map[string]string
}

// quotaUsageInfo tracks quota usage for a storage root
type quotaUsageInfo struct {
	UsedBytes     int64
	UsedResources int64
	MaxBytes      int64
	MaxResources  int64
}

// Resource represents a complete resource with body and metadata
type Resource struct {
	// URI is the resource identifier
	URI string

	// Body is the resource content
	Body []byte

	// BodyReader provides a streaming reader for the body (may be nil if Body is set)
	BodyReader io.Reader

	// Metadata contains the resource metadata
	Metadata Metadata
}

// ReadResource provides a streaming interface for reading resources
type ReadResource struct {
	// URI is the resource identifier
	URI string

	// Body provides the complete body (alternative to BodyReader)
	Body []byte

	// BodyReader provides a streaming reader for the body
	BodyReader io.Reader

	// Metadata contains the resource metadata
	Metadata Metadata
}

// WriteResource provides a streaming interface for writing resources
type WriteResource struct {
	// URI is the resource identifier
	URI string

	// Body provides the complete body (alternative to BodyReader)
	Body []byte

	// BodyReader provides a streaming reader for the body
	BodyReader io.Reader

	// BodySize is the size of the body (if known)
	BodySize int64

	// Metadata contains the resource metadata
	Metadata Metadata

	// Preconditions defines write preconditions
	Preconditions WritePrecondition
}

// Transaction represents a storage transaction
type Transaction interface {
	// Get retrieves a resource within the transaction
	Get(ctx context.Context, uri string) (*Resource, error)

	// Put stores a resource within the transaction
	Put(ctx context.Context, resource *WriteResource) error

	// Delete removes a resource within the transaction
	Delete(ctx context.Context, uri string) error

	// Commit commits the transaction
	Commit(ctx context.Context) error

	// Rollback rolls back the transaction
	Rollback(ctx context.Context) error
}

// BackupRestore provides backup and restore functionality
type BackupRestore interface {
	// Backup creates a backup of the storage
	Backup(ctx context.Context, writer io.Writer) error

	// Restore restores from a backup
	Restore(ctx context.Context, reader io.Reader) error

	// BackupResource backs up a single resource
	BackupResource(ctx context.Context, uri string, writer io.Writer) error

	// RestoreResource restores a single resource
	RestoreResource(ctx context.Context, uri string, reader io.Reader) error
}

// IntegrityScanner provides integrity verification
type IntegrityScanner interface {
	// Scan performs an integrity scan
	Scan(ctx context.Context) (*IntegrityReport, error)

	// ScanResource scans a single resource for integrity
	ScanResource(ctx context.Context, uri string) (*ResourceIntegrityReport, error)

	// Repair attempts to repair integrity violations
	Repair(ctx context.Context, report *IntegrityReport) (*IntegrityRepairReport, error)
}

// IntegrityReport contains the results of an integrity scan
type IntegrityReport struct {
	// ScannedAt is when the scan was performed
	ScannedAt time.Time

	// TotalResources is the total number of resources scanned
	TotalResources int64

	// ResourcesWithIssues is the number of resources with integrity issues
	ResourcesWithIssues int64

	// MetadataBodyMismatches is the number of metadata/body mismatches
	MetadataBodyMismatches int64

	// MissingDigests is the number of resources missing digests
	MissingDigests int64

	// OrphanedBlobs is the number of orphaned blobs
	OrphanedBlobs int64

	// ResourceReports contains per-resource reports
	ResourceReports []ResourceIntegrityReport
}

// ResourceIntegrityReport contains integrity information for a single resource
type ResourceIntegrityReport struct {
	// URI is the resource URI
	URI string

	// Issues contains the integrity issues found
	Issues []IntegrityIssue
}

// IntegrityIssue represents a single integrity issue
type IntegrityIssue struct {
	// Type is the type of issue
	Type IntegrityIssueType

	// Severity is the severity of the issue
	Severity IntegrityIssueSeverity

	// Description describes the issue
	Description string

	// Details contains additional details
	Details map[string]string
}

// IntegrityIssueType defines the type of integrity issue
type IntegrityIssueType string

const (
	IssueTypeMetadataBodyMismatch  IntegrityIssueType = "metadata_body_mismatch"
	IssueTypeMissingDigest         IntegrityIssueType = "missing_digest"
	IssueTypeInvalidDigest         IntegrityIssueType = "invalid_digest"
	IssueTypeOrphanedBlob          IntegrityIssueType = "orphaned_blob"
	IssueTypeCorruptedMetadata     IntegrityIssueType = "corrupted_metadata"
	IssueTypeLayoutVersionMismatch IntegrityIssueType = "layout_version_mismatch"
)

// IntegrityIssueSeverity defines the severity of an integrity issue
type IntegrityIssueSeverity string

const (
	SeverityLow      IntegrityIssueSeverity = "low"
	SeverityMedium   IntegrityIssueSeverity = "medium"
	SeverityHigh     IntegrityIssueSeverity = "high"
	SeverityCritical IntegrityIssueSeverity = "critical"
)

// IntegrityRepairReport contains the results of integrity repairs
type IntegrityRepairReport struct {
	// RepairedAt is when the repair was performed
	RepairedAt time.Time

	// TotalIssues is the total number of issues found
	TotalIssues int64

	// IssuesRepaired is the number of issues repaired
	IssuesRepaired int64

	// IssuesUnrepaired is the number of issues that could not be repaired
	IssuesUnrepaired int64

	// Errors contains repair errors
	Errors []error
}

// StorageEngine is the main interface for the storage engine
type StorageEngine interface {
	// Resource operations
	Get(ctx context.Context, uri string) (*ReadResource, error)
	GetMetadata(ctx context.Context, uri string) (*Metadata, error)
	Put(ctx context.Context, resource *WriteResource) error
	Delete(ctx context.Context, uri string) error
	DeleteWithTombstone(ctx context.Context, uri string, tombstone *Tombstone) error

	// Container operations
	List(ctx context.Context, containerURI string) ([]*Metadata, error)
	ListWithPrefix(ctx context.Context, containerURI, prefix string) ([]*Metadata, error)

	// Existence checks
	Exists(ctx context.Context, uri string) (bool, error)
	ExistsWithTombstone(ctx context.Context, uri string) (bool, bool, error) // (exists, isTombstoned, error)

	// Blob operations (content-addressed)
	StoreBlob(ctx context.Context, data []byte) (ContentAddress, error)
	GetBlob(ctx context.Context, address ContentAddress) ([]byte, error)
	DeleteBlob(ctx context.Context, address ContentAddress) error
	BlobExists(ctx context.Context, address ContentAddress) (bool, error)

	// Transaction operations
	BeginTransaction(ctx context.Context) (Transaction, error)

	// Quota operations
	GetQuota(ctx context.Context, storageRoot string) (*QuotaInfo, error)
	GetTenantQuota(ctx context.Context, tenant string) (*QuotaInfo, error)
	CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error

	// Tombstone operations
	GetTombstone(ctx context.Context, uri string) (*Tombstone, error)
	ListTombstones(ctx context.Context, storageRoot string) ([]*Tombstone, error)
	RestoreFromTombstone(ctx context.Context, uri string, restoreToken string) error

	// Layout version operations
	GetLayoutVersion(ctx context.Context) (StorageLayoutVersion, error)
	SetLayoutVersion(ctx context.Context, version StorageLayoutVersion) error
	MigrateLayout(ctx context.Context, targetVersion StorageLayoutVersion) error

	// Backup/restore operations
	Backup() BackupRestore

	// Integrity operations
	Integrity() IntegrityScanner

	// Health check
	HealthCheck(ctx context.Context) error

	// Close
	Close() error

	// RegisterBackend registers a new storage backend
	RegisterBackend(name string, backend StorageBackend) error
}

// MetadataStore is the interface for metadata operations
type MetadataStore interface {
	// GetMetadata retrieves metadata for a resource
	GetMetadata(ctx context.Context, uri string) (*Metadata, error)

	// StoreMetadata stores metadata for a resource
	StoreMetadata(ctx context.Context, uri string, metadata *Metadata) error

	// DeleteMetadata deletes metadata for a resource
	DeleteMetadata(ctx context.Context, uri string) error

	// ListMetadata lists metadata for resources in a container
	ListMetadata(ctx context.Context, containerURI string) ([]*Metadata, error)

	// Exists checks if metadata exists for a resource
	Exists(ctx context.Context, uri string) (bool, error)
}

// BlobStore is the interface for content-addressed blob operations
type BlobStore interface {
	// StoreBlob stores a content-addressed blob and returns its address
	StoreBlob(ctx context.Context, data []byte) (ContentAddress, error)

	// GetBlob retrieves a content-addressed blob
	GetBlob(ctx context.Context, address ContentAddress) ([]byte, error)

	// DeleteBlob deletes a content-addressed blob
	DeleteBlob(ctx context.Context, address ContentAddress) error

	// BlobExists checks if a blob exists
	BlobExists(ctx context.Context, address ContentAddress) (bool, error)

	// ListBlobs lists all blobs (for migration/integrity purposes)
	ListBlobs(ctx context.Context) ([]ContentAddress, error)
}

// TombstoneStore is the interface for tombstone operations
type TombstoneStore interface {
	// GetTombstone retrieves a tombstone for a resource
	GetTombstone(ctx context.Context, uri string) (*Tombstone, error)

	// StoreTombstone stores a tombstone for a resource
	StoreTombstone(ctx context.Context, tombstone *Tombstone) error

	// DeleteTombstone deletes a tombstone for a resource
	DeleteTombstone(ctx context.Context, uri string) error

	// ListTombstones lists tombstones for a storage root
	ListTombstones(ctx context.Context, storageRoot string) ([]*Tombstone, error)

	// TombstoneExists checks if a tombstone exists for a resource
	TombstoneExists(ctx context.Context, uri string) (bool, error)
}

// QuotaManager is the interface for quota management
type QuotaManager interface {
	// GetQuota retrieves quota information for a storage root or tenant
	GetQuota(ctx context.Context, storageRoot string) (*QuotaInfo, error)

	// GetTenantQuota retrieves quota information for a tenant
	GetTenantQuota(ctx context.Context, tenant string) (*QuotaInfo, error)

	// CheckQuota checks if a write would exceed quota
	CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error

	// RecordUsage records resource usage for quota tracking
	RecordUsage(ctx context.Context, storageRoot string, bytesUsed int64) error

	// ReleaseUsage releases resource usage for quota tracking
	ReleaseUsage(ctx context.Context, storageRoot string, bytesFreed int64) error

	// SetQuota sets quota limits for a storage root or tenant
	SetQuota(ctx context.Context, storageRoot string, quota *QuotaInfo) error
}

// StorageBackend is the interface that all storage backends must implement
// This is the plugin interface for different storage implementations
type StorageBackend interface {
	// Name returns the name of the backend
	Name() string

	// Description returns a description of the backend
	Description() string

	// Initialize initializes the backend with the given configuration
	Initialize(ctx context.Context, config map[string]string) error

	// Get retrieves a resource by URI
	Get(ctx context.Context, uri string) (*Resource, error)

	// GetMetadata retrieves metadata for a resource
	GetMetadata(ctx context.Context, uri string) (*Metadata, error)

	// Put stores a resource
	Put(ctx context.Context, uri string, resource *WriteResource) error

	// Delete removes a resource
	Delete(ctx context.Context, uri string) error

	// List lists resources in a container
	List(ctx context.Context, containerURI string) ([]*Metadata, error)

	// Exists checks if a resource exists
	Exists(ctx context.Context, uri string) (bool, error)

	// StoreBlob stores a content-addressed blob
	StoreBlob(ctx context.Context, data []byte) (ContentAddress, error)

	// GetBlob retrieves a content-addressed blob
	GetBlob(ctx context.Context, address ContentAddress) ([]byte, error)

	// BlobExists checks if a blob exists
	BlobExists(ctx context.Context, address ContentAddress) (bool, error)

	// DeleteBlob deletes a blob
	DeleteBlob(ctx context.Context, address ContentAddress) error

	// GetQuota retrieves quota information
	GetQuota(ctx context.Context, storageRoot string) (*QuotaInfo, error)

	// CheckQuota checks if a write would exceed quota
	CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error

	// GetTombstone retrieves a tombstone
	GetTombstone(ctx context.Context, uri string) (*Tombstone, error)

	// StoreTombstone stores a tombstone
	StoreTombstone(ctx context.Context, tombstone *Tombstone) error

	// DeleteTombstone deletes a tombstone
	DeleteTombstone(ctx context.Context, uri string) error

	// ListTombstones lists tombstones for a storage root
	ListTombstones(ctx context.Context, storageRoot string) ([]*Tombstone, error)

	// GetLayoutVersion retrieves the layout version
	GetLayoutVersion(ctx context.Context) (StorageLayoutVersion, error)

	// SetLayoutVersion sets the layout version
	SetLayoutVersion(ctx context.Context, version StorageLayoutVersion) error

	// Backup creates a backup
	Backup(ctx context.Context, writer io.Writer) error

	// Restore restores from a backup
	Restore(ctx context.Context, reader io.Reader) error

	// ScanIntegrity performs an integrity scan
	ScanIntegrity(ctx context.Context) (*IntegrityReport, error)

	// HealthCheck checks backend health
	HealthCheck(ctx context.Context) error

	// Close closes the backend
	Close() error
}

// GetStorageEngine returns the global storage engine
func GetStorageEngine() StorageEngine {
	return storageEngine
}

// SetStorageEngine sets the global storage engine (for testing)
func SetStorageEngine(engine StorageEngine) {
	storageEngine = engine
}

// Global storage engine instance
var storageEngine StorageEngine

// Ensure interfaces are satisfied at compile time
// These will be defined in their respective implementation files
// var _ StorageEngine = (*storageEngineImpl)(nil)
// var _ StorageBackend = (*filesystemBackend)(nil)
// var _ Transaction = (*storageTransaction)(nil)
// var _ BackupRestore = (*backupRestoreImpl)(nil)
// var _ IntegrityScanner = (*integrityScannerImpl)(nil)
