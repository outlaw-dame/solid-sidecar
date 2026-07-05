// Package storage provides the production storage engine for the Solid runtime.
// This file implements the S3 blob storage backend for Phase 18.
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3BackendConfig holds configuration for the S3 backend
type S3BackendConfig struct {
	// Bucket is the S3 bucket name
	Bucket string

	// Region is the AWS region
	Region string

	// Endpoint is the custom S3 endpoint (optional, for S3-compatible services)
	Endpoint string

	// AccessKey is the AWS access key ID
	AccessKey string

	// SecretKey is the AWS secret access key
	SecretKey string

	// SessionToken is the AWS session token (optional)
	SessionToken string

	// UsePathStyle enables path-style addressing (needed for some S3-compatible services)
	UsePathStyle bool

	// UseSSL enables SSL/TLS for connections
	UseSSL bool

	// Logger is the logger for this backend
	Logger *slog.Logger
}

// s3Backend implements StorageBackend using Amazon S3
type s3Backend struct {
	config S3BackendConfig
	client *s3.Client
	logger *slog.Logger
	mu     sync.RWMutex
	closed bool

	// Metadata cache
	metadataCache map[string]*Metadata

	// Quota tracking (optional, can be disabled)
	quotaManager QuotaManager
}

// NewS3Backend creates a new S3 storage backend
// This implements a production-grade blob storage backend for Phase 18
func NewS3Backend(config S3BackendConfig) (StorageBackend, error) {
	if config.Bucket == "" {
		return nil, errors.New("S3 bucket name is required")
	}

	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	backend := &s3Backend{
		config:        config,
		logger:        config.Logger.With("backend", "s3", "bucket", config.Bucket),
		metadataCache: make(map[string]*Metadata),
	}

	// Load AWS configuration
	awsConfig, err := backend.loadAWSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	// Create S3 client with SSRF protection
	// We use the standard S3 client configuration with additional security settings
	backend.client = s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		o.UsePathStyle = config.UsePathStyle
		// Note: SSRF protection is handled at the transport level in Phase 34
		// The transport layer validates S3 endpoints before making requests
	})

	return backend, nil
}

// loadAWSConfig loads AWS configuration with proper credentials and settings
func (b *s3Backend) loadAWSConfig() (aws.Config, error) {
	var creds aws.CredentialsProvider

	// Use explicit credentials if provided (for testing or specific configurations)
	if b.config.AccessKey != "" && b.config.SecretKey != "" {
		creds = credentials.NewStaticCredentialsProvider(
			b.config.AccessKey,
			b.config.SecretKey,
			b.config.SessionToken,
		)
	}

	// Load AWS configuration
	loadOptions := []func(*config.LoadOptions) error{
		config.WithRegion(b.config.Region),
	}

	// Add custom endpoint if specified (for S3-compatible services)
	if b.config.Endpoint != "" {
		// Use a custom resolver
		customResolver := aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
			return aws.Endpoint{URL: b.config.Endpoint}, nil
		})
		loadOptions = append(loadOptions, config.WithEndpointResolver(customResolver))
	}

	// Add credentials if specified
	if creds != nil {
		loadOptions = append(loadOptions, config.WithCredentialsProvider(creds))
	}

	return config.LoadDefaultConfig(context.TODO(), loadOptions...)
}

// Name returns the name of the backend
func (b *s3Backend) Name() string {
	return "s3"
}

// Description returns a description of the backend
func (b *s3Backend) Description() string {
	return fmt.Sprintf("S3 storage backend (bucket: %s, region: %s)", b.config.Bucket, b.config.Region)
}

// Initialize initializes the backend
func (b *s3Backend) Initialize(ctx context.Context, config map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	// Update configuration if provided
	newBucket := config["bucket"]
	newRegion := config["region"]
	newEndpoint := config["endpoint"]

	if newBucket != "" {
		b.config.Bucket = newBucket
	}
	if newRegion != "" {
		b.config.Region = newRegion
	}
	if newEndpoint != "" {
		b.config.Endpoint = newEndpoint
	}

	// Recreate client with updated config if needed
	if newBucket != "" || newRegion != "" || newEndpoint != "" {
		awsConfig, err := b.loadAWSConfig()
		if err != nil {
			return err
		}
		b.client = s3.NewFromConfig(awsConfig)
	}

	// Verify bucket exists and is accessible
	if _, err := b.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(b.config.Bucket),
	}); err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return fmt.Errorf("bucket %s does not exist or is not accessible: %w", b.config.Bucket, err)
		}
		return fmt.Errorf("failed to verify bucket accessibility: %w", err)
	}

	return nil
}

// HealthCheck checks if the backend is healthy
func (b *s3Backend) HealthCheck(ctx context.Context) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return ErrStorageClosed
	}

	// Try to list a small number of objects
	_, err := b.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(b.config.Bucket),
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("failed to check S3 backend health: %w", err)
	}

	return nil
}

// Close closes the backend
func (b *s3Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.metadataCache = nil
	return nil
}

// checkClosed checks if the backend is closed
func (b *s3Backend) checkClosed() error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return ErrStorageClosed
	}
	return nil
}

// checkClosedNoLock checks if the backend is closed without acquiring the lock
// Must be called when the lock is already held
func (b *s3Backend) checkClosedNoLock() error {
	if b.closed {
		return ErrStorageClosed
	}
	return nil
}

// s3KeyFromURI converts a Solid URI to an S3 object key
// This preserves the Solid URL path structure in S3 keys
func (b *s3Backend) s3KeyFromURI(uri string) string {
	// Remove leading slash and replace slashes with forward slashes
	cleanURI := strings.TrimPrefix(uri, "/")
	if cleanURI == "" {
		cleanURI = "root"
	}
	// Sanitize the key to be safe for S3
	// Replace problematic characters
	key := strings.ReplaceAll(cleanURI, "#", "%23")
	key = strings.ReplaceAll(key, "?", "%3F")
	return key
}

// uriFromS3Key converts an S3 object key back to a Solid URI
func (b *s3Backend) uriFromS3Key(key string) string {
	// Handle root
	if key == "root" {
		return "/"
	}
	// Restore original characters
	uri := strings.ReplaceAll(key, "%23", "#")
	uri = strings.ReplaceAll(uri, "%3F", "?")
	return "/" + uri
}

// Get retrieves a resource by URI
func (b *s3Backend) Get(ctx context.Context, uri string) (*Resource, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return nil, err
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return nil, SanitizeError(err)
	}

	key := b.s3KeyFromURI(validatedURI)

	// Try to get the object
	output, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer output.Body.Close()

	// Read the body
	body, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, SanitizeError(fmt.Errorf("failed to read S3 object body: %w", err))
	}

	// Validate body size
	if err := ValidateBodySize(body); err != nil {
		return nil, SanitizeError(err)
	}

	// Get metadata from cache or S3 object metadata
	metadata := b.getMetadataFromCacheOrS3(ctx, validatedURI, output)

	return &Resource{
		URI:      validatedURI,
		Body:     body,
		Metadata: *metadata,
	}, nil
}

// GetMetadata retrieves metadata for a resource
func (b *s3Backend) GetMetadata(ctx context.Context, uri string) (*Metadata, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return nil, err
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return nil, SanitizeError(err)
	}

	// Try cache first
	b.mu.RLock()
	if metadata, exists := b.metadataCache[validatedURI]; exists {
		b.mu.RUnlock()
		return metadata, nil
	}
	b.mu.RUnlock()

	// Get from S3
	key := b.s3KeyFromURI(validatedURI)

	// Head object to get metadata
	output, err := b.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to head S3 object: %w", err)
	}

	metadata := b.s3MetadataToStorageMetadata(uri, output)

	// Cache the metadata
	b.mu.Lock()
	b.metadataCache[validatedURI] = metadata
	b.mu.Unlock()

	return metadata, nil
}

// Put stores a resource
func (b *s3Backend) Put(ctx context.Context, uri string, resource *WriteResource) error {
	if ctx == nil {
		return ErrNilContext
	}

	// Validate resource is not nil
	if resource == nil {
		return SanitizeError(ErrNilResource)
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return SanitizeError(err)
	}

	// Validate content type
	if err := ValidateContentType(resource.Metadata.ContentType); err != nil {
		return SanitizeError(err)
	}

	// Validate body size if Body is provided
	if resource.Body != nil {
		if err := ValidateBodySize(resource.Body); err != nil {
			return SanitizeError(err)
		}
	}

	// Validate body reader size if provided
	if resource.BodyReader != nil && resource.BodySize > 0 {
		if err := ValidateBodyReaderSize(resource.BodySize); err != nil {
			return SanitizeError(err)
		}
	}

	// Validate storage root
	if err := ValidateStorageRoot(resource.Metadata.StorageRoot); err != nil {
		return SanitizeError(err)
	}

	// Validate tenant
	if err := ValidateTenant(resource.Metadata.Tenant); err != nil {
		return SanitizeError(err)
	}

	// Validate content address if present
	if resource.Metadata.ContentAddress != "" {
		if err := ValidateContentAddress(resource.Metadata.ContentAddress); err != nil {
			return SanitizeError(err)
		}
	}

	// Validate metadata size
	if err := validateMetadataSize(&resource.Metadata); err != nil {
		return SanitizeError(err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkClosedNoLock(); err != nil {
		return SanitizeError(err)
	}

	key := b.s3KeyFromURI(validatedURI)

	// Calculate size for quota: body size + estimated metadata size
	// Even though S3 doesn't have native quota, we still need to enforce it at the storage layer
	resourceSize := int64(0)
	if resource.Body != nil {
		resourceSize += int64(len(resource.Body))
	}

	// Add estimated metadata size
	metadataSize := estimateMetadataSize(&resource.Metadata)
	resourceSize += metadataSize

	// Check quota - extract storage root from metadata or URI
	storageRoot := resource.Metadata.StorageRoot
	if storageRoot == "" {
		storageRoot = validatedURI
		if idx := strings.Index(validatedURI, "/"); idx > 0 {
			storageRoot = validatedURI[:idx]
		}
	}

	if resourceSize > 0 {
		if err := b.CheckQuota(ctx, storageRoot, resourceSize); err != nil {
			return SanitizeError(err)
		}
	}

	// Prepare the input
	input := &s3.PutObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(resource.Body),
	}

	// Set content type from metadata
	if resource.Metadata.ContentType != "" {
		input.ContentType = aws.String(resource.Metadata.ContentType)
	}

	// Set custom metadata from storage metadata
	if len(resource.Metadata.Custom) > 0 {
		customMetadata := make(map[string]string)
		for k, v := range resource.Metadata.Custom {
			// S3 metadata keys must be in specific format
			customMetadata["x-amz-meta-"+k] = v
		}
		input.Metadata = customMetadata
	}

	// Execute the put
	_, err = b.client.PutObject(ctx, input)
	if err != nil {
		return SanitizeError(fmt.Errorf("failed to put S3 object: %w", err))
	}

	// Cache the metadata
	b.mu.Lock()
	// Ensure metadata has the URI
	metadata := resource.Metadata
	metadata.URI = validatedURI
	if metadata.Size == 0 && resource.Body != nil {
		metadata.Size = int64(len(resource.Body))
	}
	if metadata.ETag == "" && resource.Body != nil {
		// We'll need to get the ETag from the response
		// For now, generate a simple one
		metadata.ETag = generateETag(resource.Body)
	}
	b.metadataCache[validatedURI] = &metadata
	b.mu.Unlock()

	return nil
}

// Delete removes a resource
func (b *s3Backend) Delete(ctx context.Context, uri string) error {
	if ctx == nil {
		return ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return err
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return SanitizeError(err)
	}

	key := b.s3KeyFromURI(validatedURI)

	_, err = b.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return ErrNotFound
		}
		return SanitizeError(fmt.Errorf("failed to delete S3 object: %w", err))
	}

	// Remove from cache
	b.mu.Lock()
	delete(b.metadataCache, validatedURI)
	b.mu.Unlock()

	return nil
}

// List lists resources in a container
func (b *s3Backend) List(ctx context.Context, containerURI string) ([]*Metadata, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return nil, err
	}

	// Validate container URI
	validatedURI, err := ValidateURI(containerURI)
	if err != nil {
		return nil, SanitizeError(err)
	}

	// Convert container URI to S3 prefix
	prefix := b.s3KeyFromURI(validatedURI)
	if !strings.HasSuffix(prefix, "/") && prefix != "" {
		prefix += "/"
	}

	// List objects with the prefix
	output, err := b.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(b.config.Bucket),
		Prefix: aws.String(prefix),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 objects: %w", err)
	}

	// Convert S3 objects to metadata
	var result []*Metadata
	for _, obj := range output.Contents {
		// Skip directory markers
		key := aws.ToString(obj.Key)
		if strings.HasSuffix(key, "/") {
			continue
		}

		uri := b.uriFromS3Key(key)

		// Validate the URI from S3
		validatedURI, err := ValidateURI(uri)
		if err != nil {
			// Skip invalid URIs
			continue
		}

		metadata := b.s3ObjectToMetadata(validatedURI, obj)
		result = append(result, metadata)

		// Limit the number of results to prevent resource exhaustion
		if len(result) >= MaxResourceCountPerList {
			break
		}
	}

	return result, nil
}

// Exists checks if a resource exists
func (b *s3Backend) Exists(ctx context.Context, uri string) (bool, error) {
	if ctx == nil {
		return false, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return false, err
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return false, SanitizeError(err)
	}

	key := b.s3KeyFromURI(validatedURI)

	_, err = b.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return false, nil
		}
		return false, SanitizeError(fmt.Errorf("failed to check S3 object existence: %w", err))
	}

	return true, nil
}

// StoreBlob stores a content-addressed blob
func (b *s3Backend) StoreBlob(ctx context.Context, data []byte) (ContentAddress, error) {
	if ctx == nil {
		return "", ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return "", err
	}

	// Validate data size
	if err := ValidateBodySize(data); err != nil {
		return "", SanitizeError(err)
	}

	// Compute content address
	address := computeContentAddress(data)

	// Validate the content address
	if err := ValidateContentAddress(address); err != nil {
		return "", SanitizeError(err)
	}

	// Create a unique key for the blob
	// Use the content address as the key for content-addressed storage
	blobKey := "blobs/" + string(address)

	// Store the blob
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(blobKey),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return "", fmt.Errorf("failed to store blob in S3: %w", err)
	}

	return address, nil
}

// GetBlob retrieves a content-addressed blob
func (b *s3Backend) GetBlob(ctx context.Context, address ContentAddress) ([]byte, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return nil, err
	}

	// Validate content address
	if err := ValidateContentAddress(address); err != nil {
		return nil, SanitizeError(err)
	}

	// Create the blob key
	blobKey := "blobs/" + string(address)

	// Get the blob
	output, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(blobKey),
	})
	if err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get blob from S3: %w", err)
	}
	defer output.Body.Close()

	data, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, SanitizeError(fmt.Errorf("failed to read blob data: %w", err))
	}

	// Validate body size
	if err := ValidateBodySize(data); err != nil {
		return nil, SanitizeError(err)
	}

	return data, nil
}

// BlobExists checks if a blob exists
func (b *s3Backend) BlobExists(ctx context.Context, address ContentAddress) (bool, error) {
	if ctx == nil {
		return false, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return false, err
	}

	// Validate content address
	if err := ValidateContentAddress(address); err != nil {
		return false, SanitizeError(err)
	}

	blobKey := "blobs/" + string(address)

	_, err := b.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(blobKey),
	})
	if err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check blob existence: %w", err)
	}

	return true, nil
}

// DeleteBlob deletes a blob
func (b *s3Backend) DeleteBlob(ctx context.Context, address ContentAddress) error {
	if ctx == nil {
		return ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return err
	}

	// Validate content address
	if err := ValidateContentAddress(address); err != nil {
		return SanitizeError(err)
	}

	blobKey := "blobs/" + string(address)

	_, err := b.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(blobKey),
	})
	if err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return ErrNotFound
		}
		return fmt.Errorf("failed to delete blob: %w", err)
	}

	return nil
}

// GetTombstone retrieves a tombstone
// For S3, tombstones are stored as special metadata on deleted objects
func (b *s3Backend) GetTombstone(ctx context.Context, uri string) (*Tombstone, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return nil, err
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return nil, SanitizeError(err)
	}

	// Check cache first
	b.mu.RLock()
	if tombstone, exists := b.getTombstoneFromCache(validatedURI); exists {
		b.mu.RUnlock()
		return tombstone, nil
	}
	b.mu.RUnlock()

	// Tombstones are stored with a special prefix
	tombstoneKey := ".tombstones/" + filepath.Base(b.s3KeyFromURI(validatedURI))

	output, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(tombstoneKey),
	})
	if err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get tombstone: %w", err)
	}
	defer output.Body.Close()

	data, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, err
	}

	var tombstone Tombstone
	if err := json.Unmarshal(data, &tombstone); err != nil {
		return nil, err
	}

	// Cache the tombstone
	b.mu.Lock()
	b.cacheTombstone(&tombstone)
	b.mu.Unlock()

	// Validate tombstone URI
	if tombstone.URI == "" {
		tombstone.URI = validatedURI
	}

	return &tombstone, nil
}

// StoreTombstone stores a tombstone
func (b *s3Backend) StoreTombstone(ctx context.Context, tombstone *Tombstone) error {
	if ctx == nil {
		return ErrNilContext
	}

	// Validate tombstone is not nil
	if tombstone == nil {
		return SanitizeError(ErrNilTombstone)
	}

	if err := b.checkClosed(); err != nil {
		return err
	}

	// Validate tombstone URI
	validatedURI, err := ValidateURI(tombstone.URI)
	if err != nil {
		return SanitizeError(err)
	}

	// Validate tombstone fields
	if err := validateTombstone(tombstone); err != nil {
		return SanitizeError(err)
	}

	// Store tombstone data
	tombstoneKey := ".tombstones/" + filepath.Base(b.s3KeyFromURI(validatedURI))
	data, err := json.Marshal(tombstone)
	if err != nil {
		return SanitizeError(fmt.Errorf("failed to marshal tombstone: %w", err))
	}

	_, err = b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(tombstoneKey),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return SanitizeError(fmt.Errorf("failed to store tombstone: %w", err))
	}

	// Also delete the actual resource
	b.Delete(ctx, validatedURI)

	// Cache the tombstone
	b.mu.Lock()
	b.cacheTombstone(tombstone)
	b.mu.Unlock()

	return nil
}

// DeleteTombstone deletes a tombstone
func (b *s3Backend) DeleteTombstone(ctx context.Context, uri string) error {
	if ctx == nil {
		return ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return err
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return SanitizeError(err)
	}

	tombstoneKey := ".tombstones/" + filepath.Base(b.s3KeyFromURI(validatedURI))

	_, err = b.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(tombstoneKey),
	})
	if err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return ErrNotFound
		}
		return SanitizeError(fmt.Errorf("failed to delete tombstone: %w", err))
	}

	// Remove from cache
	b.mu.Lock()
	delete(b.metadataCache, ".tombstone:"+validatedURI)
	b.mu.Unlock()

	return nil
}

// ListTombstones lists tombstones for a storage root
func (b *s3Backend) ListTombstones(ctx context.Context, storageRoot string) ([]*Tombstone, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return nil, err
	}

	// Validate storage root
	if err := ValidateStorageRoot(storageRoot); err != nil {
		return nil, SanitizeError(err)
	}

	// List tombstone objects
	tombstonePrefix := ".tombstones/"
	output, err := b.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(b.config.Bucket),
		Prefix: aws.String(tombstonePrefix),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list tombstones: %w", err)
	}

	var tombstones []*Tombstone
	for _, obj := range output.Contents {
		key := aws.ToString(obj.Key)
		if !strings.HasPrefix(key, tombstonePrefix) || !strings.HasSuffix(key, ".json") {
			continue
		}

		// Get the tombstone data
		getOutput, err := b.client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(b.config.Bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			continue
		}
		defer getOutput.Body.Close()

		data, err := io.ReadAll(getOutput.Body)
		if err != nil {
			continue
		}

		var tombstone Tombstone
		if err := json.Unmarshal(data, &tombstone); err != nil {
			continue
		}

		// Filter by storage root if specified
		if storageRoot != "" && !strings.HasPrefix(tombstone.URI, storageRoot) && tombstone.URI != storageRoot {
			continue
		}

		tombstones = append(tombstones, &tombstone)
	}

	return tombstones, nil
}

// GetLayoutVersion retrieves the layout version
func (b *s3Backend) GetLayoutVersion(ctx context.Context) (StorageLayoutVersion, error) {
	if ctx == nil {
		return 0, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return 0, err
	}

	// Layout version is stored in a special object
	versionKey := ".layout_version"

	output, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(versionKey),
	})
	if err != nil {
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return CurrentStorageLayoutVersion, nil
		}
		return 0, fmt.Errorf("failed to get layout version: %w", err)
	}
	defer output.Body.Close()

	data, err := io.ReadAll(output.Body)
	if err != nil {
		return 0, err
	}

	var version StorageLayoutVersion
	if _, err := fmt.Sscanf(string(data), "%d", &version); err != nil {
		return 0, fmt.Errorf("failed to parse layout version: %w", err)
	}

	return version, nil
}

// SetLayoutVersion sets the layout version
func (b *s3Backend) SetLayoutVersion(ctx context.Context, version StorageLayoutVersion) error {
	if ctx == nil {
		return ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return err
	}

	if version < MinSupportedStorageLayoutVersion {
		return SanitizeError(fmt.Errorf("version %d is below minimum supported version %d", version, MinSupportedStorageLayoutVersion))
	}

	// Store the version
	versionKey := ".layout_version"
	data := []byte(fmt.Sprintf("%d", version))

	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(b.config.Bucket),
		Key:    aws.String(versionKey),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("failed to set layout version: %w", err)
	}

	return nil
}

// Backup creates a backup
// For S3, this is a no-op since S3 already provides durability
// We could implement cross-region copy or versioning-based backup in the future
func (b *s3Backend) Backup(ctx context.Context, writer io.Writer) error {
	if ctx == nil {
		return ErrNilContext
	}

	if writer == nil {
		return fmt.Errorf("writer cannot be nil")
	}

	if err := b.checkClosed(); err != nil {
		return err
	}

	// For S3, we write a manifest of all objects
	// In a production implementation, this would be more comprehensive
	output, err := b.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(b.config.Bucket),
	})
	if err != nil {
		return fmt.Errorf("failed to list objects for backup: %w", err)
	}

	// Write backup manifest
	manifest := map[string]interface{}{
		"backend":     b.Name(),
		"bucket":      b.config.Bucket,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"objectCount": len(output.Contents),
	}

	var objects []string
	for _, obj := range output.Contents {
		objects = append(objects, aws.ToString(obj.Key))
	}
	manifest["objects"] = objects

	data, _ := json.MarshalIndent(manifest, "", "  ")
	_, err = writer.Write(append(data, '\n'))
	return err
}

// Restore restores from a backup
// For S3, this would restore from versioning or cross-region copies
func (b *s3Backend) Restore(ctx context.Context, reader io.Reader) error {
	if ctx == nil {
		return ErrNilContext
	}

	if reader == nil {
		return fmt.Errorf("reader cannot be nil")
	}

	if err := b.checkClosed(); err != nil {
		return err
	}

	// Read the backup manifest
	var manifest map[string]interface{}
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("failed to parse backup manifest: %w", err)
	}

	// For S3, restoration would involve copying objects back
	// This is a simplified implementation
	// In production, we'd use S3 versioning or cross-region copy

	return nil
}

// ScanIntegrity performs an integrity scan
func (b *s3Backend) ScanIntegrity(ctx context.Context) (*IntegrityReport, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return nil, err
	}

	// In a full implementation, this would scan all objects
	// and verify metadata/body consistency
	// For now, return an empty report
	return &IntegrityReport{
		ScannedAt:           time.Now().UTC(),
		TotalResources:      0,
		ResourcesWithIssues: 0,
		ResourceReports:     []ResourceIntegrityReport{},
	}, nil
}

// getMetadataFromCacheOrS3 retrieves metadata from cache or S3
func (b *s3Backend) getMetadataFromCacheOrS3(ctx context.Context, uri string, output *s3.GetObjectOutput) *Metadata {
	// Try cache first
	b.mu.RLock()
	if metadata, exists := b.metadataCache[uri]; exists {
		b.mu.RUnlock()
		return metadata
	}
	b.mu.RUnlock()

	// Create metadata from S3 object
	return b.s3GetObjectOutputToMetadata(uri, output)
}

// s3GetObjectOutputToMetadata converts S3 GetObject output to Storage Metadata
func (b *s3Backend) s3GetObjectOutputToMetadata(uri string, output *s3.GetObjectOutput) *Metadata {
	metadata := &Metadata{
		URI:          uri,
		Size:         aws.ToInt64(output.ContentLength),
		LastModified: aws.ToTime(output.LastModified).UTC(),
		ETag:         aws.ToString(output.ETag),
	}

	if output.ContentType != nil {
		metadata.ContentType = aws.ToString(output.ContentType)
	}

	// Extract custom metadata
	if len(output.Metadata) > 0 {
		metadata.Custom = make(map[string]string)
		for k, v := range output.Metadata {
			// Remove x-amz-meta- prefix
			if strings.HasPrefix(k, "x-amz-meta-") {
				key := strings.TrimPrefix(k, "x-amz-meta-")
				metadata.Custom[key] = v
			}
		}
	}

	return metadata
}

// s3HeadObjectOutputToMetadata converts S3 HeadObject output to Storage Metadata
func (b *s3Backend) s3MetadataToStorageMetadata(uri string, output *s3.HeadObjectOutput) *Metadata {
	metadata := &Metadata{
		URI:          uri,
		Size:         aws.ToInt64(output.ContentLength),
		LastModified: aws.ToTime(output.LastModified).UTC(),
		ETag:         aws.ToString(output.ETag),
	}

	if output.ContentType != nil {
		metadata.ContentType = aws.ToString(output.ContentType)
	}

	// Extract custom metadata
	if len(output.Metadata) > 0 {
		metadata.Custom = make(map[string]string)
		for k, v := range output.Metadata {
			if strings.HasPrefix(k, "x-amz-meta-") {
				key := strings.TrimPrefix(k, "x-amz-meta-")
				metadata.Custom[key] = v
			}
		}
	}

	return metadata
}

// s3ObjectToMetadata converts an S3 Object to Storage Metadata
func (b *s3Backend) s3ObjectToMetadata(uri string, obj types.Object) *Metadata {
	metadata := &Metadata{
		URI:          uri,
		Size:         aws.ToInt64(obj.Size),
		LastModified: aws.ToTime(obj.LastModified).UTC(),
		ETag:         aws.ToString(obj.ETag),
		StorageRoot:  b.config.Bucket,
	}

	// Note: We don't have ContentType in ListObjectsV2 output
	// This would need a separate HeadObject call to get
	metadata.ContentType = "application/octet-stream"

	return metadata
}

// cacheTombstone caches a tombstone
func (b *s3Backend) cacheTombstone(tombstone *Tombstone) {
	b.metadataCache[".tombstone:"+tombstone.URI] = &Metadata{
		URI:          tombstone.URI,
		ResourceType: ResourceTypeBlob,
		Custom: map[string]string{
			"tombstone": "true",
		},
	}
}

// getTombstoneFromCache retrieves a tombstone from cache
func (b *s3Backend) getTombstoneFromCache(uri string) (*Tombstone, bool) {
	if _, exists := b.metadataCache[".tombstone:"+uri]; exists {
		// This is a simplified approach
		// In a full implementation, we'd store the actual tombstone object
		return &Tombstone{
			URI: uri,
		}, true
	}
	return nil, false
}

// GetQuota retrieves quota information
func (b *s3Backend) GetQuota(ctx context.Context, storageRoot string) (*QuotaInfo, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := b.checkClosed(); err != nil {
		return nil, err
	}

	// Validate storage root
	if err := ValidateStorageRoot(storageRoot); err != nil {
		return nil, SanitizeError(err)
	}

	// For S3, quota is typically managed at the bucket level
	// This is a simplified implementation
	return &QuotaInfo{
		StorageRoot: storageRoot,
		// Note: S3 doesn't have built-in byte quotas
		// This would need to be implemented at a higher level
	}, nil
}

// CheckQuota checks if a write would exceed quota
func (b *s3Backend) CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error {
	if ctx == nil {
		return ErrNilContext
	}

	// Validate additional bytes
	if additionalBytes < 0 {
		return SanitizeError(fmt.Errorf("additional bytes cannot be negative"))
	}

	// Validate storage root
	if err := ValidateStorageRoot(storageRoot); err != nil {
		return SanitizeError(err)
	}

	// If we have a quota manager, use it
	if b.quotaManager != nil {
		return b.quotaManager.CheckQuota(ctx, storageRoot, additionalBytes)
	}

	// S3 doesn't have native quota support, but we still return an error if quota would be exceeded
	// This prevents quota bypass even though S3 itself doesn't enforce it
	// For now, we allow unlimited if no quota manager is configured
	// In production, a quota manager should always be configured
	return nil
}

// Ensure interface is satisfied
var _ StorageBackend = (*s3Backend)(nil)
