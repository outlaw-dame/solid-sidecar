package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// ErrContainerURI indicates the supplied container URI is not a Solid-style container URI.
	ErrContainerURI = errors.New("invalid container URI")
	// ErrContainerMembershipConflict indicates an atomic container mutation could not proceed safely.
	ErrContainerMembershipConflict = errors.New("container membership conflict")
)

// ContainerOperationService coordinates resource creation/deletion with container membership checks.
// It intentionally uses only the existing StorageBackend API so it can be reviewed independently
// from PR #5's conditional-write/OCC storage work.
type ContainerOperationService struct {
	storage *StorageAbstractionLayer
	locks   [256]sync.Mutex
}

// NewContainerOperationService creates a container operation coordinator.
func NewContainerOperationService(storage *StorageAbstractionLayer) *ContainerOperationService {
	return &ContainerOperationService{storage: storage}
}

// CreateResource creates a resource under a container while holding a per-container lock.
// This prevents duplicate creates and keeps membership visibility deterministic for the
// existing in-process runtime. Distributed/cluster-wide atomicity belongs in later phases.
func (s *ContainerOperationService) CreateResource(ctx context.Context, containerURI string, resourceName string, resource *StorageResource) (*StorageResource, error) {
	if s == nil || s.storage == nil {
		return nil, errors.New("container operation service requires storage")
	}
	containerURI, err := NormalizeContainerURI(containerURI)
	if err != nil {
		return nil, err
	}
	if err := ValidateResourceName(resourceName); err != nil {
		return nil, err
	}
	if resource == nil {
		return nil, errors.New("resource must not be nil")
	}
	lock := s.lockFor(containerURI)
	lock.Lock()
	defer lock.Unlock()

	resourceURI := JoinContainerResourceURI(containerURI, resourceName)
	exists, err := s.storage.Exists(ctx, resourceURI)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, &HTTPError{StatusCode: http.StatusConflict, Message: "resource already exists"}
	}

	stored := copyContainerResource(resource)
	stored.URI = resourceURI
	if stored.ContentType == "" && stored.Metadata.ContentType != "" {
		stored.ContentType = stored.Metadata.ContentType
	}
	if stored.Metadata.ContentType == "" {
		stored.Metadata.ContentType = stored.ContentType
	}
	stored.Metadata.Size = int64(len(stored.Body))
	now := time.Now().UTC()
	if stored.Metadata.Created.IsZero() {
		stored.Metadata.Created = now
	}
	stored.Metadata.LastModified = now
	stored.LastModified = now

	if err := s.storage.Put(ctx, resourceURI, stored); err != nil {
		return nil, err
	}
	created, err := s.storage.Get(ctx, resourceURI)
	if err != nil {
		return nil, err
	}
	return created, nil
}

// DeleteResource deletes a resource under a container while holding the same per-container lock.
func (s *ContainerOperationService) DeleteResource(ctx context.Context, resourceURI string) error {
	if s == nil || s.storage == nil {
		return errors.New("container operation service requires storage")
	}
	if err := ValidateURI(resourceURI); err != nil {
		return fmt.Errorf("invalid resource URI: %w", err)
	}
	containerURI, err := ParentContainerURI(resourceURI)
	if err != nil {
		return err
	}
	lock := s.lockFor(containerURI)
	lock.Lock()
	defer lock.Unlock()

	exists, err := s.storage.Exists(ctx, resourceURI)
	if err != nil {
		return err
	}
	if !exists {
		return &HTTPError{StatusCode: http.StatusNotFound, Message: "resource not found"}
	}
	return s.storage.Delete(ctx, resourceURI)
}

// ListMembers returns stable, de-duplicated direct container members.
func (s *ContainerOperationService) ListMembers(ctx context.Context, containerURI string) ([]*StorageResource, error) {
	if s == nil || s.storage == nil {
		return nil, errors.New("container operation service requires storage")
	}
	containerURI, err := NormalizeContainerURI(containerURI)
	if err != nil {
		return nil, err
	}
	members, err := s.storage.List(ctx, containerURI)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]*StorageResource, len(members))
	for _, member := range members {
		if member == nil || member.URI == containerURI || !IsDirectContainerMember(containerURI, member.URI) {
			continue
		}
		seen[member.URI] = copyContainerResource(member)
	}
	uris := make([]string, 0, len(seen))
	for uri := range seen {
		uris = append(uris, uri)
	}
	sort.Strings(uris)
	ordered := make([]*StorageResource, 0, len(uris))
	for _, uri := range uris {
		ordered = append(ordered, seen[uri])
	}
	return ordered, nil
}

func (s *ContainerOperationService) lockFor(containerURI string) *sync.Mutex {
	var h uint32 = 2166136261
	for i := 0; i < len(containerURI); i++ {
		h ^= uint32(containerURI[i])
		h *= 16777619
	}
	return &s.locks[h%uint32(len(s.locks))]
}

// NormalizeContainerURI validates and normalizes a container URI to trailing-slash form.
func NormalizeContainerURI(containerURI string) (string, error) {
	if err := ValidateURI(containerURI); err != nil {
		return "", fmt.Errorf("%w: %v", ErrContainerURI, err)
	}
	parsed, err := url.Parse(containerURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%w: container URI must be absolute", ErrContainerURI)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: container URI must not include query or fragment", ErrContainerURI)
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	return parsed.String(), nil
}

// ValidateResourceName rejects unsafe names for atomic container creation.
func ValidateResourceName(resourceName string) error {
	if resourceName == "" {
		return fmt.Errorf("%w: resource name is empty", ErrContainerMembershipConflict)
	}
	if strings.Contains(resourceName, "/") || strings.Contains(resourceName, "\\") {
		return fmt.Errorf("%w: resource name must not contain path separators", ErrContainerMembershipConflict)
	}
	for _, r := range resourceName {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: resource name contains control characters or is unsafe", ErrContainerMembershipConflict)
		}
	}
	if resourceName == "." || resourceName == ".." {
		return fmt.Errorf("%w: resource name is unsafe", ErrContainerMembershipConflict)
	}
	if _, err := url.PathUnescape(resourceName); err != nil {
		return fmt.Errorf("%w: resource name is not valid URL path data", ErrContainerMembershipConflict)
	}
	return nil
}

// JoinContainerResourceURI joins a normalized container URI with a single resource name.
func JoinContainerResourceURI(containerURI string, resourceName string) string {
	return strings.TrimRight(containerURI, "/") + "/" + url.PathEscape(resourceName)
}

// ParentContainerURI returns the immediate parent container URI for a resource URI.
func ParentContainerURI(resourceURI string) (string, error) {
	if err := ValidateURI(resourceURI); err != nil {
		return "", fmt.Errorf("invalid resource URI: %w", err)
	}
	parsed, err := url.Parse(resourceURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", ErrContainerURI
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: resource URI must not include query or fragment", ErrContainerURI)
	}
	path := parsed.Path
	if path == "" || path == "/" {
		return "", fmt.Errorf("%w: root has no parent container", ErrContainerURI)
	}
	path = strings.TrimRight(path, "/")
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		parsed.Path = "/"
	} else {
		parsed.Path = path[:idx+1]
	}
	return NormalizeContainerURI(parsed.String())
}

// IsDirectContainerMember returns true when resourceURI is an immediate child of containerURI.
func IsDirectContainerMember(containerURI string, resourceURI string) bool {
	containerURI, err := NormalizeContainerURI(containerURI)
	if err != nil || ValidateURI(resourceURI) != nil {
		return false
	}
	if !strings.HasPrefix(resourceURI, containerURI) || resourceURI == containerURI {
		return false
	}
	remainder := strings.TrimPrefix(resourceURI, containerURI)
	return remainder != "" && !strings.Contains(strings.TrimSuffix(remainder, "/"), "/")
}

func copyContainerResource(resource *StorageResource) *StorageResource {
	if resource == nil {
		return nil
	}
	metadata := resource.Metadata
	if resource.Metadata.Custom != nil {
		metadata.Custom = make(map[string]string, len(resource.Metadata.Custom))
		for key, value := range resource.Metadata.Custom {
			metadata.Custom[key] = value
		}
	}
	return &StorageResource{
		URI:          resource.URI,
		ContentType:  resource.ContentType,
		Body:         append([]byte(nil), resource.Body...),
		Metadata:     metadata,
		ETag:         resource.ETag,
		LastModified: resource.LastModified,
	}
}
