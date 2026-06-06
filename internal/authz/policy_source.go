package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const MaxLoadedPolicyDocumentBytes = int64(1 << 20) // 1 MiB metadata-prep bound.

var ErrInvalidPolicySource = errors.New("invalid authz policy source")

type PolicySourceKind string

const (
	PolicySourceExplicit PolicySourceKind = "explicit"
	PolicySourceLink     PolicySourceKind = "link"
	PolicySourceDerived  PolicySourceKind = "derived"
)

type PolicySource struct {
	URI         string           `json:"uri"`
	Kind        PolicySourceKind `json:"kind"`
	Priority    int              `json:"priority"`
	ContentType string           `json:"content_type,omitempty"`
}

type LoadedPolicySource struct {
	Source  PolicySource `json:"source"`
	Content []byte       `json:"-"`
}

func NormalizePolicySources(input []PolicySource) ([]PolicySource, error) {
	if len(input) == 0 {
		return nil, nil
	}
	seen := make(map[string]PolicySource, len(input))
	for _, source := range input {
		normalized, err := normalizePolicySource(source)
		if err != nil {
			return nil, err
		}
		if existing, exists := seen[normalized.URI]; exists {
			if existing.Kind != normalized.Kind || existing.Priority != normalized.Priority || existing.ContentType != normalized.ContentType {
				return nil, fmt.Errorf("%w: conflicting policy source metadata for uri", ErrInvalidPolicySource)
			}
			continue
		}
		seen[normalized.URI] = normalized
	}

	out := make([]PolicySource, 0, len(seen))
	for _, source := range seen {
		out = append(out, source)
	}
	sortPolicySources(out)
	return out, nil
}

func normalizePolicySource(input PolicySource) (PolicySource, error) {
	uri := strings.TrimSpace(input.URI)
	if !validResourceURI(uri) {
		return PolicySource{}, fmt.Errorf("%w: invalid policy source uri", ErrInvalidPolicySource)
	}
	kind := input.Kind
	if kind == "" {
		kind = PolicySourceExplicit
	}
	if !validPolicySourceKind(kind) {
		return PolicySource{}, fmt.Errorf("%w: invalid policy source kind", ErrInvalidPolicySource)
	}
	if input.Priority < 0 || input.Priority > 10_000 {
		return PolicySource{}, fmt.Errorf("%w: invalid policy source priority", ErrInvalidPolicySource)
	}
	contentType := strings.TrimSpace(input.ContentType)
	if contentType != "" {
		normalized, err := normalizeContentType(contentType)
		if err != nil {
			return PolicySource{}, fmt.Errorf("%w: invalid policy source content type", ErrInvalidPolicySource)
		}
		contentType = normalized
	}
	return PolicySource{URI: uri, Kind: kind, Priority: input.Priority, ContentType: contentType}, nil
}

func validPolicySourceKind(kind PolicySourceKind) bool {
	switch kind {
	case PolicySourceExplicit, PolicySourceLink, PolicySourceDerived:
		return true
	default:
		return false
	}
}

func sortPolicySources(sources []PolicySource) {
	sort.Slice(sources, func(i, j int) bool {
		left := sources[i]
		right := sources[j]
		if left.Priority != right.Priority {
			return left.Priority < right.Priority
		}
		if left.URI != right.URI {
			return left.URI < right.URI
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.ContentType < right.ContentType
	})
}

func PolicyDocumentsFromLoadedSources(input []LoadedPolicySource) ([]PolicyDocument, error) {
	if len(input) == 0 {
		return nil, nil
	}
	documents := make([]PolicyDocument, 0, len(input))
	for _, loaded := range input {
		source, err := normalizePolicySource(loaded.Source)
		if err != nil {
			return nil, err
		}
		if len(loaded.Content) == 0 {
			return nil, fmt.Errorf("%w: empty loaded policy source content", ErrInvalidPolicySource)
		}
		if int64(len(loaded.Content)) > MaxLoadedPolicyDocumentBytes {
			return nil, fmt.Errorf("%w: loaded policy source content too large", ErrInvalidPolicySource)
		}
		if source.ContentType == "" {
			return nil, fmt.Errorf("%w: loaded policy source content type is required", ErrInvalidPolicySource)
		}
		sum := sha256.Sum256(loaded.Content)
		documents = append(documents, PolicyDocument{
			URI:         source.URI,
			SHA256:      hex.EncodeToString(sum[:]),
			ContentType: source.ContentType,
		})
	}
	return NormalizePolicyDocuments(documents)
}

func PolicySourceSetVersion(input []PolicySource) string {
	normalized, err := NormalizePolicySources(input)
	if err != nil || len(normalized) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, source := range normalized {
		builder.WriteString(source.URI)
		builder.WriteByte('\x1f')
		builder.WriteString(string(source.Kind))
		builder.WriteByte('\x1f')
		builder.WriteString(fmt.Sprintf("%010d", source.Priority))
		builder.WriteByte('\x1f')
		builder.WriteString(source.ContentType)
		builder.WriteByte('\x1e')
	}
	return "sha256:" + sha256Hex(builder.String())
}
