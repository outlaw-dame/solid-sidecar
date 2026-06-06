package authz

import (
	"errors"
	"fmt"
	"mime"
	"sort"
	"strings"
)

var ErrInvalidPolicyInput = errors.New("invalid authz policy input")

func NormalizePolicyDocuments(input []PolicyDocument) ([]PolicyDocument, error) {
	if len(input) == 0 {
		return nil, nil
	}
	seen := make(map[string]PolicyDocument, len(input))
	for _, document := range input {
		normalized, err := normalizePolicyDocument(document)
		if err != nil {
			return nil, err
		}
		if existing, exists := seen[normalized.URI]; exists {
			if existing.SHA256 != normalized.SHA256 || existing.ContentType != normalized.ContentType {
				return nil, fmt.Errorf("%w: conflicting policy document metadata for uri", ErrInvalidPolicyInput)
			}
			continue
		}
		seen[normalized.URI] = normalized
	}

	out := make([]PolicyDocument, 0, len(seen))
	for _, document := range seen {
		out = append(out, document)
	}
	sortPolicyDocuments(out)
	return out, nil
}

func normalizePolicyDocument(input PolicyDocument) (PolicyDocument, error) {
	uri := strings.TrimSpace(input.URI)
	if !validResourceURI(uri) {
		return PolicyDocument{}, fmt.Errorf("%w: invalid policy document uri", ErrInvalidPolicyInput)
	}
	sha := strings.ToLower(strings.TrimSpace(input.SHA256))
	if !validSHA256Hex(sha) {
		return PolicyDocument{}, fmt.Errorf("%w: invalid policy document hash", ErrInvalidPolicyInput)
	}
	contentType, err := normalizeContentType(input.ContentType)
	if err != nil {
		return PolicyDocument{}, err
	}
	return PolicyDocument{URI: uri, SHA256: sha, ContentType: contentType}, nil
}

func normalizeContentType(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: policy document content type is required", ErrInvalidPolicyInput)
	}
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		return "", fmt.Errorf("%w: invalid policy document content type", ErrInvalidPolicyInput)
	}
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	if mediaType == "" || strings.ContainsAny(mediaType, "\u0000\r\n") {
		return "", fmt.Errorf("%w: invalid policy document content type", ErrInvalidPolicyInput)
	}
	if len(params) == 0 {
		return mediaType, nil
	}
	canonicalParams := make(map[string]string, len(params))
	keys := make([]string, 0, len(params))
	for key, value := range params {
		canonicalKey := strings.ToLower(strings.TrimSpace(key))
		if canonicalKey == "" || strings.ContainsAny(canonicalKey, "\u0000\r\n") || containsControlRune(value) {
			return "", fmt.Errorf("%w: invalid policy document content type parameter", ErrInvalidPolicyInput)
		}
		canonicalParams[canonicalKey] = value
		keys = append(keys, canonicalKey)
	}
	sort.Strings(keys)
	parts := []string{mediaType}
	for _, key := range keys {
		parts = append(parts, key+"="+canonicalParams[key])
	}
	return strings.Join(parts, ";"), nil
}

func sortPolicyDocuments(documents []PolicyDocument) {
	sort.Slice(documents, func(i, j int) bool {
		left := documents[i]
		right := documents[j]
		if left.URI != right.URI {
			return left.URI < right.URI
		}
		if left.SHA256 != right.SHA256 {
			return left.SHA256 < right.SHA256
		}
		return left.ContentType < right.ContentType
	})
}

func PolicyVersionForDocuments(documents []PolicyDocument) string {
	normalized, err := NormalizePolicyDocuments(documents)
	if err != nil || len(normalized) == 0 {
		return ""
	}
	return "sha256:" + sha256Hex(canonicalPolicyDocuments(normalized))
}

func NormalizeResourceMetadata(input map[string]string) (map[string]string, error) {
	if len(input) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || len(key) > 128 || containsControlRune(key) {
			return nil, fmt.Errorf("%w: invalid resource metadata key", ErrInvalidPolicyInput)
		}
		if len(value) > 1024 || containsControlRune(value) {
			return nil, fmt.Errorf("%w: invalid resource metadata value", ErrInvalidPolicyInput)
		}
		out[key] = value
	}
	return out, nil
}

func containsControlRune(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
