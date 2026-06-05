package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

func AuditForRequest(request Request) AuditFields {
	return AuditFields{
		RequestHash: sha256Hex(canonicalRequest(request)),
		PolicyHash:  sha256Hex(canonicalPolicyDocuments(request.PolicyDocuments)),
	}
}

func canonicalRequest(request Request) string {
	var output strings.Builder
	pushField(&output, "schema_version", request.SchemaVersion)
	pushField(&output, "request_id", request.RequestID)
	pushField(&output, "method", request.Method)
	pushField(&output, "resource_uri", request.ResourceURI)
	pushOptionalField(&output, "agent_webid", request.AgentWebID)
	pushOptionalField(&output, "client_id", request.ClientID)
	pushOptionalField(&output, "issuer", request.Issuer)
	pushOptionalField(&output, "origin", request.Origin)
	pushModes(&output, request.RequestedModes)
	pushOptionalField(&output, "resource_version", request.ResourceVersion)
	pushOptionalField(&output, "policy_version", request.PolicyVersion)

	metadataKeys := make([]string, 0, len(request.ResourceMetadata))
	for key := range request.ResourceMetadata {
		metadataKeys = append(metadataKeys, key)
	}
	sort.Strings(metadataKeys)
	for _, key := range metadataKeys {
		pushField(&output, "resource_metadata_key", key)
		pushField(&output, "resource_metadata_value", request.ResourceMetadata[key])
	}

	pushField(&output, "now_unix", strconv.FormatInt(request.NowUnix, 10))
	return output.String()
}

func canonicalPolicyDocuments(policyDocuments []PolicyDocument) string {
	sorted := append([]PolicyDocument(nil), policyDocuments...)
	sort.Slice(sorted, func(i, j int) bool {
		left := sorted[i]
		right := sorted[j]
		if left.URI != right.URI {
			return left.URI < right.URI
		}
		if left.SHA256 != right.SHA256 {
			return left.SHA256 < right.SHA256
		}
		return left.ContentType < right.ContentType
	})

	var output strings.Builder
	for _, policyDocument := range sorted {
		pushField(&output, "policy_uri", policyDocument.URI)
		pushField(&output, "policy_sha256", policyDocument.SHA256)
		pushField(&output, "policy_content_type", policyDocument.ContentType)
	}
	return output.String()
}

func pushOptionalField(output *strings.Builder, name, value string) {
	if value != "" {
		pushField(output, name, value)
	}
}

func pushModes(output *strings.Builder, modes []AccessMode) {
	sorted := append([]AccessMode(nil), modes...)
	sort.Slice(sorted, func(i, j int) bool {
		return accessModeRank(sorted[i]) < accessModeRank(sorted[j])
	})
	for _, mode := range sorted {
		pushField(output, "requested_mode", string(mode))
	}
}

func accessModeRank(mode AccessMode) int {
	switch mode {
	case AccessModeRead:
		return 0
	case AccessModeAppend:
		return 1
	case AccessModeWrite:
		return 2
	case AccessModeControl:
		return 3
	default:
		return 99
	}
}

func pushField(output *strings.Builder, name, value string) {
	output.WriteString(name)
	output.WriteRune('\u001f')
	output.WriteString(value)
	output.WriteRune('\u001e')
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
