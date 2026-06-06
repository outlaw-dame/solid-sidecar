package authz

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	policyHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	policyHashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestNormalizePolicyDocumentsSortsAndDeduplicates(t *testing.T) {
	input := []PolicyDocument{
		{URI: " https://pod.example/policies/z.acl ", SHA256: strings.ToUpper(policyHashB), ContentType: "TEXT/TURTLE; Charset=utf-8"},
		{URI: "https://pod.example/policies/a.acl", SHA256: policyHashA, ContentType: "text/turtle"},
		{URI: "https://pod.example/policies/a.acl", SHA256: policyHashA, ContentType: "text/turtle"},
	}

	got, err := NormalizePolicyDocuments(input)
	if err != nil {
		t.Fatalf("NormalizePolicyDocuments returned error: %v", err)
	}
	want := []PolicyDocument{
		{URI: "https://pod.example/policies/a.acl", SHA256: policyHashA, ContentType: "text/turtle"},
		{URI: "https://pod.example/policies/z.acl", SHA256: policyHashB, ContentType: "text/turtle;charset=utf-8"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized documents = %#v, want %#v", got, want)
	}
}

func TestNormalizePolicyDocumentsRejectsConflictingDuplicateURI(t *testing.T) {
	_, err := NormalizePolicyDocuments([]PolicyDocument{
		{URI: "https://pod.example/policies/a.acl", SHA256: policyHashA, ContentType: "text/turtle"},
		{URI: "https://pod.example/policies/a.acl", SHA256: policyHashB, ContentType: "text/turtle"},
	})
	if !errors.Is(err, ErrInvalidPolicyInput) {
		t.Fatalf("error = %v, want ErrInvalidPolicyInput", err)
	}
}

func TestNormalizePolicyDocumentsRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct {
		name     string
		document PolicyDocument
	}{
		{name: "unsafe uri", document: PolicyDocument{URI: "https://pod.example/policies/a.acl#frag", SHA256: policyHashA, ContentType: "text/turtle"}},
		{name: "invalid hash", document: PolicyDocument{URI: "https://pod.example/policies/a.acl", SHA256: "not-a-hash", ContentType: "text/turtle"}},
		{name: "missing content type", document: PolicyDocument{URI: "https://pod.example/policies/a.acl", SHA256: policyHashA}},
		{name: "invalid content type", document: PolicyDocument{URI: "https://pod.example/policies/a.acl", SHA256: policyHashA, ContentType: "not valid"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizePolicyDocuments([]PolicyDocument{test.document})
			if !errors.Is(err, ErrInvalidPolicyInput) {
				t.Fatalf("error = %v, want ErrInvalidPolicyInput", err)
			}
		})
	}
}

func TestPolicyVersionForDocumentsIsDeterministic(t *testing.T) {
	left := []PolicyDocument{
		{URI: "https://pod.example/policies/b.acl", SHA256: policyHashB, ContentType: "text/turtle"},
		{URI: "https://pod.example/policies/a.acl", SHA256: policyHashA, ContentType: "text/turtle"},
	}
	right := []PolicyDocument{
		{URI: "https://pod.example/policies/a.acl", SHA256: policyHashA, ContentType: "text/turtle"},
		{URI: "https://pod.example/policies/b.acl", SHA256: policyHashB, ContentType: "text/turtle"},
	}
	if PolicyVersionForDocuments(left) == "" {
		t.Fatal("expected policy version")
	}
	if PolicyVersionForDocuments(left) != PolicyVersionForDocuments(right) {
		t.Fatalf("policy versions differ: %q vs %q", PolicyVersionForDocuments(left), PolicyVersionForDocuments(right))
	}
}

func TestNormalizeResourceMetadata(t *testing.T) {
	got, err := NormalizeResourceMetadata(map[string]string{
		" etag ":          " abc ",
		"content_length": " 123 ",
	})
	if err != nil {
		t.Fatalf("NormalizeResourceMetadata returned error: %v", err)
	}
	want := map[string]string{"etag": "abc", "content_length": "123"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata = %#v, want %#v", got, want)
	}
}

func TestNormalizeResourceMetadataRejectsUnsafeInput(t *testing.T) {
	for _, test := range []struct {
		name  string
		input map[string]string
	}{
		{name: "empty key", input: map[string]string{" ": "value"}},
		{name: "control key", input: map[string]string{"bad\nkey": "value"}},
		{name: "control value", input: map[string]string{"key": "bad\nvalue"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizeResourceMetadata(test.input)
			if !errors.Is(err, ErrInvalidPolicyInput) {
				t.Fatalf("error = %v, want ErrInvalidPolicyInput", err)
			}
		})
	}
}
