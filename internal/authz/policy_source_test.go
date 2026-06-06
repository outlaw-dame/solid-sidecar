package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizePolicySourcesSortsAndDeduplicates(t *testing.T) {
	input := []PolicySource{
		{URI: " https://pod.example/policies/z.acl ", Kind: PolicySourceLink, Priority: 20, ContentType: "TEXT/TURTLE; Charset=utf-8"},
		{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"},
		{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"},
	}

	got, err := NormalizePolicySources(input)
	if err != nil {
		t.Fatalf("NormalizePolicySources returned error: %v", err)
	}
	want := []PolicySource{
		{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"},
		{URI: "https://pod.example/policies/z.acl", Kind: PolicySourceLink, Priority: 20, ContentType: "text/turtle;charset=utf-8"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sources = %#v, want %#v", got, want)
	}
}

func TestNormalizePolicySourcesRejectsConflictingDuplicateURI(t *testing.T) {
	_, err := NormalizePolicySources([]PolicySource{
		{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 0, ContentType: "text/turtle"},
		{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceLink, Priority: 0, ContentType: "text/turtle"},
	})
	if !errors.Is(err, ErrInvalidPolicySource) {
		t.Fatalf("error = %v, want ErrInvalidPolicySource", err)
	}
}

func TestNormalizePolicySourcesRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct {
		name   string
		source PolicySource
	}{
		{name: "unsafe uri", source: PolicySource{URI: "https://pod.example/policies/a.acl#frag", Kind: PolicySourceExplicit}},
		{name: "invalid kind", source: PolicySource{URI: "https://pod.example/policies/a.acl", Kind: "unknown"}},
		{name: "negative priority", source: PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: -1}},
		{name: "excessive priority", source: PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10_001}},
		{name: "invalid content type", source: PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, ContentType: "not valid"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizePolicySources([]PolicySource{test.source})
			if !errors.Is(err, ErrInvalidPolicySource) {
				t.Fatalf("error = %v, want ErrInvalidPolicySource", err)
			}
		})
	}
}

func TestPolicyDocumentsFromLoadedSourcesHashesContent(t *testing.T) {
	contentA := []byte("policy a")
	contentB := []byte("policy b")
	got, err := PolicyDocumentsFromLoadedSources([]LoadedPolicySource{
		{Source: PolicySource{URI: "https://pod.example/policies/b.acl", Kind: PolicySourceExplicit, Priority: 20, ContentType: "text/turtle"}, Content: contentB},
		{Source: PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "TEXT/TURTLE"}, Content: contentA},
	})
	if err != nil {
		t.Fatalf("PolicyDocumentsFromLoadedSources returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("document count = %d, want 2", len(got))
	}
	wantHashA := sha256HexForTest(contentA)
	if got[0].URI != "https://pod.example/policies/a.acl" || got[0].SHA256 != wantHashA || got[0].ContentType != "text/turtle" {
		t.Fatalf("first document = %#v", got[0])
	}
}

func TestPolicyDocumentsFromLoadedSourcesRejectsUnsafeInput(t *testing.T) {
	validSource := PolicySource{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, ContentType: "text/turtle"}
	for _, test := range []struct {
		name   string
		loaded LoadedPolicySource
	}{
		{name: "empty content", loaded: LoadedPolicySource{Source: validSource, Content: nil}},
		{name: "missing content type", loaded: LoadedPolicySource{Source: PolicySource{URI: validSource.URI, Kind: validSource.Kind}, Content: []byte("policy")}},
		{name: "invalid source", loaded: LoadedPolicySource{Source: PolicySource{URI: "https://pod.example/policies/a.acl#frag", Kind: PolicySourceExplicit, ContentType: "text/turtle"}, Content: []byte("policy")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := PolicyDocumentsFromLoadedSources([]LoadedPolicySource{test.loaded})
			if !errors.Is(err, ErrInvalidPolicySource) {
				t.Fatalf("error = %v, want ErrInvalidPolicySource", err)
			}
		})
	}

	large := strings.Repeat("x", int(MaxLoadedPolicyDocumentBytes)+1)
	_, err := PolicyDocumentsFromLoadedSources([]LoadedPolicySource{{Source: validSource, Content: []byte(large)}})
	if !errors.Is(err, ErrInvalidPolicySource) {
		t.Fatalf("large content error = %v, want ErrInvalidPolicySource", err)
	}
}

func TestPolicySourceSetVersionIsDeterministic(t *testing.T) {
	left := []PolicySource{
		{URI: "https://pod.example/policies/b.acl", Kind: PolicySourceLink, Priority: 20, ContentType: "text/turtle"},
		{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"},
	}
	right := []PolicySource{
		{URI: "https://pod.example/policies/a.acl", Kind: PolicySourceExplicit, Priority: 10, ContentType: "text/turtle"},
		{URI: "https://pod.example/policies/b.acl", Kind: PolicySourceLink, Priority: 20, ContentType: "text/turtle"},
	}
	if PolicySourceSetVersion(left) == "" {
		t.Fatal("expected source set version")
	}
	if PolicySourceSetVersion(left) != PolicySourceSetVersion(right) {
		t.Fatalf("versions differ: %q vs %q", PolicySourceSetVersion(left), PolicySourceSetVersion(right))
	}
}

func sha256HexForTest(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}
