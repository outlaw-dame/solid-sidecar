package authz

import (
	"errors"
	"testing"
)

func TestDiscoverPolicySourcesCombinesExplicitLinkAndDerivedSources(t *testing.T) {
	sources, err := DiscoverPolicySources(PolicyDiscoveryOptions{
		ResourceURI: "https://pod.example/alice/card",
		ExplicitSources: []PolicySource{
			{URI: "https://pod.example/policies/explicit.acl", ContentType: "TEXT/TURTLE"},
		},
		LinkHeaders: []string{
			`<../policies/from-link.acl>; rel="acl"; type="text/turtle", <ignored>; rel="preview"`,
		},
		AllowedLinkRels:   []string{"acl"},
		DerivedURITails:   []string{".meta/policy.acl"},
		DefaultContentType: "text/turtle",
	})
	if err != nil {
		t.Fatalf("DiscoverPolicySources returned error: %v", err)
	}
	if len(sources) != 3 {
		t.Fatalf("source count = %d, want 3: %#v", len(sources), sources)
	}
	if sources[0].Kind != PolicySourceExplicit || sources[0].Priority != PolicySourcePriorityExplicit {
		t.Fatalf("first source = %#v, want explicit priority", sources[0])
	}
	if sources[1].Kind != PolicySourceLink || sources[1].URI != "https://pod.example/policies/from-link.acl" {
		t.Fatalf("second source = %#v, want normalized link source", sources[1])
	}
	if sources[2].Kind != PolicySourceDerived || sources[2].URI != "https://pod.example/alice/card/.meta/policy.acl" {
		t.Fatalf("third source = %#v, want derived source", sources[2])
	}
}

func TestPolicySourcesFromLinkHeadersFiltersAllowedRelations(t *testing.T) {
	sources, err := PolicySourcesFromLinkHeaders(
		[]string{`<https://pod.example/policies/one.acl>; rel="preview", <https://pod.example/policies/two.acl>; rel="acl describedby"`},
		"https://pod.example/alice/card",
		[]string{"acl"},
		"text/turtle",
	)
	if err != nil {
		t.Fatalf("PolicySourcesFromLinkHeaders returned error: %v", err)
	}
	if len(sources) != 1 || sources[0].URI != "https://pod.example/policies/two.acl" {
		t.Fatalf("sources = %#v, want only allowed relation", sources)
	}
}

func TestPolicySourcesFromLinkHeadersRejectsUnsafeInputs(t *testing.T) {
	for _, test := range []struct {
		name       string
		headers    []string
		resource   string
		relations  []string
		wantErr    error
	}{
		{name: "invalid resource", headers: []string{`<x>; rel="acl"`}, resource: "not a uri", relations: []string{"acl"}, wantErr: ErrInvalidPolicyDiscovery},
		{name: "malformed link", headers: []string{`not-link; rel="acl"`}, resource: "https://pod.example/card", relations: []string{"acl"}, wantErr: ErrInvalidPolicyDiscovery},
		{name: "fragment target", headers: []string{`<https://pod.example/policies/a.acl#frag>; rel="acl"`}, resource: "https://pod.example/card", relations: []string{"acl"}, wantErr: ErrInvalidPolicyDiscovery},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := PolicySourcesFromLinkHeaders(test.headers, test.resource, test.relations, "text/turtle")
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestDerivedPolicySourcesRejectsUnsafeTail(t *testing.T) {
	_, err := DerivedPolicySources("https://pod.example/alice/card", []string{"bad#tail"}, "text/turtle")
	if !errors.Is(err, ErrInvalidPolicyDiscovery) {
		t.Fatalf("error = %v, want ErrInvalidPolicyDiscovery", err)
	}
}

func TestPolicyDiscoveryVersionIsDeterministic(t *testing.T) {
	left := PolicyDiscoveryOptions{
		ResourceURI:       "https://pod.example/alice/card",
		AllowedLinkRels:   []string{"acl", "policy"},
		DefaultContentType: "text/turtle",
		LinkHeaders:       []string{`<https://pod.example/policies/a.acl>; rel="acl"; type="text/turtle"`},
	}
	right := PolicyDiscoveryOptions{
		ResourceURI:       "https://pod.example/alice/card",
		AllowedLinkRels:   []string{"policy", "acl"},
		DefaultContentType: "text/turtle",
		LinkHeaders:       []string{`<https://pod.example/policies/a.acl>; type="text/turtle"; rel="acl"`},
	}
	if PolicyDiscoveryVersion(left) == "" {
		t.Fatal("expected discovery version")
	}
	if PolicyDiscoveryVersion(left) != PolicyDiscoveryVersion(right) {
		t.Fatalf("versions differ: %q vs %q", PolicyDiscoveryVersion(left), PolicyDiscoveryVersion(right))
	}
}
