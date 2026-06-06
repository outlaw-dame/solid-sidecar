package authz

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	PolicySourcePriorityExplicit = 100
	PolicySourcePriorityLink     = 200
	PolicySourcePriorityDerived  = 300
)

var ErrInvalidPolicyDiscovery = errors.New("invalid authz policy discovery input")

type PolicyDiscoveryOptions struct {
	ResourceURI       string
	ExplicitSources   []PolicySource
	LinkHeaders       []string
	AllowedLinkRels   []string
	DerivedURITails   []string
	DefaultContentType string
}

func DiscoverPolicySources(options PolicyDiscoveryOptions) ([]PolicySource, error) {
	var sources []PolicySource
	for _, source := range options.ExplicitSources {
		if source.Priority == 0 {
			source.Priority = PolicySourcePriorityExplicit
		}
		if source.Kind == "" {
			source.Kind = PolicySourceExplicit
		}
		sources = append(sources, source)
	}

	linkSources, err := PolicySourcesFromLinkHeaders(options.LinkHeaders, options.ResourceURI, options.AllowedLinkRels, options.DefaultContentType)
	if err != nil {
		return nil, err
	}
	sources = append(sources, linkSources...)

	derivedSources, err := DerivedPolicySources(options.ResourceURI, options.DerivedURITails, options.DefaultContentType)
	if err != nil {
		return nil, err
	}
	sources = append(sources, derivedSources...)

	return NormalizePolicySources(sources)
}

func PolicySourcesFromLinkHeaders(headers []string, resourceURI string, allowedRels []string, defaultContentType string) ([]PolicySource, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	base, err := parseDiscoveryBaseURI(resourceURI)
	if err != nil {
		return nil, err
	}
	allowed := normalizeAllowedLinkRels(allowedRels)
	defaultContentType = strings.TrimSpace(defaultContentType)
	var sources []PolicySource
	for _, header := range headers {
		parts := splitLinkHeader(header)
		for _, part := range parts {
			source, ok, err := policySourceFromLinkValue(part, base, allowed, defaultContentType)
			if err != nil {
				return nil, err
			}
			if ok {
				sources = append(sources, source)
			}
		}
	}
	return NormalizePolicySources(sources)
}

func DerivedPolicySources(resourceURI string, tails []string, defaultContentType string) ([]PolicySource, error) {
	if len(tails) == 0 {
		return nil, nil
	}
	base, err := parseDiscoveryBaseURI(resourceURI)
	if err != nil {
		return nil, err
	}
	defaultContentType = strings.TrimSpace(defaultContentType)
	sources := make([]PolicySource, 0, len(tails))
	for _, tail := range tails {
		tail = strings.TrimSpace(tail)
		if tail == "" || strings.ContainsAny(tail, "\x00\r\n") || strings.Contains(tail, "#") {
			return nil, fmt.Errorf("%w: invalid derived policy source tail", ErrInvalidPolicyDiscovery)
		}
		derived := *base
		derived.RawQuery = ""
		derived.Fragment = ""
		derived.Path = strings.TrimRight(base.EscapedPath(), "/") + "/" + strings.TrimLeft(tail, "/")
		sources = append(sources, PolicySource{
			URI:         derived.String(),
			Kind:        PolicySourceDerived,
			Priority:    PolicySourcePriorityDerived,
			ContentType: defaultContentType,
		})
	}
	return NormalizePolicySources(sources)
}

func parseDiscoveryBaseURI(resourceURI string) (*url.URL, error) {
	resourceURI = strings.TrimSpace(resourceURI)
	if !validResourceURI(resourceURI) {
		return nil, fmt.Errorf("%w: invalid resource uri", ErrInvalidPolicyDiscovery)
	}
	parsed, err := url.Parse(resourceURI)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid resource uri", ErrInvalidPolicyDiscovery)
	}
	parsed.Fragment = ""
	return parsed, nil
}

func policySourceFromLinkValue(value string, base *url.URL, allowed map[string]struct{}, defaultContentType string) (PolicySource, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return PolicySource{}, false, nil
	}
	if !strings.HasPrefix(value, "<") {
		return PolicySource{}, false, fmt.Errorf("%w: malformed link header value", ErrInvalidPolicyDiscovery)
	}
	end := strings.Index(value, ">")
	if end <= 1 {
		return PolicySource{}, false, fmt.Errorf("%w: malformed link target", ErrInvalidPolicyDiscovery)
	}
	target := strings.TrimSpace(value[1:end])
	attrs := parseLinkAttributes(value[end+1:])
	if !linkRelAllowed(attrs["rel"], allowed) {
		return PolicySource{}, false, nil
	}
	resolved, err := resolveLinkTarget(base, target)
	if err != nil {
		return PolicySource{}, false, err
	}
	contentType := strings.TrimSpace(attrs["type"])
	if contentType == "" {
		contentType = defaultContentType
	}
	return PolicySource{
		URI:         resolved,
		Kind:        PolicySourceLink,
		Priority:    PolicySourcePriorityLink,
		ContentType: contentType,
	}, true, nil
}

func splitLinkHeader(header string) []string {
	var out []string
	var current strings.Builder
	inQuote := false
	for _, r := range header {
		switch r {
		case '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case ',':
			if inQuote {
				current.WriteRune(r)
				continue
			}
			out = append(out, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	out = append(out, current.String())
	return out
}

func parseLinkAttributes(value string) map[string]string {
	attrs := make(map[string]string)
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, raw, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		raw = strings.TrimSpace(raw)
		if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
			raw = raw[1 : len(raw)-1]
		}
		attrs[key] = raw
	}
	return attrs
}

func normalizeAllowedLinkRels(input []string) map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, rel := range input {
		rel = strings.ToLower(strings.TrimSpace(rel))
		if rel != "" {
			allowed[rel] = struct{}{}
		}
	}
	return allowed
}

func sortedAllowedLinkRels(input []string) []string {
	allowed := normalizeAllowedLinkRels(input)
	out := make([]string, 0, len(allowed))
	for rel := range allowed {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

func linkRelAllowed(relValue string, allowed map[string]struct{}) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, rel := range strings.Fields(strings.ToLower(relValue)) {
		if _, ok := allowed[rel]; ok {
			return true
		}
	}
	return false
}

func resolveLinkTarget(base *url.URL, target string) (string, error) {
	if strings.ContainsAny(target, "\x00\r\n") || strings.Contains(target, "#") {
		return "", fmt.Errorf("%w: unsafe link target", ErrInvalidPolicyDiscovery)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("%w: invalid link target", ErrInvalidPolicyDiscovery)
	}
	resolved := base.ResolveReference(parsed)
	resolved.Fragment = ""
	if !validResourceURI(resolved.String()) {
		return "", fmt.Errorf("%w: invalid resolved link target", ErrInvalidPolicyDiscovery)
	}
	return resolved.String(), nil
}

func PolicyDiscoveryVersion(options PolicyDiscoveryOptions) string {
	sources, err := DiscoverPolicySources(options)
	if err != nil || len(sources) == 0 {
		return ""
	}
	version := PolicySourceSetVersion(sources)
	if version == "" {
		return ""
	}
	return version + ":" + sha256Hex(strings.Join(sortedAllowedLinkRels(options.AllowedLinkRels), "\x1f"))
}
