package authz

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

type BuildOptions struct {
	PublicBaseURL    string
	Now              func() time.Time
	PolicyDocuments  []PolicyDocument
	PolicyVersion    string
	ResourceMetadata map[string]string
	ResourceVersion  string
}

func BuildRequest(r *http.Request, options BuildOptions) (Request, error) {
	if r == nil {
		return Request{}, errors.New("authz request source is nil")
	}

	requestID := observability.RequestIDFromContext(r.Context())
	if requestID == "" {
		requestID = strings.TrimSpace(r.Header.Get("X-Request-ID"))
	}
	if requestID == "" {
		return Request{}, errors.New("authz request id is required")
	}

	resourceURI, err := resourceURIForRequest(r, options.PublicBaseURL)
	if err != nil {
		return Request{}, err
	}

	modes, err := modesForMethod(r.Method)
	if err != nil {
		return Request{}, err
	}

	policyDocuments, err := NormalizePolicyDocuments(options.PolicyDocuments)
	if err != nil {
		return Request{}, err
	}
	resourceMetadata, err := NormalizeResourceMetadata(options.ResourceMetadata)
	if err != nil {
		return Request{}, err
	}
	policyVersion := strings.TrimSpace(options.PolicyVersion)
	if policyVersion == "" {
		policyVersion = PolicyVersionForDocuments(policyDocuments)
	}

	now := time.Now().UTC()
	if options.Now != nil {
		now = options.Now().UTC()
	}

	return Request{
		SchemaVersion:    SchemaVersion,
		RequestID:        requestID,
		Method:           r.Method,
		ResourceURI:      resourceURI,
		Origin:           strings.TrimSpace(r.Header.Get("Origin")),
		RequestedModes:   modes,
		ResourceVersion:  strings.TrimSpace(options.ResourceVersion),
		PolicyVersion:    policyVersion,
		ResourceMetadata: resourceMetadata,
		PolicyDocuments:  policyDocuments,
		NowUnix:          now.Unix(),
	}, nil
}

func modesForMethod(method string) ([]AccessMode, error) {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return []AccessMode{AccessModeRead}, nil
	case http.MethodPost:
		return []AccessMode{AccessModeAppend}, nil
	case http.MethodPut, http.MethodPatch:
		return []AccessMode{AccessModeWrite}, nil
	case http.MethodDelete:
		return []AccessMode{AccessModeWrite}, nil
	default:
		return nil, errors.New("unsupported authz method")
	}
}

func resourceURIForRequest(r *http.Request, publicBaseURL string) (string, error) {
	if r.URL == nil {
		return "", errors.New("request url is required")
	}

	base := strings.TrimSpace(publicBaseURL)
	if base != "" {
		parsedBase, err := url.Parse(base)
		if err != nil || parsedBase.Scheme == "" || parsedBase.Host == "" {
			return "", errors.New("public base url is invalid")
		}
		parsedBase.RawQuery = ""
		parsedBase.Fragment = ""
		out := *parsedBase
		out.Path = joinBaseAndRequestPath(parsedBase.EscapedPath(), r.URL.EscapedPath())
		out.RawQuery = r.URL.RawQuery
		out.Fragment = ""
		return out.String(), nil
	}

	out := *r.URL
	out.Fragment = ""
	if out.Scheme == "" {
		if r.TLS != nil {
			out.Scheme = "https"
		} else {
			out.Scheme = "http"
		}
	}
	if out.Host == "" {
		out.Host = r.Host
	}
	if out.Host == "" {
		return "", errors.New("request host is required")
	}
	return out.String(), nil
}

func joinBaseAndRequestPath(basePath, requestPath string) string {
	basePath = strings.TrimRight(basePath, "/")
	if basePath == "" {
		if requestPath == "" {
			return "/"
		}
		return requestPath
	}
	if requestPath == "" || requestPath == "/" {
		return basePath
	}
	return basePath + "/" + strings.TrimLeft(requestPath, "/")
}
