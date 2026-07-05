package authz

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OutboundTransportNetworkPolicy describes the default network-safety rules for
// remote fixture distribution transports.
type OutboundTransportNetworkPolicy struct {
	AllowLocalhost bool
	RequireHTTPS   bool
}

// DefaultOutboundTransportNetworkPolicy returns the production-safe outbound
// network policy for fixture transports.
func DefaultOutboundTransportNetworkPolicy() OutboundTransportNetworkPolicy {
	return OutboundTransportNetworkPolicy{RequireHTTPS: true}
}

// ValidateURL validates an outbound URL before it is used by an HTTP-based
// transport. Callers that perform network I/O must also use NewHTTPClient so
// DNS answers are validated at dial time.
func (p OutboundTransportNetworkPolicy) ValidateURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse outbound transport URL: %v", ErrTransportInvalidPath, err)
	}
	if err := p.ValidateParsedURL(parsedURL); err != nil {
		return nil, err
	}
	return parsedURL, nil
}

// ValidateParsedURL validates an already parsed outbound URL.
func (p OutboundTransportNetworkPolicy) ValidateParsedURL(parsedURL *url.URL) error {
	if parsedURL == nil {
		return fmt.Errorf("%w: outbound transport URL cannot be nil", ErrTransportInvalidPath)
	}
	if parsedURL.Scheme == "" {
		return fmt.Errorf("%w: outbound transport URL must include a scheme", ErrTransportInvalidPath)
	}
	if p.RequireHTTPS && parsedURL.Scheme != "https" {
		return fmt.Errorf("%w: outbound transport URL must use https", ErrTransportSecurityViolation)
	}
	if !p.RequireHTTPS && parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return fmt.Errorf("%w: outbound transport URL must use http or https", ErrTransportInvalidPath)
	}
	if parsedURL.User != nil {
		return fmt.Errorf("%w: outbound transport URL cannot contain userinfo", ErrTransportSecurityViolation)
	}
	if parsedURL.Hostname() == "" {
		return fmt.Errorf("%w: outbound transport URL must include a hostname", ErrTransportInvalidPath)
	}
	return p.ValidateHostname(parsedURL.Hostname())
}

// ValidateHostname validates a literal hostname or IP address before use.
func (p OutboundTransportNetworkPolicy) ValidateHostname(host string) error {
	cleanedHost := strings.TrimSpace(host)
	cleanedHost = strings.Trim(cleanedHost, "[]")
	cleanedHost = strings.ToLower(strings.TrimSuffix(cleanedHost, "."))
	if cleanedHost == "" {
		return fmt.Errorf("%w: outbound transport host cannot be empty", ErrTransportInvalidPath)
	}

	ip := net.ParseIP(cleanedHost)
	if ip != nil {
		if p.AllowLocalhost {
			return nil
		}
		if isUnsafeOutboundTransportIP(ip) {
			return fmt.Errorf("%w: outbound transport host resolves to a non-public IP", ErrTransportSecurityViolation)
		}
		return nil
	}

	if p.AllowLocalhost {
		return nil
	}
	if cleanedHost == "localhost" || strings.HasSuffix(cleanedHost, ".localhost") || strings.HasSuffix(cleanedHost, ".local") {
		return fmt.Errorf("%w: outbound transport host cannot use localhost or local-only names", ErrTransportSecurityViolation)
	}
	if !strings.Contains(cleanedHost, ".") {
		return fmt.Errorf("%w: outbound transport host must be a fully-qualified public hostname", ErrTransportSecurityViolation)
	}
	return nil
}

// NewHTTPClient returns an HTTP client that enforces the policy before dispatch
// and after DNS resolution, immediately before connecting.
func (p OutboundTransportNetworkPolicy) NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTransportTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return p.DialContext(ctx, dialer, network, address)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// DialContext resolves, validates, and dials a concrete IP address.
func (p OutboundTransportNetworkPolicy) DialContext(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: outbound transport address must include host and port", ErrTransportInvalidPath)
	}
	if err := p.ValidateHostname(host); err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to resolve outbound transport host", ErrTransportConnectionFailed)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: outbound transport host resolved no addresses", ErrTransportConnectionFailed)
	}
	for _, resolved := range ips {
		if resolved.IP == nil {
			continue
		}
		if err := p.validateResolvedIP(resolved.IP); err != nil {
			return nil, err
		}
	}
	for _, resolved := range ips {
		if resolved.IP == nil {
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("%w: failed to connect to outbound transport host", ErrTransportConnectionFailed)
}

func (p OutboundTransportNetworkPolicy) validateResolvedIP(ip net.IP) error {
	if p.AllowLocalhost {
		return nil
	}
	if isUnsafeOutboundTransportIP(ip) {
		return fmt.Errorf("%w: outbound transport DNS resolved to a non-public IP", ErrTransportSecurityViolation)
	}
	return nil
}

func isUnsafeOutboundTransportIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// IsTransportSecurityError reports whether an error is caused by outbound
// transport network-policy enforcement.
func IsTransportSecurityError(err error) bool {
	return errors.Is(err, ErrTransportSecurityViolation)
}
