package identity

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func newResolverHTTPClient(timeoutSeconds int) *http.Client {
	if timeoutSeconds <= 0 {
		timeoutSeconds = DefaultResolverOptions().TimeoutSeconds
	}
	dialer := &net.Dialer{
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return dialValidatedResolutionAddress(ctx, dialer, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func dialValidatedResolutionAddress(ctx context.Context, dialer *net.Dialer, network string, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no IP addresses found for resolver host", ErrUnsafeDID)
	}
	for _, ip := range ips {
		if isUnsafeResolutionIP(ip) {
			return nil, fmt.Errorf("%w: resolved resolver IP is not allowed", ErrUnsafeDID)
		}
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

func validateOutboundResolutionURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("%w: resolution URL is nil", ErrUnsafeDID)
	}
	if strings.ToLower(u.Scheme) != "https" {
		return fmt.Errorf("%w: resolution URL must use HTTPS", ErrUnsafeDID)
	}
	if u.User != nil {
		return fmt.Errorf("%w: resolution URL must not include userinfo", ErrUnsafeDID)
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return fmt.Errorf("%w: resolution URL host is empty", ErrUnsafeDID)
	}
	if isUnsafeResolutionHost(host) {
		return fmt.Errorf("%w: resolution URL host is not allowed", ErrUnsafeDID)
	}
	return nil
}

func isUnsafeResolutionHost(host string) bool {
	lower := strings.ToLower(strings.Trim(host, "."))
	if lower == "" || lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") {
		return true
	}
	if ip := net.ParseIP(lower); ip != nil {
		return isUnsafeResolutionIP(ip)
	}
	return false
}

func isUnsafeResolutionIP(ip net.IP) bool {
	return ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

func isAllowedDIDDocumentContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/did+json" || mediaType == "application/json"
}
