package identity

import (
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
	return &http.Client{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
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
