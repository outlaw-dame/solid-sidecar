package authn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const maxIdentityIssuerLength = 2048
const maxIdentitySubjectLength = 2048
const maxIdentityClientIDLength = 512

var ErrInvalidIdentityToken = errors.New("invalid identity token")

type IdentityClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
}

type IdentityValidationOptions struct {
	AllowedIssuers []string
	ExpectedAudience string
	Now time.Time
	ClockSkew time.Duration
}

type TrustedIdentity struct {
	Issuer string
	WebID string
	ClientID string
	Audience []string
	ExpiresAt time.Time
}

func ParseIdentityClaimsJSON(input []byte) (IdentityClaims, error) {
	if len(input) == 0 || len(input) > 32768 {
		return IdentityClaims{}, fmt.Errorf("%w: claims size out of bounds", ErrInvalidIdentityToken)
	}
	var raw struct {
		Issuer string `json:"iss"`
		Subject string `json:"sub"`
		Audience any `json:"aud"`
		ClientID string `json:"client_id"`
		IssuedAt int64 `json:"iat"`
		ExpiresAt int64 `json:"exp"`
	}
	if err := json.Unmarshal(input, &raw); err != nil {
		return IdentityClaims{}, fmt.Errorf("%w: claims are not valid JSON", ErrInvalidIdentityToken)
	}
	audience, err := normalizeAudienceClaim(raw.Audience)
	if err != nil {
		return IdentityClaims{}, err
	}
	return IdentityClaims{Issuer: raw.Issuer, Subject: raw.Subject, Audience: audience, ClientID: raw.ClientID, IssuedAt: raw.IssuedAt, ExpiresAt: raw.ExpiresAt}, nil
}

func ValidateIdentityClaims(claims IdentityClaims, opts IdentityValidationOptions) (TrustedIdentity, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = 2 * time.Minute
	}
	issuer, err := canonicalIdentityURI(claims.Issuer, maxIdentityIssuerLength)
	if err != nil {
		return TrustedIdentity{}, fmt.Errorf("%w: invalid issuer", ErrInvalidIdentityToken)
	}
	webID, err := canonicalIdentityURI(claims.Subject, maxIdentitySubjectLength)
	if err != nil {
		return TrustedIdentity{}, fmt.Errorf("%w: invalid subject", ErrInvalidIdentityToken)
	}
	if len(opts.AllowedIssuers) > 0 && !issuerAllowed(issuer, opts.AllowedIssuers) {
		return TrustedIdentity{}, fmt.Errorf("%w: issuer is not allowed", ErrInvalidIdentityToken)
	}
	if opts.ExpectedAudience != "" && !audienceContains(claims.Audience, opts.ExpectedAudience) {
		return TrustedIdentity{}, fmt.Errorf("%w: audience mismatch", ErrInvalidIdentityToken)
	}
	if claims.ExpiresAt <= 0 {
		return TrustedIdentity{}, fmt.Errorf("%w: expiration is required", ErrInvalidIdentityToken)
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if now.After(expiresAt.Add(skew)) {
		return TrustedIdentity{}, fmt.Errorf("%w: token expired", ErrInvalidIdentityToken)
	}
	if claims.IssuedAt > 0 && time.Unix(claims.IssuedAt, 0).After(now.Add(skew)) {
		return TrustedIdentity{}, fmt.Errorf("%w: issued-at is in the future", ErrInvalidIdentityToken)
	}
	clientID := strings.TrimSpace(claims.ClientID)
	if strings.ContainsAny(clientID, "\r\n\x00") || len(clientID) > maxIdentityClientIDLength {
		return TrustedIdentity{}, fmt.Errorf("%w: invalid client id", ErrInvalidIdentityToken)
	}
	audience := append([]string(nil), claims.Audience...)
	return TrustedIdentity{Issuer: issuer, WebID: webID, ClientID: clientID, Audience: audience, ExpiresAt: expiresAt}, nil
}

func normalizeAudienceClaim(value any) ([]string, error) {
	switch v := value.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{strings.TrimSpace(v)}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: invalid audience", ErrInvalidIdentityToken)
			}
			out = append(out, strings.TrimSpace(text))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: invalid audience", ErrInvalidIdentityToken)
	}
}

func canonicalIdentityURI(value string, maxLen int) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxLen || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid uri")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("invalid uri")
	}
	parsed.RawQuery = ""
	return parsed.String(), nil
}

func issuerAllowed(issuer string, allowed []string) bool {
	for _, item := range allowed {
		candidate, err := canonicalIdentityURI(item, maxIdentityIssuerLength)
		if err == nil && candidate == issuer {
			return true
		}
	}
	return false
}

func audienceContains(audience []string, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return true
	}
	for _, item := range audience {
		if strings.TrimSpace(item) == expected {
			return true
		}
	}
	return false
}
