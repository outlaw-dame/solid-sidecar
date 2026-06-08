package authn

import (
	"errors"
	"testing"
	"time"
)

func TestParseIdentityClaimsJSON(t *testing.T) {
	claims, err := ParseIdentityClaimsJSON([]byte(`{"iss":"https://issuer.example/","sub":"https://alice.example/profile/card#me","aud":["solid-sidecar"],"client_id":"client-1","iat":100,"exp":200}`))
	if err != nil {
		t.Fatalf("ParseIdentityClaimsJSON returned error: %v", err)
	}
	if claims.Issuer != "https://issuer.example/" || claims.Subject != "https://alice.example/profile/card#me" || len(claims.Audience) != 1 || claims.Audience[0] != "solid-sidecar" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestValidateIdentityClaimsAcceptsTrustedShape(t *testing.T) {
	claims := IdentityClaims{
		Issuer:    "https://issuer.example/",
		Subject:   "https://alice.example/profile/card#me",
		Audience:  []string{"solid-sidecar"},
		ClientID:  "client-1",
		IssuedAt:  90,
		ExpiresAt: 200,
	}
	identity, err := ValidateIdentityClaims(claims, IdentityValidationOptions{
		AllowedIssuers:   []string{"https://issuer.example/"},
		ExpectedAudience: "solid-sidecar",
		Now:              time.Unix(100, 0),
		ClockSkew:        time.Second,
	})
	if err != nil {
		t.Fatalf("ValidateIdentityClaims returned error: %v", err)
	}
	if identity.Issuer != "https://issuer.example/" || identity.WebID != "https://alice.example/profile/card" || identity.ClientID != "client-1" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestValidateIdentityClaimsRejectsUnsafeInputs(t *testing.T) {
	base := IdentityClaims{
		Issuer:    "https://issuer.example/",
		Subject:   "https://alice.example/profile/card#me",
		Audience:  []string{"solid-sidecar"},
		IssuedAt:  90,
		ExpiresAt: 200,
	}
	tests := []struct {
		name   string
		claims IdentityClaims
	}{
		{name: "http issuer", claims: withIdentityIssuer(base, "http://issuer.example/")},
		{name: "issuer not allowed", claims: withIdentityIssuer(base, "https://evil.example/")},
		{name: "missing subject", claims: withIdentitySubject(base, "")},
		{name: "bad audience", claims: withIdentityAudience(base, []string{"other"})},
		{name: "expired", claims: withIdentityExpiresAt(base, 10)},
		{name: "future issued-at", claims: withIdentityIssuedAt(base, 1000)},
		{name: "bad client", claims: withIdentityClientID(base, "bad\nclient")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateIdentityClaims(test.claims, IdentityValidationOptions{
				AllowedIssuers:   []string{"https://issuer.example/"},
				ExpectedAudience: "solid-sidecar",
				Now:              time.Unix(100, 0),
				ClockSkew:        time.Second,
			})
			if !errors.Is(err, ErrInvalidIdentityToken) {
				t.Fatalf("error = %v, want ErrInvalidIdentityToken", err)
			}
		})
	}
}

func TestParseIdentityClaimsJSONRejectsInvalidAudience(t *testing.T) {
	_, err := ParseIdentityClaimsJSON([]byte(`{"iss":"https://issuer.example/","sub":"https://alice.example/profile/card#me","aud":123,"exp":200}`))
	if !errors.Is(err, ErrInvalidIdentityToken) {
		t.Fatalf("error = %v, want ErrInvalidIdentityToken", err)
	}
}

func withIdentityIssuer(input IdentityClaims, issuer string) IdentityClaims {
	input.Issuer = issuer
	return input
}

func withIdentitySubject(input IdentityClaims, subject string) IdentityClaims {
	input.Subject = subject
	return input
}

func withIdentityAudience(input IdentityClaims, audience []string) IdentityClaims {
	input.Audience = audience
	return input
}

func withIdentityExpiresAt(input IdentityClaims, exp int64) IdentityClaims {
	input.ExpiresAt = exp
	return input
}

func withIdentityIssuedAt(input IdentityClaims, iat int64) IdentityClaims {
	input.IssuedAt = iat
	return input
}

func withIdentityClientID(input IdentityClaims, clientID string) IdentityClaims {
	input.ClientID = clientID
	return input
}
