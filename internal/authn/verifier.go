package authn

import (
	"context"
	"fmt"
)

var ErrInvalidIdentityVerification = ErrInvalidIdentityToken

type IdentityVerifier struct {
	Discovery *IssuerDiscoveryClient
	Options   IdentityValidationOptions
}

func NewIdentityVerifier(discovery *IssuerDiscoveryClient, opts IdentityValidationOptions) *IdentityVerifier {
	if discovery == nil {
		discovery = NewIssuerDiscoveryClient(nil)
	}
	return &IdentityVerifier{Discovery: discovery, Options: opts}
}

func (v *IdentityVerifier) Verify(ctx context.Context, token string) (TrustedIdentity, error) {
	if v == nil {
		return TrustedIdentity{}, fmt.Errorf("%w: nil verifier", ErrInvalidIdentityVerification)
	}
	if len(v.Options.AllowedIssuers) == 0 {
		return TrustedIdentity{}, fmt.Errorf("%w: allowed issuers are required", ErrInvalidIdentityVerification)
	}
	_, payload, _, _, err := parseCompactJWT(token)
	if err != nil {
		return TrustedIdentity{}, err
	}
	claims, err := ParseIdentityClaimsJSON(payload)
	if err != nil {
		return TrustedIdentity{}, err
	}
	issuer, err := canonicalIssuerURI(claims.Issuer)
	if err != nil {
		return TrustedIdentity{}, fmt.Errorf("%w: invalid issuer", ErrInvalidIdentityVerification)
	}
	if !issuerAllowed(issuer, v.Options.AllowedIssuers) {
		return TrustedIdentity{}, fmt.Errorf("%w: issuer is not allowed", ErrInvalidIdentityVerification)
	}
	metadata, err := v.Discovery.Discover(ctx, issuer)
	if err != nil {
		return TrustedIdentity{}, err
	}
	jwks, err := v.Discovery.FetchJWKS(ctx, metadata)
	if err != nil {
		return TrustedIdentity{}, err
	}
	return VerifyIdentityJWT(token, jwks, v.Options)
}
