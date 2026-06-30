package authn

import (
	"context"
	"errors"
	"fmt"
)

var ErrInvalidIdentityVerification = ErrInvalidIdentityToken

type IdentityVerifier struct {
	Discovery            *IssuerDiscoveryClient
	Options              IdentityValidationOptions
	WebID                *WebIDVerifier
	VerifyWebIDOwnership bool
}

func NewIdentityVerifier(discovery *IssuerDiscoveryClient, opts IdentityValidationOptions) *IdentityVerifier {
	if discovery == nil {
		discovery = NewIssuerDiscoveryClient(nil)
	}
	return &IdentityVerifier{
		Discovery:            discovery,
		Options:              opts,
		WebID:                NewWebIDVerifier(nil, opts.AllowedIssuers),
		VerifyWebIDOwnership: false,
	}
}

// NewIdentityVerifierWithWebID creates a verifier with WebID ownership verification enabled
func NewIdentityVerifierWithWebID(discovery *IssuerDiscoveryClient, opts IdentityValidationOptions, verifyWebID bool) *IdentityVerifier {
	verifier := NewIdentityVerifier(discovery, opts)
	verifier.VerifyWebIDOwnership = verifyWebID
	return verifier
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
	identity, err := VerifyIdentityJWT(token, jwks, v.Options)
	if err == nil {
		// Optionally verify WebID ownership
		if v.VerifyWebIDOwnership && v.WebID != nil {
			// Parse the token to get claims for WebID verification
			_, payload, _, _, parseErr := parseCompactJWT(token)
			if parseErr == nil {
				claims, claimParseErr := ParseIdentityClaimsJSON(payload)
				if claimParseErr == nil && claims.Subject != "" {
					if webIDErr := v.WebID.VerifyWebIDFromToken(ctx, claims); webIDErr != nil {
						return TrustedIdentity{}, fmt.Errorf("%w: WebID ownership verification failed: %v", ErrInvalidIdentityVerification, webIDErr)
					}
				}
			}
		}
		return identity, nil
	}
	if !errors.Is(err, ErrInvalidJWT) {
		return TrustedIdentity{}, err
	}
	refreshedJWKS, refreshed, refreshErr := v.Discovery.RefreshJWKS(ctx, metadata)
	if refreshErr != nil || !refreshed {
		return TrustedIdentity{}, err
	}
	return VerifyIdentityJWT(token, refreshedJWKS, v.Options)
}
