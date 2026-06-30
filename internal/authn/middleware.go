package authn

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/outlaw-dame/solid-sidecar/internal/audit"
	"github.com/outlaw-dame/solid-sidecar/internal/config"
)

// Middleware performs Phase 3 auth preflight. It rejects malformed OAuth/DPoP
// request shapes before CSS, but it does not make final Solid access decisions.
func Middleware(cfg config.AuthConfig, logger *slog.Logger, cache *ReplayCache, next http.Handler) http.Handler {
	if !cfg.PreflightEnabled {
		return next
	}
	verifier := NewDPoPVerifier(cfg, cache)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		if err := preflightRequest(verifier, r); err != nil {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
			audit.LogRejectedRequest(logger, r, http.StatusUnauthorized, err.Error())
			http.Error(w, "invalid authentication proof", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func preflightRequest(verifier *DPoPVerifier, r *http.Request) error {
	authorizationValues := r.Header.Values("Authorization")
	if len(authorizationValues) == 0 {
		return nil
	}
	if len(authorizationValues) != 1 {
		return errInvalidAuthorization("multiple Authorization headers are not allowed")
	}
	scheme, token, err := parseAuthorization(authorizationValues[0])
	if err != nil {
		return err
	}
	dpopProof, hasProof, err := dpopProofHeader(r)
	if err != nil {
		return err
	}
	switch strings.ToLower(scheme) {
	case "dpop":
		if verifier.cfg.RequireDPoPForDPoPAuthorization && !hasProof {
			return errInvalidAuthorization("DPoP authorization requires DPoP proof header")
		}
		if hasProof {
			return verifier.VerifyRequest(r, token, dpopProof)
		}
		return nil
	case "bearer":
		if hasProof {
			return errInvalidAuthorization("Bearer authorization must not include DPoP proof")
		}
		return nil
	default:
		return errInvalidAuthorization("unsupported Authorization scheme")
	}
}

func parseAuthorization(value string) (scheme string, token string, err error) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) != 2 {
		return "", "", errInvalidAuthorization("Authorization must contain exactly scheme and token")
	}
	if strings.ContainsAny(fields[0], "\r\n\x00") || strings.ContainsAny(fields[1], "\r\n\x00") {
		return "", "", errInvalidAuthorization("Authorization contains control characters")
	}
	if len(fields[1]) > 8192 {
		return "", "", errInvalidAuthorization("Authorization token is too large")
	}
	return fields[0], fields[1], nil
}

func dpopProofHeader(r *http.Request) (string, bool, error) {
	values := r.Header.Values("DPoP")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 {
		return "", false, errInvalidAuthorization("multiple DPoP headers are not allowed")
	}
	value := strings.TrimSpace(values[0])
	if value == "" {
		return "", false, errInvalidAuthorization("DPoP header is empty")
	}
	if strings.ContainsAny(value, "\r\n\x00,") {
		return "", false, errInvalidAuthorization("DPoP header contains invalid characters")
	}
	if len(value) > 16384 {
		return "", false, errInvalidAuthorization("DPoP proof is too large")
	}
	return value, true, nil
}

type invalidAuthorizationError struct{ reason string }

func (e invalidAuthorizationError) Error() string { return e.reason }

func errInvalidAuthorization(reason string) error {
	return invalidAuthorizationError{reason: reason}
}
