package safety

import "net/http"

type OriginPolicy struct {
	allowed map[string]struct{}
}

func NewOriginPolicy(origins []string) OriginPolicy {
	allowed := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		allowed[origin] = struct{}{}
	}
	return OriginPolicy{allowed: allowed}
}

func (p OriginPolicy) Middleware(next http.Handler) http.Handler {
	if len(p.allowed) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := p.allowed[origin]; !ok {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP, Link, Prefer, Slug, If-Match, If-None-Match")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
