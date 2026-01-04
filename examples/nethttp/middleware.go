package nethttp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/chr1sbest/openapi-authz/examples/authpolicy"
)

// -----------------------------------------------------------------------------
// Example Claims / JWT logic
// -----------------------------------------------------------------------------

type Claims struct {
	Sub   string   `json:"sub"`
	Roles []string `json:"roles"`
}

func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func parseToken(authHeader string) (*Claims, error) {
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return nil, fmt.Errorf("missing token")
	}
	if token == "admin" {
		return &Claims{Sub: "user1", Roles: []string{"admin"}}, nil
	}
	if token == "user" {
		return &Claims{Sub: "user2", Roles: []string{"user"}}, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// -----------------------------------------------------------------------------
// Middleware Implementation
// -----------------------------------------------------------------------------

// For standard net/http, determining the route pattern (e.g., "/users/{id}" instead of "/users/123")
// depends on your router (ServeMux, Gorilla Mux, etc.).
// Go 1.22+ ServeMux does not easily expose the matched pattern in the request context
// in a standard way that middleware can consume before the handler runs.
//
// This example assumes you are using a router that puts the pattern in the context,
// or you are using Go 1.22 ServeMux and manually handling pattern matching if needed,
// but for simplicity, we'll demonstrate with a manual lookup or assuming a helper exists.

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Resolve the route pattern.
		// NOTE: In standard net/http (Go 1.22+), getting the matched pattern
		// inside middleware is tricky without wrapping the mux.
		// Here we just use URL.Path for exact matches in this simple example.
		// In a real app with path parameters, you'd need a router that exposes the pattern.
		path := r.URL.Path

		// 2. Look up the policy
		key := authpolicy.RouteKey{
			Method: r.Method,
			Path:   path,
		}

		policy, ok := authpolicy.Policies[key]

		if !ok || !policy.RequireAuth {
			next.ServeHTTP(w, r)
			return
		}

		// 3. Authenticate
		authHeader := r.Header.Get("Authorization")
		claims, err := parseToken(authHeader)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// 4. Authorize
		if len(policy.Roles) > 0 {
			authorized := false
			for _, requiredRole := range policy.Roles {
				if claims.HasRole(requiredRole) {
					authorized = true
					break
				}
			}
			if !authorized {
				http.Error(w, "Forbidden: missing required role", http.StatusForbidden)
				return
			}
		}

		// Store claims in context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func NewHandler() http.Handler {
	mux := http.NewServeMux()

	// Wrap the mux with middleware
	handler := AuthMiddleware(mux)

	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello Admin"))
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello User"))
	})

	return handler
}
