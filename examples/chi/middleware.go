package chi

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/chr1sbest/openapi-authz/examples/api"
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

// Mock JWT parser
func parseToken(authHeader string) (*Claims, error) {
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return nil, fmt.Errorf("missing token")
	}
	// In reality: parse and validate JWT here.
	// For this example, we accept any token "admin" as admin role.
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

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Look up the policy using the route pattern (e.g. "/users/{id}") when
		// available.
		path := r.URL.Path
		if routeCtx := chi.RouteContext(r.Context()); routeCtx != nil {
			if p := routeCtx.RoutePattern(); p != "" {
				path = p
			}
		}
		key := authpolicy.RouteKey{
			Method: r.Method,
			Path:   path,
		}

		policy, ok := authpolicy.Policies[key]

		// If no policy found or auth not required, proceed.
		// (Adjust this logic if you want to deny-by-default)
		if !ok || !policy.RequireAuth {
			next.ServeHTTP(w, r)
			return
		}

		// 3. Authenticate (Check Bearer Token)
		authHeader := r.Header.Get("Authorization")
		claims, err := parseToken(authHeader)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// 4. Authorize (Check Roles)
		// Assuming x-required-roles logic where ANY of the required roles is sufficient.
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

		// Store claims in context for handlers to use
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type server struct{}

func (s *server) GetAdmin(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello Admin"))
}

func (s *server) GetUser(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello User"))
}

func NewHandler() http.Handler {
	baseRouter := chi.NewRouter()
	// oapi-codegen applies these middlewares per-operation, after routing.
	return api.HandlerWithOptions(&server{}, api.ChiServerOptions{
		BaseRouter:  baseRouter,
		Middlewares: []api.MiddlewareFunc{AuthMiddleware},
	})
}
