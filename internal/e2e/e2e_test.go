package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/chr1sbest/openapi-authz/internal/model"
	"github.com/chr1sbest/openapi-authz/internal/parser"
)

// TestParseConfig_RealSpec ensures we can parse a real openapi.yaml from this
// repository and derive sensible policies.
func TestParseConfig_RealSpec(t *testing.T) {
	// e2e_test.go -> internal/e2e -> .. -> .. -> testdata/basic.yaml
	path := filepath.Join("..", "..", "testdata", "basic.yaml")

	cfg, err := parser.ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}

	if len(cfg.Policies) == 0 {
		t.Fatalf("expected some policies from real spec, got none")
	}

	// Spot-check a few expectations based on the template's openapi.yaml.
	// GET /vegetables should be public.
	if p, ok := cfg.Policies[model.RouteKey{Method: "GET", Path: "/vegetables"}]; ok {
		if p.RequireAuth {
			t.Errorf("expected GET /vegetables to be public, got %+v", p)
		}
	}

	// POST /vegetables should require auth (BearerAuth in spec).
	if p, ok := cfg.Policies[model.RouteKey{Method: "POST", Path: "/vegetables"}]; ok {
		if !p.RequireAuth {
			t.Errorf("expected POST /vegetables to require auth, got %+v", p)
		}
	}
}

// Below is a lightweight copy of the middleware pattern from the README to
// validate end-to-end behaviour with a chi router.

type Claims struct {
	Roles  []string
	Scopes []string
}

type claimsKey struct{}

func withClaims(next http.Handler, claims *Claims) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// For the purpose of behaviour testing, we create a minimal policy map and a
// middleware that uses chi's route pattern and a RouteKey/Policy pair.

type RouteKey struct {
	Method string
	Path   string
}

type AuthPolicy struct {
	RequireAuth bool
	Roles       []string
	Scopes      []string
}

// In production code you would typically key policies by the router's route
// pattern (e.g. chi.RoutePattern) rather than the concrete URL path. For this
// test we key by path only to keep assertions simple.
var testPoliciesByPath = map[RouteKey]AuthPolicy{
	{Method: "GET", Path: "/public"}:   {RequireAuth: false},
	{Method: "GET", Path: "/user"}:     {RequireAuth: true},
	{Method: "DELETE", Path: "/admin"}: {RequireAuth: true, Roles: []string{"admin"}},
	{Method: "POST", Path: "/scoped"}:  {RequireAuth: true, Scopes: []string{"vegetable:write"}},
}

func hasAnyRole(claims *Claims, required ...string) bool {
	for _, r := range required {
		for _, have := range claims.Roles {
			if have == r {
				return true
			}
		}
	}
	return false
}

func hasAllScopes(claims *Claims, required ...string) bool {
	for _, r := range required {
		found := false
		for _, have := range claims.Scopes {
			if have == r {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func AuthPolicyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routeCtx := chi.RouteContext(r.Context())
		if routeCtx == nil {
			next.ServeHTTP(w, r)
			return
		}

		// For this test, we key policies by the concrete URL path so we can assert
		// behaviour without depending on chi's internal route pattern format.
		key := RouteKey{Method: r.Method, Path: r.URL.Path}
		policy, ok := testPoliciesByPath[key]
		if !ok || !policy.RequireAuth {
			next.ServeHTTP(w, r)
			return
		}

		claims, _ := r.Context().Value(claimsKey{}).(*Claims)
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if len(policy.Roles) > 0 && !hasAnyRole(claims, policy.Roles...) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if len(policy.Scopes) > 0 && !hasAllScopes(claims, policy.Scopes...) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func TestAuthPolicyMiddleware_WithChiRouter(t *testing.T) {
	r := chi.NewRouter()
	r.Use(AuthPolicyMiddleware)

	r.Get("/public", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/user", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Delete("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Post("/scoped", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Public route without claims should succeed.
	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for public route, got %d", rec.Code)
	}

	// User route without claims should be unauthorized.
	req = httptest.NewRequest(http.MethodGet, "/user", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for user route without claims, got %d", rec.Code)
	}

	// Admin route with user role should be forbidden.
	userClaims := &Claims{Roles: []string{"user"}}
	req = httptest.NewRequest(http.MethodDelete, "/admin", nil)
	rec = httptest.NewRecorder()
	withClaims(r, userClaims).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for admin route with user role, got %d", rec.Code)
	}

	// Admin route with admin role should succeed.
	adminClaims := &Claims{Roles: []string{"admin"}}
	req = httptest.NewRequest(http.MethodDelete, "/admin", nil)
	rec = httptest.NewRecorder()
	withClaims(r, adminClaims).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin route with admin role, got %d", rec.Code)
	}

	// Scoped route without required scope should be forbidden.
	noScopeClaims := &Claims{Roles: []string{"user"}}
	req = httptest.NewRequest(http.MethodPost, "/scoped", nil)
	rec = httptest.NewRecorder()
	withClaims(r, noScopeClaims).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for scoped route without scope, got %d", rec.Code)
	}

	// Scoped route with correct scope should succeed.
	scopedClaims := &Claims{Scopes: []string{"vegetable:write"}}
	req = httptest.NewRequest(http.MethodPost, "/scoped", nil)
	rec = httptest.NewRecorder()
	withClaims(r, scopedClaims).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for scoped route with correct scope, got %d", rec.Code)
	}
}
