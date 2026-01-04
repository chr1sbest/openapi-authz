# openapi-authz

`openapi-authz` is a tool that reads an OpenAPI v3 specification and
produces Go code describing authorization requirements per route.

## Purpose

OpenAPI already declares which operations require auth via `security`, but
servers often still hard-code auth middleware per route, which is brittle and
easy to drift out of sync with the spec.

`openapi-authz` turns the spec into a typed `RouteKey -> AuthPolicy` map. Your
middleware can then, for each request:

- Look up the method + route pattern
- Decide whether a token is required
- Enforce which roles/scopes are allowed

This keeps the **spec as the source of truth** for protection, while Go code
focuses on validating tokens and applying policies in one place.


## Install

**CLI:**
```bash
go install github.com/chr1sbest/openapi-authz/cmd/openapi-authz@latest
```

## Usage

### CLI

From the repository root:

```bash
go run ./cmd/openapi-authz \
	-in ./openapi.yaml \
	-out ./internal/http/authpolicy.gen.go \
	-pkg httproutes
```

You can also wire this up with `go generate`, e.g. in a Go file under
`internal/http`:

```go
//go:generate go run ./cmd/openapi-authz -in ../../openapi.yaml -out ./authpolicy.gen.go -pkg httproutes
```

You can then wire a middleware that looks up `Policies[RouteKey{Method, Path}]`
using `chi.RouteContext(r.Context()).RoutePattern()` to decide whether a
request should require a token and which roles/scopes are allowed.

### Library API

For programmatic use, import the `pkg/authz` package:

```go
import "github.com/chr1sbest/openapi-authz/pkg/authz"
```

**Parse from file:**
```go
cfg, err := authz.ParseFile("openapi.yaml")
if err != nil {
    log.Fatal(err)
}
```

**Parse from io.Reader (useful for embedded specs or testing):**
```go
spec := strings.NewReader(`
openapi: 3.0.0
paths:
  /admin:
    delete:
      security:
        - BearerAuth: ["role:admin"]
`)

cfg, err := authz.Parse(spec)
if err != nil {
    log.Fatal(err)
}
```

**Generate Go code:**
```go
code, err := authz.Generate("httproutes", cfg)
if err != nil {
    log.Fatal(err)
}
os.WriteFile("authpolicy.gen.go", code, 0644)
```

**Access policies directly (without code generation):**
```go
cfg, _ := authz.ParseFile("openapi.yaml")

// Using the Lookup helper
if policy, ok := cfg.Lookup("DELETE", "/admin"); ok {
    fmt.Printf("RequireAuth: %v, Roles: %v\n", policy.RequireAuth, policy.Roles)
}
```

> **Note:** Both YAML and JSON OpenAPI specs are supported.

## What it generates

Given an `openapi.yaml`, `openapi-authz` emits a file like:

```go
package httproutes

type RouteKey struct {
	Method string
	Path   string
}

type AuthPolicy struct {
	RequireAuth bool
	Roles       []string
	Scopes      []string
}

var Policies = map[RouteKey]AuthPolicy{
	{Method: "GET", Path: "/vegetables"}:   {RequireAuth: false},
	{Method: "POST", Path: "/vegetables"}:  {RequireAuth: true},
	{Method: "DELETE", Path: "/vegetables/{name}"}: {RequireAuth: true, Roles: []string{"admin"}},
}
```

This map can be consumed by HTTP middleware to enforce authentication and
authorization decisions at runtime.

## Example middleware

The exact authentication implementation (JWT validation, claims type, etc.) is
left to the consuming application, but a typical usage with `chi` might look
like this:

```go
package httproutes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Claims represents whatever your auth layer places in the request context.
// This is just an example; replace it with your real claims type.
type Claims struct {
	Roles  []string
	Scopes []string
}

type claimsKey struct{}

// GetClaims is a placeholder helper for retrieving claims from the context.
func GetClaims(r *http.Request) *Claims {
	claims, _ := r.Context().Value(claimsKey{}).(*Claims)
	return claims
}

func (c *Claims) HasAnyRole(required ...string) bool {
	for _, r := range required {
		for _, have := range c.Roles {
			if have == r {
				return true
			}
		}
	}
	return false
}

func (c *Claims) HasAllScopes(required ...string) bool {
	for _, r := range required {
		found := false
		for _, have := range c.Scopes {
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

// AuthPolicyMiddleware enforces Policies for each request based on method and
// route pattern. It assumes a separate middleware has already validated the
// token and stored *Claims in the context.
func AuthPolicyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routeCtx := chi.RouteContext(r.Context())
		if routeCtx == nil {
			next.ServeHTTP(w, r)
			return
		}

		key := RouteKey{
			Method: r.Method,
			Path:   routeCtx.RoutePattern(), // e.g. "/vegetables/{name}"
		}

		policy, ok := Policies[key]
		if !ok || !policy.RequireAuth {
			// Public or unknown route → pass through.
			next.ServeHTTP(w, r)
			return
		}

		claims := GetClaims(r)
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Role-based checks (today).
		if len(policy.Roles) > 0 && !claims.HasAnyRole(policy.Roles...) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Scope-based checks (future-ready).
		if len(policy.Scopes) > 0 && !claims.HasAllScopes(policy.Scopes...) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
```

In your application, you would typically compose this with a token-validation
middleware:

```go
r := chi.NewRouter()

h := api.HandlerWithOptions(server, api.ChiServerOptions{
    BaseRouter: r,
    Middlewares: []api.MiddlewareFunc{
        httproutes.AuthPolicyMiddleware,
    },
})
```

## Security conventions

We interpret OpenAPI `security` blocks with the following conventions:

- **Public endpoint**
  - No `security` block, or `security: []` at the operation level → `RequireAuth = false`.
- **Any authenticated user**
  - `security: [ { BearerAuth: [] } ]` → `RequireAuth = true`, no specific roles or scopes.
- **Role-based endpoint**
  - `security: [ { BearerAuth: ["role:admin"] } ]` → `RequireAuth = true`, `Roles = ["admin"]`.
  
- **Scope-based endpoint**
  - `security: [ { OAuth2: ["read:users", "write:users"] } ]` → `RequireAuth = true`, `Scopes = ["read:users", "write:users"]`.

Strings prefixed with `role:` are treated as roles (the `role:` prefix is
stripped); all other strings are treated as scopes.

### Supported security schemes

The following security scheme names are recognized:

| Scheme | Variants | Notes |
|--------|----------|-------|
| **BearerAuth** | `bearerAuth` | JWT/Bearer token authentication |
| **OAuth2** | `oauth2` | OAuth 2.0 flows with optional scopes |
| **ApiKeyAuth** | `apiKeyAuth`, `api_key` | API key authentication (header, query, or cookie) |

If your spec uses a different scheme name, rename it to one of the supported
variants or open an issue to request support.


## Testing

There are two kinds of tests:

- **Parser tests** (`internal/parser/parser_test.go`)
  - Use small OpenAPI fixtures in `testdata/` and assert the in-memory
    `AuthPolicy` map is correct.
- **Golden file tests** (`internal/generator/generator_test.go`)
  - Build an in-memory `Config`, run `Generate`, and compare the output against
    `testdata/authpolicy.golden.go`.

Run tests with:

```bash
go test ./...
```

## License

MIT. See [LICENSE](./LICENSE).
