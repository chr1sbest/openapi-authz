# openapi-authz

`openapi-authz` generates a Go map from your OpenAPI spec that tells your
middleware exactly which routes require authentication and what authorization
policies are required on those authenticated routes.

See the [Swagger Authentication docs](https://swagger.io/docs/specification/v3_0/authentication/) for more context on how these are defined in your spec.

## Purpose

OpenAPI Specs can declare which operations require auth via `security`, but generated servers
often hardcode auth middleware per route. This can be brittle and easy to drift out of sync with the spec.

`openapi-authz` turns your OpenAPI spec into a typed `RouteKey -> AuthPolicy`
map that can be consumed by a centralized HTTP auth middleware.
This keeps the **OpenAPI spec as the single source of truth**, allowing build-time validation of your spec and server.

### Example

The exact authentication implementation (JWT validation, claims type, etc.) is
left to the consuming application, but a typical usage with `chi` might look
like this:

```go
r := chi.NewRouter()

h := api.HandlerWithOptions(server, api.ChiServerOptions{
    BaseRouter: r,
    Middlewares: []api.MiddlewareFunc{
        httproutes.AuthPolicyMiddleware,
    },
})
```

Middleware is flexible and written by the developer, consuming the generated policies.

```go
// ... assumes GetClaims, HasAnyRole, etc. are defined

// AuthPolicyMiddleware enforces Policies for each request
// based on method and route pattern.
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

		// Lookup the generated policies from openapi-authz
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

		// Role-based checks
		if len(policy.Roles) > 0 && !claims.HasAnyRole(policy.Roles...) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Scope-based checks
		if len(policy.Scopes) > 0 && !claims.HasAllScopes(policy.Scopes...) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
```
## Usage

After generating policies with the CLI, wire in a middleware that enforces
whether a request requires a token and which roles/scopes are allowed.

### CLI

```bash
go install github.com/chr1sbest/openapi-authz/cmd/openapi-authz@latest
```

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


## Security conventions

We interpret OpenAPI `security` blocks with the following conventions. See the
[Swagger Authentication docs](https://swagger.io/docs/specification/v3_0/authentication/)
for more context on how these are defined in your spec.

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
