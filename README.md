# openapi-authz

`openapi-authz` generates a Go map from your OpenAPI 3.x spec that tells your
middleware exactly which routes require authentication and optionally what authorization
policies are required on those authenticated routes.

## Purpose

OpenAPI 3.x specs can declare which operations require auth via `security`, but generated servers
often hardcode auth middleware per route. This can be brittle and easy to drift out of sync with the spec.

`openapi-authz` turns your spec into a typed `RouteKey -> AuthPolicy` map that can be consumed by middleware.
This keeps the **OpenAPI spec as the single source of truth**, allowing build-time validation of your spec and server.

### Example

The exact authentication implementation (JWT validation, claims type, etc.) is
left to the consuming application, but you can see full working examples for
popular frameworks in the [examples/](./examples) directory:

- [Chi](./examples/chi/middleware.go)
- [net/http](./examples/nethttp/middleware.go)

A typical usage with `chi` might look like this:

```go
r := chi.NewRouter()

h := api.HandlerWithOptions(server, api.ChiServerOptions{
    BaseRouter: r,
    Middlewares: []api.MiddlewareFunc{
        httproutes.AuthPolicyMiddleware,
    },
})
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
  - Use the `x-required-roles` extension (array of strings) on the operation or root.
  - `x-required-roles: ["admin"]` → `RequireAuth = true` (if security is present), `Roles = ["admin"]`.
  
- **Scope-based endpoint**
  - `security: [ { OAuth2: ["read:users", "write:users"] } ]` → `RequireAuth = true`, `Scopes = ["read:users", "write:users"]`.

For spec compliance, **BearerAuth** and **ApiKeyAuth** security requirements must use an empty scopes list (`[]`).

### Authorization semantics

- **Roles**
  - If `Roles` is non-empty, the request is allowed if the caller has **any** of the required roles.
- **Scopes (OAuth2)**
  - If `Scopes` is non-empty, the request is allowed if the caller has **all** of the required scopes.

### Multiple security schemes

If an operation declares multiple security schemes, `openapi-authz` currently uses the first supported scheme it finds and generates policy from that.
It does not model "AND" requirements (multiple schemes in the same security requirement object).

We support `x-required-roles` at both the root (global) and operation levels. Operation-level roles override global ones.

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
