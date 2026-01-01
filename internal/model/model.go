package model

// RouteKey uniquely identifies an operation by HTTP method and normalized path.
type RouteKey struct {
	Method string
	Path   string
}

// AuthPolicy represents the authorization requirements for a single operation.
//
// Roles is a coarse-grained list of roles that are allowed to access the
// operation. Scopes are more granular permissions and are reserved for future
// use.
type AuthPolicy struct {
	RequireAuth bool
	Roles       []string
	Scopes      []string
}

// Config is the in-memory representation of all auth policies derived from a
// specification.
type Config struct {
	Policies map[RouteKey]AuthPolicy
}
