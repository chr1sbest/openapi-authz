package parser

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/chr1sbest/openapi-authz/internal/model"
)

type expectedPolicy struct {
	method string
	path   string
	policy model.AuthPolicy
}

func TestParseConfigFromReader(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantErr  bool
		expected []expectedPolicy
	}{
		{
			name: "public endpoint (no security)",
			yaml: `
openapi: 3.0.0
paths:
  /public:
    get:
      summary: Public endpoint
`,
			expected: []expectedPolicy{
				{"GET", "/public", model.AuthPolicy{RequireAuth: false}},
			},
		},
		{
			name: "public endpoint (explicit empty security)",
			yaml: `
openapi: 3.0.0
paths:
  /public:
    get:
      summary: Public endpoint
      security: []
`,
			expected: []expectedPolicy{
				{"GET", "/public", model.AuthPolicy{RequireAuth: false}},
			},
		},
		{
			name: "BearerAuth - any authenticated user",
			yaml: `
openapi: 3.0.0
paths:
  /user:
    get:
      summary: Protected endpoint
      security:
        - BearerAuth: []
`,
			expected: []expectedPolicy{
				{"GET", "/user", model.AuthPolicy{RequireAuth: true}},
			},
		},
		{
			name: "BearerAuth - with role",
			yaml: `
openapi: 3.0.0
paths:
  /admin:
    delete:
      summary: Admin-only
      security:
        - BearerAuth: ["role:admin"]
`,
			expected: []expectedPolicy{
				{"DELETE", "/admin", model.AuthPolicy{RequireAuth: true, Roles: []string{"admin"}}},
			},
		},
		{
			name: "BearerAuth - with scope",
			yaml: `
openapi: 3.0.0
paths:
  /scoped:
    post:
      summary: Scoped endpoint
      security:
        - BearerAuth: ["vegetable:write"]
`,
			expected: []expectedPolicy{
				{"POST", "/scoped", model.AuthPolicy{RequireAuth: true, Scopes: []string{"vegetable:write"}}},
			},
		},
		{
			name: "OAuth2 - any authenticated user",
			yaml: `
openapi: 3.0.0
paths:
  /oauth:
    get:
      summary: OAuth2 protected
      security:
        - OAuth2: []
`,
			expected: []expectedPolicy{
				{"GET", "/oauth", model.AuthPolicy{RequireAuth: true}},
			},
		},
		{
			name: "OAuth2 - with scopes",
			yaml: `
openapi: 3.0.0
paths:
  /oauth:
    post:
      summary: OAuth2 with scopes
      security:
        - OAuth2: ["read:users", "write:users"]
`,
			expected: []expectedPolicy{
				{"POST", "/oauth", model.AuthPolicy{RequireAuth: true, Scopes: []string{"read:users", "write:users"}}},
			},
		},
		{
			name: "OAuth2 - with role",
			yaml: `
openapi: 3.0.0
paths:
  /oauth-admin:
    delete:
      summary: OAuth2 admin
      security:
        - OAuth2: ["role:admin"]
`,
			expected: []expectedPolicy{
				{"DELETE", "/oauth-admin", model.AuthPolicy{RequireAuth: true, Roles: []string{"admin"}}},
			},
		},
		{
			name: "ApiKeyAuth - basic",
			yaml: `
openapi: 3.0.0
paths:
  /apikey:
    get:
      summary: API key protected
      security:
        - ApiKeyAuth: []
`,
			expected: []expectedPolicy{
				{"GET", "/apikey", model.AuthPolicy{RequireAuth: true}},
			},
		},
		{
			name: "api_key variant",
			yaml: `
openapi: 3.0.0
paths:
  /apikey:
    get:
      summary: API key protected
      security:
        - api_key: []
`,
			expected: []expectedPolicy{
				{"GET", "/apikey", model.AuthPolicy{RequireAuth: true}},
			},
		},
		{
			name: "lowercase bearerAuth variant",
			yaml: `
openapi: 3.0.0
paths:
  /user:
    get:
      summary: Protected
      security:
        - bearerAuth: []
`,
			expected: []expectedPolicy{
				{"GET", "/user", model.AuthPolicy{RequireAuth: true}},
			},
		},
		{
			name: "unsupported security scheme",
			yaml: `
openapi: 3.0.0
paths:
  /custom:
    get:
      summary: Custom auth
      security:
        - CustomAuth: []
`,
			wantErr: true,
		},
		{
			name: "global security applies to operations",
			yaml: `
openapi: 3.0.0
security:
  - BearerAuth: []
paths:
  /protected:
    get:
      summary: Inherits global security
`,
			expected: []expectedPolicy{
				{"GET", "/protected", model.AuthPolicy{RequireAuth: true}},
			},
		},
		{
			name: "operation security overrides global",
			yaml: `
openapi: 3.0.0
security:
  - BearerAuth: []
paths:
  /public:
    get:
      summary: Public override
      security: []
`,
			expected: []expectedPolicy{
				{"GET", "/public", model.AuthPolicy{RequireAuth: false}},
			},
		},
		{
			name: "JSON format support",
			yaml: `{"openapi": "3.0.0", "paths": {"/api": {"get": {"security": [{"BearerAuth": []}]}}}}`,
			expected: []expectedPolicy{
				{"GET", "/api", model.AuthPolicy{RequireAuth: true}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfigFromReader(strings.NewReader(tt.yaml))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, exp := range tt.expected {
				got, ok := cfg.Lookup(exp.method, exp.path)
				if !ok {
					t.Errorf("missing policy for %s %s", exp.method, exp.path)
					continue
				}
				if !reflect.DeepEqual(got, exp.policy) {
					t.Errorf("%s %s: got %+v, want %+v", exp.method, exp.path, got, exp.policy)
				}
			}
		})
	}
}

// TestParseConfigFromFile tests file I/O integration.
func TestParseConfigFromFile(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "basic.yaml")
	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}

	expected := []expectedPolicy{
		{"GET", "/public", model.AuthPolicy{RequireAuth: false}},
		{"GET", "/user", model.AuthPolicy{RequireAuth: true}},
		{"DELETE", "/admin", model.AuthPolicy{RequireAuth: true, Roles: []string{"admin"}}},
		{"POST", "/scoped", model.AuthPolicy{RequireAuth: true, Scopes: []string{"vegetable:write"}}},
	}

	for _, exp := range expected {
		got, ok := cfg.Lookup(exp.method, exp.path)
		if !ok {
			t.Errorf("missing policy for %s %s", exp.method, exp.path)
			continue
		}
		if !reflect.DeepEqual(got, exp.policy) {
			t.Errorf("%s %s: got %+v, want %+v", exp.method, exp.path, got, exp.policy)
		}
	}
}
