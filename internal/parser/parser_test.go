package parser

import (
	"path/filepath"
	"testing"

	"github.com/chr1sbest/openapi-authz/internal/model"
)

func TestParseConfig_Basic(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "basic.yaml")

	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}

	policies := cfg.Policies

	// /public GET -> no auth required
	if p, ok := policies[model.RouteKey{Method: "GET", Path: "/public"}]; !ok {
		t.Fatalf("missing policy for GET /public")
	} else if p.RequireAuth {
		t.Errorf("expected GET /public to not require auth, got %+v", p)
	}

	// /user GET -> requires auth, no specific roles/scopes
	if p, ok := policies[model.RouteKey{Method: "GET", Path: "/user"}]; !ok {
		t.Fatalf("missing policy for GET /user")
	} else {
		if !p.RequireAuth {
			t.Errorf("expected GET /user to require auth")
		}
		if len(p.Roles) != 0 {
			t.Errorf("expected no roles for GET /user, got %+v", p.Roles)
		}
		if len(p.Scopes) != 0 {
			t.Errorf("expected no scopes for GET /user, got %+v", p.Scopes)
		}
	}

	// /admin DELETE -> requires auth, admin role
	if p, ok := policies[model.RouteKey{Method: "DELETE", Path: "/admin"}]; !ok {
		t.Fatalf("missing policy for DELETE /admin")
	} else {
		if !p.RequireAuth {
			t.Errorf("expected DELETE /admin to require auth")
		}
		if len(p.Roles) != 1 || p.Roles[0] != "admin" {
			t.Errorf("expected admin role for DELETE /admin, got %+v", p.Roles)
		}
	}

	// /scoped POST -> requires auth, scope vegetable:write
	if p, ok := policies[model.RouteKey{Method: "POST", Path: "/scoped"}]; !ok {
		t.Fatalf("missing policy for POST /scoped")
	} else {
		if !p.RequireAuth {
			t.Errorf("expected POST /scoped to require auth")
		}
		if len(p.Scopes) != 1 || p.Scopes[0] != "vegetable:write" {
			t.Errorf("expected scope vegetable:write for POST /scoped, got %+v", p.Scopes)
		}
	}
}
