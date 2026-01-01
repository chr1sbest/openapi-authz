package generator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chr1sbest/openapi-authz/internal/model"
)

func TestGenerate_MatchesGolden(t *testing.T) {
	cfg := &model.Config{Policies: map[model.RouteKey]model.AuthPolicy{
		{Method: "GET", Path: "/public"}:   {RequireAuth: false},
		{Method: "GET", Path: "/user"}:     {RequireAuth: true},
		{Method: "DELETE", Path: "/admin"}: {RequireAuth: true, Roles: []string{"admin"}},
		{Method: "POST", Path: "/scoped"}:  {RequireAuth: true, Scopes: []string{"vegetable:write"}},
	}}

	got, err := Generate("httproutes", cfg)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	goldenPath := filepath.Join("..", "..", "testdata", "authpolicy.golden.go")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}

	// Normalize whitespace to reduce sensitivity to formatting differences.
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
		t.Errorf("generated code does not match golden file.\nGot:\n%s\nWant:\n%s", string(got), string(want))
	}
}
