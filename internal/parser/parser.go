package parser

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/chr1sbest/openapi-authz/internal/model"
)

// ParseConfig reads an OpenAPI v3 YAML file and extracts authorization
// requirements into a Config structure. It focuses on paths, methods and
// security blocks; it does not attempt to fully model the entire spec.
func ParseConfig(path string) (*model.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}

	var root openapiRoot
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("unmarshal spec: %w", err)
	}

	policies := make(map[model.RouteKey]model.AuthPolicy)

	for rawPath, item := range root.Paths {
		if item == nil {
			continue
		}

		for method, op := range item.Operations() {
			if op == nil {
				continue
			}

			key := model.RouteKey{Method: method, Path: rawPath}
			policy, err := derivePolicy(&root, op)
			if err != nil {
				return nil, fmt.Errorf("derive policy for %s %s: %w", method, rawPath, err)
			}
			policies[key] = policy
		}
	}

	return &model.Config{Policies: policies}, nil
}

// openapiRoot is a minimal representation of the parts of an OpenAPI v3
// document we care about: global security and per-path operations.
type openapiRoot struct {
	Security []securityRequirement `yaml:"security"`
	Paths    map[string]*pathItem  `yaml:"paths"`
}

type pathItem struct {
	Get     *operation `yaml:"get"`
	Post    *operation `yaml:"post"`
	Put     *operation `yaml:"put"`
	Delete  *operation `yaml:"delete"`
	Patch   *operation `yaml:"patch"`
	Options *operation `yaml:"options"`
	Head    *operation `yaml:"head"`
}

// Operations returns a map of HTTP method (uppercase) to operation.
func (p *pathItem) Operations() map[string]*operation {
	ops := make(map[string]*operation)
	if p.Get != nil {
		ops["GET"] = p.Get
	}
	if p.Post != nil {
		ops["POST"] = p.Post
	}
	if p.Put != nil {
		ops["PUT"] = p.Put
	}
	if p.Delete != nil {
		ops["DELETE"] = p.Delete
	}
	if p.Patch != nil {
		ops["PATCH"] = p.Patch
	}
	if p.Options != nil {
		ops["OPTIONS"] = p.Options
	}
	if p.Head != nil {
		ops["HEAD"] = p.Head
	}
	return ops
}

type operation struct {
	Security []securityRequirement `yaml:"security"`
}

type securityRequirement map[string][]string

// derivePolicy determines the AuthPolicy for an operation, taking into account
// operation-level and root-level security requirements. The precedence rules
// follow the OpenAPI specification: operation.security overrides root.security
// when present.

// derivePolicy determines the AuthPolicy for an operation, taking into account
// operation-level and root-level security requirements. The precedence rules
// follow the OpenAPI specification: operation.security overrides root.security
// when present. If security is present but no BearerAuth requirement is found,
// an error is returned to avoid silently misconfiguring protection.
func derivePolicy(root *openapiRoot, op *operation) (model.AuthPolicy, error) {
	sec := op.Security
	if sec == nil {
		sec = root.Security
	}

	// If there is an explicit empty array, the operation is public.
	if sec != nil && len(sec) == 0 {
		return model.AuthPolicy{RequireAuth: false}, nil
	}

	// If there is no security section at all, treat as public.
	if sec == nil {
		return model.AuthPolicy{RequireAuth: false}, nil
	}

	policy := model.AuthPolicy{RequireAuth: false}

	// We only look at the first BearerAuth requirement for now. If there are
	// multiple different security schemes, we conservatively require auth.
	for _, req := range sec {
		for scheme, scopes := range req {
			if scheme == "BearerAuth" {
				policy.RequireAuth = true
				// Convention: scopes starting with "role:" are roles; others are scopes.
				for _, s := range scopes {
					if len(s) > 5 && s[:5] == "role:" {
						policy.Roles = append(policy.Roles, s[5:])
					} else {
						policy.Scopes = append(policy.Scopes, s)
					}
				}
				return policy, nil
			}
		}
	}

	// Security requirements exist but none reference BearerAuth: treat as
	// configuration error rather than silently public.
	return model.AuthPolicy{}, fmt.Errorf("security section present but no BearerAuth requirement found")
}
