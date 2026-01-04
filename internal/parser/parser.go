package parser

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/chr1sbest/openapi-authz/internal/model"
)

// ParseConfig reads an OpenAPI v3 YAML file and extracts authorization
// requirements into a Config structure. It focuses on paths, methods and
// security blocks; it does not attempt to fully model the entire spec.
func ParseConfig(path string) (*model.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open spec: %w", err)
	}
	defer f.Close()
	return ParseConfigFromReader(f)
}

// ParseConfigFromReader reads an OpenAPI v3 YAML document from r and extracts
// authorization requirements into a Config structure.
func ParseConfigFromReader(r io.Reader) (*model.Config, error) {
	data, err := io.ReadAll(r)
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
	Security       []securityRequirement `yaml:"security"`
	XRequiredRoles []string              `yaml:"x-required-roles"`
	Paths          map[string]*pathItem  `yaml:"paths"`
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
	Security       []securityRequirement `yaml:"security"`
	XRequiredRoles []string              `yaml:"x-required-roles"`
}

type securityRequirement map[string][]string

// supportedSchemes lists the security scheme names we recognize.
// BearerAuth and OAuth2 typically carry scopes; ApiKeyAuth usually does not.
var supportedSchemes = map[string]bool{
	"BearerAuth": true,
	"OAuth2":     true,
	"ApiKeyAuth": true,
	"bearerAuth": true, // common lowercase variant
	"oauth2":     true,
	"apiKeyAuth": true,
	"api_key":    true, // another common variant
}

var scopeCapableSchemes = map[string]bool{
	"OAuth2": true,
	"oauth2": true,
}

// derivePolicy determines the AuthPolicy for an operation, taking into account
// operation-level and root-level security requirements. The precedence rules
// follow the OpenAPI specification: operation.security overrides root.security
// when present. If security is present but no supported scheme is found,
// an error is returned to avoid silently misconfiguring protection.
func derivePolicy(root *openapiRoot, op *operation) (model.AuthPolicy, error) {
	var sec []securityRequirement
	var roles []string

	if op.Security != nil {
		sec = op.Security
		roles = op.XRequiredRoles
	} else {
		sec = root.Security
		if op.XRequiredRoles != nil {
			roles = op.XRequiredRoles
		} else {
			roles = root.XRequiredRoles
		}
	}

	// If x-required-roles is set, the operation must not be public.
	if len(roles) > 0 {
		if sec == nil || len(sec) == 0 {
			return model.AuthPolicy{}, fmt.Errorf("x-required-roles is set but no security requirement is defined")
		}
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

	// Look for the first supported security scheme. If there are multiple
	// different security schemes, we use the first supported one found.
	for _, req := range sec {
		for scheme, scopes := range req {
			if supportedSchemes[scheme] {
				if len(scopes) > 0 && !scopeCapableSchemes[scheme] {
					return model.AuthPolicy{}, fmt.Errorf("%s security scheme must not include scopes", scheme)
				}
				policy.RequireAuth = true
				policy.Roles = roles
				for _, s := range scopes {
					if s != "" {
						policy.Scopes = append(policy.Scopes, s)
					}
				}
				return policy, nil
			}
		}
	}

	// Security requirements exist but none reference a supported scheme: treat as
	// configuration error rather than silently public.
	return model.AuthPolicy{}, fmt.Errorf("security section present but no supported scheme found (supported: BearerAuth, OAuth2, ApiKeyAuth)")
}
