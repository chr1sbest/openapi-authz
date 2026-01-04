// Package authz provides a library API for parsing OpenAPI v3 specifications
// and generating Go code that describes authorization requirements per route.
//
// This package re-exports the core types and functions from the internal
// packages for use by external consumers.
package authz

import (
	"io"

	"github.com/chr1sbest/openapi-authz/internal/generator"
	"github.com/chr1sbest/openapi-authz/internal/model"
	"github.com/chr1sbest/openapi-authz/internal/parser"
)

// RouteKey uniquely identifies an operation by HTTP method and normalized path.
type RouteKey = model.RouteKey

// AuthPolicy represents the authorization requirements for a single operation.
type AuthPolicy = model.AuthPolicy

// Config is the in-memory representation of all auth policies derived from a
// specification.
type Config = model.Config

// ParseFile reads an OpenAPI v3 YAML file and extracts authorization
// requirements into a Config structure.
func ParseFile(path string) (*Config, error) {
	return parser.ParseConfig(path)
}

// Parse reads an OpenAPI v3 YAML document from r and extracts authorization
// requirements into a Config structure.
func Parse(r io.Reader) (*Config, error) {
	return parser.ParseConfigFromReader(r)
}

// Generate produces Go source code that defines RouteKey, AuthPolicy and a
// Policies map initialized with the contents of cfg.
func Generate(pkg string, cfg *Config) ([]byte, error) {
	return generator.Generate(pkg, cfg)
}
