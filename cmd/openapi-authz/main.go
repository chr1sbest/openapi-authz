package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chr1sbest/openapi-authz/internal/generator"
	"github.com/chr1sbest/openapi-authz/internal/parser"
)

func main() {
	in := flag.String("in", "", "Path to OpenAPI YAML file")
	out := flag.String("out", "", "Path to output Go file")
	pkg := flag.String("pkg", "httproutes", "Package name for generated code")
	flag.Parse()

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "-in and -out are required")
		os.Exit(1)
	}

	cfg, err := parser.ParseConfig(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse spec: %v\n", err)
		os.Exit(1)
	}

	code, err := generator.Generate(*pkg, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate code: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*out, code, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		os.Exit(1)
	}
}
