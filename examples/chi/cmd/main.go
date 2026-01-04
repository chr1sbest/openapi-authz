package main

import (
	"fmt"
	"net/http"
	"os"

	example "github.com/chr1sbest/openapi-authz/examples/chi"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	fmt.Printf("Server listening on %s\n", addr)
	err := http.ListenAndServe(addr, example.NewHandler())
	if err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}
