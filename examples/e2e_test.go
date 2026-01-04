package examples_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	examplechi "github.com/chr1sbest/openapi-authz/examples/chi"
	examplenethttp "github.com/chr1sbest/openapi-authz/examples/nethttp"
)

func TestChiExample(t *testing.T) {
	runExampleTest(t, examplechi.NewHandler())
}

func TestNetHttpExample(t *testing.T) {
	runExampleTest(t, examplenethttp.NewHandler())
}

func runExampleTest(t *testing.T, h http.Handler) {
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Define test cases based on examples/openapi.yaml
	tests := []struct {
		name       string
		path       string
		token      string
		wantStatus int
	}{
		// /user: security: BearerAuth: [] -> Requires valid token
		{"Public /user request (no auth)", "/user", "", 401},
		{"Valid user token", "/user", "user", 200},
		{"Invalid user token", "/user", "bad_token", 401},

		// /admin: security: BearerAuth: [], x-required-roles: ["admin"]
		{"Public /admin request (no auth)", "/admin", "", 401},
		{"User token accessing admin", "/admin", "user", 403},
		{"Admin token accessing admin", "/admin", "admin", 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", ts.URL+tt.path, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("%s %s: got status %d, want %d", req.Method, req.URL.Path, resp.StatusCode, tt.wantStatus)
			}
		})
	}
}
