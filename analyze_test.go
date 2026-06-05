package jsluice

import (
	"strings"
	"testing"
)

func TestAnalyzeSourceExtractsURLsEndpointsAndSecrets(t *testing.T) {
	src := []byte(`
const api = "https://api.example.com/v1";
fetch("/v1/users", { method: "POST" });
axios.get('/healthz');
const aws = "AKIA1234567890ABCDEF";
`)
	res, err := AnalyzeSource("app.js", src, Options{Mode: ModeAll})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	assertFinding(t, res.Findings, "url", "https://api.example.com/v1")
	assertEndpoint(t, res.Findings, "/v1/users", "POST")
	assertEndpoint(t, res.Findings, "/healthz", "GET")
	assertSecret(t, res.Findings, "aws_access_key")
}

func TestAnalyzeSourceRunsQuery(t *testing.T) {
	src := []byte(`fetch("/api");`)
	res, err := AnalyzeSource("app.js", src, Options{
		Mode:  ModeQuery,
		Query: `(call_expression function: (_) @fn)`,
	})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	assertFinding(t, res.Findings, "query", "fetch")
}

func TestTemplatePathFolding(t *testing.T) {
	src := []byte("const route = `/api/users/${id}`;")
	res, err := AnalyzeSource("app.js", src, Options{Mode: ModeURLs})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	assertFinding(t, res.Findings, "path", "/api/users/*")
}

func assertFinding(t *testing.T, findings []Finding, kind, contains string) {
	t.Helper()
	for _, f := range findings {
		if f.Kind == kind && strings.Contains(f.Value, contains) {
			return
		}
	}
	t.Fatalf("missing %s finding containing %q in %#v", kind, contains, findings)
}

func assertEndpoint(t *testing.T, findings []Finding, value, method string) {
	t.Helper()
	for _, f := range findings {
		if f.Kind == "endpoint" && f.Value == value && f.Method == method {
			return
		}
	}
	t.Fatalf("missing endpoint %s %s in %#v", method, value, findings)
}

func assertSecret(t *testing.T, findings []Finding, rule string) {
	t.Helper()
	for _, f := range findings {
		if f.Kind == "secret" && f.Rule == rule {
			return
		}
	}
	t.Fatalf("missing secret rule %q in %#v", rule, findings)
}
