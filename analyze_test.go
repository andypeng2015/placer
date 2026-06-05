package jsluice

import (
	"os"
	"path/filepath"
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

func TestAnalyzeSourceFindsObfuscatedSecrets(t *testing.T) {
	src := []byte(`
const aws = 'AKIA' + '1234567890ABCDEF';
const gh = atob('Z2hwX2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSg==');
const stripe = String.fromCharCode(115,107,95,108,105,118,101,95,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80);
const gcp = Buffer.from('QUl6YWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJ', 'base64').toString();
`)
	res, err := AnalyzeSource("obfuscated.js", src, Options{Mode: ModeSecrets})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	assertFinding(t, res.Findings, "secret", "AKIA1234567890ABCDEF")
	assertFinding(t, res.Findings, "secret", "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ")
	assertFinding(t, res.Findings, "secret", "sk_live_ABCDEFGHIJKLMNOP")
	assertFinding(t, res.Findings, "secret", "AIzaabcdefghijklmnopqrstuvwxyzABCDEFGHI")
	assertSecret(t, res.Findings, "aws_access_key")
	assertSecret(t, res.Findings, "github_token")
	assertSecret(t, res.Findings, "stripe_secret_key")
	assertSecret(t, res.Findings, "google_api_key")
	for _, finding := range res.Findings {
		if finding.Rule == "aws_access_key" && !strings.Contains(finding.Context, "recovered: concat") {
			t.Fatalf("aws finding context = %q, want recovery marker", finding.Context)
		}
	}
}

func TestAnalyzeSourceClassifiesContextFreeMinifiedSecrets(t *testing.T) {
	src := []byte(`$.ajax({data:{k:"AKIAIOSFODNN7EXAMPLE"}});const t="ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";const s="sk_live_ABCDEFGHIJKLMNOP";const j="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";`)
	res, err := AnalyzeSource("bundle.min.js", src, Options{Mode: ModeSecrets})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	assertSecret(t, res.Findings, "aws_access_key")
	assertSecret(t, res.Findings, "github_token")
	assertSecret(t, res.Findings, "stripe_secret_key")
	assertSecret(t, res.Findings, "jwt")
	assertNoGenericForSpecific(t, res.Findings)
}

func TestAnalyzeSourceUsesContextOnlyToBoostGenericEntropy(t *testing.T) {
	plainValue := "MNBVCXZLKJHGFDSAPOIUYTREWQ987654"
	friendlyValue := "QAZWSXEDCRFVTGBYHNUJMIKOLP123456"
	src := []byte(`const x="` + plainValue + `";const apiKey="` + friendlyValue + `";`)
	res, err := AnalyzeSource("bundle.js", src, Options{Mode: ModeSecrets})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	genericValues := map[string]bool{}
	for _, finding := range res.Findings {
		if finding.Rule == "generic_high_entropy" {
			genericValues[finding.Value] = true
		}
	}
	for _, want := range []string{plainValue, friendlyValue} {
		if !genericValues[want] {
			t.Fatalf("missing context-independent generic value %q in %#v", want, res.Findings)
		}
	}
	plainConfidence := genericConfidence(t, `const x="`+plainValue+`";`)
	friendlyConfidence := genericConfidence(t, `const apiKey="`+friendlyValue+`";`)
	if friendlyConfidence <= plainConfidence {
		t.Fatalf("generic confidence plain=%f friendly=%f, want friendly context boost", plainConfidence, friendlyConfidence)
	}
}

func TestSecretTokensPreservesJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	for _, token := range secretTokens(jwt) {
		if token == jwt {
			return
		}
	}
	t.Fatalf("secretTokens(%q) = %#v, want preserved JWT", jwt, secretTokens(jwt))
}

func TestClassifierMatchesJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	matches, err := classifySecret(secretCandidate{Value: jwt})
	if err != nil {
		t.Fatalf("classifySecret: %v", err)
	}
	for _, match := range matches {
		if match.class == "jwt" {
			return
		}
	}
	t.Fatalf("classifySecret(%q) = %#v, want jwt", jwt, matches)
}

func TestAnalyzeFilesStableOrderWithWorkers(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 0, 4)
	for _, name := range []string{"a", "b", "c", "d"} {
		path := filepath.Join(dir, name+".js")
		if err := os.WriteFile(path, []byte(`fetch("/`+name+`")`), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		paths = append(paths, path)
	}
	res, err := AnalyzeFiles(paths, Options{Mode: ModeURLs, Workers: 4})
	if err != nil {
		t.Fatalf("AnalyzeFiles: %v", err)
	}
	if len(res.Files) != len(paths) {
		t.Fatalf("files = %#v", res.Files)
	}
	for i, file := range res.Files {
		if file.Path != paths[i] {
			t.Fatalf("file %d path = %s, want %s", i, file.Path, paths[i])
		}
	}
}

func TestAnalyzeFilesHonorsMaxFileBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.js")
	if err := os.WriteFile(path, []byte(`fetch("/too-large")`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	res, err := AnalyzeFiles([]string{path}, Options{Mode: ModeURLs, MaxFileBytes: 4})
	if err != nil {
		t.Fatalf("AnalyzeFiles: %v", err)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Error, "file exceeds max size") {
		t.Fatalf("errors = %#v", res.Errors)
	}
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

func assertNoGenericForSpecific(t *testing.T, findings []Finding) {
	t.Helper()
	specificValues := map[string]bool{}
	for _, finding := range findings {
		if finding.Kind == "secret" && finding.Rule != "generic_high_entropy" {
			specificValues[finding.Value] = true
		}
	}
	for _, finding := range findings {
		if finding.Rule == "generic_high_entropy" && specificValues[finding.Value] {
			t.Fatalf("generic duplicate for specific secret %#v in %#v", finding, findings)
		}
	}
}

func genericConfidence(t *testing.T, src string) float64 {
	t.Helper()
	res, err := AnalyzeSource("bundle.js", []byte(src), Options{Mode: ModeSecrets})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	for _, finding := range res.Findings {
		if finding.Rule == "generic_high_entropy" {
			return finding.Confidence
		}
	}
	t.Fatalf("missing generic_high_entropy in %#v", res.Findings)
	return 0
}
