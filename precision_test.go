package jsluice

import "testing"

// Real-world minified bundles store regex patterns, MIME types, UA tokens, and
// base64 alphabets as string literals; the eager path classifier reported all of
// them as `path`. These guard the precision pass that filters that noise without
// dropping genuine paths.

func TestPathClassifierRejectsNoise(t *testing.T) {
	src := []byte(`
var rgx="https?://(.*)bing.com";
var rgx2="google.([^/?]*)";
var mime="text/javascript";
var mime2="application/x-www-form-urlencoded";
var ua="OPR/";
var ua2="SamsungBrowser/";
var b64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
`)
	res, err := AnalyzeSource("app.js", src, Options{Mode: ModeURLs})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	noise := map[string]bool{
		"https?://(.*)bing.com": true,
		"google.([^/?]*)":       true,
		"text/javascript":       true,
		"application/x-www-form-urlencoded": true,
		"OPR/":            true,
		"SamsungBrowser/": true,
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=": true,
	}
	for _, f := range res.Findings {
		if noise[f.Value] {
			t.Errorf("noise classified as %s: %q", f.Kind, f.Value)
		}
	}
}

func TestPathClassifierKeepsRealPaths(t *testing.T) {
	src := []byte(`var a="/api/v1/users";var b="track/";var c="/engage/";var d="api/v2/orders";`)
	res, err := AnalyzeSource("app.js", src, Options{Mode: ModeURLs})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	for _, want := range []string{"/api/v1/users", "track/", "/engage/", "api/v2/orders"} {
		found := false
		for _, f := range res.Findings {
			if f.Value == want {
				found = true
			}
		}
		if !found {
			t.Errorf("real path dropped: %q", want)
		}
	}
}

func TestLooksLikeNoisePathUnit(t *testing.T) {
	noise := []string{
		"https?://(.*)bing.com", "google.([^/?]*)", "(.*)foo",
		"text/javascript", "application/json", "image/png", "audio/mpeg",
		"OPR/", "Edg/", "Chrome/", "Trident/", "SamsungBrowser/", "CriOS/",
		`CriOS\/`, `FxiOS\/`, `Edg\/`, "Konqueror[:/]?", // escaped-slash + char-class UA/regex forms
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
	}
	for _, v := range noise {
		if !looksLikeNoisePath(v) {
			t.Errorf("looksLikeNoisePath(%q) = false, want true", v)
		}
	}
	real := []string{
		"/api/v1/users", "track/", "/engage/", "api/v2/orders", "/v3/keys",
		"/internal/admin/delete", "*/v3/keys", "/healthz", "users/123/posts",
	}
	for _, v := range real {
		if looksLikeNoisePath(v) {
			t.Errorf("looksLikeNoisePath(%q) = true, want false (real path)", v)
		}
	}
}
