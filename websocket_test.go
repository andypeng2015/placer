package jsluice

import "testing"

// WebSocket/SSE endpoints use ws:// and wss:// schemes; they must be recognized
// as absolute URLs, not mis-classified as relative paths.
func TestWebSocketSchemesAreURLs(t *testing.T) {
	// Bare assignments (not `new WebSocket(...)`, which now yields a typed
	// endpoint) so this isolates absolute-URL scheme recognition.
	src := []byte(`
var a="wss://api.x.com/socket";
var b="ws://localhost:8080/live";
`)
	res, err := AnalyzeSource("app.js", src, Options{Mode: ModeURLs})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	for _, want := range []string{"wss://api.x.com/socket", "ws://localhost:8080/live"} {
		var kind string
		for _, f := range res.Findings {
			if f.Value == want {
				kind = f.Kind
			}
		}
		if kind == "" {
			t.Errorf("%q not extracted at all", want)
		} else if kind != "url" {
			t.Errorf("%q classified as %q, want url", want, kind)
		}
	}
}
