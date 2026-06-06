package jsluice

import "testing"

// Modern sinks should produce typed endpoints with the right method, not bare
// path/url findings: sendBeacon is always POST, EventSource/WebSocket/import are GET.
func TestSemanticEndpointTagging(t *testing.T) {
	cases := []struct {
		src    string
		value  string
		method string
	}{
		{`navigator.sendBeacon("/collect", d);`, "/collect", "POST"},
		{`var e=new EventSource("/stream/events");`, "/stream/events", "GET"},
		{`var w=new WebSocket("wss://api.x.com/socket");`, "wss://api.x.com/socket", "GET"},
		{`import("/chunks/lazy.js").then(f);`, "/chunks/lazy.js", "GET"},
		{`var r=new Request("/v2/orders",{method:"POST"});`, "/v2/orders", "POST"},
		{`var h=axios.create({baseURL:"https://api.x.com/v3"});`, "https://api.x.com/v3", "GET"},
	}
	for _, c := range cases {
		res, err := AnalyzeSource("app.js", []byte(c.src), Options{Mode: ModeURLs})
		if err != nil {
			t.Fatalf("AnalyzeSource(%q): %v", c.src, err)
		}
		found := false
		for _, f := range res.Findings {
			if f.Kind == "endpoint" && f.Value == c.value && f.Method == c.method {
				found = true
			}
		}
		if !found {
			t.Errorf("%s\n  want endpoint %q method %q; got %v", c.src, c.value, c.method, res.Findings)
		}
	}
}

// An endpoint subsumes the redundant url/path for the same value+line.
func TestEndpointSubsumesURL(t *testing.T) {
	res, err := AnalyzeSource("app.js", []byte(`fetch("https://api.x.com/v1/users");`), Options{Mode: ModeURLs})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	n := 0
	for _, f := range res.Findings {
		if f.Value == "https://api.x.com/v1/users" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly 1 finding for the fetched URL, got %d: %v", n, res.Findings)
	}
}
