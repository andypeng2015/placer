package placer

import (
	"strings"
	"testing"
)

func TestUpstreamAnalyzerBasicURLs(t *testing.T) {
	a := NewAnalyzer([]byte(`
		function foo(){
			document.location = "/logout"
		}
	`))
	urls := a.GetURLs()
	if len(urls) < 1 {
		t.Fatalf("expected at least 1 URL; got %d", len(urls))
	}
	if urls[0].URL != "/logout" {
		t.Fatalf("expected first URL to be '/logout'; got %s", urls[0].URL)
	}
}

func TestUpstreamAnalyzerBasicSecrets(t *testing.T) {
	a := NewAnalyzer([]byte(`
		function foo(){
			return {
				awsKey: "AKIAIOSFODNN7EXAMPLE",
				secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
			}
		}
	`))
	secrets := a.GetSecrets()
	if len(secrets) != 1 {
		t.Fatalf("expected exactly 1 secret; got %d", len(secrets))
	}
	if secrets[0].Kind != "AWSAccessKey" {
		t.Fatalf("expected first secret kind to be AWSAccessKey; got %s", secrets[0].Kind)
	}
}

func TestUpstreamMaybeURL(t *testing.T) {
	cases := []struct {
		in       string
		expected bool
	}{
		{"https://example.com", true},
		{"https://example.net/api/v1", true},
		{"HTTP://example.net/api/v1", true},
		{"application/json", false},
		{"text/plain", false},
		{"//example.org", true},
		{"example.org", false},
		{"foo?id=123", true},
		{"Who? Me?", false},
		{"foo.php?id", true},
		{"foo.lolno?id", false},
		{"/foo/bar.html", true},
		{"./foo/bar.html", true},
		{`~[A-Z](?=[/|([{\u003c\\\"'])`, false},
		{"./", false},
		{"foo/bar", false},
	}
	for _, c := range cases {
		if actual := MaybeURL(c.in); actual != c.expected {
			t.Fatalf("want %t for MaybeURL(%s); have %t", c.expected, c.in, actual)
		}
	}
}

func TestUpstreamStringDecode(t *testing.T) {
	cases := []struct {
		in       string
		expected string
	}{
		{`"foo bar"`, `foo bar`},
		{`"foo\\bar"`, `foo\bar`},
		{`"foo\"bar"`, `foo"bar`},
		{`"foo\'bar"`, `foo'bar`},
		{`"foo\075bar"`, `foo=bar`},
		{`"foo\tbar"`, "foo\tbar"},
		{`"foo\vbar"`, "foo\vbar"},
		{`"foo\u003dbar"`, "foo=bar"},
		{`"foo\u{00000000003d}bar"`, "foo=bar"},
		{`"foo\075"`, `foo=`},
		{`"foo\x3d"`, `foo=`},
		{`"foo\\"`, `foo\`},
		{`"\075foo"`, `=foo`},
		{`"\x3dfoo"`, `=foo`},
		{`"\\foo"`, `\foo`},
		{`"\075\x3d"`, `==`},
		{`"\u{00000003d}\x3d"`, `==`},
		{`"\poo"`, `poo`},
		{`"\u{0003doops"`, `=oops`},
		{`"/help/doc/user_ed.jsp?loc\x3dhelp\x26target\x3d"`, "/help/doc/user_ed.jsp?loc=help&target="},
	}
	for _, c := range cases {
		if actual := DecodeString(c.in); c.expected != actual {
			t.Fatalf("want %s for DecodeString(%s); have %s", c.expected, c.in, actual)
		}
	}
}

func TestUpstreamParseUserPatterns(t *testing.T) {
	testData := strings.NewReader(`[
		{"name": "httpAuth", "value": "/[a-z0-9_/\\.:-]+@[a-z0-9-]+\\.[a-z0-9.-]+"},
		{"name": "base64", "value": "^(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[%a-zA-Z0-9+/]+={0,2}"}
	]`)
	patterns, err := ParseUserPatterns(testData)
	if err != nil {
		t.Fatalf("want nil error for ParseUserPatterns(testData); have %s", err)
	}
	if len(patterns) != 2 {
		t.Fatalf("want 2 patterns from ParseUserPatterns(testData); have %d", len(patterns))
	}
	cases := []struct {
		i        int
		in       string
		expected bool
	}{
		{0, "//someuser:somepass@example.com", true},
		{0, "https://someuser:somepass@example.com", true},
		{0, "person@example.com", false},
		{1, "eyJmb28iOiAxMjN9Cg==", true},
		{1, "eyJ:-)b28iOiAxMjN9Cg==", false},
		{1, "foobareyJmb28iOiAxMjN9Cg==", false},
	}
	for _, c := range cases {
		if patterns[c.i].MatchValue(c.in) != c.expected {
			t.Fatalf("want %t for pattern %d MatchValue(%s)", c.expected, c.i, c.in)
		}
	}
}
