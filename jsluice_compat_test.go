package jsluice

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSLuiceCompatBasicURL(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`
const login = (redirect) => {
  document.location = "/login?redirect=" + redirect + "&method=oauth"
}
`))
	urls := analyzer.GetURLs()
	var found *URL
	for _, u := range urls {
		if u.Type == "locationAssignment" {
			found = u
			break
		}
	}
	if found == nil {
		t.Fatalf("missing locationAssignment in %#v", urls)
	}
	if got, want := found.URL, "/login?redirect=EXPR&method=oauth"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	if got, want := found.Method, "GET"; got != want {
		t.Fatalf("Method = %q, want %q", got, want)
	}
	if !contains(found.QueryParams, "redirect") || !contains(found.QueryParams, "method") {
		t.Fatalf("QueryParams = %#v, want redirect and method", found.QueryParams)
	}
}

func TestJSLuiceCompatFetchURL(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`
fetch('/api/users?id=' + userId + '&format=json', {
  method: "POST",
  headers: {"Content-Type": "application/json", "X-Env": "stage"}
})
`))
	urls := analyzer.GetURLs()
	var found *URL
	for _, u := range urls {
		if u.Type == "fetch" {
			found = u
			break
		}
	}
	if found == nil {
		t.Fatalf("missing fetch URL in %#v", urls)
	}
	if got, want := found.URL, "/api/users?id=EXPR&format=json"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	if got, want := found.Method, "POST"; got != want {
		t.Fatalf("Method = %q, want %q", got, want)
	}
	if got, want := found.ContentType, "application/json"; got != want {
		t.Fatalf("ContentType = %q, want %q", got, want)
	}
}

func TestJSLuiceCompatAWSSecret(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`
var config = {
  awsKey: "AKIA1234567890ABCDEF",
  awsSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY"
};
`))
	secrets := analyzer.GetSecrets()
	if len(secrets) != 1 {
		t.Fatalf("secrets = %#v, want one", secrets)
	}
	got := secrets[0]
	if got.Kind != "AWSAccessKey" || got.Severity != SeverityHigh {
		t.Fatalf("secret = %#v, want high AWSAccessKey", got)
	}
	data := got.Data.(map[string]string)
	if data["key"] != "AKIA1234567890ABCDEF" || !strings.Contains(data["secret"], "SECRETKEY") {
		t.Fatalf("data = %#v", data)
	}
	if _, err := json.Marshal(got); err != nil {
		t.Fatalf("Marshal secret: %v", err)
	}
}

func TestJSLuiceCompatUserPattern(t *testing.T) {
	patterns, err := ParseUserPatterns(strings.NewReader(`[
  {"name":"genericSecret","key":"secret","value":"^AUTH_[A-Za-z0-9]+$","severity":"medium"}
]`))
	if err != nil {
		t.Fatalf("ParseUserPatterns: %v", err)
	}
	analyzer := NewAnalyzer([]byte(`const config = {secret: "AUTH_abc123"};`))
	analyzer.AddSecretMatchers(patterns.SecretMatchers())
	secrets := analyzer.GetSecrets()
	if len(secrets) != 1 {
		t.Fatalf("secrets = %#v, want one", secrets)
	}
	if secrets[0].Kind != "genericSecret" || secrets[0].Severity != SeverityMedium {
		t.Fatalf("secret = %#v", secrets[0])
	}
}

func TestJSLuiceCompatCustomMatchers(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`
var config = {
  contact: "mailto:contact@example.com",
  apiKey: "AUTH_1a2b3c"
}
`))
	analyzer.DisableDefaultURLMatchers()
	analyzer.AddURLMatcher(URLMatcher{"string", func(n *Node) *URL {
		value := n.DecodedString()
		if !strings.HasPrefix(value, "mailto:") {
			return nil
		}
		return &URL{URL: value, Type: "mailto"}
	}})
	urls := analyzer.GetURLs()
	if len(urls) != 1 || urls[0].URL != "mailto:contact@example.com" || urls[0].Type != "mailto" {
		t.Fatalf("urls = %#v", urls)
	}

	analyzer.AddSecretMatcher(SecretMatcher{"(pair) @match", func(n *Node) *Secret {
		key := n.ChildByFieldName("key").DecodedString()
		value := n.ChildByFieldName("value").DecodedString()
		if key != "apiKey" || !strings.HasPrefix(value, "AUTH_") {
			return nil
		}
		return &Secret{
			Kind:     "fakeApi",
			Data:     map[string]string{"key": key, "value": value},
			Severity: SeverityLow,
			Context:  n.Parent().AsMap(),
		}
	}})
	secrets := analyzer.GetSecrets()
	for _, secret := range secrets {
		if secret.Kind == "fakeApi" && secret.Severity == SeverityLow {
			return
		}
	}
	t.Fatalf("missing custom fakeApi secret in %#v", secrets)
}

func TestJSLuiceCompatQuery(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`const x = "one"; const y = "two";`))
	var got []string
	analyzer.Query(`(string) @str`, func(n *Node) {
		got = append(got, n.AsGoType().(string))
	})
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("query got %#v", got)
	}
}

func TestJSLuiceCompatJQueryAjax(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`
$.ajax({
  method: "PUT",
  url: "/api/v1/posts",
  data:{ postId: 324 },
  headers: {"Content-Type": "application/json", "x-backend": "prod"}
})
`))
	urls := analyzer.GetURLs()
	var found *URL
	for _, u := range urls {
		if u.Type == "$.ajax" {
			found = u
			break
		}
	}
	if found == nil {
		t.Fatalf("missing $.ajax URL in %#v", urls)
	}
	if found.URL != "/api/v1/posts" || found.Method != "PUT" {
		t.Fatalf("found = %#v", found)
	}
	if !contains(found.BodyParams, "postId") {
		t.Fatalf("BodyParams = %#v, want postId", found.BodyParams)
	}
	if found.Headers["Content-Type"] != "application/json" || found.ContentType != "application/json" {
		t.Fatalf("headers/content type = %#v %q", found.Headers, found.ContentType)
	}
}

func TestJSLuiceCompatXHRHeaders(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`
function callAPI(method, callback){
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/' + method + '?format=json', true);
  xhr.setRequestHeader('Accept', 'application/json');
  xhr.setRequestHeader('X-Env', 'staging');
  xhr.send();
}
`))
	urls := analyzer.GetURLs()
	var found *URL
	for _, u := range urls {
		if u.Type == "XMLHttpRequest.open" {
			found = u
			break
		}
	}
	if found == nil {
		t.Fatalf("missing XHR URL in %#v", urls)
	}
	if found.URL != "/api/EXPR?format=json" || found.Method != "GET" {
		t.Fatalf("found = %#v", found)
	}
	if found.Headers["Accept"] != "application/json" || found.Headers["X-Env"] != "staging" {
		t.Fatalf("headers = %#v", found.Headers)
	}
}

func TestJSLuiceCompatOtherSecrets(t *testing.T) {
	source := []byte(`
const gcp = {apiKey: "AIzaSyB47WKzDu9kkmFAsAYFlagkuJxdEXAMPLE"};
const firebase = {
  apiKey: "AIzaSyB47WKzDu9kkmFAsAYFlagkuJxdEXAMPLE",
  authDomain: "someauthdomain.firebaseapp.com",
  projectId: "someprojectid",
  storageBucket: "somebucket.appspot.com"
};
const clone = "https://Some-User:ghp_BsE8x5x89jzGZxbQgFJNi4tkxs1F4EXAMPLE@github.com/foo/bar.git";
`)
	secrets := NewAnalyzer(source).GetSecrets()
	kinds := map[string]bool{}
	for _, s := range secrets {
		kinds[s.Kind] = true
	}
	for _, want := range []string{"gcpKey", "firebase", "githubKey"} {
		if !kinds[want] {
			t.Fatalf("missing %s in %#v", want, secrets)
		}
	}
}

func TestJSLuiceCompatObfuscatedSecrets(t *testing.T) {
	source := []byte(`
const aws = 'AKIA' + '1234567890ABCDEF';
const gh = atob('Z2hwX2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSg==');
const stripe = String.fromCharCode(115,107,95,108,105,118,101,95,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80);
`)
	secrets := NewAnalyzer(source).GetSecrets()
	kinds := map[string]bool{}
	recovered := map[string]string{}
	for _, secret := range secrets {
		kinds[secret.Kind] = true
		if data, ok := secret.Data.(map[string]string); ok {
			recovered[secret.Kind] = data["recoveredBy"]
		}
	}
	for _, want := range []string{"AWSAccessKey", "githubKey", "stripeSecretKey"} {
		if !kinds[want] {
			t.Fatalf("missing %s in %#v", want, secrets)
		}
		if recovered[want] == "" {
			t.Fatalf("missing recovery metadata for %s in %#v", want, secrets)
		}
	}
}

func TestJSLuiceCompatContextFreeModernSecrets(t *testing.T) {
	source := []byte(`$.ajax({data:{k:"AKIAIOSFODNN7EXAMPLE"}});const t="ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";const s="sk_live_ABCDEFGHIJKLMNOP";const j="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";`)
	secrets := NewAnalyzer(source).GetSecrets()
	kinds := map[string]bool{}
	counts := map[string]int{}
	for _, secret := range secrets {
		kinds[secret.Kind] = true
		counts[secret.Kind+" "+compatSecretPrimaryValue(secret)]++
	}
	for _, want := range []string{"AWSAccessKey", "githubKey", "stripeSecretKey", "jwt"} {
		if !kinds[want] {
			t.Fatalf("missing %s in %#v", want, secrets)
		}
	}
	for key, count := range counts {
		if count > 1 {
			t.Fatalf("duplicate %s count=%d in %#v", key, count, secrets)
		}
	}
}

func TestJSLuiceCompatHTMLInlineScript(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`<script type="text/javascript"> var contextPath = '/somepage.html'; </script><html></html>`))
	urls := analyzer.GetURLs()
	for _, u := range urls {
		if u.URL == "/somepage.html" {
			return
		}
	}
	t.Fatalf("missing inline script URL in %#v", urls)
}

func TestJSLuiceCompatCollapsedString(t *testing.T) {
	cases := []struct {
		js   []byte
		want string
	}{
		{[]byte(`"./login.php?redirect="+url`), "./login.php?redirect=EXPR"},
		{[]byte(`'/path/'+['one', 'two', 'three'].join('/')`), "/path/EXPR"},
		{[]byte(`someVar`), "EXPR"},
	}
	for _, c := range cases {
		root := NewAnalyzer(c.js).RootNode()
		got := root.NamedChild(0).NamedChild(0).CollapsedString()
		if got != c.want {
			t.Fatalf("CollapsedString(%s) = %q, want %q", c.js, got, c.want)
		}
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
