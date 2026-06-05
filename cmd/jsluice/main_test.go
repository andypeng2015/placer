package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slyrz/warc"
)

func TestCLIURLsRawInputJSONL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"urls", "--raw-input", "--include-source"}, strings.NewReader(`fetch("/api", {method:"POST"})`), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	objs := parseJSONL(t, stdout.String())
	obj := objs[0]
	if obj["url"] != "/api" {
		t.Fatalf("url = %#v, stdout=%s", obj["url"], stdout.String())
	}
}

func TestCLISecretsRawInputJSONL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"secrets", "--raw-input"}, strings.NewReader(`const k = "AKIA1234567890ABCDEF";`), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	obj := parseJSONL(t, stdout.String())[0]
	if obj["kind"] != "AWSAccessKey" {
		t.Fatalf("kind = %#v, stdout=%s", obj["kind"], stdout.String())
	}
}

func TestCLIQueryRawInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"query", "--raw-input", "-q", "(string) @str"}, strings.NewReader(`const x = "ok";`), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != `"ok"` {
		t.Fatalf("stdout = %q, want JSON string ok", got)
	}
}

func TestCLITreeAndFormatRawInput(t *testing.T) {
	var treeOut, treeErr bytes.Buffer
	err := run([]string{"tree", "--raw-input"}, strings.NewReader(`const x = "ok";`), &treeOut, &treeErr)
	if err != nil {
		t.Fatalf("tree run: %v stderr=%s", err, treeErr.String())
	}
	if got := treeOut.String(); !strings.Contains(got, "<stdin>:") || !strings.Contains(got, "program") {
		t.Fatalf("tree stdout = %q", got)
	}

	var formatOut, formatErr bytes.Buffer
	err = run([]string{"format", "--raw-input"}, strings.NewReader(`function f(){return {a:1};}`), &formatOut, &formatErr)
	if err != nil {
		t.Fatalf("format run: %v stderr=%s", err, formatErr.String())
	}
	if got := formatOut.String(); !strings.Contains(got, "function f()") || !strings.Contains(got, "a: 1") {
		t.Fatalf("format stdout = %q", got)
	}
}

func TestCLIReadsFileListFromStdin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.js")
	if err := os.WriteFile(path, []byte(`document.location = "/logout"`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{"urls"}, strings.NewReader(path+"\n"), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	for _, obj := range parseJSONL(t, stdout.String()) {
		if obj["filename"] == path && obj["url"] == "/logout" {
			return
		}
	}
	t.Fatalf("missing file URL record in %s", stdout.String())
}

func TestCLIHTTPInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "auth=true" || r.Header.Get("X-Test") != "yes" {
			t.Fatalf("headers = %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/http", {method:"POST"})`))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	err := run([]string{"urls", "-I", "-C", "auth=true", "-H", "X-Test: yes", server.URL + "/app.js"}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	obj := parseJSONL(t, stdout.String())[0]
	if obj["url"] != "/http" || obj["method"] != "POST" || obj["filename"] != server.URL+"/app.js" {
		t.Fatalf("obj = %#v", obj)
	}
}

func TestCLIConcurrentOutputOrder(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 0, 4)
	for _, name := range []string{"a", "b", "c", "d"} {
		path := filepath.Join(dir, name+".js")
		if err := os.WriteFile(path, []byte(`document.location = "/`+name+`"`), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		paths = append(paths, path)
	}
	args := append([]string{"urls", "-I", "-c", "4"}, paths...)
	var stdout, stderr bytes.Buffer
	err := run(args, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	objs := parseJSONL(t, stdout.String())
	if len(objs) != len(paths) {
		t.Fatalf("objs = %#v", objs)
	}
	for i, obj := range objs {
		if obj["filename"] != paths[i] {
			t.Fatalf("line %d filename = %#v, want %s", i, obj["filename"], paths[i])
		}
	}
}

func TestCLIWARCInput(t *testing.T) {
	var warcBuf bytes.Buffer
	record := warc.NewRecord()
	record.Header.Set("WARC-Type", "response")
	record.Header.Set("WARC-Target-URI", "https://example.test/app.js")
	record.Content = strings.NewReader("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nfetch('/warc')\n")
	if _, err := warc.NewWriter(&warcBuf).WriteRecord(record); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sample.warc")
	if err := os.WriteFile(path, warcBuf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err := run([]string{"urls", "-I", "--warc", path}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	obj := parseJSONL(t, stdout.String())[0]
	if obj["url"] != "/warc" || obj["filename"] != "https://example.test/app.js" {
		t.Fatalf("obj = %#v", obj)
	}
}

func TestCLIResolvePathsAndUnique(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"urls", "--raw-input", "-R", "https://example.com/a/b/", "-u"}, strings.NewReader(`
document.location = '../../guestbook.html'
const s = '../../guestbook.html'
`), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("lines = %#v", lines)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &obj); err != nil {
		t.Fatalf("invalid JSONL: %v", err)
	}
	if obj["url"] != "https://example.com/guestbook.html" {
		t.Fatalf("url = %#v", obj["url"])
	}
}

func parseJSONL(t *testing.T, output string) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("empty stdout")
	}
	objs := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("invalid JSONL: %v\n%s", err, output)
		}
		objs = append(objs, obj)
	}
	return objs
}
