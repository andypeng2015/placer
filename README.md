# placer

Pure-Go JavaScript reconnaissance built on
[`gotreesitter`](https://github.com/odvcencio/gotreesitter). `placer` is the
maintained M31 Labs successor to `jsluice` and the frozen gotreesitter fork that
still depends on a v0.6-era parser.

## Drop-in jsluice path

Install the compatibility command:

```sh
go install github.com/m31-labs/placer/cmd/jsluice@latest
```

Use it like upstream `jsluice`:

```sh
jsluice urls app.js
jsluice secrets app.js
jsluice query -q '(string) @str' app.js
find . -name '*.js' | jsluice urls -c 8
```

The compatibility command emits JSONL and supports the jsluice modes and flags
for `urls`, `secrets`, `tree`, `query`, and `format`.

## Go API

The root package name is `jsluice` on purpose. Existing tools can use a
`go.mod` replacement for source compatibility with `github.com/BishopFox/jsluice`
or the gotreesitter fork, while new code can import the module with a local
`placer` alias:

```go
import placer "github.com/m31-labs/placer"

analyzer := placer.NewAnalyzer([]byte(`
  fetch('/api/users?id=' + userID, {method: "POST"})
`))

for _, u := range analyzer.GetURLs() {
  fmt.Println(u.URL, u.Method, u.QueryParams)
}
```

Custom matchers and user secret pattern JSON are supported through
`AddURLMatcher`, `AddSecretMatcher`, `AddSecretMatchers`, and
`ParseUserPatterns`.

## Native placer CLI

The native command keeps a richer result envelope for newer integrations:

```sh
go run ./cmd/placer all app.js
go run ./cmd/placer query -query '(call_expression function: (_) @fn)' app.js
```

## Current coverage

- URL extraction for location assignments, `location.replace`, `window.open`,
  `fetch`, generic URL-like calls, string literals, jQuery, and XHR.
- Secret extraction for AWS, GCP, Firebase, GitHub, Stripe, Slack, JWT,
  generic high-entropy literals, obfuscated string recovery, and jsluice user
  patterns.
- Tree-sitter query helpers, syntax tree printing, raw stdin, stdin file lists,
  local file input, HTTP(S) input, and WARC input.
- Pure Go, no CGo.

## Development

```sh
go test ./...
go test -run TestSecretCorpusPrecisionRecall -v
```
