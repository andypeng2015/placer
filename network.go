package jsluice

import (
	"regexp"
	"strings"

	"github.com/odvcencio/gotreesitter"
)

var absoluteURLRe = regexp.MustCompile("(?i)\\b(?:(?:https?|wss?):)?//[^\\s\"'<>`]+")

func extractNetworkFindings(path string, tree *gotreesitter.Tree, endpointsOnly bool) []Finding {
	if tree == nil {
		return nil
	}
	lang := tree.Language()
	source := tree.Source()
	var findings []Finding
	walkNode(tree.RootNode(), func(n *gotreesitter.Node) {
		typ := n.Type(lang)
		if isLiteralType(typ) && !endpointsOnly {
			findings = append(findings, networkFindingsFromLiteral(path, n, source)...)
			return
		}
		if typ == "call_expression" {
			if f, ok := endpointFromCall(path, n, lang, source); ok {
				findings = append(findings, f)
			}
		}
		if typ == "new_expression" {
			if f, ok := endpointFromNew(path, n, lang, source); ok {
				findings = append(findings, f)
			}
		}
	})
	return findings
}

func networkFindingsFromLiteral(path string, n *gotreesitter.Node, source []byte) []Finding {
	lit, ok := parseJSLiteral(n.Text(source))
	if !ok {
		return nil
	}
	ctx := lineContext(source, int(n.StartByte()))
	var out []Finding
	for _, value := range extractAbsoluteURLs(lit.Value) {
		out = append(out, Finding{
			Kind:       "url",
			Value:      value,
			Location:   locationForNode(path, n),
			Context:    ctx,
			Confidence: 0.95,
		})
	}
	if classifyPathLike(lit.Value) {
		conf := 0.82
		if lit.Dynamic {
			conf = 0.72
		}
		out = append(out, Finding{
			Kind:       "path",
			Value:      lit.Value,
			Location:   locationForNode(path, n),
			Context:    ctx,
			Confidence: conf,
		})
	}
	return out
}

func endpointFromCall(path string, n *gotreesitter.Node, lang *gotreesitter.Language, source []byte) (Finding, bool) {
	fn := n.ChildByFieldName("function", lang)
	if fn == nil {
		return Finding{}, false
	}
	fnText := strings.TrimSpace(fn.Text(source))
	callText := n.Text(source)
	method := methodFromFunction(fnText)
	args := n.ChildByFieldName("arguments", lang)
	lits := literalNodes(args, lang)

	var endpointNode *gotreesitter.Node
	var endpoint string
	switch {
	case fnText == "fetch" || strings.HasSuffix(fnText, ".fetch"):
		if len(lits) > 0 {
			endpointNode = lits[0]
			endpoint = literalNodeValue(lits[0], source)
			if method == "" {
				method = methodFromObjectText(callText)
			}
		}
	case strings.HasPrefix(fnText, "axios"):
		if strings.Contains(fnText, ".") && len(lits) > 0 {
			endpointNode = lits[0]
			endpoint = literalNodeValue(lits[0], source)
		} else {
			endpoint, method = objectURLAndMethod(callText)
		}
	case fnText == "$.ajax" || strings.HasSuffix(fnText, ".ajax"):
		endpoint, method = objectURLAndMethod(callText)
	case strings.HasSuffix(fnText, ".open") || fnText == "open":
		if len(lits) >= 2 {
			endpointNode = lits[1]
			method = strings.ToUpper(literalNodeValue(lits[0], source))
			endpoint = literalNodeValue(lits[1], source)
		}
	case fnText == "Request" || strings.HasSuffix(fnText, ".Request"):
		if len(lits) > 0 {
			endpointNode = lits[0]
			endpoint = literalNodeValue(lits[0], source)
			method = methodFromObjectText(callText)
		}
	case fnText == "navigator.sendBeacon" || strings.HasSuffix(fnText, ".sendBeacon"):
		method = "POST"
		if len(lits) > 0 {
			endpointNode = lits[0]
			endpoint = literalNodeValue(lits[0], source)
		}
	case fnText == "import":
		method = "GET"
		if len(lits) > 0 {
			endpointNode = lits[0]
			endpoint = literalNodeValue(lits[0], source)
		}
	}

	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || (!classifyPathLike(endpoint) && len(extractAbsoluteURLs(endpoint)) == 0) {
		return Finding{}, false
	}
	locNode := n
	if endpointNode != nil {
		locNode = endpointNode
	}
	if method == "" {
		method = "GET"
	}
	return Finding{
		Kind:       "endpoint",
		Value:      endpoint,
		Location:   locationForNode(path, locNode),
		Context:    lineContext(source, int(locNode.StartByte())),
		Method:     method,
		Confidence: 0.88,
	}, true
}

// endpointFromNew types constructor-based network sinks — new WebSocket(url),
// new EventSource(url), new Request(url, {method}) — as endpoints with the
// right method, instead of leaving them as bare path/url literals.
func endpointFromNew(path string, n *gotreesitter.Node, lang *gotreesitter.Language, source []byte) (Finding, bool) {
	ctor := n.ChildByFieldName("constructor", lang)
	if ctor == nil {
		return Finding{}, false
	}
	name := strings.TrimSpace(ctor.Text(source))
	method := "GET"
	switch {
	case name == "WebSocket" || strings.HasSuffix(name, ".WebSocket"):
	case name == "EventSource" || strings.HasSuffix(name, ".EventSource"):
	case name == "Request" || strings.HasSuffix(name, ".Request"):
		if m := methodFromObjectText(n.Text(source)); m != "" {
			method = m
		}
	default:
		return Finding{}, false
	}
	lits := literalNodes(n.ChildByFieldName("arguments", lang), lang)
	if len(lits) == 0 {
		return Finding{}, false
	}
	endpoint := strings.TrimSpace(literalNodeValue(lits[0], source))
	if endpoint == "" || (!classifyPathLike(endpoint) && len(extractAbsoluteURLs(endpoint)) == 0) {
		return Finding{}, false
	}
	return Finding{
		Kind:       "endpoint",
		Value:      endpoint,
		Location:   locationForNode(path, lits[0]),
		Context:    lineContext(source, int(lits[0].StartByte())),
		Method:     method,
		Confidence: 0.88,
	}, true
}

func literalNodeValue(n *gotreesitter.Node, source []byte) string {
	if n == nil {
		return ""
	}
	lit, ok := parseJSLiteral(n.Text(source))
	if !ok {
		return ""
	}
	return lit.Value
}

func extractAbsoluteURLs(value string) []string {
	matches := absoluteURLRe.FindAllString(value, -1)
	out := matches[:0]
	for _, match := range matches {
		match = strings.TrimRight(match, ".,;:)]}")
		if match == "" {
			continue
		}
		out = append(out, match)
	}
	return out
}

func classifyPathLike(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return false
	}
	if strings.HasPrefix(value, "//") {
		return false
	}
	if looksLikeNoisePath(value) {
		return false
	}
	if len(extractAbsoluteURLs(value)) > 0 {
		return false
	}
	if strings.HasPrefix(value, "/") {
		return hasPathSignal(value)
	}
	if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return hasPathSignal(value)
	}
	if strings.Contains(value, "/") && !strings.ContainsAny(value, " \t\r\n") {
		first := value[0]
		if (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || (first >= '0' && first <= '9') {
			return hasPathSignal(value)
		}
		// A leading '*' is the folded placeholder for a dynamic base, e.g.
		// `${API}/v3/keys` -> "*/v3/keys". The static suffix is a recoverable
		// endpoint, so treat "*/path" as path-like (symmetric with the
		// trailing "/path?id=*" case, which already classifies).
		if first == '*' && len(value) > 1 && value[1] == '/' {
			return hasPathSignal(value)
		}
	}
	return false
}

// regexMetaSignals are substrings that occur in regex patterns but never in a
// real URL path. Minified bundles store patterns as string literals (for
// RegExp(...)), and the path classifier would otherwise report them as paths.
var regexMetaSignals = []string{"(.*", "(.+", "[^", "(?", ".*)", ".+)", "]?", "]*", "]+", "]{"}

// mimeTopLevelTypes are the IANA top-level media types; a `type/subtype` string
// with one of these prefixes is a MIME type, not an endpoint.
var mimeTopLevelTypes = []string{"text/", "application/", "image/", "audio/", "video/", "font/", "multipart/", "model/", "message/"}

// uaTokens are well-known User-Agent product tokens that appear as bare
// `Token/` (often `Token/version`) fragments in browser-detection code.
var uaTokens = map[string]bool{
	"OPR": true, "Edg": true, "Edge": true, "Chrome": true, "Chromium": true,
	"CriOS": true, "Safari": true, "Firefox": true, "FxiOS": true, "MSIE": true,
	"Trident": true, "SamsungBrowser": true, "Opera": true, "OPiOS": true,
	"Mobile": true, "Gecko": true, "Version": true, "AppleWebKit": true,
	"Mozilla": true, "Vivaldi": true, "YaBrowser": true, "UCBrowser": true,
	"Konqueror": true, "Netscape": true,
}

// looksLikeNoisePath reports whether a path-shaped string literal is actually a
// regex pattern, base64 alphabet dump, MIME type, or browser/UA token — the four
// classes of non-endpoint that pollute path extraction on real minified bundles.
func looksLikeNoisePath(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return false
	}
	// 1. regex patterns.
	for _, sig := range regexMetaSignals {
		if strings.Contains(v, sig) {
			return true
		}
	}
	// 2. base64 alphabet dump: long run of only base64 chars carrying '+' and '='.
	if len(v) >= 32 && strings.ContainsRune(v, '+') && strings.ContainsRune(v, '=') && isAllBase64Chars(v) {
		return true
	}
	// 3. MIME types (type/subtype with a known top-level type).
	if isMIMEType(v) {
		return true
	}
	// 4. bare UA product tokens: a leading run of letters that is a known UA
	//    product token followed by a non-letter ("OPR/", "CriOS\/", "Konqueror[").
	if !strings.HasPrefix(v, "/") {
		n := 0
		for n < len(v) && ((v[n] >= 'A' && v[n] <= 'Z') || (v[n] >= 'a' && v[n] <= 'z')) {
			n++
		}
		if n > 0 && n < len(v) && uaTokens[v[:n]] {
			return true
		}
	}
	return false
}

func isAllBase64Chars(v string) bool {
	for _, r := range v {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}

func isMIMEType(v string) bool {
	for _, p := range mimeTopLevelTypes {
		if !strings.HasPrefix(v, p) {
			continue
		}
		rest := v[len(p):]
		if rest == "" {
			return false
		}
		for _, r := range rest {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '+' || r == '-' || r == '_') {
				return false
			}
		}
		return true
	}
	return false
}

func hasPathSignal(value string) bool {
	for _, ch := range value {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '*' {
			return true
		}
	}
	return false
}

func methodFromFunction(fn string) string {
	parts := strings.Split(fn, ".")
	last := strings.ToUpper(parts[len(parts)-1])
	switch last {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return last
	default:
		return ""
	}
}

func methodFromObjectText(text string) string {
	_, method := objectURLAndMethod(text)
	return method
}

func objectURLAndMethod(text string) (string, string) {
	url := firstStringProperty(text, "url", "uri", "endpoint")
	method := strings.ToUpper(firstStringProperty(text, "method", "type"))
	if method == "" {
		method = "GET"
	}
	return url, method
}

func firstStringProperty(text string, keys ...string) string {
	for _, key := range keys {
		if value, ok := scanStringProperty(text, key); ok {
			return value
		}
	}
	return ""
}

func scanStringProperty(text, key string) (string, bool) {
	re := regexp.MustCompile("(?i)\\b" + regexp.QuoteMeta(key) + "\\s*:")
	loc := re.FindStringIndex(text)
	if loc == nil {
		return "", false
	}
	i := loc[1]
	for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n') {
		i++
	}
	if i >= len(text) || (text[i] != '"' && text[i] != '\'' && text[i] != '`') {
		return "", false
	}
	quote := text[i]
	end := i + 1
	for end < len(text) {
		if text[end] == '\\' {
			end += 2
			continue
		}
		if text[end] == quote {
			raw := text[i : end+1]
			lit, ok := parseJSLiteral(raw)
			return lit.Value, ok
		}
		end++
	}
	return "", false
}
