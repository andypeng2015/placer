package jsluice

import (
	"regexp"
	"strings"

	"github.com/odvcencio/gotreesitter"
)

var absoluteURLRe = regexp.MustCompile("(?i)\\b(?:https?:)?//[^\\s\"'<>`]+")

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
