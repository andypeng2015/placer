package jsluice

import (
	"net/url"
	"regexp"
	"strings"
)

type URL struct {
	URL         string            `json:"url"`
	QueryParams []string          `json:"queryParams"`
	BodyParams  []string          `json:"bodyParams"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
	Type        string            `json:"type"`
	Source      string            `json:"source,omitempty"`
	Filename    string            `json:"filename,omitempty"`
}

type URLMatcher struct {
	Type string
	Fn   func(*Node) *URL
}

func (a *Analyzer) AddURLMatcher(u URLMatcher) {
	if a.urlMatchers == nil {
		a.urlMatchers = make([]URLMatcher, 0)
	}
	a.urlMatchers = append(a.urlMatchers, u)
}

func (a *Analyzer) DisableDefaultURLMatchers() {
	a.urlMatchers = make([]URLMatcher, 0)
}

func (a *Analyzer) GetURLs() []*URL {
	if a == nil || a.rootNode == nil {
		return nil
	}
	matches := make([]*URL, 0)
	onlyExprRe := regexp.MustCompile("[^A-Z-a-z]")
	enter := func(n *Node) {
		for _, matcher := range a.urlMatchers {
			if matcher.Type != n.Type() {
				continue
			}
			match := matcher.Fn(n)
			if match == nil {
				continue
			}
			match.URL = DecodeString(match.URL)
			if match.QueryParams == nil {
				match.QueryParams = []string{}
			}
			if match.BodyParams == nil {
				match.BodyParams = []string{}
			}
			lower := strings.ToLower(match.URL)
			if strings.HasPrefix(lower, "data:") ||
				strings.HasPrefix(lower, "tel:") ||
				strings.HasPrefix(lower, "about:") ||
				strings.HasPrefix(lower, "javascript:") {
				continue
			}
			letters := onlyExprRe.ReplaceAllString(match.URL, "")
			if strings.ReplaceAll(letters, ExpressionPlaceholder, "") == "" {
				continue
			}
			u, err := url.Parse(match.URL)
			if err == nil {
				if u.Hostname() == "www.w3.org" {
					continue
				}
				for p := range u.Query() {
					if p == ExpressionPlaceholder {
						continue
					}
					match.QueryParams = append(match.QueryParams, p)
				}
			}
			match.QueryParams = uniqueComparable(match.QueryParams)
			matches = append(matches, match)
		}
	}
	a.Query("[(assignment_expression) (call_expression) (string) (template_string)] @matches", enter)
	return matches
}

func AllURLMatchers() []URLMatcher {
	assignmentNames := newStringSet([]string{"location", "this.url", "this._url", "this.baseUrl"})
	isInterestingAssignment := func(name string) bool {
		return assignmentNames.Contains(name) ||
			strings.HasSuffix(name, ".href") ||
			strings.HasSuffix(name, ".src") ||
			strings.HasSuffix(name, ".location")
	}
	return []URLMatcher{
		matchXHR(),
		matchJQuery(),
		{"assignment_expression", func(n *Node) *URL {
			left := n.ChildByFieldName("left")
			right := n.ChildByFieldName("right")
			if left == nil || right == nil || !isInterestingAssignment(left.Content()) || !right.IsStringy() {
				return nil
			}
			return &URL{URL: right.CollapsedString(), Method: "GET", Type: "locationAssignment", Source: n.Content()}
		}},
		{"call_expression", func(n *Node) *URL {
			fn := n.ChildByFieldName("function")
			if fn == nil || !strings.HasSuffix(fn.Content(), "location.replace") {
				return nil
			}
			args := n.ChildByFieldName("arguments")
			first := namedChild(args, 0)
			if !first.IsStringy() {
				return nil
			}
			return &URL{URL: first.CollapsedString(), Method: "GET", Type: "locationReplacement", Source: n.Content()}
		}},
		{"call_expression", func(n *Node) *URL {
			fn := n.ChildByFieldName("function")
			if fn == nil || (fn.Content() != "window.open" && fn.Content() != "open") {
				return nil
			}
			first := namedChild(n.ChildByFieldName("arguments"), 0)
			if !first.IsStringy() {
				return nil
			}
			return &URL{URL: first.CollapsedString(), Method: "GET", Type: "window.open", Source: n.Content()}
		}},
		{"call_expression", func(n *Node) *URL {
			fn := n.ChildByFieldName("function")
			if fn == nil || fn.Content() != "fetch" {
				return nil
			}
			args := n.ChildByFieldName("arguments")
			first := namedChild(args, 0)
			if !first.IsStringy() {
				return nil
			}
			init := namedChild(args, 1).AsObject()
			return &URL{
				URL:         first.CollapsedString(),
				Method:      init.GetString("method", "GET"),
				Headers:     init.GetObject("headers").AsMap(),
				ContentType: init.GetObject("headers").GetStringI("content-type", ""),
				Type:        "fetch",
				Source:      n.Content(),
			}
		}},
		{"call_expression", func(n *Node) *URL {
			fn := n.ChildByFieldName("function")
			args := n.ChildByFieldName("arguments")
			first := namedChild(args, 0)
			if fn == nil || !first.IsStringy() {
				return nil
			}
			if !MaybeURL(first.CollapsedString()) {
				return nil
			}
			return &URL{URL: first.CollapsedString(), Type: fn.Content(), Source: n.Content()}
		}},
		{"string", stringLiteralURLMatcher},
		{"template_string", stringLiteralURLMatcher},
	}
}

func stringLiteralURLMatcher(n *Node) *URL {
	trimmed := n.RawString()
	if !MaybeURL(trimmed) {
		return nil
	}
	return &URL{URL: trimmed, Type: "stringLiteral", Source: n.Content()}
}

func namedChild(n *Node, i int) *Node {
	if n == nil {
		return nil
	}
	return n.NamedChild(i)
}
