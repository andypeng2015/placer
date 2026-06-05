package jsluice

import "strings"

func matchXHR() URLMatcher {
	return URLMatcher{"call_expression", func(n *Node) *URL {
		fn := n.ChildByFieldName("function")
		if fn == nil || !strings.HasSuffix(fn.Content(), ".open") {
			return nil
		}
		args := n.ChildByFieldName("arguments")
		method := namedChild(args, 0).RawString()
		if !isHTTPMethod(method) {
			return nil
		}
		urlArg := namedChild(args, 1)
		if !urlArg.IsStringy() {
			return nil
		}
		match := &URL{URL: urlArg.CollapsedString(), Method: method, Type: "XMLHttpRequest.open", Source: n.Content()}
		objectName := strings.TrimSuffix(fn.Content(), ".open")
		scope := xhrScope(n)
		headers := make(map[string]string)
		if scope != nil {
			scope.Query(`(call_expression function: (member_expression) @fn arguments: (arguments (string))) @call`, func(candidate *Node) {
				if candidate.Type() != "call_expression" {
					return
				}
				name := candidate.ChildByFieldName("function").Content()
				if !strings.HasSuffix(name, ".setRequestHeader") || !strings.HasPrefix(name, objectName) {
					return
				}
				cargs := candidate.ChildByFieldName("arguments")
				header := namedChild(cargs, 0)
				if header == nil || header.Type() != "string" {
					return
				}
				value := ""
				if v := namedChild(cargs, 1); v != nil && v.Type() == "string" {
					value = v.RawString()
				}
				if _, exists := headers[header.RawString()]; !exists {
					headers[header.RawString()] = value
				}
			})
		}
		match.Headers = headers
		return match
	}}
}

func isHTTPMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func xhrScope(n *Node) *Node {
	parent := n.Parent()
	if parent == nil || !parent.IsValid() {
		return n
	}
	for {
		candidate := parent.Parent()
		if candidate == nil {
			return parent
		}
		parent = candidate
		switch parent.Type() {
		case "function_declaration", "function", "arrow_function":
			return parent
		}
	}
}
