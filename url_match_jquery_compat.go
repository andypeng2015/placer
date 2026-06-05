package jsluice

import "strings"

func matchJQuery() URLMatcher {
	return URLMatcher{"call_expression", func(n *Node) *URL {
		fn := n.ChildByFieldName("function")
		if fn == nil {
			return nil
		}
		callName := fn.Content()
		switch callName {
		case "$.get", "$.post", "$.ajax", "jQuery.get", "jQuery.post", "jQuery.ajax":
		default:
			return nil
		}

		args := n.ChildByFieldName("arguments")
		first := namedChild(args, 0)
		if first == nil {
			return nil
		}
		second := namedChild(args, 1)
		m := &URL{Type: callName, Source: n.Content()}
		if strings.HasSuffix(callName, ".post") {
			m.Method = "POST"
		} else if strings.HasSuffix(callName, ".get") {
			m.Method = "GET"
		}

		var settingsNode *Node
		if first.IsStringy() {
			m.URL = first.CollapsedString()
			if strings.HasSuffix(callName, ".ajax") {
				settingsNode = second
			} else {
				params := second.AsObject().GetKeys()
				if m.Method == "GET" {
					m.QueryParams = params
				} else {
					m.BodyParams = params
					m.ContentType = "application/x-www-form-urlencoded; charset=UTF-8"
				}
			}
		}
		if first.Type() == "object" {
			settingsNode = first
		}
		if settingsNode == nil {
			return m
		}
		settings := settingsNode.AsObject()
		if m.URL == "" {
			m.URL = settings.GetNode("url").CollapsedString()
		}
		headers := settings.GetObject("headers")
		m.Headers = headers.AsMap()
		if m.Method == "" {
			m.Method = settings.GetString("method", settings.GetString("type", "GET"))
		}
		params := settings.GetObject("data").GetKeys()
		if m.Method == "GET" {
			m.QueryParams = params
		} else {
			m.BodyParams = params
		}
		if m.Method != "GET" {
			ct := headers.GetStringI("content-type", "")
			if ct == "" {
				ct = settings.GetString("contentType", "application/x-www-form-urlencoded; charset=UTF-8")
			}
			m.ContentType = ct
		}
		return m
	}}
}
