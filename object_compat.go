package jsluice

import "strings"

type Object struct {
	node   *Node
	source []byte
}

func NewObject(n *Node, source []byte) Object {
	return Object{node: n, source: source}
}

func (o Object) HasValidNode() bool {
	return o.node != nil && o.node.IsValid() && o.node.Type() == "object"
}

func (o Object) AsMap() map[string]string {
	out := make(map[string]string)
	if !o.HasValidNode() {
		return out
	}
	for _, key := range o.GetKeys() {
		out[key] = o.GetString(key, "")
	}
	return out
}

func (o Object) GetNodeFunc(fn func(key string) bool) *Node {
	if !o.HasValidNode() {
		return nil
	}
	for _, pair := range o.node.NamedChildren() {
		if pair.Type() != "pair" {
			continue
		}
		key := pair.ChildByFieldName("key")
		if key == nil || !fn(key.RawString()) {
			continue
		}
		return pair.ChildByFieldName("value")
	}
	return nil
}

func (o Object) GetNode(key string) *Node {
	return o.GetNodeFunc(func(candidate string) bool { return candidate == key })
}

func (o Object) GetNodeI(key string) *Node {
	key = strings.ToLower(key)
	return o.GetNodeFunc(func(candidate string) bool { return strings.ToLower(candidate) == key })
}

func (o Object) GetKeys() []string {
	if !o.HasValidNode() {
		return nil
	}
	out := make([]string, 0, o.node.NamedChildCount())
	for _, pair := range o.node.NamedChildren() {
		if pair.Type() != "pair" {
			continue
		}
		key := pair.ChildByFieldName("key")
		if key != nil {
			out = append(out, key.RawString())
		}
	}
	return out
}

func (o Object) GetObject(key string) Object {
	return NewObject(o.GetNode(key), o.source)
}

func (o Object) GetString(key, defaultVal string) string {
	value := o.GetNode(key)
	if value == nil || (value.Type() != "string" && value.Type() != "template_string") {
		return defaultVal
	}
	return value.RawString()
}

func (o Object) GetStringI(key, defaultVal string) string {
	value := o.GetNodeI(key)
	if value == nil || (value.Type() != "string" && value.Type() != "template_string") {
		return defaultVal
	}
	return value.RawString()
}
