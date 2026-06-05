package jsluice

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
	"github.com/odvcencio/gotreesitter"
)

var ExpressionPlaceholder = "EXPR"

type Node struct {
	node        *gotreesitter.Node
	source      []byte
	lang        *gotreesitter.Language
	tree        *gotreesitter.Tree
	captureName string
}

func NewNode(n *gotreesitter.Node, source []byte) *Node {
	return newNode(n, source, nil, nil)
}

func newNode(n *gotreesitter.Node, source []byte, lang *gotreesitter.Language, tree *gotreesitter.Tree) *Node {
	if tree != nil && lang == nil {
		lang = tree.Language()
	}
	return &Node{node: n, source: source, lang: lang, tree: tree}
}

func (n *Node) IsValid() bool {
	return n != nil && n.node != nil
}

func (n *Node) language() *gotreesitter.Language {
	if n == nil {
		return nil
	}
	if n.lang != nil {
		return n.lang
	}
	if n.tree != nil {
		return n.tree.Language()
	}
	return nil
}

func (n *Node) AsObject() Object {
	if n == nil {
		return NewObject(nil, nil)
	}
	return NewObject(n, n.source)
}

func (n *Node) Content() string {
	if !n.IsValid() {
		return ""
	}
	return n.node.Text(n.source)
}

func (n *Node) Type() string {
	if !n.IsValid() || n.language() == nil {
		return ""
	}
	return n.node.Type(n.language())
}

func (n *Node) ChildByFieldName(name string) *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.ChildByFieldName(name, n.language()))
}

func (n *Node) Child(index int) *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.Child(index))
}

func (n *Node) NamedChild(index int) *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.NamedChild(index))
}

func (n *Node) ChildCount() int {
	if !n.IsValid() {
		return 0
	}
	return n.node.ChildCount()
}

func (n *Node) NamedChildCount() int {
	if !n.IsValid() {
		return 0
	}
	return n.node.NamedChildCount()
}

func (n *Node) Children() []*Node {
	out := make([]*Node, 0, n.ChildCount())
	for i := 0; i < n.ChildCount(); i++ {
		out = append(out, n.Child(i))
	}
	return out
}

func (n *Node) NamedChildren() []*Node {
	out := make([]*Node, 0, n.NamedChildCount())
	for i := 0; i < n.NamedChildCount(); i++ {
		out = append(out, n.NamedChild(i))
	}
	return out
}

func (n *Node) NextSibling() *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.NextSibling())
}

func (n *Node) NextNamedSibling() *Node {
	for sibling := n.NextSibling(); sibling != nil; sibling = sibling.NextSibling() {
		if sibling.IsNamed() {
			return sibling
		}
	}
	return nil
}

func (n *Node) PrevSibling() *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.PrevSibling())
}

func (n *Node) PrevNamedSibling() *Node {
	for sibling := n.PrevSibling(); sibling != nil; sibling = sibling.PrevSibling() {
		if sibling.IsNamed() {
			return sibling
		}
	}
	return nil
}

func (n *Node) Parent() *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.Parent())
}

func (n *Node) IsNamed() bool {
	return n.IsValid() && n.node.IsNamed()
}

func (n *Node) RawString() string {
	return dequote(n.Content())
}

func (n *Node) DecodedString() string {
	return DecodeString(n.Content())
}

func (n *Node) CollapsedString() string {
	if !n.IsValid() {
		return ""
	}
	switch n.Type() {
	case "binary_expression":
		return fmt.Sprintf("%s%s",
			n.ChildByFieldName("left").CollapsedString(),
			n.ChildByFieldName("right").CollapsedString(),
		)
	case "string":
		return n.RawString()
	case "template_string":
		lit, ok := parseJSLiteral(n.Content())
		if !ok {
			return ExpressionPlaceholder
		}
		return strings.ReplaceAll(lit.Value, "*", ExpressionPlaceholder)
	default:
		return ExpressionPlaceholder
	}
}

func (n *Node) IsStringy() bool {
	if n == nil {
		return false
	}
	if n.Type() == "string" || n.Type() == "template_string" {
		return true
	}
	c := n.Content()
	if len(c) == 0 {
		return false
	}
	switch c[0] {
	case '"', '\'', '`':
		return true
	default:
		return false
	}
}

func (n *Node) AsGoType() any {
	if n == nil {
		return nil
	}
	switch n.Type() {
	case "string", "template_string":
		return n.DecodedString()
	case "number":
		return n.AsNumber()
	case "object":
		return n.AsMap()
	case "array":
		return n.AsArray()
	case "false":
		return false
	case "true":
		return true
	case "null":
		return nil
	default:
		return n.Content()
	}
}

func (n *Node) AsMap() map[string]any {
	if n == nil || n.Type() != "object" {
		return map[string]any{}
	}
	out := make(map[string]any)
	for _, pair := range n.NamedChildren() {
		if pair.Type() != "pair" {
			continue
		}
		key := DecodeString(pair.ChildByFieldName("key").RawString())
		value := pair.ChildByFieldName("value").AsGoType()
		out[key] = value
	}
	return out
}

func (n *Node) AsArray() []any {
	if n == nil || n.Type() != "array" {
		return []any{}
	}
	out := make([]any, 0, n.NamedChildCount())
	for _, child := range n.NamedChildren() {
		out = append(out, child.AsGoType())
	}
	return out
}

func (n *Node) AsNumber() any {
	if n == nil || n.Type() != "number" {
		return 0
	}
	content := n.Content()
	if strings.Contains(content, ".") {
		f, err := strconv.ParseFloat(content, 64)
		if err != nil {
			return 0
		}
		return f
	}
	i, err := strconv.ParseInt(content, 10, 64)
	if err != nil {
		return 0
	}
	return i
}

func (n *Node) ForEachChild(fn func(*Node)) {
	walkCompatNode(n, fn, false)
}

func (n *Node) ForEachNamedChild(fn func(*Node)) {
	walkCompatNode(n, fn, true)
}

func walkCompatNode(n *Node, fn func(*Node), namedOnly bool) {
	if n == nil {
		return
	}
	for _, child := range n.Children() {
		if !namedOnly || child.IsNamed() {
			fn(child)
		}
		walkCompatNode(child, fn, namedOnly)
	}
}

func (n *Node) Format() (string, error) {
	source := n.Content()
	return jsbeautifier.Beautify(&source, jsbeautifier.DefaultOptions())
}

func (n *Node) Query(query string, fn func(*Node)) {
	n.QueryMulti(query, func(qr QueryResult) {
		for _, node := range qr {
			fn(node)
		}
	})
}

type QueryResult map[string]*Node

func NewQueryResult(nodes ...*Node) QueryResult {
	out := make(QueryResult)
	for _, n := range nodes {
		out.Add(n)
	}
	return out
}

func (qr QueryResult) Add(n *Node) {
	if n == nil || n.CaptureName() == "" {
		return
	}
	qr[n.CaptureName()] = n
}

func (qr QueryResult) Has(captureName string) bool {
	_, ok := qr[captureName]
	return ok
}

func (qr QueryResult) Get(captureName string) *Node {
	return qr[captureName]
}

func (n *Node) QueryMulti(querySource string, fn func(QueryResult)) {
	if !n.IsValid() || n.language() == nil {
		return
	}
	q, err := gotreesitter.NewQuery(querySource, n.language())
	if err != nil {
		return
	}
	cursor := q.Exec(n.node, n.language(), n.source)
	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}
		qr := NewQueryResult()
		for _, capture := range match.Captures {
			node := n.wrap(capture.Node)
			node.captureName = capture.Name
			qr.Add(node)
		}
		if len(qr) == 0 {
			continue
		}
		fn(qr)
	}
}

func (n *Node) CaptureName() string {
	if n == nil {
		return ""
	}
	return n.captureName
}

func (n *Node) wrap(child *gotreesitter.Node) *Node {
	if child == nil {
		return nil
	}
	return &Node{node: child, source: n.source, lang: n.language(), tree: n.tree}
}

func dequote(in string) string {
	return strings.Trim(in, "'\"`")
}
