package jsluice

import (
	"bytes"
	"unicode"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

type Analyzer struct {
	urlMatchers        []URLMatcher
	rootNode           *Node
	userSecretMatchers []SecretMatcher
	tree               *gotreesitter.Tree
	source             []byte
	lang               *gotreesitter.Language
}

func NewAnalyzer(source []byte) *Analyzer {
	if isProbablyHTML(source) {
		source = extractInlineJS(source)
	}
	lang := grammars.JavascriptLanguage()
	parser := gotreesitter.NewParser(lang)
	tree, _ := parser.Parse(source)
	var root *Node
	if tree != nil {
		root = newNode(tree.RootNode(), source, lang, tree)
	}
	return &Analyzer{
		urlMatchers: AllURLMatchers(),
		rootNode:    root,
		tree:        tree,
		source:      source,
		lang:        lang,
	}
}

func (a *Analyzer) Query(q string, fn func(*Node)) {
	if a == nil || a.rootNode == nil {
		return
	}
	a.rootNode.Query(q, fn)
}

func (a *Analyzer) QueryMulti(q string, fn func(QueryResult)) {
	if a == nil || a.rootNode == nil {
		return
	}
	a.rootNode.QueryMulti(q, fn)
}

func (a *Analyzer) RootNode() *Node {
	if a == nil {
		return nil
	}
	return a.rootNode
}

func isProbablyHTML(source []byte) bool {
	for _, b := range source {
		if unicode.IsSpace(rune(b)) {
			continue
		}
		return b == '<'
	}
	return false
}

func extractInlineJS(source []byte) []byte {
	lower := bytes.ToLower(source)
	var out []byte
	searchFrom := 0
	for {
		open := bytes.Index(lower[searchFrom:], []byte("<script"))
		if open < 0 {
			break
		}
		open += searchFrom
		tagEnd := bytes.IndexByte(lower[open:], '>')
		if tagEnd < 0 {
			break
		}
		contentStart := open + tagEnd + 1
		close := bytes.Index(lower[contentStart:], []byte("</script>"))
		if close < 0 {
			break
		}
		close += contentStart
		out = append(out, source[contentStart:close]...)
		out = append(out, '\n')
		searchFrom = close + len("</script>")
	}
	if len(out) == 0 {
		return source
	}
	return out
}
