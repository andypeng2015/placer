package jsluice

import (
	"strings"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

func PrintTree(source []byte) string {
	lang := grammars.JavascriptLanguage()
	parser := gotreesitter.NewParser(lang)
	tree, err := parser.Parse(source)
	if err != nil || tree == nil {
		return ""
	}
	defer tree.Release()
	var b strings.Builder
	writeTree(&b, tree.RootNode(), lang, source, 0, "")
	return b.String()
}

func writeTree(b *strings.Builder, n *gotreesitter.Node, lang *gotreesitter.Language, source []byte, depth int, field string) {
	if n == nil || !n.IsNamed() {
		return
	}
	b.WriteString(strings.Repeat("  ", depth))
	if field != "" {
		b.WriteString(field)
		b.WriteString(": ")
	}
	b.WriteString(n.Type(lang))
	if n.ChildCount() == 0 {
		text := strings.TrimSpace(n.Text(source))
		if text != "" {
			b.WriteString(" (")
			b.WriteString(text)
			b.WriteString(")")
		}
	}
	b.WriteByte('\n')
	for i := 0; i < n.ChildCount(); i++ {
		child := n.Child(i)
		if child == nil || !child.IsNamed() {
			continue
		}
		writeTree(b, child, lang, source, depth+1, n.FieldNameForChild(i, lang))
	}
}

func formatJavaScript(source string) string {
	var b strings.Builder
	indent := 0
	needIndent := false
	for i := 0; i < len(source); i++ {
		ch := source[i]
		switch ch {
		case '{':
			b.WriteByte(ch)
			b.WriteByte('\n')
			indent++
			needIndent = true
		case '}':
			if !needIndent {
				b.WriteByte('\n')
			}
			if indent > 0 {
				indent--
			}
			b.WriteString(strings.Repeat("    ", indent))
			b.WriteByte(ch)
			needIndent = false
		case ';':
			b.WriteByte(ch)
			b.WriteByte('\n')
			needIndent = true
		case '\n', '\r':
			if !needIndent {
				b.WriteByte('\n')
				needIndent = true
			}
		default:
			if needIndent && ch != ' ' && ch != '\t' {
				b.WriteString(strings.Repeat("    ", indent))
				needIndent = false
			}
			b.WriteByte(ch)
		}
	}
	return strings.TrimSpace(b.String())
}
