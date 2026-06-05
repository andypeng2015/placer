package jsluice

import "github.com/odvcencio/gotreesitter"

func walkNode(n *gotreesitter.Node, visit func(*gotreesitter.Node)) {
	if n == nil {
		return
	}
	visit(n)
	for i := 0; i < n.ChildCount(); i++ {
		walkNode(n.Child(i), visit)
	}
}

func literalNodes(n *gotreesitter.Node, lang *gotreesitter.Language) []*gotreesitter.Node {
	var out []*gotreesitter.Node
	walkNode(n, func(child *gotreesitter.Node) {
		if isLiteralType(child.Type(lang)) {
			out = append(out, child)
		}
	})
	return out
}

func isLiteralType(typ string) bool {
	switch typ {
	case "string", "template_string":
		return true
	default:
		return false
	}
}

func locationForNode(file string, n *gotreesitter.Node) Location {
	if n == nil {
		return Location{File: file}
	}
	start := n.StartPoint()
	return Location{
		File:      file,
		Line:      int(start.Row) + 1,
		Column:    int(start.Column) + 1,
		ByteStart: int(n.StartByte()),
		ByteEnd:   int(n.EndByte()),
	}
}
