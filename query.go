package jsluice

import (
	"fmt"

	"github.com/odvcencio/gotreesitter"
)

func queryFindings(path string, tree *gotreesitter.Tree, querySource string) ([]Finding, error) {
	if querySource == "" {
		return nil, fmt.Errorf("query mode requires a query")
	}
	if tree == nil {
		return nil, nil
	}
	lang := tree.Language()
	query, err := gotreesitter.NewQuery(querySource, lang)
	if err != nil {
		return nil, err
	}
	cursor := query.Exec(tree.RootNode(), lang, tree.Source())
	var out []Finding
	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}
		for _, cap := range match.Captures {
			out = append(out, Finding{
				Kind:       "query",
				Value:      cap.Text(tree.Source()),
				Location:   locationForNode(path, cap.Node),
				Context:    lineContext(tree.Source(), int(cap.Node.StartByte())),
				Rule:       cap.Name,
				Confidence: 1,
			})
		}
	}
	return dedupeFindings(out), nil
}
