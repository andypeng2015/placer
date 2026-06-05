package jsluice

type CompatFinding struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Source  string `json:"source,omitempty"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Method  string `json:"method,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Context string `json:"context,omitempty"`
}

func JSLuiceCompat(result Result) []CompatFinding {
	out := make([]CompatFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		out = append(out, CompatFinding{
			Type:    finding.Kind,
			Value:   finding.Value,
			Source:  finding.Location.File,
			Line:    finding.Location.Line,
			Column:  finding.Location.Column,
			Method:  finding.Method,
			Rule:    finding.Rule,
			Context: finding.Context,
		})
	}
	return out
}
