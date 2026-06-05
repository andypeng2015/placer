package jsluice

import (
	"embed"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/odvcencio/gotreesitter"
)

//go:embed rules/secrets.arb
var secretRulesFS embed.FS

var secretTokenRe = regexp.MustCompile(`[A-Za-z0-9_./+=:-]{20,}`)

type secretCandidate struct {
	Value       string
	Context     string
	Location    Location
	RecoveredBy string
}

func extractSecretFindings(path string, tree *gotreesitter.Tree) ([]Finding, error) {
	candidates := collectSecretCandidates(path, tree)
	var out []Finding
	for _, candidate := range candidates {
		matches, err := classifySecret(candidate)
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			out = append(out, Finding{
				Kind:       "secret",
				Value:      candidate.Value,
				Location:   candidate.Location,
				Context:    candidate.Context,
				Confidence: match.confidence,
				Rule:       match.class,
			})
		}
	}
	return dedupeFindings(out), nil
}

func collectSecretCandidates(path string, tree *gotreesitter.Tree) []secretCandidate {
	if tree == nil {
		return nil
	}
	source := tree.Source()
	var out []secretCandidate
	seen := map[string]struct{}{}
	for _, recovered := range collectRecoveredStrings(tree) {
		n := recovered.Node
		ctx := lineContext(source, int(n.StartByte()))
		if recovered.Recovered != "" && recovered.Recovered != "literal" {
			ctx = ctx + " [recovered: " + recovered.Recovered + "]"
		}
		loc := locationForNode(path, n)
		for _, token := range secretTokens(recovered.Value) {
			if suppressSecretCandidate(token, ctx) {
				continue
			}
			key := fmt.Sprintf("%s\x00%d\x00%d\x00%s", token, loc.ByteStart, loc.ByteEnd, recovered.Recovered)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, secretCandidate{Value: token, Context: ctx, Location: loc, RecoveredBy: recovered.Recovered})
		}
	}
	return out
}

func secretTokens(value string) []string {
	var out []string
	for _, match := range secretTokenRe.FindAllString(value, -1) {
		match = strings.Trim(match, ".,;:)]}\"'")
		if len(match) < 20 {
			continue
		}
		out = append(out, match)
	}
	if len(value) >= 20 && !strings.ContainsAny(value, " \t\r\n") {
		out = append(out, strings.Trim(value, ".,;:)]}\"'"))
	}
	return uniqueStrings(out)
}

type secretMatch struct {
	class      string
	confidence float64
}

func classifySecret(candidate secretCandidate) ([]secretMatch, error) {
	return defaultSecretClassifier.Classify(candidate)
}

func classifySecretWithGoRules(candidate secretCandidate) []secretMatch {
	value := candidate.Value
	var out []secretMatch
	for _, rule := range builtInSecretRules {
		if rule.re.MatchString(value) {
			out = append(out, secretMatch{class: rule.class, confidence: rule.confidence})
		}
	}
	if len(out) == 0 && len(value) >= 24 && shannonEntropy(value) >= 4.0 && secretContextRe.MatchString(candidate.Context) {
		out = append(out, secretMatch{class: "generic_high_entropy", confidence: 0.58})
	}
	return out
}

type builtInSecretRule struct {
	class      string
	confidence float64
	re         *regexp.Regexp
}

var (
	builtInSecretRules = []builtInSecretRule{
		{class: "aws_access_key", confidence: 0.98, re: regexp.MustCompile(`^(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}$`)},
		{class: "github_token", confidence: 0.95, re: regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9_]{36,255}$`)},
		{class: "stripe_secret_key", confidence: 0.95, re: regexp.MustCompile(`^sk_(test|live)_[0-9A-Za-z]{16,}$`)},
		{class: "google_api_key", confidence: 0.93, re: regexp.MustCompile(`^AIza[0-9A-Za-z_-]{35}$`)},
		{class: "slack_token", confidence: 0.92, re: regexp.MustCompile(`^xox[baprs]-[0-9A-Za-z-]{20,}$`)},
		{class: "jwt", confidence: 0.82, re: regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}$`)},
	}
	secretContextRe = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|passwd|password|bearer|authorization)`)
)

func suppressSecretCandidate(value, context string) bool {
	lower := strings.ToLower(value + " " + context)
	if strings.Contains(lower, "example") || strings.Contains(lower, "placeholder") || strings.Contains(lower, "your_") {
		return true
	}
	if strings.Contains(lower, "000000000000") || strings.Contains(lower, "xxxxxxxx") {
		return true
	}
	if strings.HasPrefix(strings.ToLower(value), "http://") || strings.HasPrefix(strings.ToLower(value), "https://") {
		return true
	}
	return false
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	var total int
	for _, r := range s {
		counts[r]++
		total++
	}
	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:0]
	seen := map[string]struct{}{}
	for _, value := range in {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
