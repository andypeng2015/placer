package jsluice

import (
	"strings"
	"testing"
)

// Values are assembled from fragments at runtime so this source file never
// contains a complete secret-shaped literal — which would trip secret scanners
// (including GitHub push protection), i.e. the very class of pattern placer
// itself detects.
func TestExpandedSecretProviders(t *testing.T) {
	j := func(parts ...string) string { return strings.Join(parts, "") }
	cases := []struct {
		value string
		class string
	}{
		{j("sk-", "ant-", strings.Repeat("a", 30)), "anthropic_api_key"},
		{j("sk-", strings.Repeat("b", 40)), "openai_api_key"},
		{j("glpat", "-", strings.Repeat("c", 24)), "gitlab_pat"},
		{j("SK", strings.Repeat("0", 32)), "twilio_api_key"},
		{j("SG", ".", strings.Repeat("d", 22), ".", strings.Repeat("e", 43)), "sendgrid_api_key"},
		{j("npm", "_", strings.Repeat("f", 36)), "npm_token"},
		{j("github", "_pat_", strings.Repeat("g", 82)), "github_fine_grained_pat"},
	}
	for _, c := range cases {
		matches, err := classifySecret(secretCandidate{Value: c.value})
		if err != nil {
			t.Fatalf("classifySecret: %v", err)
		}
		found := false
		for _, m := range matches {
			if m.class == c.class {
				found = true
			}
		}
		if !found {
			t.Errorf("missing class %q for assembled candidate; got %v", c.class, matches)
		}
	}
}
