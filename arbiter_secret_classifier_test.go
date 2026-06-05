package jsluice

import "testing"

func TestArbiterSecretClassifierEvaluatesEmbeddedRules(t *testing.T) {
	classifier := newArbiterSecretClassifier()
	matches, err := classifier.Classify(secretCandidate{
		Value:   "AKIA1234567890ABCDEF",
		Context: `const key = "AKIA1234567890ABCDEF"`,
	})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if classifier.initErr != nil {
		t.Fatalf("Arbiter initErr = %v", classifier.initErr)
	}
	for _, match := range matches {
		if match.class == "aws_access_key" && match.confidence == 0.98 {
			return
		}
	}
	t.Fatalf("missing aws_access_key from Arbiter matches %#v", matches)
}
