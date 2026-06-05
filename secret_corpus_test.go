package jsluice

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type secretCorpusManifest struct {
	Files []secretCorpusFile `json:"files"`
}

type secretCorpusFile struct {
	Path     string                 `json:"path"`
	Expected []secretCorpusExpected `json:"expected"`
}

type secretCorpusExpected struct {
	Rule  string   `json:"rule"`
	Value string   `json:"value"`
	Parts []string `json:"parts"`
}

type secretCorpusMetrics struct {
	TruePositive  int
	FalsePositive int
	FalseNegative int
	Duplicates    int
	Precision     float64
	Recall        float64
}

func TestSecretCorpusPrecisionRecall(t *testing.T) {
	metrics := scoreSecretCorpus(t, "testdata/secret_corpus/manifest.json")
	t.Logf("secret corpus precision=%.3f recall=%.3f tp=%d fp=%d fn=%d duplicates=%d",
		metrics.Precision,
		metrics.Recall,
		metrics.TruePositive,
		metrics.FalsePositive,
		metrics.FalseNegative,
		metrics.Duplicates,
	)
	if metrics.Precision != 1.0 || metrics.Recall != 1.0 || metrics.Duplicates != 0 {
		t.Fatalf("secret corpus metrics = %+v, want perfect fixture precision/recall and no duplicates", metrics)
	}
}

func scoreSecretCorpus(t *testing.T, manifestPath string) secretCorpusMetrics {
	t.Helper()
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", manifestPath, err)
	}
	var manifest secretCorpusManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("Unmarshal(%s): %v", manifestPath, err)
	}
	baseDir := filepath.Dir(manifestPath)
	expected := map[string]bool{}
	found := map[string]bool{}
	var metrics secretCorpusMetrics

	for _, file := range manifest.Files {
		for _, want := range file.Expected {
			expected[secretCorpusKey(file.Path, want.Rule, want.secretValue())] = true
		}
		source, err := os.ReadFile(filepath.Join(baseDir, file.Path))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file.Path, err)
		}
		res, err := AnalyzeSource(file.Path, source, Options{Mode: ModeSecrets})
		if err != nil {
			t.Fatalf("AnalyzeSource(%s): %v", file.Path, err)
		}
		seenInFile := map[string]bool{}
		for _, finding := range res.Findings {
			if finding.Kind != "secret" {
				continue
			}
			key := secretCorpusKey(file.Path, finding.Rule, finding.Value)
			if seenInFile[key] {
				metrics.Duplicates++
				continue
			}
			seenInFile[key] = true
			found[key] = true
		}
	}

	for key := range found {
		if expected[key] {
			metrics.TruePositive++
		} else {
			metrics.FalsePositive++
		}
	}
	for key := range expected {
		if !found[key] {
			metrics.FalseNegative++
		}
	}
	metrics.Precision = ratio(metrics.TruePositive, metrics.TruePositive+metrics.FalsePositive)
	metrics.Recall = ratio(metrics.TruePositive, metrics.TruePositive+metrics.FalseNegative)
	return metrics
}

func (e secretCorpusExpected) secretValue() string {
	if e.Value != "" {
		return e.Value
	}
	return strings.Join(e.Parts, "")
}

func secretCorpusKey(path, rule, value string) string {
	return path + "\x00" + rule + "\x00" + value
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 1
	}
	return float64(numerator) / float64(denominator)
}
