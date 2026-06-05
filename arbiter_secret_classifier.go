package jsluice

import (
	"fmt"
	"sync"

	"m31labs.dev/arbiter"
)

var defaultSecretClassifier secretClassifier = newArbiterSecretClassifier()

type secretClassifier interface {
	Classify(secretCandidate) ([]secretMatch, error)
}

type arbiterSecretClassifier struct {
	once     sync.Once
	program  *arbiter.Program
	initErr  error
	fallback goSecretClassifier
}

type goSecretClassifier struct{}

func newArbiterSecretClassifier() *arbiterSecretClassifier {
	return &arbiterSecretClassifier{}
}

func (c *arbiterSecretClassifier) Classify(candidate secretCandidate) ([]secretMatch, error) {
	c.once.Do(func() {
		source, err := secretRulesFS.ReadFile("rules/secrets.arb")
		if err != nil {
			c.initErr = err
			return
		}
		c.program, c.initErr = arbiter.Compile(source)
	})
	if c.initErr != nil || c.program == nil {
		return c.fallback.Classify(candidate)
	}
	ctx := map[string]any{
		"candidate": map[string]any{
			"value":       candidate.Value,
			"context":     candidate.Context,
			"length":      len(candidate.Value),
			"entropy":     shannonEntropy(candidate.Value),
			"recoveredBy": candidate.RecoveredBy,
			"placeholder": isPlaceholderSecretCandidate(candidate.Value, candidate.Context),
		},
	}
	matched, err := arbiter.Eval(c.program, arbiter.DataFromMap(ctx, c.program))
	if err != nil {
		return nil, err
	}
	out := make([]secretMatch, 0, len(matched))
	for _, match := range matched {
		if match.Action != "Secret" {
			continue
		}
		class, ok := stringParam(match.Params, "class")
		if !ok {
			return nil, fmt.Errorf("arbiter rule %s emitted Secret without class", match.Name)
		}
		confidence, ok := floatParam(match.Params, "confidence")
		if !ok {
			return nil, fmt.Errorf("arbiter rule %s emitted Secret without confidence", match.Name)
		}
		out = append(out, secretMatch{class: class, confidence: confidence})
	}
	return normalizeSecretMatches(out), nil
}

func (goSecretClassifier) Classify(candidate secretCandidate) ([]secretMatch, error) {
	return classifySecretWithGoRules(candidate), nil
}

func stringParam(params map[string]any, key string) (string, bool) {
	value, ok := params[key]
	if !ok {
		return "", false
	}
	s, ok := value.(string)
	return s, ok
}

func floatParam(params map[string]any, key string) (float64, bool) {
	value, ok := params[key]
	if !ok {
		return 0, false
	}
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
	}
}
