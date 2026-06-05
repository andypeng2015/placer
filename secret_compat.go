package jsluice

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

type Secret struct {
	Kind     string   `json:"kind"`
	Data     any      `json:"data"`
	Filename string   `json:"filename,omitempty"`
	Severity Severity `json:"severity"`
	Context  any      `json:"context"`
}

type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type SecretMatcher struct {
	Query string
	Fn    func(*Node) *Secret
}

func (a *Analyzer) AddSecretMatcher(s SecretMatcher) {
	a.userSecretMatchers = append(a.userSecretMatchers, s)
}

func (a *Analyzer) AddSecretMatchers(ss []SecretMatcher) {
	a.userSecretMatchers = append(a.userSecretMatchers, ss...)
}

func (a *Analyzer) GetSecrets() []*Secret {
	if a == nil {
		return nil
	}
	out := make([]*Secret, 0)
	nodeCache := make(map[string][]*Node)
	matchers := AllSecretMatchers()
	matchers = append(matchers, a.userSecretMatchers...)
	for _, matcher := range matchers {
		nodes, exists := nodeCache[matcher.Query]
		if !exists {
			a.Query(matcher.Query, func(n *Node) {
				nodes = append(nodes, n)
			})
			nodeCache[matcher.Query] = nodes
		}
		for _, n := range nodes {
			if match := matcher.Fn(n); match != nil {
				out = append(out, match)
			}
		}
	}
	out = append(out, a.getRecoveredSecrets()...)
	return out
}

func (a *Analyzer) getRecoveredSecrets() []*Secret {
	if a == nil || a.tree == nil {
		return nil
	}
	var out []*Secret
	seen := map[string]struct{}{}
	for _, candidate := range collectSecretCandidates("", a.tree) {
		if candidate.RecoveredBy == "" || candidate.RecoveredBy == "literal" {
			continue
		}
		matches, err := classifySecret(candidate)
		if err != nil {
			continue
		}
		for _, match := range matches {
			secret := compatSecretFromMatch(candidate, match)
			if secret == nil {
				continue
			}
			key := secret.Kind + "\x00" + candidate.Value + "\x00" + candidate.RecoveredBy
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, secret)
		}
	}
	return out
}

func compatSecretFromMatch(candidate secretCandidate, match secretMatch) *Secret {
	kind := match.class
	severity := SeverityMedium
	dataKey := "match"
	switch match.class {
	case "aws_access_key":
		kind = "AWSAccessKey"
		severity = SeverityLow
		dataKey = "key"
	case "google_api_key":
		kind = "gcpKey"
		severity = SeverityLow
		dataKey = "key"
	case "github_token":
		kind = "githubKey"
		severity = SeverityLow
		dataKey = "key"
	case "stripe_secret_key":
		kind = "stripeSecretKey"
		severity = SeverityHigh
		dataKey = "key"
	case "slack_token":
		kind = "slackToken"
		severity = SeverityHigh
		dataKey = "token"
	case "jwt":
		kind = "jwt"
		severity = SeverityMedium
		dataKey = "token"
	case "generic_high_entropy":
		kind = "genericHighEntropy"
		severity = SeverityMedium
	}
	data := map[string]string{
		dataKey:       candidate.Value,
		"recoveredBy": candidate.RecoveredBy,
	}
	return &Secret{
		Kind:     kind,
		Data:     data,
		Severity: severity,
		Context: map[string]string{
			"source":      candidate.Context,
			"recoveredBy": candidate.RecoveredBy,
		},
	}
}

func AllSecretMatchers() []SecretMatcher {
	return []SecretMatcher{
		awsMatcher(),
		gcpKeyMatcher(),
		firebaseMatcher(),
		githubKeyMatcher(),
	}
}

func awsMatcher() SecretMatcher {
	awsKey := regexp.MustCompile(`^\w+$`)
	prefixes := []string{"ABIA", "ACCA", "AGPA", "AIDA", "AIPA", "AKIA", "ANPA", "ANVA", "APKA", "AROA", "ASCA", "ASIA"}
	return SecretMatcher{"(string) @matches", func(n *Node) *Secret {
		str := n.RawString()
		if len(str) < 16 || len(str) > 128 || strings.Contains(str, "_") || !awsKey.MatchString(str) {
			return nil
		}
		found := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(str, prefix) {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		data := map[string]string{"key": str}
		match := &Secret{Kind: "AWSAccessKey", Severity: SeverityLow, Data: data}
		parent := n.Parent()
		if parent == nil || parent.Type() != "pair" {
			return match
		}
		grandparent := parent.Parent()
		if grandparent == nil || grandparent.Type() != "object" {
			return match
		}
		object := grandparent.AsObject()
		for _, key := range object.GetKeys() {
			if strings.Contains(strings.ToLower(key), "secret") {
				data["secret"] = DecodeString(object.GetStringI(key, ""))
				break
			}
		}
		severity := SeverityLow
		if data["secret"] != "" {
			severity = SeverityHigh
		}
		return &Secret{Kind: "AWSAccessKey", Severity: severity, Data: data, Context: object.AsMap()}
	}}
}

func gcpKeyMatcher() SecretMatcher {
	gcpKey := regexp.MustCompile(`^AIza[a-zA-Z0-9+_-]+$`)
	return SecretMatcher{"(string) @matches", func(n *Node) *Secret {
		str := n.RawString()
		if !strings.HasPrefix(str, "AIza") || !gcpKey.MatchString(str) {
			return nil
		}
		match := &Secret{Kind: "gcpKey", Severity: SeverityLow, Data: map[string]string{"key": str}}
		if parent := n.Parent(); parent != nil && parent.Type() == "pair" {
			if gp := parent.Parent(); gp != nil && gp.Type() == "object" {
				match.Context = gp.AsObject().AsMap()
			}
		}
		return match
	}}
}

func firebaseMatcher() SecretMatcher {
	return SecretMatcher{"(object) @matches", func(n *Node) *Secret {
		object := n.AsObject()
		mustHave := map[string]bool{"apiKey": true, "authDomain": true, "projectId": true, "storageBucket": true}
		count := 0
		for _, key := range object.GetKeys() {
			if mustHave[key] {
				count++
			}
		}
		if count != len(mustHave) || !strings.HasPrefix(object.GetStringI("apiKey", ""), "AIza") {
			return nil
		}
		return &Secret{Kind: "firebase", Severity: SeverityHigh, Data: object.AsMap()}
	}}
}

func githubKeyMatcher() SecretMatcher {
	githubKey := regexp.MustCompile(`([a-zA-Z0-9_-]{2,}:)?ghp_[a-zA-Z0-9]{30,}`)
	return SecretMatcher{"(string) @matches", func(n *Node) *Secret {
		str := n.RawString()
		if !githubKey.MatchString(str) {
			return nil
		}
		match := &Secret{Kind: "githubKey", Severity: SeverityLow, Data: map[string]string{"key": str}}
		if parent := n.Parent(); parent != nil && parent.Type() == "pair" {
			if gp := parent.Parent(); gp != nil && gp.Type() == "object" {
				match.Context = gp.AsObject().AsMap()
			}
		}
		return match
	}}
}

type UserPattern struct {
	Name     string         `json:"name"`
	Key      string         `json:"key"`
	Value    string         `json:"value"`
	Severity Severity       `json:"severity"`
	Object   []*UserPattern `json:"object"`
	reKey    *regexp.Regexp
	reValue  *regexp.Regexp
}

func (u *UserPattern) ParseRegex() error {
	if u.Value != "" {
		re, err := regexp.Compile(u.Value)
		if err != nil {
			return err
		}
		u.reValue = re
	}
	if u.Key != "" {
		re, err := regexp.Compile(u.Key)
		if err != nil {
			return err
		}
		u.reKey = re
	}
	for _, child := range u.Object {
		if err := child.ParseRegex(); err != nil {
			return err
		}
	}
	if u.Severity == "" {
		u.Severity = SeverityInfo
	}
	if u.reValue == nil && u.reKey == nil && len(u.Object) == 0 {
		return errors.New("'key', 'value', both, or 'object' must be supplied in user-defined matcher")
	}
	return nil
}

func (u *UserPattern) MatchValue(in string) bool {
	return u.reValue == nil || u.reValue.MatchString(in)
}

func (u *UserPattern) MatchKey(in string) bool {
	return u.reKey == nil || u.reKey.MatchString(in)
}

func (u *UserPattern) SecretMatcher() SecretMatcher {
	if len(u.Object) > 0 {
		return u.objectMatcher()
	}
	if u.reKey != nil {
		return u.pairMatcher()
	}
	return u.stringMatcher()
}

func (u *UserPattern) objectMatcher() SecretMatcher {
	return SecretMatcher{"(object) @matches", func(n *Node) *Secret {
		pairs := n.NamedChildren()
		matched := 0
		for _, pattern := range u.Object {
			matcher := pattern.pairMatcher()
			for _, pair := range pairs {
				if matcher.Fn(pair) != nil {
					matched++
					break
				}
			}
		}
		if matched != len(u.Object) {
			return nil
		}
		return &Secret{Kind: u.Name, Data: n.AsObject().AsMap(), Severity: u.Severity}
	}}
}

func (u *UserPattern) pairMatcher() SecretMatcher {
	return SecretMatcher{"(pair) @matches", func(n *Node) *Secret {
		key := n.ChildByFieldName("key")
		if key == nil || !u.MatchKey(key.RawString()) {
			return nil
		}
		value := n.ChildByFieldName("value")
		if value == nil || value.Type() != "string" || !u.MatchValue(value.RawString()) {
			return nil
		}
		secret := &Secret{
			Kind:     u.Name,
			Data:     map[string]string{"key": key.RawString(), "value": value.RawString()},
			Severity: u.Severity,
		}
		if parent := n.Parent(); parent != nil && parent.Type() == "object" {
			secret.Context = parent.AsObject().AsMap()
		}
		return secret
	}}
}

func (u *UserPattern) stringMatcher() SecretMatcher {
	return SecretMatcher{"(string) @matches", func(n *Node) *Secret {
		in := n.RawString()
		if !u.MatchValue(in) {
			return nil
		}
		secret := &Secret{Kind: u.Name, Data: map[string]string{"match": in}, Severity: u.Severity}
		if parent := n.Parent(); parent != nil && parent.Type() == "pair" {
			if gp := parent.Parent(); gp != nil && gp.Type() == "object" {
				secret.Context = gp.AsObject().AsMap()
			}
		}
		return secret
	}}
}

type UserPatterns []*UserPattern

func (u UserPatterns) SecretMatchers() []SecretMatcher {
	out := make([]SecretMatcher, 0, len(u))
	for _, pattern := range u {
		out = append(out, pattern.SecretMatcher())
	}
	return out
}

func ParseUserPatterns(r io.Reader) (UserPatterns, error) {
	out := make(UserPatterns, 0)
	dec := json.NewDecoder(r)
	if err := dec.Decode(&out); err != nil {
		return out, err
	}
	for _, pattern := range out {
		if err := pattern.ParseRegex(); err != nil {
			return out, err
		}
	}
	return out, nil
}
