package jsluice

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/odvcencio/gotreesitter"
)

const (
	maxStringEvalDepth   = 10
	maxStringEvalResults = 64
	maxRecoveredString   = 8192
)

type recoveredString struct {
	Value     string
	Recovered string
	Node      *gotreesitter.Node
}

type recoveredArray struct {
	Values    []string
	Recovered string
	Node      *gotreesitter.Node
}

type stringEvalEnv struct {
	strings map[string][]recoveredString
	arrays  map[string][]recoveredArray
}

func collectRecoveredStrings(tree *gotreesitter.Tree) []recoveredString {
	if tree == nil || tree.RootNode() == nil {
		return nil
	}
	lang := tree.Language()
	source := tree.Source()
	root := tree.RootNode()
	env := buildStringEvalEnv(root, lang, source)
	var out []recoveredString
	seen := map[string]struct{}{}
	walkNode(root, func(n *gotreesitter.Node) {
		switch n.Type(lang) {
		case "string", "template_string", "binary_expression", "array", "call_expression", "identifier":
		default:
			return
		}
		for _, recovered := range evalStringNode(n, lang, source, env, 0) {
			if recovered.Value == "" {
				continue
			}
			key := recovered.Value + "\x00" + recovered.Recovered + "\x00" + strconv.Itoa(int(n.StartByte()))
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			if recovered.Node == nil {
				recovered.Node = n
			}
			out = append(out, recovered)
		}
	})
	return out
}

func buildStringEvalEnv(root *gotreesitter.Node, lang *gotreesitter.Language, source []byte) stringEvalEnv {
	env := stringEvalEnv{
		strings: map[string][]recoveredString{},
		arrays:  map[string][]recoveredArray{},
	}
	for pass := 0; pass < 3; pass++ {
		walkNode(root, func(n *gotreesitter.Node) {
			switch n.Type(lang) {
			case "variable_declarator":
				name := n.ChildByFieldName("name", lang)
				value := n.ChildByFieldName("value", lang)
				if name == nil || value == nil || name.Type(lang) != "identifier" {
					return
				}
				key := strings.TrimSpace(name.Text(source))
				if values := evalStringNode(value, lang, source, env, 0); len(values) > 0 {
					env.strings[key] = values
				}
				if values := evalArrayNode(value, lang, source, env, 0); len(values) > 0 {
					env.arrays[key] = values
				}
			case "assignment_expression":
				left := n.ChildByFieldName("left", lang)
				right := n.ChildByFieldName("right", lang)
				if left == nil || right == nil || left.Type(lang) != "identifier" {
					return
				}
				key := strings.TrimSpace(left.Text(source))
				if values := evalStringNode(right, lang, source, env, 0); len(values) > 0 {
					env.strings[key] = values
				}
				if values := evalArrayNode(right, lang, source, env, 0); len(values) > 0 {
					env.arrays[key] = values
				}
			}
		})
	}
	return env
}

func evalStringNode(n *gotreesitter.Node, lang *gotreesitter.Language, source []byte, env stringEvalEnv, depth int) []recoveredString {
	if n == nil || depth > maxStringEvalDepth {
		return nil
	}
	switch n.Type(lang) {
	case "string", "template_string":
		lit, ok := parseJSLiteral(n.Text(source))
		if !ok {
			return nil
		}
		return []recoveredString{{Value: lit.Value, Recovered: "literal", Node: n}}
	case "identifier":
		return cloneRecoveredStrings(env.strings[strings.TrimSpace(n.Text(source))], n)
	case "parenthesized_expression":
		return evalStringNode(firstNamedChildTS(n), lang, source, env, depth+1)
	case "binary_expression":
		if !hasDirectChildText(n, source, "+") {
			return nil
		}
		left := evalStringNode(n.ChildByFieldName("left", lang), lang, source, env, depth+1)
		right := evalStringNode(n.ChildByFieldName("right", lang), lang, source, env, depth+1)
		return concatRecovered(left, right, "concat", n)
	case "array":
		arrays := evalArrayNode(n, lang, source, env, depth+1)
		out := make([]recoveredString, 0, len(arrays))
		for _, arr := range arrays {
			out = append(out, recoveredString{Value: strings.Join(arr.Values, ""), Recovered: markRecovered(arr.Recovered, "array_concat"), Node: n})
		}
		return capRecoveredStrings(out)
	case "call_expression":
		return evalCallString(n, lang, source, env, depth+1)
	default:
		return nil
	}
}

func evalCallString(n *gotreesitter.Node, lang *gotreesitter.Language, source []byte, env stringEvalEnv, depth int) []recoveredString {
	if n == nil || depth > maxStringEvalDepth {
		return nil
	}
	fn := n.ChildByFieldName("function", lang)
	args := argumentNodes(n.ChildByFieldName("arguments", lang))
	fnText := ""
	if fn != nil {
		fnText = strings.TrimSpace(fn.Text(source))
	}
	switch fnText {
	case "atob":
		return decodeCallFirstArg(args, lang, source, env, depth, "base64")
	case "decodeURI", "decodeURIComponent", "unescape":
		return decodeURICall(args, lang, source, env, depth)
	case "String.fromCharCode", "String.fromCodePoint":
		if s, ok := evalCharCodeArgs(args, lang, source); ok {
			return []recoveredString{{Value: s, Recovered: "charcode", Node: n}}
		}
	case "String":
		return evalStringNode(firstArg(args), lang, source, env, depth+1)
	}
	if fn == nil || fn.Type(lang) != "member_expression" {
		return nil
	}
	prop := memberProperty(fn, lang, source)
	obj := memberObject(fn, lang)
	switch prop {
	case "join":
		sep := ","
		if arg := firstArg(args); arg != nil {
			if vals := evalStringNode(arg, lang, source, env, depth+1); len(vals) > 0 {
				sep = vals[0].Value
			}
		}
		arrays := evalArrayNode(obj, lang, source, env, depth+1)
		out := make([]recoveredString, 0, len(arrays))
		for _, arr := range arrays {
			out = append(out, recoveredString{Value: strings.Join(arr.Values, sep), Recovered: markRecovered(arr.Recovered, "join"), Node: n})
		}
		return capRecoveredStrings(out)
	case "toString":
		if out := evalBufferToString(obj, args, lang, source, env, depth+1, n); len(out) > 0 {
			return out
		}
		return evalStringNode(obj, lang, source, env, depth+1)
	case "trim":
		return mapRecoveredStrings(evalStringNode(obj, lang, source, env, depth+1), "trim", n, strings.TrimSpace)
	case "replace", "replaceAll":
		return evalReplaceCall(obj, args, lang, source, env, depth+1, n)
	case "slice", "substring", "substr":
		return evalSliceCall(prop, obj, args, lang, source, env, depth+1, n)
	}
	return nil
}

func evalArrayNode(n *gotreesitter.Node, lang *gotreesitter.Language, source []byte, env stringEvalEnv, depth int) []recoveredArray {
	if n == nil || depth > maxStringEvalDepth {
		return nil
	}
	switch n.Type(lang) {
	case "identifier":
		return cloneRecoveredArrays(env.arrays[strings.TrimSpace(n.Text(source))], n)
	case "array":
		values := make([]string, 0, n.NamedChildCount())
		method := "array"
		for _, child := range namedChildrenTS(n) {
			evals := evalStringNode(child, lang, source, env, depth+1)
			if len(evals) == 0 {
				return nil
			}
			values = append(values, evals[0].Value)
			method = markRecovered(method, evals[0].Recovered)
		}
		return []recoveredArray{{Values: values, Recovered: method, Node: n}}
	case "call_expression":
		fn := n.ChildByFieldName("function", lang)
		if fn == nil || fn.Type(lang) != "member_expression" {
			return nil
		}
		prop := memberProperty(fn, lang, source)
		obj := memberObject(fn, lang)
		args := argumentNodes(n.ChildByFieldName("arguments", lang))
		switch prop {
		case "split":
			sep := ","
			if arg := firstArg(args); arg != nil {
				if vals := evalStringNode(arg, lang, source, env, depth+1); len(vals) > 0 {
					sep = vals[0].Value
				}
			}
			strs := evalStringNode(obj, lang, source, env, depth+1)
			out := make([]recoveredArray, 0, len(strs))
			for _, s := range strs {
				out = append(out, recoveredArray{Values: strings.Split(s.Value, sep), Recovered: markRecovered(s.Recovered, "split"), Node: n})
			}
			return capRecoveredArrays(out)
		case "reverse":
			arrays := evalArrayNode(obj, lang, source, env, depth+1)
			for i := range arrays {
				reverseStrings(arrays[i].Values)
				arrays[i].Recovered = markRecovered(arrays[i].Recovered, "reverse")
				arrays[i].Node = n
			}
			return capRecoveredArrays(arrays)
		}
	}
	return nil
}

func decodeCallFirstArg(args []*gotreesitter.Node, lang *gotreesitter.Language, source []byte, env stringEvalEnv, depth int, method string) []recoveredString {
	var out []recoveredString
	for _, value := range evalStringNode(firstArg(args), lang, source, env, depth+1) {
		for _, decoded := range decodeBase64Variants(value.Value) {
			out = append(out, recoveredString{Value: decoded, Recovered: markRecovered(value.Recovered, method), Node: value.Node})
		}
	}
	return capRecoveredStrings(out)
}

func evalBufferToString(obj *gotreesitter.Node, args []*gotreesitter.Node, lang *gotreesitter.Language, source []byte, env stringEvalEnv, depth int, loc *gotreesitter.Node) []recoveredString {
	if obj == nil || obj.Type(lang) != "call_expression" {
		return nil
	}
	fn := obj.ChildByFieldName("function", lang)
	if fn == nil {
		return nil
	}
	if strings.TrimSpace(fn.Text(source)) != "Buffer.from" {
		return nil
	}
	fromArgs := argumentNodes(obj.ChildByFieldName("arguments", lang))
	if len(fromArgs) == 0 {
		return nil
	}
	encoding := "utf8"
	if len(fromArgs) > 1 {
		if vals := evalStringNode(fromArgs[1], lang, source, env, depth+1); len(vals) > 0 {
			encoding = strings.ToLower(vals[0].Value)
		}
	}
	if len(args) > 0 {
		if vals := evalStringNode(args[0], lang, source, env, depth+1); len(vals) > 0 {
			encoding = strings.ToLower(vals[0].Value)
		}
	}
	var out []recoveredString
	for _, value := range evalStringNode(fromArgs[0], lang, source, env, depth+1) {
		switch strings.ReplaceAll(encoding, "-", "") {
		case "base64":
			for _, decoded := range decodeBase64Variants(value.Value) {
				out = append(out, recoveredString{Value: decoded, Recovered: markRecovered(value.Recovered, "buffer_base64"), Node: loc})
			}
		case "hex":
			if decoded, ok := decodeHexString(value.Value); ok {
				out = append(out, recoveredString{Value: decoded, Recovered: markRecovered(value.Recovered, "buffer_hex"), Node: loc})
			}
		default:
			out = append(out, recoveredString{Value: value.Value, Recovered: markRecovered(value.Recovered, "buffer"), Node: loc})
		}
	}
	return capRecoveredStrings(out)
}

func decodeURICall(args []*gotreesitter.Node, lang *gotreesitter.Language, source []byte, env stringEvalEnv, depth int) []recoveredString {
	var out []recoveredString
	for _, value := range evalStringNode(firstArg(args), lang, source, env, depth+1) {
		for _, decoded := range decodeURIValues(value.Value) {
			out = append(out, recoveredString{Value: decoded, Recovered: markRecovered(value.Recovered, "uri_decode"), Node: value.Node})
		}
	}
	return capRecoveredStrings(out)
}

func evalReplaceCall(obj *gotreesitter.Node, args []*gotreesitter.Node, lang *gotreesitter.Language, source []byte, env stringEvalEnv, depth int, loc *gotreesitter.Node) []recoveredString {
	if len(args) < 2 {
		return nil
	}
	replacements := evalStringNode(args[1], lang, source, env, depth+1)
	if len(replacements) == 0 {
		return nil
	}
	needle := ""
	if vals := evalStringNode(args[0], lang, source, env, depth+1); len(vals) > 0 {
		needle = vals[0].Value
	} else {
		raw := strings.TrimSpace(args[0].Text(source))
		if strings.HasPrefix(raw, "/") && strings.Count(raw, "/") >= 2 {
			raw = strings.TrimPrefix(raw, "/")
			needle = raw[:strings.LastIndex(raw, "/")]
			if len(needle) != 1 {
				return nil
			}
		}
	}
	if needle == "" {
		return nil
	}
	var out []recoveredString
	for _, base := range evalStringNode(obj, lang, source, env, depth+1) {
		replaced := strings.ReplaceAll(base.Value, needle, replacements[0].Value)
		out = append(out, recoveredString{Value: replaced, Recovered: markRecovered(base.Recovered, "replace"), Node: loc})
	}
	return capRecoveredStrings(out)
}

func evalSliceCall(prop string, obj *gotreesitter.Node, args []*gotreesitter.Node, lang *gotreesitter.Language, source []byte, env stringEvalEnv, depth int, loc *gotreesitter.Node) []recoveredString {
	if len(args) == 0 {
		return nil
	}
	start, ok := evalIntNode(args[0], lang, source)
	if !ok {
		return nil
	}
	endSet := false
	end := 0
	if len(args) > 1 {
		if v, ok := evalIntNode(args[1], lang, source); ok {
			end = v
			endSet = true
		}
	}
	var out []recoveredString
	for _, base := range evalStringNode(obj, lang, source, env, depth+1) {
		if sliced, ok := applyStringSlice(base.Value, prop, start, end, endSet); ok {
			out = append(out, recoveredString{Value: sliced, Recovered: markRecovered(base.Recovered, prop), Node: loc})
		}
	}
	return capRecoveredStrings(out)
}

func evalCharCodeArgs(args []*gotreesitter.Node, lang *gotreesitter.Language, source []byte) (string, bool) {
	if len(args) == 0 || len(args) > maxRecoveredString {
		return "", false
	}
	var b strings.Builder
	for _, arg := range args {
		value, ok := evalIntNode(arg, lang, source)
		if !ok || value < 0 || value > utf8.MaxRune {
			return "", false
		}
		b.WriteRune(rune(value))
	}
	return b.String(), true
}

func evalIntNode(n *gotreesitter.Node, lang *gotreesitter.Language, source []byte) (int, bool) {
	if n == nil {
		return 0, false
	}
	text := strings.TrimSpace(n.Text(source))
	if n.Type(lang) == "unary_expression" && strings.HasPrefix(text, "-") {
		child := firstNamedChildTS(n)
		value, ok := evalIntNode(child, lang, source)
		return -value, ok
	}
	if strings.Contains(text, ".") {
		f, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return 0, false
		}
		return int(f), true
	}
	i, err := strconv.ParseInt(text, 0, 32)
	if err != nil {
		return 0, false
	}
	return int(i), true
}

func concatRecovered(left, right []recoveredString, method string, loc *gotreesitter.Node) []recoveredString {
	var out []recoveredString
	for _, l := range left {
		for _, r := range right {
			out = append(out, recoveredString{
				Value:     l.Value + r.Value,
				Recovered: markRecovered(markRecovered(l.Recovered, r.Recovered), method),
				Node:      loc,
			})
			if len(out) >= maxStringEvalResults {
				return out
			}
		}
	}
	return capRecoveredStrings(out)
}

func mapRecoveredStrings(in []recoveredString, method string, loc *gotreesitter.Node, fn func(string) string) []recoveredString {
	out := make([]recoveredString, 0, len(in))
	for _, value := range in {
		out = append(out, recoveredString{Value: fn(value.Value), Recovered: markRecovered(value.Recovered, method), Node: loc})
	}
	return capRecoveredStrings(out)
}

func decodeBase64Variants(value string) []string {
	cleaned := strings.TrimSpace(value)
	cleaned = strings.NewReplacer("\n", "", "\r", "", "\t", "", " ", "").Replace(cleaned)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var out []string
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(cleaned)
		if err != nil {
			continue
		}
		s := string(decoded)
		if looksUsefulRecoveredString(s) {
			out = append(out, s)
		}
	}
	return uniqueStrings(out)
}

func decodeHexString(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value)%2 != 0 || len(value) == 0 {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(value); i += 2 {
		v, err := strconv.ParseUint(value[i:i+2], 16, 8)
		if err != nil {
			return "", false
		}
		b.WriteByte(byte(v))
	}
	out := b.String()
	return out, looksUsefulRecoveredString(out)
}

func decodeURIValues(value string) []string {
	var out []string
	for _, fn := range []func(string) (string, error){url.PathUnescape, url.QueryUnescape, legacyUnescape} {
		if decoded, err := fn(value); err == nil && decoded != value && looksUsefulRecoveredString(decoded) {
			out = append(out, decoded)
		}
	}
	return uniqueStrings(out)
}

func legacyUnescape(value string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+5 < len(value) && value[i+1] == 'u' {
			if r, err := strconv.ParseInt(value[i+2:i+6], 16, 32); err == nil {
				b.WriteRune(rune(r))
				i += 5
				continue
			}
		}
		b.WriteByte(value[i])
	}
	return b.String(), nil
}

func applyStringSlice(value, prop string, start, end int, endSet bool) (string, bool) {
	runes := []rune(value)
	length := len(runes)
	switch prop {
	case "slice":
		if start < 0 {
			start = length + start
		}
		if !endSet {
			end = length
		} else if end < 0 {
			end = length + end
		}
	case "substring":
		if start < 0 {
			start = 0
		}
		if !endSet {
			end = length
		}
		if end < 0 {
			end = 0
		}
		if start > end {
			start, end = end, start
		}
	case "substr":
		if start < 0 {
			start = length + start
		}
		if !endSet {
			end = length
		} else {
			end = start + end
		}
	}
	if start < 0 {
		start = 0
	}
	if end > length {
		end = length
	}
	if start > end || start > length {
		return "", false
	}
	return string(runes[start:end]), true
}

func looksUsefulRecoveredString(value string) bool {
	if value == "" || len(value) > maxRecoveredString || !utf8.ValidString(value) {
		return false
	}
	printable := 0
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(len([]rune(value))) > 0.85
}

func markRecovered(current, next string) string {
	if next == "" || next == "literal" {
		return current
	}
	if current == "" || current == "literal" {
		return next
	}
	if strings.Contains(current, next) {
		return current
	}
	return current + "+" + next
}

func capRecoveredStrings(in []recoveredString) []recoveredString {
	out := in[:0]
	seen := map[string]struct{}{}
	for _, value := range in {
		if len(out) >= maxStringEvalResults {
			break
		}
		if value.Value == "" || len(value.Value) > maxRecoveredString {
			continue
		}
		key := value.Value + "\x00" + value.Recovered
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func capRecoveredArrays(in []recoveredArray) []recoveredArray {
	if len(in) <= maxStringEvalResults {
		return in
	}
	return in[:maxStringEvalResults]
}

func cloneRecoveredStrings(in []recoveredString, loc *gotreesitter.Node) []recoveredString {
	out := make([]recoveredString, 0, len(in))
	for _, value := range in {
		value.Node = loc
		out = append(out, value)
	}
	return capRecoveredStrings(out)
}

func cloneRecoveredArrays(in []recoveredArray, loc *gotreesitter.Node) []recoveredArray {
	out := make([]recoveredArray, 0, len(in))
	for _, value := range in {
		value.Node = loc
		value.Values = append([]string(nil), value.Values...)
		out = append(out, value)
	}
	return capRecoveredArrays(out)
}

func namedChildrenTS(n *gotreesitter.Node) []*gotreesitter.Node {
	if n == nil {
		return nil
	}
	out := make([]*gotreesitter.Node, 0, n.NamedChildCount())
	for i := 0; i < n.NamedChildCount(); i++ {
		out = append(out, n.NamedChild(i))
	}
	return out
}

func firstNamedChildTS(n *gotreesitter.Node) *gotreesitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(0)
}

func argumentNodes(args *gotreesitter.Node) []*gotreesitter.Node {
	return namedChildrenTS(args)
}

func firstArg(args []*gotreesitter.Node) *gotreesitter.Node {
	if len(args) == 0 {
		return nil
	}
	return args[0]
}

func memberObject(n *gotreesitter.Node, lang *gotreesitter.Language) *gotreesitter.Node {
	if n == nil {
		return nil
	}
	return n.ChildByFieldName("object", lang)
}

func memberProperty(n *gotreesitter.Node, lang *gotreesitter.Language, source []byte) string {
	if n == nil {
		return ""
	}
	prop := n.ChildByFieldName("property", lang)
	if prop == nil {
		return ""
	}
	return strings.TrimSpace(prop.Text(source))
}

func hasDirectChildText(n *gotreesitter.Node, source []byte, want string) bool {
	if n == nil {
		return false
	}
	for i := 0; i < n.ChildCount(); i++ {
		if strings.TrimSpace(n.Child(i).Text(source)) == want {
			return true
		}
	}
	return false
}

func reverseStrings(values []string) {
	for i, j := 0, len(values)-1; i < j; i, j = i+1, j-1 {
		values[i], values[j] = values[j], values[i]
	}
}
