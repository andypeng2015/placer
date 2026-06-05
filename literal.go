package jsluice

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

type literalValue struct {
	Value    string
	Dynamic  bool
	Template bool
}

func parseJSLiteral(raw string) (literalValue, bool) {
	if len(raw) < 2 {
		return literalValue{}, false
	}
	quote := raw[0]
	if quote != '"' && quote != '\'' && quote != '`' {
		return literalValue{}, false
	}
	if raw[len(raw)-1] != quote {
		return literalValue{}, false
	}
	body := raw[1 : len(raw)-1]
	if quote == '`' {
		value, dynamic := foldTemplateBody(body)
		return literalValue{Value: unescapeJS(value), Dynamic: dynamic, Template: true}, true
	}
	return literalValue{Value: unescapeJS(body)}, true
}

func foldTemplateBody(body string) (string, bool) {
	var b strings.Builder
	dynamic := false
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) {
			b.WriteByte(body[i])
			i++
			b.WriteByte(body[i])
			continue
		}
		if body[i] == '$' && i+1 < len(body) && body[i+1] == '{' {
			dynamic = true
			b.WriteByte('*')
			i += 2
			depth := 1
			for i < len(body) && depth > 0 {
				switch body[i] {
				case '\\':
					i += 2
					continue
				case '{':
					depth++
				case '}':
					depth--
				}
				i++
			}
			i--
			continue
		}
		b.WriteByte(body[i])
	}
	return b.String(), dynamic
}

func unescapeJS(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '0':
			b.WriteByte(0)
		case '\'', '"', '`', '\\', '/':
			b.WriteByte(s[i])
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 2
					continue
				}
			}
			b.WriteString(`\x`)
		case 'u':
			if i+4 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+5], 16, 32); err == nil {
					var buf [utf8.UTFMax]byte
					n := utf8.EncodeRune(buf[:], rune(v))
					b.Write(buf[:n])
					i += 4
					continue
				}
			}
			b.WriteString(`\u`)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
