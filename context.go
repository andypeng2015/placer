package jsluice

import (
	"bytes"
	"strings"
)

func lineContext(source []byte, offset int) string {
	if offset < 0 {
		offset = 0
	}
	if offset > len(source) {
		offset = len(source)
	}
	start := bytes.LastIndexByte(source[:offset], '\n')
	if start < 0 {
		start = 0
	} else {
		start++
	}
	endRel := bytes.IndexByte(source[offset:], '\n')
	end := len(source)
	if endRel >= 0 {
		end = offset + endRel
	}
	line := strings.TrimSpace(string(source[start:end]))
	if len(line) > 240 {
		return line[:240]
	}
	return line
}
