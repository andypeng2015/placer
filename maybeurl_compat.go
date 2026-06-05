package jsluice

import (
	"net/url"
	"strings"
)

var fileExtensions = newStringSet([]string{
	"js", "css", "html", "htm", "xhtml", "xlsx",
	"xls", "docx", "doc", "pdf", "rss", "xml",
	"php", "phtml", "asp", "aspx", "asmx", "ashx",
	"cgi", "pl", "rb", "py", "do", "jsp",
	"jspa", "json", "jsonp", "txt",
})

func MaybeURL(in string) bool {
	if !strings.ContainsAny(in, "/?.") {
		return false
	}
	if strings.ContainsAny(in, " ()!<>'\"`{}^$,") {
		return false
	}
	if strings.HasPrefix(in, "/") {
		return true
	}
	u, err := url.Parse(in)
	if err != nil {
		return false
	}
	if u.Scheme != "" {
		s := strings.ToLower(u.Scheme)
		if s != "http" && s != "https" {
			return false
		}
	}
	if len(strings.Split(u.Hostname(), ".")) > 1 {
		return true
	}
	for _, vv := range u.Query() {
		if len(vv) > 0 && len(vv[0]) > 0 {
			return true
		}
	}
	if !strings.ContainsAny(u.Path, ".") {
		return false
	}
	parts := strings.Split(u.Path, ".")
	return fileExtensions.Contains(parts[len(parts)-1])
}

type stringSet map[string]struct{}

func newStringSet(items []string) stringSet {
	out := make(stringSet, len(items))
	for _, item := range items {
		out[item] = struct{}{}
	}
	return out
}

func (s stringSet) Contains(item string) bool {
	_, ok := s[item]
	return ok
}

func uniqueComparable[T comparable](items []T) []T {
	set := make(map[T]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}
	out := make([]T, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	return out
}
