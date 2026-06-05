package jsluice

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

func detectLanguage(path, override string) (*gotreesitter.Language, string, error) {
	var entry *grammars.LangEntry
	if strings.TrimSpace(override) != "" {
		entry = grammars.DetectLanguageByName(override)
		if entry == nil {
			return nil, "", fmt.Errorf("unknown language %q", override)
		}
	} else if path != "" && path != "<stdin>" {
		entry = grammars.DetectLanguage(path)
	}
	if entry == nil {
		entry = grammars.DetectLanguageByName("javascript")
	}
	if entry == nil || entry.Language == nil {
		return nil, "", fmt.Errorf("javascript grammar is unavailable")
	}
	if !supportedLanguageName(entry.Name) {
		return nil, "", fmt.Errorf("unsupported language %q", entry.Name)
	}
	return entry.Language(), entry.Name, nil
}

func supportedLanguageName(name string) bool {
	switch name {
	case "javascript", "typescript", "tsx":
		return true
	default:
		return false
	}
}

func isSupportedPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx":
		return true
	default:
		return false
	}
}
