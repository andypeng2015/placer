package jsluice

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"

	"github.com/odvcencio/gotreesitter"
)

const defaultMaxFileBytes int64 = 10 << 20

func AnalyzeSource(path string, source []byte, opts Options) (FileResult, error) {
	opts = normalizeOptions(opts)
	lang, langName, err := detectLanguage(path, opts.Language)
	if err != nil {
		return FileResult{Path: path, Error: err.Error()}, err
	}

	parser := gotreesitter.NewParser(lang)
	if opts.ParseTimeout > 0 {
		parser.SetTimeoutMicros(uint64(opts.ParseTimeout.Microseconds()))
	}
	tree, err := parser.Parse(source)
	if err != nil {
		return FileResult{Path: path, Language: langName, Error: err.Error()}, err
	}
	defer tree.Release()

	out := FileResult{
		Path:              path,
		Language:          langName,
		ParseStoppedEarly: tree.ParseStoppedEarly(),
	}

	switch opts.Mode {
	case ModeTree:
		out.Tree = tree.RootNode().SExpr(lang)
	case ModeQuery:
		findings, err := queryFindings(path, tree, opts.Query)
		if err != nil {
			out.Error = err.Error()
			return out, err
		}
		out.Findings = findings
	case ModeURLs:
		out.Findings = extractNetworkFindings(path, tree, false)
	case ModeEndpoints:
		out.Findings = extractNetworkFindings(path, tree, true)
	case ModeSecrets:
		out.Findings, err = extractSecretFindings(path, tree)
		if err != nil {
			out.Error = err.Error()
			return out, err
		}
	case ModeAll:
		out.Findings = extractNetworkFindings(path, tree, false)
		secretFindings, err := extractSecretFindings(path, tree)
		if err != nil {
			out.Error = err.Error()
			return out, err
		}
		out.Findings = append(out.Findings, secretFindings...)
	default:
		err := fmt.Errorf("unknown mode %q", opts.Mode)
		out.Error = err.Error()
		return out, err
	}

	out.Findings = dedupeFindings(out.Findings)
	return out, nil
}

func AnalyzeFiles(paths []string, opts Options) (Result, error) {
	opts = normalizeOptions(opts)
	res := Result{Mode: opts.Mode}
	if len(paths) == 0 {
		return res, nil
	}

	type job struct {
		index int
		path  string
	}
	type done struct {
		index int
		file  FileResult
	}

	jobs := make(chan job)
	results := make(chan done, len(paths))
	var wg sync.WaitGroup
	for worker := 0; worker < opts.Workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				file := analyzeFile(j.path, opts)
				results <- done{index: j.index, file: file}
			}
		}()
	}

	for i, path := range paths {
		jobs <- job{index: i, path: path}
	}
	close(jobs)
	wg.Wait()
	close(results)

	ordered := make([]FileResult, len(paths))
	for r := range results {
		ordered[r.index] = r.file
	}
	res.Files = ordered
	for _, file := range ordered {
		if file.Error != "" {
			res.Errors = append(res.Errors, FileError{Path: file.Path, Error: file.Error})
			continue
		}
		res.Findings = append(res.Findings, file.Findings...)
	}
	res.Findings = dedupeFindings(res.Findings)
	return res, nil
}

func ExpandPaths(paths []string) ([]string, error) {
	var out []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, path)
			continue
		}
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", "vendor", "dist", "build":
					if p != path {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if isSupportedPath(p) {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

func analyzeFile(path string, opts Options) FileResult {
	info, err := os.Stat(path)
	if err != nil {
		return FileResult{Path: path, Error: err.Error()}
	}
	if info.Size() > opts.MaxFileBytes {
		return FileResult{Path: path, Error: fmt.Sprintf("file exceeds max size %d bytes", opts.MaxFileBytes)}
	}
	source, err := os.ReadFile(path)
	if err != nil {
		return FileResult{Path: path, Error: err.Error()}
	}
	file, err := AnalyzeSource(path, source, opts)
	if err != nil {
		return file
	}
	return file
}

func normalizeOptions(opts Options) Options {
	if opts.Mode == "" {
		opts.Mode = ModeAll
	}
	if opts.Workers <= 0 {
		opts.Workers = runtime.GOMAXPROCS(0)
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = defaultMaxFileBytes
	}
	return opts
}

func dedupeFindings(in []Finding) []Finding {
	if len(in) == 0 {
		return nil
	}
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.Location.Column != b.Location.Column {
			return a.Location.Column < b.Location.Column
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Value != b.Value {
			return a.Value < b.Value
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		return a.Rule < b.Rule
	})
	out := in[:0]
	seen := make(map[string]struct{}, len(in))
	for _, f := range in {
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d\x00%s\x00%s",
			f.Kind, f.Value, f.Location.File, f.Location.Line, f.Location.Column, f.Method, f.Rule)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return collapseSubsumedPaths(out)
}

// collapseSubsumedPaths drops bare "path" findings that merely restate a more
// specific "endpoint" or "url" finding for the same value on the same line.
// fetch("/x") surfaces the string argument twice: once as an endpoint (from
// the call, carrying the HTTP method) and once as a path (from the string
// literal). The endpoint is strictly more informative, so the path is noise.
// Same line + same value is the disambiguator — it collapses both the
// exact-span fetch case and the call-vs-string-span jQuery/ajax case without
// touching genuinely standalone paths (a bare "/foo" with no enclosing call
// has no endpoint to subsume it, so it survives).
func collapseSubsumedPaths(in []Finding) []Finding {
	if len(in) == 0 {
		return in
	}
	key := func(f Finding) string {
		return fmt.Sprintf("%s\x00%d\x00%s", f.Location.File, f.Location.Line, f.Value)
	}
	hasEndpoint := make(map[string]struct{}, len(in))
	hasSpecific := make(map[string]struct{}, len(in)) // endpoint or url
	for _, f := range in {
		k := key(f)
		switch f.Kind {
		case "endpoint":
			hasEndpoint[k] = struct{}{}
			hasSpecific[k] = struct{}{}
		case "url":
			hasSpecific[k] = struct{}{}
		}
	}
	out := in[:0]
	for _, f := range in {
		k := key(f)
		// A bare path is subsumed by any endpoint/url for the same value+line.
		if f.Kind == "path" {
			if _, ok := hasSpecific[k]; ok {
				continue
			}
		}
		// A url is subsumed by a typed endpoint for the same value+line (the
		// endpoint carries method/sink semantics the url does not).
		if f.Kind == "url" {
			if _, ok := hasEndpoint[k]; ok {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}
