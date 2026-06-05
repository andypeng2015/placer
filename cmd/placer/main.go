package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	placer "github.com/m31-labs/placer"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return fmt.Errorf("missing mode")
	}
	mode := placer.Mode(args[0])
	switch mode {
	case placer.ModeAll, placer.ModeURLs, placer.ModeSecrets, placer.ModeEndpoints, placer.ModeQuery, placer.ModeTree:
	default:
		usage(stderr)
		return fmt.Errorf("unknown mode %q", mode)
	}

	fs := flag.NewFlagSet("placer "+string(mode), flag.ContinueOnError)
	fs.SetOutput(stderr)
	lang := fs.String("lang", "", "language override: javascript, typescript, or tsx")
	query := fs.String("query", "", "tree-sitter query for query mode")
	workers := fs.Int("workers", 0, "concurrent file workers")
	maxBytes := fs.Int64("max-bytes", 10<<20, "maximum file size to analyze")
	timeout := fs.Duration("timeout", 2*time.Second, "per-file parse timeout")
	compat := fs.Bool("jsluice-compat", false, "emit compact jsluice-shaped findings")
	pretty := fs.Bool("pretty", true, "pretty-print JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	opts := placer.Options{
		Mode:         mode,
		Language:     *lang,
		Query:        *query,
		Workers:      *workers,
		MaxFileBytes: *maxBytes,
		ParseTimeout: *timeout,
	}

	var result placer.Result
	paths := fs.Args()
	if len(paths) == 0 {
		source, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		file, err := placer.AnalyzeSource("<stdin>", source, opts)
		result = placer.Result{Mode: mode, Files: []placer.FileResult{file}, Findings: file.Findings}
		if err != nil {
			result.Errors = append(result.Errors, placer.FileError{Path: "<stdin>", Error: err.Error()})
		}
	} else {
		expanded, err := placer.ExpandPaths(paths)
		if err != nil {
			return err
		}
		var analyzeErr error
		result, analyzeErr = placer.AnalyzeFiles(expanded, opts)
		if analyzeErr != nil {
			return analyzeErr
		}
	}

	var payload any = result
	if *compat {
		payload = placer.JSLuiceCompat(result)
	}
	enc := json.NewEncoder(stdout)
	if *pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(payload); err != nil {
		return err
	}
	if len(result.Errors) > 0 {
		return fmt.Errorf("%d file(s) failed", len(result.Errors))
	}
	return nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: placer <all|urls|secrets|endpoints|query|tree> [flags] [files or dirs]")
}
