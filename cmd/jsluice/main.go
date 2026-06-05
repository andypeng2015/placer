package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	placer "github.com/m31-labs/placer"
	"github.com/pkg/profile"
	"github.com/slyrz/warc"
	flag "github.com/spf13/pflag"
)

type options struct {
	profile         bool
	cookie          string
	headers         []string
	concurrency     int
	placeholder     string
	help            bool
	warc            bool
	rawInput        bool
	noCheckCert     bool
	includeSource   bool
	ignoreStrings   bool
	resolvePaths    string
	unique          bool
	patternsFile    string
	query           string
	rawOutput       bool
	includeFilename bool
	format          bool
}

type stringSlice []string

func (ss *stringSlice) String() string { return strings.Join(*ss, ", ") }
func (ss *stringSlice) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}
func (ss *stringSlice) Type() string { return "string" }

type cmdFn func(options, string, []byte) ([]string, []error)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	var opts options
	var headers stringSlice
	fs := flag.NewFlagSet("jsluice", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	fs.BoolVar(&opts.profile, "profile", false, "Profile CPU usage and save a cpu.pprof file in the current dir")
	fs.IntVarP(&opts.concurrency, "concurrency", "c", 1, "Number of files to process concurrently")
	fs.StringVarP(&opts.cookie, "cookie", "C", "", "Cookie(s) to use when making HTTP requests")
	fs.VarP(&headers, "header", "H", "Headers to use when making HTTP requests")
	fs.BoolVarP(&opts.rawInput, "raw-input", "j", false, "Read raw JavaScript source from stdin")
	fs.StringVarP(&opts.placeholder, "placeholder", "P", "EXPR", "Set the expression placeholder to a custom string")
	fs.BoolVarP(&opts.help, "help", "h", false, "")
	fs.BoolVarP(&opts.warc, "warc", "w", false, "")
	fs.BoolVarP(&opts.noCheckCert, "no-check-certificate", "i", false, "Ignore validation of server certificates")
	fs.BoolVarP(&opts.includeSource, "include-source", "S", false, "Include the source code where the URL was found")
	fs.BoolVarP(&opts.ignoreStrings, "ignore-strings", "I", false, "Ignore matches from string literals")
	fs.StringVarP(&opts.resolvePaths, "resolve-paths", "R", "", "Resolve relative paths using the absolute URL provided")
	fs.BoolVarP(&opts.unique, "unique", "u", false, "")
	fs.StringVarP(&opts.patternsFile, "patterns", "p", "", "JSON file containing user-defined secret patterns to look for")
	fs.StringVarP(&opts.query, "query", "q", "", "Tree sitter query to run")
	fs.BoolVarP(&opts.rawOutput, "raw-output", "r", false, "Do not convert values to native types")
	fs.BoolVarP(&opts.includeFilename, "include-filename", "f", false, "Include the filename in the output")
	fs.BoolVarP(&opts.format, "format", "F", false, "Format source code in the output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts.headers = headers
	if opts.help {
		usage(stderr)
		return nil
	}
	if opts.profile {
		defer profile.Start(profile.ProfilePath(".")).Stop()
	}
	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return fmt.Errorf("usage: jsluice <mode> [...flags]")
	}
	placer.ExpressionPlaceholder = opts.placeholder
	mode := rest[0]
	files := rest[1:]
	modes := map[string]cmdFn{
		"urls":    extractURLs,
		"secrets": extractSecrets,
		"tree":    printTree,
		"query":   runQuery,
		"format":  formatSource,
	}
	modeFn, ok := modes[mode]
	if !ok {
		return fmt.Errorf("no such mode: %s", mode)
	}
	if opts.rawInput {
		source, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		lines, errs := modeFn(opts, "<stdin>", source)
		return emitResults(stdout, stderr, lines, errs)
	}
	if len(files) == 0 {
		scanner := bufio.NewScanner(stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				files = append(files, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	}
	return processFiles(files, opts, modeFn, stdout, stderr)
}

func processFiles(files []string, opts options, modeFn cmdFn, stdout, stderr io.Writer) error {
	if opts.concurrency < 1 {
		opts.concurrency = 1
	}
	type job struct {
		index int
		name  string
	}
	type result struct {
		index int
		lines []string
		errs  []error
	}
	jobs := make(chan job)
	results := make(chan result, len(files))
	var wg sync.WaitGroup
	for i := 0; i < opts.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				res := result{index: job.index}
				if opts.warc {
					responses, err := readWARCFile(job.name)
					if err != nil {
						res.errs = append(res.errs, err)
						results <- res
						continue
					}
					for _, response := range responses {
						lines, lineErrs := modeFn(opts, response.url, response.source)
						res.lines = append(res.lines, lines...)
						res.errs = append(res.errs, lineErrs...)
					}
					results <- res
					continue
				}
				source, err := readFromFileOrURL(job.name, opts)
				if err != nil {
					res.errs = append(res.errs, err)
					results <- res
					continue
				}
				lines, lineErrs := modeFn(opts, job.name, source)
				res.lines = append(res.lines, lines...)
				res.errs = append(res.errs, lineErrs...)
				results <- res
			}
		}()
	}
	go func() {
		for i, file := range files {
			jobs <- job{index: i, name: file}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	ordered := make([]result, len(files))
	for res := range results {
		ordered[res.index] = res
	}
	for _, res := range ordered {
		_ = emitResults(stdout, stderr, res.lines, res.errs)
	}
	return nil
}

func emitResults(stdout, stderr io.Writer, lines []string, errs []error) error {
	for _, line := range lines {
		if line != "" {
			fmt.Fprintln(stdout, line)
		}
	}
	for _, err := range errs {
		if err != nil {
			fmt.Fprintf(stderr, "error: %s\n", err)
		}
	}
	return nil
}

func extractURLs(opts options, filename string, source []byte) ([]string, []error) {
	var resolveURL *url.URL
	var err error
	if opts.resolvePaths != "" {
		resolveURL, err = url.Parse(opts.resolvePaths)
		if err != nil {
			return nil, []error{err}
		}
	}
	seen := map[string]struct{}{}
	analyzer := placer.NewAnalyzer(source)
	var lines []string
	var errs []error
	for _, match := range analyzer.GetURLs() {
		if opts.ignoreStrings && match.Type == "stringLiteral" {
			continue
		}
		match.Filename = filename
		if !opts.includeSource {
			match.Source = ""
		}
		if resolveURL != nil {
			parsed, err := url.Parse(match.URL)
			if err == nil {
				match.URL = resolveURL.ResolveReference(parsed).String()
			}
		}
		if _, exists := seen[match.URL]; opts.unique && exists {
			continue
		}
		seen[match.URL] = struct{}{}
		b, err := json.Marshal(match)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		lines = append(lines, string(b))
	}
	return lines, errs
}

func extractSecrets(opts options, filename string, source []byte) ([]string, []error) {
	analyzer := placer.NewAnalyzer(source)
	if opts.patternsFile != "" {
		f, err := os.Open(opts.patternsFile)
		if err != nil {
			return nil, []error{err}
		}
		defer f.Close()
		patterns, err := placer.ParseUserPatterns(f)
		if err != nil {
			return nil, []error{err}
		}
		analyzer.AddSecretMatchers(patterns.SecretMatchers())
	}
	var lines []string
	var errs []error
	for _, match := range analyzer.GetSecrets() {
		match.Filename = filename
		b, err := json.Marshal(match)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		lines = append(lines, string(b))
	}
	return lines, errs
}

func runQuery(opts options, filename string, source []byte) ([]string, []error) {
	analyzer := placer.NewAnalyzer(source)
	var lines []string
	analyzer.QueryMulti(opts.query, func(qr placer.QueryResult) {
		vals := map[string]any{}
		for name, n := range qr {
			vals[name] = n.Content()
			switch {
			case opts.format:
				formatted, err := n.Format()
				if err == nil {
					vals[name] = formatted
				}
			case !opts.rawOutput:
				vals[name] = n.AsGoType()
			}
		}
		if len(vals) == 0 {
			return
		}
		if opts.includeFilename {
			vals["filename"] = filename
		}
		var out any = vals
		if len(vals) == 1 {
			for _, val := range vals {
				out = val
				break
			}
		}
		b, err := json.Marshal(out)
		if err == nil {
			lines = append(lines, string(b))
		}
	})
	return lines, nil
}

func printTree(opts options, filename string, source []byte) ([]string, []error) {
	return []string{fmt.Sprintf("%s:\n%s", filename, placer.PrintTree(source))}, nil
}

func formatSource(opts options, filename string, source []byte) ([]string, []error) {
	formatted, err := placer.NewAnalyzer(source).RootNode().Format()
	if err != nil {
		return nil, []error{err}
	}
	return []string{formatted}, nil
}

func readFromFileOrURL(path string, opts options) ([]byte, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		req, err := http.NewRequest(http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if opts.cookie != "" {
			req.Header.Add("Cookie", opts.cookie)
		}
		for _, header := range opts.headers {
			name, value, ok := strings.Cut(header, ":")
			if !ok {
				continue
			}
			req.Header.Add(strings.TrimSpace(name), strings.TrimSpace(value))
		}
		client := &http.Client{}
		if opts.noCheckCert {
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET request failed with status code %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(path)
}

type warcResponse struct {
	url    string
	source []byte
}

func readWARCFile(path string) ([]warcResponse, error) {
	var out []warcResponse
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	r, err := warc.NewReader(f)
	if err != nil {
		return out, err
	}
	for {
		record, err := r.ReadRecord()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if record.Header.Get("WARC-Type") != "response" {
			continue
		}
		response, err := http.ReadResponse(bufio.NewReader(record.Content), nil)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			return out, err
		}
		out = append(out, warcResponse{url: record.Header.Get("WARC-Target-URI"), source: body})
	}
	return out, nil
}

func usage(w io.Writer) {
	lines := []string{
		"jsluice - Extract URLs, paths, and secrets from JavaScript files",
		"",
		"Usage:",
		"  jsluice <mode> [options] [file...]",
		"",
		"Modes:",
		"  urls      Extract URLs and paths",
		"  secrets   Extract secrets and other interesting bits",
		"  tree      Print syntax trees for input files",
		"  query     Run tree-sitter a query against input files",
		"  format    Format JavaScript source using jsbeautifier-go",
	}
	fmt.Fprintln(w, strings.Join(lines, "\n"))
}
