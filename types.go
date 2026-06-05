package jsluice

import "time"

type Mode string

const (
	ModeAll       Mode = "all"
	ModeURLs      Mode = "urls"
	ModeSecrets   Mode = "secrets"
	ModeEndpoints Mode = "endpoints"
	ModeQuery     Mode = "query"
	ModeTree      Mode = "tree"
)

type Options struct {
	Mode         Mode
	Language     string
	Query        string
	Workers      int
	MaxFileBytes int64
	ParseTimeout time.Duration
}

type Result struct {
	Mode     Mode         `json:"mode"`
	Findings []Finding    `json:"findings,omitempty"`
	Files    []FileResult `json:"files,omitempty"`
	Errors   []FileError  `json:"errors,omitempty"`
}

type FileResult struct {
	Path              string    `json:"path"`
	Language          string    `json:"language,omitempty"`
	ParseStoppedEarly bool      `json:"parse_stopped_early,omitempty"`
	Findings          []Finding `json:"findings,omitempty"`
	Tree              string    `json:"tree,omitempty"`
	Error             string    `json:"error,omitempty"`
}

type FileError struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

type Finding struct {
	Kind       string   `json:"kind"`
	Value      string   `json:"value"`
	Location   Location `json:"location"`
	Context    string   `json:"context,omitempty"`
	Method     string   `json:"method,omitempty"`
	Params     []string `json:"params,omitempty"`
	Confidence float64  `json:"confidence,omitempty"`
	Rule       string   `json:"rule,omitempty"`
}

type Location struct {
	File      string `json:"file,omitempty"`
	Line      int    `json:"line"`
	Column    int    `json:"col"`
	ByteStart int    `json:"byte_start,omitempty"`
	ByteEnd   int    `json:"byte_end,omitempty"`
}
