// Package scan implements a local, read-only search for Telegram Bot API
// token-shaped strings. It never contacts the network and never stores a
// complete secret in a Finding or in a written report.
package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"unicode/utf8"
)

// maxFileBytes is the largest file the scanner will read. Files above this
// limit are counted as skipped.
const maxFileBytes int64 = 1_000_000

var skippedDirs = map[string]struct{}{
	".git":         {},
	"target":       {},
	"node_modules": {},
	"__pycache__":  {},
}

// Finding describes one candidate. The secret itself is deliberately absent.
type Finding struct {
	File         string  `json:"file"`
	Line         int     `json:"line"`
	Column       int     `json:"column"`
	BotID        string  `json:"bot_id"`
	SecretLength int     `json:"secret_length"`
	Entropy      float64 `json:"entropy"`
	Confidence   string  `json:"confidence"`
	Reason       string  `json:"reason"`
}

// Report is the top-level findings.json document.
type Report struct {
	ScannedFiles int       `json:"scanned_files"`
	SkippedFiles int       `json:"skipped_files"`
	Findings     []Finding `json:"findings"`
}

// Entropy returns the Shannon entropy of value in bits per character,
// rounded to two decimals.
func Entropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range value {
		counts[r]++
		total++
	}
	sum := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		sum -= p * math.Log2(p)
	}
	return math.Round(sum*100) / 100
}

func classify(secretLength int, entropy float64) (confidence, reason string) {
	switch {
	case secretLength == 35 && entropy >= 4.0:
		return "high", "exact length and high entropy"
	case secretLength >= 30 && secretLength <= 50 && entropy >= 3.5:
		return "medium", "token-like length and entropy"
	default:
		return "low", "weak entropy or unusual length"
	}
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// isTokenChar reports whether b belongs to the character set used by both
// parts of a candidate, and therefore cannot serve as a boundary.
func isTokenChar(b byte) bool {
	return isDigit(b) ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		b == '_' || b == '-'
}

// splitLines splits text into lines, accepts both LF and CRLF, and does not
// add an empty trailing line when text ends with a newline.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	lines := make([]string, 0, 8)
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] != '\n' {
			continue
		}
		end := i
		if end > start && text[end-1] == '\r' {
			end--
		}
		lines = append(lines, text[start:end])
		start = i + 1
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

// runeColumns maps a byte offset in line to a 1-based character column.
func runeColumns(line string) []int {
	cols := make([]int, len(line)+1)
	col := 1
	for i := 0; i < len(line); {
		cols[i] = col
		_, size := utf8.DecodeRuneInString(line[i:])
		i += size
		col++
	}
	cols[len(line)] = col
	return cols
}

// ScanText finds all candidates in text and attributes them to file.
// A candidate is <6..12 digits>:<30..50 token characters> surrounded by
// non-token characters. A longer token-like secret is never truncated to a
// shorter, partial match.
func ScanText(text, file string) []Finding {
	findings := make([]Finding, 0)
	for lineIndex, line := range splitLines(text) {
		cols := runeColumns(line)
		for i := 0; i < len(line); {
			if !isDigit(line[i]) || (i > 0 && isTokenChar(line[i-1])) {
				i++
				continue
			}

			idStart := i
			for i < len(line) && isDigit(line[i]) {
				i++
			}
			idLen := i - idStart
			if i >= len(line) || line[i] != ':' {
				continue
			}

			secretStart := i + 1
			i = secretStart
			for i < len(line) && isTokenChar(line[i]) {
				i++
			}
			secretLen := i - secretStart
			// i now points at the first non-token character. Reading the whole
			// token means a longer secret is rejected instead of being matched
			// as a truncated 50-character prefix.
			if idLen < 6 || idLen > 12 || secretLen < 30 || secretLen > 50 {
				continue
			}

			secret := line[secretStart : secretStart+secretLen]
			entropy := Entropy(secret)
			confidence, reason := classify(secretLen, entropy)
			findings = append(findings, Finding{
				File:         file,
				Line:         lineIndex + 1,
				Column:       cols[idStart],
				BotID:        line[idStart : idStart+idLen],
				SecretLength: secretLen,
				Entropy:      entropy,
				Confidence:   confidence,
				Reason:       reason,
			})
		}
	}
	sortFindings(findings)
	return findings
}

// ScanFile reads path as text and returns the findings it contains.
func ScanFile(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	return ScanText(string(data), path), nil
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.BotID != b.BotID {
			return a.BotID < b.BotID
		}
		if a.SecretLength != b.SecretLength {
			return a.SecretLength < b.SecretLength
		}
		if a.Entropy != b.Entropy {
			return a.Entropy < b.Entropy
		}
		if a.Confidence != b.Confidence {
			return a.Confidence < b.Confidence
		}
		return a.Reason < b.Reason
	})
}

type fileResult struct {
	path     string
	findings []Finding
	skipped  bool
	err      error
}

func scanOneFile(path string) ([]Finding, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, fmt.Errorf("cannot stat %s: %w", path, err)
	}
	if info.Size() > maxFileBytes {
		return nil, true, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("cannot read %s: %w", path, err)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, true, nil
	}
	return ScanText(string(data), path), false, nil
}

// ScanDir walks root concurrently and returns a deterministically sorted
// report. Reported file names are relative to root. Ignored directories and
// non-regular files are not visited; oversized and binary files increment
// SkippedFiles.
func ScanDir(root string) (Report, error) {
	empty := Report{Findings: []Finding{}}
	info, err := os.Stat(root)
	if err != nil {
		return empty, fmt.Errorf("cannot access %s: %w", root, err)
	}
	if !info.IsDir() {
		return empty, fmt.Errorf("not a directory: %s", root)
	}

	jobs := make(chan string)
	results := make(chan fileResult)
	walkErr := make(chan error, 1)

	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for path := range jobs {
				findings, skipped, err := scanOneFile(path)
				results <- fileResult{path: path, findings: findings, skipped: skipped, err: err}
			}
		}()
	}

	go func() {
		defer close(jobs)
		walkErr <- filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if path != root {
					if _, skip := skippedDirs[entry.Name()]; skip {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			jobs <- path
			return nil
		})
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	report := Report{Findings: []Finding{}}
	errs := make(map[string]error)
	for result := range results {
		if result.err != nil {
			errs[result.path] = result.err
			continue
		}
		if result.skipped {
			report.SkippedFiles++
			continue
		}
		report.ScannedFiles++
		name, err := filepath.Rel(root, result.path)
		if err != nil || name == "." {
			name = result.path
		}
		for _, finding := range result.findings {
			finding.File = name
			report.Findings = append(report.Findings, finding)
		}
	}

	if err := <-walkErr; err != nil {
		return empty, fmt.Errorf("cannot walk %s: %w", root, err)
	}
	if len(errs) > 0 {
		paths := make([]string, 0, len(errs))
		for path := range errs {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		return empty, errs[paths[0]]
	}

	sortFindings(report.Findings)
	return report, nil
}

// WriteReport writes report as JSON indented with two spaces. Findings are
// always serialized as an array, never as null.
func WriteReport(path string, report Report) error {
	if report.Findings == nil {
		report.Findings = []Finding{}
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode report: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("cannot create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	return nil
}
