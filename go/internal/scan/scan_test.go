package scan

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSecret builds a deterministic fake secret. All examples contain FAKE
// and no real key material is ever used.
func fakeSecret(length int) string {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	out := []byte("FAKE")
	for i := 0; len(out) < length && i < len(alphabet); i++ {
		if bytes.IndexByte(out, alphabet[i]) >= 0 {
			continue
		}
		out = append(out, alphabet[i])
	}
	if len(out) < length {
		panic("fakeSecret: alphabet exhausted")
	}
	return string(out[:length])
}

func TestEntropyAndClassification(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  float64
	}{
		{"", 0},
		{"aaaa", 0},
		{"abab", 1},
		{"abcd", 2},
	} {
		if got := Entropy(tc.value); got != tc.want {
			t.Errorf("Entropy(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}

	// 35 distinct characters have entropy log2(35), rounded to 5.13.
	want := math.Round(math.Log2(35)*100) / 100
	if got := Entropy(fakeSecret(35)); got != want {
		t.Errorf("Entropy(fakeSecret(35)) = %v, want %v", got, want)
	}

	for _, tc := range []struct {
		length     int
		entropy    float64
		confidence string
		reason     string
	}{
		{35, 4.2, "high", "exact length and high entropy"},
		{35, 4.0, "high", "exact length and high entropy"},
		{35, 3.99, "medium", "token-like length and entropy"},
		{40, 3.5, "medium", "token-like length and entropy"},
		{30, 3.5, "medium", "token-like length and entropy"},
		{40, 3.49, "low", "weak entropy or unusual length"},
		{29, 4.5, "low", "weak entropy or unusual length"},
		{51, 4.5, "low", "weak entropy or unusual length"},
	} {
		confidence, reason := classify(tc.length, tc.entropy)
		if confidence != tc.confidence || reason != tc.reason {
			t.Errorf("classify(%d, %v) = (%q, %q), want (%q, %q)",
				tc.length, tc.entropy, confidence, reason, tc.confidence, tc.reason)
		}
	}
}

func TestScanTextBoundariesAndRedaction(t *testing.T) {
	secret := fakeSecret(35)
	medium := fakeSecret(40)
	low := strings.Repeat("FAKE", 9) // 36 characters, entropy 2.0

	text := strings.Join([]string{
		"123456789:" + secret,               // valid: line 1, column 1
		"x123456789:" + secret,              // glued prefix: not a boundary
		"123456789:" + fakeSecret(50) + "X", // longer token-like secret
		"12345:" + secret,                   // id too short
		"1234567890123:" + secret,           // id too long
		"xx 987654321:" + medium + " ok",    // valid: line 6, column 4
		"999999999:" + low,                  // valid: low confidence
	}, "\n")

	findings := ScanText(text, "fake.txt")
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(findings), findings)
	}

	want := []Finding{
		{File: "fake.txt", Line: 1, Column: 1, BotID: "123456789", SecretLength: 35,
			Entropy: Entropy(secret), Confidence: "high", Reason: "exact length and high entropy"},
		{File: "fake.txt", Line: 6, Column: 4, BotID: "987654321", SecretLength: 40,
			Entropy: Entropy(medium), Confidence: "medium", Reason: "token-like length and entropy"},
		{File: "fake.txt", Line: 7, Column: 1, BotID: "999999999", SecretLength: 36,
			Entropy: 2, Confidence: "low", Reason: "weak entropy or unusual length"},
	}
	for i := range want {
		if findings[i] != want[i] {
			t.Errorf("finding %d = %+v, want %+v", i, findings[i], want[i])
		}
	}

	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{secret, medium, low} {
		if bytes.Contains(encoded, []byte(value)) {
			t.Error("report contains a complete secret")
		}
	}

	var raw []map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"file": true, "line": true, "column": true, "bot_id": true,
		"secret_length": true, "entropy": true, "confidence": true, "reason": true,
	}
	for key := range raw[0] {
		if !allowed[key] {
			t.Errorf("unexpected JSON field %q", key)
		}
	}
	if len(raw[0]) != len(allowed) {
		t.Errorf("got %d JSON fields, want %d", len(raw[0]), len(allowed))
	}
}

func TestScanDirSkipsAndSorts(t *testing.T) {
	root := t.TempDir()
	secretA := fakeSecret(35)
	secretB := fakeSecret(40)

	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("app/b.txt", "987654321:"+secretA+"\nzzz 111222333:"+secretB+"\n")
	write("app/a.txt", "123123123:"+secretA+"\n")
	for _, dir := range []string{".git", "target", "node_modules", "__pycache__"} {
		write(filepath.Join(dir, "config"), "555555555:"+secretA)
	}
	write("big.txt", "444444444:"+secretA+strings.Repeat("x", int(maxFileBytes)+10))
	write("binary.bin", "\x00"+"333333333:"+secretA)

	report, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.ScannedFiles != 2 {
		t.Errorf("scanned_files = %d, want 2", report.ScannedFiles)
	}
	if report.SkippedFiles != 2 {
		t.Errorf("skipped_files = %d, want 2", report.SkippedFiles)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(report.Findings), report.Findings)
	}

	want := []struct {
		file   string
		line   int
		column int
	}{
		{"app/a.txt", 1, 1},
		{"app/b.txt", 1, 1},
		{"app/b.txt", 2, 5},
	}
	for i, f := range report.Findings {
		if f.File != want[i].file || f.Line != want[i].line || f.Column != want[i].column {
			t.Errorf("finding %d = (%q, %d, %d), want (%q, %d, %d)",
				i, f.File, f.Line, f.Column, want[i].file, want[i].line, want[i].column)
		}
	}

	if _, err := ScanDir(filepath.Join(root, "missing")); err == nil {
		t.Error("ScanDir on a missing directory should return an error")
	}
}

func TestWriteReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "findings.json")
	if err := WriteReport(path, Report{ScannedFiles: 2}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "\n  \"scanned_files\": 2") {
		t.Errorf("report is not indented with two spaces: %s", text)
	}
	if !strings.Contains(text, "\"findings\": []") || strings.Contains(text, "null") {
		t.Errorf("empty findings must be an array: %s", text)
	}

	secret := fakeSecret(35)
	report := Report{
		ScannedFiles: 1,
		Findings: []Finding{{
			File: "fake.txt", Line: 1, Column: 1, BotID: "123456789",
			SecretLength: 35, Entropy: 5.13, Confidence: "high",
			Reason: "exact length and high entropy",
		}},
	}
	if err := WriteReport(path, report); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(secret)) {
		t.Error("written report contains a complete secret")
	}
	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.ScannedFiles != 1 || len(parsed.Findings) != 1 || parsed.Findings[0] != report.Findings[0] {
		t.Errorf("round-trip mismatch: %+v", parsed)
	}
}

func TestScanFileMissingReturnsError(t *testing.T) {
	if _, err := ScanFile(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Error("ScanFile on a missing file should return an error")
	}
}
