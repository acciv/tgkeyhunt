// Command tgkeyscan scans a directory for Telegram Bot API token-shaped
// strings and writes a redacted findings.json report.
package main

import (
	"flag"
	"fmt"
	"os"

	"tgkeyhunt/internal/scan"
)

func main() {
	dir := flag.String("dir", "../examples/fixtures", "directory to scan")
	out := flag.String("out", "../examples/findings.json", "path of the JSON report")
	flag.Parse()

	report, err := scan.ScanDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tgkeyscan:", err)
		os.Exit(1)
	}
	if err := scan.WriteReport(*out, report); err != nil {
		fmt.Fprintln(os.Stderr, "tgkeyscan:", err)
		os.Exit(1)
	}

	fmt.Printf("scanned %d files, skipped %d, found %d\n",
		report.ScannedFiles, report.SkippedFiles, len(report.Findings))
}
