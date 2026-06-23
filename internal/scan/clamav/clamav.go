// Package clamav runs ClamAV over the verified artifact. libclamav can look
// inside dmg/pkg/zip/tar, so we point it at the artifact directly. A daemon
// (clamdscan) is preferred when present; otherwise clamscan is used.
package clamav

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"brewcheck/internal/deps"
	"brewcheck/internal/report"
)

// Scan scans path with ClamAV.
func Scan(ctx context.Context, path string) report.LayerResult {
	res := report.LayerResult{Name: "ClamAV"}

	// Prefer the daemon client if available (faster, shared signatures).
	var bin, mode string
	if p, ok := deps.Find("clamdscan"); ok {
		bin, mode = p, "clamdscan"
	} else if p, ok := deps.Find("clamscan"); ok {
		bin, mode = p, "clamscan"
	} else {
		res.Status = report.StatusSkipped
		res.Hint = deps.Hints["clamav"]
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	args := []string{"--no-summary"}
	if mode == "clamdscan" {
		args = append(args, "--fdpass") // let the daemon read via passed fd
	}
	args = append(args, path)

	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	// clamscan exit codes: 0 = clean, 1 = virus found, 2 = error.
	exitCode := 0
	if ee, ok := err.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else if err != nil {
		res.Status = report.StatusError
		res.Err = fmt.Sprintf("%v: %s", err, strings.TrimSpace(stderr.String()))
		return res
	}

	res.Status = report.StatusRan
	switch exitCode {
	case 0:
		res.Summary = "no signatures matched"
	case 1:
		for _, sig := range parseHits(stdout.String()) {
			res.AddFinding(report.SeverityMalicious, "ClamAV signature match: "+sig, "", path)
		}
		if len(res.Findings) == 0 {
			res.AddFinding(report.SeverityMalicious, "ClamAV reported an infection", "", path)
		}
		res.Summary = "infection detected"
	default:
		res.Status = report.StatusError
		res.Err = fmt.Sprintf("clamav error (exit %d): %s", exitCode, strings.TrimSpace(stderr.String()))
	}
	return res
}

// parseHits extracts signature names from "path: SIGNATURE FOUND" lines.
func parseHits(out string) []string {
	var hits []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.LastIndex(line, ": "); i >= 0 && strings.HasSuffix(line, " FOUND") {
			sig := strings.TrimSuffix(line[i+2:], " FOUND")
			hits = append(hits, sig)
		}
	}
	return hits
}
