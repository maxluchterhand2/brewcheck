// Package clamav runs ClamAV over the verified artifact. libclamav can look
// inside dmg/pkg/zip/tar, so we point it at the artifact directly. The daemon
// client (clamdscan) is preferred when clamd is actually running; otherwise we
// fall back to the standalone clamscan.
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

	// Prefer the daemon client (faster, shared signatures) — but only when clamd
	// is actually running. A present clamdscan binary with a dead daemon would
	// otherwise fail the scan, so fall back to clamscan in that case.
	clamdscan, hasClamd := deps.Find("clamdscan")
	clamscan, hasClamscan := deps.Find("clamscan")

	sel, hint, ok := chooseScanner(clamdscan, hasClamd, clamscan, hasClamscan,
		func() bool { return daemonRunning(ctx, clamdscan) })
	if !ok {
		res.Status = report.StatusSkipped
		res.Hint = hint
		return res
	}
	bin, mode := sel.bin, sel.mode

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
		res.Summary = fmt.Sprintf("no signatures matched (%s)", mode)
	case 1:
		for _, sig := range parseHits(stdout.String()) {
			res.AddFinding(report.SeverityMalicious, "ClamAV signature match: "+sig, "", path)
		}
		if len(res.Findings) == 0 {
			res.AddFinding(report.SeverityMalicious, "ClamAV reported an infection", "", path)
		}
		res.Summary = fmt.Sprintf("infection detected (%s)", mode)
	default:
		res.Status = report.StatusError
		res.Err = fmt.Sprintf("%s error (exit %d): %s", mode, exitCode, strings.TrimSpace(stderr.String()))
	}
	return res
}

type scanner struct {
	bin  string
	mode string // "clamdscan" | "clamscan"
}

// chooseScanner decides which ClamAV client to run. daemonUp is only consulted
// when clamdscan is present (so we never ping a daemon we can't talk to). It
// returns ok=false with a skip hint when nothing usable is available.
func chooseScanner(clamdscan string, hasClamd bool, clamscan string, hasClamscan bool, daemonUp func() bool) (s scanner, hint string, ok bool) {
	switch {
	case hasClamd && daemonUp():
		return scanner{clamdscan, "clamdscan"}, "", true
	case hasClamscan:
		return scanner{clamscan, "clamscan"}, "", true
	case hasClamd:
		// clamdscan exists but the daemon is down and there's no clamscan fallback.
		return scanner{}, "clamdscan is installed but clamd is not running, and clamscan is unavailable; start clamd (e.g. `brew services start clamav`) or install clamscan", false
	default:
		return scanner{}, deps.Hints["clamav"], false
	}
}

// daemonRunning reports whether clamd is reachable, by asking clamdscan to ping
// it. The optional --ping argument must be passed in attached (=) form so
// getopt treats it as the option's value rather than a path to scan. A single
// attempt keeps it fast, and any non-zero exit (daemon down, or an old
// clamdscan without --ping) means "treat the daemon as unavailable".
func daemonRunning(ctx context.Context, clamdscan string) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, clamdscan, "--ping=1").Run() == nil
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
