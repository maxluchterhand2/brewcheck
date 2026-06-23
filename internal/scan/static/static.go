// Package static performs the local, zero-upload static analysis of the
// definition JSON and any extracted install scripts. Per the spec this is the
// highest-value layer: it surfaces what an install would actually do
// (postinstall/uninstall/zap stanzas, pkg scripts) and flags risky patterns
// (curl|bash, base64|sh, LaunchAgents, reverse shells, obfuscation).
//
// It is heuristic and pattern-based — inspired by Datadog's guarddog, not a
// dependency. Patterns are intentionally conservative about severity: most are
// "suspicious" (worth a human look), reserving "malicious" for the scanners
// with authoritative signal (VT/ClamAV/YARA).
package static

import (
	"encoding/json"
	"fmt"
	"regexp"

	"brewcheck/internal/extract"
	"brewcheck/internal/report"
)

type pattern struct {
	re    *regexp.Regexp
	sev   report.Severity
	title string
}

// patterns are applied to both the raw definition JSON and extracted scripts.
var patterns = []pattern{
	{regexp.MustCompile(`(?i)curl[^|\n]*\|\s*(sh|bash|zsh)\b`), report.SeveritySuspicious, "pipes curl output directly into a shell"},
	{regexp.MustCompile(`(?i)wget[^|\n]*\|\s*(sh|bash|zsh)\b`), report.SeveritySuspicious, "pipes wget output directly into a shell"},
	{regexp.MustCompile(`(?i)base64\s+(-d|--decode|-D)[^|\n]*\|\s*(sh|bash|zsh)\b`), report.SeveritySuspicious, "decodes base64 and pipes it into a shell"},
	{regexp.MustCompile(`(?i)\beval\b\s*[("$]`), report.SeveritySuspicious, "uses eval on dynamic input"},
	{regexp.MustCompile(`(?i)/dev/tcp/`), report.SeveritySuspicious, "uses /dev/tcp (possible reverse shell)"},
	{regexp.MustCompile(`(?i)\bnc\b[^\n]*\s-e\b`), report.SeveritySuspicious, "uses netcat with -e (possible reverse shell)"},
	{regexp.MustCompile(`(?i)LaunchAgents|LaunchDaemons`), report.SeveritySuspicious, "writes a LaunchAgent/LaunchDaemon (persistence)"},
	{regexp.MustCompile(`(?i)\blaunchctl\b`), report.SeveritySuspicious, "invokes launchctl (persistence/service control)"},
	{regexp.MustCompile(`(?i)\bosascript\b`), report.SeveritySuspicious, "runs AppleScript via osascript"},
	{regexp.MustCompile(`(?i)\bsudo\b`), report.SeveritySuspicious, "requests elevated privileges via sudo"},
	{regexp.MustCompile(`(?i)\bchmod\b[^\n]*\b(\+x|0?7[0-7][0-7])\b`), report.SeverityInfo, "changes file execute permissions"},
	{regexp.MustCompile(`(?i)python[0-9.]*\s+-c\s`), report.SeveritySuspicious, "runs an inline python one-liner"},
	{regexp.MustCompile(`(?i)\bperl\b\s+-e\s`), report.SeveritySuspicious, "runs an inline perl one-liner"},
	{regexp.MustCompile(`(?i)\bxxd\b|\bopenssl\s+enc\b`), report.SeverityInfo, "encodes/decodes data (possible obfuscation)"},
	{regexp.MustCompile(`https?://[^\s"']+`), report.SeverityInfo, "makes a network reference"},
}

// Analyze runs static analysis over the definition JSON and any extracted
// script paths. kind is "formula" or "cask".
func Analyze(kind, name string, defJSON []byte, scriptPaths []string) report.LayerResult {
	res := report.LayerResult{Name: "static analysis (definition + scripts)", Status: report.StatusRan}

	// 1) Surface what cask install/uninstall stanzas do.
	if kind == "cask" {
		surfaceCaskArtifacts(defJSON, &res)
	}

	// 2) Pattern-scan the raw definition JSON.
	scanBytes(defJSON, "definition JSON", &res)

	// 3) Pattern-scan extracted install scripts (the real installer surface).
	for _, sp := range scriptPaths {
		data, err := extract.ReadCapped(sp, 1<<20)
		if err != nil {
			continue
		}
		res.AddFinding(report.SeverityInfo, "install script present", fmt.Sprintf("%d bytes", len(data)), sp)
		scanBytes(data, sp, &res)
	}

	if len(res.Findings) == 0 {
		res.Summary = "no risky patterns in definition or scripts"
	} else {
		res.Summary = fmt.Sprintf("%d observation(s) — review what the install does", len(res.Findings))
	}
	return res
}

func scanBytes(data []byte, loc string, res *report.LayerResult) {
	for _, p := range patterns {
		if p.re.Match(data) {
			res.AddFinding(p.sev, p.title, "", loc)
		}
	}
}

// surfaceCaskArtifacts decodes the cask artifacts array and surfaces
// uninstall/zap stanzas, pkg/installer/binary artifacts, and any embedded
// scripts so the user sees exactly what the cask manipulates.
func surfaceCaskArtifacts(defJSON []byte, res *report.LayerResult) {
	var cask struct {
		Artifacts []map[string]json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(defJSON, &cask); err != nil {
		return
	}
	for _, art := range cask.Artifacts {
		for key, raw := range art {
			switch key {
			case "uninstall", "zap":
				res.AddFinding(report.SeverityInfo, "cask "+key+" stanza", summarizeStanza(raw), "artifacts."+key)
				// uninstall/zap can carry a "script" that runs a command.
				if hasScriptStanza(raw) {
					res.AddFinding(report.SeveritySuspicious, "cask "+key+" runs a script/launchctl/pkgutil action", "", "artifacts."+key)
				}
			case "pkg":
				res.AddFinding(report.SeverityInfo, "cask installs a .pkg (scripts expanded & scanned separately)", "", "artifacts.pkg")
			case "installer":
				res.AddFinding(report.SeveritySuspicious, "cask uses an installer stanza (may run scripts/manual steps)", string(truncate(raw, 200)), "artifacts.installer")
			case "binary":
				res.AddFinding(report.SeverityInfo, "cask symlinks a binary onto PATH", "", "artifacts.binary")
			}
		}
	}
}

func hasScriptStanza(raw json.RawMessage) bool {
	s := string(raw)
	return regexp.MustCompile(`(?i)"(script|launchctl|pkgutil|delete|trash|rmdir|kext|signal)"`).MatchString(s)
}

func summarizeStanza(raw json.RawMessage) string {
	return string(truncate(raw, 240))
}

func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return append(append([]byte{}, b[:n]...), "..."...)
}
