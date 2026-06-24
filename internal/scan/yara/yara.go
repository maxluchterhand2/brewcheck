// Package yara runs the `yara` binary against the artifact and any extracted
// contents using brewcheck's bundled macOS-focused starter rules. Shelling out
// is the right call for v0.1; in-process bindings (hillu/go-yara) are a noted
// follow-up.
package yara

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"brewcheck/internal/deps"
	"brewcheck/internal/report"
	"brewcheck/internal/timeouts"
)

// Scan recursively scans targets with the compiled/loose rules in rulesDir.
func Scan(ctx context.Context, rulesFile string, targets []string) report.LayerResult {
	res := report.LayerResult{Name: "YARA"}
	bin, ok := deps.Find("yara")
	if !ok {
		res.Status = report.StatusSkipped
		res.Hint = deps.Hints["yara"]
		return res
	}
	if len(targets) == 0 {
		res.Status = report.StatusSkipped
		res.Hint = "no targets to scan"
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, timeouts.YARA)
	defer cancel()

	res.Status = report.StatusRan
	total := 0
	for _, target := range targets {
		// -r recursive, -w no warnings, -m print rule metadata (so we can read
		// each rule's `severity`); rule first, then target.
		cmd := exec.CommandContext(ctx, bin, "-r", "-w", "-m", rulesFile, target)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			if _, ok := err.(*exec.ExitError); !ok {
				res.Status = report.StatusError
				res.Err = fmt.Sprintf("%v: %s", err, strings.TrimSpace(stderr.String()))
				return res
			}
		}
		for _, m := range parseMatches(stdout.String()) {
			total++
			sev := severityFor(m.meta["severity"])
			title := "YARA rule match: " + m.rule
			res.AddFinding(sev, title, m.meta["description"], m.path)
		}
	}
	if total == 0 {
		res.Summary = "no rules matched"
	} else {
		res.Summary = fmt.Sprintf("%d match(es)", total)
	}
	return res
}

// severityFor maps a rule's `severity` meta value onto a finding severity.
//
//	high / critical          -> malicious (definitive; delete, never cache)
//	medium                   -> suspicious (don't cache by default)
//	low / hesitant / aggressive -> hesitant (cache, but warn — these are the
//	                             intentionally pedantic, false-positive-prone rules)
//	missing / unknown        -> suspicious (a rule author who forgets a severity
//	                             meta must NOT trigger a destructive MALICIOUS
//	                             verdict; malicious is opt-in via high/critical)
func severityFor(sevMeta string) report.Severity {
	switch strings.ToLower(strings.TrimSpace(sevMeta)) {
	case "low", "hesitant", "aggressive", "noisy":
		return report.SeverityHesitant
	case "high", "critical":
		return report.SeverityMalicious
	default:
		// medium / moderate / missing / unknown — default DOWN to suspicious.
		return report.SeveritySuspicious
	}
}

type match struct {
	rule string
	path string
	meta map[string]string
}

// metaPair matches one `key=value` entry inside yara's `-m` bracket block.
// Values are either double-quoted strings or bare tokens (ints/bools).
var metaPair = regexp.MustCompile(`(\w+)=("(?:[^"\\]|\\.)*"|[^,\]]+)`)

// parseMatches reads yara's `-m` output: `RULE_NAME [k=v,k="v"] /path/to/file`.
// The metadata bracket is optional (a rule with no meta prints `RULE  /path`).
func parseMatches(out string) []match {
	var matches []match
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			continue // a bare rule name with no path; nothing actionable
		}
		rule := line[:sp]
		rest := strings.TrimSpace(line[sp+1:])

		meta := map[string]string{}
		if strings.HasPrefix(rest, "[") {
			if end := strings.Index(rest, "] "); end >= 0 {
				block := rest[1:end]
				rest = strings.TrimSpace(rest[end+2:])
				for _, kv := range metaPair.FindAllStringSubmatch(block, -1) {
					meta[kv[1]] = unquoteMeta(kv[2])
				}
			}
		}
		if rest == "" {
			continue
		}
		matches = append(matches, match{rule: rule, path: rest, meta: meta})
	}
	return matches
}

func unquoteMeta(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		inner := v[1 : len(v)-1]
		inner = strings.ReplaceAll(inner, `\"`, `"`)
		inner = strings.ReplaceAll(inner, `\\`, `\`)
		return inner
	}
	return v
}
