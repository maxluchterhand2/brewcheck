// Package semgrep runs the local OSS Semgrep engine with brewcheck's curated
// Ruby/shell rules against the definition and any extracted scripts.
package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"brewcheck/internal/deps"
	"brewcheck/internal/report"
)

// Scan runs semgrep over targets with the given rules dir. Missing semgrep is
// recorded as skipped, never fatal.
func Scan(ctx context.Context, rulesDir string, targets []string) report.LayerResult {
	res := report.LayerResult{Name: "Semgrep (static rules)"}
	bin, ok := deps.Find("semgrep")
	if !ok {
		res.Status = report.StatusSkipped
		res.Hint = deps.Hints["semgrep"]
		return res
	}
	if len(targets) == 0 {
		res.Status = report.StatusSkipped
		res.Hint = "no scannable targets (definition has no extractable scripts)"
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	args := []string{"--config", rulesDir, "--json", "--quiet", "--no-git-ignore"}
	args = append(args, targets...)
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.Output()
	// semgrep exits non-zero when findings exist; parse output regardless.
	if len(out) == 0 && err != nil {
		res.Status = report.StatusError
		res.Err = err.Error()
		return res
	}

	var parsed struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
			} `json:"extra"`
		} `json:"results"`
	}
	if jerr := json.Unmarshal(out, &parsed); jerr != nil {
		res.Status = report.StatusError
		res.Err = fmt.Sprintf("parsing semgrep output: %v", jerr)
		return res
	}

	res.Status = report.StatusRan
	for _, r := range parsed.Results {
		// Pattern-based static findings are capped at "suspicious" by design
		// (only authoritative scanners produce "malicious"). INFO-level rules
		// are the intentionally pedantic / FP-prone ones — map them to the
		// non-blocking "hesitant" tier so they warn without refusing the cache.
		sev := report.SeveritySuspicious
		if r.Extra.Severity == "INFO" {
			sev = report.SeverityHesitant
		}
		title := r.Extra.Message
		if title == "" {
			title = r.CheckID
		}
		res.AddFinding(sev, title, r.CheckID, fmt.Sprintf("%s:%d", r.Path, r.Start.Line))
	}
	res.Summary = fmt.Sprintf("%d rule match(es)", len(parsed.Results))
	return res
}
