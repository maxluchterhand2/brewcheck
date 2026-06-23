// Package capa optionally surfaces capabilities (e.g. "persists via launch
// agent", "communicates over network") using Mandiant's capa. This is
// heuristic context, never a verdict — failures are non-fatal and findings are
// always informational.
package capa

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"brewcheck/internal/deps"
	"brewcheck/internal/report"
)

// Analyze runs capa against a single binary path. Mach-O support is improving;
// any error is recorded as a skipped/errored layer, not a failure.
func Analyze(ctx context.Context, path string) report.LayerResult {
	res := report.LayerResult{Name: "capa (capabilities, informational)"}
	bin, ok := deps.Find("capa")
	if !ok {
		res.Status = report.StatusSkipped
		res.Hint = deps.Hints["capa"]
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-j", path)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		// capa frequently can't analyze non-PE/partial Mach-O; treat as skipped.
		res.Status = report.StatusSkipped
		res.Hint = "capa could not analyze this artifact (often expected for Mach-O)"
		return res
	}

	var parsed struct {
		Rules map[string]struct {
			Meta struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"meta"`
		} `json:"rules"`
	}
	if jerr := json.Unmarshal(out, &parsed); jerr != nil {
		res.Status = report.StatusSkipped
		res.Hint = "capa output not parseable for this artifact"
		return res
	}

	res.Status = report.StatusRan
	for _, r := range parsed.Rules {
		res.AddFinding(report.SeverityInfo, "capability: "+r.Meta.Name, r.Meta.Namespace, "")
	}
	res.Summary = fmt.Sprintf("%d capability rule(s) matched", len(parsed.Rules))
	return res
}
