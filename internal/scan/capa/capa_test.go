package capa

import (
	"context"
	"testing"

	"brewcheck/internal/report"
)

// TestAnalyzeNeverFatal confirms capa is non-fatal: whether capa is absent or
// present-but-unable-to-analyze a bogus path, the layer is skipped (or errors)
// — never a hard failure and never a verdict-moving finding.
func TestAnalyzeNeverFatal(t *testing.T) {
	res := Analyze(context.Background(), "/nonexistent/brewcheck-capa-probe")
	if res.Status == report.StatusRan && len(res.Findings) > 0 {
		for _, f := range res.Findings {
			if f.Severity != report.SeverityInfo {
				t.Errorf("capa findings must be informational, got %v", f.Severity)
			}
		}
	}
	if res.Status != report.StatusSkipped && res.Status != report.StatusError && res.Status != report.StatusRan {
		t.Errorf("unexpected status %v", res.Status)
	}
}
