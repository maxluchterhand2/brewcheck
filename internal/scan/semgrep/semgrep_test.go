package semgrep

import (
	"context"
	"testing"

	"brewcheck/internal/report"
)

// TestScanNoTargetsOrMissing confirms Scan never errors when there's nothing to
// do: with no targets it skips, and with semgrep absent it also skips (never
// fatal). Either way the result is a clean skip.
func TestScanNoTargets(t *testing.T) {
	res := Scan(context.Background(), "rules", nil)
	if res.Status != report.StatusSkipped {
		t.Errorf("status = %v, want skipped (no targets / semgrep absent)", res.Status)
	}
	if res.Hint == "" {
		t.Error("a skipped layer should carry a hint")
	}
}
