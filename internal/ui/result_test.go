package ui

import (
	"strings"
	"testing"

	"brewcheck/internal/report"
)

func TestResultViewContent(t *testing.T) {
	r := &report.Report{
		Name: "jq", Kind: "formula", Version: "1.8.1",
		SHA256: "abcdef0123456789abcdef", HashVerified: true,
		Layers: []report.LayerResult{
			{Name: "sha256 verification", Status: report.StatusRan, Summary: "verified against Homebrew ✓"},
			{Name: "Semgrep", Status: report.StatusSkipped, Hint: "no scannable targets"},
			{Name: "GitHub author credibility", Status: report.StatusRan,
				Credibility: &report.Credibility{Score: 10, Max: 10, Repo: "github.com/jqlang/jq", Signals: []string{"35,018★"}}},
		},
		Verdict: report.VerdictClean, Action: "cached", CachePath: "/c",
	}
	out := Model{report: r, width: 100}.resultView()

	if strings.Contains(strings.ToLower(out), "safe") {
		t.Errorf("result view must never claim 'safe':\n%s", out)
	}
	for _, want := range []string{"CLEAN", "No known-malicious", "jq", "credibility", "10/10", "35,018★"} {
		if !strings.Contains(out, want) {
			t.Errorf("result view missing %q", want)
		}
	}
}

func TestVerdictMessageAndExit(t *testing.T) {
	cases := []struct {
		v    report.Verdict
		want string // substring expected in the message
	}{
		{report.VerdictClean, "No known-malicious"},
		{report.VerdictHesitant, "aggressive heuristic"},
		{report.VerdictSuspicious, "Suspicious"},
		{report.VerdictMalicious, "Known-malicious"},
	}
	for _, c := range cases {
		msg := verdictMessage(&report.Report{Verdict: c.v})
		if !strings.Contains(msg, c.want) {
			t.Errorf("verdictMessage(%s) = %q, want substring %q", c.v, msg, c.want)
		}
		if strings.Contains(strings.ToLower(msg), "safe") {
			t.Errorf("verdictMessage(%s) must not say 'safe'", c.v)
		}
	}
}

// TestModelExitCode confirms the model maps the report verdict to the exit code,
// and reports an interrupt code when aborted before completion.
func TestModelExitCode(t *testing.T) {
	if got := (Model{report: &report.Report{Verdict: report.VerdictMalicious}}).ExitCode(); got != 2 {
		t.Errorf("malicious exit code = %d, want 2", got)
	}
	if got := (Model{}).ExitCode(); got != 130 {
		t.Errorf("aborted (no report) exit code = %d, want 130", got)
	}
}
