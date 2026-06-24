package yara

import (
	"testing"

	"brewcheck/internal/report"
)

func TestParseMatches(t *testing.T) {
	out := "" +
		"Strip_Quarantine_Xattr [description=\"removes quarantine\",severity=\"hesitant\"] /tmp/scratch/postinstall.sh\n" +
		"Macho_Reverse_Shell_Strings [severity=\"high\"] /tmp/scratch/bin/agent\n" +
		"Bare_Rule_No_Meta /tmp/scratch/x\n" +
		"\n"
	got := parseMatches(out)
	if len(got) != 3 {
		t.Fatalf("expected 3 matches, got %d: %+v", len(got), got)
	}
	if got[0].rule != "Strip_Quarantine_Xattr" || got[0].path != "/tmp/scratch/postinstall.sh" {
		t.Errorf("match 0 wrong: %+v", got[0])
	}
	if got[0].meta["severity"] != "hesitant" {
		t.Errorf("severity meta not parsed: %q", got[0].meta["severity"])
	}
	if got[0].meta["description"] != "removes quarantine" {
		t.Errorf("description meta not parsed: %q", got[0].meta["description"])
	}
	if got[1].meta["severity"] != "high" || got[1].path != "/tmp/scratch/bin/agent" {
		t.Errorf("match 1 wrong: %+v", got[1])
	}
	if got[2].path != "/tmp/scratch/x" || len(got[2].meta) != 0 {
		t.Errorf("bare-meta match wrong: %+v", got[2])
	}
}

func TestSeverityFor(t *testing.T) {
	cases := map[string]report.Severity{
		"hesitant":   report.SeverityHesitant,
		"low":        report.SeverityHesitant,
		"aggressive": report.SeverityHesitant,
		"medium":     report.SeveritySuspicious,
		"high":       report.SeverityMalicious,
		"critical":   report.SeverityMalicious,
		"":           report.SeveritySuspicious, // missing -> default DOWN, never destructive
		"weird":      report.SeveritySuspicious, // unknown -> default DOWN
		"  High ":    report.SeverityMalicious,  // trimmed + case-insensitive
	}
	for in, want := range cases {
		if got := severityFor(in); got != want {
			t.Errorf("severityFor(%q) = %v, want %v", in, got, want)
		}
	}
}
