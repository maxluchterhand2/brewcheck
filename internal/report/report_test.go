package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestAggregateVerdict(t *testing.T) {
	tests := []struct {
		name   string
		layers []LayerResult
		want   Verdict
	}{
		{"empty", nil, VerdictClean},
		{"all-clean", []LayerResult{{Findings: []Finding{{Severity: SeverityInfo}}}}, VerdictClean},
		{"one-suspicious", []LayerResult{{Findings: []Finding{{Severity: SeveritySuspicious}}}}, VerdictSuspicious},
		{"malicious-wins", []LayerResult{
			{Findings: []Finding{{Severity: SeveritySuspicious}}},
			{Findings: []Finding{{Severity: SeverityMalicious}}},
		}, VerdictMalicious},
		{"info-only", []LayerResult{{Findings: []Finding{{Severity: SeverityInfo}, {Severity: SeverityInfo}}}}, VerdictClean},
		{"one-hesitant", []LayerResult{{Findings: []Finding{{Severity: SeverityHesitant}}}}, VerdictHesitant},
		{"hesitant-plus-info", []LayerResult{{Findings: []Finding{{Severity: SeverityInfo}, {Severity: SeverityHesitant}}}}, VerdictHesitant},
		{"suspicious-beats-hesitant", []LayerResult{
			{Findings: []Finding{{Severity: SeverityHesitant}}},
			{Findings: []Finding{{Severity: SeveritySuspicious}}},
		}, VerdictSuspicious},
		{"malicious-beats-hesitant", []LayerResult{
			{Findings: []Finding{{Severity: SeverityHesitant}}},
			{Findings: []Finding{{Severity: SeverityMalicious}}},
		}, VerdictMalicious},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AggregateVerdict(tt.layers); got != tt.want {
				t.Errorf("AggregateVerdict = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExitCodes(t *testing.T) {
	cases := map[Verdict]int{
		VerdictClean:      0,
		VerdictSuspicious: 1,
		VerdictMalicious:  2,
		VerdictError:      3,
		VerdictHesitant:   4,
	}
	for v, want := range cases {
		if got := v.ExitCode(); got != want {
			t.Errorf("%v.ExitCode() = %d, want %d", v, got, want)
		}
	}
}

func TestHumanNeverSaysSafe(t *testing.T) {
	r := &Report{
		Name: "wget", Kind: "formula", Version: "1.0", SHA256: "abc", HashVerified: true,
		Layers:  []LayerResult{{Name: "L1", Status: StatusRan}},
		Verdict: VerdictClean, Action: "cached", CachePath: "/x",
	}
	var buf bytes.Buffer
	r.Human(&buf)
	out := buf.String()
	if strings.Contains(strings.ToLower(out), "safe") {
		t.Errorf("human output must never claim 'safe':\n%s", out)
	}
	if !strings.Contains(out, "No known-malicious indicators found") {
		t.Error("clean verdict should print the conservative claim")
	}
	if !strings.Contains(out, "verified against Homebrew") {
		t.Error("should show hash verification status")
	}
}

func TestHumanHesitantWarnsButCaches(t *testing.T) {
	r := &Report{
		Name: "somecask", Kind: "cask", Version: "2.0", SHA256: "deadbeef", HashVerified: true,
		Layers: []LayerResult{{Name: "YARA", Status: StatusRan, Findings: []Finding{
			{Severity: SeverityHesitant, Title: "YARA rule match: Strip_Quarantine_Xattr"},
		}}},
		Verdict: VerdictHesitant, Action: "cached", Cached: true, CachePath: "/cache/x",
	}
	var buf bytes.Buffer
	r.Human(&buf)
	out := buf.String()
	if strings.Contains(strings.ToLower(out), "safe") {
		t.Errorf("human output must never claim 'safe':\n%s", out)
	}
	if !strings.Contains(out, "HESITANT") {
		t.Error("hesitant verdict should be named in the report")
	}
	if !strings.Contains(out, "NOT deleted") || !strings.Contains(out, "cache") {
		t.Error("hesitant verdict should explain the bytes were kept and cached")
	}
}

func TestJSONStableSchema(t *testing.T) {
	r := &Report{Name: "x", Kind: "cask", Verdict: VerdictSuspicious}
	var buf bytes.Buffer
	if err := r.JSON(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, field := range []string{`"schema_version"`, `"verdict"`, `"layers"`, `"cached"`} {
		if !strings.Contains(out, field) {
			t.Errorf("JSON missing field %s", field)
		}
	}
	if !strings.Contains(out, SchemaVersion) {
		t.Errorf("JSON missing schema version %s", SchemaVersion)
	}
}
