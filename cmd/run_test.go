package cmd

import (
	"testing"

	"brewcheck/internal/report"
)

// TestVerifyHash covers the load-bearing verification branch deterministically,
// without any network: published-match (proceed), mismatch (abort SUSPICIOUS),
// and "no_check" (proceed but flag SUSPICIOUS, never cacheable).
func TestVerifyHash(t *testing.T) {
	tests := []struct {
		name           string
		published      string
		got            string
		wantAbort      bool
		wantVerified   bool
		wantSuspicious bool
	}{
		{"match", "abc123", "abc123", false, true, false},
		{"mismatch", "abc123", "deadbeef", true, false, true},
		{"no_check", "no_check", "abc123", false, false, true},
		{"empty-published", "", "abc123", false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &report.Report{}
			layer, abort := verifyHash(r, tt.published, tt.got)
			if abort != tt.wantAbort {
				t.Errorf("abort = %v, want %v", abort, tt.wantAbort)
			}
			if r.HashVerified != tt.wantVerified {
				t.Errorf("HashVerified = %v, want %v", r.HashVerified, tt.wantVerified)
			}
			gotSuspicious := false
			for _, f := range layer.Findings {
				if f.Severity == report.SeveritySuspicious {
					gotSuspicious = true
				}
			}
			if gotSuspicious != tt.wantSuspicious {
				t.Errorf("suspicious finding = %v, want %v (findings: %+v)", gotSuspicious, tt.wantSuspicious, layer.Findings)
			}
		})
	}
}
