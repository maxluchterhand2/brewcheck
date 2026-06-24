package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"brewcheck/internal/report"
)

func noLog(string, ...any) {}

// TestDecideCachedAction verifies the cache-reuse policy: a file scanned in
// place from brew's cache is kept on CLEAN/HESITANT/SUSPICIOUS and only removed
// on MALICIOUS.
func TestDecideCachedAction(t *testing.T) {
	tests := []struct {
		name       string
		verdict    report.Verdict
		wantAction string
		wantGone   bool // file removed from cache?
		wantCached bool
	}{
		{"clean stays", report.VerdictClean, "already-cached", false, true},
		{"hesitant stays", report.VerdictHesitant, "already-cached", false, true},
		{"suspicious stays (not deleted)", report.VerdictSuspicious, "kept-in-cache", false, true},
		{"malicious is evicted", report.VerdictMalicious, "deleted-from-cache", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "artifact.bin")
			if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
				t.Fatal(err)
			}
			r := &report.Report{Verdict: tt.verdict}
			decideCachedAction(r, path, noLog)

			if r.Action != tt.wantAction {
				t.Errorf("action = %q, want %q", r.Action, tt.wantAction)
			}
			if r.Cached != tt.wantCached {
				t.Errorf("cached = %v, want %v", r.Cached, tt.wantCached)
			}
			_, statErr := os.Stat(path)
			gone := os.IsNotExist(statErr)
			if gone != tt.wantGone {
				t.Errorf("file removed = %v, want %v", gone, tt.wantGone)
			}
		})
	}
}
