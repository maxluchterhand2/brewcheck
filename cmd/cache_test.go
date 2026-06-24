package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"brewcheck/internal/report"
)

func noLog(string, ...any) {}

// TestDecideActionFreshDownload covers the cache-or-delete policy for a freshly
// downloaded artifact: CLEAN/HESITANT with a verified hash and caching enabled
// are placed in the cache; everything else is deleted (or kept with --keep).
func TestDecideActionFreshDownload(t *testing.T) {
	tests := []struct {
		name       string
		verdict    report.Verdict
		hashOK     bool
		cfg        config
		cacheDest  bool // is a cache path available?
		wantAction report.Action
		wantCached bool
		wantPlaced bool // bytes moved into cacheDest?
	}{
		{"clean caches", report.VerdictClean, true, config{}, true, report.ActionCached, true, true},
		{"hesitant caches", report.VerdictHesitant, true, config{}, true, report.ActionCached, true, true},
		{"clean + no-cache deletes", report.VerdictClean, true, config{noCache: true}, true, report.ActionDeleted, false, false},
		{"clean + keep keeps", report.VerdictClean, true, config{keep: true, noCache: true}, true, report.ActionKept, false, false},
		{"clean but unverified deletes", report.VerdictClean, false, config{}, true, report.ActionDeleted, false, false},
		{"clean but no cache path deletes", report.VerdictClean, true, config{}, false, report.ActionDeleted, false, false},
		{"suspicious deletes", report.VerdictSuspicious, true, config{}, true, report.ActionDeleted, false, false},
		{"malicious deletes", report.VerdictMalicious, true, config{}, true, report.ActionDeleted, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "artifact.bin")
			if err := os.WriteFile(artifact, []byte("bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
			cacheDest := ""
			if tt.cacheDest {
				cacheDest = filepath.Join(dir, "cache", "dest.bin")
			}
			r := &report.Report{Verdict: tt.verdict, HashVerified: tt.hashOK}

			decideAction(r, artifact, false, cacheDest, tt.cfg, noLog)

			if r.Action != tt.wantAction {
				t.Errorf("action = %q, want %q", r.Action, tt.wantAction)
			}
			if r.Cached != tt.wantCached {
				t.Errorf("cached = %v, want %v", r.Cached, tt.wantCached)
			}
			if tt.wantPlaced {
				if _, err := os.Stat(cacheDest); err != nil {
					t.Errorf("expected bytes placed at cacheDest: %v", err)
				}
			}
		})
	}
}

// TestDecideCachedAction verifies the cache-reuse policy: a file scanned in
// place from brew's cache is kept on CLEAN/HESITANT/SUSPICIOUS and only removed
// on MALICIOUS.
func TestDecideCachedAction(t *testing.T) {
	tests := []struct {
		name       string
		verdict    report.Verdict
		wantAction report.Action
		wantGone   bool // file removed from cache?
		wantCached bool
	}{
		{"clean stays", report.VerdictClean, report.ActionAlreadyCached, false, true},
		{"hesitant stays", report.VerdictHesitant, report.ActionAlreadyCached, false, true},
		{"suspicious stays (not deleted)", report.VerdictSuspicious, report.ActionKeptInCache, false, true},
		{"malicious is evicted", report.VerdictMalicious, report.ActionDeletedFromCache, true, false},
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
