package clamav

import "testing"

func TestChooseScanner(t *testing.T) {
	const cd, cs = "/bin/clamdscan", "/bin/clamscan"
	up := func() bool { return true }
	down := func() bool { return false }

	tests := []struct {
		name        string
		hasClamd    bool
		hasClamscan bool
		daemonUp    func() bool
		wantMode    string // "" => skipped
		wantOK      bool
	}{
		{"daemon up -> clamdscan", true, true, up, "clamdscan", true},
		{"daemon down, clamscan present -> fall back", true, true, down, "clamscan", true},
		{"daemon down, no clamscan -> skip with hint", true, false, down, "", false},
		{"no clamd, clamscan present -> clamscan (no ping)", false, true, mustNotCall(t), "clamscan", true},
		{"nothing installed -> skip", false, false, mustNotCall(t), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, hint, ok := chooseScanner(cd, tt.hasClamd, cs, tt.hasClamscan, tt.daemonUp)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (hint=%q)", ok, tt.wantOK, hint)
			}
			if s.mode != tt.wantMode {
				t.Errorf("mode = %q, want %q", s.mode, tt.wantMode)
			}
			if !ok && hint == "" {
				t.Error("a skipped selection must carry a hint")
			}
			if ok && s.bin == "" {
				t.Error("a usable selection must have a binary path")
			}
		})
	}
}

// mustNotCall returns a daemonUp func that fails the test if invoked — the
// daemon must never be pinged when clamdscan is absent.
func mustNotCall(t *testing.T) func() bool {
	return func() bool {
		t.Helper()
		t.Error("daemonUp must not be called when clamdscan is not present")
		return false
	}
}
