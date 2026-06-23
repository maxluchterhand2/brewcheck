package verify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name       string
		got, want  string
		wantResult bool
	}{
		{"exact", "abc123", "abc123", true},
		{"case-insensitive", "ABC123", "abc123", true},
		{"whitespace", "  abc123 ", "abc123", true},
		{"mismatch", "abc123", "def456", false},
		{"empty-want", "abc123", "", false},
		{"no_check", "abc123", "no_check", false},
		{"empty-got", "", "abc123", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.got, tt.want); got != tt.wantResult {
				t.Errorf("Match(%q,%q) = %v, want %v", tt.got, tt.want, got, tt.wantResult)
			}
		})
	}
}

func TestVerifiable(t *testing.T) {
	cases := map[string]bool{"abc": true, "": false, "no_check": false, "NO_CHECK": false, "  ": false}
	for in, want := range cases {
		if got := Verifiable(in); got != want {
			t.Errorf("Verifiable(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSHA256File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	// echo -n hello | sha256sum
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	got, err := SHA256File(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("SHA256File = %q, want %q", got, want)
	}
	if !Match(got, want) {
		t.Error("Match should be true for computed hash")
	}
}
