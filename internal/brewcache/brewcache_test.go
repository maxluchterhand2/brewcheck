package brewcache

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPlaceMovesBytes verifies the cache hand-off writes exactly the source
// bytes to the destination and creates parent dirs that don't exist yet.
func TestPlaceMovesBytes(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "quarantine", "artifact.bin")
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatal(err)
	}
	want := []byte("verified-clean-bytes")
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatal(err)
	}

	// Destination dir does not exist yet — Place must create it.
	dest := filepath.Join(dir, "cache", "downloads", "abc--artifact.bin")
	if err := Place(src, dest); err != nil {
		t.Fatalf("Place: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("reading dest: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("cached bytes = %q, want %q", got, want)
	}
}

// TestPlaceCopyFallback exercises the copy+fsync+rename path by pre-creating the
// destination file (rename still succeeds, but this guards the non-error flow
// and that the final contents are correct).
func TestPlaceCopyFallback(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "dest")
	if err := os.WriteFile(dest, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Place(src, dest); err != nil {
		t.Fatalf("Place: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "payload" {
		t.Errorf("dest = %q, want payload", got)
	}
}
