package extract

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeJoin(t *testing.T) {
	base := "/tmp/x"
	tests := []struct {
		name    string
		entry   string
		wantErr bool
	}{
		{"normal", "a/b.txt", false},
		{"nested", "a/b/c.txt", false},
		{"parent-escape", "../evil", true},
		{"deep-escape", "a/../../evil", true},
		{"absolute", "/etc/passwd", true},
		{"sneaky-prefix", "../xevil", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := safeJoin(base, tt.entry)
			if (err != nil) != tt.wantErr {
				t.Errorf("safeJoin(%q) err=%v, wantErr=%v", tt.entry, err, tt.wantErr)
			}
		})
	}
}

// makeZip writes a zip with the given entries (name->content) to a temp file.
func makeZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "test.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSafeUnzipRejectsZipSlip(t *testing.T) {
	src := makeZip(t, map[string]string{"../escape.txt": "pwned"})
	dest := t.TempDir()
	err := SafeUnzip(src, dest, DefaultLimits)
	if err == nil {
		t.Fatal("expected zip-slip to be rejected")
	}
	if !strings.Contains(err.Error(), "traversal") {
		t.Errorf("expected traversal error, got: %v", err)
	}
	// Ensure nothing was written outside dest.
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dest), "escape.txt")); statErr == nil {
		t.Error("zip-slip wrote a file outside the destination")
	}
}

func TestSafeUnzipExtractsNormal(t *testing.T) {
	src := makeZip(t, map[string]string{"good/file.txt": "hello", "good/sub/x.sh": "echo hi"})
	dest := t.TempDir()
	if err := SafeUnzip(src, dest, DefaultLimits); err != nil {
		t.Fatalf("SafeUnzip: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dest, "good", "file.txt"))
	if err != nil || string(data) != "hello" {
		t.Errorf("extracted content = %q, %v", data, err)
	}
}

func TestSafeUnzipEnforcesFileLimit(t *testing.T) {
	src := makeZip(t, map[string]string{"a": "1", "b": "2", "c": "3"})
	dest := t.TempDir()
	err := SafeUnzip(src, dest, Limits{MaxFiles: 2, MaxBytes: 1 << 20})
	if err == nil || !strings.Contains(err.Error(), "max file count") {
		t.Errorf("expected file-count limit error, got: %v", err)
	}
}

func TestFindScripts(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "Scripts"), 0o755)
	os.WriteFile(filepath.Join(root, "Scripts", "postinstall"), []byte("#!/bin/sh"), 0o644)
	os.WriteFile(filepath.Join(root, "install.sh"), []byte("echo"), 0o644)
	os.WriteFile(filepath.Join(root, "readme.txt"), []byte("no"), 0o644)

	scripts := FindScripts(root)
	if len(scripts) != 2 {
		t.Errorf("FindScripts found %d, want 2: %v", len(scripts), scripts)
	}
}
