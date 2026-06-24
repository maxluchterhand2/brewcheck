package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
)

// fakeFetcher serves fixed bytes for Fetch tests (no network).
type fakeFetcher struct {
	data []byte
	size int64
	name string
}

func (f fakeFetcher) Open(context.Context) (io.ReadCloser, int64, error) {
	return io.NopCloser(strings.NewReader(string(f.data))), f.size, nil
}
func (f fakeFetcher) FileName() string { return f.name }

func TestQuarantinePermsAndCleanup(t *testing.T) {
	q, err := NewQuarantine(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(q.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("quarantine perms = %o, want 0700", fi.Mode().Perm())
	}
	q.Cleanup()
	if _, err := os.Stat(q.Dir); !os.IsNotExist(err) {
		t.Error("Cleanup should remove the quarantine dir")
	}
}

func TestFetchComputesSHA256(t *testing.T) {
	data := []byte("hello brewcheck")
	sum := sha256.Sum256(data)
	q, _ := NewQuarantine(t.TempDir(), true)
	defer q.Cleanup()

	res, err := q.Fetch(context.Background(), fakeFetcher{data: data, size: int64(len(data)), name: "x.bin"}, 0, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 = %s, want %s", res.SHA256, hex.EncodeToString(sum[:]))
	}
	if res.Size != int64(len(data)) {
		t.Errorf("size = %d, want %d", res.Size, len(data))
	}
}

// TestFetchSizeCapOverflow guards the +1 LimitReader trick: a body that lies
// about its size (or has none) and exceeds maxSize must be rejected.
func TestFetchSizeCapOverflow(t *testing.T) {
	data := make([]byte, 100)
	q, _ := NewQuarantine(t.TempDir(), true)
	defer q.Cleanup()

	// size reported as -1 (unknown) so the pre-check passes; the stream itself
	// exceeds the cap and must be caught during the copy.
	_, err := q.Fetch(context.Background(), fakeFetcher{data: data, size: -1, name: "x"}, 50, nil)
	if err == nil {
		t.Fatal("expected an error when the stream exceeds maxSize")
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"wget-1.0.tar.gz": "wget-1.0.tar.gz",
		"/etc/passwd":     "passwd",
		"../../escape":    "escape",
		"":                "artifact",
		"/":               "artifact",
		".":               "artifact",
		"a/b/c.dmg":       "c.dmg",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}
