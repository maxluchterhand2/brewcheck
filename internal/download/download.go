// Package download manages the quarantine directory and streams artifacts to
// disk while computing their sha256. Nothing here ever loads a whole artifact
// into memory, and nothing trusts the bytes — verification happens afterwards.
package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"brewcheck/internal/progress"
)

// Fetcher opens a stream for an artifact. Implementations live in internal/oci
// (ghcr.io bottles) and internal/download (direct HTTP for casks).
type Fetcher interface {
	// Open returns the artifact body and its expected size (-1 if unknown).
	Open(ctx context.Context) (body io.ReadCloser, size int64, err error)
	// FileName is a suggested base name for the quarantined file.
	FileName() string
}

// Quarantine is an isolated, restrictive-perms directory for unverified bytes.
type Quarantine struct {
	Dir  string
	keep bool
}

// NewQuarantine creates a unique 0700 directory. If base is empty, the OS temp
// dir is used.
func NewQuarantine(base string, keep bool) (*Quarantine, error) {
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, fmt.Errorf("creating quarantine base: %w", err)
	}
	dir, err := os.MkdirTemp(base, "brewcheck-")
	if err != nil {
		return nil, fmt.Errorf("creating quarantine dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("securing quarantine dir: %w", err)
	}
	return &Quarantine{Dir: dir, keep: keep}, nil
}

// Scratch returns (creating if needed) a subdirectory inside the quarantine,
// used to sandbox extraction.
func (q *Quarantine) Scratch(name string) (string, error) {
	p := filepath.Join(q.Dir, name)
	if err := os.MkdirAll(p, 0o700); err != nil {
		return "", err
	}
	return p, nil
}

// Cleanup removes the quarantine directory unless keep was set.
func (q *Quarantine) Cleanup() {
	if q == nil || q.keep {
		return
	}
	_ = os.RemoveAll(q.Dir)
}

// Result describes a completed download.
type Result struct {
	Path   string
	SHA256 string
	Size   int64
}

// Fetch streams f into the quarantine dir, enforcing maxSize (0 = no limit),
// and returns the path plus computed sha256. onProgress, if non-nil, is called
// as bytes arrive with (bytesSoFar, totalSize); totalSize is -1 when unknown.
func (q *Quarantine) Fetch(ctx context.Context, f Fetcher, maxSize int64, onProgress func(done, total int64)) (*Result, error) {
	body, size, err := f.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	if maxSize > 0 && size > maxSize {
		return nil, fmt.Errorf("artifact size %d exceeds max %d", size, maxSize)
	}

	dst := filepath.Join(q.Dir, sanitizeName(f.FileName()))
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening quarantine file: %w", err)
	}
	defer out.Close()

	h := sha256.New()
	var reader io.Reader = io.TeeReader(body, h)
	if maxSize > 0 {
		// +1 so we can detect overflow when Content-Length lied or was absent.
		reader = io.LimitReader(reader, maxSize+1)
	}
	reader = progress.NewReader(reader, size, onProgress)

	n, err := io.Copy(out, reader)
	if err != nil {
		_ = os.Remove(dst)
		return nil, fmt.Errorf("streaming artifact: %w", err)
	}
	if maxSize > 0 && n > maxSize {
		_ = os.Remove(dst)
		return nil, fmt.Errorf("artifact exceeded max size %d during download", maxSize)
	}
	if err := out.Sync(); err != nil {
		return nil, fmt.Errorf("syncing artifact: %w", err)
	}
	return &Result{Path: dst, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}

func sanitizeName(name string) string {
	name = filepath.Base(name)
	if name == "" || name == "." || name == "/" {
		return "artifact"
	}
	return name
}
