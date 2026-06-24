// Package brewcache uses `brew` as a read-only path oracle: it asks brew where
// it would place a download, then drops the verified-clean bytes there. It
// never asks brew to download anything, and never reverse-engineers the cache
// filename convention (an internal detail that has changed across versions).
package brewcache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Available reports whether the brew binary is on PATH.
func Available() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

// Info returns the raw `brew info --json=v2 <ref>` output for a formula/cask
// reference (e.g. "user/repo/name" for a tap). This is how brewcheck resolves
// metadata for third-party taps, which the formulae.brew.sh API does not serve.
// brew may auto-tap (git-clone) an untapped repo to answer; that fetches only
// the formula definitions, never the artifact.
func Info(ctx context.Context, ref string) ([]byte, error) {
	if !Available() {
		return nil, fmt.Errorf("brew is required to resolve tap %q but is not on PATH", ref)
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second) // cloning a tap can be slow
	defer cancel()

	cmd := exec.CommandContext(ctx, "brew", "info", "--json=v2", ref)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("`brew info --json=v2 %s` failed: %s", ref, msg)
	}
	return stdout.Bytes(), nil
}

// CachePath returns the absolute path brew would use for the given artifact.
// kind must be "formula" or "cask". When buildFromSource is true, the source
// tarball cache path is requested (brew caches source downloads separately from
// bottles). Callers should check Available() first.
func CachePath(ctx context.Context, name, kind string, buildFromSource bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	args := []string{"--cache"}
	if kind == "cask" {
		args = append(args, "--cask")
	}
	if buildFromSource {
		args = append(args, "--build-from-source")
	}
	args = append(args, name)

	cmd := exec.CommandContext(ctx, "brew", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("`brew --cache` failed: %w", err)
	}
	path := strings.TrimSpace(string(out))
	if path == "" {
		return "", fmt.Errorf("`brew --cache` returned no path")
	}
	// brew may print multiple lines (e.g. per-file); take the first.
	if i := strings.IndexByte(path, '\n'); i >= 0 {
		path = path[:i]
	}
	return path, nil
}

// Place moves the verified-clean file to dest atomically. It tries os.Rename
// first; on a cross-filesystem error it copies into the destination directory,
// fsyncs, and renames into place so brew never sees a partial file.
func Place(src, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}
	if err := os.Rename(src, dest); err == nil {
		return nil
	}
	// Cross-device or other rename failure: copy+fsync+rename within dest dir.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".brewcheck-*")
	if err != nil {
		return fmt.Errorf("creating temp in cache dir: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if the rename below succeeds

	in, err := os.Open(src)
	if err != nil {
		tmp.Close()
		return err
	}
	defer in.Close()

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return fmt.Errorf("copying to cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("finalizing cache file: %w", err)
	}
	return nil
}
