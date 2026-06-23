// Package extract safely unpacks artifacts for scanning. The guiding rule
// (spec §6): prefer extraction over mounting or executing. We never
// `hdiutil attach` a dmg and never run a pkg installer — we expand with
// `pkgutil --expand` and unpack archives with 7z or in-process Go readers,
// all into a sandboxed scratch dir with zip-slip and size/count guards.
package extract

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"brewcheck/internal/deps"
)

// Limits bound extraction to guard against zip bombs.
type Limits struct {
	MaxFiles int
	MaxBytes int64
}

// DefaultLimits are conservative defaults.
var DefaultLimits = Limits{MaxFiles: 20000, MaxBytes: 2 << 30} // 2 GiB

// ErrUnsupported indicates no extractor is available for the artifact.
var ErrUnsupported = fmt.Errorf("no available extractor for artifact")

// Artifact extracts src into a fresh subdir of scratchParent based on the file
// type, returning the directory containing the extracted tree. Extraction is
// best-effort: callers treat errors as "could not extract" and continue.
func Artifact(ctx context.Context, src, scratchParent string) (string, error) {
	dest := filepath.Join(scratchParent, "extracted")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return "", err
	}
	lower := strings.ToLower(src)

	switch {
	case strings.HasSuffix(lower, ".pkg") || strings.HasSuffix(lower, ".mpkg"):
		return dest, ExpandPkg(ctx, src, filepath.Join(dest, "pkg"))
	case strings.HasSuffix(lower, ".zip"):
		return dest, SafeUnzip(src, dest, DefaultLimits)
	case strings.HasSuffix(lower, ".dmg"):
		// Never mount: extract with 7z so nothing is attached.
		return dest, Extract7z(ctx, src, dest)
	default:
		// tar.gz bottles and everything else: try 7z if present.
		if _, ok := deps.Find("7z", "7zz", "7za"); ok {
			return dest, Extract7z(ctx, src, dest)
		}
		return dest, ErrUnsupported
	}
}

// ExpandPkg runs `pkgutil --expand` (which never executes the installer).
// dest must not already exist (pkgutil requirement).
func ExpandPkg(ctx context.Context, pkg, dest string) error {
	if _, err := exec.LookPath("pkgutil"); err != nil {
		return fmt.Errorf("pkgutil not available: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pkgutil", "--expand", pkg, dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pkgutil --expand: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Extract7z shells out to a 7-Zip binary to unpack without mounting.
func Extract7z(ctx context.Context, src, dest string) error {
	bin, ok := deps.Find("7z", "7zz", "7za")
	if !ok {
		return fmt.Errorf("7z not available: %w", ErrUnsupported)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// -y assume yes, -o output dir (no space), x preserves paths.
	cmd := exec.CommandContext(ctx, bin, "x", "-y", "-o"+dest, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("7z extraction: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SafeUnzip extracts a zip in-process with a zip-slip guard and size/count
// caps. This is the path used for cask .zip artifacts.
func SafeUnzip(src, dest string, lim Limits) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer zr.Close()

	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}

	var files int
	var total int64
	for _, zf := range zr.File {
		files++
		if lim.MaxFiles > 0 && files > lim.MaxFiles {
			return fmt.Errorf("zip exceeds max file count %d", lim.MaxFiles)
		}
		target, err := safeJoin(destAbs, zf.Name)
		if err != nil {
			return err
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		n, err := extractZipFile(zf, target, lim.MaxBytes-total)
		if err != nil {
			return err
		}
		total += n
		if lim.MaxBytes > 0 && total > lim.MaxBytes {
			return fmt.Errorf("zip exceeds max uncompressed size %d", lim.MaxBytes)
		}
	}
	return nil
}

func extractZipFile(zf *zip.File, target string, remaining int64) (int64, error) {
	rc, err := zf.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	var reader io.Reader = rc
	if remaining > 0 {
		reader = io.LimitReader(rc, remaining+1)
	}
	return io.Copy(out, reader)
}

// safeJoin joins base and an archive entry name, rejecting path traversal
// (zip-slip): the cleaned result must stay within base.
func safeJoin(base, name string) (string, error) {
	// Reject absolute entry names outright.
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unsafe absolute path in archive: %q", name)
	}
	target := filepath.Join(base, name)
	cleaned := filepath.Clean(target)
	if cleaned != base && !strings.HasPrefix(cleaned, base+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal in archive entry: %q", name)
	}
	return cleaned, nil
}
