// Package verify performs the load-bearing sha256 check: it proves the bytes
// we scanned are byte-identical to what brew will install, and closes the
// TOCTOU window (brew re-verifies the cache file's hash at install time).
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// Match reports whether a computed hex digest equals the published one,
// case-insensitively. An empty or sentinel ("no_check") published hash never
// matches — there is nothing to verify against.
func Match(got, want string) bool {
	want = strings.TrimSpace(strings.ToLower(want))
	got = strings.TrimSpace(strings.ToLower(got))
	if !Verifiable(want) || got == "" {
		return false
	}
	return got == want
}

// Verifiable reports whether the published hash is something we can check.
func Verifiable(want string) bool {
	want = strings.TrimSpace(strings.ToLower(want))
	return want != "" && want != "no_check"
}

// SHA256File computes the sha256 of a file (used in tests and as a re-check).
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
