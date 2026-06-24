package extract

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// scriptNames are install-script basenames worth surfacing (pkg payloads).
var scriptNames = map[string]bool{
	"preinstall":  true,
	"postinstall": true,
	"preflight":   true,
	"postflight":  true,
	"preupgrade":  true,
	"postupgrade": true,
}

// FindScripts walks an extracted tree and returns paths to likely install
// scripts: known script basenames, anything under a Scripts/ directory, and
// shell/ruby/python scripts. Used by static analysis to surface what an
// installer would run.
func FindScripts(root string) []string {
	var found []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := strings.ToLower(d.Name())
		ext := strings.ToLower(filepath.Ext(base))
		parent := strings.ToLower(filepath.Base(filepath.Dir(path)))

		switch {
		case scriptNames[base]:
		case parent == "scripts":
		case ext == ".sh" || ext == ".bash" || ext == ".zsh" || ext == ".rb" || ext == ".py" || ext == ".pl":
		default:
			return nil
		}
		// Skip absurdly large files to keep static analysis cheap.
		if info, e := d.Info(); e == nil && info.Size() > 2<<20 {
			return nil
		}
		found = append(found, path)
		return nil
	})
	return found
}

// machoMagics are the 4-byte magic numbers that start a Mach-O (thin or fat)
// binary, in both byte orders.
var machoMagics = [][4]byte{
	{0xFE, 0xED, 0xFA, 0xCE}, {0xCE, 0xFA, 0xED, 0xFE}, // 32-bit
	{0xFE, 0xED, 0xFA, 0xCF}, {0xCF, 0xFA, 0xED, 0xFE}, // 64-bit
	{0xCA, 0xFE, 0xBA, 0xBE}, {0xBE, 0xBA, 0xFE, 0xCA}, // universal (fat)
}

// FindMachO walks an extracted tree and returns the path of the first Mach-O
// binary it finds (by magic number), or "" if none.
func FindMachO(root string) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, e := d.Info()
		if e != nil || !info.Mode().IsRegular() || info.Size() < 4 {
			return nil
		}
		f, e := os.Open(path)
		if e != nil {
			return nil
		}
		var magic [4]byte
		_, e = io.ReadFull(f, magic[:])
		f.Close()
		if e != nil {
			return nil
		}
		if slices.Contains(machoMagics, magic) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// ReadCapped reads up to max bytes of a file (for static scanning). It uses
// io.ReadAll over a LimitReader so it reads the *whole* capped region — a
// single Read may return a short chunk without EOF, which would silently scan
// only the start of a script and miss patterns later in the file.
func ReadCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}
