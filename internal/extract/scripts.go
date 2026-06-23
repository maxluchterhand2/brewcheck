package extract

import (
	"io/fs"
	"os"
	"path/filepath"
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

// ReadCapped reads up to max bytes of a file (for static scanning).
func ReadCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return buf[:n], nil
}
