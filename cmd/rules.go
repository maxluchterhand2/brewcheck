package cmd

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

// embeddedRules holds the bundled rules/ tree (semgrep + yara), compiled into
// the binary so they can never be misplaced. Set by Execute.
var embeddedRules embed.FS

// resolveRules returns a directory containing the semgrep/ and yara/ rule trees
// plus a cleanup func. BREWCHECK_RULES_DIR overrides (returned as-is); otherwise
// the embedded rules are materialized to a temp dir, because the external tools
// (semgrep, yara) read rules from disk.
func resolveRules() (dir string, cleanup func(), err error) {
	cleanup = func() {}
	if d := os.Getenv("BREWCHECK_RULES_DIR"); d != "" {
		return d, cleanup, nil
	}
	tmp, err := os.MkdirTemp("", "brewcheck-rules-")
	if err != nil {
		return "", cleanup, err
	}
	if err := materializeRules(tmp); err != nil {
		os.RemoveAll(tmp)
		return "", cleanup, err
	}
	return tmp, func() { os.RemoveAll(tmp) }, nil
}

// materializeRules writes the embedded rules/ tree into dir, stripping the
// leading "rules/" so dir ends up containing semgrep/ and yara/ directly.
func materializeRules(dir string) error {
	return fs.WalkDir(embeddedRules, "rules", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("rules", p)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, err := embeddedRules.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}
