// Package deps detects optional external scanners on PATH and provides
// actionable install hints. A missing scanner is never fatal — the layer is
// skipped and recorded so the report can show what actually ran.
package deps

import "os/exec"

// Find returns the path of the first available binary among names.
func Find(names ...string) (path string, found bool) {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p, true
		}
	}
	return "", false
}

// Hints maps a logical scanner to a human install hint.
var Hints = map[string]string{
	"virustotal": "set VT_API_KEY (free key at https://www.virustotal.com)",
	"semgrep":    "install with: brew install semgrep",
	"clamav":     "install with: brew install clamav (then `freshclam` to fetch signatures)",
	"yara":       "install with: brew install yara",
	"7z":         "install with: brew install sevenzip",
	"capa":       "install with: pipx install flare-capa",
}
