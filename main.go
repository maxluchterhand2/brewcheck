package main

import (
	"embed"

	"brewcheck/cmd"
)

// rulesFS bundles the semgrep/yara rule trees into the binary so they ship with
// it and can't be misplaced. BREWCHECK_RULES_DIR still overrides at runtime.
//
//go:embed all:rules
var rulesFS embed.FS

func main() {
	cmd.Execute(rulesFS)
}
