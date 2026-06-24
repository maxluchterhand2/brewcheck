package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// JSON writes the stable machine-readable report. It is the single owner of
// SchemaVersion stamping.
func (r *Report) JSON(w io.Writer) error {
	r.SchemaVersion = SchemaVersion
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Human writes the human-readable report. It is deliberately conservative in
// its language: the strongest positive claim is "No known-malicious indicators
// found" — never "safe" (spec §7).
func (r *Report) Human(w io.Writer) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }

	p("brewcheck report")
	p("================")
	kind := string(r.Kind)
	if r.BuildFromSource {
		kind += ", source build"
	}
	p("  %-12s %s (%s)", "name:", r.Name, kind)
	if r.Version != "" {
		p("  %-12s %s", "version:", r.Version)
	}
	if r.SourceURL != "" {
		p("  %-12s %s", "source:", r.SourceURL)
	}
	if r.SHA256 != "" {
		verified := "NOT verified"
		if r.HashVerified {
			verified = "verified against Homebrew ✓"
		}
		p("  %-12s %s (%s)", "sha256:", r.SHA256, verified)
	}
	if r.FromCache {
		p("  %-12s %s", "cache:", "found — scanned the existing file in place (not re-downloaded)")
	}
	p("")

	// Layers
	p("Inspection layers:")
	for _, l := range r.Layers {
		switch l.Status {
		case StatusRan:
			p("  [ran]     %s%s", l.Name, summarySuffix(l))
		case StatusSkipped:
			hint := ""
			if l.Hint != "" {
				hint = "  — " + l.Hint
			}
			p("  [skipped] %s%s", l.Name, hint)
		case StatusError:
			p("  [error]   %s — %s", l.Name, l.Err)
		}
		if c := l.Credibility; c != nil {
			p("              credibility: %s %d/%d  (%s)", credibilityBar(c.Score, c.Max), c.Score, c.Max, c.Repo)
			if len(c.Signals) > 0 {
				p("                  %s", strings.Join(c.Signals, " · "))
			}
		}
		for _, f := range l.Findings {
			line := fmt.Sprintf("              %s %s", plainMarker(f.Severity), f.Title)
			if f.Location != "" {
				line += fmt.Sprintf(" (%s)", f.Location)
			}
			p("%s", line)
			if f.Detail != "" {
				for _, dl := range strings.Split(strings.TrimRight(f.Detail, "\n"), "\n") {
					p("                  %s", dl)
				}
			}
		}
	}
	p("")
	p("  %d of %d layers ran.%s", CountRan(r.Layers), len(r.Layers), degradedSuffix(r))
	p("")

	// Verdict
	p("Verdict: %s", r.Verdict)
	if r.Verdict == VerdictError {
		if r.Error != "" {
			p("  %s", r.Error)
		}
	} else {
		p("  %s", r.Verdict.Headline())
		for _, d := range r.Verdict.Detail() {
			p("  %s", d)
		}
	}
	p("")
	p("Action: %s", r.Action.Describe(r.CachePath))
}

func summarySuffix(l LayerResult) string {
	if l.Summary != "" {
		return " — " + l.Summary
	}
	if len(l.Findings) == 0 {
		return " — nothing flagged"
	}
	return ""
}

func degradedSuffix(r *Report) string {
	if r.Degraded <= 0 {
		return ""
	}
	return fmt.Sprintf("  (degraded — %d layer(s) errored; verdict is weaker than a full run)", r.Degraded)
}

// credibilityBar renders a fixed-width [████░░░░░░] gauge for a 0..max score.
func credibilityBar(score, max int) string {
	filled, empty := CredibilityFill(score, max)
	if max <= 0 {
		return ""
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", empty) + "]"
}

// plainMarker is the plain-text finding marker, e.g. "‼ MALICIOUS:".
func plainMarker(s Severity) string {
	if w := s.Label(); w != "" {
		return s.Glyph() + " " + w + ":"
	}
	return s.Glyph()
}
