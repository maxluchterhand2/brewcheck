package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// JSON writes the stable machine-readable report.
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
	p("  %-12s %s (%s)", "name:", r.Name, r.Kind)
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
	ranCount := 0
	for _, l := range r.Layers {
		switch l.Status {
		case StatusRan:
			ranCount++
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
			marker := severityMarker(f.Severity)
			line := fmt.Sprintf("              %s %s", marker, f.Title)
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
	p("  %d of %d layers ran.", ranCount, len(r.Layers))
	p("")

	// Verdict
	p("Verdict: %s", r.Verdict)
	switch r.Verdict {
	case VerdictClean:
		p("  No known-malicious indicators found.")
		p("  (This tool detects known malware and suspicious patterns; it is not a")
		p("   defense against a novel, targeted supply-chain attack.)")
	case VerdictHesitant:
		p("  No known-malicious indicators found, but an aggressive heuristic flagged")
		p("  something worth a closer look (see ⚑ above).")
		p("  The bytes were NOT deleted and have been handed to the cache — but you may")
		p("  want to inspect the flagged item yourself before running `brew install`.")
	case VerdictSuspicious:
		p("  Suspicious patterns or an unverifiable hash were found — review above.")
	case VerdictMalicious:
		p("  Known-malicious indicators found (see the Action line for what was done).")
	case VerdictError:
		if r.Error != "" {
			p("  %s", r.Error)
		}
	}
	p("")
	p("Action: %s", actionLine(r))
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

// credibilityBar renders a fixed-width [████░░░░░░] gauge for a 0..max score.
func credibilityBar(score, max int) string {
	if max <= 0 {
		return ""
	}
	if score < 0 {
		score = 0
	}
	if score > max {
		score = max
	}
	return "[" + strings.Repeat("█", score) + strings.Repeat("░", max-score) + "]"
}

func severityMarker(s Severity) string {
	switch s {
	case SeverityMalicious:
		return "‼ MALICIOUS:"
	case SeveritySuspicious:
		return "⚠ suspicious:"
	case SeverityHesitant:
		return "⚑ HESITANT:"
	default:
		return "•"
	}
}

func actionLine(r *Report) string {
	switch r.Action {
	case "cached":
		return fmt.Sprintf("verified bytes placed in Homebrew cache (%s)", r.CachePath)
	case "deleted":
		return "quarantined bytes deleted"
	case "kept":
		return "quarantined bytes kept (not cached)"
	case "already-cached":
		return fmt.Sprintf("left in place — already in Homebrew cache (%s)", r.CachePath)
	case "kept-in-cache":
		return fmt.Sprintf("left in Homebrew cache despite suspicion — review before installing (%s)", r.CachePath)
	case "deleted-from-cache":
		return "removed from Homebrew cache (malicious)"
	case "cache-delete-failed":
		return fmt.Sprintf("FAILED to remove from Homebrew cache — delete it manually: %s", r.CachePath)
	default:
		return r.Action
	}
}
