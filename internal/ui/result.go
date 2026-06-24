package ui

import (
	"fmt"
	"strings"

	"brewcheck/internal/report"

	"github.com/charmbracelet/lipgloss"
)

// Shared styles.
var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	spinnerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	pendingStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	labelStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Width(10)
	keyStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Width(8)
	okStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	errStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	headingStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))

	doneGlyph = okStyle.Render("✓")
)

func stepLabel(s string) string { return labelStyle.Render(s) }

// sevColor maps a finding severity to a foreground color.
func sevColor(s report.Severity) lipgloss.Color {
	switch s {
	case report.SeverityMalicious:
		return lipgloss.Color("196")
	case report.SeveritySuspicious:
		return lipgloss.Color("208")
	case report.SeverityHesitant:
		return lipgloss.Color("220")
	default:
		return lipgloss.Color("245")
	}
}

func sevMarker(s report.Severity) string {
	switch s {
	case report.SeverityMalicious:
		return "‼"
	case report.SeveritySuspicious:
		return "⚠"
	case report.SeverityHesitant:
		return "⚑"
	default:
		return "•"
	}
}

// verdictColor / verdictBadge style the headline verdict.
func verdictColor(v report.Verdict) lipgloss.Color {
	switch v {
	case report.VerdictClean:
		return lipgloss.Color("42")
	case report.VerdictHesitant:
		return lipgloss.Color("220")
	case report.VerdictSuspicious:
		return lipgloss.Color("208")
	case report.VerdictMalicious:
		return lipgloss.Color("196")
	default:
		return lipgloss.Color("160")
	}
}

func verdictBadge(v report.Verdict) string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("16")).
		Background(verdictColor(v)).
		Padding(0, 1).
		Render(string(v))
}

func verdictMessage(r *report.Report) string {
	switch r.Verdict {
	case report.VerdictClean:
		return "No known-malicious indicators found."
	case report.VerdictHesitant:
		return "Cached, but an aggressive heuristic flagged something — review the ⚑ items."
	case report.VerdictSuspicious:
		return "Suspicious patterns or an unverifiable hash were found — review above."
	case report.VerdictMalicious:
		return "Known-malicious indicators found."
	default:
		if r.Error != "" {
			return r.Error
		}
		return "Could not complete the check."
	}
}

// resultView renders the final styled report.
func (m Model) resultView() string {
	r := m.report
	width := m.width
	if width <= 0 {
		width = 80
	}

	var b strings.Builder
	nl := func(s string) { b.WriteString(s); b.WriteByte('\n') }

	// Header.
	header := titleStyle.Render("🍺 brewcheck")
	if r.Name != "" {
		meta := r.Name + dimStyle.Render(" ("+r.Kind+")")
		if r.Version != "" {
			meta += " " + r.Version
		}
		header += dimStyle.Render(" — ") + meta
	}
	nl("")
	nl(header)
	nl("")

	// Verdict headline.
	nl("  " + verdictBadge(r.Verdict) + "  " + lipgloss.NewStyle().Foreground(verdictColor(r.Verdict)).Render(verdictMessage(r)))
	if r.Verdict == report.VerdictClean {
		nl("  " + dimStyle.Render("(detects known malware & suspicious patterns; not a defense against a novel,"))
		nl("  " + dimStyle.Render(" targeted supply-chain attack — the install scripts above are the real signal)"))
	}
	nl("")

	// Metadata.
	if r.SourceURL != "" {
		nl("  " + keyStyle.Render("source") + trunc(r.SourceURL, width-12))
	}
	if r.SHA256 != "" {
		badge := errStyle.Render("NOT verified")
		if r.HashVerified {
			badge = okStyle.Render("✓ verified against Homebrew")
		}
		nl("  " + keyStyle.Render("sha256") + dimStyle.Render(short(r.SHA256)) + "  " + badge)
	}
	if r.FromCache {
		nl("  " + keyStyle.Render("cache") + okStyle.Render("scanned the existing cached file in place (not re-downloaded)"))
	}
	nl("")

	// Layers.
	nl("  " + headingStyle.Render("Inspection layers"))
	ran := 0
	for _, l := range r.Layers {
		if l.Status == report.StatusRan {
			ran++
		}
		nl("  " + layerLine(l, width))
		if l.Credibility != nil {
			nl("       " + credibilityLine(l.Credibility, width))
		}
		for _, f := range l.Findings {
			c := lipgloss.NewStyle().Foreground(sevColor(f.Severity))
			nl("       " + c.Render(sevMarker(f.Severity)+" "+f.Title))
		}
	}
	nl("  " + dimStyle.Render(fmt.Sprintf("%d of %d layers ran", ran, len(r.Layers))))
	nl("")

	// Action.
	nl("  " + keyStyle.Render("action") + actionText(r))
	nl("")
	return b.String()
}

func layerLine(l report.LayerResult, width int) string {
	var tag string
	switch l.Status {
	case report.StatusRan:
		switch worstSeverity(l) {
		case report.SeverityMalicious, report.SeveritySuspicious, report.SeverityHesitant:
			tag = lipgloss.NewStyle().Foreground(sevColor(worstSeverity(l))).Render("● ran ")
		default:
			tag = okStyle.Render("✓ ran ")
		}
	case report.StatusSkipped:
		tag = dimStyle.Render("○ skip")
	case report.StatusError:
		tag = errStyle.Render("✗ err ")
	}
	line := tag + "  " + l.Name
	detail := l.Summary
	if detail == "" && l.Status == report.StatusSkipped {
		detail = l.Hint
	}
	if detail == "" && l.Status == report.StatusError {
		detail = l.Err
	}
	if detail != "" {
		line += dimStyle.Render(" — " + detail)
	}
	return trunc(line, width-2)
}

func credibilityLine(c *report.Credibility, width int) string {
	col := lipgloss.Color("42")
	switch {
	case c.Score < 4:
		col = lipgloss.Color("203")
	case c.Score < 7:
		col = lipgloss.Color("220")
	}
	filled := c.Score
	if filled > c.Max {
		filled = c.Max
	}
	bar := lipgloss.NewStyle().Foreground(col).Render(strings.Repeat("█", filled)) +
		dimStyle.Render(strings.Repeat("░", c.Max-filled))
	line := fmt.Sprintf("credibility [%s] %d/%d", bar, c.Score, c.Max)
	if len(c.Signals) > 0 {
		line += dimStyle.Render("  " + strings.Join(c.Signals, " · "))
	}
	return trunc(line, width-7)
}

func actionText(r *report.Report) string {
	switch r.Action {
	case "cached":
		return okStyle.Render("verified bytes placed in Homebrew cache")
	case "already-cached":
		return okStyle.Render("left in place — already in Homebrew cache")
	case "deleted":
		return dimStyle.Render("quarantined bytes deleted")
	case "kept":
		return dimStyle.Render("quarantined bytes kept (not cached)")
	case "kept-in-cache":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("left in Homebrew cache despite suspicion — review before installing")
	case "deleted-from-cache":
		return errStyle.Render("removed from Homebrew cache (malicious)")
	case "cache-delete-failed":
		return errStyle.Render("FAILED to remove from Homebrew cache — delete it manually: " + r.CachePath)
	default:
		return dimStyle.Render(r.Action)
	}
}

func worstSeverity(l report.LayerResult) report.Severity {
	rank := map[report.Severity]int{
		report.SeverityInfo:       1,
		report.SeverityHesitant:   2,
		report.SeveritySuspicious: 3,
		report.SeverityMalicious:  4,
	}
	var worst report.Severity
	for _, f := range l.Findings {
		if rank[f.Severity] > rank[worst] {
			worst = f.Severity
		}
	}
	return worst
}

func short(sha string) string {
	if len(sha) > 16 {
		return sha[:16] + "…"
	}
	return sha
}

// trunc clamps a (possibly styled) string's visible width. It uses lipgloss's
// MaxWidth so ANSI styling isn't miscounted or cut mid-escape.
func trunc(s string, max int) string {
	if max < 8 {
		max = 8
	}
	if lipgloss.Width(s) <= max {
		return s
	}
	return lipgloss.NewStyle().MaxWidth(max).Render(s)
}
