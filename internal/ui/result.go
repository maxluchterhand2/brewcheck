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

// verdictMessage is the one-line verdict summary. It reuses the shared
// report vocabulary so the plain and TUI renderers can't drift, except an
// ERROR shows the concrete error text.
func verdictMessage(r *report.Report) string {
	if r.Verdict == report.VerdictError && r.Error != "" {
		return r.Error
	}
	return r.Verdict.Headline()
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
		kind := string(r.Kind)
		if r.BuildFromSource {
			kind += ", source build"
		}
		meta := r.Name + dimStyle.Render(" ("+kind+")")
		if r.Version != "" {
			meta += " " + r.Version
		}
		header += dimStyle.Render(" — ") + meta
	}
	nl("")
	nl(header)
	nl("")

	// Verdict headline + shared caveat lines.
	nl("  " + verdictBadge(r.Verdict) + "  " + lipgloss.NewStyle().Foreground(verdictColor(r.Verdict)).Render(verdictMessage(r)))
	for _, d := range r.Verdict.Detail() {
		nl("  " + dimStyle.Render(d))
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
	for _, l := range r.Layers {
		nl("  " + layerLine(l, width))
		if l.Credibility != nil {
			nl("       " + credibilityLine(l.Credibility, width))
		}
		for _, f := range l.Findings {
			c := lipgloss.NewStyle().Foreground(sevColor(f.Severity))
			nl("       " + c.Render(f.Severity.Glyph()+" "+f.Title))
		}
	}
	count := fmt.Sprintf("%d of %d layers ran", report.CountRan(r.Layers), len(r.Layers))
	if r.Degraded > 0 {
		count += fmt.Sprintf("  (degraded — %d errored)", r.Degraded)
	}
	nl("  " + dimStyle.Render(count))
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
	filled, empty := report.CredibilityFill(c.Score, c.Max)
	bar := lipgloss.NewStyle().Foreground(col).Render(strings.Repeat("█", filled)) +
		dimStyle.Render(strings.Repeat("░", empty))
	line := fmt.Sprintf("credibility [%s] %d/%d", bar, c.Score, c.Max)
	if len(c.Signals) > 0 {
		line += dimStyle.Render("  " + strings.Join(c.Signals, " · "))
	}
	return trunc(line, width-7)
}

// actionText colors the (shared) action description by its typed Action. The
// wording itself lives once in report.Action.Describe.
func actionText(r *report.Report) string {
	text := r.Action.Describe(r.CachePath)
	var style lipgloss.Style
	switch r.Action {
	case report.ActionCached, report.ActionAlreadyCached:
		style = okStyle
	case report.ActionKeptInCache:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	case report.ActionDeletedFromCache, report.ActionCacheDeleteFailed:
		style = errStyle
	default:
		style = dimStyle
	}
	return style.Render(text)
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
