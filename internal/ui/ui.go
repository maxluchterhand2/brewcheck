// Package ui renders brewcheck's interactive (bubbletea) progress + result view.
// It is used only when stdout is an interactive terminal; non-TTY / --no-progress
// / --json runs print plain text instead (see cmd).
//
// The pipeline runs in a background goroutine and feeds this model messages via
// Program.Send; the model renders live progress and, on DoneMsg, the final
// styled result, then quits (leaving the result in the scrollback — no alt
// screen).
package ui

import (
	"context"
	"fmt"

	"brewcheck/internal/report"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Phase is the current pipeline stage shown in the progress view.
type Phase int

const (
	PhaseResolving Phase = iota
	PhaseDownloading
	PhaseScanning
	PhaseUploading
	PhaseDone
)

// Messages the pipeline sends to the model.
type (
	// ResolvedMsg reports the resolved target metadata.
	ResolvedMsg struct{ Name, Kind, Version, Source string }
	// PhaseMsg advances the visible stage.
	PhaseMsg struct{ Phase Phase }
	// CacheHitMsg means the artifact was found in brew's cache (no download).
	CacheHitMsg struct{}
	// DownloadMsg reports download progress (Total <= 0 means unknown).
	DownloadMsg struct{ Done, Total int64 }
	// UploadMsg reports VirusTotal upload progress.
	UploadMsg struct{ Done, Total int64 }
	// DoneMsg delivers the final report and ends the run.
	DoneMsg struct{ Report *report.Report }
)

// Model is the bubbletea model.
type Model struct {
	spinner spinner.Model
	bar     progress.Model
	width   int
	cancel  context.CancelFunc

	phase     Phase
	name      string
	kind      string
	version   string
	source    string
	fromCache bool

	dlDone, dlTotal int64
	upActive        bool
	upDone, upTotal int64

	report   *report.Report
	canceled bool
}

// New builds the model. cancel is invoked if the user aborts (ctrl+c/q).
func New(cancel context.CancelFunc) Model {
	sp := spinner.New(spinner.WithSpinner(spinner.Dot))
	sp.Style = spinnerStyle
	return Model{
		spinner: sp,
		bar:     progress.New(progress.WithDefaultGradient(), progress.WithoutPercentage()),
		cancel:  cancel,
		phase:   PhaseResolving,
	}
}

func (m Model) Init() tea.Cmd { return m.spinner.Tick }

// Aborted reports whether the user interrupted the run before it finished.
func (m Model) Aborted() bool { return m.canceled && m.report == nil }

// ExitCode is the process exit code implied by the final state.
func (m Model) ExitCode() int {
	if m.report == nil {
		return 130 // interrupted before completion
	}
	return m.report.Verdict.ExitCode()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.bar.Width = clamp(msg.Width-28, 12, 40)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			m.canceled = true
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case ResolvedMsg:
		m.name, m.kind, m.version, m.source = msg.Name, msg.Kind, msg.Version, msg.Source
		return m, nil
	case PhaseMsg:
		m.phase = msg.Phase
		return m, nil
	case CacheHitMsg:
		m.fromCache = true
		return m, nil
	case DownloadMsg:
		m.phase = PhaseDownloading
		m.dlDone, m.dlTotal = msg.Done, msg.Total
		return m, nil
	case UploadMsg:
		m.phase = PhaseUploading
		m.upActive = true
		m.upDone, m.upTotal = msg.Done, msg.Total
		return m, nil
	case DoneMsg:
		m.report = msg.Report
		m.phase = PhaseDone
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) View() string {
	switch {
	case m.report != nil:
		// Done. Render nothing: bubbletea's in-place frame would be clipped to
		// the terminal height (losing the top of a long report and any
		// scrollback). The caller prints Result() as normal stdout output after
		// the program exits, so the full report lands in the scrollback intact.
		return ""
	case m.canceled:
		return "\n  " + dimStyle.Render("aborted.") + "\n"
	default:
		return m.progressView()
	}
}

// Result returns the final styled report, or "" until the run completes. The
// caller prints it after the bubbletea program exits so the whole report (even
// if taller than the screen) is preserved in the terminal scrollback.
func (m Model) Result() string {
	if m.report == nil {
		return ""
	}
	return m.resultView()
}

// progressView renders the live step checklist.
func (m Model) progressView() string {
	title := titleStyle.Render("🍺 brewcheck")
	if m.name != "" {
		title += dimStyle.Render(fmt.Sprintf("  checking %s (%s)", m.name, m.kind))
	}

	var b []string
	b = append(b, "", title, "")

	// Resolve
	b = append(b, m.step(PhaseResolving, "resolve", m.resolveDetail()))

	// Download / cache
	switch {
	case m.fromCache:
		b = append(b, doneGlyph+" "+stepLabel("fetch")+dimStyle.Render("found in brew cache — scanning in place"))
	default:
		b = append(b, m.step(PhaseDownloading, "download", m.downloadDetail()))
	}

	// Scan
	b = append(b, m.step(PhaseScanning, "scan", ""))

	// Upload (only if the opt-in upload actually started)
	if m.upActive || m.phase == PhaseUploading {
		b = append(b, m.step(PhaseUploading, "vt upload", m.uploadDetail()))
	}

	b = append(b, "", dimStyle.Render("  press q to abort"), "")
	return joinLines(b)
}

func (m Model) resolveDetail() string {
	if m.version != "" {
		return dimStyle.Render(fmt.Sprintf("%s %s", m.name, m.version))
	}
	return ""
}

func (m Model) downloadDetail() string {
	if m.phase < PhaseDownloading {
		return ""
	}
	if m.dlTotal > 0 {
		pct := float64(m.dlDone) / float64(m.dlTotal)
		return fmt.Sprintf("%s %s", m.bar.ViewAs(pct),
			dimStyle.Render(fmt.Sprintf("%s / %s", humanBytes(m.dlDone), humanBytes(m.dlTotal))))
	}
	return dimStyle.Render(humanBytes(m.dlDone))
}

func (m Model) uploadDetail() string {
	if m.upTotal > 0 {
		return fmt.Sprintf("%s %s", m.bar.ViewAs(float64(m.upDone)/float64(m.upTotal)),
			dimStyle.Render(fmt.Sprintf("%s / %s", humanBytes(m.upDone), humanBytes(m.upTotal))))
	}
	return dimStyle.Render("sending…")
}

// step renders one checklist line with a status glyph derived from the phase.
func (m Model) step(at Phase, label, detail string) string {
	var glyph string
	switch {
	case m.phase > at:
		glyph = doneGlyph
	case m.phase == at:
		glyph = m.spinner.View()
	default:
		glyph = pendingStyle.Render("○")
	}
	line := glyph + " " + stepLabel(label)
	if detail != "" {
		line += detail
	}
	return line
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), []string{"KiB", "MiB", "GiB", "TiB"}[exp])
}

func joinLines(lines []string) string {
	return lipgloss.JoinVertical(lipgloss.Left, lines...) + "\n"
}
