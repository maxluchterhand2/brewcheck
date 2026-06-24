// Package report defines the core verdict/finding types and renders both the
// human-readable and machine-readable (--json) reports.
//
// This package has no dependencies on other internal packages so that every
// scanner can import it without creating an import cycle. It is also the single
// home for the report→text vocabulary (verdict messages, severity glyphs,
// action descriptions) that both the plain and TUI renderers consume.
package report

import "fmt"

// SchemaVersion is bumped whenever the --json output shape changes.
// 0.2.0 added the HESITANT verdict and per-layer Credibility.
// 0.3.0 added from_cache (artifact scanned in place from brew's cache).
// 0.4.0 added build_from_source (scanned the upstream source tarball).
// 0.5.0 added degraded (count of layers that errored).
const SchemaVersion = "0.5.0"

// Kind is the artifact type. Typed so "formula"/"cask" can't be mistyped.
type Kind string

// TODO: consider whether this is the right place for these
const (
	KindFormula Kind = "formula"
	KindCask    Kind = "cask"
)

// Verdict is the aggregated outcome of a run.
type Verdict string

const (
	VerdictClean      Verdict = "CLEAN"
	VerdictHesitant   Verdict = "HESITANT"
	VerdictSuspicious Verdict = "SUSPICIOUS"
	VerdictMalicious  Verdict = "MALICIOUS"
	VerdictError      Verdict = "ERROR"
)

// ExitCode maps a verdict to the process exit code (see spec §7).
//
// HESITANT uses a dedicated code 4 rather than reordering the spec's 0–3.
// Semantically it is "cached, but look closer": the bytes were kept and handed
// to the cache like CLEAN, but an aggressive heuristic fired, so the non-zero
// code lets scripts/CI notice without treating it as a hard SUSPICIOUS block.
func (v Verdict) ExitCode() int {
	switch v {
	case VerdictClean:
		return 0
	case VerdictSuspicious:
		return 1
	case VerdictMalicious:
		return 2
	case VerdictHesitant:
		return 4
	default:
		return 3
	}
}

// Headline is the one-line summary for a verdict, shared by both renderers.
func (v Verdict) Headline() string {
	switch v {
	case VerdictClean:
		return "No known-malicious indicators found."
	case VerdictHesitant:
		return "No known-malicious indicators found, but an aggressive heuristic flagged something worth a closer look (see ⚑)."
	case VerdictSuspicious:
		return "Suspicious patterns or an unverifiable hash were found — review above."
	case VerdictMalicious:
		return "Known-malicious indicators found (see the Action line for what was done)."
	default:
		return "Could not complete the check."
	}
}

// Detail returns any follow-up lines for a verdict (e.g. the CLEAN/HESITANT
// caveat). Shared so the plain and TUI renderers can't drift.
func (v Verdict) Detail() []string {
	switch v {
	case VerdictClean:
		return []string{
			"This tool detects known malware and suspicious patterns; it is not a",
			"defense against a novel, targeted supply-chain attack.",
		}
	case VerdictHesitant:
		return []string{
			"The bytes were NOT deleted and have been handed to the cache — but you may",
			"want to inspect the flagged item yourself before running `brew install`.",
		}
	default:
		return nil
	}
}

// Severity describes how alarming a single finding is. It drives aggregation.
type Severity string

const (
	SeverityInfo       Severity = "info"
	SeverityHesitant   Severity = "hesitant"
	SeveritySuspicious Severity = "suspicious"
	SeverityMalicious  Severity = "malicious"
)

// Glyph is the leading marker for a severity, shared by both renderers.
func (s Severity) Glyph() string {
	switch s {
	case SeverityMalicious:
		return "‼"
	case SeveritySuspicious:
		return "⚠"
	case SeverityHesitant:
		return "⚑"
	default:
		return "•"
	}
}

// Label is the word shown after the glyph in the plain renderer ("" for info).
func (s Severity) Label() string {
	switch s {
	case SeverityMalicious:
		return "MALICIOUS"
	case SeveritySuspicious:
		return "suspicious"
	case SeverityHesitant:
		return "HESITANT"
	default:
		return ""
	}
}

// Action is what brewcheck did with the artifact after the verdict. Typed (with
// named constants) so the writers in cmd and the matchers in the two renderers
// can't drift on free-text strings.
type Action string

const (
	ActionNone              Action = ""
	ActionCached            Action = "cached"
	ActionDeleted           Action = "deleted"
	ActionKept              Action = "kept"
	ActionAlreadyCached     Action = "already-cached"
	ActionKeptInCache       Action = "kept-in-cache"
	ActionDeletedFromCache  Action = "deleted-from-cache"
	ActionCacheDeleteFailed Action = "cache-delete-failed"
)

// Describe is the human sentence for an action. The single source of truth for
// the wording; the TUI adds color on top of it.
func (a Action) Describe(cachePath string) string {
	switch a {
	case ActionCached:
		return fmt.Sprintf("verified bytes placed in Homebrew cache (%s)", cachePath)
	case ActionDeleted:
		return "quarantined bytes deleted"
	case ActionKept:
		return "quarantined bytes kept (not cached)"
	case ActionAlreadyCached:
		return fmt.Sprintf("left in place — already in Homebrew cache (%s)", cachePath)
	case ActionKeptInCache:
		return fmt.Sprintf("left in Homebrew cache despite suspicion — review before installing (%s)", cachePath)
	case ActionDeletedFromCache:
		return "removed from Homebrew cache (malicious)"
	case ActionCacheDeleteFailed:
		return fmt.Sprintf("FAILED to remove from Homebrew cache — delete it manually: %s", cachePath)
	default:
		return string(a)
	}
}

// LayerStatus records whether a pipeline layer actually executed.
type LayerStatus string

const (
	StatusRan     LayerStatus = "ran"
	StatusSkipped LayerStatus = "skipped"
	StatusError   LayerStatus = "error"
)

// Finding is a single observation from a layer.
type Finding struct {
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Location string   `json:"location,omitempty"`
}

// LayerResult is the outcome of one inspection layer.
type LayerResult struct {
	Name        string       `json:"name"`
	Status      LayerStatus  `json:"status"`
	Summary     string       `json:"summary,omitempty"`
	Hint        string       `json:"hint,omitempty"` // install hint when skipped
	Findings    []Finding    `json:"findings,omitempty"`
	Err         string       `json:"error,omitempty"`
	Credibility *Credibility `json:"credibility,omitempty"`
}

// Credibility is the heuristic 0..Max rating produced by the GitHub author
// layer. It is purely informational signal attached to a layer; the layer's
// findings (if any) are what actually move the verdict.
type Credibility struct {
	Score   int      `json:"score"`             // 0..Max
	Max     int      `json:"max"`               // 10
	Repo    string   `json:"repo,omitempty"`    // e.g. "github.com/owner/repo"
	Signals []string `json:"signals,omitempty"` // human-readable breakdown
}

// AddFinding appends a finding to the layer.
func (l *LayerResult) AddFinding(sev Severity, title, detail, loc string) {
	l.Findings = append(l.Findings, Finding{Severity: sev, Title: title, Detail: detail, Location: loc})
}

// Report is the full structured result of a run.
type Report struct {
	SchemaVersion   string        `json:"schema_version"`
	Name            string        `json:"name"`
	Kind            Kind          `json:"kind"` // "formula" | "cask"
	Version         string        `json:"version"`
	SourceURL       string        `json:"source_url"`
	SHA256          string        `json:"sha256"`
	HashVerified    bool          `json:"hash_verified"`
	Layers          []LayerResult `json:"layers"`
	Verdict         Verdict       `json:"verdict"`
	Degraded        int           `json:"degraded"`          // # layers that errored
	BuildFromSource bool          `json:"build_from_source"` // scanned the upstream source tarball, not a bottle
	FromCache       bool          `json:"from_cache"`        // scanned in place from brew's cache (not downloaded)
	Cached          bool          `json:"cached"`
	CachePath       string        `json:"cache_path,omitempty"`
	Action          Action        `json:"action"`
	Error           string        `json:"error,omitempty"`
}

// CountRan / CountErrored summarize layer execution for the renderers.
func CountRan(layers []LayerResult) int     { return countStatus(layers, StatusRan) }
func CountErrored(layers []LayerResult) int { return countStatus(layers, StatusError) }

func countStatus(layers []LayerResult, want LayerStatus) int {
	n := 0
	for _, l := range layers {
		if l.Status == want {
			n++
		}
	}
	return n
}

// CredibilityFill returns the filled/empty cell counts for a 0..max gauge,
// clamped. Shared by both renderers so the bar math lives once.
func CredibilityFill(score, max int) (filled, empty int) {
	if max <= 0 {
		return 0, 0
	}
	if score < 0 {
		score = 0
	}
	if score > max {
		score = max
	}
	return score, max - score
}

// AggregateVerdict computes the overall verdict from the layers that ran.
//
// Precedence (worst wins): MALICIOUS > SUSPICIOUS > HESITANT > CLEAN.
//   - any malicious finding   -> MALICIOUS (definitive known-bad; delete, never cache)
//   - else any suspicious     -> SUSPICIOUS (don't cache by default; review)
//   - else any hesitant       -> HESITANT  (aggressive heuristic fired; cache, but warn)
//   - else                    -> CLEAN
//
// Layer errors do not change the severity, but the caller should record
// CountErrored so a mostly-failed run isn't presented as a confident CLEAN.
func AggregateVerdict(layers []LayerResult) Verdict {
	worst := VerdictClean
	for _, l := range layers {
		for _, f := range l.Findings {
			switch f.Severity {
			case SeverityMalicious:
				return VerdictMalicious
			case SeveritySuspicious:
				worst = VerdictSuspicious
			case SeverityHesitant:
				if worst == VerdictClean {
					worst = VerdictHesitant
				}
			}
		}
	}
	return worst
}
