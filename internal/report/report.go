// Package report defines the core verdict/finding types and renders both the
// human-readable and machine-readable (--json) reports.
//
// This package has no dependencies on other internal packages so that every
// scanner can import it without creating an import cycle.
package report

// SchemaVersion is bumped whenever the --json output shape changes.
// 0.2.0 added the HESITANT verdict and per-layer Credibility.
const SchemaVersion = "0.2.0"

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

// Severity describes how alarming a single finding is. It drives aggregation.
type Severity string

const (
	SeverityInfo       Severity = "info"
	SeverityHesitant   Severity = "hesitant"
	SeveritySuspicious Severity = "suspicious"
	SeverityMalicious  Severity = "malicious"
)

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
	SchemaVersion string        `json:"schema_version"`
	Name          string        `json:"name"`
	Kind          string        `json:"kind"` // "formula" | "cask"
	Version       string        `json:"version"`
	SourceURL     string        `json:"source_url"`
	SHA256        string        `json:"sha256"`
	HashVerified  bool          `json:"hash_verified"`
	Layers        []LayerResult `json:"layers"`
	Verdict       Verdict       `json:"verdict"`
	Cached        bool          `json:"cached"`
	CachePath     string        `json:"cache_path,omitempty"`
	Action        string        `json:"action"` // "cached" | "deleted" | "kept"
	Error         string        `json:"error,omitempty"`
}

// AggregateVerdict computes the overall verdict from the layers that ran.
//
// Precedence (worst wins): MALICIOUS > SUSPICIOUS > HESITANT > CLEAN.
//   - any malicious finding   -> MALICIOUS (definitive known-bad; delete, never cache)
//   - else any suspicious     -> SUSPICIOUS (don't cache by default; review)
//   - else any hesitant       -> HESITANT  (aggressive heuristic fired; cache, but warn)
//   - else                    -> CLEAN
//
// A hash-verification problem is folded in by the caller as a suspicious
// finding before this is called.
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
