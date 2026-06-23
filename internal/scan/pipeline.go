// Package scan orchestrates the layered inspection pipeline (spec §6): hash
// reputation first (zero upload, can short-circuit to MALICIOUS), then the
// independent local layers in parallel, then opt-in cloud upload as a last
// resort. All layers run over the *verified* quarantined artifact only.
package scan

import (
	"context"
	"sync"
	"time"

	"brewcheck/internal/report"
	"brewcheck/internal/scan/capa"
	"brewcheck/internal/scan/clamav"
	"brewcheck/internal/scan/github"
	"brewcheck/internal/scan/semgrep"
	"brewcheck/internal/scan/static"
	"brewcheck/internal/scan/vt"
	"brewcheck/internal/scan/yara"
)

// Input carries everything the pipeline needs about a verified artifact.
type Input struct {
	Name           string
	Kind           string // "formula" | "cask"
	ArtifactPath   string
	SHA256         string
	DefinitionJSON []byte
	ScriptPaths    []string // extracted install scripts
	ScanTargets    []string // artifact + extracted dirs for clamav/yara
	BinaryForCapa  string   // a single binary path, or ""

	SemgrepRules string
	YaraRules    string

	VTKey         string
	AllowCloud    bool
	MaxUploadSize int64
	ArtifactSize  int64

	GitHubRepo    string // "owner/repo" derived from the definition, or ""
	GitHubToken   string // optional, for higher API rate limits
	AllowNewRepos bool   // when true, a sub-month-old repo is not flagged SUSPICIOUS

	Logf func(format string, a ...any)
}

func (in *Input) log(format string, a ...any) {
	if in.Logf != nil {
		in.Logf(format, a...)
	}
}

// Run executes the pipeline and returns every layer's result.
func Run(ctx context.Context, in Input) []report.LayerResult {
	var layers []report.LayerResult

	// Layer 1: VirusTotal hash reputation (zero upload, may short-circuit).
	in.log("layer: VirusTotal hash reputation")
	vtClient := vt.New(in.VTKey)
	vtRes, definitelyBad, vtKnown := vtClient.LookupHash(ctx, in.SHA256)
	layers = append(layers, vtRes)

	if definitelyBad {
		in.log("definitive malicious hit — short-circuiting local layers")
		layers = append(layers,
			skipped("static analysis (definition + scripts)", "short-circuited after definitive malicious hit"),
			skipped("Semgrep (static rules)", "short-circuited after definitive malicious hit"),
			skipped("ClamAV", "short-circuited after definitive malicious hit"),
			skipped("YARA", "short-circuited after definitive malicious hit"),
			skipped("GitHub author credibility", "short-circuited after definitive malicious hit"),
		)
		return layers
	}

	// Layers 2 & 3: independent local layers, run in parallel.
	in.log("running local layers in parallel (static, semgrep, clamav, yara, capa)")
	local := runLocalParallel(ctx, in)
	layers = append(layers, local...)

	// Layer 4: opt-in cloud upload, last resort.
	layers = append(layers, maybeCloud(ctx, in, vtKnown))
	return layers
}

func runLocalParallel(ctx context.Context, in Input) []report.LayerResult {
	type job struct {
		idx int
		run func() report.LayerResult
	}
	jobs := []job{
		{0, func() report.LayerResult {
			return static.Analyze(in.Kind, in.Name, in.DefinitionJSON, in.ScriptPaths)
		}},
		{1, func() report.LayerResult {
			return semgrep.Scan(ctx, in.SemgrepRules, append([]string{}, in.ScriptPaths...))
		}},
		{2, func() report.LayerResult { return clamav.Scan(ctx, in.ArtifactPath) }},
		{3, func() report.LayerResult { return yara.Scan(ctx, in.YaraRules, in.ScanTargets) }},
		{4, func() report.LayerResult {
			if in.BinaryForCapa == "" {
				return skipped("capa (capabilities, informational)", "no single binary identified to analyze")
			}
			return capa.Analyze(ctx, in.BinaryForCapa)
		}},
		{5, func() report.LayerResult {
			return github.Analyze(ctx, github.Options{
				Repo:          in.GitHubRepo,
				Token:         in.GitHubToken,
				AllowNewRepos: in.AllowNewRepos,
				Now:           time.Now(),
			})
		}},
	}

	results := make([]report.LayerResult, len(jobs))
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			results[j.idx] = j.run()
		}(j)
	}
	wg.Wait()
	return results
}

func maybeCloud(ctx context.Context, in Input, vtKnown bool) report.LayerResult {
	name := "VirusTotal upload (opt-in)"
	if !in.AllowCloud {
		return skipped(name, "not enabled (pass --cloud to allow uploading the file)")
	}
	// No point uploading a file VirusTotal already has — it would reject the
	// re-upload with 409 Conflict (AlreadyExistsError). The hash-reputation
	// layer above already carries VT's verdict for this artifact.
	if vtKnown {
		return skipped(name, "VirusTotal already has this file (see the hash reputation layer); skipping the redundant upload")
	}
	if in.MaxUploadSize > 0 && in.ArtifactSize > in.MaxUploadSize {
		return skipped(name, "file exceeds --max-upload-size; never uploaded")
	}
	in.log("uploading artifact to VirusTotal (opt-in) — this publishes the file")
	res, _ := vt.New(in.VTKey).Upload(ctx, in.ArtifactPath)
	return res
}

func skipped(name, reason string) report.LayerResult {
	return report.LayerResult{Name: name, Status: report.StatusSkipped, Hint: reason}
}
