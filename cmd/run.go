package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"brewcheck/internal/brewcache"
	"brewcheck/internal/download"
	"brewcheck/internal/extract"
	"brewcheck/internal/progress"
	"brewcheck/internal/report"
	"brewcheck/internal/scan"
	"brewcheck/internal/verify"
)

// resolved describes a single artifact to fetch, independent of kind.
type resolved struct {
	name          string
	kind          string // "formula" | "cask"
	version       string
	sourceURL     string
	publishedHash string
	defJSON       []byte
	githubRepo    string // upstream "owner/repo", or "" if not on GitHub
	fetcher       download.Fetcher
}

// run executes the whole pipeline and returns the process exit code.
func run(ctx context.Context, positional string) int {
	logf := func(format string, a ...any) {
		if opts.verbose {
			fmt.Fprintf(os.Stderr, "[brewcheck] "+format+"\n", a...)
		}
	}

	// Progress indicators render on stderr (stdout/--json stay clean) only when
	// interactive; --verbose's step logs would otherwise fight the spinner.
	showProgress := progress.StderrIsTTY() && !opts.verbose && !opts.noProgress

	r := &report.Report{}

	sp := progress.NewSpinner(showProgress, "resolving "+displayName(positional))
	res, err := resolveTarget(ctx, positional)
	sp.Stop()
	if err != nil {
		return emitError(r, err)
	}
	r.Name, r.Kind, r.Version, r.SourceURL = res.name, res.kind, res.version, res.sourceURL
	logf("resolved %s %s version %s", res.kind, res.name, res.version)

	// Quarantine: isolated, restrictive-perms dir brew knows nothing about.
	q, err := download.NewQuarantine(opts.quarantineDir, opts.keep)
	if err != nil {
		return emitError(r, err)
	}
	defer q.Cleanup()
	logf("quarantine: %s", q.Dir)

	// Download (streaming + sha256) into quarantine, with a percentage bar.
	logf("downloading %s", res.sourceURL)
	bar := progress.NewBar(showProgress, fmt.Sprintf("downloading %s %s", res.kind, res.name))
	var onProgress func(done, total int64)
	if bar != nil {
		onProgress = bar.Update
	}
	dl, err := q.Fetch(ctx, res.fetcher, maxDownloadSize, onProgress)
	bar.Finish()
	if err != nil {
		return emitError(r, fmt.Errorf("download failed: %w", err))
	}
	r.SHA256 = dl.SHA256
	logf("downloaded %d bytes, sha256=%s", dl.Size, dl.SHA256)

	// Verify BEFORE anything else touches the bytes.
	verifyLayer, abort := verifyHash(r, res.publishedHash, dl.SHA256)
	if abort {
		// Hash mismatch: do not scan, do not cache. Bytes deleted by Cleanup.
		r.Layers = []report.LayerResult{verifyLayer}
		r.Verdict = report.VerdictSuspicious
		r.Action = "deleted"
		emit(r)
		return r.Verdict.ExitCode()
	}

	// Extract + scan can take a while (local scanners + VT/GitHub network), with
	// no measurable total — show an indeterminate spinner for the whole phase.
	scanSpin := progress.NewSpinner(showProgress, "scanning "+res.name)
	defer scanSpin.Stop() // safety net; also stopped explicitly below before output

	// Extract for scanning (never mount/run). Best-effort.
	scriptPaths, scanTargets := prepareScanInputs(ctx, q, dl.Path, res.kind, logf)

	// Run the inspection pipeline over the verified artifact.
	rulesBase := rulesDir()
	in := scan.Input{
		Name:           res.name,
		Kind:           res.kind,
		ArtifactPath:   dl.Path,
		SHA256:         dl.SHA256,
		DefinitionJSON: res.defJSON,
		ScriptPaths:    scriptPaths,
		ScanTargets:    scanTargets,
		SemgrepRules:   filepath.Join(rulesBase, "semgrep"),
		YaraRules:      filepath.Join(rulesBase, "yara", "brewcheck.yar"),
		VTKey:          os.Getenv("VT_API_KEY"),
		AllowCloud:     opts.cloud,
		MaxUploadSize:  opts.maxUploadSize,
		ArtifactSize:   dl.Size,
		GitHubRepo:     res.githubRepo,
		GitHubToken:    githubToken(),
		AllowNewRepos:  opts.allowNewRepos,
		ShowProgress:   showProgress,
		OnUploadStart:  scanSpin.Stop, // clear the scan spinner before the upload bar
		Logf:           logf,
	}
	layers := scan.Run(ctx, in)
	scanSpin.Stop() // clear the indicator before any report output

	// Verification layer leads the report.
	r.Layers = append([]report.LayerResult{verifyLayer}, layers...)
	r.Verdict = report.AggregateVerdict(r.Layers)

	// Cache-or-delete decision.
	decideAction(ctx, r, dl.Path, logf)

	emit(r)
	return r.Verdict.ExitCode()
}

// displayName picks the best label for the pre-resolution spinner from whatever
// the user supplied (positional name or --formula/--cask flag).
func displayName(positional string) string {
	switch {
	case positional != "":
		return positional
	case opts.formula != "":
		return opts.formula
	case opts.cask != "":
		return opts.cask
	default:
		return "target"
	}
}

// verifyHash builds the verification layer and reports whether to abort.
func verifyHash(r *report.Report, published, got string) (report.LayerResult, bool) {
	l := report.LayerResult{Name: "sha256 verification", Status: report.StatusRan}
	if !verify.Verifiable(published) {
		// No publishable hash (e.g. cask "no_check"): cannot verify, never cache.
		r.HashVerified = false
		l.AddFinding(report.SeveritySuspicious,
			"no published sha256 to verify against (\"no_check\")",
			"brewcheck cannot guarantee these bytes match what brew will install", "")
		l.Summary = "unverifiable"
		return l, false
	}
	if verify.Match(got, published) {
		r.HashVerified = true
		l.Summary = "verified against Homebrew ✓"
		return l, false
	}
	// Mismatch: treat as suspicious and abort before scanning (TOCTOU/HASH_MISMATCH).
	r.HashVerified = false
	l.AddFinding(report.SeveritySuspicious,
		"HASH_MISMATCH: downloaded bytes do not match Homebrew's published sha256",
		fmt.Sprintf("expected %s, got %s", published, got), "")
	l.Summary = "HASH_MISMATCH"
	return l, true
}

// prepareScanInputs extracts the artifact (best-effort) and returns the script
// paths and scan targets for the pipeline.
func prepareScanInputs(ctx context.Context, q *download.Quarantine, artifact, kind string, logf func(string, ...any)) (scripts, targets []string) {
	targets = []string{artifact}
	scratch, err := q.Scratch("scratch")
	if err != nil {
		logf("could not create scratch dir: %v", err)
		return nil, targets
	}
	extractedRoot, err := extract.Artifact(ctx, artifact, scratch)
	if err != nil {
		if errors.Is(err, extract.ErrUnsupported) {
			logf("no extractor available for this artifact; scanning the file directly")
		} else {
			logf("extraction failed (continuing with file-level scan): %v", err)
		}
		return nil, targets
	}
	scripts = extract.FindScripts(extractedRoot)
	targets = append(targets, extractedRoot)
	logf("extracted to %s (%d candidate scripts)", extractedRoot, len(scripts))
	return scripts, targets
}

// decideAction caches the bytes on a clean verdict (when allowed) or leaves
// them to be deleted by quarantine cleanup.
func decideAction(ctx context.Context, r *report.Report, artifact string, logf func(string, ...any)) {
	cacheEnabled := opts.cache && !opts.noCache
	// HESITANT caches just like CLEAN (the bytes are not radioactive — an
	// aggressive heuristic merely wants the user to look closer). SUSPICIOUS and
	// MALICIOUS never reach here as cacheable.
	cacheable := r.Verdict == report.VerdictClean || r.Verdict == report.VerdictHesitant
	if cacheable && cacheEnabled && r.HashVerified {
		if !brewcache.Available() {
			logf("brew not on PATH — skipping cache hand-off")
			r.Action = actionFor(false)
			return
		}
		dest, err := brewcache.CachePath(ctx, r.Name, r.Kind)
		if err != nil {
			logf("could not determine cache path: %v", err)
			r.Action = actionFor(false)
			return
		}
		if err := brewcache.Place(artifact, dest); err != nil {
			logf("cache hand-off failed: %v", err)
			r.Action = actionFor(false)
			return
		}
		r.Cached = true
		r.CachePath = dest
		r.Action = "cached"
		logf("placed verified bytes in cache: %s", dest)
		return
	}
	r.Action = actionFor(false)
}

func actionFor(cached bool) string {
	if cached {
		return "cached"
	}
	if opts.keep {
		return "kept"
	}
	return "deleted"
}

// emit renders the report in the chosen format.
func emit(r *report.Report) {
	r.SchemaVersion = report.SchemaVersion
	if opts.jsonOut {
		_ = r.JSON(os.Stdout)
		return
	}
	r.Human(os.Stdout)
}

// emitError finalizes an ERROR report and returns the exit code.
func emitError(r *report.Report, err error) int {
	r.Verdict = report.VerdictError
	r.Error = err.Error()
	if r.Action == "" {
		r.Action = actionFor(false)
	}
	emit(r)
	return report.VerdictError.ExitCode()
}

// githubToken returns an optional GitHub API token for higher rate limits,
// honoring the conventional env var names.
func githubToken() string {
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GH_TOKEN")
}

// rulesDir resolves the bundled rules directory.
func rulesDir() string {
	if d := os.Getenv("BREWCHECK_RULES_DIR"); d != "" {
		return d
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "rules")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
	}
	return "rules"
}
