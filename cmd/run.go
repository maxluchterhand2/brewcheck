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
	"brewcheck/internal/ui"
	"brewcheck/internal/verify"

	tea "github.com/charmbracelet/bubbletea"
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
	fromSource    bool   // scanning the upstream source tarball, not a bottle
	fetcher       download.Fetcher
}

// run dispatches to the interactive (bubbletea) UI or to plain text output, then
// returns the process exit code. The actual orchestration lives in runPipeline;
// the two modes differ only in how progress and the result are rendered.
func run(ctx context.Context, positional string) int {
	if useTUI() {
		return runTUI(ctx, positional)
	}
	r := runPipeline(ctx, positional, func(tea.Msg) {})
	emit(r)
	return r.Verdict.ExitCode()
}

// useTUI reports whether to render the interactive bubbletea UI: only when
// stdout is a terminal and the user hasn't opted into plain/machine output.
func useTUI() bool {
	return progress.IsTTY(os.Stdout) && !opts.noProgress && !opts.jsonOut && !opts.verbose
}

// runTUI runs the pipeline in the background, feeding a bubbletea model, and
// leaves the styled result on screen when it finishes.
func runTUI(ctx context.Context, positional string) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p := tea.NewProgram(ui.New(cancel), tea.WithOutput(os.Stdout))
	go func() {
		r := runPipeline(ctx, positional, p.Send)
		p.Send(ui.DoneMsg{Report: r})
	}()
	final, err := p.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: could not start the interactive UI:", err)
		return report.VerdictError.ExitCode()
	}
	m := final.(ui.Model)
	// Print the full report as normal stdout output so it stays in the terminal
	// scrollback in its entirety, regardless of the terminal height.
	if res := m.Result(); res != "" {
		fmt.Print(res)
	}
	return m.ExitCode()
}

// runPipeline does the whole resolve → fetch → verify → scan → decide flow,
// emitting UI events through send (a no-op in plain mode). It never prints; the
// caller renders the returned report.
func runPipeline(ctx context.Context, positional string, send func(tea.Msg)) *report.Report {
	logf := func(format string, a ...any) {
		if opts.verbose {
			fmt.Fprintf(os.Stderr, "[brewcheck] "+format+"\n", a...)
		}
	}
	r := &report.Report{}

	send(ui.PhaseMsg{Phase: ui.PhaseResolving})
	res, err := resolveTarget(ctx, positional)
	if err != nil {
		return failed(r, err)
	}
	r.Name, r.Kind, r.Version, r.SourceURL = res.name, res.kind, res.version, res.sourceURL
	send(ui.ResolvedMsg{Name: res.name, Kind: res.kind, Version: res.version, Source: res.sourceURL})
	logf("resolved %s %s version %s", res.kind, res.name, res.version)

	// Quarantine: isolated, restrictive-perms dir brew knows nothing about.
	q, err := download.NewQuarantine(opts.quarantineDir, opts.keep)
	if err != nil {
		return failed(r, err)
	}
	defer q.Cleanup()
	logf("quarantine: %s", q.Dir)

	// If the artifact is already in brew's cache and its hash matches Homebrew's
	// published one, scan it in place instead of re-downloading.
	var (
		dl        *download.Result
		fromCache bool
		cachePath string
	)
	if cp, sum, size, hit := reuseFromCache(ctx, res, logf); hit {
		logf("reusing verified file already in brew cache: %s", cp)
		dl = &download.Result{Path: cp, SHA256: sum, Size: size}
		fromCache, cachePath = true, cp
		send(ui.CacheHitMsg{})
	} else {
		logf("downloading %s", res.sourceURL)
		send(ui.PhaseMsg{Phase: ui.PhaseDownloading})
		dl, err = q.Fetch(ctx, res.fetcher, maxDownloadSize, func(done, total int64) {
			send(ui.DownloadMsg{Done: done, Total: total})
		})
		if err != nil {
			return failed(r, fmt.Errorf("download failed: %w", err))
		}
	}
	r.FromCache = fromCache
	r.BuildFromSource = res.fromSource
	r.SHA256 = dl.SHA256
	logf("artifact %d bytes, sha256=%s (from cache: %v, source build: %v)", dl.Size, dl.SHA256, fromCache, res.fromSource)

	// Verify BEFORE anything else touches the bytes.
	verifyLayer, abort := verifyHash(r, res.publishedHash, dl.SHA256)
	if abort {
		// Hash mismatch: do not scan, do not cache. Bytes deleted by Cleanup.
		r.Layers = []report.LayerResult{verifyLayer}
		r.Verdict = report.VerdictSuspicious
		r.Action = "deleted"
		return r
	}

	// Extract for scanning (never mount/run). Best-effort.
	send(ui.PhaseMsg{Phase: ui.PhaseScanning})
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
		OnUploadStart:  func() { send(ui.PhaseMsg{Phase: ui.PhaseUploading}) },
		OnUploadProgress: func(done, total int64) {
			send(ui.UploadMsg{Done: done, Total: total})
		},
		Logf: logf,
	}
	layers := scan.Run(ctx, in)

	// Verification layer leads the report.
	r.Layers = append([]report.LayerResult{verifyLayer}, layers...)
	r.Verdict = report.AggregateVerdict(r.Layers)

	// Cache-or-delete decision.
	decideAction(ctx, r, dl.Path, fromCache, res.fromSource, cachePath, logf)
	return r
}

// failed finalizes an ERROR report without printing anything.
func failed(r *report.Report, err error) *report.Report {
	r.Verdict = report.VerdictError
	r.Error = err.Error()
	if r.Action == "" {
		r.Action = actionFor(false)
	}
	return r
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

// reuseFromCache returns the path/sha256/size of an existing brew-cache file for
// this target, but only when it is present AND its sha256 matches Homebrew's
// published hash. That match is the whole safety story: it guarantees the cached
// bytes are exactly what we'd have downloaded. Without a verifiable published
// hash (e.g. a cask "no_check"), we never reuse — we can't prove the match.
func reuseFromCache(ctx context.Context, res *resolved, logf func(string, ...any)) (path, sum string, size int64, ok bool) {
	if !verify.Verifiable(res.publishedHash) {
		return "", "", 0, false
	}
	if !brewcache.Available() {
		return "", "", 0, false
	}
	cp, err := brewcache.CachePath(ctx, res.name, res.kind, res.fromSource)
	if err != nil {
		logf("could not determine cache path: %v", err)
		return "", "", 0, false
	}
	fi, err := os.Stat(cp)
	if err != nil || fi.IsDir() {
		return "", "", 0, false // not in the cache yet
	}
	got, err := verify.SHA256File(cp)
	if err != nil {
		logf("could not hash cached file %s: %v", cp, err)
		return "", "", 0, false
	}
	if !verify.Match(got, res.publishedHash) {
		logf("cached file present but sha256 does not match published hash; re-downloading")
		return "", "", 0, false
	}
	return cp, got, fi.Size(), true
}

// decideAction decides what to do with the artifact after the verdict. The
// behavior differs depending on whether we scanned a fresh download (quarantine)
// or a file already living in brew's cache.
func decideAction(ctx context.Context, r *report.Report, artifact string, fromCache, fromSource bool, cachePath string, logf func(string, ...any)) {
	if fromCache {
		decideCachedAction(r, cachePath, logf)
		return
	}
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
		dest, err := brewcache.CachePath(ctx, r.Name, r.Kind, fromSource)
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

// decideCachedAction handles a file scanned in place from brew's cache. Such a
// file is the user's existing download, so we never re-place it and never delete
// it for merely-suspicious findings — only a MALICIOUS verdict evicts it from
// the cache (a safety action, independent of --no-cache).
func decideCachedAction(r *report.Report, cachePath string, logf func(string, ...any)) {
	switch r.Verdict {
	case report.VerdictMalicious:
		if err := os.Remove(cachePath); err != nil {
			logf("failed to remove malicious file from cache: %v", err)
			r.CachePath = cachePath
			r.Action = "cache-delete-failed"
			return
		}
		logf("removed malicious file from brew cache: %s", cachePath)
		r.Action = "deleted-from-cache"
	case report.VerdictSuspicious:
		r.Cached = true
		r.CachePath = cachePath
		r.Action = "kept-in-cache"
	default: // CLEAN, HESITANT — already present, nothing to do
		r.Cached = true
		r.CachePath = cachePath
		r.Action = "already-cached"
	}
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
