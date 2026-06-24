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
	kind          report.Kind
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
func run(ctx context.Context, positional string, cfg config) int {
	rulesDir, cleanup, err := resolveRules()
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not materialize bundled rules:", err)
	}
	defer cleanup()

	if useTUI(cfg) {
		return runTUI(ctx, positional, cfg, rulesDir)
	}
	r := runPipeline(ctx, positional, cfg, rulesDir, func(tea.Msg) {})
	emit(r, cfg)
	return r.Verdict.ExitCode()
}

// useTUI reports whether to render the interactive bubbletea UI: only when
// stdout is a terminal and the user hasn't opted into plain/machine output.
func useTUI(cfg config) bool {
	return progress.IsTTY(os.Stdout) && !cfg.noProgress && !cfg.jsonOut && !cfg.verbose
}

// runTUI runs the pipeline in the background, feeding a bubbletea model, and
// leaves the styled result on screen when it finishes.
func runTUI(ctx context.Context, positional string, cfg config, rulesDir string) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p := tea.NewProgram(ui.New(cancel), tea.WithOutput(os.Stdout))
	go func() {
		r := runPipeline(ctx, positional, cfg, rulesDir, p.Send)
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
func runPipeline(ctx context.Context, positional string, cfg config, rulesDir string, send func(tea.Msg)) *report.Report {
	logf := func(format string, a ...any) {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "[brewcheck] "+format+"\n", a...)
		}
	}
	r := &report.Report{}

	send(ui.PhaseMsg{Phase: ui.PhaseResolving})
	res, err := resolveTarget(ctx, positional, cfg)
	if err != nil {
		return failed(r, err, cfg)
	}
	r.Name, r.Kind, r.Version, r.SourceURL = res.name, res.kind, res.version, res.sourceURL
	send(ui.ResolvedMsg{Name: res.name, Kind: string(res.kind), Version: res.version, Source: res.sourceURL})
	logf("resolved %s %s version %s", res.kind, res.name, res.version)

	// Quarantine: isolated, restrictive-perms dir brew knows nothing about.
	q, err := download.NewQuarantine(cfg.quarantineDir, cfg.keep)
	if err != nil {
		return failed(r, err, cfg)
	}
	defer q.Cleanup()
	logf("quarantine: %s", q.Dir)

	// Resolve brew's cache path for this artifact ONCE (a `brew --cache`
	// subprocess), then reuse it both for cache-reuse detection and the
	// clean-verdict hand-off. Empty when brew is absent or the hash is
	// unverifiable (a cask "no_check"), which disables both.
	cacheDest := resolveCacheDest(ctx, res, logf)

	// If the artifact is already in brew's cache and its hash matches Homebrew's
	// published one, scan it in place instead of re-downloading.
	var (
		dl        *download.Result
		fromCache bool
	)
	if sum, size, hit := reuseFromCache(cacheDest, res.publishedHash, logf); hit {
		logf("reusing verified file already in brew cache: %s", cacheDest)
		dl = &download.Result{Path: cacheDest, SHA256: sum, Size: size}
		fromCache = true
		send(ui.CacheHitMsg{})
	} else {
		logf("downloading %s", res.sourceURL)
		send(ui.PhaseMsg{Phase: ui.PhaseDownloading})
		dl, err = q.Fetch(ctx, res.fetcher, maxDownloadSize, func(done, total int64) {
			send(ui.DownloadMsg{Done: done, Total: total})
		})
		if err != nil {
			return failed(r, fmt.Errorf("download failed: %w", err), cfg)
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
		r.Action = report.ActionDeleted
		return r
	}

	// Extract for scanning (never mount/run). Best-effort.
	send(ui.PhaseMsg{Phase: ui.PhaseScanning})
	scripts, extractedRoot, machO := prepareScanInputs(ctx, q, dl.Path, logf)
	scanTargets := []string{dl.Path}
	semgrepTargets := append([]string{}, scripts...)
	if extractedRoot != "" {
		scanTargets = append(scanTargets, extractedRoot)
		semgrepTargets = append(semgrepTargets, extractedRoot)
	}

	// Run the inspection pipeline over the verified artifact.
	in := scan.Input{
		Name:           res.name,
		Kind:           res.kind,
		ArtifactPath:   dl.Path,
		SHA256:         dl.SHA256,
		DefinitionJSON: res.defJSON,
		ScriptPaths:    scripts,
		SemgrepTargets: semgrepTargets,
		ScanTargets:    scanTargets,
		BinaryForCapa:  machO,
		SemgrepRules:   filepath.Join(rulesDir, "semgrep"),
		YaraRules:      filepath.Join(rulesDir, "yara", "brewcheck.yar"),
		VTKey:          os.Getenv("VT_API_KEY"),
		AllowCloud:     cfg.cloud,
		MaxUploadSize:  cfg.maxUploadSize,
		ArtifactSize:   dl.Size,
		GitHubRepo:     res.githubRepo,
		GitHubToken:    githubToken(),
		AllowNewRepos:  cfg.allowNewRepos,
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
	r.Degraded = report.CountErrored(r.Layers)

	// Cache-or-delete decision.
	decideAction(r, dl.Path, fromCache, cacheDest, cfg, logf)
	return r
}

// resolveCacheDest computes brew's cache path for this artifact, or "" when brew
// is absent or the hash isn't verifiable (so caching/reuse are both off).
func resolveCacheDest(ctx context.Context, res *resolved, logf func(string, ...any)) string {
	if !verify.Verifiable(res.publishedHash) || !brewcache.Available() {
		return ""
	}
	cp, err := brewcache.CachePath(ctx, res.name, res.kind, res.fromSource)
	if err != nil {
		logf("could not determine cache path: %v", err)
		return ""
	}
	return cp
}

// failed finalizes an ERROR report without printing anything.
func failed(r *report.Report, err error, cfg config) *report.Report {
	r.Verdict = report.VerdictError
	r.Error = err.Error()
	if r.Action == report.ActionNone {
		r.Action = actionFor(cfg)
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

// prepareScanInputs extracts the artifact (best-effort) and returns the install
// script paths, the extracted root ("" if extraction failed), and a
// representative Mach-O for capa ("" if none).
func prepareScanInputs(ctx context.Context, q *download.Quarantine, artifact string, logf func(string, ...any)) (scripts []string, extractedRoot, machO string) {
	scratch, err := q.Scratch("scratch")
	if err != nil {
		logf("could not create scratch dir: %v", err)
		return nil, "", ""
	}
	root, err := extract.Artifact(ctx, artifact, scratch)
	if err != nil {
		if errors.Is(err, extract.ErrUnsupported) {
			logf("no extractor available for this artifact; scanning the file directly")
		} else {
			logf("extraction failed (continuing with file-level scan): %v", err)
		}
		return nil, "", ""
	}
	scripts = extract.FindScripts(root)
	machO = extract.FindMachO(root)
	logf("extracted to %s (%d candidate scripts, machO=%q)", root, len(scripts), machO)
	return scripts, root, machO
}

// reuseFromCache reports whether cacheDest is a present file whose sha256 matches
// Homebrew's published hash — the whole safety story for scanning it in place
// rather than re-downloading. cacheDest is "" when caching is unavailable.
func reuseFromCache(cacheDest, publishedHash string, logf func(string, ...any)) (sum string, size int64, ok bool) {
	if cacheDest == "" || !verify.Verifiable(publishedHash) {
		return "", 0, false
	}
	fi, err := os.Stat(cacheDest)
	if err != nil || fi.IsDir() {
		return "", 0, false // not in the cache yet
	}
	got, err := verify.SHA256File(cacheDest)
	if err != nil {
		logf("could not hash cached file %s: %v", cacheDest, err)
		return "", 0, false
	}
	if !verify.Match(got, publishedHash) {
		logf("cached file present but sha256 does not match published hash; re-downloading")
		return "", 0, false
	}
	return got, fi.Size(), true
}

// decideAction decides what to do with the artifact after the verdict. The
// behavior differs depending on whether we scanned a fresh download (quarantine)
// or a file already living in brew's cache. cacheDest is brew's cache path (""
// when caching is unavailable), computed once by resolveCacheDest.
func decideAction(r *report.Report, artifact string, fromCache bool, cacheDest string, cfg config, logf func(string, ...any)) {
	if fromCache {
		decideCachedAction(r, cacheDest, logf)
		return
	}
	// HESITANT caches just like CLEAN (the bytes are not radioactive — an
	// aggressive heuristic merely wants the user to look closer). SUSPICIOUS and
	// MALICIOUS never reach here as cacheable.
	cacheable := r.Verdict == report.VerdictClean || r.Verdict == report.VerdictHesitant
	if cacheable && !cfg.noCache && r.HashVerified && cacheDest != "" {
		if err := brewcache.Place(artifact, cacheDest); err != nil {
			logf("cache hand-off failed: %v", err)
			r.Action = actionFor(cfg)
			return
		}
		r.Cached = true
		r.CachePath = cacheDest
		r.Action = report.ActionCached
		logf("placed verified bytes in cache: %s", cacheDest)
		return
	}
	r.Action = actionFor(cfg)
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
			r.Action = report.ActionCacheDeleteFailed
			return
		}
		logf("removed malicious file from brew cache: %s", cachePath)
		r.Action = report.ActionDeletedFromCache
	case report.VerdictSuspicious:
		r.Cached = true
		r.CachePath = cachePath
		r.Action = report.ActionKeptInCache
	default: // CLEAN, HESITANT — already present, nothing to do
		r.Cached = true
		r.CachePath = cachePath
		r.Action = report.ActionAlreadyCached
	}
}

func actionFor(cfg config) report.Action {
	if cfg.keep {
		return report.ActionKept
	}
	return report.ActionDeleted
}

// emit renders the report in the chosen format (plain text or --json).
func emit(r *report.Report, cfg config) {
	if cfg.jsonOut {
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
