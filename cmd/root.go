// Package cmd wires the CLI (cobra) and orchestrates the run:
// resolve -> download to quarantine -> verify sha256 -> extract -> scan ->
// aggregate -> cache-or-delete -> report.
package cmd

import (
	"context"
	"embed"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// options holds parsed flag values (the cobra binding target). It is snapshotted
// into an immutable config for the run, so the orchestration helpers receive
// config rather than reaching into this global.
type options struct {
	formula         string
	cask            string
	tap             string
	buildFromSource bool
	noCache         bool
	keep            bool
	cloud           bool
	maxUploadSize   int64
	jsonOut         bool
	verbose         bool
	quarantineDir   string
	allowNewRepos   bool
	noProgress      bool
}

// config is an immutable snapshot of the flags for one run.
type config struct {
	formula         string
	cask            string
	tap             string
	buildFromSource bool
	noCache         bool
	keep            bool
	cloud           bool
	maxUploadSize   int64
	jsonOut         bool
	verbose         bool
	quarantineDir   string
	allowNewRepos   bool
	noProgress      bool
}

func (o options) config() config {
	return config{
		formula:         o.formula,
		cask:            o.cask,
		tap:             o.tap,
		buildFromSource: o.buildFromSource,
		noCache:         o.noCache,
		keep:            o.keep,
		cloud:           o.cloud,
		maxUploadSize:   o.maxUploadSize,
		jsonOut:         o.jsonOut,
		verbose:         o.verbose,
		quarantineDir:   o.quarantineDir,
		allowNewRepos:   o.allowNewRepos,
		noProgress:      o.noProgress,
	}
}

var opts options

var rootCmd = &cobra.Command{
	Use:   "brewcheck [name]",
	Short: "Fetch, verify, and scan Homebrew formulae/casks before they touch brew's cache",
	Long: `brewcheck downloads a Homebrew formula bottle or cask artifact WITHOUT using
the brew binary to download, verifies its sha256 against Homebrew's published
hash, scans the verified bytes for malware and suspicious patterns, and — only
on a clean verdict — hands the bytes to brew's cache so a later 'brew install'
skips the download.

This tool detects known malware and suspicious patterns; it is not a defense
against a novel, targeted supply-chain attack. Its most valuable output is
showing what an install script actually does.`,
	Args:          cobra.MaximumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		positional := ""
		if len(args) == 1 {
			positional = args[0]
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		code := run(ctx, positional, opts.config())
		os.Exit(code)
		return nil
	},
}

// Execute runs the root command with the embedded rules tree.
func Execute(rulesFS embed.FS) {
	embeddedRules = rulesFS
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(3)
	}
}

func init() {
	f := rootCmd.Flags()
	f.StringVar(&opts.formula, "formula", "", "check a formula by name")
	f.StringVar(&opts.cask, "cask", "", "check a cask by name")
	f.StringVar(&opts.tap, "tap", "", "scan a formula/cask from a third-party tap, e.g. --tap user/repo (resolves metadata via 'brew info'; requires brew)")
	f.BoolVarP(&opts.buildFromSource, "build-from-source", "s", false, "scan the upstream source tarball instead of a bottle (forced for source-only formulae)")
	f.BoolVar(&opts.noCache, "no-cache", false, "do not place verified bytes in brew's cache on a clean verdict")
	f.BoolVar(&opts.keep, "keep", false, "keep the quarantine dir after the run (debugging)")
	f.BoolVar(&opts.cloud, "cloud", false, "allow opt-in cloud upload (VirusTotal) when the file's hash is unknown to VirusTotal")
	f.Int64Var(&opts.maxUploadSize, "max-upload-size", 52428800, "never cloud-upload a file larger than this many bytes")
	f.BoolVar(&opts.jsonOut, "json", false, "emit a machine-readable JSON report")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "log each pipeline step to stderr")
	f.StringVar(&opts.quarantineDir, "quarantine-dir", "", "override the default quarantine location")
	f.BoolVar(&opts.allowNewRepos, "allow-new-repos", false, "do not flag GitHub repositories younger than 30 days as SUSPICIOUS (credibility caps at HESITANT instead)")
	f.BoolVar(&opts.noProgress, "no-progress", false, "disable progress indicators (auto-disabled when stdout is not a TTY or with --verbose)")

	rootCmd.MarkFlagsMutuallyExclusive("formula", "cask")
}
