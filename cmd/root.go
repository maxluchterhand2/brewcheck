// Package cmd wires the CLI (cobra) and orchestrates the run:
// resolve -> download to quarantine -> verify sha256 -> extract -> scan ->
// aggregate -> cache-or-delete -> report.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// options holds parsed flag values for a run.
type options struct {
	formula       string
	cask          string
	cache         bool
	noCache       bool
	keep          bool
	cloud         bool
	maxUploadSize int64
	jsonOut       bool
	verbose       bool
	quarantineDir string
	allowNewRepos bool
	noProgress    bool
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

		code := run(ctx, positional)
		os.Exit(code)
		return nil
	},
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(3)
	}
}

func init() {
	f := rootCmd.Flags()
	f.StringVar(&opts.formula, "formula", "", "check a formula bottle by name")
	f.StringVar(&opts.cask, "cask", "", "check a cask by name")
	f.BoolVar(&opts.cache, "cache", true, "on a clean verdict, place verified bytes in brew's cache")
	f.BoolVar(&opts.noCache, "no-cache", false, "disable the cache hand-off (overrides --cache)")
	f.BoolVar(&opts.keep, "keep", false, "keep the quarantine dir after the run (debugging)")
	f.BoolVar(&opts.cloud, "cloud", false, "allow opt-in cloud upload (VirusTotal) as a last resort")
	f.Int64Var(&opts.maxUploadSize, "max-upload-size", 52428800, "never cloud-upload a file larger than this many bytes")
	f.BoolVar(&opts.jsonOut, "json", false, "emit a machine-readable JSON report")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "log each pipeline step to stderr")
	f.StringVar(&opts.quarantineDir, "quarantine-dir", "", "override the default quarantine location")
	f.BoolVar(&opts.allowNewRepos, "allow-new-repos", false, "do not flag GitHub repositories younger than 30 days as SUSPICIOUS (credibility caps at HESITANT instead)")
	f.BoolVar(&opts.noProgress, "no-progress", false, "disable progress indicators (auto-disabled when stderr is not a TTY or with --verbose)")

	rootCmd.MarkFlagsMutuallyExclusive("formula", "cask")
}
