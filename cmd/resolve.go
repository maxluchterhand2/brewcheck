package cmd

import (
	"context"
	"errors"
	"fmt"

	"brewcheck/internal/api"
	"brewcheck/internal/download"
)

// maxDownloadSize guards against runaway downloads (2 GiB). Bottles and casks
// are well under this; it is a safety rail, not a policy knob.
const maxDownloadSize int64 = 2 << 30

// resolveTarget figures out which artifact to fetch based on the flags and any
// positional name, querying both API endpoints when the type is ambiguous.
func resolveTarget(ctx context.Context, positional string) (*resolved, error) {
	if opts.tap != "" {
		return resolveTap(ctx, opts.tap, positional)
	}

	client := api.New()

	switch {
	case opts.formula != "":
		return resolveFormula(ctx, client, opts.formula)
	case opts.cask != "":
		return resolveCask(ctx, client, opts.cask)
	case positional != "":
		return resolvePositional(ctx, client, positional)
	default:
		return nil, errors.New("provide a name: brewcheck <name> | --formula <name> | --cask <name>")
	}
}

func resolvePositional(ctx context.Context, client *api.Client, name string) (*resolved, error) {
	f, ferr := client.GetFormula(ctx, name)
	k, kerr := client.GetCask(ctx, name)

	formulaOK := ferr == nil
	caskOK := kerr == nil

	switch {
	case formulaOK && caskOK:
		return nil, fmt.Errorf("%q resolves as both a formula and a cask; disambiguate with --formula or --cask", name)
	case formulaOK:
		return buildFormula(f)
	case caskOK:
		return buildCask(k)
	default:
		// Neither resolved. Surface a non-404 error if there was one.
		if !errors.Is(ferr, api.ErrNotFound) {
			return nil, fmt.Errorf("resolving %q as formula: %w", name, ferr)
		}
		if !errors.Is(kerr, api.ErrNotFound) {
			return nil, fmt.Errorf("resolving %q as cask: %w", name, kerr)
		}
		return nil, fmt.Errorf("%q is neither a known formula nor a cask", name)
	}
}

func resolveFormula(ctx context.Context, client *api.Client, name string) (*resolved, error) {
	f, err := client.GetFormula(ctx, name)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return nil, fmt.Errorf("formula %q not found", name)
		}
		return nil, err
	}
	return buildFormula(f)
}

func resolveCask(ctx context.Context, client *api.Client, name string) (*resolved, error) {
	k, err := client.GetCask(ctx, name)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return nil, fmt.Errorf("cask %q not found", name)
		}
		return nil, err
	}
	return buildCask(k)
}

func buildFormula(f *api.Formula) (*resolved, error) {
	return formulaTarget(f.Name, f)
}

// formulaTarget resolves a formula to either its bottle or its upstream source
// tarball. It prefers the bottle for the host platform; if none exists (or
// --build-from-source is set), it falls back to the source tarball — the same
// choice `brew install` makes. name is the display/cache reference (the bare
// name for core formulae, the full "tap/name" ref for taps).
func formulaTarget(name string, f *api.Formula) (*resolved, error) {
	platform, err := api.HostPlatform()
	if err != nil {
		return nil, err
	}

	if !opts.buildFromSource {
		if key, bottle, err := f.SelectBottle(platform); err == nil {
			return &resolved{
				name:          name,
				kind:          "formula",
				version:       f.Versions.Stable,
				sourceURL:     bottle.URL,
				publishedHash: bottle.SHA256,
				defJSON:       f.Raw,
				githubRepo:    f.GitHubRepo(),
				fetcher:       bottleFetcher(bottle.URL, f.Name, f.Versions.Stable, key),
			}, nil
		}
		// No bottle for this platform — fall through to a source build.
	}

	src := f.SourceURL()
	if src == "" {
		if opts.buildFromSource {
			return nil, fmt.Errorf("formula %q has no source URL to build from", name)
		}
		return nil, fmt.Errorf("formula %q has no bottle for %s and no source URL to fall back to", name, platform)
	}
	return &resolved{
		name:          name,
		kind:          "formula",
		version:       f.Versions.Stable,
		sourceURL:     src,
		publishedHash: f.SourceChecksum(),
		defJSON:       f.Raw,
		githubRepo:    f.GitHubRepo(),
		fromSource:    true,
		fetcher:       download.NewHTTPFetcher(src, nil),
	}, nil
}

func buildCask(k *api.Cask) (*resolved, error) {
	if k.URL == "" {
		return nil, fmt.Errorf("cask %q has no download URL", k.Token)
	}
	return &resolved{
		name:          k.Token,
		kind:          "cask",
		version:       k.Version,
		sourceURL:     k.URL,
		publishedHash: k.SHA256,
		defJSON:       k.Raw,
		githubRepo:    k.GitHubRepo(),
		fetcher:       download.NewHTTPFetcher(k.URL, nil),
	}, nil
}
