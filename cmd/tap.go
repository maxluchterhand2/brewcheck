package cmd

import (
	"context"
	"fmt"
	"strings"

	"brewcheck/internal/api"
	"brewcheck/internal/brewcache"
	"brewcheck/internal/download"
	"brewcheck/internal/oci"
	"brewcheck/internal/report"
)

// resolveTap resolves a formula/cask from a third-party tap. Unlike the core
// path (which uses the formulae.brew.sh JSON API), taps are resolved via
// `brew info --json=v2 <tap>/<name>` — the API does not serve third-party taps.
func resolveTap(ctx context.Context, tap, positional string, cfg config) (*resolved, error) {
	name, kindHint, err := tapTarget(positional, cfg)
	if err != nil {
		return nil, err
	}
	ref := strings.TrimSuffix(tap, "/") + "/" + name

	if !brewcache.Available() {
		return nil, fmt.Errorf("brew is required to resolve tap %q but is not on PATH", ref)
	}
	infoJSON, err := brewcache.Info(ctx, ref)
	if err != nil {
		return nil, err
	}
	f, k, err := api.ParseInfoV2(infoJSON)
	if err != nil {
		return nil, err
	}

	switch kindHint {
	case report.KindFormula:
		if f == nil {
			return nil, fmt.Errorf("%q is not a formula in tap %q (use --cask?)", name, tap)
		}
		return formulaTarget(ref, f, cfg)
	case report.KindCask:
		if k == nil {
			return nil, fmt.Errorf("%q is not a cask in tap %q (use --formula?)", name, tap)
		}
		return buildTapCask(ref, k)
	default: // positional: infer from whichever the tap provides
		switch {
		case f != nil && k != nil:
			return nil, fmt.Errorf("%q resolves as both a formula and a cask in %q; disambiguate with --formula or --cask", name, tap)
		case f != nil:
			return formulaTarget(ref, f, cfg)
		case k != nil:
			return buildTapCask(ref, k)
		default:
			return nil, fmt.Errorf("%q is neither a formula nor a cask in tap %q", name, tap)
		}
	}
}

// tapTarget picks the target name and kind hint from the flags/positional arg.
// An empty Kind means "infer from what the tap provides".
func tapTarget(positional string, cfg config) (name string, kindHint report.Kind, err error) {
	switch {
	case cfg.formula != "":
		return cfg.formula, report.KindFormula, nil
	case cfg.cask != "":
		return cfg.cask, report.KindCask, nil
	case positional != "":
		return positional, "", nil
	default:
		return "", "", fmt.Errorf("--tap requires a name: brewcheck --tap <user/repo> <name> | --formula <name> | --cask <name>")
	}
}

func buildTapCask(ref string, k *api.Cask) (*resolved, error) {
	if k.URL == "" {
		return nil, fmt.Errorf("cask %q has no download URL", ref)
	}
	return &resolved{
		name:          ref,
		kind:          report.KindCask,
		version:       k.Version,
		sourceURL:     k.URL,
		publishedHash: k.SHA256,
		defJSON:       k.Raw,
		githubRepo:    k.GitHubRepo(),
		fetcher:       download.NewHTTPFetcher(k.URL),
	}, nil
}

// bottleFetcher picks the right fetcher for a bottle URL. homebrew/core bottles
// live on ghcr.io (OCI registry), but third-party taps often host bottles as
// plain files (GitHub releases, a custom root_url), which need a direct GET.
func bottleFetcher(blobURL, name, version, platform string) download.Fetcher {
	if strings.Contains(blobURL, "ghcr.io") {
		return oci.NewBlobFetcher(blobURL, name, version, platform)
	}
	return download.NewHTTPFetcher(blobURL)
}
