package cmd

import (
	"context"
	"fmt"
	"strings"

	"brewcheck/internal/api"
	"brewcheck/internal/brewcache"
	"brewcheck/internal/download"
	"brewcheck/internal/oci"
)

// resolveTap resolves a formula/cask from a third-party tap. Unlike the core
// path (which uses the formulae.brew.sh JSON API), taps are resolved via
// `brew info --json=v2 <tap>/<name>` — the API does not serve third-party taps.
func resolveTap(ctx context.Context, tap, positional string) (*resolved, error) {
	name, kindHint, err := tapTarget(positional)
	if err != nil {
		return nil, err
	}
	ref := strings.TrimSuffix(tap, "/") + "/" + name

	infoJSON, err := brewcache.Info(ctx, ref)
	if err != nil {
		return nil, err
	}
	f, k, err := api.ParseInfoV2(infoJSON)
	if err != nil {
		return nil, err
	}

	switch kindHint {
	case "formula":
		if f == nil {
			return nil, fmt.Errorf("%q is not a formula in tap %q (use --cask?)", name, tap)
		}
		return buildTapFormula(ref, f)
	case "cask":
		if k == nil {
			return nil, fmt.Errorf("%q is not a cask in tap %q (use --formula?)", name, tap)
		}
		return buildTapCask(ref, k)
	default: // positional: infer from whichever the tap provides
		switch {
		case f != nil && k != nil:
			return nil, fmt.Errorf("%q resolves as both a formula and a cask in %q; disambiguate with --formula or --cask", name, tap)
		case f != nil:
			return buildTapFormula(ref, f)
		case k != nil:
			return buildTapCask(ref, k)
		default:
			return nil, fmt.Errorf("%q is neither a formula nor a cask in tap %q", name, tap)
		}
	}
}

// tapTarget picks the target name and kind hint from the flags/positional arg.
func tapTarget(positional string) (name, kindHint string, err error) {
	switch {
	case opts.formula != "":
		return opts.formula, "formula", nil
	case opts.cask != "":
		return opts.cask, "cask", nil
	case positional != "":
		return positional, "", nil
	default:
		return "", "", fmt.Errorf("--tap requires a name: brewcheck --tap <user/repo> <name> | --formula <name> | --cask <name>")
	}
}

func buildTapFormula(ref string, f *api.Formula) (*resolved, error) {
	// Same bottle-or-source resolution as a core formula; taps are frequently
	// source-only, so the source fallback matters here.
	return formulaTarget(ref, f)
}

func buildTapCask(ref string, k *api.Cask) (*resolved, error) {
	if k.URL == "" {
		return nil, fmt.Errorf("cask %q has no download URL", ref)
	}
	return &resolved{
		name:          ref,
		kind:          "cask",
		version:       k.Version,
		sourceURL:     k.URL,
		publishedHash: k.SHA256,
		defJSON:       k.Raw,
		githubRepo:    k.GitHubRepo(),
		fetcher:       download.NewHTTPFetcher(k.URL, nil),
	}, nil
}

// bottleFetcher picks the right fetcher for a bottle URL. homebrew/core bottles
// live on ghcr.io (OCI registry), but third-party taps often host bottles as
// plain files (GitHub releases, a custom root_url), which need a direct GET.
func bottleFetcher(blobURL, name, version, platform string) download.Fetcher {
	if strings.Contains(blobURL, "ghcr.io") {
		return oci.NewBlobFetcher(blobURL, name, version, platform)
	}
	return download.NewHTTPFetcher(blobURL, nil)
}
