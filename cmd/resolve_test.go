package cmd

import (
	"testing"

	"brewcheck/internal/api"
)

// withBottle returns a formula carrying a bottle for the current host platform.
func withBottle(t *testing.T) *api.Formula {
	t.Helper()
	platform, err := api.HostPlatform()
	if err != nil {
		t.Skipf("host platform unavailable: %v", err)
	}
	f := &api.Formula{Name: "demo"}
	f.Versions.Stable = "1.0"
	f.Bottle.Stable.Files = map[string]api.BottleFile{
		platform: {URL: "https://ghcr.io/v2/homebrew/core/demo/blobs/sha256:bottle", SHA256: "bottlehash"},
	}
	f.URLs.Stable.URL = "https://example.com/demo-1.0.tar.gz"
	f.URLs.Stable.Checksum = "sourcehash"
	return f
}

func TestFormulaTargetPrefersBottle(t *testing.T) {
	r, err := formulaTarget("demo", withBottle(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.fromSource {
		t.Error("should prefer the bottle when one exists for the host platform")
	}
	if r.publishedHash != "bottlehash" {
		t.Errorf("publishedHash = %q, want bottlehash", r.publishedHash)
	}
}

func TestFormulaTargetSourceFallback(t *testing.T) {
	f := &api.Formula{Name: "srcdemo"}
	f.Versions.Stable = "2.0"
	f.URLs.Stable.URL = "https://example.com/srcdemo-2.0.tar.gz"
	f.URLs.Stable.Checksum = "srcsum"
	// No bottle at all -> must fall back to source.

	r, err := formulaTarget("srcdemo", f)
	if err != nil {
		t.Fatal(err)
	}
	if !r.fromSource {
		t.Fatal("a formula with no bottle should fall back to a source build")
	}
	if r.kind != "formula" || r.sourceURL != f.URLs.Stable.URL || r.publishedHash != "srcsum" {
		t.Errorf("unexpected resolved: %+v", r)
	}
}

func TestFormulaTargetForceSource(t *testing.T) {
	old := opts.buildFromSource
	opts.buildFromSource = true
	defer func() { opts.buildFromSource = old }()

	r, err := formulaTarget("demo", withBottle(t)) // has a bottle, but we force source
	if err != nil {
		t.Fatal(err)
	}
	if !r.fromSource {
		t.Error("--build-from-source must use the source tarball even when a bottle exists")
	}
	if r.publishedHash != "sourcehash" {
		t.Errorf("publishedHash = %q, want sourcehash", r.publishedHash)
	}
}

func TestFormulaTargetNoBottleNoSource(t *testing.T) {
	f := &api.Formula{Name: "nothing"}
	f.Versions.Stable = "0.1"
	if _, err := formulaTarget("nothing", f); err == nil {
		t.Error("expected an error when there is neither a bottle nor a source URL")
	}
}

func TestFormulaTargetForceSourceWithoutSourceErrors(t *testing.T) {
	old := opts.buildFromSource
	opts.buildFromSource = true
	defer func() { opts.buildFromSource = old }()

	f := &api.Formula{Name: "bottleonly"}
	f.Versions.Stable = "1.0"
	platform, err := api.HostPlatform()
	if err != nil {
		t.Skipf("host platform unavailable: %v", err)
	}
	f.Bottle.Stable.Files = map[string]api.BottleFile{platform: {URL: "u", SHA256: "h"}}
	// bottle present but no source URL, and source is forced.
	if _, err := formulaTarget("bottleonly", f); err == nil {
		t.Error("expected an error: --build-from-source with no source URL")
	}
}
