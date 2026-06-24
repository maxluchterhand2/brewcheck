package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// rewriteTransport redirects all requests to the test server, so we can mock
// the hard-coded formulae.brew.sh endpoints.
type rewriteTransport struct{ base *url.URL }

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = rt.base.Scheme
	req.URL.Host = rt.base.Host
	return http.DefaultTransport.RoundTrip(req)
}

const sampleFormula = `{
  "name": "wget",
  "versions": {"stable": "1.25.0"},
  "bottle": {"stable": {"rebuild": 0, "files": {
    "arm64_tahoe": {"url": "https://ghcr.io/v2/homebrew/core/wget/blobs/sha256:aaa", "sha256": "aaa"},
    "sonoma": {"url": "https://ghcr.io/v2/homebrew/core/wget/blobs/sha256:bbb", "sha256": "bbb"}
  }}}
}`

const sampleCask = `{
  "token": "google-chrome",
  "version": "149.0",
  "url": "https://dl.google.com/chrome.dmg",
  "sha256": "no_check",
  "artifacts": [{"app": ["Google Chrome.app"]}, {"zap": [{"trash": ["~/Library/Caches/Google"]}]}]
}`

func newMockClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)
	return &Client{HTTP: &http.Client{Transport: rewriteTransport{base}}}
}

func TestGetFormulaAndSelectBottle(t *testing.T) {
	c := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/formula/wget.json" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(sampleFormula))
	})

	f, err := c.GetFormula(context.Background(), "wget")
	if err != nil {
		t.Fatalf("GetFormula: %v", err)
	}
	if f.Versions.Stable != "1.25.0" {
		t.Errorf("version = %q, want 1.25.0", f.Versions.Stable)
	}

	tests := []struct {
		platform string
		wantKey  string
		wantHash string
		wantErr  bool
	}{
		{"arm64_tahoe", "arm64_tahoe", "aaa", false},
		{"sonoma", "sonoma", "bbb", false},
		{"arm64_ventura", "", "", true}, // not present, no "all"
	}
	for _, tt := range tests {
		key, bf, err := f.SelectBottle(tt.platform)
		if (err != nil) != tt.wantErr {
			t.Errorf("SelectBottle(%q) err=%v, wantErr=%v", tt.platform, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if key != tt.wantKey || bf.SHA256 != tt.wantHash {
			t.Errorf("SelectBottle(%q) = (%q,%q), want (%q,%q)", tt.platform, key, bf.SHA256, tt.wantKey, tt.wantHash)
		}
	}
}

func TestSelectBottleFallsBackToAll(t *testing.T) {
	f := &Formula{Name: "noarch"}
	f.Bottle.Stable.Files = map[string]BottleFile{"all": {URL: "u", SHA256: "h"}}
	key, bf, err := f.SelectBottle("arm64_tahoe")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if key != "all" || bf.SHA256 != "h" {
		t.Errorf("got (%q,%q), want (all,h)", key, bf.SHA256)
	}
}

func TestGetCask(t *testing.T) {
	c := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cask/google-chrome.json" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(sampleCask))
	})
	k, err := c.GetCask(context.Background(), "google-chrome")
	if err != nil {
		t.Fatalf("GetCask: %v", err)
	}
	if k.URL != "https://dl.google.com/chrome.dmg" {
		t.Errorf("url = %q", k.URL)
	}
	if k.SHA256 != "no_check" {
		t.Errorf("sha256 = %q, want no_check", k.SHA256)
	}
	if len(k.Artifacts) != 2 {
		t.Errorf("artifacts = %d, want 2", len(k.Artifacts))
	}
}

func TestGitHubRepoFrom(t *testing.T) {
	tests := []struct {
		name       string
		candidates []string
		want       string
	}{
		{"plain repo homepage", []string{"https://github.com/owner/repo"}, "owner/repo"},
		{"repo with trailing path", []string{"https://github.com/owner/repo/releases/latest"}, "owner/repo"},
		{"git suffix stripped", []string{"https://github.com/owner/repo.git"}, "owner/repo"},
		{"www host", []string{"https://www.github.com/owner/repo"}, "owner/repo"},
		{"release tarball host", []string{"https://codeload.github.com/owner/repo/tar.gz/v1"}, "owner/repo"},
		{"raw content host", []string{"https://raw.githubusercontent.com/owner/repo/main/x"}, "owner/repo"},
		{"homepage preferred over source url", []string{"https://github.com/a/b", "https://github.com/c/d"}, "a/b"},
		{"falls back to second candidate", []string{"https://example.com/foo", "https://github.com/c/d"}, "c/d"},
		{"non-github", []string{"https://gitlab.com/owner/repo"}, ""},
		{"github user only, no repo", []string{"https://github.com/owner"}, ""},
		{"reserved route", []string{"https://github.com/sponsors/owner"}, ""},
		{"empty", []string{""}, ""},
		{"gist not a repo host", []string{"https://gist.github.com/owner/deadbeef"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GitHubRepoFrom(tt.candidates...); got != tt.want {
				t.Errorf("GitHubRepoFrom(%v) = %q, want %q", tt.candidates, got, tt.want)
			}
		})
	}
}

func TestFormulaGitHubRepoPrefersHomepage(t *testing.T) {
	f := &Formula{Homepage: "https://github.com/jqlang/jq"}
	f.URLs.Stable.URL = "https://github.com/other/mirror/archive/v1.tar.gz"
	if got := f.GitHubRepo(); got != "jqlang/jq" {
		t.Errorf("GitHubRepo() = %q, want jqlang/jq", got)
	}
	// Homepage not on GitHub -> fall back to the source URL.
	f2 := &Formula{Homepage: "https://stedolan.github.io/jq/"}
	f2.URLs.Stable.URL = "https://github.com/jqlang/jq/releases/download/v1/jq.tar.gz"
	if got := f2.GitHubRepo(); got != "jqlang/jq" {
		t.Errorf("fallback GitHubRepo() = %q, want jqlang/jq", got)
	}
}

func TestParseInfoV2(t *testing.T) {
	formulaInfo := `{
	  "formulae": [{
	    "name": "tapfoo",
	    "homepage": "https://github.com/acme/tapfoo",
	    "versions": {"stable": "2.1.0"},
	    "urls": {"stable": {"url": "https://github.com/acme/tapfoo/archive/v2.1.0.tar.gz"}},
	    "bottle": {"stable": {"files": {
	      "arm64_tahoe": {"url": "https://ghcr.io/v2/acme/tapfoo/blobs/sha256:abc", "sha256": "abc"}
	    }}}
	  }],
	  "casks": []
	}`
	f, k, err := ParseInfoV2([]byte(formulaInfo))
	if err != nil {
		t.Fatalf("ParseInfoV2: %v", err)
	}
	if k != nil {
		t.Errorf("expected no cask, got %+v", k)
	}
	if f == nil || f.Name != "tapfoo" || f.Versions.Stable != "2.1.0" {
		t.Fatalf("formula not parsed correctly: %+v", f)
	}
	if f.GitHubRepo() != "acme/tapfoo" {
		t.Errorf("GitHubRepo = %q, want acme/tapfoo", f.GitHubRepo())
	}
	if len(f.Raw) == 0 {
		t.Error("formula Raw should be populated for static analysis")
	}

	caskInfo := `{
	  "formulae": [],
	  "casks": [{
	    "token": "tapbar",
	    "version": "9.9",
	    "url": "https://downloads.example.com/tapbar.dmg",
	    "sha256": "deadbeef",
	    "homepage": "https://github.com/acme/tapbar"
	  }]
	}`
	f, k, err = ParseInfoV2([]byte(caskInfo))
	if err != nil {
		t.Fatalf("ParseInfoV2 cask: %v", err)
	}
	if f != nil {
		t.Errorf("expected no formula, got %+v", f)
	}
	if k == nil || k.Token != "tapbar" || k.URL != "https://downloads.example.com/tapbar.dmg" {
		t.Fatalf("cask not parsed correctly: %+v", k)
	}

	// Empty info => both nil, no error.
	f, k, err = ParseInfoV2([]byte(`{"formulae": [], "casks": []}`))
	if err != nil || f != nil || k != nil {
		t.Errorf("empty info should yield (nil,nil,nil); got (%v,%v,%v)", f, k, err)
	}

	// Malformed JSON => error.
	if _, _, err := ParseInfoV2([]byte(`not json`)); err == nil {
		t.Error("expected error on malformed JSON")
	}
}

func TestNotFound(t *testing.T) {
	c := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	_, err := c.GetFormula(context.Background(), "nope")
	if err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
