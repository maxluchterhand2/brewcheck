// Package api is a thin client for the Homebrew JSON API — the same source of
// truth that `brew` itself reads. It never invokes the brew binary.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	formulaEndpoint = "https://formulae.brew.sh/api/formula/%s.json"
	caskEndpoint    = "https://formulae.brew.sh/api/cask/%s.json"
)

// ErrNotFound is returned when the API responds 404 for a name.
var ErrNotFound = fmt.Errorf("not found")

// Client fetches metadata from the Homebrew API.
type Client struct {
	HTTP *http.Client
}

// New returns a Client with a sane default timeout.
func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// Formula holds the subset of formula metadata brewcheck needs, plus the raw
// JSON for static analysis.
type Formula struct {
	Name     string `json:"name"`
	Homepage string `json:"homepage"`
	Versions struct {
		Stable string `json:"stable"`
	} `json:"versions"`
	URLs struct {
		Stable struct {
			URL string `json:"url"`
		} `json:"stable"`
	} `json:"urls"`
	Bottle struct {
		Stable struct {
			Rebuild int                   `json:"rebuild"`
			Files   map[string]BottleFile `json:"files"`
		} `json:"stable"`
	} `json:"bottle"`

	Raw []byte `json:"-"`
}

// GitHubRepo returns the upstream "owner/repo" parsed from the formula's
// homepage or source URL, or "" if neither points at a GitHub repository.
func (f *Formula) GitHubRepo() string {
	return GitHubRepoFrom(f.Homepage, f.URLs.Stable.URL)
}

// BottleFile is one platform's bottle entry.
type BottleFile struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// Cask holds the subset of cask metadata brewcheck needs, plus raw JSON.
type Cask struct {
	Token     string            `json:"token"`
	Version   string            `json:"version"`
	URL       string            `json:"url"`
	Homepage  string            `json:"homepage"`
	SHA256    string            `json:"sha256"`
	Artifacts []json.RawMessage `json:"artifacts"`

	Raw []byte `json:"-"`
}

// GitHubRepo returns the upstream "owner/repo" parsed from the cask's homepage
// or download URL, or "" if neither points at a GitHub repository.
func (k *Cask) GitHubRepo() string {
	return GitHubRepoFrom(k.Homepage, k.URL)
}

// GitHubRepoFrom returns the first "owner/repo" it can parse from the given
// candidate URLs (in priority order), or "" if none point at a GitHub repo.
func GitHubRepoFrom(candidates ...string) string {
	for _, c := range candidates {
		if repo := parseGitHubRepo(c); repo != "" {
			return repo
		}
	}
	return ""
}

// parseGitHubRepo extracts "owner/repo" from a github.com (or related host) URL.
func parseGitHubRepo(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch strings.ToLower(u.Host) {
	case "github.com", "www.github.com",
		"raw.githubusercontent.com", "codeload.github.com", "objects.githubusercontent.com":
		// owner/repo are the first two path segments on all of these.
	default:
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	owner, repo := parts[0], strings.TrimSuffix(parts[1], ".git")
	if owner == "" || repo == "" {
		return ""
	}
	// First path segment is sometimes a reserved, non-user route.
	switch strings.ToLower(owner) {
	case "downloads", "sponsors", "marketplace", "about", "features", "topics", "collections", "orgs":
		return ""
	}
	return owner + "/" + repo
}

// GetFormula resolves a formula by name.
func (c *Client) GetFormula(ctx context.Context, name string) (*Formula, error) {
	body, err := c.get(ctx, fmt.Sprintf(formulaEndpoint, name))
	if err != nil {
		return nil, err
	}
	var f Formula
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("decoding formula JSON: %w", err)
	}
	f.Raw = body
	return &f, nil
}

// GetCask resolves a cask by name.
func (c *Client) GetCask(ctx context.Context, name string) (*Cask, error) {
	body, err := c.get(ctx, fmt.Sprintf(caskEndpoint, name))
	if err != nil {
		return nil, err
	}
	var k Cask
	if err := json.Unmarshal(body, &k); err != nil {
		return nil, fmt.Errorf("decoding cask JSON: %w", err)
	}
	k.Raw = body
	return &k, nil
}

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "brewcheck/0.1")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned %s for %s", resp.Status, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}
