// Package oci is a focused client for fetching Homebrew bottle blobs from
// ghcr.io. Homebrew's bottle URLs already point at the blob endpoint
// (.../blobs/sha256:<digest>), so we only need an anonymous pull token and a
// streamed GET — no manifest round-trip and no heavyweight registry library.
//
// See DECISIONS.md for why we resolve a token rather than hard-coding the
// well-known anonymous "QQ==" bearer (which also works, and is the fallback).
package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// anonFallbackToken is Homebrew's well-known anonymous GHCR bearer for public
// blobs, used if the token endpoint is unreachable.
const anonFallbackToken = "QQ=="

// BlobFetcher implements download.Fetcher for a ghcr.io bottle blob URL.
type BlobFetcher struct {
	BlobURL  string
	Name     string // formula name, for the suggested filename
	Version  string
	Platform string
	client   *http.Client
}

// NewBlobFetcher constructs a fetcher for a bottle blob URL.
func NewBlobFetcher(blobURL, name, version, platform string) *BlobFetcher {
	return &BlobFetcher{
		BlobURL:  blobURL,
		Name:     name,
		Version:  version,
		Platform: platform,
		client:   &http.Client{},
	}
}

// Open acquires an anonymous pull token and streams the blob.
func (b *BlobFetcher) Open(ctx context.Context) (io.ReadCloser, int64, error) {
	repo, err := repoFromBlobURL(b.BlobURL)
	if err != nil {
		return nil, 0, err
	}
	token := b.fetchToken(ctx, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.BlobURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.oci.image.layer.v1.tar+gzip, application/octet-stream")
	req.Header.Set("User-Agent", "brewcheck/0.1")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetching bottle blob: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("fetching bottle blob: %s", resp.Status)
	}
	return resp.Body, resp.ContentLength, nil
}

// FileName suggests a descriptive name for the quarantined bottle.
func (b *BlobFetcher) FileName() string {
	if b.Name != "" && b.Version != "" && b.Platform != "" {
		return fmt.Sprintf("%s-%s.%s.bottle.tar.gz", b.Name, b.Version, b.Platform)
	}
	return "bottle.tar.gz"
}

// fetchToken requests an anonymous pull token, falling back to the well-known
// anonymous bearer on any failure.
func (b *BlobFetcher) fetchToken(ctx context.Context, repo string) string {
	url := fmt.Sprintf("https://ghcr.io/token?service=ghcr.io&scope=repository:%s:pull", repo)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return anonFallbackToken
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return anonFallbackToken
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return anonFallbackToken
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return anonFallbackToken
	}
	if tok.Token != "" {
		return tok.Token
	}
	if tok.AccessToken != "" {
		return tok.AccessToken
	}
	return anonFallbackToken
}

// repoFromBlobURL extracts the repository path from a ghcr blob URL, e.g.
// https://ghcr.io/v2/homebrew/core/wget/blobs/sha256:... -> homebrew/core/wget
func repoFromBlobURL(blobURL string) (string, error) {
	const marker = "/v2/"
	i := strings.Index(blobURL, marker)
	if i < 0 {
		return "", fmt.Errorf("unrecognized ghcr blob URL: %s", blobURL)
	}
	rest := blobURL[i+len(marker):]
	j := strings.Index(rest, "/blobs/")
	if j < 0 {
		return "", fmt.Errorf("unrecognized ghcr blob URL: %s", blobURL)
	}
	repo := rest[:j]
	if repo == "" {
		return "", fmt.Errorf("empty repository in ghcr blob URL: %s", blobURL)
	}
	return repo, nil
}
