package download

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

// browserUA mimics a real browser; some vendor servers reject Go's default UA.
const browserUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

const maxRedirects = 10

// HTTPFetcher streams a cask artifact from a direct vendor/GitHub URL.
type HTTPFetcher struct {
	URL     string
	Headers map[string]string // extra headers from cask hints
	client  *http.Client
}

// NewHTTPFetcher builds a fetcher that follows a capped number of redirects.
func NewHTTPFetcher(url string, headers map[string]string) *HTTPFetcher {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
	return &HTTPFetcher{URL: url, Headers: headers, client: client}
}

// Open implements Fetcher.
func (f *HTTPFetcher) Open(ctx context.Context) (io.ReadCloser, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "*/*")
	for k, v := range f.Headers {
		req.Header.Set(k, v)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetching %s: %w", f.URL, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("fetching %s: %s", f.URL, resp.Status)
	}
	return resp.Body, resp.ContentLength, nil
}

// FileName implements Fetcher, deriving a name from the URL path.
func (f *HTTPFetcher) FileName() string {
	u := f.URL
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	base := path.Base(u)
	if base == "" || base == "/" || base == "." {
		return "artifact"
	}
	return base
}
