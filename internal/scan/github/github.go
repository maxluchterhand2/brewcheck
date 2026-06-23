// Package github rates the credibility of an artifact's upstream GitHub
// author/repository from cheap, public signals (stars, contributors, repo age,
// account age, license). It is deliberately lenient — new authors are normal in
// open source — so it NEVER produces a verdict worse than HESITANT, with one
// exception: a repository younger than one month yields a SUSPICIOUS finding.
//
// The 0..10 score is always surfaced to the user (via report.Credibility); the
// findings are what (occasionally) move the verdict.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"brewcheck/internal/report"
)

// apiBase is a var (not const) so tests can point it at a mock server.
var apiBase = "https://api.github.com"

// lowScoreThreshold: at or below this (for a not-brand-new repo) we raise a
// non-blocking HESITANT finding so the user takes a closer look.
const lowScoreThreshold = 3

// newRepoWindow is the "brand new" cutoff that triggers the SUSPICIOUS exception.
const newRepoWindow = 30 * 24 * time.Hour

var (
	errRateLimited  = errors.New("github API rate limit reached")
	errRepoNotFound = errors.New("github repository not found")
)

// Metrics are the raw public signals pulled from the GitHub API.
type Metrics struct {
	Repo         string
	Stars        int
	Contributors int // -1 when it could not be determined
	RepoCreated  time.Time
	OwnerCreated time.Time
	OwnerType    string // "User" | "Organization"
	HasLicense   bool
	Archived     bool
	Fork         bool
}

// Options configures an Analyze run.
type Options struct {
	Repo          string    // "owner/repo", or "" to skip
	Token         string    // optional GitHub API token for higher rate limits
	AllowNewRepos bool      // when true, a sub-month-old repo is NOT flagged SUSPICIOUS
	Now           time.Time // injected clock (for testability)
}

// Analyze fetches metrics for "owner/repo" and returns a credibility layer.
// A missing repo link, a rate-limit, or a network error never affects the
// verdict — only a valid result can, and then only up to HESITANT (or
// SUSPICIOUS for a sub-month-old repo, unless opt.AllowNewRepos disables that).
func Analyze(ctx context.Context, opt Options) report.LayerResult {
	repo, token, now := opt.Repo, opt.Token, opt.Now
	res := report.LayerResult{Name: "GitHub author credibility"}
	if repo == "" {
		res.Status = report.StatusSkipped
		res.Hint = "no GitHub repository linked in the definition"
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 25 * time.Second}

	m, err := fetchMetrics(ctx, client, repo, token)
	if err != nil {
		switch {
		case errors.Is(err, errRateLimited):
			res.Status = report.StatusSkipped
			res.Hint = "GitHub API rate limit reached; set GITHUB_TOKEN (or GH_TOKEN) for higher limits"
		case errors.Is(err, errRepoNotFound):
			// The definition links a repo that the API can't see (renamed,
			// deleted, or private). Note it, but don't punish the score.
			res.Status = report.StatusRan
			res.Summary = fmt.Sprintf("github.com/%s — repository not found via API", repo)
		default:
			res.Status = report.StatusError
			res.Err = err.Error()
		}
		return res
	}

	sc := Score(m, now)
	res.Status = report.StatusRan
	res.Summary = "github.com/" + repo
	res.Credibility = &report.Credibility{
		Score:   sc.Score,
		Max:     10,
		Repo:    "github.com/" + repo,
		Signals: sc.Signals,
	}
	loc := "github.com/" + repo
	switch {
	case sc.RepoTooNew && !opt.AllowNewRepos:
		res.AddFinding(report.SeveritySuspicious,
			"upstream GitHub repository is less than a month old",
			fmt.Sprintf("created %s — a brand-new upstream repo warrants extra scrutiny before trusting it",
				m.RepoCreated.Format("2006-01-02")),
			loc)
	case sc.RepoTooNew:
		// AllowNewRepos: the sub-month repo is not blocking, but still worth a
		// non-blocking heads-up rather than staying silent.
		res.AddFinding(report.SeverityHesitant,
			"upstream GitHub repository is less than a month old (30-day rule disabled)",
			fmt.Sprintf("created %s — flagged HESITANT instead of SUSPICIOUS because --allow-new-repos is set",
				m.RepoCreated.Format("2006-01-02")),
			loc)
	case sc.Score <= lowScoreThreshold:
		res.AddFinding(report.SeverityHesitant,
			fmt.Sprintf("low upstream credibility (score %d/10)", sc.Score),
			"this only reflects the project's public footprint, not its safety: "+strings.Join(sc.Signals, ", "),
			loc)
	}
	return res
}

// ScoreResult is the outcome of the heuristic.
type ScoreResult struct {
	Score      int
	Signals    []string
	RepoTooNew bool
}

// Score turns metrics into a 0..10 credibility score. It is pure (takes `now`)
// so it is fully table-testable. Weighting, highest-priority first:
//
//	stars        max 4.0
//	contributors max 2.0
//	repo age     max 2.0   (and < 1 month sets RepoTooNew)
//	owner age    max 1.5
//	license      max 0.5
func Score(m Metrics, now time.Time) ScoreResult {
	var pts float64
	var sig []string

	// Stars — highest priority.
	pts += bucketInt(m.Stars, []intBucket{
		{5000, 4.0}, {1000, 3.5}, {200, 3.0}, {50, 2.25}, {10, 1.5}, {1, 0.75},
	})
	sig = append(sig, fmt.Sprintf("%s★", comma(m.Stars)))

	// Contributors.
	if m.Contributors < 0 {
		pts += 0.25 // unknown: small neutral credit, don't punish
		sig = append(sig, "contributors: unknown")
	} else {
		pts += bucketInt(m.Contributors, []intBucket{
			{50, 2.0}, {10, 1.5}, {5, 1.0}, {2, 0.5}, {1, 0.25},
		})
		sig = append(sig, fmt.Sprintf("%s contributors", comma(m.Contributors)))
	}

	// Repo age (+ the sub-month exception).
	var repoTooNew bool
	if m.RepoCreated.IsZero() {
		sig = append(sig, "repo age: unknown")
	} else {
		age := now.Sub(m.RepoCreated)
		if age < newRepoWindow {
			repoTooNew = true
			sig = append(sig, fmt.Sprintf("repo age %s (NEW)", humanAge(age)))
		} else {
			pts += bucketDur(age, []durBucket{
				{3 * 365 * 24 * time.Hour, 2.0},
				{365 * 24 * time.Hour, 1.5},
				{182 * 24 * time.Hour, 1.0},
				{30 * 24 * time.Hour, 0.5},
			})
			sig = append(sig, fmt.Sprintf("repo age %s", humanAge(age)))
		}
	}

	// Owner/account age.
	if m.OwnerCreated.IsZero() {
		sig = append(sig, "account age: unknown")
	} else {
		age := now.Sub(m.OwnerCreated)
		pts += bucketDur(age, []durBucket{
			{3 * 365 * 24 * time.Hour, 1.5},
			{365 * 24 * time.Hour, 1.0},
			{182 * 24 * time.Hour, 0.5},
		})
		who := "account age"
		if m.OwnerType == "Organization" {
			who = "org age"
		}
		sig = append(sig, fmt.Sprintf("%s %s", who, humanAge(age)))
	}

	// License bonus.
	if m.HasLicense {
		pts += 0.5
		sig = append(sig, "licensed")
	} else {
		sig = append(sig, "no license")
	}

	// Informational flags — no score effect, but worth showing.
	if m.Archived {
		sig = append(sig, "ARCHIVED")
	}
	if m.Fork {
		sig = append(sig, "fork")
	}

	s := int(math.Round(pts))
	if s < 0 {
		s = 0
	}
	if s > 10 {
		s = 10
	}
	return ScoreResult{Score: s, Signals: sig, RepoTooNew: repoTooNew}
}

// ---- GitHub API plumbing -------------------------------------------------

func fetchMetrics(ctx context.Context, c *http.Client, repo, token string) (Metrics, error) {
	m := Metrics{Repo: repo, Contributors: -1}

	var repoResp struct {
		StargazersCount int       `json:"stargazers_count"`
		CreatedAt       time.Time `json:"created_at"`
		Fork            bool      `json:"fork"`
		Archived        bool      `json:"archived"`
		License         *struct {
			SPDXID string `json:"spdx_id"`
		} `json:"license"`
		Owner struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"owner"`
	}
	status, err := getJSON(ctx, c, token, apiBase+"/repos/"+repo, &repoResp)
	if err != nil {
		return m, err
	}
	if status == http.StatusNotFound {
		return m, errRepoNotFound
	}
	m.Stars = repoResp.StargazersCount
	m.RepoCreated = repoResp.CreatedAt
	m.Fork = repoResp.Fork
	m.Archived = repoResp.Archived
	m.OwnerType = repoResp.Owner.Type
	if l := repoResp.License; l != nil && l.SPDXID != "" && l.SPDXID != "NOASSERTION" {
		m.HasLicense = true
	}

	if n, ok := contributorCount(ctx, c, token, repo); ok {
		m.Contributors = n
	}

	if repoResp.Owner.Login != "" {
		var userResp struct {
			CreatedAt time.Time `json:"created_at"`
		}
		if _, err := getJSON(ctx, c, token, apiBase+"/users/"+repoResp.Owner.Login, &userResp); err == nil {
			m.OwnerCreated = userResp.CreatedAt
		}
	}
	return m, nil
}

// contributorCount derives the contributor count from the Link header of a
// per_page=1 listing (the standard cheap trick). Returns ok=false if it can't.
func contributorCount(ctx context.Context, c *http.Client, token, repo string) (int, bool) {
	url := apiBase + "/repos/" + repo + "/contributors?per_page=1&anon=1"
	req, err := newReq(ctx, token, url)
	if err != nil {
		return 0, false
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false // 204 (empty), 403 (too many), etc. -> unknown
	}
	if n, ok := lastPageFromLink(resp.Header.Get("Link")); ok {
		return n, true
	}
	// No pagination: the count is however many entries came back (0 or 1).
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var arr []json.RawMessage
	if json.Unmarshal(body, &arr) == nil {
		return len(arr), true
	}
	return 0, false
}

var linkLastPage = regexp.MustCompile(`[?&]page=(\d+)>;\s*rel="last"`)

func lastPageFromLink(link string) (int, bool) {
	mm := linkLastPage.FindStringSubmatch(link)
	if mm == nil {
		return 0, false
	}
	n, err := strconv.Atoi(mm[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

func newReq(ctx context.Context, token, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "brewcheck/0.1")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

// getJSON performs a GET and decodes a 200 body into v. It maps an exhausted
// rate limit to errRateLimited and returns the status code for 404 handling.
func getJSON(ctx context.Context, c *http.Client, token, url string, v any) (int, error) {
	req, err := newReq(ctx, token, url)
	if err != nil {
		return 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests ||
		(resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0") {
		return resp.StatusCode, errRateLimited
	}
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("github API returned %s for %s", resp.Status, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if v != nil {
		if err := json.Unmarshal(body, v); err != nil {
			return resp.StatusCode, fmt.Errorf("decoding %s: %w", url, err)
		}
	}
	return resp.StatusCode, nil
}

// ---- formatting helpers --------------------------------------------------

type intBucket struct {
	min int
	pts float64
}

func bucketInt(v int, defs []intBucket) float64 {
	for _, d := range defs {
		if v >= d.min {
			return d.pts
		}
	}
	return 0
}

type durBucket struct {
	min time.Duration
	pts float64
}

func bucketDur(d time.Duration, defs []durBucket) float64 {
	for _, b := range defs {
		if d >= b.min {
			return b.pts
		}
	}
	return 0
}

func humanAge(d time.Duration) string {
	days := d.Hours() / 24
	switch {
	case days >= 365:
		return fmt.Sprintf("%.1fy", days/365)
	case days >= 30:
		return fmt.Sprintf("%.0fmo", days/30)
	default:
		return fmt.Sprintf("%.0fd", days)
	}
}

// comma formats an int with thousands separators ("1234" -> "1,234").
func comma(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}
