package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"brewcheck/internal/report"
)

var now = time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)

func ago(d time.Duration) time.Time { return now.Add(-d) }

const (
	day   = 24 * time.Hour
	month = 30 * day
	year  = 365 * day
)

func TestScore(t *testing.T) {
	tests := []struct {
		name        string
		m           Metrics
		wantScore   int
		wantTooNew  bool
		scoreAtMost int // 0 = exact; otherwise assert <=
	}{
		{
			name: "popular mature org repo scores high",
			m: Metrics{
				Stars: 25000, Contributors: 400,
				RepoCreated: ago(8 * year), OwnerCreated: ago(12 * year),
				OwnerType: "Organization", HasLicense: true,
			},
			wantScore: 10,
		},
		{
			name: "brand-new repo flips RepoTooNew regardless of stars",
			m: Metrics{
				Stars: 8000, Contributors: 3,
				RepoCreated: ago(10 * day), OwnerCreated: ago(5 * year), HasLicense: true,
			},
			wantTooNew: true,
		},
		{
			name: "exactly under a month is still too new",
			m: Metrics{
				Stars: 5, RepoCreated: ago(29 * day), OwnerCreated: ago(2 * year),
			},
			wantTooNew: true,
		},
		{
			name: "just over a month is not too new",
			m: Metrics{
				Stars: 5, Contributors: 1, RepoCreated: ago(35 * day), OwnerCreated: ago(2 * year),
			},
			wantTooNew:  false,
			scoreAtMost: 10, // only asserting it's not flagged new
		},
		{
			name: "obscure new-ish solo project scores low (but not zero)",
			m: Metrics{
				Stars: 2, Contributors: 1,
				RepoCreated: ago(3 * month), OwnerCreated: ago(8 * month), HasLicense: false,
			},
			scoreAtMost: lowScoreThreshold,
		},
		{
			name: "unknown contributors does not crash and stays bounded",
			m: Metrics{
				Stars: 120, Contributors: -1,
				RepoCreated: ago(2 * year), OwnerCreated: ago(4 * year), HasLicense: true,
			},
			scoreAtMost: 10,
		},
		{
			name:       "all-zero metrics with zero times => 0 and not too new (unknown age)",
			m:          Metrics{Contributors: -1},
			wantScore:  0,
			wantTooNew: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Score(tt.m, now)
			if got.RepoTooNew != tt.wantTooNew {
				t.Errorf("RepoTooNew = %v, want %v", got.RepoTooNew, tt.wantTooNew)
			}
			if got.Score < 0 || got.Score > 10 {
				t.Errorf("score %d out of range", got.Score)
			}
			if tt.scoreAtMost > 0 && got.Score > tt.scoreAtMost {
				t.Errorf("score = %d, want <= %d (signals: %v)", got.Score, tt.scoreAtMost, got.Signals)
			}
			if tt.scoreAtMost == 0 && !tt.wantTooNew {
				if got.Score != tt.wantScore {
					t.Errorf("score = %d, want %d (signals: %v)", got.Score, tt.wantScore, got.Signals)
				}
			}
		})
	}
}

func TestScoreStarsDominate(t *testing.T) {
	low := Score(Metrics{Stars: 1, Contributors: 1, RepoCreated: ago(2 * year), OwnerCreated: ago(2 * year)}, now)
	high := Score(Metrics{Stars: 9000, Contributors: 1, RepoCreated: ago(2 * year), OwnerCreated: ago(2 * year)}, now)
	if high.Score <= low.Score {
		t.Errorf("more stars should score higher: low=%d high=%d", low.Score, high.Score)
	}
}

func TestLastPageFromLink(t *testing.T) {
	link := `<https://api.github.com/repositories/1/contributors?per_page=1&anon=1&page=2>; rel="next", ` +
		`<https://api.github.com/repositories/1/contributors?per_page=1&anon=1&page=137>; rel="last"`
	n, ok := lastPageFromLink(link)
	if !ok || n != 137 {
		t.Errorf("lastPageFromLink = (%d,%v), want (137,true)", n, ok)
	}
	if _, ok := lastPageFromLink(""); ok {
		t.Error("empty Link header should yield ok=false")
	}
}

func TestComma(t *testing.T) {
	cases := map[int]string{0: "0", 42: "42", 1000: "1,000", 25000: "25,000", 1234567: "1,234,567"}
	for in, want := range cases {
		if got := comma(in); got != want {
			t.Errorf("comma(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestAnalyzeIntegration drives Analyze against a mock GitHub API to confirm
// end-to-end wiring (3 endpoints, Link-header contributors) and the sub-month
// SUSPICIOUS exception.
func TestAnalyzeIntegration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/widget", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{
			"stargazers_count": 12000,
			"created_at": %q,
			"fork": false, "archived": false,
			"license": {"spdx_id": "MIT"},
			"owner": {"login": "acme", "type": "Organization"}
		}`, ago(6*year).Format(time.RFC3339))
	})
	mux.HandleFunc("/repos/acme/widget/contributors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<...&page=88>; rel="last"`)
		fmt.Fprint(w, `[{}]`)
	})
	mux.HandleFunc("/users/acme", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"created_at": %q}`, ago(11*year).Format(time.RFC3339))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Redirect apiBase to the test server.
	oldBase := apiBase
	apiBase = srv.URL
	defer func() { apiBase = oldBase }()

	res := Analyze(context.Background(), Options{Repo: "acme/widget", Now: now})
	if res.Status != report.StatusRan {
		t.Fatalf("status = %v (err=%s)", res.Status, res.Err)
	}
	if res.Credibility == nil {
		t.Fatal("expected a Credibility result")
	}
	if res.Credibility.Score < 8 {
		t.Errorf("popular mature repo should score high, got %d (%v)", res.Credibility.Score, res.Credibility.Signals)
	}
	for _, f := range res.Findings {
		if f.Severity == report.SeveritySuspicious || f.Severity == report.SeverityMalicious {
			t.Errorf("healthy repo must not yield a blocking finding: %+v", f)
		}
	}
}

// mockNewRepo stands up a mock GitHub API for a 9-day-old repo and points
// apiBase at it for the duration of the test.
func mockNewRepo(t *testing.T) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/new/proj", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"stargazers_count": 3, "created_at": %q, "owner": {"login":"new","type":"User"}}`,
			ago(9*day).Format(time.RFC3339))
	})
	mux.HandleFunc("/repos/new/proj/contributors", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{}]`)
	})
	mux.HandleFunc("/users/new", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"created_at": %q}`, ago(20*day).Format(time.RFC3339))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	oldBase := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = oldBase })
}

func severities(res report.LayerResult) (suspicious, hesitant bool) {
	for _, f := range res.Findings {
		switch f.Severity {
		case report.SeveritySuspicious:
			suspicious = true
		case report.SeverityHesitant:
			hesitant = true
		}
	}
	return
}

func TestAnalyzeNewRepoIsSuspicious(t *testing.T) {
	mockNewRepo(t)
	res := Analyze(context.Background(), Options{Repo: "new/proj", Now: now})
	if res.Status != report.StatusRan {
		t.Fatalf("status = %v (err=%s)", res.Status, res.Err)
	}
	suspicious, _ := severities(res)
	if !suspicious {
		t.Errorf("sub-month repo must produce a SUSPICIOUS finding; findings=%+v", res.Findings)
	}
}

// TestAnalyzeNewRepoAllowed verifies the --allow-new-repos escape hatch: the
// sub-month repo no longer triggers SUSPICIOUS, only a non-blocking HESITANT.
func TestAnalyzeNewRepoAllowed(t *testing.T) {
	mockNewRepo(t)
	res := Analyze(context.Background(), Options{Repo: "new/proj", AllowNewRepos: true, Now: now})
	if res.Status != report.StatusRan {
		t.Fatalf("status = %v (err=%s)", res.Status, res.Err)
	}
	suspicious, hesitant := severities(res)
	if suspicious {
		t.Errorf("AllowNewRepos must suppress the SUSPICIOUS finding; findings=%+v", res.Findings)
	}
	if !hesitant {
		t.Errorf("a new repo with the rule disabled should still warn at HESITANT; findings=%+v", res.Findings)
	}
}

func TestAnalyzeNoRepoSkips(t *testing.T) {
	res := Analyze(context.Background(), Options{Repo: "", Now: now})
	if res.Status != report.StatusSkipped {
		t.Errorf("empty repo should skip, got %v", res.Status)
	}
}
