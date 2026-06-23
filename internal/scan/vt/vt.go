// Package vt is a minimal VirusTotal v3 client: hash lookup (zero upload) and
// an opt-in file upload as a last resort. Homebrew artifacts are public and
// popular, so the hash lookup usually returns multi-engine results without
// uploading any bytes.
package vt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"brewcheck/internal/report"
)

const apiBase = "https://www.virustotal.com/api/v3"

// maliciousThreshold is the engine-detection count at/above which we treat a
// hash as definitively known-bad.
const maliciousThreshold = 3

// Client talks to the VirusTotal API.
type Client struct {
	APIKey string
	HTTP   *http.Client
}

// New returns a Client reading the key from VT_API_KEY if apiKey is empty.
func New(apiKey string) *Client {
	if apiKey == "" {
		apiKey = os.Getenv("VT_API_KEY")
	}
	return &Client{APIKey: apiKey, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Configured reports whether an API key is present.
func (c *Client) Configured() bool { return c.APIKey != "" }

type fileStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Harmless   int `json:"harmless"`
}

type fileResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats fileStats `json:"last_analysis_stats"`
			MeaningfulName    string    `json:"meaningful_name"`
		} `json:"attributes"`
	} `json:"data"`
}

// LookupHash queries VT by sha256 without uploading. It returns the layer
// result, a boolean indicating a definitive malicious hit (for short-
// circuiting), and a boolean reporting whether VirusTotal already has a record
// of this file. The latter lets the caller skip a redundant cloud upload — VT
// rejects re-uploads of known files with 409 Conflict (AlreadyExistsError).
func (c *Client) LookupHash(ctx context.Context, sha256 string) (res report.LayerResult, definitelyBad, known bool) {
	res = report.LayerResult{Name: "VirusTotal hash reputation"}
	if !c.Configured() {
		res.Status = report.StatusSkipped
		res.Hint = "set VT_API_KEY (free key at https://www.virustotal.com)"
		return res, false, false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/files/"+sha256, nil)
	if err != nil {
		res.Status = report.StatusError
		res.Err = err.Error()
		return res, false, false
	}
	req.Header.Set("x-apikey", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		res.Status = report.StatusError
		res.Err = err.Error()
		return res, false, false
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		res.Status = report.StatusRan
		res.Summary = "hash unknown to VirusTotal (no prior analysis)"
		return res, false, false
	case http.StatusTooManyRequests:
		res.Status = report.StatusError
		res.Err = "VirusTotal rate limit hit (free tier ~4 req/min)"
		return res, false, false
	case http.StatusOK:
		// fallthrough below
	default:
		res.Status = report.StatusError
		res.Err = fmt.Sprintf("VirusTotal returned %s", resp.Status)
		return res, false, false
	}

	var fr fileResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&fr); err != nil {
		res.Status = report.StatusError
		res.Err = err.Error()
		return res, false, false
	}
	// A 200 means VT already has this file on record.
	out, bad := interpret(&res, fr.Data.Attributes.LastAnalysisStats)
	return out, bad, true
}

func interpret(res *report.LayerResult, st fileStats) (report.LayerResult, bool) {
	res.Status = report.StatusRan
	res.Summary = fmt.Sprintf("%d malicious / %d suspicious / %d harmless / %d undetected",
		st.Malicious, st.Suspicious, st.Harmless, st.Undetected)
	if st.Malicious >= maliciousThreshold {
		res.AddFinding(report.SeverityMalicious,
			fmt.Sprintf("%d engines flag this file as malicious", st.Malicious), "", "")
		return *res, true
	}
	if st.Malicious > 0 || st.Suspicious > 0 {
		res.AddFinding(report.SeveritySuspicious,
			fmt.Sprintf("%d malicious / %d suspicious engine detections", st.Malicious, st.Suspicious), "", "")
	}
	return *res, false
}

// Upload performs the opt-in last-resort file upload and polls the analysis.
// The caller is responsible for the size cap and for telling the user before
// calling this — Upload never decides policy on its own.
func (c *Client) Upload(ctx context.Context, path string) (report.LayerResult, bool) {
	res := report.LayerResult{Name: "VirusTotal upload (opt-in)"}
	if !c.Configured() {
		res.Status = report.StatusSkipped
		res.Hint = "set VT_API_KEY to enable cloud upload"
		return res, false
	}

	f, err := os.Open(path)
	if err != nil {
		res.Status = report.StatusError
		res.Err = err.Error()
		return res, false
	}
	defer f.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "artifact")
	if err == nil {
		_, err = io.Copy(fw, f)
	}
	if err != nil {
		res.Status = report.StatusError
		res.Err = err.Error()
		return res, false
	}
	mw.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/files", &buf)
	if err != nil {
		res.Status = report.StatusError
		res.Err = err.Error()
		return res, false
	}
	req.Header.Set("x-apikey", c.APIKey)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := c.HTTP.Do(req)
	if err != nil {
		res.Status = report.StatusError
		res.Err = err.Error()
		return res, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		res.Status = report.StatusError
		res.Err = fmt.Sprintf("upload returned %s", resp.Status)
		return res, false
	}

	var up struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&up); err != nil {
		res.Status = report.StatusError
		res.Err = err.Error()
		return res, false
	}
	return c.pollAnalysis(ctx, &res, up.Data.ID)
}

func (c *Client) pollAnalysis(ctx context.Context, res *report.LayerResult, id string) (report.LayerResult, bool) {
	for attempt := 0; attempt < 20; attempt++ {
		select {
		case <-ctx.Done():
			res.Status = report.StatusError
			res.Err = ctx.Err().Error()
			return *res, false
		case <-time.After(15 * time.Second):
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/analyses/"+id, nil)
		if err != nil {
			res.Status = report.StatusError
			res.Err = err.Error()
			return *res, false
		}
		req.Header.Set("x-apikey", c.APIKey)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			res.Status = report.StatusError
			res.Err = err.Error()
			return *res, false
		}
		var ar struct {
			Data struct {
				Attributes struct {
					Status string    `json:"status"`
					Stats  fileStats `json:"stats"`
				} `json:"attributes"`
			} `json:"data"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&ar)
		resp.Body.Close()
		if err != nil {
			res.Status = report.StatusError
			res.Err = err.Error()
			return *res, false
		}
		if ar.Data.Attributes.Status == "completed" {
			return interpret(res, ar.Data.Attributes.Stats)
		}
	}
	res.Status = report.StatusError
	res.Err = "VirusTotal analysis did not complete in time"
	return *res, false
}
