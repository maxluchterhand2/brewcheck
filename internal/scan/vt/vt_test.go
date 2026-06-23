package vt

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"brewcheck/internal/report"
)

// TestUploadFileReportsProgress drives UploadFile against a mock VT endpoint and
// confirms (a) the file is POSTed, (b) the progress callback is invoked and
// reaches done == total, and (c) the analysis id is returned.
func TestUploadFileReportsProgress(t *testing.T) {
	var gotBody int64
	mux := http.NewServeMux()
	mux.HandleFunc("/files", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		n, _ := io.Copy(io.Discard, r.Body)
		gotBody = n
		w.Write([]byte(`{"data":{"id":"analysis-123"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	payload := make([]byte, 64*1024) // 64 KiB so the body is non-trivial
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	var lastDone, lastTotal int64
	progressCalls := 0
	id, res, ok := New("test-key").UploadFile(context.Background(), path, func(done, total int64) {
		progressCalls++
		lastDone, lastTotal = done, total
	})

	if !ok {
		t.Fatalf("UploadFile failed: status=%s err=%s", res.Status, res.Err)
	}
	if id != "analysis-123" {
		t.Errorf("analysis id = %q, want analysis-123", id)
	}
	if gotBody < int64(len(payload)) {
		t.Errorf("server received %d bytes, want >= %d (multipart body)", gotBody, len(payload))
	}
	if progressCalls == 0 {
		t.Error("progress callback was never called")
	}
	if lastDone != lastTotal || lastTotal <= 0 {
		t.Errorf("final progress = (%d/%d), want done == total > 0", lastDone, lastTotal)
	}
}

func TestUploadFileSkipsWithoutKey(t *testing.T) {
	client := New("")
	client.APIKey = ""
	id, res, ok := client.UploadFile(context.Background(), "/nonexistent", nil)
	if ok || id != "" {
		t.Errorf("unconfigured client should not upload; got ok=%v id=%q", ok, id)
	}
	if res.Status != report.StatusSkipped {
		t.Errorf("status = %v, want skipped", res.Status)
	}
}
