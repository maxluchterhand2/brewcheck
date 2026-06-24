package scan

import (
	"context"
	"strings"
	"testing"

	"brewcheck/internal/report"
	"brewcheck/internal/scan/vt"
)

// TestMaybeCloudSkips covers the non-network skip branches of the opt-in cloud
// upload, including the new "VirusTotal already has this file" guard that avoids
// the 409 Conflict on re-uploading a known artifact.
func TestMaybeCloudSkips(t *testing.T) {
	tests := []struct {
		name     string
		in       Input
		vtKnown  bool
		wantHint string
	}{
		{
			name:     "cloud not enabled",
			in:       Input{AllowCloud: false},
			vtKnown:  true,
			wantHint: "not enabled",
		},
		{
			name:     "enabled but VT already has the file -> skip, not upload",
			in:       Input{AllowCloud: true},
			vtKnown:  true,
			wantHint: "VirusTotal already has this file",
		},
		{
			name:     "enabled, unknown to VT, but over the size cap",
			in:       Input{AllowCloud: true, MaxUploadSize: 10, ArtifactSize: 1000},
			vtKnown:  false,
			wantHint: "max-upload-size",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maybeCloud(context.Background(), tt.in, vt.New(""), tt.vtKnown)
			if got.Status != report.StatusSkipped {
				t.Fatalf("status = %v, want skipped (no upload should be attempted)", got.Status)
			}
			if !strings.Contains(got.Hint, tt.wantHint) {
				t.Errorf("hint = %q, want it to contain %q", got.Hint, tt.wantHint)
			}
		})
	}
}
