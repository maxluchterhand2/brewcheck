package progress

import (
	"bytes"
	"strings"
	"testing"
)

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:          "0 B",
		512:        "512 B",
		1024:       "1.0 KiB",
		1536:       "1.5 KiB",
		1048576:    "1.0 MiB",
		11534336:   "11.0 MiB",
		1073741824: "1.0 GiB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestDisabledConstructorsAreNil(t *testing.T) {
	if NewBar(false, "x") != nil {
		t.Error("NewBar(false) should be nil")
	}
	if NewSpinner(false, "x") != nil {
		t.Error("NewSpinner(false) should be nil")
	}
}

func TestNilReceiversAreNoOps(t *testing.T) {
	// Must not panic — callers rely on this to stay branch-free when disabled.
	var b *Bar
	b.Update(1, 2)
	b.Finish()
	var s *Spinner
	s.Stop()
	s.Stop() // idempotent even on nil
}

func TestBarRenderKnownTotal(t *testing.T) {
	var buf bytes.Buffer
	b := &Bar{w: &buf, label: "downloading formula jq"}
	b.Update(50, 100) // first call always draws
	b.Finish()
	out := buf.String()
	for _, want := range []string{"downloading formula jq", " 50%", "50 B / 100 B"} {
		if !strings.Contains(out, want) {
			t.Errorf("bar output missing %q; got:\n%q", want, out)
		}
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("Finish should end the line with a newline")
	}
}

func TestBarRenderUnknownTotal(t *testing.T) {
	var buf bytes.Buffer
	b := &Bar{w: &buf, label: "downloading"}
	b.Update(2048, -1)
	b.Finish()
	out := buf.String()
	if !strings.Contains(out, "2.0 KiB") {
		t.Errorf("unknown-total bar should show a byte counter; got:\n%q", out)
	}
	if strings.Contains(out, "%") {
		t.Errorf("unknown-total bar must not show a percentage; got:\n%q", out)
	}
}

func TestBarFinishWithoutDrawIsSilent(t *testing.T) {
	var buf bytes.Buffer
	b := &Bar{w: &buf, label: "x"}
	b.Finish() // never Updated
	if buf.Len() != 0 {
		t.Errorf("Finish without any Update should write nothing; got %q", buf.String())
	}
}
