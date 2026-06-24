package progress

import (
	"io"
	"strings"
	"testing"
)

func TestNewReaderReportsProgress(t *testing.T) {
	const total = 100
	src := strings.NewReader(strings.Repeat("x", total))

	var lastDone, lastTotal int64
	calls := 0
	r := NewReader(src, total, func(done, tot int64) {
		calls++
		lastDone, lastTotal = done, tot
	})

	n, err := io.Copy(io.Discard, r)
	if err != nil {
		t.Fatal(err)
	}
	if n != total {
		t.Fatalf("copied %d bytes, want %d", n, total)
	}
	if calls == 0 {
		t.Error("callback was never invoked")
	}
	if lastDone != total || lastTotal != total {
		t.Errorf("final progress = (%d, %d), want (%d, %d)", lastDone, lastTotal, total, total)
	}
}

func TestNewReaderNilCallbackIsPassThrough(t *testing.T) {
	src := strings.NewReader("hello")
	if got := NewReader(src, 5, nil); got != src {
		t.Error("NewReader with nil callback should return the reader unchanged")
	}
}
