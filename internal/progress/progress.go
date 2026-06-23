// Package progress renders lightweight, dependency-free terminal progress
// indicators on stderr: a percentage Bar for measurable work (downloads) and a
// braille Spinner for indeterminate waits (resolution, scanning).
//
// Everything writes to stderr so stdout (and --json) stays clean, and both
// types are no-ops on a nil receiver — callers construct them disabled (nil)
// when output isn't an interactive terminal and otherwise stay branch-free.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// StderrIsTTY reports whether stderr is an interactive terminal. Progress is
// pointless (and corrupts logs) when stderr is a pipe or file.
func StderrIsTTY() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

const barWidth = 24

// clearLine is the ANSI "carriage return + erase to end of line" sequence used
// to redraw an indicator in place.
const clearLine = "\r\033[K"

// Bar is an in-place percentage/byte progress bar for a measurable operation. A
// nil *Bar is a no-op.
type Bar struct {
	w     io.Writer
	label string

	mu       sync.Mutex
	total    int64
	done     int64
	lastDraw time.Time
	started  bool
}

// NewBar returns a Bar writing to stderr, or nil when enabled is false.
func NewBar(enabled bool, label string) *Bar {
	if !enabled {
		return nil
	}
	return &Bar{w: os.Stderr, label: label}
}

// Update records progress (done of total bytes; total <= 0 means unknown size)
// and redraws, throttled so frequent calls don't flood the terminal. It is safe
// to pass Update as a callback even when the Bar is nil.
func (b *Bar) Update(done, total int64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done, b.total = done, total

	complete := total > 0 && done >= total
	now := time.Now()
	if b.started && !complete && now.Sub(b.lastDraw) < 80*time.Millisecond {
		return
	}
	b.started = true
	b.lastDraw = now
	b.draw()
}

func (b *Bar) draw() {
	if b.total > 0 {
		pct := int(b.done * 100 / b.total)
		if pct > 100 {
			pct = 100
		}
		filled := pct * barWidth / 100
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		fmt.Fprintf(b.w, "%s%s  [%s] %3d%%  %s / %s",
			clearLine, b.label, bar, pct, humanBytes(b.done), humanBytes(b.total))
		return
	}
	fmt.Fprintf(b.w, "%s%s  %s", clearLine, b.label, humanBytes(b.done))
}

// Finish redraws the final state and moves to a new line. Safe on a nil Bar.
func (b *Bar) Finish() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.started {
		return // nothing was ever drawn (e.g. instant/empty download)
	}
	b.draw()
	fmt.Fprint(b.w, "\n")
}

// NewReader wraps r so each Read reports cumulative bytes to cb with the fixed
// total. Pass a Bar's Update as cb to drive a transfer/upload bar. When cb is
// nil, r is returned unchanged.
func NewReader(r io.Reader, total int64, cb func(done, total int64)) io.Reader {
	if cb == nil {
		return r
	}
	return &countingReader{r: r, total: total, cb: cb}
}

type countingReader struct {
	r     io.Reader
	total int64
	done  int64
	cb    func(done, total int64)
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		c.done += int64(n)
		c.cb(c.done, c.total)
	}
	return n, err
}

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner is an in-place braille spinner for indeterminate waits. A nil
// *Spinner is a no-op.
type Spinner struct {
	w     io.Writer
	label string
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
}

// NewSpinner starts a Spinner on stderr, or returns nil when enabled is false.
func NewSpinner(enabled bool, label string) *Spinner {
	if !enabled {
		return nil
	}
	s := &Spinner{
		w:     os.Stderr,
		label: label,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go s.run()
	return s
}

func (s *Spinner) run() {
	defer close(s.done)
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	fmt.Fprintf(s.w, "%s%s %s", clearLine, spinFrames[0], s.label)
	for i := 1; ; i++ {
		select {
		case <-s.stop:
			return
		case <-t.C:
			fmt.Fprintf(s.w, "%s%s %s", clearLine, spinFrames[i%len(spinFrames)], s.label)
		}
	}
}

// Stop halts the spinner and clears its line. Idempotent and safe on a nil
// Spinner.
func (s *Spinner) Stop() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		close(s.stop)
		<-s.done
		fmt.Fprint(s.w, clearLine)
	})
}

// humanBytes formats a byte count as a human-readable string.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), []string{"KiB", "MiB", "GiB", "TiB"}[exp])
}
