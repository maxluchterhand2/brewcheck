// Package progress provides the small pieces that survive the bubbletea UI: a
// byte-counting io.Reader to drive transfer progress, and TTY detection used to
// decide between the interactive UI and plain text output.
package progress

import (
	"io"
	"os"

	"github.com/mattn/go-isatty"
)

// IsTTY reports whether f is an interactive terminal.
func IsTTY(f *os.File) bool {
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}

// NewReader wraps r so each Read reports cumulative bytes to cb with the fixed
// total. Pass it the download/upload callback to drive a progress bar. When cb
// is nil, r is returned unchanged.
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
