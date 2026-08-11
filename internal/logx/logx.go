// Package logx implements gopr's leveled diagnostic logging (-d/-dd/-ddd)
// and raw data dump (-v), modeled on socat's -d/-v options: each additional
// -d reveals one more, less severe tier of messages, while -v is an
// independent switch that dumps the actual bytes relayed between target and
// listen (regardless of -d level).
package logx

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"sync"
)

// Level selects gopr's diagnostic verbosity, mirroring socat's -d stacking:
// each additional -d reveals one more, less severe tier of messages.
type Level int

const (
	// LevelError is the default (no -d): only fatal/error conditions that
	// abort a listener or a single connection/dial attempt. These are
	// always printed, independent of Level.
	LevelError Level = iota
	// LevelWarn (-d) adds connection/session lifecycle notices: accept,
	// close, UDP session create/reap.
	LevelWarn
	// LevelInfo (-dd) adds per-connection detail: dial targets, TLS/DTLS
	// handshake results, transfer byte-count summaries.
	LevelInfo
	// LevelDebug (-ddd) adds the most verbose trace: per-chunk read/write
	// sizes and per-packet UDP activity.
	LevelDebug
)

// MaxLevel is the highest level reachable by stacking -d (-ddd).
const MaxLevel = LevelDebug

// Clamp restricts level to [LevelError, MaxLevel].
func Clamp(level Level) Level {
	switch {
	case level < LevelError:
		return LevelError
	case level > MaxLevel:
		return MaxLevel
	default:
		return level
	}
}

// Logger is gopr's diagnostic + data-dump sink. It is safe for concurrent
// use. A nil *Logger behaves like New(LevelError, false): errors only, no
// data dump -- every method tolerates a nil receiver so callers that don't
// have a configured logger handy (e.g. in tests) can pass nil.
type Logger struct {
	level   Level
	verbose bool
	mu      sync.Mutex // serializes -v data-dump writes so chunks don't interleave
}

// New returns a Logger at the given level (clamped) with data dumping (-v)
// enabled per verbose.
func New(level Level, verbose bool) *Logger {
	return &Logger{level: Clamp(level), verbose: verbose}
}

// Error logs a message unconditionally: fatal/error conditions are always
// visible, independent of -d.
func (l *Logger) Error(format string, args ...any) { log.Printf(format, args...) }

// Print logs a message unconditionally, independent of level -- for
// operational banners such as "listening on ..." that should always be
// visible. Distinct from Error only in intent (both are unconditional);
// Error marks a failure, Print does not.
func (l *Logger) Print(format string, args ...any) { log.Printf(format, args...) }

// Warn logs a message when -d (or higher) is given.
func (l *Logger) Warn(format string, args ...any) { l.logAt(LevelWarn, format, args...) }

// Info logs a message when -dd (or higher) is given.
func (l *Logger) Info(format string, args ...any) { l.logAt(LevelInfo, format, args...) }

// Debug logs a message when -ddd is given.
func (l *Logger) Debug(format string, args ...any) { l.logAt(LevelDebug, format, args...) }

func (l *Logger) logAt(min Level, format string, args ...any) {
	if l == nil || l.level < min {
		return
	}
	log.Printf(format, args...)
}

// InfoEnabled reports whether -dd (or higher) is active, so callers can
// skip assembling otherwise-discarded detail (e.g. TLS cipher suite names).
func (l *Logger) InfoEnabled() bool { return l != nil && l.level >= LevelInfo }

// DebugEnabled reports whether -ddd is active.
func (l *Logger) DebugEnabled() bool { return l != nil && l.level >= LevelDebug }

// Verbose reports whether -v (data dump) is active.
func (l *Logger) Verbose() bool { return l != nil && l.verbose }

// Data writes one chunk of relayed application data to stderr, prefixed
// with "label > " (out) or "label < " (in) to indicate flow direction, in
// the same spirit as socat's -v. Non-printable bytes are escaped so each
// chunk stays on one line. No-op unless -v is active.
func (l *Logger) Data(label string, out bool, p []byte) {
	if l == nil || !l.verbose || len(p) == 0 {
		return
	}
	arrow := "< "
	if out {
		arrow = "> "
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "%s: %s%s\n", label, arrow, strconv.Quote(string(p)))
}

// Copy relays src to dst like io.Copy, additionally honoring -ddd (per-chunk
// size trace) and -v (data content dump). label identifies the
// connection/stream in log output; out is the flow direction to report to
// Data/Debug (true = data flowing toward the target, false = back toward
// the client). When neither -ddd nor -v is active, Copy is exactly
// io.Copy -- no per-chunk overhead is added to the common case.
func Copy(l *Logger, label string, out bool, dst io.Writer, src io.Reader) (int64, error) {
	if !l.Verbose() && !l.DebugEnabled() {
		return io.Copy(dst, src)
	}

	arrow := "<-"
	if out {
		arrow = "->"
	}
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			l.Data(label, out, chunk)
			l.Debug("%s: %s %d bytes", label, arrow, n)
			wn, werr := dst.Write(chunk)
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
			if wn != n {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}
