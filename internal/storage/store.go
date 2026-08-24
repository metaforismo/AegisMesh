// Package storage implements the local-first JSONL evidence store: append-only
// size-rotated segment files, count/age retention, and read/export helpers.
package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

var errStore = errors.New("storage")

const (
	segmentPrefix = "events-"
	segmentExt    = ".jsonl"
	timeFormat    = "20060102T150405.000000000Z"
)

type Options struct {
	Dir          string
	MaxFileBytes int64 // rotate when a segment reaches this size (0 = use default)
	MaxEvents    int   // retention cap across all segments (0 = use default)
	MaxAgeDays   int   // drop segments older than this (0 = never age out)
}

// Store is a durable append-only JSONL store. Safe for concurrent use.
type Store struct {
	opts Options

	mu       sync.Mutex
	f        *os.File
	w        *bufio.Writer
	path     string
	size     int64
	appended uint64
}

const defaultMaxFileBytes = 16 << 20

func New(opts Options) (*Store, error) {
	if opts.MaxFileBytes == 0 {
		opts.MaxFileBytes = defaultMaxFileBytes
	}
	if opts.MaxFileBytes < 4096 {
		return nil, fmt.Errorf("%w: max_file_bytes must be >= 4096", errStore)
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create data dir %s: %v", errStore, opts.Dir, err)
	}
	s := &Store{opts: opts}
	if err := s.rotateLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func segName(t time.Time) string {
	return segmentPrefix + t.UTC().Format(timeFormat) + segmentExt
}

func (s *Store) rotateLocked() error {
	if s.w != nil {
		if err := s.w.Flush(); err != nil {
			return fmt.Errorf("%w: flush before rotate: %v", errStore, err)
		}
	}
	if s.f != nil {
		if err := s.f.Close(); err != nil {
			return fmt.Errorf("%w: close before rotate: %v", errStore, err)
		}
	}
	name := segName(time.Now())
	p := filepath.Join(s.opts.Dir, name)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		// Same-nanosecond collision is vanishingly unlikely; fall back to a suffix.
		p = filepath.Join(s.opts.Dir, segmentPrefix+time.Now().UTC().Format(timeFormat)+"-"+fmt.Sprint(os.Getpid())+segmentExt)
		f, err = os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("%w: open segment: %v", errStore, err)
		}
	}
	s.f, s.w, s.path, s.size = f, bufio.NewWriter(f), name, 0
	return nil
}

// Append writes one envelope as a single JSON line, rotating as needed.
func (s *Store) Append(_ context.Context, e event.Envelope) error {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("%w: marshal: %v", errStore, err)
	}
	b = append(b, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if int64(len(b)) > s.opts.MaxFileBytes {
		return fmt.Errorf("%w: encoded event (%d bytes) exceeds segment size %d; raise storage.max_file_bytes or lower max_event_bytes", errStore, len(b), s.opts.MaxFileBytes)
	}
	if s.size > 0 && s.size+int64(len(b)) > s.opts.MaxFileBytes {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := s.w.Write(b)
	s.size += int64(n)
	s.appended++
	if err != nil {
		return fmt.Errorf("%w: write: %v", errStore, err)
	}
	return nil
}

// Flush pushes buffered bytes to the OS. Called periodically by the runtime.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return nil
	}
	return s.w.Flush()
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return nil
	}
	err := s.w.Flush()
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	s.w, s.f = nil, nil
	return err
}

// Segment describes one evidence file on disk.
type Segment struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	ModTime   time.Time `json:"mod_time"`
}

// Segments lists evidence files oldest-first.
func (s *Store) Segments() ([]Segment, error) {
	entries, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("%w: list dir: %v", errStore, err)
	}
	var out []Segment
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), segmentPrefix) || !strings.HasSuffix(e.Name(), segmentExt) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("%w: inspect segment %s: %v", errStore, e.Name(), err)
		}
		out = append(out, Segment{
			Name:      e.Name(),
			Path:      filepath.Join(s.opts.Dir, e.Name()),
			SizeBytes: info.Size(),
			ModTime:   info.ModTime().UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime.Before(out[j].ModTime) })
	return out, nil
}

// ApplyRetention enforces count and age caps by deleting whole oldest segments.
// It returns the names of what it removed so callers can log/report it.
func (s *Store) ApplyRetention(ctx context.Context) (removed []string, err error) {
	remove := func(name string) bool {
		if rmErr := os.Remove(filepath.Join(s.opts.Dir, name)); rmErr == nil {
			removed = append(removed, name)
			return true
		}
		return false
	}

	segs, err := s.Segments()
	if err != nil || len(segs) == 0 {
		return nil, err
	}

	if s.opts.MaxAgeDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -s.opts.MaxAgeDays)
		for _, sg := range segs {
			select {
			case <-ctx.Done():
				return removed, ctx.Err()
			default:
			}
			start, ok := parseSegmentStart(sg.Name)
			old := sg.ModTime.Before(cutoff)
			if ok {
				old = start.Before(cutoff)
			}
			if old {
				remove(sg.Name)
			}
		}
		if segs, err = s.Segments(); err != nil {
			return removed, err
		}
	}

	if s.opts.MaxEvents > 0 && len(segs) > 1 { // never delete the active segment
		total := 0
		counts := make([]int, len(segs))
		for i, sg := range segs {
			n, cErr := CountSegment(sg.Path)
			if cErr != nil {
				return removed, cErr
			}
			counts[i] = n
			total += n
		}
		for i := 0; i < len(segs)-1 && total > s.opts.MaxEvents; i++ {
			select {
			case <-ctx.Done():
				return removed, ctx.Err()
			default:
			}
			if counts[i] == 0 {
				continue
			}
			before := total
			if remove(segs[i].Name) {
				total -= counts[i]
			}
			if total == before {
				break // disk removal failed; do not loop forever
			}
		}
	}
	return removed, nil
}

func parseSegmentStart(name string) (time.Time, bool) {
	base := strings.TrimSuffix(strings.TrimPrefix(name, segmentPrefix), segmentExt)
	if i := strings.Index(base, "-"); i > 0 && strings.Contains(base[:i], "T") {
		base = base[:i] // pid-collision fallback name
	}
	t, err := time.Parse(timeFormat, base)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// CountSegment counts envelopes in one file without materializing them.
func CountSegment(path string) (int, error) {
	f, err := os.Open(path) //nolint:gosec // paths come from our own segment listing
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n, sc.Err()
}

func forEachLine(path string, fn func(string) error) error {
	f, err := os.Open(path) //nolint:gosec // see above
	if err != nil {
		return fmt.Errorf("%w: read segment %s: %v", errStore, filepath.Base(path), err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if err := fn(sc.Text()); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w: read segment %s: %v", errStore, filepath.Base(path), err)
	}
	return nil
}

// Reader iterates envelopes across all segments in a directory without
// creating anything (read-only inspection path).
type Reader struct {
	dir string
}

// NewReader opens a read-only view over an evidence directory.
func NewReader(dir string) (*Reader, error) {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a readable evidence directory", errStore, dir)
	}
	return &Reader{dir: dir}, nil
}

func (s *Store) Reader() *Reader { return &Reader{dir: s.opts.Dir} }

func (r *Reader) segments() ([]Segment, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, fmt.Errorf("%w: list dir: %v", errStore, err)
	}
	var out []Segment
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), segmentPrefix) || !strings.HasSuffix(e.Name(), segmentExt) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("%w: inspect segment %s: %v", errStore, e.Name(), err)
		}
		out = append(out, Segment{
			Name:      e.Name(),
			Path:      filepath.Join(r.dir, e.Name()),
			SizeBytes: info.Size(),
			ModTime:   info.ModTime().UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime.Before(out[j].ModTime) })
	return out, nil
}

// IsSegmentPath reports whether path currently resolves to an evidence segment
// owned by this reader. It follows symlinks and detects hard links.
func (r *Reader) IsSegmentPath(path string) (bool, error) {
	target, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: inspect export target: %v", errStore, err)
	}
	segs, err := r.segments()
	if err != nil {
		return false, err
	}
	for _, seg := range segs {
		info, statErr := os.Stat(seg.Path)
		if statErr != nil {
			return false, fmt.Errorf("%w: inspect segment %s: %v", errStore, seg.Name, statErr)
		}
		if os.SameFile(target, info) {
			return true, nil
		}
	}
	return false, nil
}

// ForEach calls fn for every valid envelope in order. Corrupt lines are
// reported via onCorrupt and skipped — evidence readers must not crash on a
// partially written line (e.g., after power loss).
func (r *Reader) ForEach(fn func(event.Envelope) error, onCorrupt func(line string, err error)) error {
	segs, err := r.segments()
	if err != nil {
		return err
	}
	for _, sg := range segs {
		if err := forEachLine(sg.Path, func(ln string) error {
			if strings.TrimSpace(ln) == "" {
				return nil
			}
			var env event.Envelope
			if err := json.Unmarshal([]byte(ln), &env); err != nil {
				if onCorrupt != nil {
					onCorrupt(ln, err)
				}
				return nil
			}
			return fn(env)
		}); err != nil {
			return err
		}
	}
	return nil
}
