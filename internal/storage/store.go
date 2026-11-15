// Package storage implements the local-first evidence store: append-only
// size-rotated segment files, count/age retention, and read/export helpers.
package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

var errStore = errors.New("storage")

const (
	segmentPrefix = "events-"
	segmentExt    = ".jsonl"
	timeFormat    = "20060102T150405.000000000Z"

	encryptionGuardName    = ".aegismesh-encryption-required-v1"
	encryptionGuardContent = "aegismesh.encryption-required/v1\n"
)

type Options struct {
	Dir           string
	MaxFileBytes  int64 // rotate when a segment reaches this size (0 = use default)
	MaxEventBytes int   // reject larger encoded envelopes (0 = use default)
	MaxEvents     int   // retention cap across all segments (0 = use default)
	MaxAgeDays    int   // drop segments older than this (0 = never age out)
	Encryption    *EncryptionOptions
	now           func() time.Time
}

// Store is a durable append-only evidence store. Safe for concurrent use.
type Store struct {
	opts      Options
	encryptor *segmentEncryptor
	now       func() time.Time

	mu               sync.Mutex
	f                *os.File
	w                *bufio.Writer
	path             string
	size             int64
	segmentEvents    uint64
	checkpointEvents uint64
	firstEventAt     time.Time
	appended         uint64
	digest           hash.Hash
	sealed           bool
}

const (
	defaultMaxFileBytes  = 16 << 20
	defaultMaxEventBytes = 256 << 10
)

func New(opts Options) (*Store, error) {
	if opts.MaxFileBytes == 0 {
		opts.MaxFileBytes = defaultMaxFileBytes
	}
	if opts.MaxEventBytes == 0 {
		opts.MaxEventBytes = defaultMaxEventBytes
	}
	if opts.MaxFileBytes < 4096 {
		return nil, fmt.Errorf("%w: max_file_bytes must be >= 4096", errStore)
	}
	if opts.MaxEventBytes < 1024 {
		return nil, fmt.Errorf("%w: max_event_bytes must be >= 1024", errStore)
	}
	if opts.MaxEventBytes > event.MaxStoredEnvelopeBytes {
		return nil, fmt.Errorf("%w: max_event_bytes must be <= %d", errStore, event.MaxStoredEnvelopeBytes)
	}
	encryptor, err := newSegmentEncryptor(opts.Encryption)
	if err != nil {
		return nil, err
	}
	now := opts.now
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create data dir %s: %v", errStore, opts.Dir, err)
	}
	if err := enforceEncryptionMode(opts.Dir, encryptor != nil); err != nil {
		return nil, err
	}
	s := &Store{opts: opts, encryptor: encryptor, now: now}
	if err := s.rotateLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func enforceEncryptionMode(dir string, encrypted bool) error {
	guardPath := filepath.Join(dir, encryptionGuardName)
	if encrypted {
		return ensureEncryptionGuard(guardPath)
	}
	if _, err := os.Lstat(guardPath); err == nil {
		return fmt.Errorf("%w: encryption was previously enabled for this data directory; refusing plaintext writes", errStore)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: inspect encryption guard: %v", errStore, err)
	}
	segments, err := listSegments(dir)
	if err != nil {
		return err
	}
	for _, segment := range segments {
		if segment.Encrypted {
			return fmt.Errorf("%w: encrypted evidence exists in this data directory; refusing plaintext writes", errStore)
		}
	}
	return nil
}

func ensureEncryptionGuard(path string) error {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			return fmt.Errorf("%w: create encryption guard: %v", errStore, createErr)
		}
		if _, writeErr := io.WriteString(f, encryptionGuardContent); writeErr != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return fmt.Errorf("%w: write encryption guard: %v", errStore, writeErr)
		}
		if closeErr := f.Close(); closeErr != nil {
			_ = os.Remove(path)
			return fmt.Errorf("%w: close encryption guard: %v", errStore, closeErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: inspect encryption guard: %v", errStore, err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: encryption guard must be an owner-only regular file", errStore)
	}
	// Fixed path inside the configured data directory.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec
	if err != nil {
		return fmt.Errorf("%w: open encryption guard: %v", errStore, err)
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%w: inspect opened encryption guard: %v", errStore, err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return fmt.Errorf("%w: encryption guard changed while opening", errStore)
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(len(encryptionGuardContent)+1)))
	if err != nil {
		return fmt.Errorf("%w: read encryption guard: %v", errStore, err)
	}
	if string(raw) != encryptionGuardContent {
		return fmt.Errorf("%w: encryption guard has unsupported contents", errStore)
	}
	return nil
}

func segName(t time.Time) string { return segmentName(t, false) }

func segmentName(t time.Time, encrypted bool) string {
	return segmentPrefix + t.UTC().Format(timeFormat) + segmentExtension(encrypted)
}

func segmentExtension(encrypted bool) string {
	if encrypted {
		return encryptedSegmentExt
	}
	return segmentExt
}

func (s *Store) sealLocked() error {
	return s.completeLocked(sealKind)
}

func (s *Store) completeLocked(kind byte) error {
	if s.encryptor == nil || s.sealed || s.w == nil {
		return nil
	}
	if kind == checkpointKind && s.checkpointEvents == s.segmentEvents {
		return nil
	}
	plain := completionPlaintext(kind, s.segmentEvents, s.digest.Sum(nil))
	frame, err := s.encryptor.frame(plain)
	if err != nil {
		return err
	}
	recordSize := frameLengthBytes + len(frame)
	if recordSize > encryptedFooterReserve {
		return fmt.Errorf("%w: encrypted completion exceeds reserved space", errStore)
	}
	// Preserve seal space even when flushes, rather than events, fill a segment.
	if kind == checkpointKind && s.size+int64(recordSize)+encryptedFooterReserve > s.opts.MaxFileBytes {
		return s.sealLocked()
	}
	record := make([]byte, frameLengthBytes, recordSize)
	if kind == sealKind {
		for i := range record {
			record[i] = 0xff
		}
	}
	record = append(record, frame...)
	if n, err := s.w.Write(record); err != nil {
		return fmt.Errorf("%w: write encrypted completion: %v", errStore, err)
	} else if n != len(record) {
		return fmt.Errorf("%w: write encrypted completion: %v", errStore, io.ErrShortWrite)
	}
	s.size += int64(len(record))
	s.checkpointEvents = s.segmentEvents
	s.sealed = kind == sealKind
	return nil
}

func (s *Store) rotateLocked() error {
	if err := s.sealLocked(); err != nil {
		return err
	}
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

	encrypted := s.encryptor != nil
	ext := segmentExtension(encrypted)
	base := strings.TrimSuffix(segmentName(s.now(), encrypted), ext)
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		name := base + ext
		if attempt > 0 {
			name = fmt.Sprintf("%s-%d-%d%s", base, os.Getpid(), attempt, ext)
		}
		path := filepath.Join(s.opts.Dir, name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
		if errors.Is(err, os.ErrExist) {
			lastErr = err
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: open segment: %v", errStore, err)
		}

		size := int64(0)
		if encrypted {
			n, err := writeEncryptedSegmentHeader(f)
			if err != nil {
				_ = f.Close()
				_ = os.Remove(path)
				return err
			}
			size = int64(n)
		}

		s.f = f
		s.w = bufio.NewWriter(f)
		s.path = name
		s.size = size
		s.segmentEvents = 0
		s.checkpointEvents = 0
		s.firstEventAt = time.Time{}
		s.digest = sha256.New()
		s.sealed = false
		return nil
	}
	return fmt.Errorf("%w: open unique segment after collisions: %v", errStore, lastErr)
}

// Append writes one envelope as one plaintext JSONL record or one authenticated
// age frame, rotating whole segments as needed.
func (s *Store) Append(_ context.Context, e event.Envelope) error {
	plaintext, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("%w: marshal: %v", errStore, err)
	}
	if len(plaintext) > s.opts.MaxEventBytes {
		return fmt.Errorf("%w: encoded event (%d bytes) exceeds max_event_bytes %d",
			errStore, len(plaintext), s.opts.MaxEventBytes)
	}

	return s.AppendEncoded(plaintext)
}

// AppendEncoded preserves a validated native envelope encoding supplied by a trusted ingestion boundary.
// Callers must validate schema and payload integrity before using this method.
func (s *Store) AppendEncoded(plaintext []byte) error {
	if len(plaintext) > s.opts.MaxEventBytes || !json.Valid(plaintext) || bytes.ContainsAny(plaintext, "\r\n") {
		return fmt.Errorf("%w: invalid encoded envelope", errStore)
	}

	var err error
	record := plaintext
	if s.encryptor != nil {
		record, err = s.encryptor.frame(plaintext)
		if err != nil {
			return err
		}
	} else {
		record = append(plaintext, '\n')
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.w == nil || s.f == nil {
		return fmt.Errorf("%w: append on closed store", errStore)
	}
	// Reject frames that cannot fit even a fresh segment before sealing/rotating
	// anything. Rejected traffic must not force tiny segments or empty successors.
	if s.encryptor != nil && int64(len(encryptedSegmentMagic)+len(record)+encryptedFooterReserve) > s.opts.MaxFileBytes {
		return fmt.Errorf("%w: encoded event (%d bytes on disk) exceeds segment size %d; "+
			"raise storage.max_file_bytes or lower max_event_bytes", errStore, len(record), s.opts.MaxFileBytes)
	}
	if s.sealed {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	reserve := int64(0)
	if s.encryptor != nil {
		reserve = encryptedFooterReserve
	}
	if s.size+int64(len(record))+reserve > s.opts.MaxFileBytes && s.segmentEvents == 0 {
		return fmt.Errorf("%w: encoded event (%d bytes on disk) exceeds segment size %d; "+
			"raise storage.max_file_bytes or lower max_event_bytes", errStore, len(record), s.opts.MaxFileBytes)
	}
	if s.segmentEvents > 0 && s.size+int64(len(record))+reserve > s.opts.MaxFileBytes {
		if err := s.rotateLocked(); err != nil {
			return err
		}
		if s.size+int64(len(record))+reserve > s.opts.MaxFileBytes {
			return fmt.Errorf("%w: encoded event (%d bytes on disk) exceeds segment size %d; "+
				"raise storage.max_file_bytes or lower max_event_bytes", errStore, len(record), s.opts.MaxFileBytes)
		}
	}

	n, err := s.w.Write(record)
	if err != nil {
		return fmt.Errorf("%w: write: %v", errStore, err)
	}
	if n != len(record) {
		return fmt.Errorf("%w: write: %v", errStore, io.ErrShortWrite)
	}
	s.size += int64(n)
	if s.encryptor != nil {
		_, _ = s.digest.Write(record)
		if s.segmentEvents == 0 {
			s.firstEventAt = s.now()
		}
	}
	s.segmentEvents++
	s.appended++
	return nil
}

// Flush pushes buffered bytes to the OS (it does not fsync). Encrypted segments
// checkpoint new frames, or seal at the age/space bound. The next append after
// sealing starts a new segment. Empty segments never seal because of elapsed time.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return nil
	}
	if s.encryptor != nil && s.segmentEvents > 0 && !s.sealed && s.now().Sub(s.firstEventAt) >= maxEncryptedSegmentAge {
		if err := s.sealLocked(); err != nil {
			return err
		}
	}
	if err := s.completeLocked(checkpointKind); err != nil {
		return err
	}
	if err := s.w.Flush(); err != nil {
		return fmt.Errorf("%w: flush: %v", errStore, err)
	}
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return nil
	}
	err := s.sealLocked()
	if flushErr := s.w.Flush(); err == nil {
		err = flushErr
	}
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
	Encrypted bool      `json:"encrypted,omitempty"`
}

func segmentEncryption(name string) (encrypted bool, ok bool) {
	if !strings.HasPrefix(name, segmentPrefix) {
		return false, false
	}
	switch {
	case strings.HasSuffix(name, encryptedSegmentExt):
		return true, true
	case strings.HasSuffix(name, segmentExt):
		return false, true
	default:
		return false, false
	}
}

func listSegments(dir string) ([]Segment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: list dir: %v", errStore, err)
	}
	out := make([]Segment, 0, len(entries))
	for _, entry := range entries {
		encrypted, ok := segmentEncryption(entry.Name())
		if !ok {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("%w: inspect segment %s: %v", errStore, entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: read segment %s: not a regular file", errStore, entry.Name())
		}
		out = append(out, Segment{
			Name:      entry.Name(),
			Path:      filepath.Join(dir, entry.Name()),
			SizeBytes: info.Size(),
			ModTime:   info.ModTime().UTC(),
			Encrypted: encrypted,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ModTime.Equal(out[j].ModTime) {
			return out[i].Name < out[j].Name
		}
		return out[i].ModTime.Before(out[j].ModTime)
	})
	return out, nil
}

// Segments lists evidence files oldest-first.
func (s *Store) Segments() ([]Segment, error) { return listSegments(s.opts.Dir) }

// ApplyRetention enforces count and age caps by deleting whole oldest closed
// segments. The active segment is never removed.
func (s *Store) ApplyRetention(ctx context.Context) (removed []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	segs, err := listSegments(s.opts.Dir)
	if err != nil || len(segs) == 0 {
		return nil, err
	}
	active := s.path
	remove := func(name string) bool {
		if name == active {
			return false
		}
		if rmErr := os.Remove(filepath.Join(s.opts.Dir, name)); rmErr == nil {
			removed = append(removed, name)
			return true
		}
		return false
	}

	if s.opts.MaxAgeDays > 0 {
		cutoff := s.now().UTC().AddDate(0, 0, -s.opts.MaxAgeDays)
		for _, sg := range segs {
			select {
			case <-ctx.Done():
				return removed, ctx.Err()
			default:
			}
			if sg.Name == active {
				continue
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
		if segs, err = listSegments(s.opts.Dir); err != nil {
			return removed, err
		}
	}

	if s.opts.MaxEvents > 0 && len(segs) > 1 {
		total := 0
		counts := make([]int, len(segs))
		for i, sg := range segs {
			var n int
			if sg.Name == active {
				n = int(s.segmentEvents)
			} else {
				n, err = CountSegment(sg.Path)
				var open *OpenSegmentError
				if err != nil && !errors.As(err, &open) {
					return removed, err
				}
			}
			counts[i] = n
			total += n
		}
		for i := 0; i < len(segs) && total > s.opts.MaxEvents; i++ {
			select {
			case <-ctx.Done():
				return removed, ctx.Err()
			default:
			}
			if segs[i].Name == active {
				continue
			}
			if remove(segs[i].Name) {
				total -= counts[i]
			}
		}
	}
	return removed, nil
}

func parseSegmentStart(name string) (time.Time, bool) {
	encrypted, ok := segmentEncryption(name)
	if !ok {
		return time.Time{}, false
	}
	base := strings.TrimSuffix(strings.TrimPrefix(name, segmentPrefix), segmentExtension(encrypted))
	stampLen := len(time.Unix(0, 0).UTC().Format(timeFormat))
	if len(base) < stampLen {
		return time.Time{}, false
	}
	t, err := time.Parse(timeFormat, base[:stampLen])
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func openRegularSegment(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect segment %s: %v", errStore, filepath.Base(path), err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: read segment %s: not a regular file", errStore, filepath.Base(path))
	}
	// Path comes from evidence discovery or an explicit local operator argument.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("%w: read segment %s: %v", errStore, filepath.Base(path), err)
	}
	after, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: inspect opened segment %s: %v", errStore, filepath.Base(path), err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, fmt.Errorf("%w: evidence segment %s changed while opening", errStore, filepath.Base(path))
	}
	return f, nil
}

// CountSegment counts records without materializing or decrypting them.
// For encrypted segments it checks framing/completion, not ciphertext authenticity.
// An open v3 segment returns its checkpoint count and an OpenSegmentError.
func CountSegment(path string) (int, error) {
	encrypted := strings.HasSuffix(filepath.Base(path), encryptedSegmentExt)
	if encrypted {
		return countEncryptedFrames(path)
	}
	if !strings.HasSuffix(filepath.Base(path), segmentExt) {
		return 0, fmt.Errorf("%w: unsupported evidence segment %s", errStore, filepath.Base(path))
	}
	f, err := openRegularSegment(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	if magic, _ := reader.Peek(len(encryptedSegmentMagic)); bytes.Equal(magic, []byte(encryptedSegmentMagic)) ||
		bytes.Equal(magic, []byte(encryptedSegmentV2Magic)) {
		return 0, fmt.Errorf("%w: encrypted evidence has a plaintext filename %s", errStore, filepath.Base(path))
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), event.MaxStoredEnvelopeBytes+1)
	n := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("%w: read segment %s: %v", errStore, filepath.Base(path), err)
	}
	return n, nil
}

func forEachLine(path string, fn func(string) error) error {
	f, err := openRegularSegment(path)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	if magic, _ := reader.Peek(len(encryptedSegmentMagic)); bytes.Equal(magic, []byte(encryptedSegmentMagic)) ||
		bytes.Equal(magic, []byte(encryptedSegmentV2Magic)) {
		return fmt.Errorf("%w: encrypted evidence has a plaintext filename %s", errStore, filepath.Base(path))
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), event.MaxStoredEnvelopeBytes+1)
	for scanner.Scan() {
		if err := fn(scanner.Text()); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%w: read segment %s: %v", errStore, filepath.Base(path), err)
	}
	return nil
}

// ReaderOptions supplies local identities and an optional completeness requirement.
type ReaderOptions struct {
	IdentityFiles []string
	RequireSealed bool
}

// Reader iterates envelopes across all segments in a directory without
// creating anything (read-only inspection path).
type Reader struct {
	dir           string
	identities    identitySet
	requireSealed bool
}

// NewReader opens a read-only view over an evidence directory.
func NewReader(dir string) (*Reader, error) { return NewReaderWithOptions(dir, ReaderOptions{}) }

// NewReaderWithOptions opens a read-only view with explicit local read policy.
func NewReaderWithOptions(dir string, opts ReaderOptions) (*Reader, error) {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a readable evidence directory", errStore, dir)
	}
	identities, err := loadIdentitySet(opts.IdentityFiles)
	if err != nil {
		return nil, err
	}
	return &Reader{dir: dir, identities: identities, requireSealed: opts.RequireSealed}, nil
}

func (s *Store) Reader() *Reader { return &Reader{dir: s.opts.Dir} }

func (r *Reader) segments() ([]Segment, error) { return listSegments(r.dir) }

func (r *Reader) rejectIdentitySegmentAliases(segs []Segment) error {
	if len(r.identities.files) == 0 {
		return nil
	}
	for _, seg := range segs {
		f, err := openRegularSegment(seg.Path)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("%w: inspect segment %s: %v", errStore, seg.Name, err)
		}
		for _, identityInfo := range r.identities.files {
			if os.SameFile(identityInfo, info) {
				return fmt.Errorf("%w: identity file resolves to evidence segment %s", errStore, seg.Name)
			}
		}
	}
	return nil
}

// IsSegmentPath reports whether path currently resolves to an evidence segment
// owned by this reader. It follows aliases at the destination and detects hard links.
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
		f, err := openRegularSegment(seg.Path)
		if err != nil {
			return false, err
		}
		info, statErr := f.Stat()
		_ = f.Close()
		if statErr != nil {
			return false, fmt.Errorf("%w: inspect segment %s: %v", errStore, seg.Name, statErr)
		}
		if os.SameFile(target, info) {
			return true, nil
		}
	}
	return false, nil
}

// IsProtectedPath reports whether an output path aliases evidence or a supplied
// private identity file. It also remembers the exact identity paths so removal
// cannot turn a later export into an accidental key overwrite.
func (r *Reader) IsProtectedPath(path string) (bool, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("%w: resolve output path: %v", errStore, err)
	}
	clean := filepath.Clean(absolute)
	for _, identityPath := range r.identities.paths {
		if clean == identityPath {
			return true, nil
		}
	}
	if target, statErr := os.Stat(path); statErr == nil {
		for _, identityInfo := range r.identities.files {
			if os.SameFile(target, identityInfo) {
				return true, nil
			}
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("%w: inspect output path: %v", errStore, statErr)
	}
	return r.IsSegmentPath(path)
}

// ForEach calls fn for decoded envelopes in order. Malformed plaintext JSON
// is reported via onCorrupt and skipped. Encrypted JSON, framing, completion,
// I/O, authentication and identity failures stop the read. Callback results
// are provisional until the entire read succeeds. This legacy API requires seals;
// use ForEachVerified to accept prefixes with explicit incompleteness notices.
func (r *Reader) ForEach(fn func(event.Envelope) error, onCorrupt func(line string, err error)) error {
	_, err := r.forEach(fn, onCorrupt, true)
	return err
}

// ForEachVerified returns authenticated prefixes and explicit open-segment notices.
// RequireSealed makes any open segment terminal. Results remain provisional until
// the directory read succeeds; no frames beyond a verified checkpoint are emitted.
func (r *Reader) ForEachVerified(fn func(event.Envelope) error,
	onCorrupt func(line string, err error),
) ([]OpenSegmentError, error) {
	return r.forEach(fn, onCorrupt, r.requireSealed)
}

func (r *Reader) forEach(fn func(event.Envelope) error, onCorrupt func(string, error),
	requireSealed bool,
) ([]OpenSegmentError, error) {
	var notices []OpenSegmentError
	segs, err := r.segments()
	if err != nil {
		return nil, err
	}
	if err := r.rejectIdentitySegmentAliases(segs); err != nil {
		return nil, err
	}
	for i, segment := range segs {
		consume := func(raw []byte) error {
			if len(bytes.TrimSpace(raw)) == 0 {
				if segment.Encrypted {
					return fmt.Errorf("%w: encrypted segment %s contains an empty event", errStore, segment.Name)
				}
				return nil
			}
			var env event.Envelope
			if err := json.Unmarshal(raw, &env); err != nil {
				if segment.Encrypted {
					return fmt.Errorf("%w: encrypted segment %s contains malformed event JSON", errStore, segment.Name)
				}
				if onCorrupt != nil {
					onCorrupt(string(raw), err)
				}
				return nil
			}
			return fn(env)
		}
		if segment.Encrypted {
			if err := forEachEncryptedFrame(segment.Path, r.identities, consume); err != nil {
				var open *OpenSegmentError
				if !errors.As(err, &open) {
					return nil, err
				}
				open.Interrupted = i != len(segs)-1
				if requireSealed {
					return nil, open
				}
				notices = append(notices, *open)
			}
			continue
		}
		if err := forEachLine(segment.Path, func(line string) error { return consume([]byte(line)) }); err != nil {
			return nil, err
		}
	}
	return notices, nil
}
