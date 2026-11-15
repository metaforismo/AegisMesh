package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/metaforismo/aegismesh/internal/event"
)

type checkpointFixture struct {
	ids                   identitySet
	header, a, b, cp, cp2 []byte
	seal, v2seal          []byte
	encryptor             *segmentEncryptor
}

func newCheckpointFixture(t testing.TB) checkpointFixture {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := newSegmentEncryptor(&EncryptionOptions{Recipient: id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	frame := func(plain []byte) []byte {
		t.Helper()
		out, err := enc.frame(plain)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	a, b := frame([]byte(`{"n":1}`)), frame([]byte(`{"n":2}`))
	d1, d2 := sha256.Sum256(a), sha256.Sum256(joinRecords(a, b))
	control := func(marker uint32, plain []byte) []byte {
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, marker)
		return joinRecords(prefix, frame(plain))
	}
	return checkpointFixture{
		ids: identitySet{values: []age.Identity{id}}, header: []byte(encryptedSegmentMagic), a: a, b: b,
		cp:     control(checkpointMarker, completionPlaintext(checkpointKind, 1, d1[:])),
		cp2:    control(checkpointMarker, completionPlaintext(checkpointKind, 2, d2[:])),
		seal:   control(sealMarker, completionPlaintext(sealKind, 2, d2[:])),
		v2seal: control(0, completionPlaintext(sealKind, 2, d2[:])[2:]), encryptor: enc,
	}
}

func joinRecords(records ...[]byte) []byte { return bytes.Join(records, nil) }

func (f checkpointFixture) badControl(t *testing.T, kind byte, count uint64, digest []byte) []byte {
	t.Helper()
	frame, err := f.encryptor.frame(completionPlaintext(kind, count, digest))
	if err != nil {
		t.Fatal(err)
	}
	return joinRecords(make([]byte, 4), frame)
}

func TestCheckpointRecordSequences(t *testing.T) {
	f := newCheckpointFixture(t)
	d1 := sha256.Sum256(f.a)
	badDigest := append([]byte(nil), d1[:]...)
	badDigest[0] ^= 1
	flip := func(raw []byte) []byte {
		out := append([]byte(nil), raw...)
		out[len(out)-1] ^= 1
		return out
	}
	for _, tc := range []struct {
		name    string
		raw     []byte
		want    int
		open    bool
		failure bool
	}{
		{"sealed", joinRecords(f.header, f.a, f.cp, f.b, f.seal), 2, false, false},
		{"checkpoint only", joinRecords(f.header, f.a, f.cp), 1, true, false},
		{"trailing complete frame", joinRecords(f.header, f.a, f.cp, f.b), 1, true, false},
		{"trailing torn frame", joinRecords(f.header, f.a, f.cp, f.b[:len(f.b)-1]), 1, true, false},
		{"torn checkpoint", joinRecords(f.header, f.a, f.cp, f.b, f.cp2[:len(f.cp2)-1]), 1, true, false},
		{"two checkpoints", joinRecords(f.header, f.a, f.cp, f.b, f.cp2), 2, true, false},
		{"torn seal", joinRecords(f.header, f.a, f.cp, f.b, f.seal[:len(f.seal)-1]), 1, true, false},
		{"no checkpoint", joinRecords(f.header, f.a, f.b), 0, false, true},
		{"empty header", f.header, 0, false, true},
		{"digest mismatch", joinRecords(f.header, f.a, f.badControl(t, 1, 1, badDigest)), 0, false, true},
		{"count mismatch", joinRecords(f.header, f.a, f.badControl(t, 1, 2, d1[:])), 0, false, true},
		{"kind mismatch", joinRecords(f.header, f.a, f.badControl(t, 2, 1, d1[:])), 0, false, true},
		{"unknown kind", joinRecords(f.header, f.a, f.badControl(t, 3, 1, d1[:])), 0, false, true},
		{"corrupt before checkpoint", joinRecords(f.header, flip(f.a), f.cp), 0, false, true},
		{"corrupt complete tail", joinRecords(f.header, f.a, f.cp, flip(f.b)), 0, false, true},
		{"corrupt checkpoint", joinRecords(f.header, f.a, flip(f.cp)), 0, false, true},
		{"reordered frames", joinRecords(f.header, f.b, f.a, f.seal), 0, false, true},
		{"record after seal", joinRecords(f.header, f.a, f.b, f.seal, f.a), 0, false, true},
		{"duplicate seal", joinRecords(f.header, f.a, f.b, f.seal, f.seal), 0, false, true},
		{"v2 sealed", joinRecords([]byte(encryptedSegmentV2Magic), f.a, f.b, f.v2seal), 2, false, false},
		{"v2 unsealed", joinRecords([]byte(encryptedSegmentV2Magic), f.a), 0, false, true},
		{"unknown version", joinRecords([]byte("aegismesh.ageframes/v4\n"), f.a, f.cp), 0, false, true},
		{"invalid length", joinRecords(f.header, []byte{0x7f, 0xff, 0xff, 0xff}), 0, false, true},
		{"nested marker", joinRecords(f.header, make([]byte, 8)), 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := 0
			err := readEncryptedFrames(bytes.NewReader(tc.raw), int64(len(tc.raw)), "sequence.jsonl.age", f.ids,
				func([]byte) error { seen++; return nil })
			var open *OpenSegmentError
			isOpen := errors.As(err, &open)
			if seen != tc.want || isOpen != tc.open || (err != nil && !isOpen) != tc.failure {
				t.Fatalf("seen=%d want=%d open=%t want=%t err=%v", seen, tc.want, isOpen, tc.open, err)
			}
			if isOpen && int(open.VerifiedEvents) != seen {
				t.Fatalf("notice disagrees with callback count: %+v", open)
			}
			if tc.name == "v2 unsealed" && !strings.Contains(err.Error(), "v3 checkpoints") {
				t.Fatal("missing v2 recovery guidance")
			}
		})
	}
}

func TestCheckpointCrashEveryByte(t *testing.T) {
	f := newCheckpointFixture(t)
	raw := joinRecords(f.header, f.a, f.cp, f.b, f.cp2, f.seal)
	cpEnd := len(f.header) + len(f.a) + len(f.cp)
	cp2End := cpEnd + len(f.b) + len(f.cp2)
	for cut := 0; cut <= len(raw); cut++ {
		seen := 0
		err := readEncryptedFrames(bytes.NewReader(raw[:cut]), int64(cut), "crash.jsonl.age", f.ids,
			func([]byte) error { seen++; return nil })
		want := 0
		if cut >= cpEnd {
			want = 1
		}
		if cut >= cp2End {
			want = 2
		}
		var open *OpenSegmentError
		if seen != want || (cut < cpEnd && err == nil) ||
			(cut >= cpEnd && cut < len(raw) && !errors.As(err, &open)) || (cut == len(raw) && err != nil) {
			t.Fatalf("cut=%d seen=%d want=%d err=%v", cut, seen, want, err)
		}
		if open != nil && open.TrailingBytes != int64(cut)-map[int]int64{1: int64(cpEnd), 2: int64(cp2End)}[want] {
			t.Fatalf("cut=%d incorrect ignored bytes: %+v", cut, open)
		}
	}
	// A complete corrupted record is never treated as an ordinary crash tail.
	for _, start := range []int{len(f.header) + 4, cpEnd + 4, cp2End + 8} {
		changed := append([]byte(nil), raw...)
		changed[start] ^= 1
		err := readEncryptedFrames(bytes.NewReader(changed), int64(len(changed)), "corrupt.jsonl.age", f.ids,
			func([]byte) error { t.Fatal("corruption released events"); return nil })
		var open *OpenSegmentError
		if err == nil || errors.As(err, &open) {
			t.Fatalf("accepted corruption at %d: %v", start, err)
		}
	}
}

func TestCheckpointWriterFlushAndSpace(t *testing.T) {
	id, key := generateIdentityFile(t)
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := encryptedStore(t, dir, id, func(o *Options) {
		o.MaxFileBytes = 4096
		o.now = func() time.Time { return now }
	})
	defer s.Close()
	for i := 0; i < 12; i++ {
		if err := s.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{}`)); err != nil {
			t.Fatal(err)
		}
		if err := s.Flush(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, s.path)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 3; j++ {
			if err := s.Flush(); err != nil {
				t.Fatal(err)
			}
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("idle flush wrote checkpoint: %v", err)
		}
		now = now.Add(5 * time.Second)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	segments := mustSegments(t, dir)
	if len(segments) < 2 {
		t.Fatal("checkpoint bytes did not cause bounded rotation")
	}
	for _, segment := range segments {
		if segment.SizeBytes > 4096 {
			t.Fatalf("segment exceeds max_file_bytes: %+v", segment)
		}
		if _, err := CountSegment(segment.Path); err != nil {
			t.Fatalf("rotation/close did not seal: %v", err)
		}
	}
	r, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{key}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := r.ForEach(func(event.Envelope) error { seen++; return nil }, nil); err != nil || seen != 12 {
		t.Fatalf("lost events on checkpoint rotation: seen=%d err=%v", seen, err)
	}
}

func TestCheckpointRestartMixedDirectoryAndRetention(t *testing.T) {
	id, key := generateIdentityFile(t)
	dir := t.TempDir()
	env := mkEnv(t, &event.Sequencer{}, `{}`)
	plain, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Append(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	enc, err := newSegmentEncryptor(&EncryptionOptions{Recipient: id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	// Reuse actual JSON from the plaintext segment in a historical v2 container.
	plainRaw, err := os.ReadFile(filepath.Join(dir, plain.path))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := enc.frame(bytes.TrimSpace(plainRaw))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(frame)
	footer, err := enc.frame(completionPlaintext(sealKind, 1, digest[:])[2:])
	if err != nil {
		t.Fatal(err)
	}
	v2 := filepath.Join(dir, "events-v2.jsonl.age")
	v2raw := joinRecords([]byte(encryptedSegmentV2Magic), frame, make([]byte, 4), footer)
	if err := os.WriteFile(v2, v2raw, 0o600); err != nil {
		t.Fatal(err)
	}
	first := encryptedStore(t, dir, id, nil)
	if err := first.Append(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := first.Flush(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, first.path)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate abrupt process loss: close the descriptor without a seal.
	if err := first.f.Close(); err != nil {
		t.Fatal(err)
	}
	second := encryptedStore(t, dir, id, func(o *Options) { o.MaxEvents = 1 })
	defer second.Close()
	if err := second.Append(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := second.Flush(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) || first.path == second.path {
		t.Fatalf("restart changed prior segment: %v", err)
	}
	// Make discovery order deterministic, including the interrupted predecessor.
	paths := []string{filepath.Join(dir, plain.path), v2, path, filepath.Join(dir, second.path)}
	for i, p := range paths {
		stamp := time.Unix(int64(i+1), 0)
		if err := os.Chtimes(p, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{key}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	notices, err := r.ForEachVerified(func(event.Envelope) error { seen++; return nil }, nil)
	if err != nil || seen != 4 || len(notices) != 2 || !notices[0].Interrupted || notices[1].Interrupted {
		t.Fatalf("mixed read: seen=%d notices=%+v err=%v", seen, notices, err)
	}
	strict, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{key}, RequireSealed: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.ForEachVerified(func(event.Envelope) error { return nil }, nil); err == nil {
		t.Fatal("require sealed accepted interrupted history")
	}
	removed, err := second.ApplyRetention(context.Background())
	if err != nil || len(removed) != 3 {
		t.Fatalf("structural retention: removed=%v err=%v", removed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, second.path)); err != nil {
		t.Fatalf("active segment deleted: %v", err)
	}
}

func TestCheckpointOverhead(t *testing.T) {
	f := newCheckpointFixture(t)
	if len(f.cp) != 250 || len(f.seal) != 250 {
		t.Fatalf("checkpoint=%d seal=%d bytes; update documented overhead", len(f.cp), len(f.seal))
	}
	t.Logf("native X25519 checkpoint/seal: %d bytes (42 plaintext + 200 age + 8 framing)", len(f.cp))
	r := bufio.NewReader(bytes.NewReader(joinRecords(f.header, f.a, f.cp)))
	if n, err := countEncryptedFramesReader(r, "test"); n != 1 || err == nil {
		t.Fatalf("open structural count=%d err=%v", n, err)
	}
}

type changingSnapshot struct {
	first, second []byte
	starts        int
}

func (s *changingSnapshot) ReadAt(p []byte, off int64) (int, error) {
	if off == 0 {
		s.starts++
	}
	raw := s.first
	if s.starts > 1 {
		raw = s.second
	}
	return bytes.NewReader(raw).ReadAt(p, off)
}

func TestCheckpointSnapshotChangesFailClosed(t *testing.T) {
	f := newCheckpointFixture(t)
	prefix := joinRecords(f.header, f.a, f.cp)
	for _, first := range [][]byte{
		joinRecords(prefix, f.b, f.seal),
		joinRecords(prefix, f.b, f.cp2),
	} {
		src := &changingSnapshot{first: first, second: prefix}
		err := readEncryptedFrames(src, int64(len(first)), "changing.jsonl.age", f.ids, func([]byte) error { return nil })
		var open *OpenSegmentError
		if err == nil || errors.As(err, &open) {
			t.Fatalf("concurrent truncation accepted as a live prefix: %v", err)
		}
	}
	// A later seal outside the captured size must not turn the snapshot complete.
	full := joinRecords(prefix, f.b, f.seal)
	seen := 0
	err := readEncryptedFrames(bytes.NewReader(full), int64(len(prefix)), "live.jsonl.age", f.ids,
		func([]byte) error { seen++; return nil })
	var open *OpenSegmentError
	if !errors.As(err, &open) || seen != 1 || open.TrailingBytes != 0 {
		t.Fatalf("read exceeded snapshot size: seen=%d err=%v", seen, err)
	}
}

func TestCheckpointPlaintextWireContract(t *testing.T) {
	// A literal wire vector guards against writer and reader agreeing on the
	// same accidental layout change. SHA-256 here is the standard empty digest.
	digest := sha256.Sum256(nil)
	got := completionPlaintext(checkpointKind, 0x0102030405060708, digest[:])
	want := "03010102030405060708" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hex.EncodeToString(got) != want {
		t.Fatalf("completion wire layout changed: %x", got)
	}
}
