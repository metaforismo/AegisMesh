package storage

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/metaforismo/aegismesh/internal/agekey"
	"github.com/metaforismo/aegismesh/internal/event"
)

func generateIdentityFile(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return identity, path
}

func encryptedStore(t *testing.T, dir string, identity *age.X25519Identity, mutate func(*Options)) *Store {
	t.Helper()
	opts := Options{
		Dir:           dir,
		MaxFileBytes:  1 << 20,
		MaxEventBytes: 256 << 10,
		Encryption:    &EncryptionOptions{Recipient: identity.Recipient().String()},
	}
	if mutate != nil {
		mutate(&opts)
	}
	store, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestEncryptedAppendAndReadBack(t *testing.T) {
	identity, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, nil)
	marker := "secret-marker-must-not-appear"
	envelope := mkEnv(t, &event.Sequencer{}, `{"marker":"`+marker+`"}`)
	if err := store.Append(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	segments, err := store.Segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 1 || !segments[0].Encrypted || !strings.HasSuffix(segments[0].Name, encryptedSegmentExt) {
		t.Fatalf("unexpected segments: %+v", segments)
	}
	raw, err := os.ReadFile(segments[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte(encryptedSegmentMagic)) {
		t.Fatal("missing encrypted segment framing header")
	}
	if bytes.Contains(raw, []byte(marker)) || bytes.Contains(raw, []byte(`"schema":"aegismesh.event/v1"`)) {
		t.Fatal("encrypted segment leaked plaintext evidence")
	}
	info, err := os.Stat(segments[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("encrypted segment permissions = %v", info.Mode().Perm())
	}

	withoutIdentity, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := withoutIdentity.ForEach(func(event.Envelope) error { return nil }, nil); err == nil || !strings.Contains(err.Error(), "requires at least one identity") {
		t.Fatalf("encrypted read without identity = %v", err)
	}

	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := reader.ForEach(func(got event.Envelope) error {
		seen++
		if got.ID != envelope.ID {
			t.Fatalf("event ID = %s, want %s", got.ID, envelope.ID)
		}
		return got.VerifyIntegrity()
	}, func(string, error) { t.Fatal("authenticated frame contained malformed JSON") }); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("read %d events", seen)
	}
}

func TestEncryptionDisabledPreservesPlaintextRecord(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, Options{Dir: dir, MaxFileBytes: 1 << 20})
	envelope := mkEnv(t, &event.Sequencer{}, `{"mode":"plaintext"}`)
	if err := store.Append(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	segments, err := listSegments(dir)
	if err != nil || len(segments) != 1 || segments[0].Encrypted {
		t.Fatalf("segments=%+v err=%v", segments, err)
	}
	want, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	got, err := os.ReadFile(segments[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("plaintext record changed:\n got %q\nwant %q", got, want)
	}
}

func TestEncryptedWrongIdentityFailsBeforeCallback(t *testing.T) {
	writerIdentity, _ := generateIdentityFile(t)
	_, wrongIdentityPath := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, writerIdentity, nil)
	if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{wrongIdentityPath}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	err = reader.ForEach(func(event.Envelope) error { seen++; return nil }, nil)
	if err == nil || !strings.Contains(err.Error(), "did not match any supplied identity") || seen != 0 {
		t.Fatalf("seen=%d err=%v", seen, err)
	}
}

func TestEncryptedCorruptionAndTruncationFailClosed(t *testing.T) {
	identity, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, nil)
	if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	segments, err := listSegments(dir)
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments=%v err=%v", segments, err)
	}
	original, err := os.ReadFile(segments[0].Path)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "ciphertext bit flip",
			mutate: func(raw []byte) []byte {
				out := append([]byte(nil), raw...)
				end := len(encryptedSegmentMagic) + frameLengthBytes + int(binary.BigEndian.Uint32(out[len(encryptedSegmentMagic):]))
				out[end-1] ^= 0x01
				return out
			},
		},
		{
			name: "truncated ciphertext",
			mutate: func(raw []byte) []byte {
				end := len(encryptedSegmentMagic) + frameLengthBytes + int(binary.BigEndian.Uint32(raw[len(encryptedSegmentMagic):]))
				return append([]byte(nil), raw[:end-1]...)
			},
		},
		{
			name: "truncated prefix",
			mutate: func(raw []byte) []byte {
				return append([]byte(nil), raw[:len(encryptedSegmentMagic)+2]...)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(segments[0].Path, tc.mutate(original), 0o600); err != nil {
				t.Fatal(err)
			}
			reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
			if err != nil {
				t.Fatal(err)
			}
			seen := 0
			err = reader.ForEach(func(event.Envelope) error { seen++; return nil }, nil)
			if err == nil || seen != 0 {
				t.Fatalf("corrupt segment was accepted: seen=%d err=%v", seen, err)
			}
			if err := os.WriteFile(segments[0].Path, original, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEncryptedRestartCreatesIndependentSegments(t *testing.T) {
	identity, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		store := encryptedStore(t, dir, identity, nil)
		if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"restart":true}`)); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	segments, err := listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 2 {
		t.Fatalf("restart produced %d segments, want 2", len(segments))
	}
	for _, segment := range segments {
		count, err := CountSegment(segment.Path)
		if err != nil || count != 1 {
			t.Fatalf("segment %s count=%d err=%v", segment.Name, count, err)
		}
	}
	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := reader.ForEach(func(event.Envelope) error { seen++; return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if seen != 2 {
		t.Fatalf("read %d events after restart", seen)
	}
}

func TestEncryptedKeyRotationReadsSegmentsWithRepeatedIdentities(t *testing.T) {
	firstIdentity, firstPath := generateIdentityFile(t)
	secondIdentity, secondPath := generateIdentityFile(t)
	dir := t.TempDir()

	first := encryptedStore(t, dir, firstIdentity, nil)
	if err := first.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"key":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := encryptedStore(t, dir, secondIdentity, nil)
	if err := second.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"key":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{firstPath, secondPath}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := reader.ForEach(func(event.Envelope) error { seen++; return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if seen != 2 {
		t.Fatalf("read %d rotated-key events", seen)
	}
}

func TestEncryptedUncheckpointedTruncationEmitsNothing(t *testing.T) {
	identity, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, nil)
	seq := &event.Sequencer{}
	if err := store.Append(context.Background(), mkEnv(t, seq, `{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(context.Background(), mkEnv(t, seq, `{"n":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	segments, err := listSegments(dir)
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments=%+v err=%v", segments, err)
	}
	raw, err := os.ReadFile(segments[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	end := len(encryptedSegmentMagic)
	for i := 0; i < 2; i++ {
		end += frameLengthBytes + int(binary.BigEndian.Uint32(raw[end:]))
	}
	if err := os.WriteFile(segments[0].Path, raw[:end-1], 0o600); err != nil {
		t.Fatal(err)
	}

	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	err = reader.ForEach(func(event.Envelope) error { seen++; return nil }, nil)
	if err == nil || seen != 0 {
		t.Fatalf("seen=%d err=%v", seen, err)
	}
}

func TestEncryptedRotationAndCountRetention(t *testing.T) {
	identity, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, func(options *Options) {
		options.MaxFileBytes = 4096
		options.MaxEvents = 2
	})
	pad := `{"pad":"` + strings.Repeat("x", 1800) + `"}`
	for i := 0; i < 4; i++ {
		if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, pad)); err != nil {
			t.Fatal(err)
		}
	}
	segments, err := store.Segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) < 2 {
		t.Fatalf("expected rotation, got %d segment(s)", len(segments))
	}
	removed, err := store.ApplyRetention(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) == 0 {
		t.Fatal("retention removed no closed segment")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := reader.ForEach(func(event.Envelope) error { seen++; return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if seen > 2 {
		t.Fatalf("retention left %d events", seen)
	}
}

func TestMixedPlaintextAndEncryptedHistory(t *testing.T) {
	identity, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	plain, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"mode":"plain"}`)); err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	encrypted := encryptedStore(t, dir, identity, nil)
	if err := encrypted.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"mode":"encrypted"}`)); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := reader.ForEach(func(event.Envelope) error { seen++; return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if seen != 2 {
		t.Fatalf("mixed history yielded %d events", seen)
	}

	withoutIdentity, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen = 0
	err = withoutIdentity.ForEach(func(event.Envelope) error { seen++; return nil }, nil)
	if err == nil || seen != 1 {
		t.Fatalf("mixed read without identity: seen=%d err=%v", seen, err)
	}
}

func TestEncryptedSegmentRenamedAsPlaintextFailsClosed(t *testing.T) {
	identity, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, nil)
	if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	segments, err := listSegments(dir)
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments=%+v err=%v", segments, err)
	}
	renamed := strings.TrimSuffix(segments[0].Path, ".age")
	if err := os.Rename(segments[0].Path, renamed); err != nil {
		t.Fatal(err)
	}

	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.ForEach(func(event.Envelope) error { return nil }, nil); err == nil || !strings.Contains(err.Error(), "plaintext filename") {
		t.Fatalf("renamed encrypted segment error = %v", err)
	}
	if _, err := CountSegment(renamed); err == nil || !strings.Contains(err.Error(), "plaintext filename") {
		t.Fatalf("renamed encrypted segment count error = %v", err)
	}
}

func TestAgeRetentionNeverDeletesActiveSegment(t *testing.T) {
	current := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	store, err := New(Options{
		Dir:          t.TempDir(),
		MaxAgeDays:   1,
		MaxFileBytes: 1 << 20,
		now:          func() time.Time { return current },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{}`)); err != nil {
		t.Fatal(err)
	}
	active := store.path
	current = current.AddDate(0, 0, 2)
	removed, err := store.ApplyRetention(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("active segment was removed: %v", removed)
	}
	if _, err := os.Stat(filepath.Join(store.opts.Dir, active)); err != nil {
		t.Fatalf("active segment missing: %v", err)
	}
}

func TestIdentityAliasesAreProtectedAndDuplicatesRejected(t *testing.T) {
	_, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	hardlink := filepath.Join(dir, "identity-hardlink")
	if err := os.Link(identityPath, hardlink); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath, hardlink}}); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("identity alias was not rejected: %v", err)
	}

	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
	if err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "identity-symlink")
	if err := os.Symlink(identityPath, symlink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, path := range []string{identityPath, hardlink, symlink} {
		protected, err := reader.IsProtectedPath(path)
		if err != nil || !protected {
			t.Fatalf("path %s protected=%v err=%v", path, protected, err)
		}
	}
	if err := os.Remove(identityPath); err != nil {
		t.Fatal(err)
	}
	protected, err := reader.IsProtectedPath(identityPath)
	if err != nil || !protected {
		t.Fatalf("removed supplied identity path protected=%v err=%v", protected, err)
	}
}

func TestSegmentReadersRejectSymlinkEntries(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.jsonl")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	segmentPath := filepath.Join(dir, "events-20260101T000000.000000000Z.jsonl")
	if err := os.Symlink(target, segmentPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := listSegments(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("segment listing followed a symlink: %v", err)
	}
	if _, err := CountSegment(segmentPath); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("segment counter followed a symlink: %v", err)
	}
	reader, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.ForEach(func(event.Envelope) error { return nil }, nil); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("reader followed a symlink: %v", err)
	}
}

func TestIdentityHardLinkCannotBeReadAsEvidence(t *testing.T) {
	_, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	segmentPath := filepath.Join(dir, "events-20260101T000000.000000000Z.jsonl")
	if err := os.Link(identityPath, segmentPath); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	err = reader.ForEach(func(event.Envelope) error {
		called = true
		return nil
	}, func(string, error) {
		called = true
	})
	if err == nil || !strings.Contains(err.Error(), "identity file resolves to evidence segment") || called {
		t.Fatalf("identity alias was exposed as evidence: called=%v err=%v", called, err)
	}
}

func TestEncryptedErrorsDoNotEchoCiphertext(t *testing.T) {
	_, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	const marker = "attacker-controlled-error-marker"
	payload := []byte("not-an-age-file:" + marker)
	var segment bytes.Buffer
	segment.WriteString(encryptedSegmentMagic)
	var length [frameLengthBytes]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	segment.Write(length[:])
	segment.Write(payload)
	path := filepath.Join(dir, "events-20260101T000000.000000000Z.jsonl.age")
	if err := os.WriteFile(path, segment.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
	if err != nil {
		t.Fatal(err)
	}
	err = reader.ForEach(func(event.Envelope) error { return nil }, nil)
	if err == nil || !strings.Contains(err.Error(), "header authentication failed") {
		t.Fatalf("malformed ciphertext error = %v", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error reflected attacker-controlled ciphertext: %v", err)
	}
}

func TestEncryptedReaderPropagatesCallbackStopAfterAuthentication(t *testing.T) {
	identity, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, nil)
	if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop")
	if err := reader.ForEach(func(event.Envelope) error { return stop }, nil); !errors.Is(err, stop) {
		t.Fatalf("callback error = %v", err)
	}
}

func TestEncryptionGuardPreventsSilentPlaintextDowngrade(t *testing.T) {
	identity, _ := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, nil)
	if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	guard := filepath.Join(dir, encryptionGuardName)
	info, err := os.Stat(guard)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("guard permissions = %v", info.Mode().Perm())
	}

	if _, err := New(Options{Dir: dir, MaxFileBytes: 1 << 20}); err == nil || !strings.Contains(err.Error(), "refusing plaintext") {
		t.Fatalf("plaintext reopen after encryption = %v", err)
	}
	if _, err := New(Options{
		Dir:          dir,
		MaxFileBytes: 1 << 20,
		Encryption:   &EncryptionOptions{Recipient: identity.Recipient().String()},
	}); err != nil {
		t.Fatalf("encrypted reopen with guard: %v", err)
	}
}

func TestEncryptedHistoryWithoutGuardStillPreventsPlaintextWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events-20260101T000000.000000000Z.jsonl.age")
	if err := os.WriteFile(path, []byte(encryptedSegmentMagic), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Dir: dir, MaxFileBytes: 1 << 20}); err == nil || !strings.Contains(err.Error(), "encrypted evidence exists") {
		t.Fatalf("plaintext store accepted encrypted history: %v", err)
	}
}

func TestEncryptionGuardRejectsUnsafeReplacement(t *testing.T) {
	identity, _ := generateIdentityFile(t)
	dir := t.TempDir()
	guard := filepath.Join(dir, encryptionGuardName)
	target := filepath.Join(t.TempDir(), "guard")
	if err := os.WriteFile(target, []byte(encryptionGuardContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, guard); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := New(Options{
		Dir:          dir,
		MaxFileBytes: 1 << 20,
		Encryption:   &EncryptionOptions{Recipient: identity.Recipient().String()},
	})
	if err == nil || !strings.Contains(err.Error(), "owner-only regular file") {
		t.Fatalf("unsafe encryption guard accepted: %v", err)
	}
}

func FuzzEncryptedFrameStructure(f *testing.F) {
	fixture := newCheckpointFixture(f)
	seeds := [][]byte{
		fixture.header,
		joinRecords(fixture.header, fixture.a),
		joinRecords(fixture.header, fixture.a, fixture.cp),
		joinRecords(fixture.header, fixture.a, fixture.cp, fixture.b),
		joinRecords(fixture.header, fixture.a, fixture.cp, fixture.b[:len(fixture.b)-1]),
		joinRecords(fixture.header, fixture.a, fixture.cp, fixture.b, fixture.seal),
		joinRecords(fixture.header, fixture.a, fixture.b, fixture.seal, fixture.seal),
		joinRecords(fixture.header, fixture.b, fixture.a, fixture.seal),
		joinRecords([]byte(encryptedSegmentV2Magic), fixture.a, fixture.b, fixture.v2seal),
		joinRecords([]byte(encryptedSegmentV2Magic), fixture.a),
		joinRecords(fixture.header, make([]byte, 8)),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2*agekey.MaxEncryptedFrameBytes {
			return
		}
		_, _ = countEncryptedFramesReader(bufio.NewReader(bytes.NewReader(raw)), "fuzz.jsonl.age")
		seen := 0
		err := readEncryptedFrames(bytes.NewReader(raw), int64(len(raw)), "fuzz.jsonl.age", fixture.ids,
			func([]byte) error { seen++; return nil })
		var open *OpenSegmentError
		if errors.As(err, &open) {
			if uint64(seen) != open.VerifiedEvents {
				t.Fatalf("uncheckpointed events emitted: seen=%d status=%+v", seen, open)
			}
		} else if err != nil && seen != 0 {
			t.Fatalf("corruption emitted %d events: %v", seen, err)
		}
	})
}

func TestEncryptedFrameBoundaryTruncationFailsClosed(t *testing.T) {
	identity, identityPath := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, nil)
	for i := 0; i < 2; i++ {
		if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"n":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	segs, err := listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(segs[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	end := len(encryptedSegmentMagic)
	boundaries := []int{end}
	for end+frameLengthBytes <= len(raw) {
		n := int(binary.BigEndian.Uint32(raw[end : end+frameLengthBytes]))
		end += frameLengthBytes + n
		if end < len(raw) {
			boundaries = append(boundaries, end)
		}
	}
	for _, end := range boundaries {
		if err := os.WriteFile(segs[0].Path, raw[:end], 0o600); err != nil {
			t.Fatal(err)
		}
		reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{identityPath}})
		if err != nil {
			t.Fatal(err)
		}
		if err := reader.ForEach(func(event.Envelope) error { return nil }, nil); err == nil {
			t.Errorf("accepted segment truncated at byte %d", end)
		}
	}
}

func TestEncryptedFlushKeepsSegmentUntilAgeBound(t *testing.T) {
	identity, key := generateIdentityFile(t)
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := encryptedStore(t, dir, identity, func(opts *Options) {
		opts.now = func() time.Time { return now }
	})
	defer store.Close()
	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{key}})
	if err != nil {
		t.Fatal(err)
	}
	const flushes = 60 // The runtime's five-second cadence, all within five minutes.
	for i := 0; i < flushes; i++ {
		if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"marker":"never-plaintext"}`)); err != nil {
			t.Fatal(err)
		}
		if err := store.Flush(); err != nil {
			t.Fatal(err)
		}
		segments := mustSegments(t, dir)
		if len(segments) != 1 {
			t.Fatalf("flush %d: got %d segments", i, len(segments))
		}
		raw, err := os.ReadFile(segments[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(raw)) != store.size || len(raw) <= len(encryptedSegmentMagic) {
			t.Fatalf("flush %d did not publish buffered frames", i)
		}
		if !segments[0].Encrypted || bytes.Contains(raw, []byte("never-plaintext")) {
			t.Fatal("plaintext write")
		}
		if store.sealed {
			t.Fatalf("flush %d sealed before the age bound", i)
		}
		now = now.Add(5 * time.Second)
	}
	if err := reader.ForEach(func(event.Envelope) error { return nil }, nil); err == nil || !strings.Contains(err.Error(), "not sealed") {
		t.Fatalf("active segment read: %v", err)
	}
	if n, err := CountSegment(filepath.Join(dir, store.path)); n != flushes || err == nil {
		t.Fatalf("active segment count: n=%d err=%v", n, err)
	}
	live := 0
	notices, err := reader.ForEachVerified(func(event.Envelope) error { live++; return nil }, nil)
	if err != nil || live != flushes || len(notices) != 1 || notices[0].VerifiedEvents != flushes {
		t.Fatalf("live read: seen=%d notices=%+v err=%v", live, notices, err)
	}

	// At exactly five minutes seal once, without eagerly opening an empty successor.
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, store.path)
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		now = now.Add(maxEncryptedSegmentAge)
		if err := store.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	again, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(sealed, again) || len(mustSegments(t, dir)) != 1 {
		t.Fatalf("repeated aged flush changed sealed segment: %v", err)
	}
	seen := 0
	if err := reader.ForEach(func(e event.Envelope) error { seen++; return e.VerifyIntegrity() }, nil); err != nil || seen != flushes {
		t.Fatalf("sealed read: seen=%d err=%v", seen, err)
	}
	if count, err := CountSegment(path); err != nil || count != flushes {
		t.Fatalf("sealed count=%d err=%v", count, err)
	}

	// The next event creates one new stream with its own age window.
	if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(mustSegments(t, dir)) != 2 || store.sealed {
		t.Fatal("successor missing or inherited predecessor's age")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	seen = 0
	if err := reader.ForEach(func(e event.Envelope) error { seen++; return e.VerifyIntegrity() }, nil); err != nil || seen != flushes+1 {
		t.Fatalf("close read: seen=%d err=%v", seen, err)
	}
}

func TestEncryptedIdleFlushDoesNotSealOrCreateFiles(t *testing.T) {
	identity, _ := generateIdentityFile(t)
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := encryptedStore(t, dir, identity, func(opts *Options) {
		opts.now = func() time.Time { return now }
	})
	defer store.Close()
	original, err := os.ReadFile(filepath.Join(dir, store.path))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		now = now.Add(maxEncryptedSegmentAge)
		if err := store.Flush(); err != nil {
			t.Fatal(err)
		}
		segments := mustSegments(t, dir)
		if len(segments) != 1 || store.sealed {
			t.Fatal("idle flush sealed or rotated an empty segment")
		}
		raw, err := os.ReadFile(segments[0].Path)
		if err != nil || !bytes.Equal(original, raw) {
			t.Fatalf("idle flush changed file: %v", err)
		}
	}
	// A long idle period must not consume the first event's read-delay window.
	if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(mustSegments(t, dir)) != 1 || store.sealed {
		t.Fatal("first event after idle sealed prematurely")
	}
}

func TestEncryptedOversizeFrameDoesNotForceRotation(t *testing.T) {
	identity, key := generateIdentityFile(t)
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := encryptedStore(t, dir, identity, func(opts *Options) {
		opts.MaxFileBytes = 4096
		opts.now = func() time.Time { return now }
	})
	defer store.Close()
	if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{}`)); err != nil {
		t.Fatal(err)
	}
	path := store.path
	tooLarge := mkEnv(t, &event.Sequencer{}, `{"pad":"`+strings.Repeat("x", 5000)+`"}`)
	for _, sealed := range []bool{false, true} {
		if sealed {
			now = now.Add(maxEncryptedSegmentAge)
			if err := store.Flush(); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 10; i++ {
			if err := store.Append(context.Background(), tooLarge); err == nil || !strings.Contains(err.Error(), "exceeds segment size") {
				t.Fatalf("oversize append: %v", err)
			}
			if len(mustSegments(t, dir)) != 1 || store.path != path || store.sealed != sealed || store.segmentEvents != 1 {
				t.Fatal("rejected event changed segment lifecycle")
			}
		}
	}
	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{key}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := reader.ForEach(func(e event.Envelope) error { seen++; return e.VerifyIntegrity() }, nil); err != nil || seen != 1 {
		t.Fatalf("original segment: seen=%d err=%v", seen, err)
	}
}

func TestPlaintextFlushIgnoresEncryptedAgeBound(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store, err := New(Options{Dir: dir, now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var expected []byte
	for i := 0; i < 3; i++ {
		env := mkEnv(t, &event.Sequencer{}, `{}`)
		record, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, record...)
		expected = append(expected, '\n')
		if err := store.Append(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * maxEncryptedSegmentAge)
		if err := store.Flush(); err != nil {
			t.Fatal(err)
		}
		segments := mustSegments(t, dir)
		if len(segments) != 1 || segments[0].Encrypted || store.sealed {
			t.Fatal("encrypted lifecycle affected plaintext store")
		}
		raw, err := os.ReadFile(segments[0].Path)
		if err != nil || !bytes.Equal(raw, expected) {
			t.Fatalf("plaintext bytes changed: %v", err)
		}
	}
}

func TestEncryptedRestartAfterInterruptedWriteAndWriteFailure(t *testing.T) {
	identity, key := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, nil)
	env := mkEnv(t, &event.Sequencer{}, `{"marker":"never-plaintext"}`)
	if err := store.Append(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	segments, err := listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(segments[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segments[0].Path, raw[:len(raw)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := encryptedStore(t, dir, identity, nil)
	if err := restarted.Append(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	// A real closed-file failure exercises the buffered writer's sticky error path.
	if err := restarted.f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Flush(); err == nil {
		t.Fatal("flush accepted a failed underlying file")
	}
	if err := restarted.Append(context.Background(), env); err == nil {
		t.Fatal("append accepted a failed writer")
	}
	_ = restarted.Close()
	for _, seg := range mustSegments(t, dir) {
		data, err := os.ReadFile(seg.Path)
		if err != nil {
			t.Fatal(err)
		}
		if !seg.Encrypted || bytes.Contains(data, []byte("never-plaintext")) {
			t.Fatal("plaintext fallback after failure")
		}
	}
	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{key}})
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.ForEach(func(event.Envelope) error { return nil }, nil); err == nil {
		t.Fatal("damaged history accepted after restart")
	}
}

func mustSegments(t *testing.T, dir string) []Segment {
	t.Helper()
	segments, err := listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	return segments
}

func TestEncryptedFooterRejectsReorderedEvents(t *testing.T) {
	identity, key := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, nil)
	for i := 0; i < 2; i++ {
		if err := store.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"n":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	path := mustSegments(t, dir)[0].Path
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a := len(encryptedSegmentMagic)
	b := a + 4 + int(binary.BigEndian.Uint32(raw[a:]))
	c := b + 4 + int(binary.BigEndian.Uint32(raw[b:]))
	changed := append([]byte(nil), raw[:a]...)
	changed = append(changed, raw[b:c]...)
	changed = append(changed, raw[a:b]...)
	changed = append(changed, raw[c:]...)
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{key}})
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.ForEach(func(event.Envelope) error { return nil }, nil); err == nil || !strings.Contains(err.Error(), "count and order") {
		t.Fatalf("reordered events: %v", err)
	}
}

func TestEncryptedConcurrentAppendFlushAndRetention(t *testing.T) {
	identity, key := generateIdentityFile(t)
	dir := t.TempDir()
	store := encryptedStore(t, dir, identity, func(opts *Options) { opts.MaxEvents = 1000 })
	defer store.Close()
	envelope := mkEnv(t, &event.Sequencer{}, `{"marker":"concurrent-secret"}`)
	var wg sync.WaitGroup
	failures := make(chan error, 100)
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := store.Append(context.Background(), envelope); err != nil {
					failures <- err
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if err := store.Flush(); err != nil {
				failures <- err
				return
			}
			if _, err := store.ApplyRetention(context.Background()); err != nil {
				failures <- err
				return
			}
		}
	}()
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{key}})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := reader.ForEach(func(event.Envelope) error { seen++; return nil }, nil); err != nil || seen != 80 {
		t.Fatalf("seen=%d err=%v", seen, err)
	}
}

func TestEncryptedMalformedAuthenticatedRecordFailsClosed(t *testing.T) {
	for _, plaintext := range []string{" ", "{"} {
		t.Run(plaintext, func(t *testing.T) {
			identity, key := generateIdentityFile(t)
			dir := t.TempDir()
			store := encryptedStore(t, dir, identity, nil)
			frame, err := store.encryptor.frame([]byte(plaintext))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.w.Write(frame); err != nil {
				t.Fatal(err)
			}
			_, _ = store.digest.Write(frame)
			store.segmentEvents = 1
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{key}})
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.ForEach(func(event.Envelope) error { t.Fatal("invalid record emitted"); return nil }, func(string, error) { t.Fatal("invalid encrypted record skipped") }); err == nil {
				t.Fatal("malformed encrypted event accepted")
			}
		})
	}
}

func TestMixedHistoryOrderingCountingAndRetention(t *testing.T) {
	identity, key := generateIdentityFile(t)
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	plain, err := New(Options{Dir: dir, now: clock})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := plain.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"mode":"plain"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	plainPath := filepath.Join(dir, plain.path)
	original, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatal(err)
	}
	now = now.AddDate(0, 0, 1)
	encrypted := encryptedStore(t, dir, identity, func(opts *Options) { opts.now = clock })
	for i := 0; i < 2; i++ {
		if err := encrypted.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"mode":"encrypted"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	now = now.AddDate(0, 0, 1)
	active := encryptedStore(t, dir, identity, func(opts *Options) { opts.now = clock; opts.MaxEvents = 3; opts.MaxAgeDays = 1 })
	defer active.Close()
	if err := active.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{"mode":"active"}`)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(maxEncryptedSegmentAge)
	if err := active.Flush(); err != nil {
		t.Fatal(err)
	}
	// Set deterministic filesystem ordering independently of current wall time.
	for _, seg := range mustSegments(t, dir) {
		start, ok := parseSegmentStart(seg.Name)
		if !ok {
			t.Fatal("unparseable segment name")
		}
		if err := os.Chtimes(seg.Path, start, start); err != nil {
			t.Fatal(err)
		}
	}
	segments := mustSegments(t, dir)
	if len(segments) != 3 || segments[0].Encrypted || !segments[1].Encrypted || segments[2].Name != active.path {
		t.Fatalf("mixed ordering: %+v", segments)
	}
	for i, want := range []int{2, 2, 1} {
		count, err := CountSegment(segments[i].Path)
		if err != nil || count != want {
			t.Fatalf("count=%d want=%d err=%v", count, want, err)
		}
	}
	unchanged, err := os.ReadFile(plainPath)
	if err != nil || !bytes.Equal(original, unchanged) {
		t.Fatal("enabling encryption rewrote plaintext history")
	}
	// Disable age for the count pass; only the oldest plaintext segment is excess.
	active.opts.MaxAgeDays = 0
	removed, err := active.ApplyRetention(context.Background())
	if err != nil || len(removed) != 1 || removed[0] != plain.path {
		t.Fatalf("count retention removed=%v err=%v", removed, err)
	}
	reader, err := NewReaderWithOptions(dir, ReaderOptions{IdentityFiles: []string{key}})
	if err != nil {
		t.Fatal(err)
	}
	var modes []string
	if err := reader.ForEach(func(e event.Envelope) error {
		var obj struct{ Mode string }
		if err := json.Unmarshal(e.Observation, &obj); err != nil {
			return err
		}
		modes = append(modes, obj.Mode)
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(modes, ",") != "encrypted,encrypted,active" {
		t.Fatalf("retained order=%v", modes)
	}
	now = now.AddDate(0, 0, 10)
	active.opts.MaxAgeDays = 1
	removed, err = active.ApplyRetention(context.Background())
	if err != nil || len(removed) != 1 || removed[0] != encrypted.path {
		t.Fatalf("age retention removed=%v err=%v", removed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, active.path)); err != nil {
		t.Fatalf("old active encrypted segment deleted: %v", err)
	}
}
