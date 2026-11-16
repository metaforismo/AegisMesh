package storage

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/metaforismo/aegismesh/internal/agekey"
)

const (
	encryptedSegmentExt     = ".jsonl.age"
	encryptedSegmentMagic   = "aegismesh.ageframes/v3\n"
	encryptedSegmentV2Magic = "aegismesh.ageframes/v2\n"
	encryptedFooterReserve  = 1024
	frameLengthBytes        = 4

	// Age-driven sealing bounds segment lifetime without rotating on every runtime flush.
	// Measured from the first event; empty segments do not age out.
	maxEncryptedSegmentAge = 5 * time.Minute
)

// EncryptionError identifies a failed encrypted read without retaining key or ciphertext data.
type EncryptionError struct {
	Segment string
	Frame   int
	Reason  string
}

func (e *EncryptionError) Error() string {
	if e.Frame > 0 {
		return fmt.Sprintf("storage: encrypted segment %s frame %d %s", e.Segment, e.Frame, e.Reason)
	}
	return fmt.Sprintf("storage: encrypted segment %s %s", e.Segment, e.Reason)
}

func (e *EncryptionError) Unwrap() error { return errStore }

func encryptedReadError(segment string, frame int, reason string) error {
	return &EncryptionError{Segment: segment, Frame: frame, Reason: reason}
}

// EncryptionOptions configures public-recipient-only writes.
type EncryptionOptions struct {
	Recipient string
}

type segmentEncryptor struct {
	recipient *age.X25519Recipient
}

func newSegmentEncryptor(options *EncryptionOptions) (*segmentEncryptor, error) {
	if options == nil {
		return nil, nil
	}
	recipient, err := agekey.ParseRecipient(options.Recipient)
	if err != nil {
		return nil, fmt.Errorf("%w: encryption recipient: %v", errStore, err)
	}
	return &segmentEncryptor{recipient: recipient}, nil
}

func (e *segmentEncryptor) frame(plaintext []byte) ([]byte, error) {
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, e.recipient)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize age encryption: %v", errStore, err)
	}
	n, err := writer.Write(plaintext)
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("%w: encrypt event: %v", errStore, err)
	}
	if n != len(plaintext) {
		_ = writer.Close()
		return nil, fmt.Errorf("%w: encrypt event: %v", errStore, io.ErrShortWrite)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("%w: finalize encrypted event: %v", errStore, err)
	}
	if ciphertext.Len() > agekey.MaxEncryptedFrameBytes {
		return nil, fmt.Errorf("%w: encrypted frame exceeds %d bytes", errStore, agekey.MaxEncryptedFrameBytes)
	}

	frame := make([]byte, frameLengthBytes+ciphertext.Len())
	binary.BigEndian.PutUint32(frame[:frameLengthBytes], uint32(ciphertext.Len()))
	copy(frame[frameLengthBytes:], ciphertext.Bytes())
	return frame, nil
}

type identitySet struct {
	values []age.Identity
	files  []os.FileInfo
	paths  []string
}

func loadIdentitySet(paths []string) (identitySet, error) {
	if len(paths) > agekey.MaxIdentityFiles {
		return identitySet{}, fmt.Errorf("%w: at most %d identity files are allowed", errStore, agekey.MaxIdentityFiles)
	}
	set := identitySet{
		values: make([]age.Identity, 0, len(paths)),
		files:  make([]os.FileInfo, 0, len(paths)),
		paths:  make([]string, 0, len(paths)),
	}
	for _, path := range paths {
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			return identitySet{}, fmt.Errorf("%w: resolve identity file path: %v", errStore, err)
		}
		identity, info, err := agekey.LoadIdentityFile(path)
		if err != nil {
			return identitySet{}, fmt.Errorf("%w: identity file reference: %v", errStore, err)
		}
		for _, existing := range set.files {
			if os.SameFile(existing, info) {
				return identitySet{}, fmt.Errorf("%w: identity file supplied more than once", errStore)
			}
		}
		set.values = append(set.values, identity)
		set.files = append(set.files, info)
		set.paths = append(set.paths, filepath.Clean(absolutePath))
	}
	return set, nil
}

func writeEncryptedSegmentHeader(dst io.Writer) (int, error) {
	n, err := io.WriteString(dst, encryptedSegmentMagic)
	if err != nil {
		return n, fmt.Errorf("%w: write encrypted segment header: %v", errStore, err)
	}
	if n != len(encryptedSegmentMagic) {
		return n, fmt.Errorf("%w: write encrypted segment header: %v", errStore, io.ErrShortWrite)
	}
	return n, nil
}

// OpenSegmentError identifies an authenticated but incomplete v3 prefix.
// TrailingBytes are excluded from the returned events. Interrupted means a newer
// segment exists; it is an operational crash warning, not proof of its cause.
type OpenSegmentError struct {
	Segment        string `json:"segment"`
	VerifiedEvents uint64 `json:"verified_events"`
	TrailingBytes  int64  `json:"trailing_bytes"`
	Interrupted    bool   `json:"interrupted"`
}

func (e *OpenSegmentError) Error() string {
	label := "open segment"
	if e.Interrupted {
		label = "WARNING: interrupted segment"
	}
	return fmt.Sprintf("storage: %s %s not sealed; %d events verified through the last checkpoint; "+
		"%d trailing bytes ignored; later events may exist",
		label, e.Segment, e.VerifiedEvents, e.TrailingBytes)
}

func (e *OpenSegmentError) Unwrap() error { return errStore }

func forEachEncryptedFrame(path string, identities identitySet, fn func([]byte) error) error {
	if len(identities.values) == 0 {
		return encryptedReadError(filepath.Base(path), 0, "requires at least one identity file")
	}
	f, err := openRegularSegment(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat encrypted snapshot: %v", errStore, err)
	}
	return readEncryptedFrames(f, info.Size(), filepath.Base(path), identities, fn)
}

// Two passes keep memory bounded by one frame. The initial size is a live-read
// snapshot boundary; subsequent appends cannot extend this read indefinitely.
func readEncryptedFrames(src io.ReaderAt, size int64, segment string, ids identitySet, fn func([]byte) error) error {
	snapshot := func(n int64) *bufio.Reader {
		return bufio.NewReader(io.NewSectionReader(src, 0, n))
	}
	result, err := scanEncryptedFrames(snapshot(size), segment, ids, true, nil)
	var open *OpenSegmentError
	if err != nil && !errors.As(err, &open) {
		return err
	}
	replay, replayErr := scanEncryptedFrames(snapshot(result.end), segment, ids, true, fn)
	var replayOpen *OpenSegmentError
	if replayErr != nil && !errors.As(replayErr, &replayOpen) {
		return replayErr
	}
	if replay != result || (replayOpen != nil && (open == nil || replayOpen.TrailingBytes != 0)) {
		return encryptedReadError(segment, 0, "changed while reading the verified prefix")
	}
	return err
}

func decryptFrame(reader io.Reader, length uint32, identities identitySet, segment string, frameNumber int) ([]byte, error) {
	frame := &io.LimitedReader{R: reader, N: int64(length)}
	decrypted, err := age.Decrypt(frame, identities.values...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, encryptedReadError(segment, frameNumber, "did not match any supplied identity")
		}
		return nil, encryptedReadError(segment, frameNumber, "header authentication failed")
	}
	plaintext, err := io.ReadAll(io.LimitReader(decrypted, agekey.MaxEncryptedEventBytes+1))
	if err != nil {
		return nil, encryptedReadError(segment, frameNumber, "authentication failed")
	}
	if len(plaintext) > agekey.MaxEncryptedEventBytes {
		return nil, encryptedReadError(segment, frameNumber,
			fmt.Sprintf("plaintext exceeds %d bytes", agekey.MaxEncryptedEventBytes))
	}
	if frame.N != 0 {
		return nil, encryptedReadError(segment, frameNumber, "is truncated or contains trailing data")
	}
	return plaintext, nil
}

func countEncryptedFrames(path string) (int, error) {
	f, err := openRegularSegment(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("%w: stat encrypted snapshot: %v", errStore, err)
	}
	reader := bufio.NewReader(io.NewSectionReader(f, 0, info.Size()))
	return countEncryptedFramesReader(reader, filepath.Base(path))
}

func countEncryptedFramesReader(reader *bufio.Reader, segment string) (int, error) {
	result, err := scanEncryptedFrames(reader, segment, identitySet{}, false, nil)
	return int(result.events), err
}
