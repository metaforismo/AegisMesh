package storage

import (
	"bufio"
	"bytes"
	"crypto/sha256"
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
	encryptedSegmentExt    = ".jsonl.age"
	encryptedSegmentMagic  = "aegismesh.ageframes/v2\n"
	encryptedFooterReserve = 1024
	frameLengthBytes       = 4

	// Age-driven sealing bounds read delay without rotating on every runtime flush.
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

func forEachEncryptedFrame(path string, identities identitySet, fn func([]byte) error) error {
	if len(identities.values) == 0 {
		return encryptedReadError(filepath.Base(path), 0, "requires at least one identity file")
	}
	f, err := openRegularSegment(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return readEncryptedFrames(bufio.NewReader(f), filepath.Base(path), identities, fn)
}

func readEncryptedFrames(reader *bufio.Reader, segment string, identities identitySet, fn func([]byte) error) error {
	if err := readEncryptedSegmentHeader(reader, segment); err != nil {
		return err
	}
	digest := sha256.New()
	for frameNumber := 1; ; frameNumber++ {
		length, footer, err := readEncryptedFrameLength(reader, segment, frameNumber)
		if err != nil {
			return err
		}
		if footer {
			length, nested, err := readEncryptedFrameLength(reader, segment, frameNumber)
			if err != nil {
				return err
			}
			if nested || length > encryptedFooterReserve-frameLengthBytes*2 {
				return encryptedReadError(segment, 0, "has invalid footer")
			}
			plaintext, err := decryptFrame(reader, length, identities, segment, frameNumber)
			if err != nil {
				return err
			}
			expected := make([]byte, 8, 8+sha256.Size)
			binary.BigEndian.PutUint64(expected, uint64(frameNumber-1))
			expected = digest.Sum(expected)
			if !bytes.Equal(plaintext, expected) {
				return encryptedReadError(segment, 0, "footer does not match event count and order")
			}
			if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
				return encryptedReadError(segment, 0, "has trailing data or read failure")
			}
			return nil
		}
		ciphertext := make([]byte, int(length))
		if _, err := io.ReadFull(reader, ciphertext); err != nil {
			return encryptedReadError(segment, frameNumber, "is truncated")
		}
		var prefix [frameLengthBytes]byte
		binary.BigEndian.PutUint32(prefix[:], length)
		_, _ = digest.Write(prefix[:])
		_, _ = digest.Write(ciphertext)
		plaintext, err := decryptFrame(bytes.NewReader(ciphertext), length, identities, segment, frameNumber)
		if err != nil {
			return err
		}
		if err := fn(plaintext); err != nil {
			return err
		}
	}
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
		return nil, encryptedReadError(segment, frameNumber, fmt.Sprintf("plaintext exceeds %d bytes", agekey.MaxEncryptedEventBytes))
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
	return countEncryptedFramesReader(bufio.NewReader(f), filepath.Base(path))
}

func countEncryptedFramesReader(reader *bufio.Reader, segment string) (int, error) {
	if err := readEncryptedSegmentHeader(reader, segment); err != nil {
		return 0, err
	}
	count := 0
	for frameNumber := 1; ; frameNumber++ {
		length, done, err := readEncryptedFrameLength(reader, segment, frameNumber)
		if err != nil {
			return 0, err
		}
		if done {
			length, nested, err := readEncryptedFrameLength(reader, segment, frameNumber)
			if err != nil {
				return 0, err
			}
			if nested || length > encryptedFooterReserve-frameLengthBytes*2 {
				return 0, encryptedReadError(segment, 0, "has invalid footer")
			}
			if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
				return 0, encryptedReadError(segment, 0, "footer is truncated")
			}
			if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
				return 0, encryptedReadError(segment, 0, "has trailing data or read failure")
			}
			return count, nil
		}
		if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
			return 0, encryptedReadError(segment, frameNumber, "is truncated")
		}
		count++
	}
}

func readEncryptedSegmentHeader(reader *bufio.Reader, segment string) error {
	magic := make([]byte, len(encryptedSegmentMagic))
	if _, err := io.ReadFull(reader, magic); err != nil {
		return encryptedReadError(segment, 0, "has a truncated header")
	}
	if string(magic) != encryptedSegmentMagic {
		return encryptedReadError(segment, 0, "has an unsupported framing header")
	}
	return nil
}

func readEncryptedFrameLength(reader *bufio.Reader, segment string, frameNumber int) (uint32, bool, error) {
	var prefix [frameLengthBytes]byte
	n, err := io.ReadFull(reader, prefix[:])
	if errors.Is(err, io.EOF) && n == 0 {
		return 0, false, encryptedReadError(segment, 0, "is not sealed (missing footer)")
	}
	if err != nil {
		return 0, false, encryptedReadError(segment, frameNumber, "has a truncated length prefix")
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 {
		return 0, true, nil
	}
	if length > agekey.MaxEncryptedFrameBytes {
		return 0, false, encryptedReadError(segment, frameNumber, fmt.Sprintf("has invalid length %d", length))
	}
	return length, false, nil
}
