package storage

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/metaforismo/aegismesh/internal/agekey"
)

const (
	checkpointMarker uint32 = 0
	sealMarker       uint32 = 0xffffffff
	checkpointKind   byte   = 1
	sealKind         byte   = 2
	checkpointBytes         = 2 + 8 + sha256.Size
)

func completionPlaintext(kind byte, count uint64, digest []byte) []byte {
	plain := make([]byte, checkpointBytes)
	plain[0], plain[1] = 3, kind
	binary.BigEndian.PutUint64(plain[2:10], count)
	copy(plain[10:], digest)
	return plain
}

type encryptedScan struct {
	events uint64
	end    int64
}

// scanEncryptedFrames also serves keyless retention/doctor. In structural mode
// marker kinds and boundaries are checked, but no authenticity is claimed.
func scanEncryptedFrames(r *bufio.Reader, segment string, ids identitySet,
	authenticate bool, consume func([]byte) error,
) (encryptedScan, error) {
	var verified encryptedScan
	magic := make([]byte, len(encryptedSegmentMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return verified, encryptedReadError(segment, 0, "has a truncated header")
	}
	v2 := string(magic) == encryptedSegmentV2Magic
	if !v2 && string(magic) != encryptedSegmentMagic {
		return verified, encryptedReadError(segment, 0, "has an unsupported framing header")
	}
	offset := int64(len(magic))
	count := uint64(0)
	digest := sha256.New()
	openTail := func(reason string) (encryptedScan, error) {
		if !v2 && verified.end > 0 {
			return verified, &OpenSegmentError{
				Segment: segment, VerifiedEvents: verified.events, TrailingBytes: offset - verified.end,
			}
		}
		if v2 {
			reason += "; v2 requires a seal (v3 checkpoints support live reads; no in-place migration)"
		}
		return verified, encryptedReadError(segment, 0, reason)
	}
	for {
		var prefix [frameLengthBytes]byte
		n, err := io.ReadFull(r, prefix[:])
		offset += int64(n)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return openTail("is not sealed (missing completion record or torn length prefix)")
		}
		if err != nil {
			return verified, encryptedReadError(segment, 0, "length read failed")
		}
		length := binary.BigEndian.Uint32(prefix[:])
		control := length == checkpointMarker || (!v2 && length == sealMarker)
		kind := checkpointKind
		if v2 || length == sealMarker {
			kind = sealKind
		}
		if control {
			n, err = io.ReadFull(r, prefix[:])
			offset += int64(n)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return openTail("has a truncated completion length")
			}
			if err != nil {
				return verified, encryptedReadError(segment, 0, "completion length read failed")
			}
			length = binary.BigEndian.Uint32(prefix[:])
			if length == 0 || length > encryptedFooterReserve-2*frameLengthBytes {
				return verified, encryptedReadError(segment, 0, "has invalid completion length")
			}
		} else if length > agekey.MaxEncryptedFrameBytes {
			return verified, encryptedReadError(segment, 0, fmt.Sprintf("has invalid length %d", length))
		}
		var ciphertext []byte
		var readBytes int64
		if authenticate {
			ciphertext = make([]byte, int(length))
			n, err = io.ReadFull(r, ciphertext)
			readBytes = int64(n)
		} else {
			readBytes, err = io.CopyN(io.Discard, r, int64(length))
		}
		offset += readBytes
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return openTail("has a truncated ciphertext")
		}
		if err != nil {
			return verified, encryptedReadError(segment, 0, "ciphertext read failed")
		}
		var plain []byte
		if authenticate {
			plain, err = decryptFrame(bytes.NewReader(ciphertext), length, ids, segment, int(count+1))
			if err != nil {
				return verified, err
			}
		}
		if !control {
			count++
			_, _ = digest.Write(prefix[:])
			_, _ = digest.Write(ciphertext)
			if consume != nil {
				if err := consume(plain); err != nil {
					return verified, err
				}
			}
			continue
		}
		if authenticate {
			expected := completionPlaintext(kind, count, digest.Sum(nil))
			if v2 {
				expected = expected[2:]
			}
			if !bytes.Equal(plain, expected) {
				return verified, encryptedReadError(segment, 0, "completion does not match version, kind, count and order")
			}
		}
		verified = encryptedScan{events: count, end: offset}
		if kind == sealKind {
			if _, err := r.ReadByte(); !errors.Is(err, io.EOF) {
				return verified, encryptedReadError(segment, 0, "has trailing data or read failure after seal")
			}
			return verified, nil
		}
	}
}
