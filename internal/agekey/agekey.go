// Package agekey owns the narrow age/X25519 key boundary used by AegisMesh.
package agekey

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"filippo.io/age"
	"github.com/metaforismo/aegismesh/internal/event"
)

const (
	MaxRecipientBytes      = 128
	MaxIdentityFiles       = 8
	MaxIdentityFileBytes   = 4 << 10
	MaxEncryptedEventBytes = event.MaxStoredEnvelopeBytes
	MaxEncryptedFrameBytes = MaxEncryptedEventBytes + (128 << 10)
)

// ParseRecipient accepts only the native age X25519 public-key format.
func ParseRecipient(value string) (*age.X25519Recipient, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return nil, errors.New("recipient must be a non-empty age X25519 public key without surrounding whitespace")
	}
	if len(value) > MaxRecipientBytes || strings.ContainsAny(value, ",\r\n") {
		return nil, errors.New("recipient must be one age X25519 public key")
	}
	recipient, err := age.ParseX25519Recipient(value)
	if err != nil {
		return nil, errors.New("recipient is not a valid age X25519 public key")
	}
	return recipient, nil
}

func validateIdentityFileInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("identity file must be a regular file")
	}
	if info.Size() > MaxIdentityFileBytes {
		return fmt.Errorf("identity file exceeds %d bytes", MaxIdentityFileBytes)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("identity file permissions must not grant group or other access")
	}
	return nil
}

// LoadIdentityFile reads exactly one native age X25519 private key from path.
// Blank lines and comments are ignored so age-keygen output can be used directly.
func LoadIdentityFile(path string) (*age.X25519Identity, os.FileInfo, error) {
	if path == "" || strings.TrimSpace(path) != path || strings.Contains(strings.ToUpper(path), "AGE-SECRET-KEY-") {
		return nil, nil, errors.New("identity file path must not be empty or padded")
	}
	before, err := os.Stat(path) // follows secret-manager symlinks intentionally
	if err != nil {
		return nil, nil, errors.New("cannot inspect identity file; check the file reference and permissions")
	}
	if err := validateIdentityFileInfo(before); err != nil {
		return nil, nil, err
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // explicit operator path; non-blocking rejects FIFOs safely
	if err != nil {
		return nil, nil, errors.New("cannot open identity file; check the file reference and permissions")
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("inspect opened identity file: %w", err)
	}
	if err := validateIdentityFileInfo(info); err != nil {
		return nil, nil, err
	}
	if !os.SameFile(before, info) {
		return nil, nil, errors.New("identity file changed while opening")
	}

	raw, err := io.ReadAll(io.LimitReader(f, MaxIdentityFileBytes+1))
	if err != nil {
		return nil, nil, errors.New("cannot read identity file")
	}
	if len(raw) > MaxIdentityFileBytes {
		return nil, nil, fmt.Errorf("identity file exceeds %d bytes", MaxIdentityFileBytes)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 256), MaxIdentityFileBytes+1)
	var encoded string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if encoded != "" {
			return nil, nil, errors.New("identity file must contain exactly one X25519 identity")
		}
		encoded = line
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read identity file: %w", err)
	}
	if encoded == "" {
		return nil, nil, errors.New("identity file contains no X25519 identity")
	}
	identity, err := age.ParseX25519Identity(encoded)
	if err != nil {
		return nil, nil, errors.New("identity file does not contain a valid age X25519 identity")
	}
	return identity, info, nil
}
