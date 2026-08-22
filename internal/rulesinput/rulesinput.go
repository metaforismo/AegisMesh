// Package rulesinput defines the bounded offline input contract for rule
// test documents (capability 4d-1): it loads exactly one explicitly declared
// source — a literal string, a named local file, or an injected stdin
// reader — and returns the validated UTF-8 text plus safe provenance
// metadata for later rules evaluation.
//
// SECURITY INVARIANTS:
//   - Strictly offline: no network, no exec, no environment access, no
//     writes, no process-global stdin lookup (streams are injected).
//   - Read-only: paths are opened O_RDONLY and used verbatim — no expansion,
//     no traversal resolution, no candidate guessing, no fallbacks.
//   - Bounded: at most MaxBytes are accepted; readers are capped at
//     MaxBytes+1 so oversized input fails before unbounded allocation.
//   - Content never appears in errors or metadata; only the source kind, a
//     safe caller-facing name, and the byte count leave this package.
package rulesinput

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// MaxBytes is the conservative upper bound on accepted input size.
// Rule test documents are small YAML fixtures; 64 KiB is far above any
// plausible document and low enough that hostile input cannot stress
// memory. The limit is part of the contract and must not be raised casually.
const MaxBytes = 64 << 10 // 65536 bytes

// SourceKind identifies which single member of Source carried the input.
type SourceKind string

const (
	KindLiteral SourceKind = "literal" // inline text supplied by the caller
	KindFile    SourceKind = "file"    // one named local regular file
	KindStdin   SourceKind = "stdin"   // caller-injected stream (e.g. os.Stdin)
)

// Source declares exactly one input origin. Kind selects the member that
// must be populated; every other member must stay zero. A Source with no,
// several, or mismatched members makes Load fail rather than guess —
// ambiguity is always a hard error, never resolved by priority.
type Source struct {
	Kind  SourceKind
	Text  string    // required when Kind == KindLiteral (may be empty: still an explicit declaration)
	Path  string    // required when Kind == KindFile; verbatim local path
	Stdin io.Reader // required when Kind == KindStdin; injected, never global
}

// Input is the result of a successful load: the validated text plus safe
// metadata only. Name is caller-facing (a label such as "literal", "stdin",
// or the file's base name — never a full path); Bytes is the deterministic
// length of Text in bytes.
type Input struct {
	Kind  SourceKind
	Name  string
	Bytes int
	Text  string
}

// Sentinel errors for every rejection class of the contract. Wrapped details
// add context (names, counts, wrapped *os errors carrying the caller's own
// path argument) but never input content.
var (
	ErrNoSource        = errors.New("rulesinput: exactly one source required, none given")
	ErrAmbiguousSource = errors.New("rulesinput: exactly one source required, multiple or mismatched members given")
	ErrEmptyInput      = errors.New("rulesinput: input is empty")
	ErrTooLarge        = errors.New("rulesinput: input exceeds maximum size")
	ErrInvalidUTF8     = errors.New("rulesinput: input is not valid UTF-8")
	ErrNotRegularFile  = errors.New("rulesinput: not a regular file")
	ErrSymlink         = errors.New("rulesinput: symbolic links are not accepted")
)

// Load validates src and reads its content under the documented bounds.
// It performs exactly one attempt against the declared source — no retries,
// no fallbacks — and fails closed on any contract violation. The returned
// error never contains input content.
func Load(src Source) (Input, error) {
	kind, name, data, err := read(src)
	if err != nil {
		return Input{}, err
	}
	if err := validate(data); err != nil {
		return Input{}, err
	}
	return Input{Kind: kind, Name: name, Bytes: len(data), Text: string(data)}, nil
}

// read dispatches on the declared kind, enforces the exactly-one contract,
// and returns the bounded raw bytes plus the safe caller-facing name.
func read(src Source) (SourceKind, string, []byte, error) {
	if src.Kind == "" && src.Text == "" && src.Path == "" && src.Stdin == nil {
		return "", "", nil, ErrNoSource
	}
	switch src.Kind {
	case KindLiteral:
		if src.Path != "" || src.Stdin != nil {
			return "", "", nil, fmt.Errorf("%w: literal source also sets Path or Stdin", ErrAmbiguousSource)
		}
		if len(src.Text) > MaxBytes {
			return "", "", nil, overLimit(len(src.Text))
		}
		return KindLiteral, "literal", []byte(src.Text), nil
	case KindFile:
		if src.Text != "" || src.Stdin != nil {
			return "", "", nil, fmt.Errorf("%w: file source also sets Text or Stdin", ErrAmbiguousSource)
		}
		if src.Path == "" {
			return "", "", nil, fmt.Errorf("%w: file source has empty path", ErrAmbiguousSource)
		}
		data, err := readFile(src.Path)
		if err != nil {
			return "", "", nil, err
		}
		return KindFile, filepath.Base(src.Path), data, nil
	case KindStdin:
		if src.Text != "" || src.Path != "" {
			return "", "", nil, fmt.Errorf("%w: stdin source also sets Text or Path", ErrAmbiguousSource)
		}
		if src.Stdin == nil {
			return "", "", nil, fmt.Errorf("%w: stdin source has nil reader", ErrAmbiguousSource)
		}
		data, err := readStream(src.Stdin)
		if err != nil {
			return "", "", nil, err
		}
		return KindStdin, "stdin", data, nil
	default:
		return "", "", nil, fmt.Errorf("%w: unknown source kind %q", ErrAmbiguousSource, src.Kind)
	}
}

// readFile opens path verbatim (no cleaning, no traversal, no fallback),
// refuses symlinks and non-regular files before opening (so a named FIFO
// cannot block), re-checks regularity after open, and reads at most
// MaxBytes+1 bytes. A narrow TOCTOU window remains between the two stats
// (file swapped for a symlink or special file); it is accepted because this
// is a defensive input contract, not a sandbox.
func readFile(path string) ([]byte, error) {
	name := filepath.Base(path)
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("rulesinput: stat %s: %w", name, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("rulesinput: %s: %w", name, ErrSymlink)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("rulesinput: %s: %w", name, ErrNotRegularFile)
	}
	f, err := os.Open(path) //nolint:gosec // verbatim caller-named path is the documented contract; helpers would hide intent
	if err != nil {
		return nil, fmt.Errorf("rulesinput: open %s: %w", name, err)
	}
	defer f.Close() //nolint:errcheck // read-only handle; a close failure cannot affect bytes already returned
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("rulesinput: stat %s: %w", name, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("rulesinput: %s: %w", name, ErrNotRegularFile)
	}
	if st.Size() > MaxBytes {
		return nil, overLimit(int(st.Size()))
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("rulesinput: read %s: %w", name, err)
	}
	if len(data) > MaxBytes {
		return nil, overLimit(len(data))
	}
	return data, nil
}

// readStream drains r through a hard MaxBytes+1 cap so an oversized stream
// is rejected after a bounded allocation instead of buffering forever.
func readStream(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("rulesinput: read stream: %w", err)
	}
	if len(data) > MaxBytes {
		return nil, overLimit(len(data))
	}
	return data, nil
}

// validate applies the shared content contract: non-empty, valid UTF-8.
func validate(data []byte) error {
	if len(data) == 0 {
		return ErrEmptyInput
	}
	if !utf8.Valid(data) {
		return ErrInvalidUTF8
	}
	return nil
}

// overLimit reports the size violation with the exact count when known and
// "more than" when only a lower bound is observable (capped streams stop at
// MaxBytes+1 by design).
func overLimit(got int) error {
	if got <= MaxBytes+1 {
		return fmt.Errorf("%w: limit is %d bytes, got more than %d", ErrTooLarge, MaxBytes, MaxBytes)
	}
	return fmt.Errorf("%w: limit is %d bytes, got %d", ErrTooLarge, MaxBytes, got)
}
