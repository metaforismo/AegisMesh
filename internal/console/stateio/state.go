// Package stateio confines console-owned state to a private directory.
// Callers must supply trusted fixed filenames; request data must never select filesystem paths.
package stateio

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxStateBytes caps the encoded investigation snapshot.
const MaxStateBytes = 32 << 20

// Open verifies a private real directory and probes synchronous write access.
func Open(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("console state directory: %w", err)
	}

	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("console state directory must be a real directory with mode 0700")
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}

	file, err := File(root, ".write-probe", os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("console state directory is not writable (inspect stale .write-probe if present): %w", err)
	}

	err = file.Sync()
	closeErr := file.Close()
	removeErr := root.Remove(".write-probe")
	if err != nil || closeErr != nil || removeErr != nil {
		root.Close()
		return nil, errors.New("console state write/sync probe failed")
	}

	return root, nil
}

// File opens a trusted fixed filename, rejecting nonregular or nonprivate existing files.
func File(root *os.Root, name string, flags int) (*os.File, error) {
	info, err := root.Lstat(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600) {
		return nil, errors.New("console state file must be regular with mode 0600")
	}

	return root.OpenFile(name, flags, 0600)
}

// Read reads a trusted fixed filename with a hard byte limit.
func Read(root *os.Root, name string, max int) ([]byte, error) {
	file, err := File(root, name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	body, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if len(body) > max {
		return nil, errors.New("console state exceeds byte limit")
	}

	return body, err
}

// Atomic syncs a trusted fixed-name temporary file, renames it, and syncs the directory.
func Atomic(root *os.Root, name string, body []byte) error {
	if len(body) > MaxStateBytes {
		return errors.New("console state exceeds byte limit")
	}

	// Names are fixed at compile time by the owning repository, never request IDs.
	tmp := name + ".tmp"
	file, err := File(root, tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		return fmt.Errorf("console state temporary file (remove stale .tmp after inspection): %w", err)
	}

	defer root.Remove(tmp)

	if _, err = file.Write(body); err == nil {
		err = file.Sync()
	}

	closeErr := file.Close()
	if err != nil {
		return err
	}

	if closeErr != nil {
		return closeErr
	}

	if err = root.Rename(tmp, name); err != nil {
		return err
	}

	directory, err := root.Open(".")
	if err != nil {
		return err
	}

	defer directory.Close()

	return directory.Sync()
}
