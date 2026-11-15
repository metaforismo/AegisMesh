package storage

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxMetadataEntries bounds directory entries examined by interactive console requests.
const MaxMetadataEntries = 65536

// Metadata is a bounded physical-directory snapshot, without reading evidence.
type Metadata struct {
	// Segments counts regular evidence segment files.
	Segments int
	// Bytes totals physical segment bytes without opening payloads.
	Bytes int64
}

// SnapshotMetadata refuses directories above maxEntries rather than allocating
// a complete directory listing in an interactive request.
func (s *Store) SnapshotMetadata(maxEntries int) (Metadata, error) {
	var out Metadata
	if maxEntries < 1 || maxEntries > MaxMetadataEntries {
		return out, fmt.Errorf("%w: metadata entry limit must be within 1..65536", errStore)
	}

	dir, err := os.Open(s.opts.Dir)
	if err != nil {
		return out, fmt.Errorf("%w: open metadata directory: %v", errStore, err)
	}

	defer dir.Close()

	entries, err := dir.ReadDir(maxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return out, fmt.Errorf("%w: read metadata directory: %v", errStore, err)
	}

	if len(entries) > maxEntries {
		return out, fmt.Errorf("%w: directory exceeds console metadata entry limit %d", errStore, maxEntries)
	}

	for _, entry := range entries {
		if _, ok := segmentEncryption(entry.Name()); !ok {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return Metadata{}, fmt.Errorf("%w: stat metadata segment: %v", errStore, err)
		}
		if !info.Mode().IsRegular() {
			return Metadata{}, fmt.Errorf("%w: non-regular metadata segment", errStore)
		}
		out.Segments++
		out.Bytes += info.Size()
	}

	return out, nil
}
