package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

// RetainBytes removes oldest closed segments until disk usage is at most limit.
// It flushes buffered bytes before accounting; an active segment is never deleted.
// The returned size includes the active segment and encryption overhead.
func (s *Store) RetainBytes(limit int64) (int64, error) {
	if err := s.Flush(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	segments, err := listSegments(s.opts.Dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, segment := range segments {
		total += segment.SizeBytes
	}
	for _, segment := range segments {
		if total <= limit {
			break
		}
		if segment.Name == s.path {
			continue
		}
		if err := os.Remove(filepath.Join(s.opts.Dir, segment.Name)); err != nil {
			return total, fmt.Errorf("%w: byte retention: %v", errStore, err)
		}
		total -= segment.SizeBytes
	}
	return total, nil
}
