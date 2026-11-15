package storage

import (
	"errors"
	"fmt"
)

// UnsealedSegment reports a structural completion warning, without authentication.
type UnsealedSegment struct {
	Segment     string
	Interrupted bool
}

// UnsealedSegments checks structural completion without identities, for doctor.
func UnsealedSegments(dir string) ([]UnsealedSegment, error) {
	segments, err := listSegments(dir)
	if err != nil {
		return nil, err
	}
	var notices []UnsealedSegment
	for i, segment := range segments {
		if !segment.Encrypted {
			continue
		}
		_, err := countEncryptedFrames(segment.Path)
		if err == nil {
			continue
		}
		var open *OpenSegmentError
		if !errors.As(err, &open) {
			if i < len(segments)-1 {
				return notices, fmt.Errorf("storage: interrupted segment %s: %w", segment.Name, err)
			}
			return notices, err
		}
		notices = append(notices, UnsealedSegment{
			Segment: segment.Name, Interrupted: i < len(segments)-1,
		})
	}
	return notices, nil
}
