package storage

import (
	"context"
	"testing"

	"github.com/metaforismo/aegismesh/internal/event"
)

func TestBoundedMetadataSnapshot(t *testing.T) {
	s := newStore(t, Options{
		Dir:          t.TempDir(),
		MaxFileBytes: 4096,
	})
	seq := &event.Sequencer{}
	for range 40 {
		if err := s.Append(context.Background(), mkEnv(t, seq, `{"synthetic":"metadata"}`)); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}

	segments, err := s.Segments()
	if err != nil || len(segments) < 2 {
		t.Fatal("rotation fixture failed", err)
	}

	m, err := s.SnapshotMetadata(65536)
	var bytes int64
	for _, seg := range segments {
		bytes += seg.SizeBytes
	}

	if err != nil || m.Segments != len(segments) || m.Bytes != bytes {
		t.Fatalf("%+v %v", m, err)
	}

	if _, err = s.SnapshotMetadata(1); err == nil {
		t.Fatal("directory entry bound ignored")
	}

	if _, err = s.SnapshotMetadata(65537); err == nil {
		t.Fatal("unbounded limit accepted")
	}
}
