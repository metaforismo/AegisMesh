package evidenceindex

import (
	"encoding/json"
	"io"
	"sync"
)

// StreamEvent shares one immutable, lazily encoded observation among a tenant's subscribers.
// Encoding runs outside the index lock; slow writers never hold the encoding lock.
type StreamEvent struct {
	summary Summary
	once    sync.Once
	frame   []byte
	err     error
}

// Matches applies a validated filter without exposing the shared projection.
func (e *StreamEvent) Matches(filter Filter) bool { return filter.Matches(e.summary) }

// WriteTo encodes once and writes a complete SSE observation frame.
func (e *StreamEvent) WriteTo(w io.Writer) (int64, error) {
	e.once.Do(func() {
		var body []byte
		body, e.err = json.Marshal(e.summary)
		if e.err == nil {
			e.frame = make([]byte, 0, len(body)+28)
			e.frame = append(e.frame, "event: observation\ndata: "...)
			e.frame = append(e.frame, body...)
			e.frame = append(e.frame, '\n', '\n')
		}
	})
	if e.err != nil {
		return 0, e.err
	}
	n, err := w.Write(e.frame)
	return int64(n), err
}

// SubscribeEncoded registers an encode-once feed with the same 32-slot slow-client policy.
func (index *Index) SubscribeEncoded() (<-chan *StreamEvent, func(), bool) {
	index.mu.Lock()
	defer index.mu.Unlock()
	if len(index.subscribers)+len(index.streams) >= MaxStreams {
		return nil, nil, false
	}
	if index.streams == nil {
		index.streams = map[chan *StreamEvent]struct{}{}
	}
	channel := make(chan *StreamEvent, 32)
	index.streams[channel] = struct{}{}
	return channel, func() {
		index.mu.Lock()
		defer index.mu.Unlock()
		if _, ok := index.streams[channel]; ok {
			delete(index.streams, channel)
			close(channel)
		}
	}, true
}
