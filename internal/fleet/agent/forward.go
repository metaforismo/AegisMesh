package agent

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// QueueEvents bounds pending events, including the retrying batch.
const QueueEvents = 4096

// QueueBytes bounds encoded envelopes retained in memory, including retries.
const QueueBytes = 16 << 20

type queuedEvidence struct {
	sequence uint64
	body     json.RawMessage
}

type forwarder struct {
	mu       sync.Mutex
	step     sync.Mutex
	items    []queuedEvidence
	head     int
	count    int
	bytes    int
	next     uint64
	stream   string
	status   protocol.Forwarding
	client   *Agent
	outcomes observe.LabeledCounter
}

// Enqueue offers a successfully stored redacted envelope; it never waits for network or disk IO.
// A disabled forwarder performs no serialization or allocation.
func (a *Agent) Enqueue(envelope event.Envelope) {
	if a.forward == nil {
		return
	}
	f := a.forward
	body, err := json.Marshal(envelope)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	if err != nil || len(body) > event.MaxStoredEnvelopeBytes || len(body) > QueueBytes {
		f.status.DroppedTotal++
		f.outcomes.Inc("dropped")
		return
	}
	for f.count >= len(f.items) || f.bytes+len(body) > QueueBytes {
		f.remove()
		f.status.DroppedTotal++
		f.outcomes.Inc("dropped")
	}
	tail := (f.head + f.count) % len(f.items)
	f.items[tail] = queuedEvidence{sequence: f.next, body: body}
	f.count++
	f.bytes += len(body)
}

func (f *forwarder) remove() {
	f.bytes -= len(f.items[f.head].body)
	f.items[f.head] = queuedEvidence{}
	f.head = (f.head + 1) % len(f.items)
	f.count--
}

func (a *Agent) forwardingStatus() protocol.Forwarding {
	if a.forward == nil {
		return protocol.Forwarding{}
	}
	f := a.forward
	f.mu.Lock()
	defer f.mu.Unlock()
	status := f.status
	status.QueuedBytes = f.bytes
	status.QueuedEvents = f.count
	return status
}

// ForwardStep submits one bounded batch independently of heartbeat scheduling.
func (a *Agent) ForwardStep(ctx context.Context) error {
	if a.forward == nil || !a.Status().Enrolled {
		return nil
	}
	f := a.forward
	f.step.Lock()
	defer f.step.Unlock()
	f.mu.Lock()
	batch := protocol.EvidenceBatch{StreamID: f.stream, Events: []json.RawMessage{}}
	bytes := 256
	for i := 0; i < f.count && len(batch.Events) < protocol.MaxBatchEvents; i++ {
		item := f.items[(f.head+i)%len(f.items)]
		if bytes+len(item.body)+1 > protocol.MaxEvidenceBytes ||
			len(batch.Events) > 0 && item.sequence != batch.Last+1 {
			break
		}
		if len(batch.Events) == 0 {
			batch.First = item.sequence
		}
		batch.Last = item.sequence
		batch.Events = append(batch.Events, item.body)
		bytes += len(item.body) + 1
	}
	f.mu.Unlock()
	if len(batch.Events) == 0 {
		return nil
	}
	var ack protocol.EvidenceAck
	err := f.client.postAck(ctx, protocol.EvidencePath, batch, &ack)
	if err == nil && (ack.Accepted < 0 || ack.Invalid < 0 || ack.Duplicates < 0 ||
		ack.Accepted > len(batch.Events) || ack.Invalid > len(batch.Events) || ack.Duplicates > len(batch.Events) ||
		ack.Accepted+ack.Invalid+ack.Duplicates != len(batch.Events)) {
		err = localError("response", "invalid evidence acknowledgement counts")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		var typed *Error
		f.status.LastError = "delivery_failed"
		if errors.As(err, &typed) {
			f.status.LastError = typed.Code
		}
		f.outcomes.Inc("failed")
		return err
	}
	// Overflow may already have removed a prefix while this batch was in flight.
	for f.count > 0 && f.items[f.head].sequence <= batch.Last {
		f.remove()
	}
	f.status.ForwardedTotal += uint64(ack.Accepted + ack.Duplicates)
	f.status.DroppedTotal += uint64(ack.Invalid)
	f.status.LastForwardedAt = a.now().UTC().Format(time.RFC3339Nano)
	f.status.LastError = ""
	f.outcomes.Inc("accepted")
	return nil
}

func (a *Agent) runForward(ctx context.Context) {
	defer a.wg.Done()
	failures := 0
	for {
		err := a.ForwardStep(ctx)
		delay := 5 * time.Second
		if err != nil {
			failures = min(failures+1, 9)
			ceiling := min(time.Second*time.Duration(1<<failures), 300*time.Second)
			delay = ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)+1))
			var typed *Error
			if errors.As(err, &typed) && typed.Code == "evidence_disabled" {
				delay = 5*time.Minute + time.Duration(rand.Int64N(int64(time.Minute)))
			}
		} else {
			failures = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
