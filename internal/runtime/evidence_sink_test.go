package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/metaforismo/aegismesh/internal/event"
)

type appendRecorder struct {
	err   error
	calls int
}

func (r *appendRecorder) Append(context.Context, event.Envelope) error {
	r.calls++
	return r.err
}

type deliveryRecorder struct{ calls int }

func (r *deliveryRecorder) Deliver(event.Envelope) { r.calls++ }

type offerRecorder struct{ calls int }

func (r *offerRecorder) Offer(event.Envelope) bool {
	r.calls++
	return true
}

type correlationRecorder struct{ calls int }

func (r *correlationRecorder) observe(event.Envelope) { r.calls++ }

func TestEvidenceSinkOffersOnlyAfterSuccessfulPrimaryAppend(t *testing.T) {
	primaryErr := errors.New("synthetic append failure")
	primary := &appendRecorder{err: primaryErr}
	mgr := &deliveryRecorder{}
	hook := &offerRecorder{}
	corr := &correlationRecorder{}
	sink := evidenceSink{primary: primary, mgr: mgr, hook: hook, corr: corr}

	if err := sink.Append(context.Background(), event.Envelope{}); !errors.Is(err, primaryErr) {
		t.Fatalf("Append error = %v, want %v", err, primaryErr)
	}
	if primary.calls != 1 || mgr.calls != 0 || hook.calls != 0 || corr.calls != 0 {
		t.Fatalf("failed append must not fan out: primary=%d extension=%d webhook=%d correlation=%d",
			primary.calls, mgr.calls, hook.calls, corr.calls)
	}

	primary.err = nil
	if err := sink.Append(context.Background(), event.Envelope{}); err != nil {
		t.Fatalf("successful Append: %v", err)
	}
	if primary.calls != 2 || mgr.calls != 1 || hook.calls != 1 || corr.calls != 1 {
		t.Fatalf("successful append must fan out once: primary=%d extension=%d webhook=%d correlation=%d",
			primary.calls, mgr.calls, hook.calls, corr.calls)
	}
}
