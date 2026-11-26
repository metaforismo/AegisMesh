package demo

import (
	"context"
	"fmt"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/demoseed"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/storage"
)

// seed appends a generated synthetic history to the demo's private evidence
// store with the runtime's own storage options. The store is closed before the
// runtime is built, so the console reads it back through its normal backfill.
// Ctrl-C (ctx cancellation) stops generation between envelopes.
func seed(ctx context.Context, cfg *config.Config, profile string, now time.Time) (demoseed.Result, error) {
	selected, err := demoseed.Lookup(profile)
	if err != nil {
		return demoseed.Result{}, fmt.Errorf("demo: %w", err)
	}
	store, err := storage.New(storage.Options{
		Dir:           cfg.Runtime.DataDir,
		MaxFileBytes:  cfg.Storage.MaxFileBytes,
		MaxEventBytes: cfg.Storage.MaxEventBytes,
		MaxEvents:     cfg.Storage.Retention.MaxEvents,
		MaxAgeDays:    cfg.Storage.Retention.MaxAgeDays,
	})
	if err != nil {
		return demoseed.Result{}, fmt.Errorf("demo: open seed store: %w", err)
	}
	result, err := demoseed.Generate(selected, cfg, now, func(envelope event.Envelope) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return store.Append(ctx, envelope)
	})
	if closeErr := store.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return demoseed.Result{}, fmt.Errorf("demo: seed synthetic history: %w", err)
	}
	return result, nil
}
