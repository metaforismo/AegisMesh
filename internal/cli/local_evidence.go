package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/eventexport"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func localEvidence(ctx context.Context, dir string, identities identityFilesFlag, sealed bool, stderr io.Writer) ([]event.Envelope, error) {
	reader, err := identities.openReader(dir, sealed)
	if err != nil {
		return nil, err
	}
	out := []event.Envelope{}
	corrupt := 0
	notices, err := reader.ForEachVerified(func(e event.Envelope) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(out) >= eventexport.MaxEvents {
			return fmt.Errorf("local evidence exceeds 8192 events; narrow the evidence directory")
		}
		if e.Validate() != nil || e.VerifyIntegrity() != nil || !evidenceindex.ValidID(e.ID) {
			return fmt.Errorf("local evidence failed closed: invalid envelope or integrity")
		}
		out = append(out, e)
		return nil
	}, func(_ string, _ error) { corrupt++ })
	if err != nil {
		return nil, err
	}
	if corrupt > 0 {
		return nil, fmt.Errorf("local evidence failed closed: %d malformed lines", corrupt)
	}
	reportOpenSegments(stderr, notices)
	return out, nil
}

func writeLocalOutput(stdout io.Writer, path string, body []byte) error {
	if path == "" {
		_, err := stdout.Write(body)
		return err
	}
	// Exclusive creation avoids replacing evidence or following a pre-existing symlink.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(body)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
