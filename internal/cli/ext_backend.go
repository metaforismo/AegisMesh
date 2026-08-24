package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/ext"
)

const maxExtensionPublicKeyFileBytes = 1024

// runVerify bridges the ext command to manifest verification.
func runVerify(manifestPath, pubKeyPath string) (*ext.VerifyResult, error) {
	m, err := ext.LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	pubHex := ""
	if pubKeyPath != "" {
		pubHex, err = readExtensionPublicKey(pubKeyPath)
		if err != nil {
			return nil, err
		}
	}
	res, err := ext.Verify(m, pubHex)
	if err != nil && res == nil {
		return nil, err
	}
	return res, err
}

// runExtension verifies an observer, sends one synthetic data-only probe, and
// returns only core-owned acknowledgement metadata.
func runExtension(ctx context.Context, manifestPath, input, pubKeyPath string) (map[string]any, error) {
	payload := json.RawMessage(input)
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if !json.Valid(payload) {
		return nil, fmt.Errorf("--input must be one valid JSON value")
	}
	m, err := ext.LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	pubHex := ""
	if pubKeyPath != "" {
		pubHex, err = readExtensionPublicKey(pubKeyPath)
		if err != nil {
			return nil, err
		}
	}
	if _, err := ext.Verify(m, pubHex); err != nil {
		return nil, fmt.Errorf("verification failed; refusing to run: %v", err)
	}

	h, err := ext.Start(ctx, m)
	if err != nil {
		return nil, err
	}
	defer h.Stop()

	const eventID = "extension-probe"
	if err := h.Observe(ctx, ext.Observation{
		EventID:        eventID,
		Time:           time.Unix(0, 0).UTC(),
		Classification: event.ClassificationInteraction,
		Sensor:         event.SensorRef{ID: "extension-probe", Kind: "probe", Listen: "local"},
		Payload:        payload,
	}); err != nil {
		return nil, err
	}
	return map[string]any{
		"extension": m.Name,
		"version":   m.Version,
		"event_id":  eventID,
		"accepted":  true,
		"applied":   false,
	}, nil
}

func readExtensionPublicKey(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // explicit operator CLI path
	if err != nil {
		return "", fmt.Errorf("read pubkey: %v", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxExtensionPublicKeyFileBytes {
		return "", fmt.Errorf("read pubkey: must be a regular file no larger than %d bytes", maxExtensionPublicKeyFileBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxExtensionPublicKeyFileBytes+1))
	if err != nil || len(b) > maxExtensionPublicKeyFileBytes {
		return "", fmt.Errorf("read pubkey: must be no larger than %d bytes", maxExtensionPublicKeyFileBytes)
	}
	return trimSpace(string(b)), nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
