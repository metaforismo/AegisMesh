package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/metaforismo/aegismesh/internal/ext"
)

// runVerify bridges the ext command to manifest verification.
func runVerify(manifestPath, pubKeyPath string) (*ext.VerifyResult, error) {
	m, err := ext.LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	pubHex := ""
	if pubKeyPath != "" {
		b, err := os.ReadFile(pubKeyPath) //nolint:gosec // explicit operator path
		if err != nil {
			return nil, fmt.Errorf("read pubkey: %v", err)
		}
		pubHex = trimSpace(string(b))
	}
	res, err := ext.Verify(m, pubHex)
	if err != nil && res == nil {
		return nil, err
	}
	return res, err
}

// runExtension verifies then executes one call against an extension through
// the out-of-process host.
func runExtension(ctx context.Context, manifestPath, input, pubKeyPath string) (map[string]any, error) {
	m, err := ext.LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	pubHex := ""
	if pubKeyPath != "" {
		b, err := os.ReadFile(pubKeyPath) //nolint:gosec // explicit operator path
		if err != nil {
			return nil, fmt.Errorf("read pubkey: %v", err)
		}
		pubHex = trimSpace(string(b))
	}
	if _, err := ext.Verify(m, pubHex); err != nil {
		return nil, fmt.Errorf("verification failed; refusing to run: %v", err)
	}

	h, err := ext.Start(ctx, m, func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	})
	if err != nil {
		return nil, err
	}
	defer h.Stop()

	params := json.RawMessage(input)
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	result, err := h.Call(ctx, "respond", params)
	if err != nil {
		return nil, err
	}
	var parsed any
	if json.Unmarshal(result, &parsed) == nil {
		return map[string]any{"extension": m.Name, "version": m.Version, "result": parsed}, nil
	}
	return map[string]any{"extension": m.Name, "version": m.Version, "result_raw": string(result)}, nil
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
