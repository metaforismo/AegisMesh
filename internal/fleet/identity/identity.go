// Package identity owns a node's local Ed25519 seed in private fixed-name state.
// Private key material never crosses the agent boundary or enters status and logging.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/metaforismo/aegismesh/internal/console/stateio"
)

// Load creates an identity once, or reads an existing owner-only seed without replacing it.
func Load(dir string) (ed25519.PrivateKey, error) {
	root, err := stateio.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("fleet identity: %w", err)
	}
	defer root.Close()
	seed, err := stateio.Read(root, "identity.seed", ed25519.SeedSize)
	if errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err = rand.Read(seed); err != nil {
			return nil, err
		}
		if err = stateio.Atomic(root, "identity.seed", seed); err != nil {
			return nil, fmt.Errorf("fleet identity: save seed: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("fleet identity: read seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("fleet identity: corrupt seed; restore the original identity backup")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
