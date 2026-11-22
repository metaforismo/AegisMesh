package investigations

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/metaforismo/aegismesh/internal/console/stateio"
)

// ReadOpenCount reads fixed-name state without creating directories or probing writes.
// A missing directory means annotations are unavailable; an empty existing store counts zero.
func ReadOpenCount(dir string) (*int, error) {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if _, err := root.Lstat("investigations.json.tmp"); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrInvalid
	}
	body, err := stateio.Read(root, "investigations.json", stateio.MaxStateBytes)
	count := 0
	if errors.Is(err, os.ErrNotExist) {
		return &count, nil
	}
	if err != nil {
		return nil, err
	}
	var items map[string]Investigation
	if json.Unmarshal(body, &items) != nil || items == nil || len(items) > MaxInvestigations {
		return nil, ErrInvalid
	}
	for id, item := range items {
		if id != item.ID || validate(item) != nil {
			return nil, ErrInvalid
		}
		if item.Status != "closed" {
			count++
		}
	}
	return &count, nil
}
