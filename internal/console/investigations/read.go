package investigations

import (
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
	items, err := decode(body)
	if err != nil {
		return nil, ErrInvalid
	}
	for _, item := range items {
		if item.Status != "closed" {
			count++
		}
	}
	return &count, nil
}
