package tenant

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Prepare migrates a legacy directory by atomic rename, resuming after interruption.
// Only validated configuration names, never request claims, select these directories.
func Prepare(dir string, names []string) (map[string]string, error) {
	return prepare(dir, names, nil)
}

func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("tenant: state directory must be real and mode 0700")
	}
	return nil
}

func syncDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func prepare(dir string, names []string, checkpoint func(string) error) (map[string]string, error) {
	names = Names(names)
	if len(names) > MaxTenants {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			return nil, ErrInvalid
		}
		seen[name] = true
		if _, err := Parse(name); err != nil {
			return nil, err
		}
	}
	dir = filepath.Clean(dir)
	pending := dir + ".tenant-migration"
	destination := filepath.Join(dir, "tenants", Default)
	_, pendingErr := os.Lstat(pending)
	if pendingErr != nil && !errors.Is(pendingErr, os.ErrNotExist) {
		return nil, pendingErr
	}
	if errors.Is(pendingErr, os.ErrNotExist) {
		if err := privateDir(dir); err != nil {
			return nil, err
		}
		_, err := os.Lstat(filepath.Join(dir, "tenants"))
		if errors.Is(err, os.ErrNotExist) {
			if err := legacyState(dir); err != nil {
				return nil, err
			}
			if err := os.Rename(dir, pending); err != nil {
				return nil, err
			}
			if err := syncDir(filepath.Dir(dir)); err != nil {
				return nil, err
			}
			if checkpoint != nil {
				if err := checkpoint("renamed"); err != nil {
					return nil, err
				}
			}
		} else if err != nil {
			return nil, err
		}
	}
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	if err := privateDir(filepath.Join(dir, "tenants")); err != nil {
		return nil, err
	}
	// Persist the new ancestor links before removing the durable legacy backup.
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	if checkpoint != nil {
		if err := checkpoint("prepared"); err != nil {
			return nil, err
		}
	}
	if _, err := os.Lstat(pending); err == nil {
		if err := privateDir(pending); err != nil {
			return nil, err
		}
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("tenant: migration conflict; preserve both directories and inspect")
		}
		if err := os.Rename(pending, destination); err != nil {
			return nil, err
		}
		if err := syncDir(filepath.Join(dir, "tenants")); err != nil {
			return nil, err
		}
		if err := syncDir(filepath.Dir(dir)); err != nil {
			return nil, err
		}
	}
	if checkpoint != nil {
		if err := checkpoint("moved"); err != nil {
			return nil, err
		}
	}
	paths := make(map[string]string, len(names))
	for _, name := range names {
		path := filepath.Join(dir, "tenants", name)
		if err := privateDir(path); err != nil {
			return nil, fmt.Errorf("tenant state: %w", err)
		}
		paths[name] = path
	}
	if err := syncDir(filepath.Join(dir, "tenants")); err != nil {
		return nil, err
	}
	return paths, syncDir(dir)
}

// Refuse an accidentally selected repository/config/data root before renaming it.
func legacyState(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	entries, err := file.ReadDir(160)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) >= 160 {
		return errors.New("tenant: legacy state entry limit exceeded")
	}
	for _, entry := range entries {
		name := entry.Name()
		known := name == "registry.json" || name == "registry.json.tmp" || name == "investigations.json" ||
			name == "investigations.json.tmp" || name == "audit.jsonl" || name == ".write-probe" ||
			strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".jsonl")
		directory := name == "audit" || name == "evidence"
		if entry.Type()&os.ModeSymlink != 0 || !known && !directory || directory != entry.IsDir() {
			return errors.New("tenant: unexpected legacy state entry; preserve directory and inspect configuration")
		}
	}
	return nil
}
