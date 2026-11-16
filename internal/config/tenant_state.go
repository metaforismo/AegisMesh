package config

import (
	"errors"
	"path/filepath"
	"strings"
)

func containsDir(parent, child string) bool {
	parent, _ = filepath.Abs(parent)
	child, _ = filepath.Abs(child)
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (c *Config) validateTenantState() error {
	roots := []string{}
	if c.Console.Enabled {
		roots = append(roots, c.ConsoleStateDir())
	}
	if c.Fleet.Hub.Enabled {
		roots = append(roots, c.FleetStateDir(false))
	}
	for i, root := range roots {
		if c.SourcePath != "" && containsDir(root, filepath.Dir(absClean(c.SourcePath))) {
			return errors.New("config: tenant state cannot contain the configuration directory")
		}
		if c.Fleet.Agent.Enabled && (containsDir(root, c.FleetStateDir(true)) || containsDir(c.FleetStateDir(true), root)) {
			return errors.New("config: tenant state and agent identity directories must be disjoint")
		}
		if containsDir(root, c.Runtime.DataDir) {
			return errors.New("config: tenant state cannot contain the local evidence directory")
		}
		for _, other := range roots[:i] {
			if containsDir(root, other) || containsDir(other, root) {
				return errors.New("config: console and hub state directories must be disjoint")
			}
		}
	}
	return nil
}
