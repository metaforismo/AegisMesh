package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/metaforismo/aegismesh/internal/config"
)

// Global flag state shared by most commands.
type globals struct {
	jsonOut bool
}

// addGlobalFlags registers flags common to every command.
func addGlobalFlags(fs *flag.FlagSet, g *globals) {
	fs.BoolVar(&g.jsonOut, "json", false, "emit machine-readable JSON output")
}

// loadConfig is the single config entrypoint used by all commands so error
// rendering stays consistent.
func loadConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("%v\nhint: run 'aegismesh init' for a valid example, or check docs/configuration.md", err)
	}
	return cfg, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are rendered by Run() with usage context
	return fs
}

func slogLevel(l string) slog.Level {
	switch l {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
