package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/egress"
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

// classifyProviderEndpoint returns the egress class label for the configured
// LLM endpoint plus its normalized base URL. Shared by doctor and validate so
// both commands describe the same policy with the same words.
func classifyProviderEndpoint(cfg *config.Config) (class, baseURL string) {
	if cfg.LLM.Provider == "" || cfg.LLM.Provider == "local" {
		return "none (local deterministic provider)", ""
	}
	pol := egress.Policy{
		AllowLoopback: cfg.LLM.Provider == "ollama",
		AllowPrivate:  cfg.Security.AllowPrivateLLMEgress,
	}
	u, err := egress.ValidateURL(pol, cfg.LLM.BaseURL)
	if err != nil {
		return "DENIED by egress policy: " + err.Error(), cfg.LLM.BaseURL
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		switch {
		case ip.IsLoopback():
			return "loopback endpoint", u.String()
		case ip.IsPrivate():
			return "private gateway (opt-in honored)", u.String()
		}
	} else if strings.EqualFold(host, "localhost") {
		return "loopback endpoint", u.String()
	}
	return "public https endpoint", u.String()
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

// classifyWebhookEndpoint returns the egress class label for the configured
// webhook collector plus its parsed URL. Shared by doctor and validate.
func classifyWebhookEndpoint(cfg *config.Config) (string, *url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.Webhook.URL))
	if err != nil {
		return "", nil, err
	}
	pol := egress.Policy{
		AllowLoopback: cfg.Webhook.AllowLoopbackHTTP,
		AllowPrivate:  cfg.Security.AllowPrivateLLMEgress,
	}
	vu, err := egress.ValidateURL(pol, cfg.Webhook.URL)
	if err != nil {
		return "DENIED by egress policy: " + err.Error(), u, err
	}
	host := vu.Hostname()
	class := "public https endpoint"
	if ip := net.ParseIP(host); ip != nil {
		switch {
		case ip.IsLoopback():
			class = "loopback endpoint (dev mode)"
		case ip.IsPrivate():
			class = "private gateway (opt-in honored)"
		}
	} else if strings.EqualFold(host, "localhost") {
		class = "loopback endpoint (dev mode)"
	}
	return class, vu, nil
}
