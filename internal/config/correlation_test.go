package config

import (
	"strings"
	"testing"
)

func minimalValidConfig(t *testing.T) *Config {
	t.Helper()
	c, err := Load(writeTemp(t, "mesh.yaml", minimalValid))
	if err != nil {
		t.Fatalf("Load minimal: %v", err)
	}
	return c
}

func TestCorrelationDefaultsAppliedWhenAbsent(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("baseline with no correlation section must stay valid: %v", err)
	}
	if cfg.Correlation.WindowSeconds != DefaultCorrelationWindowSecs ||
		cfg.Correlation.PerSourceEvents != DefaultCorrelationPerSrcEvents ||
		cfg.Correlation.MaxSources != DefaultCorrelationMaxSources {
		t.Fatalf("defaults not applied: %+v", cfg.Correlation)
	}
	if cfg.Correlation.IsEnabled() {
		t.Fatal("correlation must default to off")
	}
}

func TestCorrelationValidSectionPasses(t *testing.T) {
	on := true
	cfg := minimalValidConfig(t)
	cfg.Correlation = Correlation{
		Enabled:         &on,
		DisabledRules:   []string{"COR-004"},
		WindowSeconds:   120,
		PerSourceEvents: 32,
		MaxSources:      1024,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid correlation section rejected: %v", err)
	}
}

func TestCorrelationUnknownDisabledRuleRejected(t *testing.T) {
	on := true
	cfg := minimalValidConfig(t)
	cfg.Correlation = Correlation{Enabled: &on, DisabledRules: []string{"COR-999"}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "COR-999") {
		t.Fatalf("unknown rule id must be named in the error: %v", err)
	}
}

func TestCorrelationBoundsRejected(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Correlation)
	}{
		{"window too small", func(c *Correlation) { c.WindowSeconds = 30 }},
		{"window too large", func(c *Correlation) { c.WindowSeconds = 7200 }},
		{"ring too small", func(c *Correlation) { c.PerSourceEvents = 4 }},
		{"ring too large", func(c *Correlation) { c.PerSourceEvents = 4096 }},
		{"sources too few", func(c *Correlation) { c.MaxSources = 10 }},
		{"sources too many", func(c *Correlation) { c.MaxSources = 1 << 20 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := minimalValidConfig(t)
			tc.mut(&cfg.Correlation)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("%s must be rejected", tc.name)
			}
		})
	}
}

func TestCorrelationDisabledSectionStillValidated(t *testing.T) {
	off := false
	cfg := minimalValidConfig(t)
	cfg.Correlation = Correlation{Enabled: &off, WindowSeconds: 5} // invalid even while off
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid values must not hide behind enabled=false")
	}
}
