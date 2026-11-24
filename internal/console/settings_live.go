package console

import (
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/settings"
)

// liveSettings holds the effective values of the editable settings, shared by
// every tenant view. It changes only through applySettings.
type liveSettings struct {
	mu             sync.RWMutex
	effective      map[string]string
	overridden     []string
	startupIgnored []string
}

func (l *liveSettings) snapshot() (map[string]string, []string) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return maps.Clone(l.effective), slices.Clone(l.overridden)
}

func (l *liveSettings) value(key string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.effective[key]
}

func (l *liveSettings) ignoredAtStartup() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return slices.Clone(l.startupIgnored)
}

// editing reports whether the console may change the allowlisted settings.
func (s *Server) editing() bool { return s.cfg.SettingsEditing == config.SettingsEditingConsole }

// applySettings resolves file values and, while editing is on and the overlay
// loaded, the stored overrides; then applies them to the live components.
// With editing off the overlay is kept on disk but not applied: the
// configuration file is the only source. At startup, overrides that no longer
// validate are ignored with a warning instead of failing the console.
func (s *Server) applySettings(startup bool) error {
	file := settings.FileValues(s.cfg)
	overlay := map[string]string{}
	if s.editing() {
		overlay = s.overlay.Values()
		if problem := s.overlay.Problem(); problem != "" && startup {
			s.log.Warn("console settings overlay not applied; file values are in effect", "problem", problem)
		}
	}
	effective, overridden, ignored := settings.Resolve(file, overlay)
	if startup {
		for _, key := range ignored {
			s.log.Warn("console settings override ignored: it no longer validates; the file value applies", "key", key)
		}
	}
	ttl, _ := strconv.Atoi(effective[settings.SessionTTL])
	idle, _ := strconv.Atoi(effective[settings.SessionIdle])
	maxDays, _ := strconv.Atoi(effective[settings.KeyMaxDays])
	defaultDays, _ := strconv.Atoi(effective[settings.KeyDefaultDays])
	if err := s.auth.SetTTL(time.Duration(ttl) * time.Second); err != nil {
		return err
	}
	if err := s.auth.SetIdleTimeout(time.Duration(idle) * time.Second); err != nil {
		return err
	}
	if err := s.accounts.SetKeyLimits(maxDays, defaultDays); err != nil {
		return err
	}
	if err := s.accounts.SetDefaultWindow(effective[settings.DefaultWindow]); err != nil {
		return err
	}
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	s.live.effective, s.live.overridden = effective, overridden
	if startup {
		s.live.startupIgnored = ignored
	}
	return nil
}
