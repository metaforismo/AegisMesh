// Package settings owns the console settings overlay: a small, fixed
// allowlist of console-only values that principals with settings.manage may
// override while console.settings_editing is "console", plus accepted posture
// risks and a capped change history.
//
// The overlay is one versioned JSON snapshot under the console state
// directory, replaced atomically and decoded strictly. It never writes the
// config file and nothing request-supplied selects a path or a key outside
// the compiled-in allowlist. Values are validated against the same bounds as
// the config file (or stricter) before they are stored and again before they
// are applied.
package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"github.com/metaforismo/aegismesh/internal/config"
)

// Editable setting keys. posture.accepted is edited through the posture
// acceptance endpoints, never through a generic value.
const (
	SessionTTL       = "console.session_ttl_seconds"
	SessionIdle      = "console.session_idle_seconds"
	KeyMaxDays       = "console.key_max_days"
	KeyDefaultDays   = "console.key_default_days"
	SignInBanner     = "console.sign_in_banner"
	OrganizationName = "console.organization_name"
	DefaultWindow    = "console.default_window"
	PostureAccepted  = "posture.accepted"
)

// Value kinds.
const (
	KindSeconds = "seconds"
	KindDays    = "days"
	KindText    = "text"
	KindEnum    = "enum"
)

// Definition is the fixed description and bounds of one editable key.
type Definition struct {
	Key       string
	Kind      string
	Min       int
	Max       int
	AllowZero bool
	MaxRunes  int
	Multiline bool
	Enum      []string
}

// Definitions lists the editable value keys in application order
// (key_max_days before key_default_days, which is bounded by it).
var Definitions = []Definition{
	{Key: SessionTTL, Kind: KindSeconds, Min: 900, Max: 86400},
	{Key: SessionIdle, Kind: KindSeconds, Min: 300, Max: 86400, AllowZero: true},
	{Key: KeyMaxDays, Kind: KindDays, Min: 1, Max: config.MaxKeyDays},
	{Key: KeyDefaultDays, Kind: KindDays, Min: 1, Max: config.MaxKeyDays},
	{Key: SignInBanner, Kind: KindText, MaxRunes: config.MaxSignInBannerRunes, Multiline: true},
	{Key: OrganizationName, Kind: KindText, MaxRunes: config.MaxOrganizationNameRunes},
	{Key: DefaultWindow, Kind: KindEnum, Enum: []string{"1h", "24h", "7d"}},
}

// Errors map to fixed HTTP outcomes in the console.
var (
	// ErrInvalid marks a value outside its bounds or a malformed request.
	ErrInvalid = errors.New("settings: invalid value")
	// ErrNotEditable marks a key outside the allowlist.
	ErrNotEditable = errors.New("settings: key is not editable in the console")
	// ErrUnavailable marks an overlay that could not be loaded and is not written.
	ErrUnavailable = errors.New("settings: overlay unavailable; inspect settings.json")
	// ErrModified marks an overlay changed by another writer since load.
	ErrModified = errors.New("settings: overlay changed outside this process; restart the console")
	// ErrNewer marks an overlay written by a newer version.
	ErrNewer = errors.New("settings: overlay was written by a newer AegisMesh version")
	// ErrNotFound marks a missing acceptance.
	ErrNotFound = errors.New("settings: not found")
)

// Lookup returns the definition of an editable value key.
func Lookup(key string) (Definition, bool) {
	for _, definition := range Definitions {
		if definition.Key == key {
			return definition, true
		}
	}
	return Definition{}, false
}

// Editable reports whether key is on the allowlist, posture.accepted included.
func Editable(key string) bool {
	_, ok := Lookup(key)
	return ok || key == PostureAccepted
}

// Check validates a canonical value. maxDays bounds key_default_days by the
// effective key_max_days; other keys ignore it.
func (d Definition) Check(value string, maxDays int) error {
	switch d.Kind {
	case KindSeconds, KindDays:
		number, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(number) != value {
			return ErrInvalid
		}
		upper := d.Max
		if d.Key == KeyDefaultDays && maxDays > 0 {
			upper = min(upper, maxDays)
		}
		if number == 0 && d.AllowZero {
			return nil
		}
		if number < d.Min || number > upper {
			return ErrInvalid
		}
	case KindText:
		valid := config.ValidOrganizationName(value)
		if d.Multiline {
			valid = config.ValidBanner(value)
		}
		if !valid {
			return ErrInvalid
		}
	case KindEnum:
		if !slices.Contains(d.Enum, value) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Parse converts a request JSON value to the canonical string form: an
// integer for numeric keys, a string otherwise. Bounds are checked by Check.
func (d Definition) Parse(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	switch d.Kind {
	case KindSeconds, KindDays:
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if decoder.Decode(&value) != nil {
			return "", ErrInvalid
		}
		literal, ok := value.(json.Number)
		if !ok {
			return "", ErrInvalid
		}
		number, err := strconv.Atoi(literal.String())
		if err != nil {
			return "", ErrInvalid
		}
		return strconv.Itoa(number), nil
	default:
		var text string
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &text) != nil {
			return "", ErrInvalid
		}
		return text, nil
	}
}

// FileValues returns the canonical file/env/default values of every editable key.
func FileValues(c config.Console) map[string]string {
	c = c.WithDefaults()
	return map[string]string{
		SessionTTL:       strconv.Itoa(c.SessionTTLSeconds),
		SessionIdle:      strconv.Itoa(c.IdleSeconds()),
		KeyMaxDays:       strconv.Itoa(c.KeyMaxDays),
		KeyDefaultDays:   strconv.Itoa(c.KeyDefaultDays),
		SignInBanner:     c.SignInBanner,
		OrganizationName: c.OrganizationName,
		DefaultWindow:    c.DefaultWindow,
	}
}

// Resolve layers overlay values over file values in definition order and
// returns the effective values, the keys overridden and the overlay keys
// ignored because they no longer validate against the effective values.
func Resolve(file, overlay map[string]string) (map[string]string, []string, []string) {
	effective := make(map[string]string, len(file))
	for key, value := range file {
		effective[key] = value
	}
	overridden, ignored := []string{}, []string{}
	for _, definition := range Definitions {
		value, ok := overlay[definition.Key]
		if !ok {
			continue
		}
		maxDays, _ := strconv.Atoi(effective[KeyMaxDays])
		if definition.Check(value, maxDays) != nil {
			ignored = append(ignored, definition.Key)
			continue
		}
		effective[definition.Key] = value
		overridden = append(overridden, definition.Key)
	}
	// A lowered maximum below the (file) default leaves no valid default:
	// drop the maximum override rather than issue keys longer than allowed.
	maxDays, _ := strconv.Atoi(effective[KeyMaxDays])
	defaultDays, _ := strconv.Atoi(effective[KeyDefaultDays])
	if defaultDays > maxDays && slices.Contains(overridden, KeyMaxDays) {
		effective[KeyMaxDays] = file[KeyMaxDays]
		overridden = slices.DeleteFunc(overridden, func(key string) bool { return key == KeyMaxDays })
		ignored = append(ignored, KeyMaxDays)
	}
	return effective, overridden, ignored
}
