// Package accounts persists console-managed accounts, their API key digests,
// the directory of seen OIDC identities and per-principal UI preferences.
//
// The store is a single versioned JSON snapshot under a private os.Root with a
// fixed file name, replaced atomically. Request data never selects a path.
// Config-file operators are never stored or changed here: they remain the
// authoritative break-glass identities. Custom roles combine only catalogue
// permissions (package permission), so no record can grant more than admin.
package accounts

import (
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/console/permission"
	"github.com/metaforismo/aegismesh/internal/console/tenant"
)

// Fixed names and bounds.
const (
	// FileName is the only state file this package writes, besides its fixed .tmp sibling.
	FileName = "accounts.json"
	// Schema identifies the snapshot format written by this version.
	Schema = "aegismesh.console.accounts/v2"
	// SchemaV1 is the round-5 format without custom roles; it is migrated on open.
	SchemaV1 = "aegismesh.console.accounts/v1"
	// BackupV1 keeps the pre-migration v1 snapshot for a downgrade.
	BackupV1 = "accounts.v1.json"
	// MaxRoles bounds custom roles (the three built-in roles are not stored).
	MaxRoles = 32
	// MaxRoleNameRunes bounds role names.
	MaxRoleNameRunes = 40
	// MaxRoleDescriptionRunes bounds role descriptions.
	MaxRoleDescriptionRunes = 200
	// MaxAccounts bounds managed accounts.
	MaxAccounts = 200
	// MaxKeysPerAccount bounds stored keys per account, including revoked and expired ones.
	MaxKeysPerAccount = 10
	// MaxIdentities bounds the directory of seen OIDC identities (least recently seen is evicted).
	MaxIdentities = 1000
	// MaxPreferences bounds stored preference records.
	MaxPreferences = MaxAccounts + 32 + MaxIdentities
	// MaxNameRunes bounds account display names.
	MaxNameRunes = 80
	// MaxLabelRunes bounds key labels.
	MaxLabelRunes = 64
	// DefaultKeyDays is the expiry applied when none is requested.
	DefaultKeyDays = 90
	// MaxKeyDays is the longest allowed key lifetime.
	MaxKeyDays = 365
	// MaxStoreBytes caps the encoded snapshot.
	MaxStoreBytes = 4 << 20
	// TokenPrefix marks managed API keys.
	TokenPrefix = "amk_"
	// LastUsedResolution limits last_used_at updates to one per key per interval.
	LastUsedResolution = time.Minute
)

// Account and key states.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
	KeyActive      = "active"
	KeyExpired     = "expired"
	KeyRevoked     = "revoked"
)

// Errors map to fixed HTTP outcomes in the console.
var (
	// ErrInvalid marks invalid fields or a corrupt snapshot.
	ErrInvalid = errors.New("accounts: invalid")
	// ErrNotFound marks an unknown account or key.
	ErrNotFound = errors.New("accounts: not found")
	// ErrLimit marks an exhausted count or byte quota.
	ErrLimit = errors.New("accounts: quota reached")
	// ErrNameTaken marks a display name already used by another account or operator.
	ErrNameTaken = errors.New("accounts: name already in use")
	// ErrLastAdmin marks a change that would leave no usable administrator.
	ErrLastAdmin = errors.New("accounts: change would leave no active administrator")
	// ErrDisabled marks an operation that needs an active account.
	ErrDisabled = errors.New("accounts: account is disabled")
	// ErrBuiltin marks an attempt to change or delete a built-in role.
	ErrBuiltin = errors.New("accounts: built-in roles cannot be changed")
	// ErrInUse marks a role that is still assigned.
	ErrInUse = errors.New("accounts: role is assigned")
	// ErrNewer marks a snapshot written by a newer version.
	ErrNewer = errors.New("accounts: state was written by a newer AegisMesh version")
	// ErrModified marks a snapshot changed by another writer since this process loaded it.
	ErrModified = errors.New("accounts: state changed outside this process; restart the console")
)

// Key is a persisted API key record. SHA256 never leaves the store.
type Key struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Prefix     string     `json:"prefix"`
	SHA256     string     `json:"sha256"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// Account is a persisted managed account.
type Account struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	Role       string     `json:"role"`
	Tenants    []string   `json:"tenants"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	Keys       []Key      `json:"keys"`
}

// Identity is a seen OIDC identity. Issuer and subject are not stored; ID is a keyed hash.
type Identity struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	Tenants     []string  `json:"tenants"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// Preferences is the fixed per-principal UI preference schema.
type Preferences struct {
	Timezone      string `json:"timezone"`
	DefaultWindow string `json:"default_window"`
	Density       string `json:"density"`
	Theme         string `json:"theme"`
	ReduceMotion  string `json:"reduce_motion"`
}

// DefaultPreferences is returned for principals that never saved preferences.
var DefaultPreferences = Preferences{
	Timezone: "utc", DefaultWindow: "24h", Density: "comfortable", Theme: "system", ReduceMotion: "system",
}

// KeyView is the API projection of a key: no digest, with derived status.
type KeyView struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	Status     string     `json:"status"`
}

// Role is a persisted custom role: a named, sorted set of catalogue permissions.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// snapshot is the complete persisted document. Roles is absent in v1.
type snapshot struct {
	Schema      string                 `json:"schema"`
	IdentityKey string                 `json:"identity_key"`
	Accounts    []Account              `json:"accounts"`
	Identities  []Identity             `json:"oidc_identities"`
	Preferences map[string]Preferences `json:"preferences"`
	Roles       []Role                 `json:"roles"`
}

var (
	accountIDPattern = regexp.MustCompile(`^acc_[0-9a-f]{16}$`)
	roleIDPattern    = regexp.MustCompile(`^role_[0-9a-f]{12}$`)
	keyIDPattern     = regexp.MustCompile(`^key_[0-9a-f]{12}$`)
	oidcIDPattern    = regexp.MustCompile(`^oidc:[0-9a-f]{12}$`)
	configIDPattern  = regexp.MustCompile(`^cfg:[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)
	prefixPattern    = regexp.MustCompile(`^amk_[A-Za-z0-9_-]{4}$`)
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidAccountID reports the managed account id grammar.
func ValidAccountID(id string) bool { return accountIDPattern.MatchString(id) }

// ValidKeyID reports the key id grammar.
func ValidKeyID(id string) bool { return keyIDPattern.MatchString(id) }

// ValidPrincipalID reports any of the three stable principal id grammars.
func ValidPrincipalID(id string) bool {
	return accountIDPattern.MatchString(id) || oidcIDPattern.MatchString(id) || configIDPattern.MatchString(id)
}

// ValidName accepts 1..80 printable runes without surrounding whitespace.
func ValidName(name string) bool {
	return printable(name, 1, MaxNameRunes)
}

// ValidLabel accepts 1..64 printable runes without surrounding whitespace.
func ValidLabel(label string) bool {
	return printable(label, 1, MaxLabelRunes)
}

func printable(text string, min, max int) bool {
	if !utf8.ValidString(text) || strings.TrimSpace(text) != text {
		return false
	}
	count := utf8.RuneCountInString(text)
	if count < min || count > max {
		return false
	}
	for _, r := range text {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// ValidRole accepts only the fixed built-in roles (config operators and OIDC identities).
func ValidRole(role string) bool { return permission.IsBuiltin(role) }

// ValidRoleID reports the custom role id grammar.
func ValidRoleID(id string) bool { return roleIDPattern.MatchString(id) }

// ValidRoleName accepts 1..40 printable runes without surrounding whitespace.
func ValidRoleName(name string) bool { return printable(name, 1, MaxRoleNameRunes) }

// ValidRoleDescription accepts 0..200 printable runes without surrounding whitespace.
func ValidRoleDescription(text string) bool { return printable(text, 0, MaxRoleDescriptionRunes) }

// ValidPermissions accepts a sorted, duplicate-free, coherent set of catalogue ids.
func ValidPermissions(ids []string) bool {
	if ids == nil || len(ids) > len(permission.Catalogue()) || !slices.Equal(ids, permission.Normalize(ids)) {
		return false
	}
	for _, id := range ids {
		if !permission.Valid(id) {
			return false
		}
	}
	return permission.Coherent(ids)
}

func cloneRole(role Role) Role {
	role.Permissions = slices.Clone(role.Permissions)
	return role
}

// roleName returns a role's display name, or "" when it does not exist.
func (s snapshot) roleName(id string) string {
	if permission.IsBuiltin(id) {
		return id
	}
	for _, role := range s.Roles {
		if role.ID == id {
			return role.Name
		}
	}
	return ""
}

// permissions resolves a role id to its permission set; unknown → nil.
func (s snapshot) permissions(id string) []string {
	if permission.IsBuiltin(id) {
		return permission.Builtin(id)
	}
	for _, role := range s.Roles {
		if role.ID == id {
			return role.Permissions
		}
	}
	return nil
}

// ValidKind accepts person and service accounts.
func ValidKind(kind string) bool { return kind == "person" || kind == "service" }

// Valid reports whether every preference holds a value from its fixed vocabulary.
func (p Preferences) Valid() bool {
	return (p.Timezone == "utc" || p.Timezone == "local") &&
		(p.DefaultWindow == "1h" || p.DefaultWindow == "24h" || p.DefaultWindow == "7d") &&
		(p.Density == "comfortable" || p.Density == "compact") &&
		(p.Theme == "system" || p.Theme == "dark" || p.Theme == "light") &&
		(p.ReduceMotion == "system" || p.ReduceMotion == "on")
}

func validTenants(names []string) bool {
	if len(names) == 0 || len(names) > tenant.MaxTenants {
		return false
	}
	seen := map[string]bool{}
	for _, name := range names {
		if _, err := tenant.Parse(name); err != nil || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

func validActor(actor string) bool {
	if len(actor) == 0 || len(actor) > 80 {
		return false
	}
	for _, r := range actor {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// Status derives the key state at now.
func (k Key) Status(now time.Time) string {
	switch {
	case k.RevokedAt != nil:
		return KeyRevoked
	case !now.Before(k.ExpiresAt):
		return KeyExpired
	default:
		return KeyActive
	}
}

// View projects a key without its digest.
func (k Key) View(now time.Time) KeyView {
	return KeyView{
		ID: k.ID, Label: k.Label, Prefix: k.Prefix, CreatedAt: k.CreatedAt, CreatedBy: k.CreatedBy,
		ExpiresAt: k.ExpiresAt, LastUsedAt: cloneTime(k.LastUsedAt), RevokedAt: cloneTime(k.RevokedAt),
		Status: k.Status(now),
	}
}

// ActiveKeys counts keys usable at now.
func (a Account) ActiveKeys(now time.Time) int {
	count := 0
	for _, key := range a.Keys {
		if key.Status(now) == KeyActive {
			count++
		}
	}
	return count
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func cloneAccount(account Account) Account {
	account.Tenants = slices.Clone(account.Tenants)
	account.LastSeenAt = cloneTime(account.LastSeenAt)
	keys := make([]Key, 0, len(account.Keys))
	for _, key := range account.Keys {
		key.LastUsedAt = cloneTime(key.LastUsedAt)
		key.RevokedAt = cloneTime(key.RevokedAt)
		keys = append(keys, key)
	}
	account.Keys = keys
	return account
}

func (s snapshot) clone() snapshot {
	next := snapshot{
		Schema: s.Schema, IdentityKey: s.IdentityKey,
		Accounts:    make([]Account, 0, len(s.Accounts)),
		Identities:  make([]Identity, 0, len(s.Identities)),
		Preferences: make(map[string]Preferences, len(s.Preferences)),
		Roles:       make([]Role, 0, len(s.Roles)),
	}
	for _, role := range s.Roles {
		next.Roles = append(next.Roles, cloneRole(role))
	}
	for _, account := range s.Accounts {
		next.Accounts = append(next.Accounts, cloneAccount(account))
	}
	for _, identity := range s.Identities {
		identity.Tenants = slices.Clone(identity.Tenants)
		next.Identities = append(next.Identities, identity)
	}
	for id, preferences := range s.Preferences {
		next.Preferences[id] = preferences
	}
	return next
}

func validate(s snapshot) error {
	key, err := hex.DecodeString(s.IdentityKey)
	if s.Schema != Schema || err != nil || len(key) != 32 || s.Accounts == nil || s.Identities == nil ||
		s.Preferences == nil || s.Roles == nil || len(s.Roles) > MaxRoles || len(s.Accounts) > MaxAccounts || len(s.Identities) > MaxIdentities ||
		len(s.Preferences) > MaxPreferences {
		return ErrInvalid
	}
	ids := map[string]bool{}
	roleNames := map[string]bool{permission.Viewer: true, permission.Analyst: true, permission.Admin: true}
	for _, role := range s.Roles {
		folded := strings.ToLower(role.Name)
		if !roleIDPattern.MatchString(role.ID) || ids[role.ID] || !ValidRoleName(role.Name) || roleNames[folded] ||
			!ValidRoleDescription(role.Description) || !ValidPermissions(role.Permissions) ||
			role.CreatedAt.IsZero() || role.UpdatedAt.Before(role.CreatedAt) || !validActor(role.CreatedBy) {
			return ErrInvalid
		}
		ids[role.ID], roleNames[folded] = true, true
	}
	names := map[string]bool{}
	keys := map[string]bool{}
	digests := map[string]bool{}
	for _, account := range s.Accounts {
		folded := strings.ToLower(account.Name)
		if !accountIDPattern.MatchString(account.ID) || ids[account.ID] || !ValidName(account.Name) ||
			names[folded] || !ValidKind(account.Kind) || s.roleName(account.Role) == "" || !validTenants(account.Tenants) ||
			(account.Status != StatusActive && account.Status != StatusDisabled) || account.CreatedAt.IsZero() ||
			account.UpdatedAt.Before(account.CreatedAt) || !validActor(account.CreatedBy) ||
			account.Keys == nil || len(account.Keys) > MaxKeysPerAccount {
			return ErrInvalid
		}
		ids[account.ID], names[folded] = true, true
		for _, key := range account.Keys {
			if !keyIDPattern.MatchString(key.ID) || keys[key.ID] || !ValidLabel(key.Label) ||
				!prefixPattern.MatchString(key.Prefix) || !digestPattern.MatchString(key.SHA256) ||
				digests[key.SHA256] || key.CreatedAt.IsZero() || !key.ExpiresAt.After(key.CreatedAt) ||
				key.ExpiresAt.Sub(key.CreatedAt) > MaxKeyDays*24*time.Hour || !validActor(key.CreatedBy) {
				return ErrInvalid
			}
			keys[key.ID], digests[key.SHA256] = true, true
		}
	}
	for _, identity := range s.Identities {
		if !oidcIDPattern.MatchString(identity.ID) || ids[identity.ID] || !printable(identity.Name, 1, 64) ||
			!ValidRole(identity.Role) || !validTenants(identity.Tenants) || identity.FirstSeenAt.IsZero() ||
			identity.LastSeenAt.Before(identity.FirstSeenAt) {
			return ErrInvalid
		}
		ids[identity.ID] = true
	}
	for id, preferences := range s.Preferences {
		if !ValidPrincipalID(id) || !preferences.Valid() {
			return ErrInvalid
		}
	}
	return nil
}
