package accounts

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/stateio"
	"github.com/metaforismo/aegismesh/internal/strictjson"
)

// identityLimit is MaxIdentities; tests lower it to exercise eviction quickly.
var identityLimit = MaxIdentities

// NoGuard disables the last-administrator guard; only the offline CLI uses it.
const NoGuard = -1

// Options supplies trusted configuration facts; nothing here comes from requests.
type Options struct {
	// Tenants is the declared partition set. When non-empty, authentication
	// only grants declared memberships and creation/patch may name only these.
	Tenants []string
	// LocalTenant is the partition whose administrators administer accounts.
	LocalTenant string
	// Reserved holds config operator names that managed names may not reuse.
	Reserved []string
	// Now is a trusted clock; nil uses time.Now.
	Now func() time.Time
}

type digestRef struct {
	account string
	key     string
	digest  [32]byte
}

// Store owns the bounded snapshot and the in-memory digest registry.
type Store struct {
	mu         sync.Mutex
	root       *os.Root
	data       snapshot
	refs       []digestRef
	dirty      bool
	disk       [32]byte
	diskExists bool
	identity   []byte
	opts       Options
	now        func() time.Time
}

// Create carries the fields of a new managed account.
type Create struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Role    string   `json:"role"`
	Tenants []string `json:"tenants"`
}

// Patch carries optional account changes; an empty patch is invalid.
type Patch struct {
	Name    *string   `json:"name"`
	Role    *string   `json:"role"`
	Tenants *[]string `json:"tenants"`
	Status  *string   `json:"status"`
}

// Change reports which fields an update changed and whether existing
// credentials and sessions must be cut off (role, tenants or status changed).
type Change struct {
	Fields []string
	Revoke bool
}

// Open opens dir (created private when absent) and loads the snapshot strictly.
// A corrupt, oversized or interrupted snapshot fails startup instead of being reset.
func Open(dir string, opts Options) (*Store, error) {
	root, err := stateio.Open(dir)
	if err != nil {
		return nil, err
	}
	store, err := load(root, opts)
	if err != nil {
		root.Close()
		return nil, err
	}
	return store, nil
}

// OpenExisting loads a store without creating its directory; the offline CLI uses it.
func OpenExisting(dir string, opts Options) (*Store, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("accounts store %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, errors.New("accounts store must be a directory")
	}
	return Open(dir, opts)
}

func load(root *os.Root, opts Options) (*Store, error) {
	if _, err := root.Lstat(FileName + ".tmp"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("console accounts: inspect stale accounts.json.tmp before startup")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	store := &Store{root: root, opts: opts, now: now}
	body, err := stateio.Read(root, FileName, MaxStoreBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		store.data = snapshot{
			Schema: Schema, IdentityKey: hex.EncodeToString(key), Accounts: []Account{},
			Identities: []Identity{}, Preferences: map[string]Preferences{},
		}
	case err != nil:
		return nil, fmt.Errorf("inspect %s before restart: %w", FileName, err)
	default:
		store.data, err = decode(body)
		if err != nil {
			return nil, fmt.Errorf("%w: %s is corrupt or over quota; inspect state and restore a verified backup",
				ErrInvalid, FileName)
		}
		store.disk, store.diskExists = sha256.Sum256(body), true
	}
	store.identity, _ = hex.DecodeString(store.data.IdentityKey)
	store.reindex()
	return store, nil
}

// Check strictly parses and validates an encoded snapshot without loading it.
func Check(body []byte) error {
	_, err := decode(body)
	return err
}

// decode strictly parses and validates a snapshot: duplicate keys, unknown
// fields, trailing data, out-of-vocabulary values and quota overruns fail.
func decode(body []byte) (snapshot, error) {
	if len(body) > MaxStoreBytes || !strictjson.ValidObject(body) {
		return snapshot{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var decoded snapshot
	if err := decoder.Decode(&decoded); err != nil {
		return snapshot{}, ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return snapshot{}, ErrInvalid
	}
	if err := validate(decoded); err != nil {
		return snapshot{}, err
	}
	return decoded, nil
}

func (s *Store) reindex() {
	refs := make([]digestRef, 0, len(s.data.Accounts)*2)
	for _, account := range s.data.Accounts {
		for _, key := range account.Keys {
			raw, _ := hex.DecodeString(key.SHA256)
			ref := digestRef{account: account.ID, key: key.ID}
			copy(ref.digest[:], raw)
			refs = append(refs, ref)
		}
	}
	s.refs = refs
}

// save validates, checks for foreign writers, then atomically replaces the snapshot.
func (s *Store) save(next snapshot) error {
	if err := validate(next); err != nil {
		return err
	}
	body, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(body) > MaxStoreBytes {
		return ErrLimit
	}
	current, err := stateio.Read(s.root, FileName, MaxStoreBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if s.diskExists {
			return ErrModified
		}
	case err != nil:
		return ErrModified
	default:
		if !s.diskExists || sha256.Sum256(current) != s.disk {
			return ErrModified
		}
	}
	if err = stateio.Atomic(s.root, FileName, body); err != nil {
		return err
	}
	s.data, s.disk, s.diskExists, s.dirty = next, sha256.Sum256(body), true, false
	s.reindex()
	return nil
}

func (s *Store) clock() time.Time { return s.now().UTC().Truncate(time.Millisecond) }

func (s *Store) declared(names []string) bool {
	if !validTenants(names) {
		return false
	}
	if len(s.opts.Tenants) == 0 {
		return true
	}
	for _, name := range names {
		if !slices.Contains(s.opts.Tenants, name) {
			return false
		}
	}
	return true
}

func (s *Store) nameTaken(data snapshot, name, except string) bool {
	folded := strings.ToLower(name)
	for _, reserved := range s.opts.Reserved {
		if strings.ToLower(reserved) == folded {
			return true
		}
	}
	for _, account := range data.Accounts {
		if account.ID != except && strings.ToLower(account.Name) == folded {
			return true
		}
	}
	return false
}

func randomHex(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func find(data snapshot, id string) int {
	for i, account := range data.Accounts {
		if account.ID == id {
			return i
		}
	}
	return -1
}

// usableAdmins counts managed accounts that can administer: active, admin,
// member of the local tenant and holding at least one usable key.
func (s *Store) usableAdmins(data snapshot, now time.Time) int {
	local := s.opts.LocalTenant
	if local == "" {
		local = "default"
	}
	count := 0
	for _, account := range data.Accounts {
		if account.Status == StatusActive && account.Role == "admin" && slices.Contains(account.Tenants, local) &&
			account.ActiveKeys(now) > 0 {
			count++
		}
	}
	return count
}

// UsableAdmins counts managed accounts that can currently administer.
func (s *Store) UsableAdmins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usableAdmins(s.data, s.now())
}

func (s *Store) guard(before, after snapshot, configAdmins int) error {
	if configAdmins == NoGuard {
		return nil
	}
	now := s.now()
	if configAdmins+s.usableAdmins(before, now) > 0 && configAdmins+s.usableAdmins(after, now) == 0 {
		return ErrLastAdmin
	}
	return nil
}

// Create validates and persists a new active account without keys.
func (s *Store) Create(input Create, actor string) (Account, error) {
	if !ValidName(input.Name) || !ValidKind(input.Kind) || !ValidRole(input.Role) || !validActor(actor) {
		return Account{}, ErrInvalid
	}
	if !s.declared(input.Tenants) {
		return Account{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.Accounts) >= MaxAccounts {
		return Account{}, ErrLimit
	}
	if s.nameTaken(s.data, input.Name, "") {
		return Account{}, ErrNameTaken
	}
	suffix, err := randomHex(8)
	if err != nil {
		return Account{}, err
	}
	if find(s.data, "acc_"+suffix) >= 0 {
		return Account{}, ErrLimit
	}
	now := s.clock()
	account := Account{
		ID: "acc_" + suffix, Name: input.Name, Kind: input.Kind, Role: input.Role,
		Tenants: slices.Clone(input.Tenants), Status: StatusActive, CreatedAt: now, CreatedBy: actor,
		UpdatedAt: now, Keys: []Key{},
	}
	next := s.data.clone()
	next.Accounts = append(next.Accounts, account)
	if err := s.save(next); err != nil {
		return Account{}, err
	}
	return cloneAccount(account), nil
}

// List returns copies of every managed account, newest first.
func (s *Store) List() []Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Account, 0, len(s.data.Accounts))
	for _, account := range s.data.Accounts {
		out = append(out, cloneAccount(account))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// Get returns a copy of one managed account.
func (s *Store) Get(id string) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := find(s.data, id)
	if index < 0 {
		return Account{}, ErrNotFound
	}
	return cloneAccount(s.data.Accounts[index]), nil
}

// Update applies a validated patch. configAdmins counts usable config-file
// administrators for the last-administrator guard (NoGuard disables it).
func (s *Store) Update(id string, patch Patch, actor string, configAdmins int) (Account, Change, error) {
	if patch.Name == nil && patch.Role == nil && patch.Tenants == nil && patch.Status == nil {
		return Account{}, Change{}, ErrInvalid
	}
	if patch.Name != nil && !ValidName(*patch.Name) || patch.Role != nil && !ValidRole(*patch.Role) ||
		patch.Tenants != nil && !s.declared(*patch.Tenants) ||
		patch.Status != nil && *patch.Status != StatusActive && *patch.Status != StatusDisabled || !validActor(actor) {
		return Account{}, Change{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index := find(s.data, id)
	if index < 0 {
		return Account{}, Change{}, ErrNotFound
	}
	next := s.data.clone()
	account := &next.Accounts[index]
	change := Change{Fields: []string{}}
	if patch.Name != nil && *patch.Name != account.Name {
		if s.nameTaken(next, *patch.Name, id) {
			return Account{}, Change{}, ErrNameTaken
		}
		account.Name = *patch.Name
		change.Fields = append(change.Fields, "name")
	}
	if patch.Role != nil && *patch.Role != account.Role {
		account.Role = *patch.Role
		change.Fields = append(change.Fields, "role")
		change.Revoke = true
	}
	if patch.Tenants != nil && !slices.Equal(*patch.Tenants, account.Tenants) {
		account.Tenants = slices.Clone(*patch.Tenants)
		change.Fields = append(change.Fields, "tenants")
		change.Revoke = true
	}
	if patch.Status != nil && *patch.Status != account.Status {
		account.Status = *patch.Status
		change.Fields = append(change.Fields, "status")
		change.Revoke = true
	}
	if len(change.Fields) == 0 {
		return cloneAccount(s.data.Accounts[index]), change, nil
	}
	if err := s.guard(s.data, next, configAdmins); err != nil {
		return Account{}, Change{}, err
	}
	account.UpdatedAt = s.clock()
	result := cloneAccount(*account)
	if err := s.save(next); err != nil {
		return Account{}, Change{}, err
	}
	return result, change, nil
}

// CreateKey mints a key for an active account and returns the token exactly once.
// days of 0 selects DefaultKeyDays. When the account already holds the maximum,
// the longest-inactive revoked or expired key is pruned; ten active keys is a limit.
func (s *Store) CreateKey(accountID, label string, days int, actor string) (KeyView, string, error) {
	if days == 0 {
		days = DefaultKeyDays
	}
	if !ValidLabel(label) || days < 1 || days > MaxKeyDays || !validActor(actor) {
		return KeyView{}, "", ErrInvalid
	}
	random, err := auth.Token()
	if err != nil {
		return KeyView{}, "", err
	}
	token := TokenPrefix + random
	suffix, err := randomHex(6)
	if err != nil {
		return KeyView{}, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index := find(s.data, accountID)
	if index < 0 {
		return KeyView{}, "", ErrNotFound
	}
	if s.data.Accounts[index].Status != StatusActive {
		return KeyView{}, "", ErrDisabled
	}
	for _, ref := range s.refs {
		if ref.key == "key_"+suffix {
			return KeyView{}, "", ErrLimit
		}
	}
	now := s.clock()
	next := s.data.clone()
	account := &next.Accounts[index]
	if len(account.Keys) >= MaxKeysPerAccount {
		prune := -1
		var oldest time.Time
		for i, key := range account.Keys {
			if key.Status(now) == KeyActive {
				continue
			}
			ended := key.ExpiresAt
			if key.RevokedAt != nil && key.RevokedAt.Before(ended) {
				ended = *key.RevokedAt
			}
			if prune < 0 || ended.Before(oldest) {
				prune, oldest = i, ended
			}
		}
		if prune < 0 {
			return KeyView{}, "", ErrLimit
		}
		account.Keys = slices.Delete(account.Keys, prune, prune+1)
	}
	key := Key{
		ID: "key_" + suffix, Label: label, Prefix: token[:len(TokenPrefix)+4], SHA256: auth.Digest(token),
		CreatedAt: now, CreatedBy: actor, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour),
	}
	account.Keys = append(account.Keys, key)
	account.UpdatedAt = now
	if err := s.save(next); err != nil {
		return KeyView{}, "", err
	}
	return key.View(now), token, nil
}

// RevokeKey revokes one key; revoking an already revoked key changes nothing.
func (s *Store) RevokeKey(accountID, keyID, actor string, configAdmins int) (KeyView, bool, error) {
	if !validActor(actor) {
		return KeyView{}, false, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index := find(s.data, accountID)
	if index < 0 {
		return KeyView{}, false, ErrNotFound
	}
	next := s.data.clone()
	account := &next.Accounts[index]
	now := s.clock()
	for i := range account.Keys {
		key := &account.Keys[i]
		if key.ID != keyID {
			continue
		}
		if key.RevokedAt != nil {
			return key.View(now), false, nil
		}
		key.RevokedAt = &now
		account.UpdatedAt = now
		if err := s.guard(s.data, next, configAdmins); err != nil {
			return KeyView{}, false, err
		}
		view := key.View(now)
		if err := s.save(next); err != nil {
			return KeyView{}, false, err
		}
		return view, true, nil
	}
	return KeyView{}, false, ErrNotFound
}

// Match implements auth.Registry. It compares digest against every stored key
// in constant time per entry, then fails closed for revoked or expired keys,
// disabled accounts and accounts without a declared membership. A successful
// match records last_used_at at most once per LastUsedResolution, in memory;
// Flush persists it.
func (s *Store) Match(digest [32]byte) (auth.Principal, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	accountID, keyID := "", ""
	matched := 0
	for _, ref := range s.refs {
		equal := subtle.ConstantTimeCompare(digest[:], ref.digest[:])
		if equal == 1 {
			accountID, keyID = ref.account, ref.key
		}
		matched |= equal
	}
	if matched != 1 {
		return auth.Principal{}, time.Time{}, false
	}
	index := find(s.data, accountID)
	if index < 0 {
		return auth.Principal{}, time.Time{}, false
	}
	account := &s.data.Accounts[index]
	now := s.now().UTC()
	for i := range account.Keys {
		key := &account.Keys[i]
		if key.ID != keyID {
			continue
		}
		if account.Status != StatusActive || key.Status(now) != KeyActive {
			return auth.Principal{}, time.Time{}, false
		}
		tenants := []string{}
		for _, name := range account.Tenants {
			if len(s.opts.Tenants) == 0 || slices.Contains(s.opts.Tenants, name) {
				tenants = append(tenants, name)
			}
		}
		if len(tenants) == 0 {
			return auth.Principal{}, time.Time{}, false
		}
		if key.LastUsedAt == nil || now.Sub(*key.LastUsedAt) >= LastUsedResolution {
			stamp := now.Truncate(time.Millisecond)
			key.LastUsedAt = &stamp
			seen := stamp
			account.LastSeenAt = &seen
			s.dirty = true
		}
		return auth.Principal{
			ID: account.ID, Source: auth.SourceManaged, Kind: account.Kind, KeyID: key.ID,
			AuthMethod: "token", Name: account.Name, Role: account.Role,
			Tenant: tenants[0], Tenants: tenants,
		}, key.ExpiresAt, true
	}
	return auth.Principal{}, time.Time{}, false
}

// Flush persists pending last_used_at updates.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.save(s.data.clone())
}

// IdentityID derives the stable OIDC principal id from issuer and subject with
// the store's persisted key; neither value is stored or exposed.
func (s *Store) IdentityID(issuer, subject string) string {
	mac := hmac.New(sha256.New, s.identity)
	mac.Write([]byte(issuer))
	mac.Write([]byte{0})
	mac.Write([]byte(subject))
	return "oidc:" + hex.EncodeToString(mac.Sum(nil))[:12]
}

// SeenIdentity records an OIDC sign-in in the bounded directory and returns its id.
// When the directory is full, the least recently seen identity and its preferences are evicted.
func (s *Store) SeenIdentity(issuer, subject, name, role string, tenants []string) (string, error) {
	id := s.IdentityID(issuer, subject)
	if !printable(name, 1, 64) {
		name = id
	}
	if !ValidRole(role) || !validTenants(tenants) {
		return "", ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	next := s.data.clone()
	found := false
	for i := range next.Identities {
		identity := &next.Identities[i]
		if identity.ID == id {
			identity.Name, identity.Role, identity.Tenants, identity.LastSeenAt = name, role, slices.Clone(tenants), now
			found = true
		}
	}
	if !found {
		if len(next.Identities) >= identityLimit {
			oldest := 0
			for i, identity := range next.Identities {
				if identity.LastSeenAt.Before(next.Identities[oldest].LastSeenAt) {
					oldest = i
				}
			}
			delete(next.Preferences, next.Identities[oldest].ID)
			next.Identities = slices.Delete(next.Identities, oldest, oldest+1)
		}
		next.Identities = append(next.Identities, Identity{
			ID: id, Name: name, Role: role, Tenants: slices.Clone(tenants), FirstSeenAt: now, LastSeenAt: now,
		})
	}
	return id, s.save(next)
}

// Identities returns the seen OIDC identities, most recently seen first.
func (s *Store) Identities() []Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Identity, 0, len(s.data.Identities))
	for _, identity := range s.data.Identities {
		identity.Tenants = slices.Clone(identity.Tenants)
		out = append(out, identity)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeenAt.Equal(out[j].LastSeenAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].LastSeenAt.After(out[j].LastSeenAt)
	})
	return out
}

// Preferences returns stored preferences, or the defaults.
func (s *Store) Preferences(principalID string) Preferences {
	s.mu.Lock()
	defer s.mu.Unlock()
	if preferences, ok := s.data.Preferences[principalID]; ok {
		return preferences
	}
	return DefaultPreferences
}

// SetPreferences validates and persists the complete preference record.
func (s *Store) SetPreferences(principalID string, preferences Preferences) error {
	if !ValidPrincipalID(principalID) || !preferences.Valid() {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.data.Preferences[principalID]; ok && current == preferences {
		return nil
	}
	if _, ok := s.data.Preferences[principalID]; !ok && len(s.data.Preferences) >= MaxPreferences {
		return ErrLimit
	}
	next := s.data.clone()
	next.Preferences[principalID] = preferences
	return s.save(next)
}

// Close persists pending usage timestamps and releases the directory handle.
func (s *Store) Close() error {
	flushErr := s.Flush()
	closeErr := s.root.Close()
	return errors.Join(flushErr, closeErr)
}
