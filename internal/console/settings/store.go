package settings

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/console/stateio"
	"github.com/metaforismo/aegismesh/internal/strictjson"
)

// Fixed names and bounds.
const (
	// FileName is the only state file this package writes, besides its fixed .tmp sibling.
	FileName = "settings.json"
	// Schema identifies the snapshot format.
	Schema = "aegismesh.console.settings/v1"
	// MaxHistory bounds retained changes; the oldest are dropped first.
	MaxHistory = 500
	// MaxAccepted bounds accepted posture checks.
	MaxAccepted = 64
	// MaxReasonRunes bounds change and acceptance reasons.
	MaxReasonRunes = 200
	// MaxAcceptDays bounds how far ahead an acceptance may expire.
	MaxAcceptDays = 180
	// MaxValueBytes bounds one stored value or history value.
	MaxValueBytes = 2048
	// MaxStoreBytes caps the encoded snapshot.
	MaxStoreBytes = 2 << 20
)

var (
	checkIDPattern = regexp.MustCompile(`^POS-[0-9]{3}$`)
)

// ValidCheckID reports the posture check id grammar.
func ValidCheckID(id string) bool { return checkIDPattern.MatchString(id) }

// Acceptance records an accepted posture risk.
type Acceptance struct {
	By         string    `json:"by"`
	ByName     string    `json:"by_name"`
	Reason     string    `json:"reason"`
	Until      time.Time `json:"until"`
	AcceptedAt time.Time `json:"accepted_at"`
}

// Change is one history entry.
type Change struct {
	Seq       uint64    `json:"seq"`
	Key       string    `json:"key"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	ActorID   string    `json:"actor_id"`
	ActorName string    `json:"actor_name"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
}

// Actor identifies who made a change.
type Actor struct {
	ID   string
	Name string
}

type snapshot struct {
	Schema   string                `json:"schema"`
	NextSeq  uint64                `json:"next_seq"`
	Values   map[string]string     `json:"values"`
	Accepted map[string]Acceptance `json:"accepted"`
	History  []Change              `json:"history"`
}

// Store owns the overlay snapshot. A snapshot that cannot be loaded leaves the
// store unavailable: nothing is applied and nothing is written, so the file
// stays for inspection and the configuration file remains authoritative.
type Store struct {
	mu         sync.Mutex
	root       *os.Root
	data       snapshot
	problem    string
	disk       [32]byte
	diskExists bool
	now        func() time.Time
}

func empty() snapshot {
	return snapshot{Schema: Schema, NextSeq: 1, Values: map[string]string{}, Accepted: map[string]Acceptance{}, History: []Change{}}
}

// Open opens dir (created private when absent) and loads the overlay. Only an
// unusable directory is an error; an unreadable, corrupt or newer overlay is
// reported by Problem and leaves the store unavailable.
func Open(dir string, now func() time.Time) (*Store, error) {
	root, err := stateio.Open(dir)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	store := &Store{root: root, data: empty(), now: now}
	if _, err := root.Lstat(FileName + ".tmp"); err == nil || !errors.Is(err, os.ErrNotExist) {
		store.problem = "stale settings.json.tmp; inspect it before the overlay is used again"
		return store, nil
	}
	body, err := stateio.Read(root, FileName, MaxStoreBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		store.problem = "settings.json could not be read"
	default:
		decoded, err := decode(body)
		switch {
		case errors.Is(err, ErrNewer):
			store.problem = "settings.json was written by a newer AegisMesh version"
		case err != nil:
			store.problem = "settings.json is corrupt or over quota"
		default:
			store.data, store.disk, store.diskExists = decoded, sha256.Sum256(body), true
		}
	}
	return store, nil
}

// Check strictly parses and validates an encoded snapshot.
func Check(body []byte) error {
	_, err := decode(body)
	return err
}

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
	if decoded.Schema != Schema {
		if strings.HasPrefix(decoded.Schema, "aegismesh.console.settings/") {
			return snapshot{}, ErrNewer
		}
		return snapshot{}, ErrInvalid
	}
	if err := validate(decoded); err != nil {
		return snapshot{}, err
	}
	return decoded, nil
}

func validReason(text string) bool {
	return printable(text, 1, MaxReasonRunes)
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

func validActor(actor Actor) bool {
	if len(actor.ID) == 0 || len(actor.ID) > 80 || !printable(actor.Name, 0, 80) {
		return false
	}
	for _, r := range actor.ID {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// validValue checks a stored value's shape only: bounded, valid UTF-8 and on
// the allowlist. Bounds are checked when values are resolved, so a value that
// no longer validates is ignored at startup instead of failing it.
func validValue(key, value string) bool {
	_, ok := Lookup(key)
	return ok && len(value) <= MaxValueBytes && utf8.ValidString(value)
}

func validate(s snapshot) error {
	if s.Values == nil || s.Accepted == nil || s.History == nil || s.NextSeq == 0 ||
		len(s.Values) > len(Definitions) || len(s.Accepted) > MaxAccepted || len(s.History) > MaxHistory {
		return ErrInvalid
	}
	for key, value := range s.Values {
		if !validValue(key, value) {
			return ErrInvalid
		}
	}
	for id, acceptance := range s.Accepted {
		if !ValidCheckID(id) || !validReason(acceptance.Reason) ||
			!validActor(Actor{ID: acceptance.By, Name: acceptance.ByName}) || acceptance.AcceptedAt.IsZero() ||
			!acceptance.Until.After(acceptance.AcceptedAt) ||
			acceptance.Until.Sub(acceptance.AcceptedAt) > MaxAcceptDays*24*time.Hour {
			return ErrInvalid
		}
	}
	var previous uint64
	for _, change := range s.History {
		if change.Seq <= previous || change.Seq >= s.NextSeq || !Editable(change.Key) ||
			len(change.From) > MaxValueBytes || len(change.To) > MaxValueBytes ||
			!utf8.ValidString(change.From) || !utf8.ValidString(change.To) ||
			!printable(change.Reason, 0, MaxReasonRunes) || change.At.IsZero() ||
			!validActor(Actor{ID: change.ActorID, Name: change.ActorName}) {
			return ErrInvalid
		}
		previous = change.Seq
	}
	return nil
}

// Problem describes why the overlay is unavailable, or "" when it loaded.
func (s *Store) Problem() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.problem
}

// Values returns a copy of the stored overrides (empty when unavailable).
func (s *Store) Values() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.data.Values))
	for key, value := range s.data.Values {
		out[key] = value
	}
	return out
}

// Accepted returns the acceptances that have not expired at now.
func (s *Store) Accepted() map[string]Acceptance {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := map[string]Acceptance{}
	for id, acceptance := range s.data.Accepted {
		if now.Before(acceptance.Until) {
			out[id] = acceptance
		}
	}
	return out
}

// History returns retained changes, newest first.
func (s *Store) History() []Change {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Change{}, s.data.History...)
	sort.Slice(out, func(i, j int) bool { return out[i].Seq > out[j].Seq })
	return out
}

func (s *Store) clone() snapshot {
	next := snapshot{
		Schema: s.data.Schema, NextSeq: s.data.NextSeq, Values: map[string]string{},
		Accepted: map[string]Acceptance{}, History: append([]Change{}, s.data.History...),
	}
	for key, value := range s.data.Values {
		next.Values[key] = value
	}
	now := s.now()
	for id, acceptance := range s.data.Accepted {
		// Expired acceptances are pruned on every write.
		if now.Before(acceptance.Until) {
			next.Accepted[id] = acceptance
		}
	}
	return next
}

func (next *snapshot) record(change Change) Change {
	change.Seq = next.NextSeq
	next.NextSeq++
	next.History = append(next.History, change)
	if len(next.History) > MaxHistory {
		next.History = next.History[len(next.History)-MaxHistory:]
	}
	return change
}

func (s *Store) save(next snapshot) error {
	if err := validate(next); err != nil {
		return err
	}
	body, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(body) > MaxStoreBytes {
		return ErrInvalid
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
	if err := stateio.Atomic(s.root, FileName, body); err != nil {
		return err
	}
	s.data, s.disk, s.diskExists = next, sha256.Sum256(body), true
	return nil
}

func (s *Store) clock() time.Time { return s.now().UTC().Truncate(time.Millisecond) }

func (s *Store) writable() error {
	if s.problem != "" {
		return ErrUnavailable
	}
	return nil
}

// Set stores an override that the caller already validated against the
// effective values and records the change from the previous effective value.
func (s *Store) Set(key, value, from, reason string, actor Actor) (Change, error) {
	if !validValue(key, value) || !validReason(reason) || !validActor(actor) || len(from) > MaxValueBytes {
		return Change{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return Change{}, err
	}
	next := s.clone()
	next.Values[key] = value
	change := next.record(Change{Key: key, From: from, To: value, ActorID: actor.ID, ActorName: actor.Name,
		Reason: reason, At: s.clock()})
	if err := s.save(next); err != nil {
		return Change{}, err
	}
	return change, nil
}

// Revert removes an override; to is the file value that applies again. A key
// without an override changes nothing and reports ok=false.
func (s *Store) Revert(key, from, to string, actor Actor) (Change, bool, error) {
	if _, ok := Lookup(key); !ok || !validActor(actor) || len(from) > MaxValueBytes || len(to) > MaxValueBytes {
		return Change{}, false, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return Change{}, false, err
	}
	if _, ok := s.data.Values[key]; !ok {
		return Change{}, false, nil
	}
	next := s.clone()
	delete(next.Values, key)
	change := next.record(Change{Key: key, From: from, To: to, ActorID: actor.ID, ActorName: actor.Name,
		Reason: "reverted to the configuration file value", At: s.clock()})
	if err := s.save(next); err != nil {
		return Change{}, false, err
	}
	return change, true, nil
}

// Accept records an accepted posture risk until a time at most 180 days ahead.
func (s *Store) Accept(checkID, reason string, until time.Time, actor Actor) (Acceptance, Change, error) {
	now := s.clock()
	until = until.UTC().Truncate(time.Second)
	if !ValidCheckID(checkID) || !validReason(reason) || !validActor(actor) || !until.After(now) ||
		until.Sub(now) > MaxAcceptDays*24*time.Hour {
		return Acceptance{}, Change{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return Acceptance{}, Change{}, err
	}
	next := s.clone()
	from := describe(checkID, next.Accepted[checkID], next.Accepted[checkID].Until.IsZero())
	if _, ok := next.Accepted[checkID]; !ok && len(next.Accepted) >= MaxAccepted {
		return Acceptance{}, Change{}, ErrInvalid
	}
	acceptance := Acceptance{By: actor.ID, ByName: actor.Name, Reason: reason, Until: until, AcceptedAt: now}
	next.Accepted[checkID] = acceptance
	change := next.record(Change{Key: PostureAccepted, From: from, To: describe(checkID, acceptance, false),
		ActorID: actor.ID, ActorName: actor.Name, Reason: reason, At: now})
	if err := s.save(next); err != nil {
		return Acceptance{}, Change{}, err
	}
	return acceptance, change, nil
}

// Unaccept withdraws an acceptance; an unknown or expired one is ErrNotFound.
func (s *Store) Unaccept(checkID string, actor Actor) (Change, error) {
	if !ValidCheckID(checkID) || !validActor(actor) {
		return Change{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return Change{}, err
	}
	next := s.clone()
	previous, ok := next.Accepted[checkID]
	if !ok {
		return Change{}, ErrNotFound
	}
	delete(next.Accepted, checkID)
	change := next.record(Change{Key: PostureAccepted, From: describe(checkID, previous, false),
		To: describe(checkID, Acceptance{}, true), ActorID: actor.ID, ActorName: actor.Name,
		Reason: "acceptance withdrawn", At: s.clock()})
	if err := s.save(next); err != nil {
		return Change{}, err
	}
	return change, nil
}

func describe(checkID string, acceptance Acceptance, none bool) string {
	if none {
		return checkID + ": not accepted"
	}
	return fmt.Sprintf("%s: accepted until %s", checkID, acceptance.Until.UTC().Format(time.RFC3339))
}

// Close releases the directory handle.
func (s *Store) Close() error { return s.root.Close() }

// ReadAccepted reads the unexpired acceptances of an overlay without creating,
// migrating or writing anything; the offline posture command uses it. A
// missing directory or file returns an error wrapping os.ErrNotExist.
func ReadAccepted(dir string, now time.Time) (map[string]Acceptance, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("settings overlay location is not a directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	body, err := stateio.Read(root, FileName, MaxStoreBytes)
	if err != nil {
		return nil, err
	}
	decoded, err := decode(body)
	if err != nil {
		return nil, err
	}
	out := map[string]Acceptance{}
	for id, acceptance := range decoded.Accepted {
		if now.Before(acceptance.Until) {
			out[id] = acceptance
		}
	}
	return out, nil
}
