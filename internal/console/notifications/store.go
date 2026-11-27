package notifications

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/accounts"
	"github.com/metaforismo/aegismesh/internal/console/stateio"
)

// Bounds. They are fixed on purpose; see ADR-0027.
const (
	// MaxItems is the per-tenant ring size; the oldest item is dropped first.
	MaxItems = 2000
	// MaxReaders bounds principals with stored read state or preferences per
	// tenant; the least recently active one is dropped first.
	MaxReaders = 256
	// GroupWindow folds repeats of one kind+rule+source into one item.
	GroupWindow = 10 * time.Minute
	// ObservationBudget bounds new evidence-derived items per observation-time minute.
	ObservationBudget = 20
	// WallBudget bounds new evidence-derived items per wall-clock minute.
	WallBudget = 60
	// MaxSeenCampaigns bounds remembered campaign ids (oldest forgotten first).
	MaxSeenCampaigns = 1024
	// MaxReadIDs bounds ids in one mark-read request.
	MaxReadIDs = 200
	// MaxGroupCount saturates group_count.
	MaxGroupCount = 1_000_000
	// FileName is the fixed state file inside a tenant's private directory.
	FileName = "notifications.json"
	// Schema versions the persisted snapshot.
	Schema = "aegismesh.notifications/v1"
	// MaxSubscribers bounds live subscribers per tenant store.
	MaxSubscribers = 16
)

// ErrInvalid marks invalid input or a corrupt persisted snapshot.
var ErrInvalid = errors.New("invalid notification state")

var idPattern = regexp.MustCompile(`^ntf_[0-9a-f]{16}$`)

// ValidID reports the notification id grammar.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Permissions an item can require (beside recipient-only items).
const (
	PermEvidence       = "evidence.read"
	PermAnalysis       = "analysis.read"
	PermInvestigations = "investigations.read"
)

// Link opens the item's target in the console.
type Link struct {
	Route string `json:"route"`
	ID    string `json:"id"`
	// Node qualifies a forwarded event id; omitted for local evidence.
	Node string `json:"node,omitempty"`
}

// Item is one persisted inbox entry. It holds no rendered text.
type Item struct {
	Seq        uint64    `json:"seq"`
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Severity   string    `json:"severity"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Link       Link      `json:"link"`
	GroupCount int       `json:"group_count"`
	GroupKey   string    `json:"group_key"`
	// Perm is the permission a principal needs to see the item; empty for
	// recipient-only items.
	Perm string `json:"perm"`
	// Recipient restricts the item to one principal id.
	Recipient string `json:"recipient,omitempty"`
	Facts     Facts  `json:"facts"`
}

// View is the API projection of an item for one principal.
type View struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Summary    string `json:"summary"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	Read       bool   `json:"read"`
	Link       Link   `json:"link"`
	GroupCount int    `json:"group_count"`
	RuleID     string `json:"rule_id,omitempty"`
	Source     string `json:"source,omitempty"`
	Sensor     string `json:"sensor,omitempty"`
}

// Preferences select which items a principal sees. account_security items
// are always shown and are not filtered by severity.
type Preferences struct {
	Kinds       map[string]bool `json:"kinds"`
	MinSeverity string          `json:"min_severity"`
}

// DefaultPreferences enables every kind at every severity.
func DefaultPreferences() Preferences {
	prefs := Preferences{Kinds: map[string]bool{}, MinSeverity: SeverityInfo}
	for _, kind := range kinds {
		prefs.Kinds[kind] = true
	}
	return prefs
}

func (p Preferences) valid() bool {
	if Rank(p.MinSeverity) == 0 || len(p.Kinds) != len(kinds) || !p.Kinds[KindAccount] {
		return false
	}
	for kind := range p.Kinds {
		if !ValidKind(kind) {
			return false
		}
	}
	return true
}

func (p Preferences) clone() Preferences {
	out := Preferences{Kinds: map[string]bool{}, MinSeverity: p.MinSeverity}
	for kind, on := range p.Kinds {
		out.Kinds[kind] = on
	}
	return out
}

// Viewer is the principal a list or count is computed for. Can resolves a
// permission against the principal's role at call time.
type Viewer struct {
	ID  string
	Can func(perm string) bool
}

type reader struct {
	// Before marks every seq at or below it read.
	Before uint64 `json:"before"`
	// Seqs lists individually read items above Before (pruned to the ring).
	Seqs  []uint64     `json:"seqs"`
	Prefs *Preferences `json:"prefs,omitempty"`
	At    time.Time    `json:"at"`
}

// Mark is the persisted high-water mark of derived observations.
type Mark struct {
	Time time.Time `json:"time"`
	Key  string    `json:"key"`
}

// After reports whether (t, key) sorts after the mark.
func (m *Mark) After(t time.Time, key string) bool {
	if m == nil {
		return true
	}
	return t.After(m.Time) || t.Equal(m.Time) && key > m.Key
}

// DeriveState is the deriver's persisted memory: what was already turned into
// notifications, so a restart never re-derives or resurrects items as unread.
type DeriveState struct {
	HighWater *Mark    `json:"high_water"`
	Campaigns []string `json:"campaigns"`
	// PostureKnown is true once posture was evaluated; Attention lists checks
	// last seen in attention; Expiring lists "check@until" already notified.
	PostureKnown bool     `json:"posture_known"`
	Attention    []string `json:"attention"`
	Expiring     []string `json:"expiring"`
}

type snapshot struct {
	Schema  string             `json:"schema"`
	NextSeq uint64             `json:"next_seq"`
	Items   []Item             `json:"items"`
	Readers map[string]*reader `json:"readers"`
	Derive  DeriveState        `json:"derive"`
}

// Event is a live change: a new Item, or a read-state change for Principal.
type Event struct {
	Item      *Item
	Principal string
}

// Store owns one tenant's ring, read state and deriver memory.
type Store struct {
	mu      sync.Mutex
	root    *os.Root
	data    snapshot
	groups  map[string]uint64
	ids     map[string]uint64
	dirty   bool
	obs     map[int64]int
	wall    map[int64]int
	subs    map[chan Event]struct{}
	dropped int
}

// Open loads or creates the tenant's notification state in dir and fails
// closed on a corrupt snapshot or an interrupted write.
func Open(dir string) (*Store, error) {
	root, err := stateio.Open(dir)
	if err != nil {
		return nil, err
	}
	if _, err := root.Lstat(FileName + ".tmp"); err == nil || !errors.Is(err, os.ErrNotExist) {
		root.Close()
		return nil, errors.New("console notifications: inspect stale notifications.json.tmp before startup")
	}
	store := &Store{root: root, obs: map[int64]int{}, wall: map[int64]int{}, subs: map[chan Event]struct{}{}}
	store.data = snapshot{Schema: Schema, NextSeq: 1, Items: []Item{}, Readers: map[string]*reader{}, Derive: emptyDerive()}
	body, err := stateio.Read(root, FileName, stateio.MaxStateBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		root.Close()
		return nil, fmt.Errorf("inspect notifications.json before restart: %w", err)
	}
	if err == nil {
		data, decodeErr := decode(body)
		if decodeErr != nil {
			root.Close()
			return nil, fmt.Errorf("%w: notifications.json is corrupt; it holds derived items and read state only, so it may be moved aside after inspection", ErrInvalid)
		}
		store.data = data
	}
	store.reindex()
	return store, nil
}

func emptyDerive() DeriveState {
	return DeriveState{Campaigns: []string{}, Attention: []string{}, Expiring: []string{}}
}

// decode strictly parses and validates a persisted snapshot.
func decode(body []byte) (snapshot, error) {
	var data snapshot
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&data); err != nil || decoder.More() {
		return snapshot{}, ErrInvalid
	}
	if data.Schema != Schema || data.Items == nil || data.Readers == nil || len(data.Items) > MaxItems ||
		len(data.Readers) > MaxReaders || data.NextSeq == 0 {
		return snapshot{}, ErrInvalid
	}
	var previous uint64
	ids := map[string]bool{}
	for _, item := range data.Items {
		if item.Seq <= previous || item.Seq >= data.NextSeq || ids[item.ID] || !validItem(item) {
			return snapshot{}, ErrInvalid
		}
		previous = item.Seq
		ids[item.ID] = true
	}
	for id, state := range data.Readers {
		if !accounts.ValidPrincipalID(id) || state == nil || len(state.Seqs) > MaxItems ||
			state.Prefs != nil && !state.Prefs.valid() {
			return snapshot{}, ErrInvalid
		}
		if state.Seqs == nil {
			state.Seqs = []uint64{}
		}
	}
	derive := data.Derive
	if derive.Campaigns == nil || derive.Attention == nil || derive.Expiring == nil ||
		len(derive.Campaigns) > MaxSeenCampaigns || len(derive.Attention) > 256 || len(derive.Expiring) > 256 {
		return snapshot{}, ErrInvalid
	}
	for _, id := range derive.Campaigns {
		if !campaignPattern.MatchString(id) {
			return snapshot{}, ErrInvalid
		}
	}
	for _, id := range derive.Attention {
		if !checkPattern.MatchString(id) {
			return snapshot{}, ErrInvalid
		}
	}
	for _, key := range derive.Expiring {
		if len(key) > 64 {
			return snapshot{}, ErrInvalid
		}
	}
	if derive.HighWater != nil && len(derive.HighWater.Key) > 128 {
		return snapshot{}, ErrInvalid
	}
	return data, nil
}

func validItem(item Item) bool {
	if !ValidID(item.ID) || !ValidKind(item.Kind) || Rank(item.Severity) == 0 || item.GroupCount < 1 ||
		item.GroupCount > MaxGroupCount || len(item.GroupKey) == 0 || len(item.GroupKey) > 256 ||
		!item.Facts.Valid() || !validLink(item.Link) || item.CreatedAt.IsZero() || item.UpdatedAt.Before(item.CreatedAt) {
		return false
	}
	personal := item.Kind == KindAccount || item.Kind == KindAssignment
	if personal {
		return item.Perm == "" && accounts.ValidPrincipalID(item.Recipient)
	}
	if item.Recipient != "" {
		return false
	}
	switch item.Perm {
	case PermEvidence, PermAnalysis, PermInvestigations:
		return true
	}
	return false
}

func (s *Store) reindex() {
	s.groups = map[string]uint64{}
	s.ids = map[string]uint64{}
	for _, item := range s.data.Items {
		s.groups[item.GroupKey] = item.Seq
		s.ids[item.ID] = item.Seq
	}
}

// Close flushes pending derived state and releases the directory handle.
func (s *Store) Close() error {
	flushErr := s.Flush()
	s.mu.Lock()
	for channel := range s.subs {
		delete(s.subs, channel)
		close(channel)
	}
	s.mu.Unlock()
	if err := s.root.Close(); err != nil {
		return err
	}
	return flushErr
}

func (s *Store) encode() ([]byte, error) {
	body, err := json.Marshal(s.data)
	if err != nil {
		return nil, err
	}
	if len(body) > stateio.MaxStateBytes {
		return nil, ErrInvalid
	}
	return body, nil
}

// persistLocked writes the snapshot; callers hold mu.
func (s *Store) persistLocked() error {
	body, err := s.encode()
	if err != nil {
		return err
	}
	if err := stateio.Atomic(s.root, FileName, body); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// Flush persists pending derived changes, if any.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.persistLocked()
}

// Dirty reports whether derived changes await a Flush.
func (s *Store) Dirty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dirty
}

// Candidate is a proposed notification from the deriver or a console action.
type Candidate struct {
	Kind     string
	Severity string
	// At is the time the item is about: the observation time for evidence,
	// the action time otherwise.
	At        time.Time
	GroupKey  string
	Link      Link
	Facts     Facts
	Perm      string
	Recipient string
	// Limited candidates count against the per-minute budgets.
	Limited bool
}

func newID() (string, error) {
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return "ntf_" + hex.EncodeToString(entropy[:]), nil
}

func (s *Store) find(seq uint64) int {
	i := sort.Search(len(s.data.Items), func(i int) bool { return s.data.Items[i].Seq >= seq })
	if i < len(s.data.Items) && s.data.Items[i].Seq == seq {
		return i
	}
	return -1
}

func within(a, b time.Time) bool {
	gap := a.Sub(b)
	return gap <= GroupWindow && gap >= -GroupWindow
}

// group folds c into an existing item with the same key inside the window;
// anyWindow skips the window check (overflow keys carry their own bucket).
func (s *Store) group(key string, at time.Time, anyWindow bool) bool {
	seq, ok := s.groups[key]
	if !ok {
		return false
	}
	i := s.find(seq)
	if i < 0 || !anyWindow && !within(at, s.data.Items[i].CreatedAt) {
		return false
	}
	item := &s.data.Items[i]
	if item.GroupCount < MaxGroupCount {
		item.GroupCount++
	}
	if at.After(item.UpdatedAt) {
		item.UpdatedAt = at
	}
	s.dirty = true
	return true
}

func bump(buckets map[int64]int, minute int64, budget int) bool {
	if buckets[minute] >= budget {
		return false
	}
	buckets[minute]++
	for len(buckets) > 64 {
		oldest := minute
		for key := range buckets {
			oldest = min(oldest, key)
		}
		delete(buckets, oldest)
	}
	return true
}

// Add groups, rate-limits or stores a candidate. It returns the new item, or
// nil when the candidate was folded into an existing one or rejected.
func (s *Store) Add(c Candidate, wall time.Time) *Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addLocked(c, wall)
}

func (s *Store) addLocked(c Candidate, wall time.Time) *Item {
	c.At = c.At.UTC()
	if c.At.After(wall) {
		c.At = wall.UTC()
	}
	if c.GroupKey == "" || len(c.GroupKey) > 200 {
		return nil
	}
	if s.group(c.GroupKey, c.At, false) {
		return nil
	}
	if c.Limited {
		admitted := s.obs[c.At.Unix()/60] < ObservationBudget && s.wall[wall.Unix()/60] < WallBudget
		if admitted {
			bump(s.obs, c.At.Unix()/60, ObservationBudget)
			bump(s.wall, wall.Unix()/60, WallBudget)
		} else {
			// One overflow item per kind per 10 wall-clock minutes, whatever
			// the observation times claim.
			s.dropped++
			c.GroupKey = c.Kind + "|overflow|" + strconv.FormatInt(wall.Unix()/int64(GroupWindow/time.Second), 10)
			c.Facts = Facts{Overflow: true}
			if s.group(c.GroupKey, c.At, true) {
				return nil
			}
		}
	}
	id, err := newID()
	if err != nil {
		return nil
	}
	item := Item{
		Seq: s.data.NextSeq, ID: id, Kind: c.Kind, Severity: c.Severity, CreatedAt: c.At, UpdatedAt: c.At,
		Link: c.Link, GroupCount: 1, GroupKey: c.GroupKey, Perm: c.Perm, Recipient: c.Recipient, Facts: c.Facts,
	}
	if !validItem(item) {
		return nil
	}
	s.data.NextSeq++
	s.data.Items = append(s.data.Items, item)
	s.groups[item.GroupKey] = item.Seq
	s.ids[item.ID] = item.Seq
	for len(s.data.Items) > MaxItems {
		old := s.data.Items[0]
		if s.groups[old.GroupKey] == old.Seq {
			delete(s.groups, old.GroupKey)
		}
		delete(s.ids, old.ID)
		s.data.Items = s.data.Items[1:]
	}
	s.dirty = true
	copied := item
	s.publishLocked(Event{Item: &copied})
	return &copied
}

// Dropped reports how many limited candidates were folded into overflow items
// since start-up.
func (s *Store) Dropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Derive returns a copy of the deriver's persisted memory.
func (s *Store) Derive() DeriveState {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.data.Derive
	d.Campaigns = append([]string{}, d.Campaigns...)
	d.Attention = append([]string{}, d.Attention...)
	d.Expiring = append([]string{}, d.Expiring...)
	if d.HighWater != nil {
		mark := *d.HighWater
		d.HighWater = &mark
	}
	return d
}

// SetDerive replaces the deriver's memory (bounded) and marks state dirty.
func (s *Store) SetDerive(d DeriveState) {
	if len(d.Campaigns) > MaxSeenCampaigns {
		d.Campaigns = d.Campaigns[len(d.Campaigns)-MaxSeenCampaigns:]
	}
	if len(d.Attention) > 256 {
		d.Attention = d.Attention[:256]
	}
	if len(d.Expiring) > 256 {
		d.Expiring = d.Expiring[len(d.Expiring)-256:]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Derive = d
	s.dirty = true
}

func (s *Store) prefsLocked(principal string) Preferences {
	if state := s.data.Readers[principal]; state != nil && state.Prefs != nil {
		return state.Prefs.clone()
	}
	return DefaultPreferences()
}

func visible(viewer Viewer, item *Item, prefs Preferences) bool {
	if item.Recipient != "" || item.Kind == KindAccount || item.Kind == KindAssignment {
		if item.Recipient != viewer.ID {
			return false
		}
		if item.Kind == KindAccount {
			return true
		}
	} else if viewer.Can == nil || !viewer.Can(item.Perm) {
		return false
	}
	return prefs.Kinds[item.Kind] && Rank(item.Severity) >= Rank(prefs.MinSeverity)
}

// Visible reports whether viewer may see item under its current preferences.
func (s *Store) Visible(viewer Viewer, item *Item) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return visible(viewer, item, s.prefsLocked(viewer.ID))
}

type readSet struct {
	before uint64
	seqs   map[uint64]bool
}

func (s *Store) readSetLocked(principal string) readSet {
	out := readSet{seqs: map[uint64]bool{}}
	if state := s.data.Readers[principal]; state != nil {
		out.before = state.Before
		for _, seq := range state.Seqs {
			out.seqs[seq] = true
		}
	}
	return out
}

func (r readSet) has(seq uint64) bool { return seq <= r.before || r.seqs[seq] }

func (s *Store) unreadLocked(viewer Viewer) int {
	prefs, read := s.prefsLocked(viewer.ID), s.readSetLocked(viewer.ID)
	count := 0
	for i := range s.data.Items {
		item := &s.data.Items[i]
		if !read.has(item.Seq) && visible(viewer, item, prefs) {
			count++
		}
	}
	return count
}

// Unread counts the items viewer can see and has not read.
func (s *Store) Unread(viewer Viewer) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unreadLocked(viewer)
}

// Project renders one item for viewer.
func Project(item Item, read bool) View {
	title, summary := Render(item.Kind, item.Severity, item.Facts, item.GroupCount)
	return View{
		ID: item.ID, Kind: item.Kind, Severity: item.Severity, Title: title, Summary: summary,
		CreatedAt: item.CreatedAt.UTC().Format(time.RFC3339Nano), UpdatedAt: item.UpdatedAt.UTC().Format(time.RFC3339Nano),
		Read: read, Link: item.Link, GroupCount: item.GroupCount,
		RuleID: item.Facts.RuleID, Source: item.Facts.Source, Sensor: item.Facts.Sensor,
	}
}

// Filter narrows a list; zero values select everything.
type Filter struct {
	Unread   bool
	Kind     string
	Severity string
	// Cursor is the seq of the last item of the previous page, or zero.
	Cursor uint64
	Limit  int
}

// Page is one newest-first list page.
type Page struct {
	Items      []View  `json:"items"`
	Unread     int     `json:"unread"`
	NextCursor *string `json:"next_cursor"`
}

// EncodeCursor and DecodeCursor make the opaque list cursor.
func EncodeCursor(seq uint64) string { return "n" + strconv.FormatUint(seq, 10) }

// DecodeCursor parses a cursor produced by EncodeCursor.
func DecodeCursor(value string) (uint64, bool) {
	if len(value) < 2 || len(value) > 21 || value[0] != 'n' {
		return 0, false
	}
	seq, err := strconv.ParseUint(value[1:], 10, 64)
	return seq, err == nil && seq > 0 && strconv.FormatUint(seq, 10) == value[1:]
}

// List returns one newest-first page of items viewer can see.
func (s *Store) List(viewer Viewer, filter Filter) Page {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefs, read := s.prefsLocked(viewer.ID), s.readSetLocked(viewer.ID)
	page := Page{Items: []View{}}
	var last uint64
	for i := len(s.data.Items) - 1; i >= 0; i-- {
		item := &s.data.Items[i]
		if filter.Cursor != 0 && item.Seq >= filter.Cursor {
			continue
		}
		isRead := read.has(item.Seq)
		if !visible(viewer, item, prefs) || filter.Unread && isRead ||
			filter.Kind != "" && item.Kind != filter.Kind || filter.Severity != "" && item.Severity != filter.Severity {
			continue
		}
		if len(page.Items) == filter.Limit {
			// The cursor is the seq of the last returned item.
			cursor := EncodeCursor(last)
			page.NextCursor = &cursor
			break
		}
		page.Items = append(page.Items, Project(*item, isRead))
		last = item.Seq
	}
	page.Unread = s.unreadLocked(viewer)
	return page
}

func (s *Store) touchReaderLocked(principal string, now time.Time) *reader {
	state := s.data.Readers[principal]
	if state == nil {
		state = &reader{Seqs: []uint64{}}
		s.data.Readers[principal] = state
		for len(s.data.Readers) > MaxReaders {
			oldestID := ""
			for id, candidate := range s.data.Readers {
				if id != principal && (oldestID == "" || candidate.At.Before(s.data.Readers[oldestID].At)) {
					oldestID = id
				}
			}
			delete(s.data.Readers, oldestID)
		}
	}
	state.At = now.UTC()
	return state
}

// pruneLocked keeps only explicit read seqs above Before that are still in the ring.
func (s *Store) pruneLocked(state *reader) {
	kept := state.Seqs[:0]
	seen := map[uint64]bool{}
	for _, seq := range state.Seqs {
		if seq > state.Before && !seen[seq] && s.find(seq) >= 0 {
			kept = append(kept, seq)
			seen[seq] = true
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i] < kept[j] })
	state.Seqs = kept
}

// mutateReader applies fn to a copy of the principal's state, persists, and
// only then commits it; on a persistence error nothing changes.
func (s *Store) mutateReader(principal string, now time.Time, fn func(*reader)) error {
	previous, existed := s.data.Readers[principal]
	var backup reader
	if existed {
		backup = *previous
		backup.Seqs = append([]uint64{}, previous.Seqs...)
	}
	state := s.touchReaderLocked(principal, now)
	fn(state)
	s.pruneLocked(state)
	if err := s.persistLocked(); err != nil {
		if existed {
			*previous = backup
			s.data.Readers[principal] = previous
		} else {
			delete(s.data.Readers, principal)
		}
		s.dirty = true
		return err
	}
	s.publishLocked(Event{Principal: principal})
	return nil
}

// MarkRead marks the given ids read for viewer. Unknown ids and items the
// viewer cannot see are ignored. It returns the new unread count.
func (s *Store) MarkRead(viewer Viewer, ids []string, now time.Time) (int, error) {
	if len(ids) == 0 || len(ids) > MaxReadIDs {
		return 0, ErrInvalid
	}
	for _, id := range ids {
		if !ValidID(id) {
			return 0, ErrInvalid
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prefs := s.prefsLocked(viewer.ID)
	err := s.mutateReader(viewer.ID, now, func(state *reader) {
		for _, id := range ids {
			seq, ok := s.ids[id]
			if i := s.find(seq); ok && i >= 0 && visible(viewer, &s.data.Items[i], prefs) {
				state.Seqs = append(state.Seqs, seq)
			}
		}
	})
	if err != nil {
		return 0, err
	}
	return s.unreadLocked(viewer), nil
}

// MarkAllRead marks every item created at or before `before` read for viewer.
func (s *Store) MarkAllRead(viewer Viewer, before, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.mutateReader(viewer.ID, now, func(state *reader) {
		// The watermark advances over the leading run created at or before
		// `before`; later items in that range are recorded individually, so
		// an item created after `before` is never marked read.
		prefix := true
		for i := range s.data.Items {
			item := &s.data.Items[i]
			if item.CreatedAt.After(before) {
				prefix = false
				continue
			}
			if prefix {
				state.Before = max(state.Before, item.Seq)
			} else {
				state.Seqs = append(state.Seqs, item.Seq)
			}
		}
	})
	if err != nil {
		return 0, err
	}
	return s.unreadLocked(viewer), nil
}

// Preferences returns viewer's preferences (defaults when unset).
func (s *Store) Preferences(principal string) Preferences {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prefsLocked(principal)
}

// SetPreferences validates and persists a principal's preferences.
func (s *Store) SetPreferences(principal string, prefs Preferences, now time.Time) error {
	if !prefs.valid() || !accounts.ValidPrincipalID(principal) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := prefs.clone()
	return s.mutateReader(principal, now, func(state *reader) { state.Prefs = &copied })
}

// Subscribe registers a bounded live feed; a slow subscriber is closed rather
// than blocking the deriver.
func (s *Store) Subscribe() (<-chan Event, func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.subs) >= MaxSubscribers {
		return nil, nil, false
	}
	channel := make(chan Event, 64)
	s.subs[channel] = struct{}{}
	return channel, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.subs[channel]; ok {
			delete(s.subs, channel)
			close(channel)
		}
	}, true
}

func (s *Store) publishLocked(event Event) {
	for channel := range s.subs {
		select {
		case channel <- event:
		default:
			delete(s.subs, channel)
			close(channel)
		}
	}
}
