// Package investigations persists bounded operator annotations separately from evidence.
// Untrusted annotation text is stored as data and never selects files or changes runtime behavior.
package investigations

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/stateio"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// MaxInvestigations bounds the number of persisted investigations.
const MaxInvestigations = 1000

// MaxNotes bounds notes per investigation.
const MaxNotes = 100

// MaxActivity bounds the activity log per investigation; the oldest entries
// are dropped first and ActivityTruncated is set.
const MaxActivity = 200

// MaxEvents bounds evidence references per investigation.
const MaxEvents = 200

// Schema versions the persisted snapshot. The unversioned legacy format (a
// bare id → investigation map) is read and migrated in memory with empty
// activity, no origin and no assignee; it is rewritten as Schema on the next
// change.
const Schema = "aegismesh.investigations/v2"

// Activity kinds.
const (
	ActivityCreated  = "created"
	ActivityStatus   = "status"
	ActivityPriority = "priority"
	ActivityTitle    = "title"
	ActivityAssignee = "assignee"
	ActivityNote     = "note"
	ActivityAttach   = "attach"
	ActivityDetach   = "detach"
)

// Origin kinds.
const (
	OriginCampaign = "campaign"
	OriginSession  = "session"
)

var (
	campaignIDPattern  = regexp.MustCompile(`^cmp_[0-9a-f]{12}$`)
	sessionIDPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	principalIDPattern = regexp.MustCompile(`^(acc_[0-9a-f]{16}|oidc:[0-9a-f]{12}|cfg:[a-z0-9][a-z0-9-]{1,62}[a-z0-9])$`)
)

// ErrInvalid marks invalid fields or a corrupt persisted snapshot.
var ErrInvalid = errors.New("invalid investigation")

// ErrNotFound marks an unknown investigation id.
var ErrNotFound = errors.New("investigation not found")

// ErrLimit marks an exhausted count or encoded-state quota.
var ErrLimit = errors.New("investigation quota reached")

// Note is an operator annotation stored separately from sensor evidence.
type Note struct {
	// ID is a fresh note identifier.
	ID string `json:"id"`
	// Time is the UTC annotation time in RFC3339Nano format.
	Time string `json:"time"`
	// Author identifies the annotating operator.
	Author string `json:"author"`
	// Text contains 1..4000 UTF-8 characters of operator annotation.
	Text string `json:"text"`
}

// Origin records what an investigation was opened from.
type Origin struct {
	// Kind is campaign or session.
	Kind string `json:"kind"`
	// ID is the campaign or session identifier at creation time.
	ID string `json:"id"`
}

// Activity is one entry of an investigation's change log. Detail is composed
// by the console from fixed words, identifiers and counts; it never copies
// note, title or evidence text.
type Activity struct {
	At        string `json:"at"`
	ActorID   string `json:"actor_id"`
	ActorName string `json:"actor_name"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail"`
}

// Actor identifies the principal making a change.
type Actor struct {
	ID   string
	Name string
}

// Investigation groups operator annotations and evidence references without mutating evidence.
type Investigation struct {
	// ID is the immutable investigation identifier.
	ID string `json:"id"`
	// Title contains 1..200 UTF-8 characters of operator text.
	Title string `json:"title"`
	// Status is open, monitoring, or closed.
	Status string `json:"status"`
	// Priority is low, medium, or high.
	Priority string `json:"priority"`
	// CreatedAt is the UTC creation time in RFC3339Nano format.
	CreatedAt string `json:"created_at"`
	// UpdatedAt is the UTC time of the last persisted change.
	UpdatedAt string `json:"updated_at"`
	// CreatedBy identifies the creating operator.
	CreatedBy string `json:"created_by"`
	// EventIDs contains at most 200 unique evidence references.
	EventIDs []string `json:"event_ids"`
	// Notes contains at most 100 operator notes and is omitted from list responses.
	Notes []Note `json:"notes,omitempty"`
	// Events contains disposable detail projections; it is never persisted as evidence.
	Events []evidenceindex.Summary `json:"events,omitempty"`
	// Origin is the campaign or session the investigation was opened from, or null.
	Origin *Origin `json:"origin"`
	// Assignee is a principal id holding investigations.read, or null.
	Assignee *string `json:"assignee"`
	// AssigneeName is the assignee's display name when assigned, or null.
	AssigneeName *string `json:"assignee_name"`
	// Activity is the bounded change log, newest last; omitted from lists.
	Activity []Activity `json:"activity,omitempty"`
	// ActivityTruncated reports that older activity entries were dropped.
	ActivityTruncated bool `json:"activity_truncated,omitempty"`
}

// Create carries validated fields for a new investigation.
type Create struct {
	// Title contains the proposed 1..200-character title.
	Title string `json:"title"`
	// Priority is an optional priority; empty defaults to medium.
	Priority string `json:"priority"`
	// EventIDs contains at most 200 unique validated evidence references.
	EventIDs []string `json:"event_ids"`
}

// Patch carries optional updates; an empty patch is invalid.
type Patch struct {
	// Title replaces the title when nonnil.
	Title *string `json:"title"`
	// Status replaces the workflow status when nonnil.
	Status *string `json:"status"`
	// Priority replaces the priority when nonnil.
	Priority *string `json:"priority"`
	// Assign changes the assignee when nonnil; a zero Actor unassigns. The
	// caller validates that the principal exists and may read investigations.
	Assign *Actor `json:"-"`
}

// Seed opens an investigation from a campaign or session: the origin, the
// bounded evidence to attach, the first note (composed by the console from
// fixed templates) and the activity detail for the attachment.
type Seed struct {
	Origin       Origin
	Note         string
	AttachDetail string
}

// Store owns bounded investigation snapshots persisted by atomic replacement.
type Store struct {
	index *evidenceindex.Index
	mu    sync.Mutex
	root  *os.Root
	items map[string]Investigation
}

// NewScoped confines newly attached references to the tenant's index.
func NewScoped(dir string, index *evidenceindex.Index) (*Store, error) {
	store, err := New(dir)
	if err == nil {
		store.index = index
	}
	return store, err
}

// New opens private state and fails closed on corrupt snapshots or interrupted writes.
func New(dir string) (*Store, error) {
	root, err := stateio.Open(dir)
	if err != nil {
		return nil, err
	}

	if _, err := root.Lstat("investigations.json.tmp"); err == nil || !errors.Is(err, os.ErrNotExist) {
		root.Close()
		return nil, errors.New("console investigations: inspect stale temporary state before startup")
	}

	store := &Store{
		root:  root,
		items: map[string]Investigation{},
	}

	body, err := stateio.Read(root, "investigations.json", stateio.MaxStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}

	if err != nil {
		root.Close()
		return nil, fmt.Errorf("inspect investigations.json before restart: %w", err)
	}

	items, err := decode(body)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf(
			"%w: investigations.json corrupt, invalid or over quota; inspect state and restore a verified backup", ErrInvalid,
		)
	}
	store.items = items
	return store, nil
}

type snapshot struct {
	Schema string                   `json:"schema"`
	Items  map[string]Investigation `json:"items"`
}

// decode reads the versioned snapshot strictly, or the legacy bare map, and
// migrates legacy records to an empty activity log without origin or assignee.
func decode(body []byte) (map[string]Investigation, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil || probe == nil {
		return nil, ErrInvalid
	}
	var items map[string]Investigation
	if _, versioned := probe["schema"]; versioned {
		var data snapshot
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&data); err != nil || decoder.More() || data.Schema != Schema || data.Items == nil {
			return nil, ErrInvalid
		}
		items = data.Items
	} else {
		if err := json.Unmarshal(body, &items); err != nil || items == nil {
			return nil, ErrInvalid
		}
		for id, item := range items {
			item.Activity, item.ActivityTruncated = []Activity{}, false
			item.Origin, item.Assignee, item.AssigneeName = nil, nil, nil
			items[id] = item
		}
	}
	if len(items) > MaxInvestigations {
		return nil, ErrInvalid
	}
	for id, item := range items {
		if item.Activity == nil {
			item.Activity = []Activity{}
		}
		if item.Notes == nil {
			item.Notes = []Note{}
		}
		if item.EventIDs == nil {
			item.EventIDs = []string{}
		}
		item.Events = nil
		items[id] = item
		if id != item.ID || validate(item) != nil {
			return nil, ErrInvalid
		}
	}
	return items, nil
}

func validText(text string, min, max int) bool {
	return utf8.ValidString(text) && utf8.RuneCountInString(text) >= min && utf8.RuneCountInString(text) <= max
}

// printable accepts 1..max runes without control characters.
func printable(text string, max int) bool {
	if !validText(text, 1, max) {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validActivity(entry Activity) bool {
	if _, err := time.Parse(time.RFC3339Nano, entry.At); err != nil {
		return false
	}
	if entry.ActorID != "" && !principalIDPattern.MatchString(entry.ActorID) {
		return false
	}
	if entry.ActorName != "" && !printable(entry.ActorName, 80) || len(entry.Detail) > 0 && !printable(entry.Detail, 300) {
		return false
	}
	switch entry.Kind {
	case ActivityCreated, ActivityStatus, ActivityPriority, ActivityTitle, ActivityAssignee, ActivityNote,
		ActivityAttach, ActivityDetach:
		return true
	}
	return false
}

func validate(investigation Investigation) error {
	if !validText(investigation.Title, 1, 200) ||
		len(investigation.EventIDs) > MaxEvents ||
		len(investigation.Notes) > MaxNotes ||
		len(investigation.Activity) > MaxActivity {
		return ErrInvalid
	}

	if origin := investigation.Origin; origin != nil {
		if !(origin.Kind == OriginCampaign && campaignIDPattern.MatchString(origin.ID) ||
			origin.Kind == OriginSession && sessionIDPattern.MatchString(origin.ID)) {
			return ErrInvalid
		}
	}

	if (investigation.Assignee == nil) != (investigation.AssigneeName == nil) ||
		investigation.Assignee != nil && (!principalIDPattern.MatchString(*investigation.Assignee) ||
			!printable(*investigation.AssigneeName, 80)) {
		return ErrInvalid
	}

	for _, entry := range investigation.Activity {
		if !validActivity(entry) {
			return ErrInvalid
		}
	}

	if investigation.Status != "open" && investigation.Status != "monitoring" && investigation.Status != "closed" {
		return ErrInvalid
	}

	if investigation.Priority != "low" && investigation.Priority != "medium" && investigation.Priority != "high" {
		return ErrInvalid
	}

	seen := map[string]bool{}
	for _, id := range investigation.EventIDs {
		if !evidenceindex.ValidID(id) || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}

	for _, note := range investigation.Notes {
		if !validText(note.Text, 1, 4000) {
			return ErrInvalid
		}
	}

	return nil
}

func copyItem(investigation Investigation) Investigation {
	investigation.EventIDs = append([]string{}, investigation.EventIDs...)
	investigation.Notes = append([]Note{}, investigation.Notes...)
	investigation.Activity = append([]Activity{}, investigation.Activity...)
	if investigation.Origin != nil {
		origin := *investigation.Origin
		investigation.Origin = &origin
	}
	if investigation.Assignee != nil {
		id, name := *investigation.Assignee, *investigation.AssigneeName
		investigation.Assignee, investigation.AssigneeName = &id, &name
	}
	investigation.Events = nil
	return investigation
}

// record appends an activity entry, dropping the oldest beyond MaxActivity.
func record(investigation *Investigation, actor Actor, kind, detail string) {
	investigation.Activity = append(investigation.Activity, Activity{
		At: time.Now().UTC().Format(time.RFC3339Nano), ActorID: actor.ID, ActorName: truncateRunes(actor.Name, 80),
		Kind: kind, Detail: detail,
	})
	if over := len(investigation.Activity) - MaxActivity; over > 0 {
		investigation.Activity = append([]Activity{}, investigation.Activity[over:]...)
		investigation.ActivityTruncated = true
	}
}

// truncateRunes drops control characters and keeps at most max runes.
func truncateRunes(text string, max int) string {
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(text, ""))
	runes := []rune(text)
	if len(runes) > max {
		return string(runes[:max])
	}
	return text
}

func (s *Store) save(investigation Investigation) error {
	if err := validate(investigation); err != nil {
		return err
	}

	next := make(map[string]Investigation, len(s.items)+1)
	for id, item := range s.items {
		next[id] = item
	}

	next[investigation.ID] = investigation
	body, err := json.Marshal(snapshot{Schema: Schema, Items: next})
	if err != nil {
		return err
	}

	if len(body) > stateio.MaxStateBytes {
		return ErrLimit
	}

	if err = stateio.Atomic(s.root, "investigations.json", body); err != nil {
		return err
	}

	s.items = next
	return nil
}

// Create validates and atomically persists a new investigation with a fresh id.
func (s *Store) Create(input Create, actor string) (Investigation, error) {
	return s.CreateBy(input, Actor{Name: actor}, nil)
}

// CreateBy is Create with a full actor for the activity log and an optional
// campaign or session seed.
func (s *Store) CreateBy(input Create, actor Actor, seed *Seed) (Investigation, error) {
	if seed != nil && !printable(actor.Name, 80) {
		return Investigation{}, ErrInvalid
	}
	for _, id := range input.EventIDs {
		if !s.hasEvent(id) {
			return Investigation{}, ErrNotFound
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.items) >= MaxInvestigations {
		return Investigation{}, ErrLimit
	}

	id, err := auth.Token()
	if err != nil {
		return Investigation{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if input.Priority == "" {
		input.Priority = "medium"
	}

	investigation := Investigation{
		ID:        "inv_" + id,
		Title:     input.Title,
		Status:    "open",
		Priority:  input.Priority,
		CreatedAt: now,
		UpdatedAt: now,
		CreatedBy: actor.Name,
		EventIDs:  append([]string{}, input.EventIDs...),
		Notes:     []Note{},
		Activity:  []Activity{},
	}
	created := "created"
	if seed != nil {
		origin := seed.Origin
		investigation.Origin = &origin
		created = "created from " + origin.Kind + " " + origin.ID
	}
	record(&investigation, actor, ActivityCreated, created)
	if seed != nil {
		if len(investigation.EventIDs) > 0 {
			record(&investigation, actor, ActivityAttach, seed.AttachDetail)
		}
		noteID, err := auth.Token()
		if err != nil {
			return Investigation{}, err
		}
		investigation.Notes = append(investigation.Notes, Note{
			ID: "note_" + noteID, Time: now, Author: actor.Name, Text: seed.Note,
		})
		record(&investigation, actor, ActivityNote, "note added")
	}

	if err = s.save(investigation); err != nil {
		return Investigation{}, err
	}
	return copyItem(investigation), nil
}

// Get returns an independent copy of a single investigation.
func (s *Store) Get(id string) (Investigation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	investigation, ok := s.items[id]
	if !ok {
		return Investigation{}, ErrNotFound
	}

	return copyItem(investigation), nil
}

// List returns recent investigations, optionally filtered by status, without note bodies.
func (s *Store) List(status string) []Investigation {
	return s.Filter(status, nil)
}

// Filter is List with an optional assignee filter: nil selects all, a pointer
// to "" selects unassigned investigations, otherwise that principal id.
func (s *Store) Filter(status string, assignee *string) []Investigation {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := []Investigation{}
	for _, investigation := range s.items {
		if status != "" && investigation.Status != status {
			continue
		}
		if assignee != nil {
			current := ""
			if investigation.Assignee != nil {
				current = *investigation.Assignee
			}
			if current != *assignee {
				continue
			}
		}
		investigation = copyItem(investigation)
		investigation.Notes = nil
		investigation.Activity = nil
		out = append(out, investigation)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt == out[j].UpdatedAt {
			return out[i].ID < out[j].ID
		}
		return out[i].UpdatedAt > out[j].UpdatedAt
	})
	return out
}

func (s *Store) change(id string, fn func(*Investigation) error) (Investigation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	investigation, ok := s.items[id]
	if !ok {
		return Investigation{}, ErrNotFound
	}

	investigation = copyItem(investigation)
	if err := fn(&investigation); err != nil {
		return Investigation{}, err
	}

	investigation.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.save(investigation); err != nil {
		return Investigation{}, err
	}

	return copyItem(investigation), nil
}

// Patch validates and atomically persists selected annotation fields.
func (s *Store) Patch(id string, patch Patch) (Investigation, error) {
	investigation, _, err := s.PatchBy(id, patch, Actor{})
	return investigation, err
}

// PatchBy is Patch with an actor for the activity log. It also reports the
// previous assignee id ("" when none) so callers can notify a new assignee.
func (s *Store) PatchBy(id string, patch Patch, actor Actor) (Investigation, string, error) {
	if patch.Title == nil && patch.Status == nil && patch.Priority == nil && patch.Assign == nil {
		return Investigation{}, "", ErrInvalid
	}
	if patch.Assign != nil {
		assign := Actor{ID: patch.Assign.ID, Name: truncateRunes(patch.Assign.Name, 80)}
		if assign.Name == "" {
			assign.Name = assign.ID
		}
		patch.Assign = &assign
	}
	if patch.Assign != nil && patch.Assign.ID != "" &&
		(!principalIDPattern.MatchString(patch.Assign.ID) || !printable(patch.Assign.Name, 80)) {
		return Investigation{}, "", ErrInvalid
	}

	previous := ""
	investigation, err := s.change(id, func(investigation *Investigation) error {
		if investigation.Assignee != nil {
			previous = *investigation.Assignee
		}
		if patch.Title != nil && *patch.Title != investigation.Title {
			investigation.Title = *patch.Title
			record(investigation, actor, ActivityTitle, "title changed")
		}
		if patch.Status != nil && *patch.Status != investigation.Status {
			detail := investigation.Status + " → " + *patch.Status
			investigation.Status = *patch.Status
			record(investigation, actor, ActivityStatus, detail)
		}
		if patch.Priority != nil && *patch.Priority != investigation.Priority {
			detail := investigation.Priority + " → " + *patch.Priority
			investigation.Priority = *patch.Priority
			record(investigation, actor, ActivityPriority, detail)
		}
		if patch.Assign != nil && patch.Assign.ID != previous {
			if patch.Assign.ID == "" {
				investigation.Assignee, investigation.AssigneeName = nil, nil
				record(investigation, actor, ActivityAssignee, "unassigned")
			} else {
				assignee, name := patch.Assign.ID, patch.Assign.Name
				investigation.Assignee, investigation.AssigneeName = &assignee, &name
				record(investigation, actor, ActivityAssignee, "assigned to "+name+" ("+assignee+")")
			}
		}
		return nil
	})
	return investigation, previous, err
}

// AddNote appends a bounded operator annotation and atomically persists the snapshot.
func (s *Store) AddNote(id, text, actor string) (Investigation, error) {
	return s.NoteBy(id, text, Actor{Name: actor})
}

// NoteBy is AddNote with an actor for the activity log.
func (s *Store) NoteBy(id, text string, actor Actor) (Investigation, error) {
	if !validText(text, 1, 4000) {
		return Investigation{}, ErrInvalid
	}

	return s.change(id, func(investigation *Investigation) error {
		if len(investigation.Notes) >= MaxNotes {
			return ErrLimit
		}
		noteID, err := auth.Token()
		if err != nil {
			return err
		}
		investigation.Notes = append(investigation.Notes, Note{
			ID:     "note_" + noteID,
			Time:   time.Now().UTC().Format(time.RFC3339Nano),
			Author: actor.Name,
			Text:   text,
		})
		record(investigation, actor, ActivityNote, "note added")
		return nil
	})
}

// Attach idempotently adds or removes a validated evidence id; it never reads a path.
func (s *Store) Attach(id, eventID string, attach bool) (Investigation, error) {
	return s.AttachBy(id, eventID, attach, Actor{})
}

// AttachBy is Attach with an actor for the activity log; an idempotent no-op
// records no activity.
func (s *Store) AttachBy(id, eventID string, attach bool, actor Actor) (Investigation, error) {
	if !evidenceindex.ValidID(eventID) {
		return Investigation{}, ErrInvalid
	}

	return s.change(id, func(investigation *Investigation) error {
		if attach && !s.hasEvent(eventID) {
			return ErrNotFound
		}
		for i, attachedID := range investigation.EventIDs {
			if attachedID == eventID {
				if !attach {
					investigation.EventIDs = append(investigation.EventIDs[:i], investigation.EventIDs[i+1:]...)
					record(investigation, actor, ActivityDetach, "detached event "+eventID)
				}
				return nil
			}
		}
		if !s.hasEvent(eventID) {
			return ErrNotFound
		}
		if attach {
			if len(investigation.EventIDs) >= MaxEvents {
				return ErrLimit
			}
			investigation.EventIDs = append(investigation.EventIDs, eventID)
			record(investigation, actor, ActivityAttach, "attached event "+eventID)
		}
		return nil
	})
}

// Close releases the investigation state directory handle.
func (s *Store) Close() error {
	return s.root.Close()
}

func (s *Store) hasEvent(id string) bool {
	if s.index == nil {
		return true
	}
	_, _, _, _, ok := s.index.GetNode(id, "local")
	return ok
}
