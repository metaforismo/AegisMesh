// Package investigations persists bounded operator annotations separately from evidence.
// Untrusted annotation text is stored as data and never selects files or changes runtime behavior.
package investigations

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/stateio"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// MaxInvestigations bounds the number of persisted investigations.
const MaxInvestigations = 1000

// MaxNotes bounds notes per investigation.
const MaxNotes = 100

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

	if err = json.Unmarshal(body, &store.items); err != nil || store.items == nil || len(store.items) > MaxInvestigations {
		root.Close()
		return nil, fmt.Errorf(
			"%w: investigations.json corrupt or over quota; inspect state and restore a verified backup", ErrInvalid,
		)
	}

	for id, investigation := range store.items {
		if id != investigation.ID || validate(investigation) != nil {
			root.Close()
			return nil, fmt.Errorf(
				"%w: investigations.json contains an invalid record; inspect state and restore a verified backup", ErrInvalid,
			)
		}
	}

	return store, nil
}

func validText(text string, min, max int) bool {
	return utf8.ValidString(text) && utf8.RuneCountInString(text) >= min && utf8.RuneCountInString(text) <= max
}

func validate(investigation Investigation) error {
	if !validText(investigation.Title, 1, 200) ||
		len(investigation.EventIDs) > 200 ||
		len(investigation.Notes) > MaxNotes {
		return ErrInvalid
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
	investigation.Events = nil
	return investigation
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
	body, err := json.Marshal(next)
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
		CreatedBy: actor,
		EventIDs:  append([]string{}, input.EventIDs...),
		Notes:     []Note{},
	}

	err = s.save(investigation)
	return copyItem(investigation), err
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
	s.mu.Lock()
	defer s.mu.Unlock()

	out := []Investigation{}
	for _, investigation := range s.items {
		if status != "" && investigation.Status != status {
			continue
		}
		investigation = copyItem(investigation)
		investigation.Notes = nil
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
	if patch.Title == nil && patch.Status == nil && patch.Priority == nil {
		return Investigation{}, ErrInvalid
	}

	return s.change(id, func(investigation *Investigation) error {
		if patch.Title != nil {
			investigation.Title = *patch.Title
		}
		if patch.Status != nil {
			investigation.Status = *patch.Status
		}
		if patch.Priority != nil {
			investigation.Priority = *patch.Priority
		}
		return nil
	})
}

// AddNote appends a bounded operator annotation and atomically persists the snapshot.
func (s *Store) AddNote(id, text, actor string) (Investigation, error) {
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
			Author: actor,
			Text:   text,
		})
		return nil
	})
}

// Attach idempotently adds or removes a validated evidence id; it never reads a path.
func (s *Store) Attach(id, eventID string, attach bool) (Investigation, error) {
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
				}
				return nil
			}
		}
		if !s.hasEvent(eventID) {
			return ErrNotFound
		}
		if attach {
			if len(investigation.EventIDs) >= 200 {
				return ErrLimit
			}
			investigation.EventIDs = append(investigation.EventIDs, eventID)
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
