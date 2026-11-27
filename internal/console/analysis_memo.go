package console

import (
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/recommend"
)

// analysisMemo lets the requests of one tenant view share derived analysis for
// one index generation, so N reads between two appends cost one computation.
//
// Bounds: each view keeps only its newest generation (one 8,192-summary sample
// and what is derived from it), one recommendation report and one digest
// recommendation count. An append, eviction or history change advances the
// index generation and the next request replaces the entry; nothing is merged
// across generations or tenants. Snapshots taken while a live node-name
// resolver is installed have generation zero and are never memoised.
//
// Sessions of a new generation are derived incrementally from the newest
// earlier generation whose sessions were computed (evidenceview.UpdateSessions,
// byte-identical to a full recompute), so at most one older sample and its
// sessions stay referenced until the new generation's sessions exist.
type analysisMemo struct {
	mu              sync.Mutex
	current         *analysisResult
	recommendations *recommendationMemo
	digest          *digestMemo
}

type recommendationMemo struct {
	generation uint64
	limit      int
	report     recommend.Report
}

type digestMemo struct {
	generation uint64
	ids        [sha256.Size]byte
	count      int
	missing    int
}

// incrementalSessions counts generations whose sessions were derived from a
// base generation (tests assert the incremental path is exercised).
var incrementalSessions atomic.Int64

// analysisResult is immutable once each lazily derived value is computed.
// Callers must treat every returned slice, map and pointer as read-only.
type analysisResult struct {
	snapshot evidenceindex.Snapshot
	tenant   string

	sessionsOnce sync.Once
	sessions     []evidenceview.Session
	// base is an earlier generation whose sessions are computed, or nil; it
	// is released once this generation's sessions exist.
	base          atomic.Pointer[analysisResult]
	sessionsReady atomic.Bool

	campaignsOnce sync.Once
	campaigns     evidenceview.CampaignSet

	digestOnce  sync.Once
	digestState []byte

	eventsOnce     sync.Once
	sessionByEvent map[string]string
}

// analysis returns the shared derivation for the index's current generation.
func (s *Server) analysis() *analysisResult {
	snapshot := s.index.SharedAnalysis()
	fresh := &analysisResult{snapshot: snapshot, tenant: s.tenantID}
	generation := snapshot.Generation()
	if generation == 0 {
		return fresh
	}
	s.memo.mu.Lock()
	defer s.memo.mu.Unlock()
	current := s.memo.current
	if current != nil && current.snapshot.Generation() == generation {
		return current
	}
	// A request holding an older snapshot never replaces a newer entry.
	if current == nil || generation > current.snapshot.Generation() {
		if current != nil {
			// Keep the chain at depth one: the base always has its sessions.
			if current.sessionsReady.Load() {
				fresh.base.Store(current)
			} else {
				fresh.base.Store(current.base.Load())
			}
		}
		s.memo.current = fresh
	}
	return fresh
}

// Sessions is evidenceview.Sessions over the snapshot, computed once, and
// incrementally from the base generation when there is one.
func (a *analysisResult) Sessions() []evidenceview.Session {
	a.sessionsOnce.Do(func() {
		if base := a.base.Load(); base != nil && base.sessionsReady.Load() {
			incrementalSessions.Add(1)
			a.sessions = evidenceview.UpdateSessions(a.tenant, base.snapshot.Events, base.sessions, a.snapshot.Events)
		} else {
			a.sessions = evidenceview.Sessions(a.tenant, a.snapshot.Events)
		}
		a.base.Store(nil)
		a.sessionsReady.Store(true)
	})
	return a.sessions
}

// Campaigns is evidenceview.Campaigns over Sessions, computed once.
func (a *analysisResult) Campaigns() evidenceview.CampaignSet {
	a.campaignsOnce.Do(func() { a.campaigns = evidenceview.Campaigns(a.tenant, a.Sessions()) })
	return a.campaigns
}

// sessionOf returns the ID of the session containing an event key, or "".
// When several sessions contain the key the last one wins, as in the former
// per-request scan.
func (a *analysisResult) sessionOf(key string) string {
	a.eventsOnce.Do(func() {
		a.sessionByEvent = map[string]string{}
		for _, session := range a.Sessions() {
			for _, e := range session.Events {
				a.sessionByEvent[evidenceview.EventKey(e)] = session.ID
			}
		}
	})
	return a.sessionByEvent[key]
}

// digest returns analysisDigest(snapshot, source, window) byte-for-byte. The
// SHA-256 state after the shared `{"Events":[...]` prefix is computed once per
// generation; each request hashes only its own source and window suffix.
func (a *analysisResult) digest(source, window string) string {
	a.digestOnce.Do(func() {
		events, err := json.Marshal(a.snapshot.Events)
		if err != nil {
			return
		}
		h := sha256.New()
		h.Write([]byte(`{"Events":`))
		h.Write(events)
		state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err == nil {
			a.digestState = state
		}
	})
	if a.digestState == nil {
		return analysisDigest(a.snapshot, source, window)
	}
	h := sha256.New()
	if h.(encoding.BinaryUnmarshaler).UnmarshalBinary(a.digestState) != nil {
		return analysisDigest(a.snapshot, source, window)
	}
	quotedSource, _ := json.Marshal(source)
	quotedWindow, _ := json.Marshal(window)
	h.Write([]byte(`,"Source":`))
	h.Write(quotedSource)
	h.Write([]byte(`,"Window":`))
	h.Write(quotedWindow)
	h.Write([]byte(`}`))
	digest := h.Sum(nil)
	return hex.EncodeToString(digest[:16])
}

// recommendations returns recommend.Generate over the index's newest local
// envelopes, reusing the report while the index generation is unchanged.
func (s *Server) recommendationReport(limit int) (recommend.Report, error) {
	s.memo.mu.Lock()
	cached := s.memo.recommendations
	s.memo.mu.Unlock()
	if cached != nil && cached.limit == limit && cached.generation == s.index.Generation() {
		return cached.report, nil
	}
	envelopes, generation := s.index.EnvelopesAt(recommend.MaxEvidence)
	report, err := recommend.Generate(envelopes, recommend.Options{Limit: limit})
	if err != nil {
		return report, err
	}
	s.memo.mu.Lock()
	if current := s.memo.recommendations; current == nil || generation >= current.generation {
		s.memo.recommendations = &recommendationMemo{generation: generation, limit: limit, report: report}
	}
	s.memo.mu.Unlock()
	return report, nil
}

// errDigestInputs marks a digest whose recommendation inputs exceed limits,
// as distinct from evidence that cannot produce verified recommendations.
var errDigestInputs = errors.New("digest recommendation inputs exceed limits")

// digestRecommendations counts proposals over the given local event IDs and
// reports how many were no longer indexed, reusing the result while the
// snapshot generation, the ID list and the index generation all match.
func (s *Server) digestRecommendations(snapshot evidenceindex.Snapshot, ids []string) (int, int, error) {
	key := sha256.Sum256([]byte(strings.Join(ids, ",")))
	generation := snapshot.Generation()
	if generation != 0 {
		s.memo.mu.Lock()
		cached := s.memo.digest
		s.memo.mu.Unlock()
		if cached != nil && cached.generation == generation && cached.ids == key && s.index.Generation() == generation {
			return cached.count, cached.missing, nil
		}
	}
	envelopes, missing, readAt, err := s.index.LocalEvidenceAt(ids)
	if err != nil {
		return 0, 0, errDigestInputs
	}
	proposals, err := recommend.Generate(envelopes, recommend.Options{Limit: 20})
	if err != nil {
		return 0, 0, err
	}
	if generation != 0 && readAt == generation {
		s.memo.mu.Lock()
		s.memo.digest = &digestMemo{generation: generation, ids: key, count: len(proposals.Recommendations), missing: missing}
		s.memo.mu.Unlock()
	}
	return len(proposals.Recommendations), missing, nil
}
