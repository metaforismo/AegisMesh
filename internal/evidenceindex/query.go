package evidenceindex

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrQuery marks invalid filters, limits, or cursor authentication.
var ErrQuery = errors.New("invalid index query")

// Filter contains validated selection criteria and trusted cursor scope; limits do not affect cursor identity.
type Filter struct {
	// Node selects an authenticated node ID, or local observations.
	Node string
	// CursorScope is assigned by the trusted caller to isolate pagination by endpoint.
	CursorScope string
	// Classification selects one recognized observation classification.
	Classification string
	// Sensor selects a sensor identifier.
	Sensor string
	// Kind selects a sensor protocol.
	Kind string
	// Source selects the exact stored source value.
	Source string
	// Rule selects observations associated with a rule id.
	Rule string
	// Severity sets the minimum catalog severity.
	Severity string
	// Q is a bounded case-insensitive search over display metadata.
	Q string
	// Since sets an inclusive lower timestamp bound when nonzero.
	Since time.Time
	// Until sets an inclusive upper timestamp bound when nonzero.
	Until time.Time
	// Cursor holds a signed continuation token.
	Cursor string `json:"-"`
	// Limit bounds returned summaries to 1..200.
	Limit int `json:"-"`
}

// ParseFilter rejects unknown, duplicate, oversized, or malformed query values.
func ParseFilter(values url.Values) (Filter, error) {
	filter := Filter{Limit: 50}
	allowed := map[string]bool{
		"node":           true,
		"classification": true,
		"sensor":         true,
		"kind":           true,
		"source":         true,
		"rule":           true,
		"severity":       true,
		"since":          true,
		"until":          true,
		"q":              true,
		"cursor":         true,
		"limit":          true,
	}

	for key, vals := range values {
		if !allowed[key] || len(vals) != 1 || len(vals[0]) > 512 || !utf8.ValidString(vals[0]) {
			return filter, ErrQuery
		}
	}

	filter.Node = values.Get("node")
	if filter.Node != "" && filter.Node != "local" && !ValidID(filter.Node) {
		return filter, ErrQuery
	}
	filter.Classification = values.Get("classification")
	filter.Sensor = values.Get("sensor")
	filter.Kind = values.Get("kind")
	filter.Source = values.Get("source")
	filter.Rule = values.Get("rule")
	filter.Severity = values.Get("severity")
	filter.Q = values.Get("q")
	filter.Cursor = values.Get("cursor")
	if len(filter.Source) > 255 ||
		len(filter.Sensor) > 64 ||
		len(filter.Kind) > 32 ||
		len(filter.Rule) > 32 ||
		utf8.RuneCountInString(filter.Q) > 128 ||
		!utf8.ValidString(filter.Q) {
		return filter, ErrQuery
	}

	if filter.Classification != "" &&
		filter.Classification != "interaction" &&
		filter.Classification != "canary_invocation" &&
		filter.Classification != "correlation_signal" {
		return filter, ErrQuery
	}

	if filter.Severity != "" && Rank(filter.Severity) == 0 {
		return filter, ErrQuery
	}

	if value := values.Get("limit"); value != "" {
		count, err := strconv.Atoi(value)
		if err != nil || count < 1 || count > 200 {
			return filter, ErrQuery
		}
		filter.Limit = count
	}

	for key, dst := range map[string]*time.Time{
		"since": &filter.Since,
		"until": &filter.Until,
	} {
		if value := values.Get(key); value != "" {
			timestamp, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return filter, ErrQuery
			}
			*dst = timestamp
		}
	}

	if !filter.Since.IsZero() && !filter.Until.IsZero() && filter.Since.After(filter.Until) {
		return filter, ErrQuery
	}

	return filter, nil
}

// Matches selects live summaries using the same validated filters as paginated queries.
func (filter Filter) Matches(summary Summary) bool { return filter.matches(summary) }

func searchText(summary Summary) string {
	return strings.ToLower(summary.Summary + " " + summary.Source + " " + strings.Join(summary.RuleIDs, " "))
}

func (filter Filter) selectsAll() bool {
	return filter.Node == "" && filter.Classification == "" && filter.Sensor == "" && filter.Kind == "" && filter.Source == "" && filter.Rule == "" && filter.Severity == "" && filter.Q == "" && filter.Since.IsZero() && filter.Until.IsZero()
}

func (filter Filter) matches(summary Summary) bool {
	var timestamp time.Time
	if !filter.Since.IsZero() || !filter.Until.IsZero() {
		timestamp, _ = time.Parse(time.RFC3339Nano, summary.Time)
	}
	var search string
	if filter.Q != "" {
		search = searchText(summary)
	}
	return filter.matchesAt(summary, timestamp, search, strings.ToLower(filter.Q))
}

func (filter Filter) matchesAt(summary Summary, timestamp time.Time, search, needle string) bool {
	if filter.Node == "local" && summary.Node != nil ||
		filter.Node != "" && filter.Node != "local" && (summary.Node == nil || summary.Node.ID != filter.Node) {
		return false
	}
	if (filter.Classification != "" && filter.Classification != summary.Classification) ||
		(filter.Sensor != "" && filter.Sensor != summary.Sensor.ID) ||
		(filter.Kind != "" && filter.Kind != summary.Sensor.Kind) ||
		(filter.Source != "" && filter.Source != summary.Source) ||
		Rank(summary.Severity) < Rank(filter.Severity) {
		return false
	}

	if !filter.Since.IsZero() &&
		timestamp.Before(filter.Since) ||
		!filter.Until.IsZero() &&
			timestamp.After(filter.Until) {
		return false
	}

	if filter.Rule != "" {
		found := false
		for _, ruleID := range summary.RuleIDs {
			found = found || ruleID == filter.Rule
		}
		if !found {
			return false
		}
	}

	return needle == "" || strings.Contains(search, needle)
}

type cursor struct {
	Time   time.Time `json:"t"`
	Before uint64    `json:"b"`
	Filter string    `json:"f"`
}

func fingerprint(filter Filter) string {
	body, _ := json.Marshal(filter)
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:16])
}

func (index *Index) encodeCursor(timestamp time.Time, count uint64, filter Filter) string {
	body, _ := json.Marshal(cursor{
		Time:   timestamp,
		Before: count,
		Filter: fingerprint(filter),
	})
	mac := hmac.New(sha256.New, index.key[:])
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(append(body, mac.Sum(nil)...))
}

func (index *Index) decodeCursor(filter Filter) (cursor, error) {
	if filter.Cursor == "" {
		return cursor{}, nil
	}

	if len(filter.Cursor) > 512 {
		return cursor{}, ErrQuery
	}

	body, err := base64.RawURLEncoding.DecodeString(filter.Cursor)
	if err != nil || len(body) < 33 {
		return cursor{}, ErrQuery
	}

	payload, signature := body[:len(body)-32], body[len(body)-32:]
	mac := hmac.New(sha256.New, index.key[:])
	mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return cursor{}, ErrQuery
	}

	var cursorValue cursor
	if json.Unmarshal(payload, &cursorValue) != nil || cursorValue.Filter != fingerprint(filter) {
		return cursor{}, ErrQuery
	}

	return cursorValue, nil
}
