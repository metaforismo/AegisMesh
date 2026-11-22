// Package honeytoken matches synthetic operator-owned markers as bounded data.
package honeytoken

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	Credential    = "credential"
	AgentCanary   = "agent_canary"
	MaxEntries    = 64
	MaxInputBytes = 4 << 20
)

var ErrConfig = errors.New("honeytokens: invalid configuration")
var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

type Token struct {
	ID    string `yaml:"id" json:"id"`
	Value string `yaml:"value" json:"value"`
	Kind  string `yaml:"kind" json:"kind"`
}

type Match struct {
	ID   string
	Kind string
}

func Validate(tokens []Token) error {
	if len(tokens) > MaxEntries {
		return fmt.Errorf("%w: at most 64 entries", ErrConfig)
	}
	ids, values := map[string]bool{}, map[string]bool{}
	for i, t := range tokens {
		if !slug.MatchString(t.ID) || ids[t.ID] {
			return fmt.Errorf("%w: entry %d needs a unique slug id (1..64 lowercase letters, digits, hyphens)", ErrConfig, i)
		}
		if len(t.Value) < 16 || len(t.Value) > 256 || values[t.Value] {
			return fmt.Errorf("%w: entry %d needs a unique value of 16..256 bytes", ErrConfig, i)
		}
		for _, c := range []byte(t.Value) {
			if c < 33 || c > 126 {
				return fmt.Errorf("%w: entry %d value must be printable ASCII without spaces", ErrConfig, i)
			}
		}
		if t.Kind != Credential && t.Kind != AgentCanary {
			return fmt.Errorf("%w: entry %d kind must be credential or agent_canary", ErrConfig, i)
		}
		ids[t.ID], values[t.Value] = true, true
	}
	return nil
}

// Matcher is immutable. No patterns or executable behavior come from config.
type Matcher struct {
	tokens   []Token
	replacer *strings.Replacer
}

func New(tokens []Token) *Matcher {
	if Validate(tokens) != nil {
		return &Matcher{}
	}
	m := &Matcher{tokens: append([]Token(nil), tokens...)}
	ordered := append([]Token(nil), tokens...)
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i].Value) > len(ordered[j].Value) })
	pairs := make([]string, 0, len(ordered)*2)
	for _, token := range ordered {
		pairs = append(pairs, token.Value, "[honeytoken:"+token.ID+"]")
	}
	if len(pairs) > 0 {
		m.replacer = strings.NewReplacer(pairs...)
	}
	return m
}

// Find returns configuration-order matches, once per id, across separate fields.
// Fields are never concatenated: two partial fields cannot fabricate a match.
func (m *Matcher) Find(parts ...string) []Match {
	var out []Match
	for _, t := range m.tokens {
		for _, part := range parts {
			if len(part) > MaxInputBytes {
				part = part[:MaxInputBytes]
			}
			if strings.Contains(part, t.Value) {
				out = append(out, Match{t.ID, t.Kind})
				break
			}
		}
	}
	return out
}

// Scrub replaces original spans before preview truncation or generic scrubbing.
// Longest-first at each byte handles overlapping configured values without
// rescanning replacement markers as if they were inbound content.
func (m *Matcher) Scrub(s string) string {
	if len(s) > MaxInputBytes {
		s = s[:MaxInputBytes]
	}
	if m.replacer == nil {
		return s
	}
	return m.replacer.Replace(s)
}

// Generate produces an explicitly synthetic look-alike, never a provider key.
func Generate(id, kind, format string) (Token, error) {
	prefixes := map[string]string{"openai": "sk-synthetic-", "anthropic": "sk-ant-synthetic-", "aws": "AKIA-SYNTHETIC-", "github": "ghp_synthetic_", "generic": "synthetic-"}
	prefix, ok := prefixes[format]
	if !ok {
		return Token{}, fmt.Errorf("%w: format must be openai, anthropic, aws, github or generic", ErrConfig)
	}
	t := Token{ID: id, Kind: kind, Value: prefix + strings.Repeat("0", 32)}
	if err := Validate([]Token{t}); err != nil {
		return Token{}, err
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Token{}, fmt.Errorf("honeytokens: random generation: %w", err)
	}
	t.Value = prefix + hex.EncodeToString(raw[:])
	return t, nil
}
