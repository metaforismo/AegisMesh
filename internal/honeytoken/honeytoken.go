// Package honeytoken matches synthetic operator-owned markers as bounded data.
package honeytoken

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	// Credential marks decoy credentials; AgentCanary marks instruction-following markers.
	Credential    = "credential"
	AgentCanary   = "agent_canary"
	MaxEntries    = 64
	MaxInputBytes = 4 << 20
)

// ErrConfig identifies invalid marker configuration without exposing values.
var ErrConfig = errors.New("honeytokens: invalid configuration")
var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Token is an operator-owned marker and its safe public identifier.
type Token struct {
	ID    string `yaml:"id" json:"id"`
	Value string `yaml:"value" json:"value"`
	Kind  string `yaml:"kind" json:"kind"`
}

// Match identifies a marker without retaining its value.
type Match struct {
	ID   string
	Kind string
}

// Validate checks bounded, unique printable markers and rejects template placeholders.
func Validate(tokens []Token) error {
	if len(tokens) > MaxEntries {
		return fmt.Errorf("%w: at most 64 entries", ErrConfig)
	}
	ids, values := map[string]bool{}, map[string]bool{}
	for i, t := range tokens {
		if !slug.MatchString(t.ID) || ids[t.ID] {
			return fmt.Errorf("%w: entry %d needs a unique slug id (1..64 lowercase letters, digits, hyphens)", ErrConfig, i)
		}
		if strings.HasPrefix(t.Value, "REPLACE_WITH_") {
			return fmt.Errorf("%w: entry %d has an unreplaced placeholder; use aegismesh honeytoken new", ErrConfig, i)
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

// New builds an immutable matcher; invalid configuration produces an empty matcher.
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

// Generate produces an unregistered random provider-shaped decoy value locally.
// It never contacts a provider. Shape alone cannot prove provider invalidity.
func Generate(id, kind, format string) (Token, error) {
	const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var prefix, suffix, alphabet string
	var length int
	switch format {
	case "openai":
		prefix, alphabet, length = "sk-proj-", base62, 48
	case "anthropic":
		prefix, suffix, alphabet, length = "sk-ant-api03-", "AA", base62+"_-", 86
	case "aws":
		prefix, alphabet, length = "AKIA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16
	case "github":
		prefix, alphabet, length = "ghp_", base62, 36
	case "generic":
		alphabet, length = "0123456789abcdef", 40
	default:
		return Token{}, fmt.Errorf("%w: format must be openai, anthropic, aws, github or generic", ErrConfig)
	}
	t := Token{ID: id, Kind: kind, Value: prefix + strings.Repeat("0", length) + suffix}
	if err := Validate([]Token{t}); err != nil {
		return Token{}, err
	}
	value, err := randomCharacters(alphabet, length)
	if err != nil {
		return Token{}, fmt.Errorf("honeytokens: random generation: %w", err)
	}
	t.Value = prefix + value + suffix
	return t, nil
}

// Rejection sampling discards the incomplete final bucket, avoiding modulo bias.
func randomCharacters(alphabet string, length int) (string, error) {
	out := make([]byte, 0, length)
	ceiling := 256 - 256%len(alphabet)
	var random [128]byte
	for len(out) < length {
		if _, err := rand.Read(random[:]); err != nil {
			return "", err
		}
		for _, b := range random {
			if int(b) < ceiling {
				out = append(out, alphabet[int(b)%len(alphabet)])
				if len(out) == length {
					break
				}
			}
		}
	}
	return string(out), nil
}
