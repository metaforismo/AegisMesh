package honeytoken

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestValidation(t *testing.T) {
	valid := Token{"plant-one", "synthetic-token-one", Credential}
	cases := []struct {
		name   string
		tokens []Token
		ok     bool
	}{
		{"empty", nil, true}, {"valid", []Token{valid}, true},
		{"kind", []Token{{valid.ID, valid.Value, "other"}}, false},
		{"id", []Token{{"../path", valid.Value, Credential}}, false},
		{"long id", []Token{{strings.Repeat("a", 65), valid.Value, Credential}}, false},
		{"placeholder", []Token{{valid.ID, "REPLACE_WITH_GENERATED_TOKEN", Credential}}, false},
		{"short value", []Token{{valid.ID, "tiny", Credential}}, false},
		{"long value", []Token{{valid.ID, strings.Repeat("x", 257), Credential}}, false},
		{"control", []Token{{valid.ID, "synthetic-token\nvalue", Credential}}, false},
		{"duplicate", []Token{valid, valid}, false},
		{"duplicate value", []Token{valid, {"two", valid.Value, AgentCanary}}, false},
		{"duplicate id", []Token{valid, {valid.ID, "synthetic-token-two", AgentCanary}}, false},
		{"limit", make([]Token, 65), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.tokens)
			if (err == nil) != tc.ok {
				t.Fatalf("valid=%v, err=%v", tc.ok, err)
			}
			if err != nil && !errors.Is(err, ErrConfig) {
				t.Fatal(err)
			}
			if err != nil && strings.Contains(err.Error(), valid.Value) {
				t.Fatal("value leaked")
			}
		})
	}
}

func TestMatchingAndRedaction(t *testing.T) {
	tokens := []Token{{"one", "synthetic-token-one", Credential}, {"two", "synthetic-token-one-extra", AgentCanary}}
	m := New(tokens)
	got := m.Find("prefix "+tokens[1].Value, "again "+tokens[0].Value)
	if !reflect.DeepEqual(got, []Match{{"one", Credential}, {"two", AgentCanary}}) {
		t.Fatal(got)
	}
	if s := m.Scrub("x " + tokens[1].Value + " " + tokens[0].Value); s != "x [honeytoken:two] [honeytoken:one]" {
		t.Fatal(s)
	}
	if got := m.Find("synthetic-", "token-one"); len(got) != 0 {
		t.Fatal("cross-field match")
	}
	// Replacement must precede preview truncation, and matching must cover
	// values beyond the detector's separate 64 KiB text cap.
	input := strings.Repeat(".", 70<<10) + tokens[0].Value
	if len(m.Find(input)) != 1 || strings.Contains(m.Scrub(input), tokens[0].Value) {
		t.Fatal("late token missed")
	}
	tokens[0].Value = "mutated-original"
	if len(m.Find("synthetic-token-one")) != 1 {
		t.Fatal("aliased config")
	}
}

func TestGenerate(t *testing.T) {
	patterns := map[string]string{"openai": `^sk-proj-[A-Za-z0-9]{48}$`, "anthropic": `^sk-ant-api03-[A-Za-z0-9_-]{86}AA$`, "aws": `^AKIA[A-Z2-7]{16}$`, "github": `^ghp_[A-Za-z0-9]{36}$`, "generic": `^[0-9a-f]{40}$`}
	for format, pattern := range patterns {
		a, err := Generate("test-marker", Credential, format)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Generate("test-marker", AgentCanary, format)
		if err != nil {
			t.Fatal(err)
		}
		if a.Value == b.Value || !regexp.MustCompile(pattern).MatchString(a.Value) || !regexp.MustCompile(pattern).MatchString(b.Value) {
			t.Fatal("non-random or incorrect format")
		}
	}
	if _, err := Generate("bad/id", Credential, "generic"); err == nil {
		t.Fatal("invalid id accepted")
	}
	if _, err := Generate("valid", Credential, "other"); err == nil {
		t.Fatal("invalid format accepted")
	}
}

func FuzzMatcher(f *testing.F) {
	f.Add("synthetic-token-one")
	f.Add("\x00invalid\xff")
	m := New([]Token{{"one", "synthetic-token-one", Credential}})
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > MaxInputBytes {
			return
		}
		got := m.Find(s)
		scrubbed := m.Scrub(s)
		if len(got) > 1 || strings.Contains(scrubbed, "synthetic-token-one") {
			t.Fatal("unsafe match or scrub")
		}
	})
}

func TestAcceptedValueAndEntryBounds(t *testing.T) {
	for _, length := range []int{16, 256} {
		if err := Validate([]Token{{"edge", strings.Repeat("x", length), Credential}}); err != nil {
			t.Fatal(err)
		}
	}
	var tokens []Token
	for i := 0; i < 64; i++ {
		suffix := string(rune('A'+i/26)) + string(rune('A'+i%26))
		tokens = append(tokens, Token{"plant-" + strings.ToLower(suffix), "synthetic-marker-" + suffix, Credential})
	}
	if err := Validate(tokens); err != nil {
		t.Fatal(err)
	}
}

func TestRepeatedMarkersUseOriginalSpans(t *testing.T) {
	var tokens []Token
	for i := 0; i < 64; i++ {
		suffix := string(rune('A'+i/26)) + string(rune('A'+i%26))
		tokens = append(tokens, Token{"plant-" + strings.ToLower(suffix), "synthetic-marker-" + suffix, Credential})
	}
	m := New(tokens)
	input := strings.Repeat(tokens[0].Value, 8192)
	scrubbed := m.Scrub(input)
	if strings.Contains(scrubbed, tokens[0].Value) || strings.Count(scrubbed, "[honeytoken:plant-aa]") != 8192 {
		t.Fatal("repeated matches were dropped or rescanned")
	}
}
