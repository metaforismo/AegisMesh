// Package redact is the single choke point for minimizing sensitive content
// before it becomes part of an event or a response. Storage and export trust
// nothing that has not passed through here.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MaxPreviewBytes bounds any raw-content preview stored in an event.
	MaxPreviewBytes = 512

	TruncationMarker = "…[truncated]"
)

// redactor pairs one credential shape with its exact replacement. A shared
// "$1=…" template was wrong for patterns without a usable capture group and
// left artifacts behind; per-pattern replacements keep scrubbing precise.
type redactor struct {
	re   *regexp.Regexp
	repl string
}

var (
	// credentialPatterns scrub common secret shapes from previews. Order
	// matters: full-value forms run before generic key=value so partial
	// consumption cannot leave half a credential behind. The JSON-key rule
	// runs before both because quoted keys never satisfy the bare [=:]
	// forms ("password":"x" is invisible to them).
	credentialPatterns = []redactor{
		{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), "[redacted-private-key]"},
		{regexp.MustCompile(`(?i)bearer\s+[a-z0-9._~+/=-]{8,512}`), "bearer [redacted]"},
		{regexp.MustCompile(`(?i)aws4-hmac-sha256\s+\S{16,512}`), "aws4-hmac-sha256 [redacted]"},
		{regexp.MustCompile(`(?i)(authorization|proxy-authorization|www-authenticate)[:]\s*[^\r\n]{1,1000}`), "$1: [redacted]"},
		{regexp.MustCompile(`(?i)((set-)?cookie)[:]\s*[^\r\n]{1,1000}`), "$1: [redacted]"},
		{regexp.MustCompile(`(?i)"(password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|session[_-]?id|client[_-]?secret|private[_-]?key)"\s*:\s*(?:"[^"]{0,1000}"|[^,\s}{\]]{1,256})`), `"$1": "[redacted]"`},
		{regexp.MustCompile(`(?i)\b(password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|session[_-]?id)[=:]\s?\S{1,256}`), "$1=[redacted]"},
	}
)

// Scrub replaces obvious credential-bearing substrings with stable markers.
func Scrub(s string) string {
	for _, r := range credentialPatterns {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// Preview converts raw bytes into a bounded, printable-safe string suitable
// for evidence storage. Control characters are escaped; invalid UTF-8 is
// replaced; credentials are scrubbed; the result notes truncation.
func Preview(b []byte, max int) (string, bool) {
	truncated := false
	if max > 0 && len(b) > max {
		b = b[:max]
		truncated = true
	}
	var sb strings.Builder
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size <= 1 {
			sb.WriteString(`\x`)
			const hexdigits = "0123456789abcdef"
			sb.WriteByte(hexdigits[b[i]>>4])
			sb.WriteByte(hexdigits[b[i]&0xf])
			i++
			continue
		}
		switch {
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			sb.WriteByte('?')
		default:
			sb.WriteRune(r)
		}
		i += size
	}
	return Scrub(sb.String()), truncated
}

// SHA256Hex hashes bytes for integrity metadata. Inputs are already bounded by
// the sensors' read caps, so this cannot be driven to unbounded work.
func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// HeaderPolicy decides which request headers keep their values in evidence.
// Everything else is recorded as name-only with its original byte length.
type HeaderPolicy struct {
	KeepValue map[string]bool // lowercased names
	MaxKept   int             // max kept-value length
}

func DefaultHeaderPolicy() HeaderPolicy {
	return HeaderPolicy{
		KeepValue: map[string]bool{
			"user-agent":   true,
			"content-type": true,
			"accept":       true,
			"server":       true,
		},
		MaxKept: 128,
	}
}

// Header returns the value (or redaction marker) to store for name/value.
func (p HeaderPolicy) Header(name, value string) string {
	if p.KeepValue[strings.ToLower(name)] {
		v := Scrub(value)
		if len(v) > p.MaxKept {
			v = truncateRunes(v, p.MaxKept) + TruncationMarker
		}
		return v
	}
	return "[redacted:len=" + strconv.Itoa(len(value)) + "]"
}

// truncateRunes cuts to at most n bytes without splitting a UTF-8 sequence.
func truncateRunes(s string, n int) string {
	for len(s) > n && !utf8.RuneStart(s[n]) {
		s = s[:n]
		n--
	}
	if len(s) > n {
		s = s[:n]
	}
	return s
}
