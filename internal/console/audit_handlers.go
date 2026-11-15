package console

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) readAudit(w http.ResponseWriter, r *http.Request, credentials caller) {
	values, ok := query(w, r, "cursor", "limit", "action", "actor")
	if !ok {
		return
	}

	count, err := limit(values, 50, 200)
	if err != nil || len(values.Get("action")) > 64 || len(values.Get("actor")) > 64 {
		invalid(w)
		return
	}

	before := ^uint64(0)
	filter := values.Get("action") + "\x00" + values.Get("actor")
	if cursor := values.Get("cursor"); cursor != "" {
		raw, valid := s.unsign(cursor)
		parts := strings.SplitN(raw, "|", 2)
		if !valid || len(parts) != 2 || parts[1] != filter {
			invalid(w)
			return
		}
		before, err = strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			invalid(w)
			return
		}
	}

	if s.record(r, credentials.session.Principal, "audit.read", "", "ok") != nil {
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}

	records, more, err := s.audit.Read(before, count, values.Get("action"), values.Get("actor"))
	if err != nil {
		fail(w, 503, "unavailable", "audit trail is unreadable")
		return
	}

	cursor := ""
	if more {
		cursor = s.sign(fmt.Sprintf("%d|%s", records[len(records)-1].Seq, filter))
	}

	send(w, 200, map[string]any{
		"records":     records,
		"next_cursor": cursor,
	})
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request, credentials caller) {
	if s.record(r, credentials.session.Principal, "audit.verify", "", "ok") != nil {
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}

	send(w, 200, s.audit.Verify())
}

// Audit cursors bind pagination to its filters and this process.
func (s *Server) sign(values string) string {
	mac := hmac.New(sha256.New, s.key[:])
	mac.Write([]byte(values))
	return base64.RawURLEncoding.EncodeToString(append([]byte(values), mac.Sum(nil)...))
}

func (s *Server) unsign(values string) (string, bool) {
	if len(values) > 512 {
		return "", false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(values)
	if err != nil || len(decoded) < 32 {
		return "", false
	}

	payload, signature := decoded[:len(decoded)-32], decoded[len(decoded)-32:]
	mac := hmac.New(sha256.New, s.key[:])
	mac.Write(payload)
	return string(payload), hmac.Equal(signature, mac.Sum(nil))
}
