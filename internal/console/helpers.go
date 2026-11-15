package console

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func query(w http.ResponseWriter, r *http.Request, allowed ...string) (url.Values, bool) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(w, 400, "invalid_argument", "malformed query")
		return nil, false
	}

	for key, entries := range values {
		valid := false
		for _, parameter := range allowed {
			valid = valid || key == parameter
		}
		if !valid || len(entries) != 1 || len(entries[0]) > 512 {
			fail(w, 400, "invalid_argument", "unknown, duplicate or oversized query parameter")
			return nil, false
		}
	}

	return values, true
}

func limit(values url.Values, defaultLimit, maxLimit int) (int, error) {
	value := values.Get("limit")
	if value == "" {
		return defaultLimit, nil
	}

	count, err := strconv.Atoi(value)
	if err != nil || count < 1 || count > maxLimit {
		return 0, evidenceindex.ErrQuery
	}

	return count, nil
}

func invalid(w http.ResponseWriter) {
	fail(w, 400, "invalid_argument", "invalid query or cursor")
}

func send(w http.ResponseWriter, status int, values any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(values)
}

func fail(w http.ResponseWriter, status int, code, message string) {
	send(w, status, map[string]any{"error": map[string]string{
		"code":    code,
		"message": message,
	}})
}

func strictBody(w http.ResponseWriter, r *http.Request, values any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "application/json" && ct != "application/json; charset=utf-8" {
		fail(w, 400, "invalid_argument", "Content-Type must be application/json")
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	body, err := io.ReadAll(r.Body)
	if err != nil || !validObject(body) {
		fail(w, 400, "invalid_argument", "invalid JSON object (64 KiB maximum; duplicate keys rejected)")
		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(values); err != nil {
		fail(w, 400, "invalid_argument", "invalid JSON body (64 KiB maximum)")
		return false
	}

	var extra any
	if decoder.Decode(&extra) != io.EOF {
		fail(w, 400, "invalid_argument", "exactly one JSON object is required")
		return false
	}

	return true
}
