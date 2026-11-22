// Package eventexport renders bounded local SIEM files. It has no transport.
package eventexport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/metaforismo/aegismesh/internal/ecsexport"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

const (
	// MaxEvents caps a single export.
	MaxEvents = 8192
	// MaxBytes caps staged output before any attachment or file write.
	MaxBytes = 2 << 20
)

// Record preserves the authenticated origin separately from native evidence.
type Record = event.OriginEnvelope

// ValidFormat accepts only the four local file encodings.
func ValidFormat(format string) bool {
	switch format {
	case "cef", "syslog-rfc5424", "otlp-json", "ecs":
		return true
	}
	return false
}

// Render validates all evidence and stages deterministic bytes before disclosure.
func Render(records []Record, format string) ([]byte, error) {
	if !ValidFormat(format) {
		return nil, errors.New("unsupported event format")
	}
	if len(records) > MaxEvents {
		return nil, errors.New("event export exceeds 8192 events")
	}
	records = append([]Record{}, records...)
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if !a.Envelope.Time.Equal(b.Envelope.Time) {
			return a.Envelope.Time.Before(b.Envelope.Time)
		}
		if a.NodeID != b.NodeID {
			return a.NodeID < b.NodeID
		}
		return a.Envelope.ID < b.Envelope.ID
	})
	var out bytes.Buffer
	logs := []any{}
	for _, record := range records {
		e := record.Envelope
		if e.Validate() != nil || e.VerifyIntegrity() != nil || !evidenceindex.ValidID(e.ID) || record.NodeID != "" && record.NodeID != "local" && !evidenceindex.ValidID(record.NodeID) {
			return nil, errors.New("invalid event export evidence")
		}
		summary, _, _ := evidenceindex.Project(e)
		node := record.NodeID
		if node == "" {
			node = "local"
		}
		severity, cef, syslog, otlp := severity(summary.Severity)
		switch format {
		case "cef":
			fmt.Fprintf(&out, "CEF:0|AegisMesh|AegisMesh|1|%s|%s|%d|externalId=%s cs3Label=source cs3=%s cs1Label=node_id cs1=%s cs2Label=sensor_id cs2=%s rt=%d cs4Label=rule_ids cs4=%s msg=%s\n", cefHeader(e.Classification), cefHeader(summary.Summary), cef, cefValue(e.ID), cefValue(summary.Source), cefValue(node), cefValue(e.Sensor.ID), e.Time.UnixMilli(), cefValue(strings.Join(summary.RuleIDs, ",")), cefValue(summary.Summary))
		case "syslog-rfc5424":
			fmt.Fprintf(&out, "<%d>1 %s - AegisMesh - observation [aegismesh@32473 event_id=\"%s\" node_id=\"%s\" sensor_id=\"%s\" source=\"%s\" severity=\"%s\" rule_ids=\"%s\"] %s\n", 128+syslog, e.Time.UTC().Format("2006-01-02T15:04:05.000000Z07:00"), structured(e.ID), structured(node), structured(e.Sensor.ID), structured(summary.Source), severity, structured(strings.Join(summary.RuleIDs, ",")), line(summary.Summary))
		case "ecs":
			body, err := ecsexport.Marshal(e)
			if err != nil {
				return nil, err
			}
			var doc map[string]json.RawMessage
			_ = json.Unmarshal(body, &doc)
			origin, _ := json.Marshal(node)
			doc["aegismesh.node_id"] = origin
			body, err = json.Marshal(doc)
			if err != nil {
				return nil, err
			}
			out.Write(body)
			out.WriteByte('\n')
		case "otlp-json":
			if e.Time.Before(time.Unix(0, 0)) || e.Time.After(time.Unix(0, math.MaxInt64)) {
				return nil, errors.New("event timestamp outside supported OTLP nanosecond range")
			}
			attributes := []any{}
			for _, kv := range [][2]string{{"event.id", e.ID}, {"aegismesh.node_id", node}, {"sensor.id", e.Sensor.ID}, {"source.address", summary.Source}, {"event.action", e.Classification}, {"rule.ids", strings.Join(summary.RuleIDs, ",")}} {
				attributes = append(attributes, map[string]any{"key": kv[0], "value": map[string]string{"stringValue": kv[1]}})
			}
			logs = append(logs, map[string]any{"timeUnixNano": strconv.FormatInt(e.Time.UnixNano(), 10), "severityNumber": otlp, "severityText": severity, "body": map[string]string{"stringValue": summary.Summary}, "attributes": attributes})
		}
		if out.Len() > MaxBytes {
			return nil, errors.New("event export exceeds 2 MiB")
		}
		// OTLP is staged as independent bounded records before the final container.
		if format == "otlp-json" {
			body, _ := json.Marshal(logs[len(logs)-1])
			out.Write(body)
			if out.Len() > MaxBytes {
				return nil, errors.New("event export exceeds 2 MiB")
			}
		}
	}
	if format == "otlp-json" {
		body, err := json.Marshal(map[string]any{"resourceLogs": []any{map[string]any{"resource": map[string]any{"attributes": []any{map[string]any{"key": "service.name", "value": map[string]string{"stringValue": "aegismesh"}}}}, "scopeLogs": []any{map[string]any{"scope": map[string]string{"name": "aegismesh.eventexport"}, "logRecords": logs}}}}})
		if err != nil {
			return nil, err
		}
		body = append(body, '\n')
		if len(body) > MaxBytes {
			return nil, errors.New("event export exceeds 2 MiB")
		}
		return body, nil
	}
	return out.Bytes(), nil
}

func severity(value string) (string, int, int, int) {
	switch value {
	case "critical":
		return value, 10, 2, 21
	case "high":
		return value, 7, 3, 17
	case "medium":
		return value, 4, 4, 13
	case "low":
		return value, 1, 5, 9
	default:
		return "info", 0, 6, 9
	}
}

func line(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
}
func cefHeader(s string) string { return strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(line(s)) }
func cefValue(s string) string  { return strings.NewReplacer(`\`, `\\`, `=`, `\=`).Replace(line(s)) }
func structured(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(line(s))
}
