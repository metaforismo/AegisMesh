package evidenceview

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/redact"
)

const (
	// MaxShapeRunes caps one normalised step description.
	MaxShapeRunes = 120
	// MaxShapeSegments caps the path segments kept in an HTTP path template.
	MaxShapeSegments = 12
	// MaxSegmentRunes is the longest literal path segment kept; longer ones collapse to {token}.
	MaxSegmentRunes = 32
	// MaxShapeSteps caps the collapsed step sequence derived from one session.
	MaxShapeSteps = 32
)

// interaction is the per-event view used by shapes, actor signals and campaigns.
// Every text field is derived from the bounded, already scrubbed index summary.
type interaction struct {
	at     time.Time
	sensor string
	kind   string
	shape  string
	method string // HTTP or MCP method
	path   string // raw (scrubbed, bounded) HTTP path, used only for edit distance
	tool   string // MCP tool name for tools/call
	status int    // HTTP decoy response status, or 0
	stage  string
	client string
}

// step is one entry of a session's collapsed shape sequence.
type step struct {
	kind  string
	shape string
	stage string
}

// Shape normalises one stored observation summary into a bounded, scrubbed,
// attacker-influenced step description. It never returns an empty string.
func Shape(kind, classification, summary string) string {
	shape, _, _, _ := shapeParts(kind, classification, summary, 0)
	return shape
}

// shapeParts returns the shape plus parsed method, raw path and MCP tool.
// status is the projection's verified HTTP status, used to strip the suffix.
// Method, path and tool are comparison inputs only and are never rendered;
// every rendered shape passes finishShape.
func shapeParts(kind, classification, summary string, status int) (shape, method, path, tool string) {
	summary = evidenceindex.Bound(summary, 160)
	if classification == event.ClassificationCorrelationSignal {
		return finishShape(kind + " signal"), "", "", ""
	}
	switch kind {
	case "http":
		if status >= 100 && status <= 599 {
			summary = strings.TrimSuffix(summary, fmt.Sprintf(" → %d", status))
		}
		rawMethod, rawPath, ok := strings.Cut(summary, " ")
		if !ok || rawPath == "" || summary == "http observation" {
			return "http (unparsed)", "", "", ""
		}
		method = normaliseMethod(rawMethod)
		path = evidenceindex.Bound(rawPath, 128)
		return finishShape(method + " " + PathTemplate(path)), method, path, ""
	case "mcp":
		if summary == "mcp observation" || summary == "" {
			return "mcp (unparsed)", "", "", ""
		}
		rawMethod, rawTool, _ := strings.Cut(summary, " ")
		method = evidenceindex.Bound(rawMethod, 48)
		if rawTool == "" {
			return finishShape(method), method, "", ""
		}
		tool = evidenceindex.Bound(rawTool, 64)
		return finishShape(method + " " + normaliseSegment(tool)), method, "", tool
	case "ssh":
		parts := strings.Split(summary, " · ")
		if len(parts) == 3 && strings.HasPrefix(parts[0], "auth ") {
			// "login", not "auth": redact.Scrub treats a leading AUTH as an SMTP credential line.
			return finishShape("login " + strings.TrimPrefix(parts[0], "auth ") + " · " + parts[2]), "", "", ""
		}
		return "ssh session", "", "", ""
	case "tcp":
		parts := strings.Split(summary, " · ")
		if len(parts) >= 2 && strings.HasSuffix(parts[0], " lines") {
			if len(parts) == 3 && strings.HasPrefix(parts[2], "rule ") {
				return finishShape("exchange · " + parts[2]), "", "", ""
			}
			return "exchange · no rule", "", "", ""
		}
		return "tcp session", "", "", ""
	}
	return finishShape(evidenceindex.Bound(kind, 32) + " observation"), "", "", ""
}

// finishShape applies credential scrubbing again (defence in depth: stored
// fields were already scrubbed by the sensor) and the final rune cap.
func finishShape(value string) string {
	value = evidenceindex.Bound(redact.Scrub(value), MaxShapeRunes)
	if strings.TrimSpace(value) == "" {
		return "(empty)"
	}
	return value
}

func normaliseMethod(value string) string {
	if value == "" || len(value) > 16 {
		return "OTHER"
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 'A' || value[i] > 'Z' {
			return "OTHER"
		}
	}
	return value
}

// PathTemplate collapses identifier-like path segments into placeholders and
// caps the number of segments. Literal segments are kept so behaviour stays
// explainable; see docs/ai-threat-detection.md#campaigns.
func PathTemplate(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return normaliseSegment(path)
	}
	segments := strings.Split(path[1:], "/")
	truncated := len(segments) > MaxShapeSegments
	if truncated {
		segments = segments[:MaxShapeSegments]
	}
	for i, segment := range segments {
		segments[i] = normaliseSegment(segment)
	}
	out := "/" + strings.Join(segments, "/")
	if truncated {
		out += "/…"
	}
	return out
}

// normaliseSegment maps one path segment (or MCP tool name) to itself or a placeholder.
func normaliseSegment(segment string) string {
	switch {
	case segment == "":
		return ""
	case strings.HasPrefix(segment, "[honeytoken:"):
		return "{honeytoken}"
	case strings.HasPrefix(segment, "[redacted"):
		return "{redacted}"
	case allBytes(segment, isDigit):
		return "{n}"
	case isUUID(segment):
		return "{uuid}"
	case len(segment) >= 8 && allBytes(segment, isHex):
		return "{hex}"
	case utf8.RuneCountInString(segment) > MaxSegmentRunes:
		return "{token}"
	case len(segment) >= 10 && countBytes(segment, isDigit) >= 3:
		return "{id}"
	}
	return segment
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

func allBytes(value string, predicate func(byte) bool) bool {
	for i := 0; i < len(value); i++ {
		if !predicate(value[i]) {
			return false
		}
	}
	return value != ""
}

func countBytes(value string, predicate func(byte) bool) int {
	count := 0
	for i := 0; i < len(value); i++ {
		if predicate(value[i]) {
			count++
		}
	}
	return count
}

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if value[i] != '-' {
				return false
			}
		} else if !isHex(value[i]) {
			return false
		}
	}
	return true
}

// interactions projects non-signal session events in chronological order.
func interactions(events []evidenceindex.Summary) []interaction {
	out := make([]interaction, 0, len(events))
	for _, e := range events {
		if e.Classification == event.ClassificationCorrelationSignal {
			continue
		}
		shape, method, path, tool := shapeParts(e.Sensor.Kind, e.Classification, e.Summary, e.HTTPStatus)
		out = append(out, interaction{
			at: Time(e), sensor: e.Sensor.ID, kind: e.Sensor.Kind, shape: shape,
			method: method, path: path, tool: tool, status: e.HTTPStatus,
			stage: eventStage(e), client: e.ClientFamily,
		})
	}
	return out
}

// collapse removes consecutive repeats of the same kind+shape and caps the result.
func collapse(items []interaction) ([]step, bool) {
	out := []step{}
	for _, item := range items {
		if n := len(out); n > 0 && out[n-1].kind == item.kind && out[n-1].shape == item.shape {
			continue
		}
		if len(out) == MaxShapeSteps {
			return out, true
		}
		out = append(out, step{kind: item.kind, shape: item.shape, stage: item.stage})
	}
	return out, false
}
