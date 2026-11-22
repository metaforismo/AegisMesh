// Package indicatorexport renders conservative IP observation proposals. It has
// no network, filesystem, policy mutation, or enforcement capability.
package indicatorexport

import (
	"bytes"
	"crypto/sha1" // UUIDv5 requires SHA-1; not used for evidence integrity.
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
)

const (
	// MaxEvents caps both CLI and console input.
	MaxEvents = evidenceindex.AnalysisLimit
	// MaxBytes bounds any generated download, including STIX relationships.
	MaxBytes = 2 << 20
	// Confidence is deliberately low: decoy contact does not establish malice.
	Confidence = 15
)

// ErrLimit marks input or rendered-output exhaustion; no partial output is returned.
var ErrLimit = errors.New("indicator export exceeds bounded input or output")

// Indicator is one canonical IP with deduplicated origin-qualified evidence refs.
type Indicator struct {
	IP        string
	Type      string
	FirstSeen string
	LastSeen  string
	EventRefs []string
	RuleIDs   []string
}

// Result includes skip counts even when there are no IP indicators.
type Result struct {
	Indicators    []Indicator
	SkippedSource int
	SkippedEvents int
}

// Collect skips non-IP source keys (no DNS, ports or IPv6 zones) and counts them.
func Collect(events []evidenceindex.Summary) (Result, error) {
	if len(events) > MaxEvents {
		return Result{}, ErrLimit
	}
	out := Result{Indicators: []Indicator{}}
	byIP := map[string][]evidenceindex.Summary{}
	skipped := map[string]bool{}
	for _, e := range evidenceview.Chronological(events) {
		ip, err := netip.ParseAddr(e.Source)
		if err != nil || ip.Zone() != "" {
			skipped[e.Source] = true
			out.SkippedEvents++
			continue
		}
		byIP[ip.Unmap().String()] = append(byIP[ip.Unmap().String()], e)
	}
	out.SkippedSource = len(skipped)
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		events := byIP[ip]
		kind := "ipv6-addr"
		if netip.MustParseAddr(ip).Is4() {
			kind = "ipv4-addr"
		}
		indicator := Indicator{IP: ip, Type: kind, FirstSeen: stamp(events[0].Time), LastSeen: stamp(events[len(events)-1].Time), EventRefs: []string{}, RuleIDs: []string{}}
		rules, refs := map[string]bool{}, map[string]bool{}
		for _, e := range events {
			refs[evidenceview.EventKey(e)] = true
			for _, id := range e.RuleIDs {
				rules[id] = true
			}
		}
		for ref := range refs {
			indicator.EventRefs = append(indicator.EventRefs, ref)
		}
		for id := range rules {
			indicator.RuleIDs = append(indicator.RuleIDs, id)
		}
		sort.Strings(indicator.EventRefs)
		sort.Strings(indicator.RuleIDs)
		out.Indicators = append(out.Indicators, indicator)
	}
	return out, nil
}

func stamp(value string) string {
	t, _ := time.Parse(time.RFC3339Nano, value)
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

// Render buffers a complete bounded export. Instance is a trusted local identity
// namespace, never an attacker-selected path or a provider name.
func Render(events []evidenceindex.Summary, format, instance string) ([]byte, Result, error) {
	result, err := Collect(events)
	if err != nil {
		return nil, result, err
	}
	var buffer bytes.Buffer
	switch format {
	case "txt":
		fmt.Fprintln(&buffer, "# PROPOSED blocklist for operator review; never applied by AegisMesh.")
		fmt.Fprintf(&buffer, "# Decoy contact is an observation, not an incident. Confidence: %d/100 (low).\n", Confidence)
		fmt.Fprintf(&buffer, "# Skipped non-IP source keys: %d; events: %d.\n", result.SkippedSource, result.SkippedEvents)
		for _, indicator := range result.Indicators {
			fmt.Fprintln(&buffer, indicator.IP)
		}
	case "csv":
		writer := csv.NewWriter(&buffer)
		_ = writer.Write([]string{"indicator", "type", "first_seen", "last_seen", "event_count", "confidence", "interpretation", "skipped_non_ip_sources", "skipped_non_ip_events"})
		for _, indicator := range result.Indicators {
			_ = writer.Write([]string{indicator.IP, indicator.Type, indicator.FirstSeen, indicator.LastSeen, strconv.Itoa(len(indicator.EventRefs)), strconv.Itoa(Confidence), "observation_not_incident", strconv.Itoa(result.SkippedSource), strconv.Itoa(result.SkippedEvents)})
		}
		writer.Flush()
		if err = writer.Error(); err != nil {
			return nil, result, err
		}
	case "stix":
		body, err := stix(result, instance)
		if err != nil {
			return nil, result, err
		}
		buffer.Write(body)
		buffer.WriteByte('\n')
	default:
		return nil, result, errors.New("format must be stix, csv or txt")
	}
	if buffer.Len() > MaxBytes {
		return nil, result, ErrLimit
	}
	return buffer.Bytes(), result, nil
}

// UUIDv5 uses the RFC 4122 DNS namespace and a JSON array name to avoid ambiguous
// concatenation. IDs identify immutable export content, including timestamp bounds.
func objectID(kind string, values ...string) string {
	namespace := []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	name, _ := json.Marshal(append([]string{"aegismesh", kind}, values...))
	hash := sha1.New()
	hash.Write(namespace)
	hash.Write(name)
	uuid := hash.Sum(nil)[:16]
	uuid[6] = uuid[6]&0x0f | 0x50
	uuid[8] = uuid[8]&0x3f | 0x80
	hexID := hex.EncodeToString(uuid)
	return kind + "--" + hexID[:8] + "-" + hexID[8:12] + "-" + hexID[12:16] + "-" + hexID[16:20] + "-" + hexID[20:]
}

func common(kind, id, timestamp, identity string) map[string]any {
	out := map[string]any{"type": kind, "spec_version": "2.1", "id": id, "created": timestamp, "modified": timestamp}
	if identity != "" {
		out["created_by_ref"] = identity
	}
	return out
}

func stix(result Result, instance string) ([]byte, error) {
	// Static catalog/identity dates do not depend on wall clock or export time.
	const epoch = "2026-01-01T00:00:00.000000000Z"
	identityID := objectID("identity", instance)
	identity := common("identity", identityID, epoch, "")
	identity["name"] = "AegisMesh synthetic instance " + strings.TrimPrefix(identityID, "identity--")[:8]
	identity["identity_class"] = "system"
	objects := []map[string]any{identity}
	allRules := []string{}
	for _, indicator := range result.Indicators {
		allRules = append(allRules, indicator.RuleIDs...)
	}
	patterns := map[string]string{}
	for _, mapping := range evidenceview.Mappings(allRules) {
		if mapping.Framework != "mitre-attack" && mapping.Framework != "mitre-atlas" {
			continue
		}
		id := objectID("attack-pattern", mapping.Framework, mapping.ID)
		patterns[mapping.Framework+":"+mapping.ID] = id
		pattern := common("attack-pattern", id, epoch, identityID)
		pattern["name"] = mapping.Name
		pattern["description"] = "Editorial rule relation; observation does not establish technique execution."
		pattern["external_references"] = []map[string]string{{"source_name": mapping.Framework, "external_id": mapping.ID}}
		objects = append(objects, pattern)
	}
	for _, indicator := range result.Indicators {
		content, _ := json.Marshal(indicator)
		id := objectID("indicator", instance, string(content))
		object := common("indicator", id, indicator.FirstSeen, identityID)
		object["modified"] = indicator.LastSeen
		object["name"] = "Decoy contact observation: " + indicator.IP
		object["description"] = "Proposed operator-review indicator. Decoy contact alone does not prove malice, compromise or attribution."
		object["indicator_types"] = []string{"anomalous-activity"}
		object["pattern"] = "[" + indicator.Type + ":value = '" + indicator.IP + "']"
		object["pattern_type"], object["pattern_version"] = "stix", "2.1"
		object["valid_from"], object["confidence"] = indicator.FirstSeen, Confidence
		objects = append(objects, object)

		note := common("note", objectID("note", id), indicator.LastSeen, identityID)
		note["content"] = "Redacted evidence references (origin:event_id): " + strings.Join(indicator.EventRefs, ", ") + ". Observations, not incidents."
		note["object_refs"] = []string{id}
		objects = append(objects, note)
		if len(objects) > 2048 {
			return nil, ErrLimit
		}
		for _, mapping := range evidenceview.Mappings(indicator.RuleIDs) {
			target := patterns[mapping.Framework+":"+mapping.ID]
			if target == "" {
				continue
			}
			relation := common("relationship", objectID("relationship", id, target), indicator.LastSeen, identityID)
			relation["relationship_type"], relation["source_ref"], relation["target_ref"] = "related-to", id, target
			objects = append(objects, relation)
		}
	}
	summary := common("note", objectID("note", instance, "export-summary", strconv.Itoa(result.SkippedSource), strconv.Itoa(result.SkippedEvents)), epoch, identityID)
	summary["content"] = fmt.Sprintf("Proposed indicators for operator review; never applied. Confidence %d/100. Skipped non-IP sources: %d; events: %d. Retained redacted observations only; bounded index or local read, at most 8192 events. No incident or completeness claim.", Confidence, result.SkippedSource, result.SkippedEvents)
	summary["object_refs"] = []string{identityID}
	objects = append(objects, summary)
	// Bundle has no spec_version in STIX 2.1; each contained SDO/SRO does.
	manifest, _ := json.Marshal(objects)
	return json.MarshalIndent(map[string]any{"type": "bundle", "id": objectID("bundle", instance, string(manifest)), "objects": objects}, "", "  ")
}
