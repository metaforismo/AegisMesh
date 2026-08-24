// Package recommend turns verified evidence signals into bounded, dry-run
// recommendations. It has no runtime or I/O dependencies: recommendations
// are static operator-review guidance, never enforcement instructions.
package recommend

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

const (
	SchemaV1              = "aegismesh.recommendation/v1"
	ModeDryRun            = "dry_run"
	InterpretationSignal  = "signal_not_incident"
	KindRecommendation    = "recommendation"
	StatusProposed        = "proposed"
	DefaultLimit          = 20
	MaxLimit              = 1000
	MaxEvidence           = 4096
	MaxObservationBytes   = 64 << 10
	MaxDetectionFindings  = 64
	MaxSourceEventIDs     = 64
	MaxRuleIDBytes        = 32
	MaxActionBytes        = 32
	MaxSummaryBytes       = 256
	MaxSourceKeyBytes     = 128
	MaxSensorIDBytes      = 64
	MaxSensorKindBytes    = 32
	MaxInstanceBytes      = 64
	MaxListenBytes        = 256
	MaxRedactionRules     = 32
	MaxRedactionRuleBytes = 64
	maxJSONDepth          = 32
	maxJSONObjectFields   = 128
	maxJSONArrayItems     = 128
)

var (
	errRecommendation = errors.New("recommendation")
	errInput          = errors.New("recommendation input")
	errObservation    = errors.New("recommendation observation")
)

// Options bounds report generation. A zero limit selects DefaultLimit.
type Options struct {
	Limit          int
	RuleID         string
	SensorID       string
	Classification string
}

// Validate reports invalid explicit options without silently broadening the
// recommendation surface.
func (o Options) Validate() error {
	if o.Limit < 0 || o.Limit > MaxLimit {
		return fmt.Errorf("%w: limit must be within 0..%d", errRecommendation, MaxLimit)
	}
	if o.RuleID != "" {
		if _, ok := rulecatalog.Lookup(o.RuleID); !ok {
			return fmt.Errorf("%w: unknown rule filter", errRecommendation)
		}
	}
	if o.Classification != "" && !validClassification(o.Classification) {
		return fmt.Errorf("%w: unknown classification filter", errRecommendation)
	}
	if o.SensorID != "" && !validSensorID(o.SensorID) {
		return fmt.Errorf("%w: invalid sensor filter", errRecommendation)
	}
	return nil
}

func (o Options) limit() int {
	if o.Limit == 0 {
		return DefaultLimit
	}
	return o.Limit
}

// Report is the deterministic, JSON-ready result of Generate.
type Report struct {
	Schema          string           `json:"schema"`
	Mode            string           `json:"mode"`
	Interpretation  string           `json:"interpretation"`
	Kind            string           `json:"kind"`
	Status          string           `json:"status"`
	Recommendations []Recommendation `json:"recommendations"`
}

// Recommendation is proposed operator-review work. All operator-guidance prose
// is static catalog text; event observations never populate it. Envelope-derived
// metadata is bounded separately and is not covered by the observation hash.
type Recommendation struct {
	Schema             string             `json:"schema"`
	Mode               string             `json:"mode"`
	Interpretation     string             `json:"interpretation"`
	Kind               string             `json:"kind"`
	Status             string             `json:"status"`
	Classification     string             `json:"classification"`
	SensorID           string             `json:"sensor_id"`
	SensorKind         string             `json:"sensor_kind"`
	ID                 string             `json:"id"`
	RuleIDs            []string           `json:"rule_ids"`
	Summary            string             `json:"summary"`
	OperatorReview     string             `json:"operator_review"`
	NextSteps          []string           `json:"next_steps"`
	Evidence           []EvidenceLink     `json:"evidence"`
	Conflicts          []ConflictMetadata `json:"conflicts,omitempty"`
	FalsePositiveNotes []string           `json:"false_positive_notes"`
	SourceResolution   *SourceResolution  `json:"source_resolution,omitempty"`
}

// EvidenceLink is an exact link to one accepted envelope. The hash is copied
// from the envelope after payload verification; this is not provenance
// authentication or a signature over the envelope metadata.
type EvidenceLink struct {
	EventID        string `json:"event_id"`
	PayloadSHA256  string `json:"payload_sha256"`
	IntegrityScope string `json:"integrity_scope"`
	Verification   string `json:"verification"`
}

// ConflictMetadata explains why multiple signals require human review. The
// resolution is a fixed label and cannot select an action or a target.
type ConflictMetadata struct {
	Code       string   `json:"code"`
	RuleIDs    []string `json:"rule_ids"`
	Resolution string   `json:"resolution"`
	Note       string   `json:"note"`
}

// SourceResolution reports whether persisted correlation provenance could be
// matched to verified raw input events. Unresolved IDs are deliberately not
// emitted, preventing attacker-controlled provenance from becoming evidence.
type SourceResolution struct {
	Resolved   int `json:"resolved"`
	Unresolved int `json:"unresolved"`
}

const (
	integrityScopeObservation = "observation_payload_only"
	verificationPayloadHash   = "payload_hash_consistent"
	canarySummary             = "A canary invocation was observed; review the linked evidence and decoy configuration."
)

// Generate validates every input envelope, parses only supported persisted
// signal blocks, and returns deterministic recommendations. Invalid envelopes
// or malformed supported blocks fail closed with no accepted result.
func Generate(events []event.Envelope, opts Options) (Report, error) {
	report := newReport()
	if err := opts.Validate(); err != nil {
		return report, err
	}
	if len(events) > MaxEvidence {
		return report, fmt.Errorf("%w: event count exceeds %d", errInput, MaxEvidence)
	}

	verified := make(map[string]event.Envelope, len(events))
	ordered := make([]event.Envelope, 0, len(events))
	for i := range events {
		e := events[i]
		if err := ValidateEnvelope(e); err != nil {
			return report, fmt.Errorf("%w: event %d rejected", errInput, i)
		}
		if _, ok := verified[e.ID]; ok {
			return report, fmt.Errorf("%w: duplicate event identity", errInput)
		}
		verified[e.ID] = e
		ordered = append(ordered, e)
	}

	allCandidates := make([]candidate, 0, len(ordered))
	for _, e := range ordered {
		parsed, err := parseEnvelope(e, verified)
		if err != nil {
			return report, fmt.Errorf("%w: event observation rejected", errObservation)
		}
		if parsed == nil {
			continue
		}
		allCandidates = append(allCandidates, candidate{envelope: e, parsed: parsed})
	}
	// Filters run only after the complete verified input set has been parsed,
	// so correlation provenance can resolve against events omitted by a filter.
	candidates := make([]candidate, 0, len(allCandidates))
	for _, c := range allCandidates {
		if matches(c.envelope, c.parsed, opts) {
			candidates = append(candidates, c)
		}
	}
	// Time and Seq make presentation deterministic but are envelope metadata;
	// VerifyIntegrity covers only Observation bytes, not these fields.
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i].envelope, candidates[j].envelope
		if !left.Time.UTC().Equal(right.Time.UTC()) {
			return left.Time.UTC().Before(right.Time.UTC())
		}
		if left.Seq != right.Seq {
			return left.Seq < right.Seq
		}
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		return strings.Join(candidates[i].parsed.ruleIDs, "\x00") < strings.Join(candidates[j].parsed.ruleIDs, "\x00")
	})
	recommendations := make([]Recommendation, 0, len(candidates))
	for _, c := range candidates {
		recommendations = append(recommendations, buildRecommendation(c.envelope, c.parsed))
	}
	if limit := opts.limit(); len(recommendations) > limit {
		recommendations = recommendations[:limit]
	}
	report.Recommendations = recommendations
	return report, nil
}

// ValidateEnvelope applies the bounded recommendation input contract before a
// caller retains an envelope. Generate repeats this check so direct callers
// cannot bypass it.
func ValidateEnvelope(e event.Envelope) error {
	return verifyEnvelope(e)
}

// RecommendationID returns the stable ID used by Generate. Rule IDs are
// deduplicated and sorted before marshaling into the canonical identity input.
func RecommendationID(eventID, payloadSHA256 string, ruleIDs []string) string {
	rules := sortedRuleIDs(ruleIDs)
	canonical := struct {
		Schema        string   `json:"schema"`
		EventID       string   `json:"event_id"`
		PayloadSHA256 string   `json:"payload_sha256"`
		RuleIDs       []string `json:"rule_ids"`
	}{SchemaV1, eventID, payloadSHA256, rules}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type parsedSignal struct {
	ruleIDs          []string
	evidence         []EvidenceLink
	sourceResolution *SourceResolution
}

type candidate struct {
	envelope event.Envelope
	parsed   *parsedSignal
}

func newReport() Report {
	return Report{
		Schema:          SchemaV1,
		Mode:            ModeDryRun,
		Interpretation:  InterpretationSignal,
		Kind:            KindRecommendation,
		Status:          StatusProposed,
		Recommendations: []Recommendation{},
	}
}

func verifyEnvelope(e event.Envelope) error {
	if err := e.Validate(); err != nil {
		return errInput
	}
	if !isHex(e.ID, 16) || e.Integrity.Algorithm != "sha256" || !isHex(e.Integrity.PayloadSHA256, 32) {
		return errInput
	}
	if !validSensorID(e.Sensor.ID) || !validSlug(e.Sensor.Kind, 3, MaxSensorKindBytes) ||
		!isBoundedString(e.Instance, MaxInstanceBytes) || !isBoundedString(e.Sensor.Listen, MaxListenBytes) ||
		len(e.Redaction.Rules) > MaxRedactionRules {
		return errInput
	}
	for _, rule := range e.Redaction.Rules {
		if rule == "" || !isBoundedString(rule, MaxRedactionRuleBytes) {
			return errInput
		}
	}
	if len(e.Observation) > MaxObservationBytes {
		return errInput
	}
	if err := e.VerifyIntegrity(); err != nil {
		return errInput
	}
	return nil
}

func parseEnvelope(e event.Envelope, verified map[string]event.Envelope) (*parsedSignal, error) {
	fields, err := parseTopLevel(e.Observation)
	if err != nil {
		return nil, err
	}
	base := evidenceLink(e)
	switch e.Classification {
	case event.ClassificationInteraction, event.ClassificationCanaryHit:
		rules, err := parseDetection(fields)
		if err != nil {
			return nil, err
		}
		if len(rules) == 0 && e.Classification != event.ClassificationCanaryHit {
			return nil, nil
		}
		return &parsedSignal{ruleIDs: rules, evidence: []EvidenceLink{base}}, nil
	case event.ClassificationCorrelationSignal:
		corr, present, err := parseCorrelation(e.Observation)
		if err != nil {
			return nil, err
		}
		if !present {
			return nil, nil
		}
		if corr.RuleID == "" {
			return nil, errObservation
		}
		info, ok := rulecatalog.Lookup(corr.RuleID)
		if !ok || info.Family != rulecatalog.FamilyCorrelation || !isBoundedString(corr.RuleID, MaxRuleIDBytes) {
			return nil, errObservation
		}
		evidence := []EvidenceLink{base}
		resolved, unresolved := 0, 0
		seen := make(map[string]bool, len(corr.SourceEventIDs))
		for _, id := range corr.SourceEventIDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			source, ok := verified[id]
			if !ok || source.Classification == event.ClassificationCorrelationSignal {
				unresolved++
				continue
			}
			resolved++
			evidence = append(evidence, evidenceLink(source))
		}
		sort.Slice(evidence, func(i, j int) bool {
			if evidence[i].EventID != evidence[j].EventID {
				return evidence[i].EventID < evidence[j].EventID
			}
			return evidence[i].PayloadSHA256 < evidence[j].PayloadSHA256
		})
		var resolution *SourceResolution
		if resolved > 0 || unresolved > 0 {
			resolution = &SourceResolution{Resolved: resolved, Unresolved: unresolved}
		}
		return &parsedSignal{
			ruleIDs:          []string{corr.RuleID},
			evidence:         evidence,
			sourceResolution: resolution,
		}, nil
	default:
		return nil, nil
	}
}

func evidenceLink(e event.Envelope) EvidenceLink {
	return EvidenceLink{
		EventID:        e.ID,
		PayloadSHA256:  e.Integrity.PayloadSHA256,
		IntegrityScope: integrityScopeObservation,
		Verification:   verificationPayloadHash,
	}
}

type detectionBlock struct {
	Action   string             `json:"action"`
	Findings []detectionFinding `json:"findings"`
}

type detectionFinding struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}

type correlationObservation struct {
	RuleID         string   `json:"rule_id"`
	Summary        string   `json:"summary"`
	SourceKey      string   `json:"source_key"`
	SourceEventIDs []string `json:"source_event_ids"`
	Truncated      bool     `json:"truncated"`
}

func parseDetection(fields map[string]json.RawMessage) ([]string, error) {
	raw, ok := fields["detection"]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var block detectionBlock
	if err := decodeStrict(raw, &block); err != nil || !isBoundedString(block.Action, MaxActionBytes) {
		return nil, errObservation
	}
	if !knownDetectionAction(block.Action) {
		return nil, errObservation
	}
	if len(block.Findings) > MaxDetectionFindings {
		return nil, errObservation
	}
	rules := make([]string, 0, len(block.Findings))
	for _, finding := range block.Findings {
		if !isBoundedString(finding.RuleID, MaxRuleIDBytes) {
			return nil, errObservation
		}
		if finding.RuleID == "" {
			return nil, errObservation
		}
		if !isBoundedString(finding.Severity, MaxActionBytes) ||
			!knownConfidence(finding.Confidence) ||
			finding.Reason == "" || !isBoundedString(finding.Reason, MaxSummaryBytes) {
			return nil, errObservation
		}
		info, ok := rulecatalog.Lookup(finding.RuleID)
		if !ok || info.Family != rulecatalog.FamilyDetection || finding.Severity != info.Severity {
			return nil, errObservation
		}
		rules = append(rules, finding.RuleID)
	}
	return sortedRuleIDs(rules), nil
}

func knownConfidence(confidence string) bool {
	switch confidence {
	case "low", "medium", "high":
		return true
	default:
		return false
	}
}

func knownDetectionAction(action string) bool {
	switch action {
	case "observe", "tag", "throttle", "isolate", "refuse":
		return true
	default:
		return false
	}
}

func parseCorrelation(raw []byte) (correlationObservation, bool, error) {
	var corr correlationObservation
	if err := decodeStrict(raw, &corr); err != nil {
		return correlationObservation{}, true, errObservation
	}
	if corr.RuleID == "" && corr.Summary == "" && corr.SourceKey == "" && corr.SourceEventIDs == nil && !corr.Truncated {
		return correlationObservation{}, false, nil
	}
	if err := validateCorrelation(corr); err != nil {
		return correlationObservation{}, true, err
	}
	return corr, true, nil
}

func validateCorrelation(corr correlationObservation) error {
	if !isBoundedString(corr.RuleID, MaxRuleIDBytes) ||
		!isBoundedString(corr.Summary, MaxSummaryBytes) ||
		!isBoundedString(corr.SourceKey, MaxSourceKeyBytes) ||
		len(corr.SourceEventIDs) > MaxSourceEventIDs {
		return errObservation
	}
	for _, id := range corr.SourceEventIDs {
		if !isHex(id, 16) {
			return errObservation
		}
	}
	return nil
}

func buildRecommendation(e event.Envelope, parsed *parsedSignal) Recommendation {
	rules := sortedRuleIDs(parsed.ruleIDs)
	entries := make([]rulecatalog.Entry, 0, len(rules))
	for _, id := range rules {
		if entry, ok := rulecatalog.Lookup(id); ok {
			entries = append(entries, entry)
		}
	}
	summaries := make([]string, 0, len(entries))
	for _, entry := range entries {
		summaries = append(summaries, entry.Summary)
	}
	if e.Classification == event.ClassificationCanaryHit {
		summaries = append([]string{canarySummary}, summaries...)
	}
	rec := Recommendation{
		Schema:         SchemaV1,
		Mode:           ModeDryRun,
		Interpretation: InterpretationSignal,
		Kind:           KindRecommendation,
		Status:         StatusProposed,
		Classification: e.Classification,
		SensorID:       e.Sensor.ID,
		SensorKind:     e.Sensor.Kind,
		ID:             RecommendationID(e.ID, e.Integrity.PayloadSHA256, rules),
		RuleIDs:        rules,
		Summary:        strings.Join(summaries, "; "),
		OperatorReview: "Review the linked evidence and surrounding context before deciding whether any response is warranted.",
		NextSteps: []string{
			"Review linked evidence in the context of the decoy configuration.",
			"Compare the signal with known benign testing and automation.",
			"Record an operator disposition with the evidence reference.",
		},
		Evidence:           append([]EvidenceLink(nil), parsed.evidence...),
		FalsePositiveNotes: []string{"Signals can result from benign testing, automation, malformed clients, or configuration; they are not proof of an incident."},
		SourceResolution:   parsed.sourceResolution,
	}
	if conflict, ok := conflictFor(rules); ok {
		rec.Conflicts = []ConflictMetadata{conflict}
	}
	return rec
}

func conflictFor(rules []string) (ConflictMetadata, bool) {
	if len(rules) < 2 {
		return ConflictMetadata{}, false
	}
	for _, id := range rules {
		if id == "RES-001" {
			others := make([]string, 0, len(rules))
			for _, other := range rules {
				if other != id {
					others = append(others, other)
				}
			}
			return ConflictMetadata{
				Code:       "bounded_input_vs_content_signal",
				RuleIDs:    sortedRuleIDs(append([]string{id}, others...)),
				Resolution: "operator_review",
				Note:       "The input-size signal may limit interpretation of content-derived signals; review the complete linked evidence before drawing conclusions.",
			}, true
		}
	}
	return ConflictMetadata{}, false
}

func matches(e event.Envelope, parsed *parsedSignal, opts Options) bool {
	if opts.SensorID != "" && e.Sensor.ID != opts.SensorID {
		return false
	}
	if opts.Classification != "" && e.Classification != opts.Classification {
		return false
	}
	if opts.RuleID == "" {
		return true
	}
	for _, id := range parsed.ruleIDs {
		if id == opts.RuleID {
			return true
		}
	}
	return false
}

func sortedRuleIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func isBoundedString(s string, max int) bool {
	return len(s) <= max && (s == "" || strings.ToValidUTF8(s, "") == s)
}

func validClassification(classification string) bool {
	switch classification {
	case event.ClassificationInteraction, event.ClassificationCanaryHit, event.ClassificationCorrelationSignal:
		return true
	default:
		return false
	}
}

func validSensorID(id string) bool {
	return validSlug(id, 3, MaxSensorIDBytes)
}

func validSlug(id string, min, max int) bool {
	if len(id) < min || len(id) > max {
		return false
	}
	for i, r := range id {
		if i == 0 {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				return false
			}
			continue
		}
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func isHex(s string, bytesLen int) bool {
	if len(s) != bytesLen*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func parseTopLevel(raw []byte) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaxObservationBytes || scanJSON(raw) != nil {
		return nil, errObservation
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&fields); err != nil || fields == nil {
		return nil, errObservation
	}
	if err := ensureEOF(dec); err != nil {
		return nil, errObservation
	}
	return fields, nil
}

func decodeStrict(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errObservation
	}
	return ensureEOF(dec)
}

func ensureEOF(dec *json.Decoder) error {
	_, err := dec.Token()
	if err == io.EOF {
		return nil
	}
	return errObservation
}

// scanJSON rejects duplicate object keys before any map decode. It also puts
// fixed depth and collection bounds around unknown attacker-controlled JSON.
func scanJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := scanValue(dec, 0); err != nil {
		return errObservation
	}
	return ensureEOF(dec)
}

func scanValue(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errObservation
	}
	tok, err := dec.Token()
	if err != nil {
		return errObservation
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		count := 0
		for dec.More() {
			tok, err := dec.Token()
			key, ok := tok.(string)
			if err != nil || !ok || seen[key] || count >= maxJSONObjectFields {
				return errObservation
			}
			seen[key] = true
			count++
			if err := scanValue(dec, depth+1); err != nil {
				return err
			}
		}
		if end, err := dec.Token(); err != nil || end != json.Delim('}') {
			return errObservation
		}
	case '[':
		count := 0
		for dec.More() {
			if count >= maxJSONArrayItems {
				return errObservation
			}
			count++
			if err := scanValue(dec, depth+1); err != nil {
				return err
			}
		}
		if end, err := dec.Token(); err != nil || end != json.Delim(']') {
			return errObservation
		}
	default:
		return errObservation
	}
	return nil
}
