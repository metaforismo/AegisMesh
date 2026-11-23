// Package posture reviews a validated configuration snapshot and the retained
// evidence sample with fixed, deterministic checks. It is advisory: it reads
// value facts only, holds no secrets, performs no I/O and changes nothing.
// A clean review is not a security guarantee.
package posture

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Check statuses.
const (
	StatusAttention = "attention"
	StatusOK        = "ok"
	StatusInfo      = "info"
)

// Check areas.
const (
	AreaExposure  = "exposure"
	AreaDeception = "deception"
	AreaDetection = "detection"
	AreaEvidence  = "evidence"
	AreaAccess    = "access"
)

// MaxListed caps identifiers named in one check detail.
const MaxListed = 10

const (
	docPosture     = "docs/ai-threat-detection.md#posture-review"
	docHoneytokens = "docs/ai-threat-detection.md#honeytokens-and-agent-markers"
	docDetection   = "docs/ai-threat-detection.md#detection-rules"
	docCorrelation = "docs/ai-threat-detection.md#correlation-rules"
	docMCP         = "docs/mcp-environments.md"
	docEncryption  = "docs/evidence-encryption.md"
	docConsole     = "docs/architecture/console-api.md#transport-and-exposure"
	docAccounts    = "docs/architecture/console-api.md#accounts-access-and-settings-adr-0025"
)

// Check is one deterministic finding about configuration or retained evidence.
type Check struct {
	ID             string `json:"id"`
	Area           string `json:"area"`
	Status         string `json:"status"`
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
	Doc            string `json:"doc"`
}

// Summary counts checks by status.
type Summary struct {
	Attention int `json:"attention"`
	OK        int `json:"ok"`
	Info      int `json:"info"`
}

// Report is the full review. Scope is "configuration_and_evidence" when the
// configuration belongs to the caller's tenant, otherwise "evidence_only".
type Report struct {
	GeneratedAt string  `json:"generated_at"`
	Scope       string  `json:"scope"`
	Summary     Summary `json:"summary"`
	Checks      []Check `json:"checks"`
	Disclaimer  string  `json:"disclaimer"`
}

// Disclaimer is included verbatim in every report.
const Disclaimer = "Static review of the running configuration and of retained evidence; not a security guarantee or a complete audit."

// Sensor is a value fact about one configured decoy.
type Sensor struct {
	ID              string
	Kind            string
	Listen          string
	SurfaceFamilies []string
	MCPEnvironment  bool
	LLMFallback     bool
	BodyFiles       bool
}

// Token is a honeytoken identifier, kind and whether inline planting was found.
type Token struct {
	ID      string
	Kind    string
	Planted bool
}

// Facts is a secret-free snapshot of the validated configuration.
type Facts struct {
	Sensors               []Sensor
	Honeytokens           []Token
	ConsoleEnabled        bool
	ConsoleListen         string
	ConsoleTLS            bool
	TokenLogin            bool
	OIDC                  bool
	OperatorRoles         map[string]int
	AllowPublicBind       bool
	AllowPrivilegedPorts  bool
	AllowPrivateLLMEgress bool
	LLMProvider           string
	LLMEndpointLoopback   bool
	DetectionEnabled      bool
	DetectionDisabled     []string
	Actions               map[string]string
	CorrelationEnabled    bool
	CorrelationDisabled   []string
	Webhook               bool
	FleetForwarding       bool
	FleetHubCAPinned      bool
	EncryptionAtRest      bool
	// ManagedKnown is true when the console account store was read (never offline);
	// ManagedAdmins then counts managed admins that can sign in to the local tenant.
	ManagedKnown  bool
	ManagedAdmins int
}

// Evidence summarises the retained analysis sample. Available=false means
// evidence-based checks report Reason instead of a result.
type Evidence struct {
	Available    bool
	Reason       string
	Scanned      int
	Limit        int
	Truncated    bool
	SensorEvents map[string]int
	TokenHits    map[string]int
}

// Evaluate runs every applicable check in ID order. facts==nil means the
// configuration belongs to another tenant: only evidence checks that need no
// configuration are returned.
func Evaluate(facts *Facts, evidence Evidence, now time.Time) Report {
	r := Report{GeneratedAt: now.UTC().Format(time.RFC3339Nano), Scope: "configuration_and_evidence", Checks: []Check{}, Disclaimer: Disclaimer}
	var checks []func(*Facts, Evidence) Check
	if facts == nil {
		r.Scope = "evidence_only"
		checks = []func(*Facts, Evidence) Check{checkSampleSaturation}
	} else {
		checks = allChecks
	}
	for _, check := range checks {
		c := check(facts, evidence)
		if c.Status == StatusOK {
			c.Recommendation = ""
		}
		r.Checks = append(r.Checks, c)
		switch c.Status {
		case StatusAttention:
			r.Summary.Attention++
		case StatusOK:
			r.Summary.OK++
		default:
			r.Summary.Info++
		}
	}
	return r
}

var allChecks = []func(*Facts, Evidence) Check{
	checkSensorExposure, checkSecurityOptIns, checkConsoleExposure, checkLLMForwarding, checkEvidenceEgress,
	checkRoleSeparation, checkHoneytokens, checkAgentCanary, checkPlanting, checkTokenObservations,
	checkAISurface, checkMCPEnvironment, checkDetection, checkCorrelation, checkActions,
	checkSilentSensors, checkSampleSaturation, checkEncryption, checkBreakGlass,
}

// Public reports whether a listen authority binds beyond loopback.
func Public(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

func list(values []string) string {
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	if len(sorted) > MaxListed {
		return strings.Join(sorted[:MaxListed], ", ") + fmt.Sprintf(" and %d more", len(sorted)-MaxListed)
	}
	return strings.Join(sorted, ", ")
}

func checkSensorExposure(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-001", Area: AreaExposure, Title: "Decoys reachable beyond loopback", Doc: docPosture}
	public := []string{}
	for _, s := range f.Sensors {
		if Public(s.Listen) {
			public = append(public, s.ID+" ("+s.Listen+")")
		}
	}
	if len(public) == 0 {
		c.Status, c.Detail = StatusOK, fmt.Sprintf("All %d sensor(s) bind to loopback; only local clients can reach them.", len(f.Sensors))
		return c
	}
	c.Status = StatusInfo
	c.Detail = fmt.Sprintf("%d of %d sensor(s) bind beyond loopback: %s. That is how a decoy meets real attackers, and it also means anything on those networks can reach it.", len(public), len(f.Sensors), list(public))
	c.Recommendation = "Confirm these decoys sit on networks with no production assets or credentials, and that firewall rules match the intended exposure."
	return c
}

func checkSecurityOptIns(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-002", Area: AreaExposure, Title: "Relaxed safety opt-ins", Doc: docPosture}
	set := []string{}
	for _, opt := range []struct {
		name string
		on   bool
	}{{"security.allow_public_bind", f.AllowPublicBind}, {"security.allow_privileged_ports", f.AllowPrivilegedPorts}, {"security.allow_private_llm_egress", f.AllowPrivateLLMEgress}} {
		if opt.on {
			set = append(set, opt.name)
		}
	}
	if len(set) == 0 {
		c.Status, c.Detail = StatusOK, "No safety opt-in is relaxed; loopback binding, unprivileged ports and public-only LLM egress remain enforced."
		return c
	}
	c.Status = StatusInfo
	c.Detail = "Opt-ins set: " + strings.Join(set, ", ") + "."
	c.Recommendation = "Keep each opt-in only while the deployment needs it; it widens what a configuration mistake can expose."
	return c
}

func checkConsoleExposure(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-003", Area: AreaExposure, Title: "Console listener exposure", Doc: docConsole}
	switch {
	case !f.ConsoleEnabled:
		c.Status, c.Detail = StatusOK, "The operator console is disabled."
	case !Public(f.ConsoleListen):
		c.Status, c.Detail = StatusOK, "The console binds to loopback ("+f.ConsoleListen+")."
	case f.ConsoleTLS:
		c.Status = StatusInfo
		c.Detail = "The console binds beyond loopback (" + f.ConsoleListen + ") with TLS, as validation requires."
		c.Recommendation = "Restrict which networks can reach the console; it serves evidence that includes attacker-supplied text."
	default:
		c.Status = StatusAttention
		c.Detail = "The console binds beyond loopback (" + f.ConsoleListen + ") without TLS."
		c.Recommendation = "Configure console.tls_cert_file and console.tls_key_file, or bind the console to loopback."
	}
	return c
}

func checkLLMForwarding(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-004", Area: AreaExposure, Title: "Attacker input sent to an LLM provider", Doc: docPosture}
	fallback := []string{}
	for _, s := range f.Sensors {
		if s.LLMFallback {
			fallback = append(fallback, s.ID)
		}
	}
	switch {
	case f.LLMProvider == "" || f.LLMProvider == "local" || len(fallback) == 0:
		c.Status, c.Detail = StatusOK, "No sensor forwards attacker input to a model provider (provider: "+providerName(f.LLMProvider)+", fallback sensors: "+fmt.Sprint(len(fallback))+")."
	case f.LLMEndpointLoopback:
		c.Status = StatusInfo
		c.Detail = "Sensors " + list(fallback) + " send attacker-controlled prompts to a loopback " + f.LLMProvider + " endpoint."
		c.Recommendation = "Treat that model as exposed to prompt injection; give it no tools, data or credentials."
	default:
		c.Status = StatusAttention
		c.Detail = "Sensors " + list(fallback) + " send attacker-controlled prompts to a " + f.LLMProvider + " endpoint beyond loopback."
		c.Recommendation = "Prefer the local deterministic provider; otherwise accept that attackers can spend provider quota and that their text leaves this host."
	}
	return c
}

func providerName(p string) string {
	if p == "" {
		return "local"
	}
	return p
}

func checkEvidenceEgress(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-005", Area: AreaExposure, Title: "Evidence copies leaving this host", Doc: docPosture}
	channels := []string{}
	if f.Webhook {
		channels = append(channels, "webhook delivery")
	}
	if f.FleetForwarding {
		channels = append(channels, "fleet evidence forwarding")
	}
	if len(channels) == 0 {
		c.Status, c.Detail = StatusOK, "No webhook or fleet forwarding is configured; evidence stays on this host."
		return c
	}
	c.Status = StatusInfo
	c.Detail = "Enabled: " + strings.Join(channels, ", ") + "."
	if f.FleetForwarding && !f.FleetHubCAPinned {
		c.Detail += " The fleet hub is authenticated by system trust roots only (no fleet.agent.hub_ca_file)."
	}
	c.Recommendation = "Make sure the receiving systems are allowed to hold attacker-supplied, redacted evidence and are access controlled."
	return c
}

func checkRoleSeparation(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-006", Area: AreaAccess, Title: "Operator role separation", Doc: docConsole}
	if !f.ConsoleEnabled {
		c.Status, c.Detail = StatusInfo, "The console is disabled; operator roles were not evaluated."
		return c
	}
	total := 0
	for _, n := range f.OperatorRoles {
		total += n
	}
	nonAdmin := f.OperatorRoles["viewer"] + f.OperatorRoles["analyst"]
	detail := fmt.Sprintf("%d token operator(s): %d admin, %d analyst, %d viewer; OIDC %s.", total, f.OperatorRoles["admin"], f.OperatorRoles["analyst"], f.OperatorRoles["viewer"], map[bool]string{true: "enabled", false: "disabled"}[f.OIDC])
	switch {
	case f.TokenLogin && total > 0 && nonAdmin == 0:
		c.Status, c.Detail = StatusAttention, detail+" Every token operator is an administrator."
		c.Recommendation = "Give day-to-day readers viewer or analyst tokens and keep admin for audit and fleet administration."
	case f.TokenLogin && total == 1 && !f.OIDC:
		c.Status, c.Detail = StatusAttention, detail+" A single shared token cannot be attributed in the audit trail."
		c.Recommendation = "Issue one token per operator so audit entries name a person."
	default:
		c.Status, c.Detail = StatusOK, detail
	}
	return c
}

func checkHoneytokens(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-007", Area: AreaDeception, Title: "Honeytokens configured", Doc: docHoneytokens}
	if len(f.Honeytokens) == 0 {
		c.Status, c.Detail = StatusAttention, "No honeytokens are configured, so a replayed decoy credential cannot be recognised (HT-001, COR-008)."
		c.Recommendation = "Generate markers with 'aegismesh honeytoken new' and plant them in decoy responses."
		return c
	}
	c.Status, c.Detail = StatusOK, fmt.Sprintf("%d honeytoken(s) configured.", len(f.Honeytokens))
	return c
}

func checkAgentCanary(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-008", Area: AreaDeception, Title: "Agent canary marker", Doc: docHoneytokens}
	count := 0
	for _, t := range f.Honeytokens {
		if t.Kind == "agent_canary" {
			count++
		}
	}
	switch {
	case len(f.Honeytokens) == 0:
		c.Status, c.Detail = StatusInfo, "No honeytokens are configured (see POS-007), so no agent canary exists."
		c.Recommendation = "Add an agent_canary marker; following it is the strongest AI-agent signal (AGT-001)."
	case count == 0:
		c.Status, c.Detail = StatusAttention, "Honeytokens exist but none has kind agent_canary, so AGT-001 cannot fire."
		c.Recommendation = "Add an agent_canary marker to decoy content that only an instruction-following client would act on."
	default:
		c.Status, c.Detail = StatusOK, fmt.Sprintf("%d agent_canary marker(s) configured.", count)
	}
	return c
}

func checkPlanting(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-009", Area: AreaDeception, Title: "Honeytokens planted in decoy content", Doc: docHoneytokens}
	if len(f.Honeytokens) == 0 {
		c.Status, c.Detail = StatusInfo, "No honeytokens are configured (see POS-007)."
		return c
	}
	unplanted := []string{}
	for _, t := range f.Honeytokens {
		if !t.Planted {
			unplanted = append(unplanted, t.ID)
		}
	}
	if len(unplanted) == 0 {
		c.Status, c.Detail = StatusOK, "Every honeytoken appears in inline decoy content."
		return c
	}
	bodyFiles := false
	for _, s := range f.Sensors {
		bodyFiles = bodyFiles || s.BodyFiles
	}
	c.Status = StatusAttention
	c.Detail = "Not found in any inline decoy response, banner, tool, resource or prompt: " + list(unplanted) + "."
	if bodyFiles {
		c.Detail += " Some sensors serve body_file content, which this review does not read; markers planted there are not detected."
	}
	c.Recommendation = "Place each marker where a client can retrieve it, otherwise it can only be presented by someone who already holds it."
	return c
}

func checkTokenObservations(f *Facts, e Evidence) Check {
	c := Check{ID: "POS-010", Area: AreaDeception, Title: "Honeytokens seen in retained evidence", Doc: docHoneytokens}
	switch {
	case len(f.Honeytokens) == 0:
		c.Status, c.Detail = StatusInfo, "No honeytokens are configured (see POS-007)."
	case !e.Available:
		c.Status, c.Detail = StatusInfo, "Not evaluated: "+e.Reason
	default:
		seen := []string{}
		for _, t := range f.Honeytokens {
			if e.TokenHits[t.ID] > 0 {
				seen = append(seen, t.ID)
			}
		}
		c.Status = StatusInfo
		if len(seen) == 0 {
			c.Detail = fmt.Sprintf("None of %d honeytoken(s) appears in the %d retained events examined. This is normal on a quiet deployment.", len(f.Honeytokens), e.Scanned)
			c.Recommendation = "No action needed; if decoys see traffic but markers never return, check they are reachable (POS-009)."
		} else {
			c.Status, c.Detail = StatusOK, "Observed in retained evidence: "+list(seen)+"."
		}
	}
	return c
}

func checkAISurface(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-011", Area: AreaDeception, Title: "AI decoy surface", Doc: docPosture}
	surfaces := []string{}
	for _, s := range f.Sensors {
		if s.Kind == "mcp" {
			surfaces = append(surfaces, s.ID+" (mcp)")
			continue
		}
		for _, family := range s.SurfaceFamilies {
			if family != s.Kind {
				surfaces = append(surfaces, s.ID+" ("+family+")")
			}
		}
	}
	if len(surfaces) == 0 {
		c.Status, c.Detail = StatusAttention, "No sensor presents an AI service or MCP surface, so AI-specific probing has nothing to interact with."
		c.Recommendation = "Add an AI decoy (for example 'aegismesh init --profile ai-decoy') or an MCP sensor."
		return c
	}
	c.Status, c.Detail = StatusOK, "AI surfaces configured: "+list(surfaces)+"."
	return c
}

func checkMCPEnvironment(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-012", Area: AreaDeception, Title: "MCP synthetic environment", Doc: docMCP}
	mcp, bare := 0, []string{}
	for _, s := range f.Sensors {
		if s.Kind == "mcp" {
			mcp++
			if !s.MCPEnvironment {
				bare = append(bare, s.ID)
			}
		}
	}
	switch {
	case mcp == 0:
		c.Status, c.Detail = StatusInfo, "No MCP sensor is configured."
	case len(bare) == 0:
		c.Status, c.Detail = StatusOK, fmt.Sprintf("All %d MCP sensor(s) serve a synthetic environment.", mcp)
	default:
		c.Status = StatusInfo
		c.Detail = "MCP sensors without a synthetic environment: " + list(bare) + ". Agents see only the static tools, so multi-step tool chains are less likely to be observed."
		c.Recommendation = "Add an environment with fake files and planted markers to observe multi-step agent behaviour."
	}
	return c
}

func checkDetection(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-013", Area: AreaDetection, Title: "Detection engine and rules", Doc: docDetection}
	switch {
	case !f.DetectionEnabled:
		c.Status, c.Detail = StatusAttention, "Detection is disabled; interactions are stored without findings."
		c.Recommendation = "Remove detection.enabled: false unless this node is a pure capture decoy."
	case len(f.DetectionDisabled) > 0:
		c.Status, c.Detail = StatusInfo, "Detection is enabled with rules disabled: "+list(f.DetectionDisabled)+"."
		c.Recommendation = "Confirm each disabled rule is intentional; disabled rules leave gaps in sessions, campaigns and actor signals."
	default:
		c.Status, c.Detail = StatusOK, "Detection is enabled with every rule active."
	}
	return c
}

func checkCorrelation(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-014", Area: AreaDetection, Title: "Correlation engine and rules", Doc: docCorrelation}
	switch {
	case !f.CorrelationEnabled:
		c.Status, c.Detail = StatusAttention, "Correlation is disabled, so cross-sensor signals (COR-001..COR-008) such as cadence and credential replay are never produced."
		c.Recommendation = "Set correlation.enabled: true."
	case len(f.CorrelationDisabled) > 0:
		c.Status, c.Detail = StatusInfo, "Correlation is enabled with rules disabled: "+list(f.CorrelationDisabled)+"."
		c.Recommendation = "Confirm each disabled rule is intentional."
	default:
		c.Status, c.Detail = StatusOK, "Correlation is enabled with every rule active."
	}
	return c
}

func checkActions(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-015", Area: AreaDetection, Title: "Detection actions change decoy responses", Doc: docDetection}
	changed := []string{}
	for _, severity := range []string{"info", "low", "medium", "high"} {
		switch action := f.Actions[severity]; action {
		case "throttle", "isolate", "refuse":
			changed = append(changed, severity+"="+action)
		}
	}
	if len(changed) == 0 {
		c.Status, c.Detail = StatusOK, "Every severity maps to observe or tag; decoy responses do not change when rules fire."
		return c
	}
	c.Status = StatusInfo
	c.Detail = "Decoy responses change when rules fire (" + strings.Join(changed, ", ") + "). These actions affect only the decoy, never other systems, but an adaptive client can notice the change."
	c.Recommendation = "Use observe for severities where staying convincing matters more than slowing the client."
	return c
}

func checkSilentSensors(f *Facts, e Evidence) Check {
	c := Check{ID: "POS-016", Area: AreaEvidence, Title: "Sensors without retained observations", Doc: docPosture}
	if !e.Available {
		c.Status, c.Detail = StatusInfo, "Not evaluated: "+e.Reason
		return c
	}
	silent := []string{}
	for _, s := range f.Sensors {
		if e.SensorEvents[s.ID] == 0 {
			silent = append(silent, s.ID)
		}
	}
	if len(silent) == 0 {
		c.Status, c.Detail = StatusOK, fmt.Sprintf("Every configured sensor has observations among the %d retained events examined.", e.Scanned)
		return c
	}
	c.Status = StatusInfo
	c.Detail = fmt.Sprintf("No observations among the %d retained events examined: %s. A quiet decoy is not a fault.", e.Scanned, list(silent))
	c.Recommendation = "If traffic was expected, check the listener is reachable from where attackers would come from."
	return c
}

func checkSampleSaturation(_ *Facts, e Evidence) Check {
	c := Check{ID: "POS-017", Area: AreaEvidence, Title: "Analysis sample saturation", Doc: docPosture}
	switch {
	case !e.Available:
		c.Status, c.Detail = StatusInfo, "Not evaluated: "+e.Reason
	case e.Truncated:
		c.Status = StatusAttention
		c.Detail = fmt.Sprintf("Retained evidence exceeds the %d-event analysis sample; sessions, campaigns, actor profiles and this review ignore older events.", e.Limit)
		c.Recommendation = "Use exports or narrower windows for older evidence, and lower retention if analysis should cover everything retained."
	default:
		c.Status, c.Detail = StatusOK, fmt.Sprintf("%d retained event(s) fit within the %d-event analysis sample.", e.Scanned, e.Limit)
	}
	return c
}

func checkBreakGlass(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-019", Area: AreaAccess, Title: "Break-glass administrator", Doc: docAccounts}
	configAdmins := 0
	if f.TokenLogin {
		configAdmins = f.OperatorRoles["admin"]
	}
	managed := "managed accounts were not evaluated (offline review)"
	if f.ManagedKnown {
		managed = fmt.Sprintf("%d managed admin account(s) can sign in", f.ManagedAdmins)
	}
	switch {
	case !f.ConsoleEnabled:
		c.Status, c.Detail = StatusInfo, "The console is disabled; administrator access was not evaluated."
	case configAdmins > 0:
		c.Status = StatusOK
		c.Detail = fmt.Sprintf("%d config-file admin token(s) can sign in independently of managed accounts and SSO; %s.", configAdmins, managed)
	default:
		c.Status = StatusInfo
		c.Detail = "No config-file admin token can sign in, so recovery depends on " + map[bool]string{true: "OIDC role mapping and ", false: ""}[f.OIDC] + "managed accounts; " + managed + "."
		c.Recommendation = "Keep one config-file admin operator (console.operators) with its token stored offline as break-glass access."
	}
	return c
}

func checkEncryption(f *Facts, _ Evidence) Check {
	c := Check{ID: "POS-018", Area: AreaEvidence, Title: "Evidence encryption at rest", Doc: docEncryption}
	if f.EncryptionAtRest {
		c.Status, c.Detail = StatusOK, "Evidence segments are encrypted to an age/X25519 recipient."
		return c
	}
	c.Status = StatusInfo
	c.Detail = "Evidence is stored unencrypted; it is redacted but still holds attacker-supplied text and source addresses."
	c.Recommendation = "Enable storage.encryption if the data directory is backed up or shared."
	return c
}
