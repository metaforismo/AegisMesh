package rulecatalog

// FrameworkMapping is an editorial "relates to" reference, not coverage.
type FrameworkMapping struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Name      string `json:"name"`
}

type frameworkRefs struct{ attack, atlas, owasp []string }

// Explicit entries include empty framework lists; unmapped rules must never
// silently inherit a guessed technique. Names and IDs are the operator's table.
var frameworkTable = map[string]frameworkRefs{
	"PI-001":  {nil, []string{"AML.T0051 LLM Prompt Injection", "AML.T0054 LLM Jailbreak"}, []string{"LLM01 Prompt Injection"}},
	"PI-002":  {[]string{"T1027 Obfuscated Files or Information"}, []string{"AML.T0051 LLM Prompt Injection"}, []string{"LLM01 Prompt Injection"}},
	"EXF-001": {[]string{"T1552 Unsecured Credentials"}, []string{"AML.T0057 LLM Data Leakage"}, []string{"LLM02 Sensitive Information Disclosure"}},
	"ESC-001": {[]string{"T1059 Command and Scripting Interpreter"}, []string{"AML.T0053 LLM Plugin Compromise"}, []string{"LLM06 Excessive Agency"}},
	"OBS-001": {[]string{"T1027 Obfuscated Files or Information"}, nil, nil},
	"RES-001": {[]string{"T1499 Endpoint Denial of Service"}, []string{"AML.T0029 Denial of ML Service"}, []string{"LLM10 Unbounded Consumption"}},
	"LLM-001": {[]string{"T1595 Active Scanning"}, []string{"AML.T0006 Active Scanning"}, nil},
	"LLM-002": {[]string{"T1078 Valid Accounts"}, []string{"AML.T0012 Valid Accounts", "AML.T0040 AI Model Inference API Access"}, []string{"LLM10 Unbounded Consumption"}},
	"LLM-003": {[]string{"T1496 Resource Hijacking"}, []string{"AML.T0034 Cost Harvesting"}, []string{"LLM10 Unbounded Consumption"}},
	"LLM-004": {[]string{"T1078 Valid Accounts"}, []string{"AML.T0012 Valid Accounts"}, nil},
	"HT-001":  {[]string{"T1552 Unsecured Credentials", "T1078 Valid Accounts"}, []string{"AML.T0055 Unsecured Credentials"}, []string{"LLM02 Sensitive Information Disclosure"}},
	"AGT-001": {nil, []string{"AML.T0051 LLM Prompt Injection"}, []string{"LLM01 Prompt Injection"}},
	"COR-001": {nil, []string{"AML.T0051 LLM Prompt Injection"}, []string{"LLM01 Prompt Injection"}},
	"COR-002": {[]string{"T1046 Network Service Discovery"}, nil, nil},
	"COR-003": {[]string{"T1046 Network Service Discovery"}, []string{"AML.T0053 LLM Plugin Compromise"}, []string{"LLM06 Excessive Agency"}},
	"COR-004": {[]string{"T1595 Active Scanning"}, []string{"AML.T0006 Active Scanning"}, nil},
	"COR-005": {[]string{"T1595 Active Scanning"}, nil, nil},
	"COR-006": {[]string{"T1595 Active Scanning"}, []string{"AML.T0006 Active Scanning"}, nil},
	"COR-007": {[]string{"T1110 Brute Force"}, nil, nil},
	"COR-008": {[]string{"T1078 Valid Accounts"}, []string{"AML.T0012 Valid Accounts"}, []string{"LLM02 Sensitive Information Disclosure"}},
}

func frameworks(id string) []FrameworkMapping {
	refs := frameworkTable[id]
	out := []FrameworkMapping{}
	for _, f := range []struct {
		name string
		refs []string
	}{{"mitre-attack", refs.attack}, {"mitre-atlas", refs.atlas}, {"owasp-llm-2025", refs.owasp}} {
		for _, ref := range f.refs {
			for i := range ref {
				if ref[i] == ' ' {
					out = append(out, FrameworkMapping{f.name, ref[:i], ref[i+1:]})
					break
				}
			}
		}
	}
	return out
}
