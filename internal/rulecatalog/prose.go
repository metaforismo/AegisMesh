package rulecatalog

import "github.com/metaforismo/aegismesh/internal/detect"

// Prose is static operator guidance; no observed text supplies these fields.
var prose = map[string][2]string{
	"PI-001":  {"Instruction override phrasing was observed.", "Review the redacted request and surrounding session for legitimate diagnostic context."},
	"PI-002":  {"Hidden channel characters were observed in an interaction.", "Check the redacted preview and encoding context before interpreting the observation."},
	"EXF-001": {"A credential or environment disclosure request pattern was observed.", "Check which synthetic surface was contacted and whether a planted token was later presented."},
	"ESC-001": {"Tool escalation phrasing was observed.", "Review the requested tool name and the recorded response action."},
	"OBS-001": {"A large encoded blob or repeated encoding marker was observed.", "Check payload size and protocol context without executing or decoding it into behavior."},
	"RES-001": {"The interaction exceeded the detection evaluation bound.", "Check retained length and truncation flags before drawing conclusions from partial evidence."},
	"LLM-001": {"An AI service shaped endpoint was contacted.", "Review other surfaces contacted by the same retained source."},
	"LLM-002": {"A small completion shaped probe was observed.", "Check nearby enumeration requests and normal health monitoring context."},
	"LLM-003": {"An AI management shaped request was observed.", "Review the static response and adjacent requests; no management operation occurred."},
	"LLM-004": {"A provider shaped credential was presented.", "Check credential class metadata and planted-token matches without seeking credential values."},
	"HT-001":  {"A planted synthetic credential was presented to a sensor.", "Follow the token identifier across retained observations and verify its configured planting."},
	"AGT-001": {"A planted agent marker was presented to a sensor.", "Review the originating synthetic response and subsequent request sequence."},
	"MCP-001": {"Declared synthetic credential content was requested from the workspace.", "Check the connection tool sequence and later HT-001 or COR-008 observations."},
	"MCP-002": {"A connection reached the configured workspace exploration depth.", "Review tool order and cadence; depth alone does not identify an automated client."},
	"MCP-003": {"A write or execution shaped tool name was requested.", "Review the tool name and not-found response; no write or execution was performed."},
	"COR-001": {"Repeated injection findings were observed for a retained source.", "Review the linked observations and their detection limits."},
	"COR-002": {"A retained source contacted multiple sensor kinds.", "Check whether an authorized scanner or monitoring client explains the sequence."},
	"COR-003": {"Tool escalation findings were observed across retained interactions.", "Review the linked tool calls and their static responses."},
	"COR-004": {"A retained source showed repeated decoy enumeration.", "Check the linked requests and expected scanner schedules."},
	"COR-005": {"A retained source showed a cadence consistent with automation.", "Inspect timing gaps and clock precision; this is not client attribution."},
	"COR-006": {"A retained source enumerated multiple AI surface families.", "Compare contacted families with normal client and monitoring behavior."},
	"COR-007": {"Multiple distinct credential presentations were observed.", "Review counts and credential classes without seeking raw credential values."},
	"COR-008": {"A planted credential was presented across sensor contexts.", "Trace the token identifier and linked sensor observations within retained evidence."},
}

func enrich(e *Entry) {
	e.Description = prose[e.ID][0]
	e.Guidance = prose[e.ID][1]
	e.ObserveOnly = e.Family == FamilyCorrelation || detect.ObserveOnly(detect.RuleID(e.ID))
}
