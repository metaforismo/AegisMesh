package evidencereport

import (
	"bytes"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/console/investigations"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func TestMarkdownNeutralizer(t *testing.T) {
	for _, value := range []string{
		"```\n# Forged report\n<script>alert(1)</script>\n```",
		"\r\n~~~\n![tracker](https://example.invalid/x)\n[click](javascript:x)",
		"<img src=x onerror=alert(1)>\u2028# forged\u2029<script>",
		"\x00\xff\t# escaped",
		"\u202e# forged\u2066",
	} {
		t.Run(value, func(t *testing.T) {
			got := MarkdownText(value)
			lines := strings.Split(got, "\n")
			if len(lines) != 6 || lines[1] != "```text" || lines[3] != "```" || !strings.HasPrefix(lines[2], `"`) || strings.ContainsAny(lines[2], "\r\u2028\u2029<>") {
				t.Fatalf("unsafe structure: %q", got)
			}
		})
	}
}

func TestReportDeterministicAndNeutralized(t *testing.T) {
	attack := "```\n# FORGED\n<img src=tracker>\n```"
	input := Input{
		Tenant: "default", Scope: attack,
		Bounds:        evidenceindex.Snapshot{Limit: evidenceindex.AnalysisLimit, Index: evidenceindex.Stats{History: "unavailable"}},
		Events:        []evidenceindex.Summary{{ID: strings.Repeat("a", 32), Time: "2026-01-01T00:00:00Z", Source: attack, Summary: attack, RuleIDs: []string{"AGT-001"}}},
		Investigation: &investigations.Investigation{Title: attack, EventIDs: []string{strings.Repeat("a", 32)}, Notes: []investigations.Note{{Author: attack, Text: attack}}},
	}
	first, err := Render(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(input)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("report changed without input changes")
	}
	if bytes.Contains(first, []byte("\n# FORGED")) || bytes.Contains(first, []byte("<img")) {
		t.Fatal("forged Markdown or active HTML")
	}
	for _, required := range []string{"## Scope", "## Timeline", "## Sources", "## Rules and framework references", "mitre-atlas AML.T0051", "## Automation observations", "agent_canary", "## Attached notes", "## Proposed dry-run recommendations", "Not executed", "## Limits", "unavailable", "redacted"} {
		if !bytes.Contains(first, []byte(required)) {
			t.Errorf("missing %q", required)
		}
	}
}

func FuzzMarkdownNeutralizer(f *testing.F) {
	for _, seed := range []string{"```\n# forged", "~~~\n<script>", "[link](javascript:evil)", "\xff\x00\u2028"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		got := MarkdownText(value)
		lines := strings.Split(got, "\n")
		if len(lines) != 6 || !strings.HasPrefix(lines[2], `"`) || lines[1] != "```text" || lines[3] != "```" || strings.ContainsAny(lines[2], "<>\r\u2028\u2029\u202e\u2066") {
			t.Fatal("variable text escaped its data line")
		}
	})
}
