package config

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/honeytoken"
)

// MCPEnvironment is an optional in-memory workspace. Names are exact lookup keys.
type MCPEnvironment struct {
	Files          []MCPEntry        `yaml:"files" json:"files"`
	Env            []MCPEntry        `yaml:"env" json:"env"`
	Queries        map[string]string `yaml:"queries" json:"queries"`
	DepthThreshold int               `yaml:"depth_threshold" json:"depth_threshold"`
}

// MCPEntry declares inert content and an optional planted credential reference.
type MCPEntry struct {
	Name    string `yaml:"name" json:"name"`
	Content string `yaml:"content" json:"content"`
	TokenID string `yaml:"token_id,omitempty" json:"token_id,omitempty"`
}

// ValidateMCPEnvironment checks every environment field independently of listener setup.
func ValidateMCPEnvironment(e *MCPEnvironment, tokens []honeytoken.Token) error {
	if e == nil {
		return nil
	}
	if e.DepthThreshold < 2 || e.DepthThreshold > 32 {
		return fmt.Errorf("environment.depth_threshold must be 2..32")
	}
	if len(e.Files)+len(e.Env)+len(e.Queries) == 0 {
		return fmt.Errorf("environment requires declared content")
	}
	total := 0
	for _, group := range []struct {
		name    string
		entries []MCPEntry
	}{{"files", e.Files}, {"env", e.Env}} {
		if len(group.entries) > 32 {
			return fmt.Errorf("environment.%s exceeds 32 entries", group.name)
		}
		seen := map[string]bool{}
		for _, entry := range group.entries {
			if !environmentKey(entry.Name) || seen[entry.Name] {
				return fmt.Errorf("environment.%s requires unique names of 1..128 printable bytes", group.name)
			}
			seen[entry.Name] = true
			if group.name == "env" && (!envNameRe.MatchString(entry.Name) || entry.TokenID == "") {
				return fmt.Errorf("environment.env requires env-shaped names and honeytoken ids")
			}
			if len(entry.Content) == 0 || len(entry.Content) > 4096 || !utf8.ValidString(entry.Content) {
				return fmt.Errorf("environment content must be 1..4096 UTF-8 bytes")
			}
			total += len(entry.Name) + len(entry.Content)
			if entry.TokenID != "" {
				found := false
				for _, token := range tokens {
					if token.ID == entry.TokenID && token.Kind == honeytoken.Credential && strings.Contains(entry.Content, token.Value) {
						found = true
					}
				}
				if !found {
					return fmt.Errorf("environment token_id must reference a planted credential present in content")
				}
			}
		}
	}
	if len(e.Queries) > 32 {
		return fmt.Errorf("environment.queries exceeds 32 entries")
	}
	for key, content := range e.Queries {
		if !environmentKey(key) || len(content) == 0 || len(content) > 4096 || !utf8.ValidString(content) {
			return fmt.Errorf("environment.queries requires printable keys and 1..4096 UTF-8 content bytes")
		}
		total += len(key) + len(content)
	}
	if total > 16<<10 {
		return fmt.Errorf("environment exceeds 16384 total key/content bytes")
	}
	return nil
}

func environmentKey(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// MCPEnvironmentTools returns the fixed, data-only environment tool names.
func MCPEnvironmentTools() []string {
	return []string{"list_files", "read_file", "get_env", "search", "run_query"}
}

// MCPEnvironmentToolCount reports the number of built-in environment tools.
func MCPEnvironmentToolCount(e *MCPEnvironment) int {
	if e == nil {
		return 0
	}
	return 5
}

// IsMCPEnvironmentTool reports membership in the fixed tool set.
func IsMCPEnvironmentTool(name string) bool {
	for _, n := range MCPEnvironmentTools() {
		if name == n {
			return true
		}
	}
	return false
}
