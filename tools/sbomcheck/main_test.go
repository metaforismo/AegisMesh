package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func validSBOM() map[string]any {
	return map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"metadata": map[string]any{
			"component": map[string]any{
				"type":    "application",
				"name":    "AegisMesh",
				"bom-ref": "pkg:aegismesh",
				"components": []any{
					map[string]any{
						"type":    "library",
						"name":    "nested-library",
						"bom-ref": "pkg:nested",
					},
				},
			},
		},
		"components": []any{
			map[string]any{
				"type":    "library",
				"name":    "direct-library",
				"bom-ref": "pkg:direct",
				"components": []any{
					map[string]any{
						"type":    "library",
						"name":    "transitive-library",
						"bom-ref": "pkg:transitive",
					},
				},
			},
		},
		"dependencies": []any{
			map[string]any{
				"ref": "pkg:aegismesh",
				"dependsOn": []any{
					"pkg:direct",
					"pkg:nested",
				},
			},
			map[string]any{
				"ref":       "pkg:direct",
				"dependsOn": []any{"pkg:transitive"},
			},
			map[string]any{
				"ref": "pkg:nested",
			},
			map[string]any{
				"ref": "pkg:transitive",
			},
		},
	}
}

func marshalSBOM(t *testing.T, value map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return data
}

func TestValidateContract(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(map[string]any)
		raw        []byte
		wantReason string
	}{
		{
			name: "valid graph with nested components",
		},
		{
			name: "wrong format",
			mutate: func(sbom map[string]any) {
				sbom["bomFormat"] = "SPDX"
			},
			wantReason: `$.bomFormat: must be exactly "CycloneDX"`,
		},
		{
			name: "wrong version",
			mutate: func(sbom map[string]any) {
				sbom["specVersion"] = "1.5"
			},
			wantReason: `$.specVersion: must be exactly "1.6"`,
		},
		{
			name: "missing root ref",
			mutate: func(sbom map[string]any) {
				delete(sbom["metadata"].(map[string]any)["component"].(map[string]any), "bom-ref")
			},
			wantReason: "$.metadata.component.bom-ref: is required and must be nonempty",
		},
		{
			name: "duplicate components",
			mutate: func(sbom map[string]any) {
				components := sbom["components"].([]any)
				components = append(components, map[string]any{"bom-ref": "pkg:direct"})
				sbom["components"] = components
			},
			wantReason: `duplicate component bom-ref "pkg:direct"`,
		},
		{
			name: "duplicate nested component",
			mutate: func(sbom map[string]any) {
				metadataComponent := sbom["metadata"].(map[string]any)["component"].(map[string]any)
				nested := metadataComponent["components"].([]any)
				nested = append(nested, map[string]any{"bom-ref": "pkg:direct"})
				metadataComponent["components"] = nested
			},
			wantReason: `duplicate component bom-ref "pkg:direct"`,
		},
		{
			name: "duplicate dependencies",
			mutate: func(sbom map[string]any) {
				dependencies := sbom["dependencies"].([]any)
				dependencies = append(dependencies, map[string]any{"ref": "pkg:direct"})
				sbom["dependencies"] = dependencies
			},
			wantReason: `duplicate dependency ref "pkg:direct"`,
		},
		{
			name: "dangling dependency ref",
			mutate: func(sbom map[string]any) {
				sbom["dependencies"].([]any)[1].(map[string]any)["ref"] = "pkg:missing"
			},
			wantReason: `ref "pkg:missing" does not resolve to a component`,
		},
		{
			name: "dangling dependency target",
			mutate: func(sbom map[string]any) {
				sbom["dependencies"].([]any)[0].(map[string]any)["dependsOn"] = []any{"pkg:missing"}
			},
			wantReason: `target "pkg:missing" does not resolve to a component`,
		},
		{
			name: "missing root dependency",
			mutate: func(sbom map[string]any) {
				dependencies := sbom["dependencies"].([]any)
				dependencies = dependencies[1:]
				sbom["dependencies"] = dependencies
			},
			wantReason: `root component ref "pkg:aegismesh" is missing`,
		},
		{
			name: "empty graph",
			mutate: func(sbom map[string]any) {
				sbom["dependencies"] = []any{}
			},
			wantReason: "$.dependencies: dependency graph must be nonempty",
		},
		{
			name: "root has no edges",
			mutate: func(sbom map[string]any) {
				sbom["dependencies"].([]any)[0].(map[string]any)["dependsOn"] = []any{}
			},
			wantReason: "dependency graph for the root component must contain at least one edge",
		},
		{
			name:       "malformed JSON",
			raw:        []byte(`{"bomFormat":"CycloneDX"`),
			wantReason: "JSON parse error",
		},
		{
			name:       "trailing JSON",
			raw:        append(marshalSBOM(t, validSBOM()), []byte(` {}`)...),
			wantReason: "trailing JSON value",
		},
		{
			name:       "duplicate JSON field",
			raw:        []byte(`{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}`),
			wantReason: "duplicate JSON object field",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var data []byte
			if test.raw != nil {
				data = test.raw
			} else {
				sbom := validSBOM()
				if test.mutate != nil {
					test.mutate(sbom)
				}
				data = marshalSBOM(t, sbom)
			}

			err := Validate(data)
			if test.wantReason == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() error = nil, want %q", test.wantReason)
			}
			if !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf("Validate() error = %q, want substring %q", err, test.wantReason)
			}
			var contractErr *ContractError
			if !errors.As(err, &contractErr) {
				t.Fatalf("Validate() error type = %T, want *ContractError", err)
			}
		})
	}
}

func TestValidateRejectsOversizedInput(t *testing.T) {
	data := bytes.Repeat([]byte(" "), maxSBOMBytes+1)
	err := Validate(data)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("Validate() error = %v, want bounded-input error", err)
	}
}

func TestReadBoundedRejectsOversizedFile(t *testing.T) {
	tempDir := t.TempDir()
	path := tempDir + "/oversized.json"
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), maxSBOMBytes+1), 0o600); err != nil {
		t.Fatalf("write oversized fixture: %v", err)
	}
	_, err := readBounded(path)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("readBounded() error = %v, want bounded-input error", err)
	}
}

func TestRunRequiresExactlyOnePath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("run(nil) code = %d, want 2", code)
	}
	if got, want := stderr.String(), "sbomcheck: usage: sbomcheck <sbom-path>\n"; got != want {
		t.Fatalf("run(nil) stderr = %q, want %q", got, want)
	}
}

func TestRunValidatesOnePath(t *testing.T) {
	tempDir := t.TempDir()
	path := tempDir + "/valid.json"
	if err := os.WriteFile(path, marshalSBOM(t, validSBOM()), 0o600); err != nil {
		t.Fatalf("write valid fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, stderr = %q", code, stderr.String())
	}
	if got, want := stdout.String(), "SBOM valid\n"; got != want {
		t.Fatalf("run() stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("run() stderr = %q, want empty", stderr.String())
	}
}

func TestContractErrorWrapsInputCause(t *testing.T) {
	missingPath := t.TempDir() + "/missing.json"
	_, err := readBounded(missingPath)
	if err == nil {
		t.Fatal("readBounded() error = nil")
	}
	var contractErr *ContractError
	if !errors.As(err, &contractErr) {
		t.Fatalf("readBounded() error type = %T, want *ContractError", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readBounded() error = %v, want os.ErrNotExist cause", err)
	}
}
