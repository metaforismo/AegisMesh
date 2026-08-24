// Command sbomcheck validates the small CycloneDX contract required by the
// AegisMesh release artifacts.
//
// The validator deliberately uses only the standard library. It is intended
// to be a deterministic, offline gate: it reads one bounded JSON file and
// never executes or interprets anything from that file.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	maxSBOMBytes = 16 << 20
	maxJSONDepth = 256
)

// ErrorKind identifies which part of the contract rejected an input.
type ErrorKind string

const (
	ErrorInput      ErrorKind = "input error"
	ErrorParse      ErrorKind = "JSON parse error"
	ErrorValidation ErrorKind = "validation error"
)

// ContractError is an actionable, typed error returned for bounded input,
// JSON, and CycloneDX contract failures.
type ContractError struct {
	Kind   ErrorKind
	Path   string
	Reason string
	Err    error
}

func (e *ContractError) Error() string {
	if e == nil {
		return "<nil>"
	}

	where := string(e.Kind)
	if e.Path != "" {
		where += " at " + e.Path
	}
	if e.Reason != "" {
		where += ": " + e.Reason
	}
	if e.Err != nil {
		where += ": " + e.Err.Error()
	}
	return where
}

func (e *ContractError) Unwrap() error { return e.Err }

// Validate checks the AegisMesh CycloneDX contract for data already read by
// the caller. It does not perform I/O.
func Validate(data []byte) error {
	if len(data) > maxSBOMBytes {
		return inputError("$", fmt.Sprintf("SBOM exceeds maximum size of %d bytes", maxSBOMBytes), nil)
	}

	value, err := decodeJSON(data)
	if err != nil {
		return err
	}

	root, ok := value.(map[string]any)
	if !ok {
		return validationError("$", "the top-level JSON value must be an object")
	}

	if err := requireString(root, "bomFormat", "$.bomFormat", "CycloneDX"); err != nil {
		return err
	}
	if err := requireString(root, "specVersion", "$.specVersion", "1.6"); err != nil {
		return err
	}

	metadata, err := requireObject(root, "metadata", "$.metadata")
	if err != nil {
		return err
	}
	metadataComponent, err := requireObject(metadata, "component", "$.metadata.component")
	if err != nil {
		return err
	}
	if len(metadataComponent) == 0 {
		return validationError("$.metadata.component", "must be nonempty")
	}

	components := make(map[string]struct{})
	rootRef, err := requireNonEmptyString(metadataComponent, "bom-ref", "$.metadata.component.bom-ref")
	if err != nil {
		return err
	}
	components[rootRef] = struct{}{}

	if err := collectNestedComponents(metadataComponent, "$.metadata.component", components); err != nil {
		return err
	}

	if rawComponents, exists := root["components"]; exists {
		componentList, ok := rawComponents.([]any)
		if !ok {
			return validationError("$.components", "must be an array")
		}
		for i, rawComponent := range componentList {
			componentPath := fmt.Sprintf("$.components[%d]", i)
			component, ok := rawComponent.(map[string]any)
			if !ok {
				return validationError(componentPath, "must be an object")
			}
			if err := collectComponent(component, componentPath, components); err != nil {
				return err
			}
		}
	}

	dependencies, err := requireArray(root, "dependencies", "$.dependencies")
	if err != nil {
		return err
	}
	if len(dependencies) == 0 {
		return validationError("$.dependencies", "dependency graph must be nonempty")
	}

	dependencyRefs := make(map[string]struct{}, len(dependencies))
	rootEdgeCount := 0
	for i, rawDependency := range dependencies {
		dependencyPath := fmt.Sprintf("$.dependencies[%d]", i)
		dependency, ok := rawDependency.(map[string]any)
		if !ok {
			return validationError(dependencyPath, "must be an object")
		}

		ref, err := requireNonEmptyString(dependency, "ref", dependencyPath+".ref")
		if err != nil {
			return err
		}
		if _, exists := dependencyRefs[ref]; exists {
			return validationError(dependencyPath+".ref", fmt.Sprintf("duplicate dependency ref %q", ref))
		}
		dependencyRefs[ref] = struct{}{}
		if _, resolves := components[ref]; !resolves {
			return validationError(dependencyPath+".ref", fmt.Sprintf("ref %q does not resolve to a component", ref))
		}
		dependsOn, err := optionalStringArray(dependency, "dependsOn", dependencyPath+".dependsOn")
		if err != nil {
			return err
		}
		if ref == rootRef {
			rootEdgeCount = len(dependsOn)
		}
		for j, target := range dependsOn {
			targetPath := fmt.Sprintf("%s[%d]", dependencyPath+".dependsOn", j)
			if _, resolves := components[target]; !resolves {
				return validationError(targetPath, fmt.Sprintf("target %q does not resolve to a component", target))
			}
		}
	}

	if _, rootFound := dependencyRefs[rootRef]; !rootFound {
		return validationError("$.dependencies", fmt.Sprintf("root component ref %q is missing", rootRef))
	}
	if rootEdgeCount == 0 {
		return validationError("$.dependencies", "dependency graph for the root component must contain at least one edge")
	}

	return nil
}

func validationError(path, reason string) error {
	return &ContractError{Kind: ErrorValidation, Path: path, Reason: reason}
}

func parseError(path, reason string, err error) error {
	return &ContractError{Kind: ErrorParse, Path: path, Reason: reason, Err: err}
}

func inputError(path, reason string, err error) error {
	return &ContractError{Kind: ErrorInput, Path: path, Reason: reason, Err: err}
}

func requireString(object map[string]any, key, path, expected string) error {
	value, ok := object[key]
	if !ok {
		return validationError(path, "is required")
	}
	actual, ok := value.(string)
	if !ok {
		return validationError(path, "must be a string")
	}
	if actual != expected {
		return validationError(path, fmt.Sprintf("must be exactly %q", expected))
	}
	return nil
}

func requireNonEmptyString(object map[string]any, key, path string) (string, error) {
	value, ok := object[key]
	if !ok {
		return "", validationError(path, "is required and must be nonempty")
	}
	actual, ok := value.(string)
	if !ok {
		return "", validationError(path, "must be a string")
	}
	if actual == "" {
		return "", validationError(path, "must be nonempty")
	}
	return actual, nil
}

func requireObject(object map[string]any, key, path string) (map[string]any, error) {
	value, ok := object[key]
	if !ok {
		return nil, validationError(path, "is required")
	}
	actual, ok := value.(map[string]any)
	if !ok {
		return nil, validationError(path, "must be an object")
	}
	return actual, nil
}

func requireArray(object map[string]any, key, path string) ([]any, error) {
	value, ok := object[key]
	if !ok {
		return nil, validationError(path, "is required")
	}
	actual, ok := value.([]any)
	if !ok {
		return nil, validationError(path, "must be an array")
	}
	return actual, nil
}

func optionalStringArray(object map[string]any, key, path string) ([]string, error) {
	value, ok := object[key]
	if !ok {
		return nil, nil
	}
	array, ok := value.([]any)
	if !ok {
		return nil, validationError(path, "must be an array of nonempty strings")
	}
	result := make([]string, len(array))
	for i, item := range array {
		itemPath := fmt.Sprintf("%s[%d]", path, i)
		value, ok := item.(string)
		if !ok {
			return nil, validationError(itemPath, "must be a string")
		}
		if value == "" {
			return nil, validationError(itemPath, "must be nonempty")
		}
		result[i] = value
	}
	return result, nil
}

func collectComponent(component map[string]any, path string, refs map[string]struct{}) error {
	ref, err := requireNonEmptyString(component, "bom-ref", path+".bom-ref")
	if err != nil {
		return err
	}
	if _, exists := refs[ref]; exists {
		return validationError(path+".bom-ref", fmt.Sprintf("duplicate component bom-ref %q", ref))
	}
	refs[ref] = struct{}{}
	return collectNestedComponents(component, path, refs)
}

func collectNestedComponents(component map[string]any, path string, refs map[string]struct{}) error {
	rawNested, exists := component["components"]
	if !exists {
		return nil
	}
	nested, ok := rawNested.([]any)
	if !ok {
		return validationError(path+".components", "must be an array")
	}
	for i, rawComponent := range nested {
		nestedPath := fmt.Sprintf("%s.components[%d]", path, i)
		child, ok := rawComponent.(map[string]any)
		if !ok {
			return validationError(nestedPath, "must be an object")
		}
		if err := collectComponent(child, nestedPath, refs); err != nil {
			return err
		}
	}
	return nil
}

func decodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := parseJSONValue(decoder, "$", 0)
	if err != nil {
		return nil, err
	}

	_, err = decoder.Token()
	if err == nil {
		return nil, parseError("$", "trailing JSON value", nil)
	}
	if !errors.Is(err, io.EOF) {
		return nil, parseError("$", "trailing data after the JSON value", err)
	}
	return value, nil
}

func parseJSONValue(decoder *json.Decoder, path string, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, parseError(path, fmt.Sprintf("maximum JSON nesting depth %d exceeded", maxJSONDepth), nil)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, parseError(path, "invalid JSON", err)
	}

	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}

	switch delim {
	case '{':
		object := make(map[string]any)
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, parseError(path, "invalid JSON object key", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, parseError(path, "JSON object key must be a string", nil)
			}
			if _, duplicate := seen[key]; duplicate {
				return nil, parseError(path+"."+key, "duplicate JSON object field", nil)
			}
			seen[key] = struct{}{}
			value, err := parseJSONValue(decoder, path+"."+key, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		closing, err := decoder.Token()
		if err != nil {
			return nil, parseError(path, "unterminated JSON object", err)
		}
		if closing != json.Delim('}') {
			return nil, parseError(path, "JSON object has an invalid closing delimiter", nil)
		}
		return object, nil

	case '[':
		array := make([]any, 0)
		index := 0
		for decoder.More() {
			itemPath := fmt.Sprintf("%s[%d]", path, index)
			value, err := parseJSONValue(decoder, itemPath, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
			index++
		}
		closing, err := decoder.Token()
		if err != nil {
			return nil, parseError(path, "unterminated JSON array", err)
		}
		if closing != json.Delim(']') {
			return nil, parseError(path, "JSON array has an invalid closing delimiter", nil)
		}
		return array, nil

	default:
		return nil, parseError(path, fmt.Sprintf("unexpected JSON delimiter %q", delim), nil)
	}
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, inputError(path, "cannot open SBOM", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxSBOMBytes+1))
	if err != nil {
		return nil, inputError(path, "cannot read SBOM", err)
	}
	if len(data) > maxSBOMBytes {
		return nil, inputError(path, fmt.Sprintf("SBOM exceeds maximum size of %d bytes", maxSBOMBytes), nil)
	}
	return data, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "sbomcheck: usage: sbomcheck <sbom-path>")
		return 2
	}

	data, err := readBounded(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "sbomcheck: %v\n", err)
		return 1
	}
	if err := Validate(data); err != nil {
		fmt.Fprintf(stderr, "sbomcheck: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "SBOM valid")
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
