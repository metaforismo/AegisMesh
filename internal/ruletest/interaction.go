package ruletest

import (
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/honeytoken"
)

// EvaluateInteraction is the structured offline seam for synthetic sensor
// fixtures. It acquires no input and never persists or echoes fixture bytes.
func EvaluateInteraction(in detect.Input, tokens []honeytoken.Token) ([]detect.Finding, error) {
	if err := honeytoken.Validate(tokens); err != nil {
		return nil, err
	}
	parts := []string{in.Text, in.Path, in.Body}
	for name, values := range in.Headers {
		parts = append(parts, name)
		parts = append(parts, values...)
	}
	in.TokenMatches = honeytoken.New(tokens).Find(parts...)
	// Mirror the HTTP gate's legacy text view as well as the new typed fields.
	if in.Text == "" && in.Method != "" {
		in.Text = in.Method + " " + in.Path + " " + in.Body
		in.TotalBytes = len(in.Method) + len(in.Path) + len(in.Body)
		if len(in.Text) > detect.DefaultMaxInputBytes {
			in.Text = in.Text[:detect.DefaultMaxInputBytes]
		}
	}
	return detect.New(detect.Options{}).Evaluate(in), nil
}
