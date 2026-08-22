package cli

import (
	"encoding/json"
	"io"
	"text/tabwriter"
)

func tabWriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
}

// marshalLine produces compact single-line JSON for NDJSON output.
func marshalLine(v any) ([]byte, error) {
	return json.Marshal(v)
}
