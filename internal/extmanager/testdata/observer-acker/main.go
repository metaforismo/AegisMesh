// Synthetic observer extension used only by tests: acks every observe call.
package main

import (
	"bufio"
	"encoding/json"
	"os"
)

type frame struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Proto   int             `json:"protocol,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Message string          `json:"message,omitempty"`
}

func write(w *bufio.Writer, f frame) {
	_ = json.NewEncoder(w).Encode(f)
	w.Flush()
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 4096), 1<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		var f frame
		if json.Unmarshal(sc.Bytes(), &f) != nil {
			return
		}
		switch {
		case f.Type == "hello":
			write(w, frame{Type: "hello_ok", Proto: f.Proto})
		case f.Type == "request":
			// Record the observation to received.ndjson in the process cwd so
			// tests can prove delivery happened end-to-end.
			if fh, err := os.OpenFile("received.ndjson", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				fh.WriteString(f.ID + "\n")
				fh.Close()
			}
			write(w, frame{Type: "response", ID: f.ID, Result: json.RawMessage(`{"ok":true}`)})
		}
	}
}
