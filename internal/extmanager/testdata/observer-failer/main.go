// Synthetic observer extension used only by tests: answers every observe call with an error frame.
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
			write(w, frame{Type: "error", ID: f.ID, Message: "synthetic failure"})
		}
	}
}
