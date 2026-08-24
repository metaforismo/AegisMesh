// Synthetic observer extension used only by tests: crashes on the first observe call.
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
	Name    string          `json:"name,omitempty"`
	Version string          `json:"version,omitempty"`
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
			write(w, frame{Type: "hello_ok", Proto: f.Proto, Name: "obs-crasher", Version: "1.0.0"})
		case f.Type == "request":
			os.Exit(9) // die without replying: subprocess crash mid-stream
		}
	}
}
