// Command echo-responder is the AegisMesh reference extension: a minimal
// out-of-process responder demonstrating the subprocess-NDJSON contract.
//
// Contract: reads newline-delimited JSON frames on stdin, writes single-line
// JSON frames on stdout, answers the handshake, and responds to "respond"
// calls with a canned synthetic payload. It performs no IO beyond stdio.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type frame struct {
	Type     string          `json:"type"`
	Protocol int             `json:"protocol,omitempty"`
	ID       string          `json:"id,omitempty"`
	Method   string          `json:"method,omitempty"`
	Name     string          `json:"name,omitempty"`
	Version  string          `json:"version,omitempty"`
	Params   json.RawMessage `json:"params,omitempty"`
	Result   json.RawMessage `json:"result,omitempty"`
	Message  string          `json:"message,omitempty"`
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	enc := func(f frame) {
		b, _ := json.Marshal(f)
		fmt.Fprintln(out, string(b))
		out.Flush()
	}

	for in.Scan() {
		var f frame
		if err := json.Unmarshal(in.Bytes(), &f); err != nil {
			enc(frame{Type: "error", Message: "undecodable frame"})
			continue
		}
		switch f.Type {
		case "hello":
			if f.Protocol != 1 {
				enc(frame{Type: "error", Message: "unsupported protocol"})
				return
			}
			enc(frame{Type: "hello_ok", Protocol: 1, Name: "echo-responder", Version: "0.1.0"})
		case "request":
			if f.Method != "respond" {
				enc(frame{Type: "error", ID: f.ID, Message: "unknown method"})
				continue
			}
			result := `{"status":"ok","note":"synthetic reference response","echo_len":` +
				fmt.Sprint(len(strings.TrimSpace(string(f.Params)))) + `}`
			enc(frame{Type: "response", ID: f.ID, Result: json.RawMessage(result)})
		default:
			enc(frame{Type: "error", Message: "unknown frame type"})
		}
	}
}
