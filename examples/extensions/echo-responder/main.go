// Command echo-responder is the AegisMesh reference observer extension.
//
// Contract: reads newline-delimited JSON frames on stdin, writes single-line
// JSON frames on stdout, answers the handshake, and acknowledges "observe"
// calls without returning policy or response data. It performs no IO beyond
// stdio.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
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

type observation struct {
	EventID string `json:"event_id"`
}

type acknowledgement struct {
	EventID  string `json:"event_id"`
	Accepted bool   `json:"accepted"`
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
			if f.Method != "observe" {
				enc(frame{Type: "error", ID: f.ID, Message: "unknown method"})
				continue
			}
			var obs observation
			if json.Unmarshal(f.Params, &obs) != nil || obs.EventID == "" {
				enc(frame{Type: "error", ID: f.ID, Message: "invalid observation"})
				continue
			}
			result, _ := json.Marshal(acknowledgement{EventID: obs.EventID, Accepted: true})
			enc(frame{Type: "response", ID: f.ID, Result: result})
		default:
			enc(frame{Type: "error", Message: "unknown frame type"})
		}
	}
}
