package ext

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// Frame is one NDJSON message on the extension wire.
type Frame struct {
	Type     string          `json:"type"` // hello|hello_ok|request|response|error
	Protocol int             `json:"protocol,omitempty"`
	ID       string          `json:"id,omitempty"`
	Method   string          `json:"method,omitempty"`
	Name     string          `json:"name,omitempty"`
	Version  string          `json:"version,omitempty"`
	Params   json.RawMessage `json:"params,omitempty"`
	Result   json.RawMessage `json:"result,omitempty"`
	Message  string          `json:"message,omitempty"`
}

// Host runs a verified extension as an isolated subprocess.
type Host struct {
	m       *Manifest
	exe     string
	cmd     *exec.Cmd
	stdin   chan<- Frame
	stdout  <-chan Frame
	errCh   <-chan error
	closed  bool
	closeMu sync.Mutex
	logf    func(format string, args ...any)
}

// Start spawns the extension and performs the version handshake. Any failure
// tears the process down before Start returns.
func Start(ctx context.Context, m *Manifest, logf func(string, ...any)) (*Host, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	exe, err := m.ExecutablePath()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, m.Transport.Command[1:]...) //nolint:gosec // binary digest-verified by caller; no shell
	// Extensions are untrusted: they run with a fixed minimal environment and
	// the manifest directory as cwd. Inheriting the operator's environment
	// would leak configuration secrets (e.g. AEGISMESH_LLM_API_KEY) into a
	// process we do not trust.
	cmd.Env = []string{"AEGISMESH_EXTENSION=1"}
	cmd.Dir = m.Dir
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: stdin pipe: %v", errManifest, err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: stdout pipe: %v", errManifest, err)
	}
	cmd.Stderr = nil // extensions get no stderr channel into our logs

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: start %s: %v", errManifest, exe, err)
	}

	hErr := make(chan error, 1)
	frames := make(chan Frame, 16)
	go readFrames(stdoutPipe, frames, hErr, m.Transport.MaxOutputBytes)

	inCh := make(chan Frame, 4)
	go writeFrames(stdinPipe, inCh)

	h := &Host{m: m, exe: exe, cmd: cmd, stdin: inCh, stdout: frames, errCh: hErr, logf: logf}

	hsCtx, cancel := context.WithTimeout(ctx, time.Duration(m.Transport.HandshakeTimeoutMS)*time.Millisecond)
	defer cancel()
	hello := Frame{Type: "hello", Protocol: ProtocolVersion}
	select {
	case inCh <- hello:
	case <-hsCtx.Done():
		h.kill()
		return nil, fmt.Errorf("%w: handshake send timed out for %s", errManifest, m.Name)
	}
	select {
	case f, ok := <-frames:
		if !ok || f.Type != "hello_ok" || f.Protocol != ProtocolVersion {
			h.kill()
			return nil, fmt.Errorf("%w: bad handshake from %s (want hello_ok protocol=%d)", errManifest, m.Name, ProtocolVersion)
		}
	case err := <-hErr:
		h.kill()
		return nil, fmt.Errorf("%w: handshake read from %s: %v", errManifest, m.Name, err)
	case <-hsCtx.Done():
		h.kill()
		return nil, fmt.Errorf("%w: handshake timed out for %s", errManifest, m.Name)
	}
	return h, nil
}

func readFrames(r interface{ Read([]byte) (int, error) }, out chan<- Frame, errOut chan<- error, maxBytes int) {
	defer close(out)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), maxBytes)
	for sc.Scan() {
		var f Frame
		if err := json.Unmarshal(sc.Bytes(), &f); err != nil {
			errOut <- fmt.Errorf("undecodable frame: %w", err)
			return
		}
		out <- f
	}
	if err := sc.Err(); err != nil {
		// Scanner errors are cap violations (token too long) or I/O failures;
		// clean EOF ends the loop above without an error.
		errOut <- fmt.Errorf("read loop: %w (output cap %d bytes enforced)", err, maxBytes)
	}
	// Clean EOF signals only via close(out); errOut carries real failures so
	// callers never race a nil against a useful frame/closed-channel result.
}

func writeFrames(w interface{ Write([]byte) (int, error) }, in <-chan Frame) {
	enc := json.NewEncoder(frameWriter{w})
	for f := range in {
		if enc.Encode(f) != nil {
			return
		}
	}
}

type frameWriter struct {
	w interface{ Write([]byte) (int, error) }
}

func (fw frameWriter) Write(p []byte) (int, error) { return fw.w.Write(p) }

// Call sends one request and waits for its response within the manifest's
// call deadline. On timeout the process is revoked immediately.
func (h *Host) Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	id := fmt.Sprintf("req-%d", time.Now().UnixNano())
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(h.m.Transport.CallTimeoutMS)*time.Millisecond)
	defer cancel()

	select {
	case h.stdin <- Frame{Type: "request", ID: id, Method: method, Params: params}:
	case <-callCtx.Done():
		h.kill()
		return nil, fmt.Errorf("%w: call to %s timed out sending; process revoked", errManifest, h.m.Name)
	}
	for {
		select {
		case f, ok := <-h.stdout:
			if !ok {
				return nil, fmt.Errorf("%w: extension %s closed output unexpectedly", errManifest, h.m.Name)
			}
			if f.ID != id {
				continue // ignore stray notifications; protocol has none today
			}
			if f.Type == "error" {
				return nil, fmt.Errorf("extension error: %s", f.Message)
			}
			if f.Type != "response" {
				return nil, fmt.Errorf("%w: unexpected frame type %q", errManifest, f.Type)
			}
			return f.Result, nil
		case err := <-h.errCh:
			return nil, fmt.Errorf("%w: extension %s failed: %v", errManifest, h.m.Name, err)
		case <-callCtx.Done():
			h.kill()
			return nil, fmt.Errorf("%w: call deadline exceeded for %s; process revoked", errManifest, h.m.Name)
		}
	}
}

// kill revokes the extension. It never returns an error the caller must handle:
// best-effort teardown after a violation or shutdown.
func (h *Host) kill() {
	h.closeMu.Lock()
	defer h.closeMu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_ = h.cmd.Wait()
	}
}

// Stop shuts the extension down cleanly (close stdin, then wait briefly).
func (h *Host) Stop() {
	h.closeMu.Lock()
	defer h.closeMu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	close(h.stdin)
	done := make(chan struct{})
	go func() { _ = h.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = h.cmd.Process.Kill()
		<-done
	}
}
