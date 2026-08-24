package ext

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

const MaxObservationBytes = 128 << 10

// Observation is the bounded data-only projection available to an observer.
// It intentionally omits response policy and runtime controls.
type Observation struct {
	EventID        string          `json:"event_id"`
	Time           time.Time       `json:"time"`
	Classification string          `json:"classification"`
	Sensor         event.SensorRef `json:"sensor"`
	Payload        json.RawMessage `json:"payload,omitempty"`
}

type observeAck struct {
	EventID  string `json:"event_id"`
	Accepted bool   `json:"accepted"`
}

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
	raw      []byte
}

// Host runs one verified data-only observer subprocess.
type Host struct {
	m      *Manifest
	cmd    *exec.Cmd
	stdin  chan Frame
	stdout <-chan Frame
	errCh  <-chan error
	done   chan struct{}
	waitCh <-chan error
	pipe   io.WriteCloser

	callMu   sync.Mutex
	stopOnce sync.Once
	seq      atomic.Uint64
}

// Start spawns the observer and binds its handshake identity to the verified
// manifest. Any failure revokes the process before Start returns.
func Start(ctx context.Context, m *Manifest) (*Host, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nil manifest", errManifest)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	exe, err := m.ExecutablePath()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, m.Transport.Command[1:]...) //nolint:gosec // artifact digest is verified by the caller; no shell
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
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: start %s: %v", errManifest, exe, err)
	}

	done := make(chan struct{})
	hErr := make(chan error, 1)
	frames := make(chan Frame, 16)
	inCh := make(chan Frame, 4)
	waitCh := make(chan error, 1)
	h := &Host{
		m: m, cmd: cmd, stdin: inCh, stdout: frames, errCh: hErr,
		done: done, waitCh: waitCh, pipe: stdinPipe,
	}
	go readFrames(stdoutPipe, frames, hErr, done, m.Transport.MaxOutputBytes)
	go writeFrames(stdinPipe, inCh, done)
	go func() {
		waitCh <- cmd.Wait()
		close(waitCh)
	}()

	hsCtx, cancel := context.WithTimeout(ctx, time.Duration(m.Transport.HandshakeTimeoutMS)*time.Millisecond)
	defer cancel()
	select {
	case inCh <- Frame{Type: "hello", Protocol: ProtocolVersion}:
	case <-done:
		h.revoke()
		return nil, fmt.Errorf("%w: observer %s stopped during handshake", errManifest, m.Name)
	case <-hsCtx.Done():
		h.revoke()
		return nil, fmt.Errorf("%w: handshake send timed out for %s", errManifest, m.Name)
	}
	select {
	case f, ok := <-frames:
		if !ok || !validHello(f, m) {
			h.revoke()
			return nil, fmt.Errorf("%w: bad handshake from %s (want hello_ok protocol=%d name=%s version=%s)", errManifest, m.Name, ProtocolVersion, m.Name, m.Version)
		}
	case err := <-hErr:
		h.revoke()
		return nil, fmt.Errorf("%w: handshake read from %s: %v", errManifest, m.Name, err)
	case <-hsCtx.Done():
		h.revoke()
		return nil, fmt.Errorf("%w: handshake timed out for %s", errManifest, m.Name)
	}
	return h, nil
}

func validHello(f Frame, m *Manifest) bool {
	expected, err := json.Marshal(Frame{
		Type:     "hello_ok",
		Protocol: ProtocolVersion,
		Name:     m.Name,
		Version:  m.Version,
	})
	return err == nil && bytes.Equal(f.raw, expected)
}

func readFrames(r io.Reader, out chan<- Frame, errOut chan<- error, done <-chan struct{}, maxBytes int) {
	defer close(out)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), maxBytes)
	for sc.Scan() {
		if err := rejectDuplicateJSONKeys(sc.Bytes()); err != nil {
			sendFrameError(errOut, done, fmt.Errorf("undecodable frame: %w", err))
			return
		}
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		var f Frame
		if err := dec.Decode(&f); err != nil {
			sendFrameError(errOut, done, fmt.Errorf("undecodable frame: %w", err))
			return
		}
		if err := requireJSONEOF(dec); err != nil {
			sendFrameError(errOut, done, fmt.Errorf("undecodable frame: %w", err))
			return
		}
		f.raw = append([]byte(nil), sc.Bytes()...)
		select {
		case out <- f:
		case <-done:
			return
		}
	}
	if err := sc.Err(); err != nil {
		sendFrameError(errOut, done, fmt.Errorf("read loop: %w (output cap %d bytes enforced)", err, maxBytes))
	}
}

func sendFrameError(errOut chan<- error, done <-chan struct{}, err error) {
	select {
	case errOut <- err:
	case <-done:
	}
}

func writeFrames(w io.Writer, in <-chan Frame, done <-chan struct{}) {
	enc := json.NewEncoder(w)
	for {
		select {
		case <-done:
			return
		case f := <-in:
			if enc.Encode(f) != nil {
				return
			}
		}
	}
}

// Observe delivers one bounded observation. Success requires an exact
// canonical acknowledgement tied to the source event. No extension-produced
// value is returned to callers or exposed to runtime policy.
func (h *Host) Observe(ctx context.Context, observation Observation) error {
	params, err := marshalObservation(observation)
	if err != nil {
		return err
	}
	expected, err := json.Marshal(observeAck{EventID: observation.EventID, Accepted: true})
	if err != nil {
		return fmt.Errorf("%w: build acknowledgement contract: %v", errManifest, err)
	}

	h.callMu.Lock()
	defer h.callMu.Unlock()
	id := fmt.Sprintf("req-%d", h.seq.Add(1))
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(h.m.Transport.CallTimeoutMS)*time.Millisecond)
	defer cancel()
	select {
	case h.stdin <- Frame{Type: "request", ID: id, Method: "observe", Params: params}:
	case <-h.done:
		return fmt.Errorf("%w: observer %s is stopped", errManifest, h.m.Name)
	case <-callCtx.Done():
		h.revoke()
		return fmt.Errorf("%w: call to %s timed out sending; process revoked", errManifest, h.m.Name)
	}
	select {
	case f, ok := <-h.stdout:
		if !ok {
			h.revoke()
			return fmt.Errorf("%w: observer %s closed output unexpectedly; process revoked", errManifest, h.m.Name)
		}
		expectedFrame, err := json.Marshal(Frame{Type: "response", ID: id, Result: expected})
		if err != nil || !bytes.Equal(f.raw, expectedFrame) {
			h.revoke()
			return fmt.Errorf("%w: observer %s violated the acknowledgement protocol; process revoked", errManifest, h.m.Name)
		}
		return nil
	case err := <-h.errCh:
		h.revoke()
		return fmt.Errorf("%w: observer %s failed; process revoked: %v", errManifest, h.m.Name, err)
	case <-h.done:
		return fmt.Errorf("%w: observer %s is stopped", errManifest, h.m.Name)
	case <-callCtx.Done():
		h.revoke()
		return fmt.Errorf("%w: call deadline exceeded for %s; process revoked", errManifest, h.m.Name)
	}
}

func marshalObservation(observation Observation) ([]byte, error) {
	if observation.EventID == "" {
		return nil, fmt.Errorf("%w: observation event_id is required", errManifest)
	}
	if observation.Time.IsZero() {
		return nil, fmt.Errorf("%w: observation time is required", errManifest)
	}
	if observation.Sensor.ID == "" || observation.Sensor.Kind == "" {
		return nil, fmt.Errorf("%w: observation sensor is incomplete", errManifest)
	}
	switch observation.Classification {
	case event.ClassificationInteraction, event.ClassificationCanaryHit:
	default:
		return nil, fmt.Errorf("%w: observation classification %q is not deliverable", errManifest, observation.Classification)
	}
	if !json.Valid(observation.Payload) {
		return nil, fmt.Errorf("%w: observation payload is not valid JSON", errManifest)
	}
	params, err := json.Marshal(observation)
	if err != nil {
		return nil, fmt.Errorf("%w: observation is not valid JSON", errManifest)
	}
	if len(params) > MaxObservationBytes {
		return nil, fmt.Errorf("%w: observation exceeds the %d-byte protocol cap", errManifest, MaxObservationBytes)
	}
	return params, nil
}

func (h *Host) revoke() {
	h.stopOnce.Do(func() {
		close(h.done)
		_ = h.pipe.Close()
		if h.cmd.Process != nil {
			_ = h.cmd.Process.Kill()
		}
	})
}

// Stop closes observer input, waits briefly for a clean exit, then revokes the
// process. It is safe to call concurrently with Observe and is idempotent.
func (h *Host) Stop() {
	h.stopOnce.Do(func() {
		close(h.done)
		_ = h.pipe.Close()
	})
	select {
	case <-h.waitCh:
	case <-time.After(2 * time.Second):
		if h.cmd.Process != nil {
			_ = h.cmd.Process.Kill()
		}
		select {
		case <-h.waitCh:
		case <-time.After(2 * time.Second):
		}
	}
}
