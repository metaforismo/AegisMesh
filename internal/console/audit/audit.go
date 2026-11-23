// Package audit persists bounded console-authored metadata in a synchronous SHA-256 chain.
// Files are private; the chain detects inconsistent records, not a trusted administrator rewriting history.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/stateio"
)

// RotateBytes caps the normal size of each audit segment before rotation.
const RotateBytes = 4 << 20

// MaxSegments bounds retained audit files; exhaustion fails closed.
const MaxSegments = 128

const maxRecordBytes = 4096

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// ErrAudit marks invalid, unavailable, or exhausted audit state.
var ErrAudit = errors.New("console audit")

// Record contains bounded console-authored metadata and its hash-chain links.
type Record struct {
	// Issuer and Subject identify federated identities independently of mutable display names.
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject,omitempty"`
	// ActorID is the stable principal id (cfg:, acc_ or oidc:); omitted by older records.
	ActorID string `json:"actor_id,omitempty"`
	// Seq is the monotonically increasing sequence across segments.
	Seq uint64 `json:"seq"`
	// Time is the UTC append time in RFC3339Nano format.
	Time string `json:"time"`
	// Actor identifies the authenticated operator, or is empty for failed login.
	Actor string `json:"actor"`
	// Role records the operator role at the time of the action.
	Role string `json:"role"`
	// Action is a console-authored action name.
	Action string `json:"action"`
	// Target identifies the affected operator record without annotation contents.
	Target string `json:"target"`
	// Outcome records the fixed action result.
	Outcome string `json:"outcome"`
	// Remote records the peer host without trusting forwarded headers.
	Remote string `json:"remote"`
	// Detail holds bounded console-authored context, never request bodies.
	Detail string `json:"detail"`
	// PrevHash links to the preceding record, or the all-zero initial hash.
	PrevHash string `json:"prev_hash"`
	// Hash is SHA-256 of the canonical record with this field empty.
	Hash string `json:"hash"`
}

// Verification reports the valid prefix and the first inconsistent sequence.
type Verification struct {
	// Verified reports consistency across all readable retained records.
	Verified bool `json:"verified"`
	// Records counts the verified prefix.
	Records uint64 `json:"records"`
	// FirstInvalidSeq identifies the first inconsistent or unreadable sequence, or zero on success.
	FirstInvalidSeq uint64 `json:"first_invalid_seq"`
	// Error contains an operator-safe consistency error on failure.
	Error string `json:"error"`
}

// Log synchronously persists canonical JSONL records in a SHA-256 chain.
type Log struct {
	mu          sync.Mutex
	root        *os.Root
	seq         uint64
	hash        string
	rotateBytes int64
	failed      bool
}

func hashRecord(record Record) string {
	record.Hash = ""
	body, _ := json.Marshal(record)
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

// New opens private audit state and rejects an unreadable or inconsistent existing chain.
func New(dir string) (*Log, error) {
	root, err := stateio.Open(dir)
	if err != nil {
		return nil, err
	}

	auditLog := &Log{
		root:        root,
		hash:        zeroHash,
		rotateBytes: RotateBytes,
	}

	verification := auditLog.verify()
	if !verification.Verified {
		root.Close()
		return nil, fmt.Errorf("%w: existing chain invalid at seq %d", ErrAudit, verification.FirstInvalidSeq)
	}

	return auditLog, nil
}

func (auditLog *Log) files() ([]string, error) {
	directory, err := auditLog.root.Open(".")
	if err != nil {
		return nil, err
	}

	defer directory.Close()

	entries, err := directory.ReadDir(MaxSegments + 16)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	if len(entries) >= MaxSegments+16 {
		return nil, fmt.Errorf("%w: state directory entry limit exceeded", ErrAudit)
	}

	files := []string{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "audit-") && strings.HasSuffix(entry.Name(), ".jsonl") {
			files = append(files, entry.Name())
		}
	}

	sort.Strings(files)
	if len(files) >= MaxSegments {
		return nil, fmt.Errorf("%w: segment quota reached", ErrAudit)
	}

	files = append(files, "audit.jsonl")
	return files, nil
}

func (auditLog *Log) scan(fn func(Record) error) error {
	files, err := auditLog.files()
	if err != nil {
		return err
	}

	for _, name := range files {
		file, err := stateio.File(auditLog.root, name, os.O_RDONLY)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil || info.Size() > RotateBytes+maxRecordBytes {
			file.Close()
			return fmt.Errorf("%w: segment exceeds byte limit", ErrAudit)
		}
		// A complete JSON value without its JSONL separator cannot be safely
		// extended: O_APPEND would concatenate it with the next record.
		if info.Size() > 0 {
			var last [1]byte
			if _, err := file.ReadAt(last[:], info.Size()-1); err != nil || last[0] != '\n' {
				file.Close()
				return fmt.Errorf("%w: unterminated JSONL record", ErrAudit)
			}
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 1024), maxRecordBytes)
		for scanner.Scan() {
			var record Record
			if json.Unmarshal(scanner.Bytes(), &record) != nil {
				file.Close()
				return fmt.Errorf("%w: malformed record", ErrAudit)
			}
			canonical, _ := json.Marshal(record)
			if !bytes.Equal(scanner.Bytes(), canonical) {
				file.Close()
				return fmt.Errorf("%w: record is not canonical JSON", ErrAudit)
			}
			if err := fn(record); err != nil {
				file.Close()
				return err
			}
		}
		err = scanner.Err()
		file.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (auditLog *Log) verify() Verification {
	verification := Verification{Verified: true}
	prev := zeroHash
	var seq uint64
	err := auditLog.scan(func(record Record) error {
		if record.Seq != seq+1 || record.PrevHash != prev || hashRecord(record) != record.Hash {
			verification.FirstInvalidSeq = seq + 1
			return ErrAudit
		}
		seq = record.Seq
		prev = record.Hash
		return nil
	})
	verification.Records = seq
	if err != nil {
		verification.Verified = false
		verification.Error = "audit chain is unreadable or inconsistent"
		if verification.FirstInvalidSeq == 0 {
			verification.FirstInvalidSeq = seq + 1
		}
	} else {
		auditLog.seq = seq
		auditLog.hash = prev
	}

	return verification
}

// Verify checks all retained records and reports the first invalid sequence.
func (auditLog *Log) Verify() Verification {
	auditLog.mu.Lock()
	defer auditLog.mu.Unlock()

	return auditLog.verify()
}

// Append synchronously writes and syncs a record; any failure poisons later appends.
func (auditLog *Log) Append(record Record) (err error) {
	auditLog.mu.Lock()
	defer auditLog.mu.Unlock()
	defer func() {
		if err != nil {
			auditLog.failed = true
		}
	}()
	if auditLog.failed {
		return fmt.Errorf("%w: prior write failed; restart after inspecting audit state", ErrAudit)
	}

	// Only fixed actions/details and validated principals enter this API.
	if len(record.Issuer) > 512 || len(record.Subject) > 255 ||
		len(record.Actor) > 64 || len(record.ActorID) > 80 ||
		len(record.Role) > 16 ||
		len(record.Action) > 64 ||
		len(record.Target) > 128 ||
		len(record.Remote) > 255 ||
		len(record.Detail) > 256 {
		return fmt.Errorf("%w: record field exceeds limit", ErrAudit)
	}

	record.Seq = auditLog.seq + 1
	record.Time = time.Now().UTC().Format(time.RFC3339Nano)
	record.PrevHash = auditLog.hash
	record.Hash = hashRecord(record)
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}

	body = append(body, '\n')
	if len(body) > maxRecordBytes {
		return ErrAudit
	}

	file, err := stateio.File(auditLog.root, "audit.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY)
	if err != nil {
		return err
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}

	if info.Size()+int64(len(body)) > auditLog.rotateBytes && info.Size() > 0 {
		if err = file.Sync(); err != nil {
			file.Close()
			return err
		}
		if err = file.Close(); err != nil {
			return err
		}
		files, err := auditLog.files()
		if err != nil {
			return err
		}
		if len(files) >= MaxSegments {
			return fmt.Errorf("%w: segment quota reached", ErrAudit)
		}
		name := fmt.Sprintf("audit-%020d.jsonl", auditLog.seq)
		if _, err = auditLog.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: rotation destination exists", ErrAudit)
		}
		if err = auditLog.root.Rename("audit.jsonl", name); err != nil {
			return err
		}
		directory, err := auditLog.root.Open(".")
		if err != nil {
			return err
		}
		err = directory.Sync()
		directory.Close()
		if err != nil {
			return err
		}
		file, err = stateio.File(auditLog.root, "audit.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY)
		if err != nil {
			return err
		}
	}

	_, err = file.Write(body)
	if err == nil {
		err = file.Sync()
	}

	closeErr := file.Close()
	if err != nil || closeErr != nil {
		auditLog.failed = true
		return fmt.Errorf("%w: append or sync failed", ErrAudit)
	}

	auditLog.seq = record.Seq
	auditLog.hash = record.Hash
	return nil
}

// Read keeps at most limit+1 records, even across rotated segments.
func (auditLog *Log) Read(before uint64, limit int, action, actor string) ([]Record, bool, error) {
	if limit < 1 || limit > 200 {
		return nil, false, ErrAudit
	}

	auditLog.mu.Lock()
	defer auditLog.mu.Unlock()

	records := []Record{}
	err := auditLog.scan(func(record Record) error {
		if record.Seq >= before || action != "" && record.Action != action || actor != "" && record.Actor != actor {
			return nil
		}
		records = append(records, record)
		if len(records) > limit+1 {
			copy(records, records[1:])
			records = records[:limit+1]
		}
		return nil
	})
	sort.Slice(records, func(i, j int) bool {
		return records[i].Seq > records[j].Seq
	})
	more := len(records) > limit
	if more {
		records = records[:limit]
	}

	return records, more, err
}

// MaxExportRecords bounds one export; callers narrow later exports with since.
const MaxExportRecords = 10000

// Collect returns, oldest first, at most limit records appended at or after
// since (zero means all) and whether more matching records exist. It holds the
// log lock only while scanning, so callers stream the copy without blocking appends.
func (auditLog *Log) Collect(since time.Time, limit int) ([]Record, bool, error) {
	if limit < 1 || limit > MaxExportRecords {
		return nil, false, ErrAudit
	}
	auditLog.mu.Lock()
	defer auditLog.mu.Unlock()
	records := []Record{}
	more := false
	err := auditLog.scan(func(record Record) error {
		if !since.IsZero() {
			appended, err := time.Parse(time.RFC3339Nano, record.Time)
			if err != nil || appended.Before(since) {
				return nil
			}
		}
		if len(records) >= limit {
			more = true
			return nil
		}
		records = append(records, record)
		return nil
	})
	return records, more, err
}

// Close releases the audit state directory handle.
func (auditLog *Log) Close() error {
	return auditLog.root.Close()
}

// Ready reports whether this process has avoided audit write failures.
func (auditLog *Log) Ready() bool {
	auditLog.mu.Lock()
	defer auditLog.mu.Unlock()

	return !auditLog.failed
}
